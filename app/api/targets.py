# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>
"""Scan targets: CRUD and the discovery preview (SPEC section 11)."""

from __future__ import annotations

from fastapi import APIRouter, Query, Response, status

from app.config import get_settings
from app.dependencies import (
    AuditIdentityDep,
    LocaleDep,
    SchedulerDep,
    SessionDep,
    SourcesDep,
    WorkerDep,
)
from app.i18n import t
from app.errors import AppError
from app.schemas import (
    ConnectionTestResult,
    NoteRead,
    RunRead,
    PreviewBranch,
    PreviewProject,
    PreviewRequest,
    PreviewResponse,
    PreviewSkipped,
    TargetCreate,
    TargetList,
    TargetRead,
    TargetUpdate,
)
from app.services import runs as run_service
from app.services import targets as target_service
from app.services.app_settings import get_global_exclude_patterns
from app.services.notifications import mask_webhook
from app.services.discovery import DiscoveryResult, Note, discover

router = APIRouter(prefix="/targets", tags=["targets"])


@router.get("", response_model=TargetList)
async def list_targets(
    session: SessionDep,
    enabled: bool | None = Query(default=None),
) -> TargetList:
    items, total = await target_service.list_targets(session, enabled=enabled)
    return TargetList(items=[_target(item) for item in items], total=total)


@router.post("", response_model=TargetRead, status_code=status.HTTP_201_CREATED)
async def create_target(
    payload: TargetCreate,
    session: SessionDep,
    sources: SourcesDep,
    scheduler: SchedulerDep,
    identity: AuditIdentityDep,
) -> TargetRead:
    target_service.validate_selection(payload)
    target_service.validate_cron(payload.schedule_cron)

    credentials = target_service.credentials_from_payload(payload)
    source = sources.get(credentials or sources.credentials_for(None))

    name, source_path = payload.name, payload.source_path
    if not name or not source_path:
        # Fill in the display name and path from the instance this target uses.
        resolved_name, resolved_path = await target_service.resolve_source_metadata(
            source, payload.kind, payload.source_ref
        )
        name = name or resolved_name
        source_path = source_path or resolved_path

    target = await target_service.create_target(
        session, payload, name=name, source_path=source_path, updated_by=identity
    )
    await _reschedule(scheduler)
    return _target(target)


@router.get("/{target_id}", response_model=TargetRead)
async def read_target(target_id: int, session: SessionDep) -> TargetRead:
    target = await target_service.get_target(session, target_id)
    return _target(target)


@router.put("/{target_id}", response_model=TargetRead)
async def update_target(
    target_id: int,
    payload: TargetUpdate,
    session: SessionDep,
    scheduler: SchedulerDep,
    identity: AuditIdentityDep,
) -> TargetRead:
    target = await target_service.get_target(session, target_id)

    if payload.schedule_cron is not None:
        target_service.validate_cron(payload.schedule_cron)

    # Validate the resulting selection, not just the changed fields.
    merged = payload.model_dump(exclude_unset=True)
    selection = PreviewRequest(
        kind=target.kind,
        source_ref=target.source_ref,
        include_subgroups=merged.get("include_subgroups", target.include_subgroups),
        branch_mode=merged.get("branch_mode", target.branch_mode),
        branch_patterns=merged.get("branch_patterns", list(target.branch_patterns or [])),
        include_default_branch=merged.get("include_default_branch", target.include_default_branch),
        max_branches_per_project=merged.get(
            "max_branches_per_project", target.max_branches_per_project
        ),
        exclude_patterns=merged.get("exclude_patterns", list(target.exclude_patterns or [])),
    )
    target_service.validate_selection(selection)

    updated = await target_service.update_target(session, target, payload, updated_by=identity)
    # The cron or the enabled flag may have changed, so reschedule.
    await _reschedule(scheduler)
    return _target(updated)


@router.delete("/{target_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_target(target_id: int, session: SessionDep, scheduler: SchedulerDep) -> Response:
    target = await target_service.get_target(session, target_id)
    await target_service.delete_target(session, target)
    await _reschedule(scheduler)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/{target_id}/scan", response_model=RunRead, status_code=status.HTTP_201_CREATED)
async def scan_target(
    target_id: int,
    session: SessionDep,
    sources: SourcesDep,
    worker: WorkerDep,
    identity: AuditIdentityDep,
    force: bool = Query(default=False),
) -> RunRead:
    """Queue a run for one target; `force` rescans unchanged commits (SPEC 7.2)."""
    target = await target_service.get_target(session, target_id)
    run = await run_service.create_run_for_targets(
        session,
        sources,
        [target],
        triggered_by=identity,
        global_exclude_patterns=await get_global_exclude_patterns(session),
        force=force,
    )
    worker.notify()
    return RunRead(
        id=run.id,
        trigger=run.trigger,
        target_id=run.target_id,
        target_name=target.name,
        triggered_by=run.triggered_by,
        status=run.status,
        created_at=run.created_at,
        started_at=run.started_at,
        finished_at=run.finished_at,
        total=run.total,
        succeeded=run.succeeded,
        failed=run.failed,
        skipped=run.skipped,
    )


@router.post("/{target_id}/test-source", response_model=ConnectionTestResult)
async def test_target_source(
    target_id: int, session: SessionDep, sources: SourcesDep, locale: LocaleDep
) -> ConnectionTestResult:
    """Ask the instance this target uses for its version (SPEC 12.5)."""
    target = await target_service.get_target(session, target_id)
    url = target.source_url or get_settings().gitlab_url
    try:
        version = await sources.for_target(target).version()
    except AppError as error:
        return ConnectionTestResult(
            ok=False, code=error.code, detail=t(error.code, locale, **error.params)
        )
    return ConnectionTestResult(
        ok=True,
        version=version,
        detail=t("settings.test.target_source_ok", locale, url=url, version=version or "?"),
    )


@router.post("/preview", response_model=PreviewResponse)
async def preview_target(
    payload: PreviewRequest,
    session: SessionDep,
    sources: SourcesDep,
    locale: LocaleDep,
) -> PreviewResponse:
    """Run discovery without saving anything (SPEC 11, "Náhled projektů")."""
    target_service.validate_selection(payload)

    credentials = target_service.credentials_from_payload(payload)
    result = await discover(
        sources.get(credentials or sources.credentials_for(None)),
        target_service.spec_from_selection(payload),
        global_exclude_patterns=await get_global_exclude_patterns(session),
    )
    return _preview_response(result, locale)


def _preview_response(result: DiscoveryResult, locale: str) -> PreviewResponse:
    return PreviewResponse(
        projects=[
            PreviewProject(
                source_ref=item.project.ref,
                path_with_namespace=item.project.path_with_namespace,
                name=item.project.name,
                web_url=item.project.web_url,
                default_branch=item.project.default_branch,
                branches=[
                    PreviewBranch(
                        branch=branch.branch,
                        is_default_branch=branch.is_default_branch,
                        commit_sha=branch.commit_sha,
                    )
                    for branch in item.branches
                ],
                notes=[_note(note, locale) for note in item.notes],
            )
            for item in result.projects
        ],
        skipped=[
            PreviewSkipped(
                source_ref=item.project.ref,
                path_with_namespace=item.project.path_with_namespace,
                name=item.project.name,
                web_url=item.project.web_url,
                reason=_note(item.reason, locale),
            )
            for item in result.skipped
        ],
        warnings=[_note(note, locale) for note in result.warnings],
        project_count=len(result.projects),
        branch_count=result.branch_count,
        skipped_count=len(result.skipped),
    )


def _target(target) -> TargetRead:  # noqa: ANN001 - ORM row
    """Target for the API: the webhook is reported masked, never in full."""
    return TargetRead(
        **{
            **{
                column: getattr(target, column)
                for column in (
                    "id",
                    "name",
                    "source",
                    "kind",
                    "source_ref",
                    "source_path",
                    "include_subgroups",
                    "branch_mode",
                    "include_default_branch",
                    "max_branches_per_project",
                    "schedule_cron",
                    "skip_unchanged",
                    "enabled",
                    "dt_parent_uuid",
                    "created_at",
                    "updated_at",
                    "updated_by",
                )
            },
            "branch_patterns": list(target.branch_patterns or []),
            "exclude_patterns": list(target.exclude_patterns or []),
            "notify_webhook_configured": bool(target.notify_webhook_url),
            "notify_webhook_url_masked": mask_webhook(target.notify_webhook_url),
            "source_url": target.source_url,
            # What this target actually talks to, own setting or the default.
            "source_url_effective": target.source_url or get_settings().gitlab_url,
            "source_token_configured": bool(target.source_token),
        }
    )


async def _reschedule(scheduler: SchedulerDep) -> None:
    """Re-register the cron jobs after a target changed (SPEC section 8)."""
    if scheduler is not None and scheduler.running:
        await scheduler.sync_targets()


def _note(note: Note, locale: str) -> NoteRead:
    return NoteRead(code=note.code, params=note.params, message=t(note.code, locale, **note.params))
