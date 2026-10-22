// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>

import { useTranslation } from 'react-i18next'
import { Link, useParams } from 'react-router-dom'

import { ApiError } from '../api/client'
import { ACTIVE_RUN_STATUSES, useCancelRun, useRun } from '../api/runs'
import { useStatus } from '../api/status'
import StatusBadge from '../components/StatusBadge'
import { secondaryButton } from '../lib/buttons'
import { formatBytes, formatDateTime, formatDuration, shortSha } from '../lib/format'

export default function RunDetail() {
  const { t, i18n } = useTranslation()
  const params = useParams<{ runId: string }>()
  const runId = params.runId ? Number(params.runId) : null
  const { data: run, isLoading, isError, error } = useRun(runId)
  const { data: status } = useStatus()
  const cancelRun = useCancelRun()
  const dtUiUrl = status?.runtime.dt_ui_url ?? null

  return (
    <section className="space-y-4">
      <header className="flex flex-wrap items-end justify-between gap-3">
        <div className="space-y-1">
          <Link to="/runs" className="text-sm underline hover:no-underline">
            ← {t('runs.backToList')}
          </Link>
          <h1 className="text-2xl font-semibold tracking-tight">
            {t('runs.detailTitle', { id: runId })}
          </h1>
        </div>
        {run && ACTIVE_RUN_STATUSES.includes(run.status) && (
          <button
            type="button"
            onClick={() => cancelRun.mutate(run.id)}
            disabled={cancelRun.isPending}
            className={secondaryButton}
          >
            {cancelRun.isPending ? t('common.loading') : t('runs.cancel')}
          </button>
        )}
      </header>

      {isLoading && <p className="text-sm text-slate-600 dark:text-slate-400">{t('common.loading')}</p>}

      {isError && (
        <p className="rounded-md border border-red-300 bg-red-50 px-3 py-2 text-sm text-red-900 dark:border-red-500/40 dark:bg-red-500/10 dark:text-red-100">
          {error instanceof ApiError ? error.message : String(error)}
        </p>
      )}

      {run && (
        <>
          <dl className="grid gap-3 rounded-lg border border-slate-200 bg-white p-4 text-sm sm:grid-cols-2 lg:grid-cols-4 dark:border-slate-800 dark:bg-slate-900">
            <div>
              <dt className="text-xs uppercase text-slate-500 dark:text-slate-400">{t('runs.table.status')}</dt>
              <dd className="mt-1">
                <StatusBadge status={run.status} kind="run" />
              </dd>
            </div>
            <div>
              <dt className="text-xs uppercase text-slate-500 dark:text-slate-400">{t('runs.table.target')}</dt>
              <dd className="mt-1">{run.target_name ?? t('runs.allTargets')}</dd>
            </div>
            <div>
              <dt className="text-xs uppercase text-slate-500 dark:text-slate-400">{t('runs.table.result')}</dt>
              <dd className="mt-1">
                {t('runs.table.counts', {
                  succeeded: run.succeeded,
                  failed: run.failed,
                  skipped: run.skipped,
                  total: run.total,
                })}
              </dd>
            </div>
            <div>
              <dt className="text-xs uppercase text-slate-500 dark:text-slate-400">{t('runs.table.started')}</dt>
              <dd className="mt-1">{formatDateTime(run.started_at ?? run.created_at, i18n.language)}</dd>
            </div>
          </dl>

          {run.jobs.length === 0 ? (
            <p className="text-sm text-slate-600 dark:text-slate-400">{t('runs.noJobs')}</p>
          ) : (
            <div className="space-y-2">
              {run.jobs.map((job) => (
                <article
                  key={job.id}
                  className="rounded-lg border border-slate-200 bg-white p-3 text-sm dark:border-slate-800 dark:bg-slate-900"
                >
                  <header className="flex flex-wrap items-center justify-between gap-2">
                    <div className="space-y-0.5">
                      <a
                        href={job.web_url}
                        target="_blank"
                        rel="noreferrer"
                        className="font-medium underline hover:no-underline"
                      >
                        <code className="text-xs">{job.path_with_namespace}</code>
                      </a>
                      <p className="text-xs text-slate-500 dark:text-slate-400">
                        <code>{job.branch}</code>
                        {job.is_default_branch && ` · ${t('targets.preview.defaultBranch')}`}
                        {job.commit_sha && ` · ${shortSha(job.commit_sha)}`}
                      </p>
                    </div>
                    <div className="flex items-center gap-2">
                      {job.dt_project_uuid && dtUiUrl && (
                        <a
                          href={`${dtUiUrl}/projects/${job.dt_project_uuid}`}
                          target="_blank"
                          rel="noreferrer"
                          className="text-xs underline hover:no-underline"
                        >
                          {t('runs.openInDtrack')}
                        </a>
                      )}
                      <StatusBadge status={job.status} kind="job" />
                    </div>
                  </header>

                  {/* A skipped job has nothing measured, so the line is left out. */}
                  {(job.components_count !== null || job.sbom_bytes !== null) && (
                    <p className="mt-2 text-xs text-slate-600 dark:text-slate-400">
                      {t('runs.job.components', { count: job.components_count ?? 0 })} ·{' '}
                      {t('runs.job.size', { size: formatBytes(job.sbom_bytes, i18n.language) })} ·{' '}
                      {t('runs.job.duration', { duration: formatDuration(job.duration_ms, i18n.language) })}
                    </p>
                  )}

                  {job.skip_message && (
                    <p className="mt-2 rounded-md border border-slate-200 bg-slate-50 px-3 py-2 text-xs text-slate-700 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200">
                      {job.skip_message}
                    </p>
                  )}

                  {job.error_message && (
                    <div className="mt-2 rounded-md border border-red-300 bg-red-50 px-3 py-2 text-xs text-red-900 dark:border-red-500/40 dark:bg-red-500/10 dark:text-red-100">
                      <p className="font-medium">{job.error_message}</p>
                      {job.error_detail && (
                        <pre className="mt-1 overflow-x-auto whitespace-pre-wrap font-mono text-[11px]">
                          {job.error_detail}
                        </pre>
                      )}
                    </div>
                  )}

                  {job.log_tail && (
                    <details className="mt-2 text-xs">
                      <summary className="cursor-pointer">{t('runs.job.log')}</summary>
                      <pre className="mt-1 overflow-x-auto whitespace-pre-wrap rounded bg-slate-100 p-2 font-mono text-[11px] dark:bg-slate-800">
                        {job.log_tail}
                      </pre>
                    </details>
                  )}
                </article>
              ))}
            </div>
          )}
        </>
      )}
    </section>
  )
}
