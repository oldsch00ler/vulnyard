// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>

import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Link, useParams } from 'react-router-dom'

import { ApiError } from '../api/client'
import {
  useDeleteBranchOverride,
  useProject,
  useProjectFindings,
  useProjectHistory,
  useSaveBranchOverride,
  useScanProject,
  useSetProjectExcluded,
} from '../api/projects'
import { useStatus } from '../api/status'
import ChipInput from '../components/ChipInput'
import SeverityBadges, { SeverityLabel } from '../components/SeverityBadges'
import StatusBadge from '../components/StatusBadge'
import LazyTrendChart from '../components/LazyTrendChart'
import {
  compactPrimaryButton,
  compactSecondaryButton,
  smallButton,
  smallPrimaryButton,
} from '../lib/buttons'
import { formatDateTime, formatDuration, shortSha } from '../lib/format'

export default function ProjectDetail() {
  const { t, i18n } = useTranslation()
  const params = useParams<{ projectId: string }>()
  const projectId = params.projectId ? Number(params.projectId) : null

  const { data: project, isLoading, isError, error } = useProject(projectId)
  const findings = useProjectFindings(projectId, Boolean(project?.dt_project_uuid))
  const history = useProjectHistory(projectId)
  const { data: status } = useStatus()
  const scanProject = useScanProject()
  const setExcluded = useSetProjectExcluded()
  const saveOverride = useSaveBranchOverride()
  const deleteOverride = useDeleteBranchOverride()

  const [overrideOpen, setOverrideOpen] = useState(false)
  const [patterns, setPatterns] = useState<string[]>([])
  const [includeDefault, setIncludeDefault] = useState(true)

  const dtUiUrl = status?.runtime.dt_ui_url ?? null

  const openOverride = () => {
    setPatterns(project?.branch_override?.branch_patterns ?? [])
    setIncludeDefault(project?.branch_override?.include_default_branch ?? true)
    setOverrideOpen(true)
  }

  return (
    <section className="space-y-4">
      <Link to="/projects" className="text-sm underline hover:no-underline">
        ← {t('projects.backToList')}
      </Link>

      {isLoading && <p className="text-sm text-slate-600 dark:text-slate-400">{t('common.loading')}</p>}

      {isError && (
        <p className="rounded-md border border-red-300 bg-red-50 px-3 py-2 text-sm text-red-900 dark:border-red-500/40 dark:bg-red-500/10 dark:text-red-100">
          {error instanceof ApiError ? error.message : String(error)}
        </p>
      )}

      {project && (
        <>
          <header className="flex flex-wrap items-start justify-between gap-3">
            <div className="space-y-1">
              <h1 className="text-2xl font-semibold tracking-tight">
                <code className="text-xl">{project.path_with_namespace}</code>
              </h1>
              <p className="text-sm text-slate-600 dark:text-slate-400">
                <code>{project.branch}</code>
                {project.is_default_branch && ` · ${t('targets.preview.defaultBranch')}`}
                {project.last_commit_sha && ` · ${shortSha(project.last_commit_sha)}`}
              </p>
            </div>
            <div className="flex flex-wrap gap-2 text-sm">
              <a
                href={project.web_url}
                target="_blank"
                rel="noreferrer"
                className="rounded-md border border-slate-300 px-3 py-1.5 font-medium dark:border-slate-700"
              >
                {t('projects.openInSource')}
              </a>
              {project.dt_project_uuid && dtUiUrl && (
                <a
                  href={`${dtUiUrl}/projects/${project.dt_project_uuid}`}
                  target="_blank"
                  rel="noreferrer"
                  className="rounded-md border border-slate-300 px-3 py-1.5 font-medium dark:border-slate-700"
                >
                  {t('runs.openInDtrack')}
                </a>
              )}
              <button
                type="button"
                onClick={() => scanProject.mutate(project.id)}
                disabled={scanProject.isPending}
                className={compactPrimaryButton}
              >
                {t('projects.scanNow')}
              </button>
              <button
                type="button"
                onClick={() => setExcluded.mutate({ projectId: project.id, excluded: !project.excluded })}
                disabled={setExcluded.isPending}
                className={compactSecondaryButton}
              >
                {project.excluded ? t('projects.include') : t('projects.exclude')}
              </button>
            </div>
          </header>

          {scanProject.isSuccess && scanProject.data && (
            <p className="rounded-md border border-emerald-300 bg-emerald-50 px-3 py-2 text-sm text-emerald-900 dark:border-emerald-500/40 dark:bg-emerald-500/10 dark:text-emerald-100">
              <Link to={`/runs/${scanProject.data.id}`} className="underline hover:no-underline">
                {t('targets.openRun', { id: scanProject.data.id })}
              </Link>
            </p>
          )}

          {project.excluded && (
            <p className="rounded-md border border-amber-300 bg-amber-50 px-3 py-2 text-sm text-amber-900 dark:border-amber-500/40 dark:bg-amber-500/10 dark:text-amber-100">
              {t('projects.excludedNotice')}
            </p>
          )}

          <div className="grid gap-4 lg:grid-cols-3">
            <dl className="space-y-2 rounded-lg border border-slate-200 bg-white p-4 text-sm lg:col-span-2 dark:border-slate-800 dark:bg-slate-900">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <dt className="text-slate-600 dark:text-slate-400">{t('projects.table.findings')}</dt>
                <dd>
                  <SeverityBadges counts={project.severities} />
                </dd>
              </div>
              <div className="flex justify-between gap-2">
                <dt className="text-slate-600 dark:text-slate-400">{t('projects.riskScore')}</dt>
                <dd className="tabular-nums">{project.risk_score?.toFixed(1) ?? '—'}</dd>
              </div>
              <div className="flex justify-between gap-2">
                <dt className="text-slate-600 dark:text-slate-400">{t('dashboard.components')}</dt>
                <dd className="tabular-nums">
                  {project.components} ({t('dashboard.vulnerableComponents', {
                    count: project.vulnerable_components,
                  })})
                </dd>
              </div>
              <div className="flex justify-between gap-2">
                <dt className="text-slate-600 dark:text-slate-400">{t('projects.lastScan')}</dt>
                <dd>{formatDateTime(project.last_scan_at, i18n.language)}</dd>
              </div>
              <div className="flex justify-between gap-2">
                <dt className="text-slate-600 dark:text-slate-400">{t('projects.lastBomImport')}</dt>
                <dd>{formatDateTime(project.dt_last_import, i18n.language)}</dd>
              </div>
            </dl>

            <section className="space-y-2 rounded-lg border border-slate-200 bg-white p-4 text-sm dark:border-slate-800 dark:bg-slate-900">
              <h2 className="font-semibold">{t('projects.branches')}</h2>
              <ul className="space-y-1">
                {project.branches.map((item) => (
                  <li key={item.id}>
                    {item.id === project.id ? (
                      <span className="font-medium">
                        <code className="text-xs">{item.branch}</code>
                      </span>
                    ) : (
                      <Link to={`/projects/${item.id}`} className="underline hover:no-underline">
                        <code className="text-xs">{item.branch}</code>
                      </Link>
                    )}
                    {item.is_default_branch && (
                      <span className="ml-1 rounded bg-slate-200 px-1 text-[10px] uppercase dark:bg-slate-700">
                        {t('targets.preview.defaultBranch')}
                      </span>
                    )}
                  </li>
                ))}
              </ul>

              <div className="border-t border-slate-200 pt-2 dark:border-slate-800">
                <h3 className="font-semibold">{t('projects.override.title')}</h3>
                {project.branch_override ? (
                  <p className="mt-1 text-xs text-slate-600 dark:text-slate-400">
                    {t('projects.override.active', {
                      patterns: project.branch_override.branch_patterns.join(', ') || '—',
                    })}
                  </p>
                ) : (
                  <p className="mt-1 text-xs text-slate-600 dark:text-slate-400">
                    {t('projects.override.none')}
                  </p>
                )}

                {overrideOpen ? (
                  <div className="mt-2 space-y-2">
                    <ChipInput
                      inputId="override-patterns"
                      label={t('targets.form.branchPatterns')}
                      hint={t('targets.form.branchPatternsHint')}
                      placeholder="release/*"
                      values={patterns}
                      onChange={setPatterns}
                    />
                    <label className="flex items-center gap-2 text-xs">
                      <input
                        type="checkbox"
                        checked={includeDefault}
                        onChange={(event) => setIncludeDefault(event.target.checked)}
                      />
                      {t('targets.form.includeDefaultBranch')}
                    </label>
                    {saveOverride.isError && (
                      <p className="text-xs text-red-600 dark:text-red-400">
                        {saveOverride.error instanceof ApiError
                          ? saveOverride.error.message
                          : String(saveOverride.error)}
                      </p>
                    )}
                    <div className="flex flex-wrap gap-2 text-xs">
                      <button
                        type="button"
                        onClick={() =>
                          saveOverride.mutate(
                            {
                              projectId: project.id,
                              override: {
                                branch_mode: 'custom',
                                branch_patterns: patterns,
                                include_default_branch: includeDefault,
                              },
                            },
                            { onSuccess: () => setOverrideOpen(false) },
                          )
                        }
                        className={smallPrimaryButton}
                      >
                        {t('common.save')}
                      </button>
                      <button
                        type="button"
                        onClick={() => setOverrideOpen(false)}
                        className={smallButton}
                      >
                        {t('common.cancel')}
                      </button>
                    </div>
                  </div>
                ) : (
                  <div className="mt-2 flex flex-wrap gap-2 text-xs">
                    <button type="button" onClick={openOverride} className={smallButton}>
                      {project.branch_override
                        ? t('projects.override.edit')
                        : t('projects.override.set')}
                    </button>
                    {project.branch_override && (
                      <button
                        type="button"
                        onClick={() => deleteOverride.mutate(project.id)}
                        className={smallButton}
                      >
                        {t('projects.override.remove')}
                      </button>
                    )}
                  </div>
                )}
              </div>
            </section>
          </div>

          {history.data && history.data.snapshots.length > 0 && (
            <section className="rounded-lg border border-slate-200 bg-white p-4 dark:border-slate-800 dark:bg-slate-900">
              <h2 className="text-lg font-semibold">{t('projects.trend')}</h2>
              <div className="mt-2 text-slate-500 dark:text-slate-400">
                <LazyTrendChart points={history.data.snapshots} height={180} />
              </div>
            </section>
          )}

          <section className="rounded-lg border border-slate-200 bg-white p-4 dark:border-slate-800 dark:bg-slate-900">
            <h2 className="text-lg font-semibold">{t('projects.findings')}</h2>
            {!project.dt_project_uuid && (
              <p className="mt-2 text-sm text-slate-600 dark:text-slate-400">
                {t('projects.notScannedYet')}
              </p>
            )}
            {findings.isLoading && (
              <p className="mt-2 text-sm text-slate-600 dark:text-slate-400">{t('common.loading')}</p>
            )}
            {findings.isError && (
              <p className="mt-2 text-sm text-red-600 dark:text-red-400">
                {findings.error instanceof ApiError
                  ? findings.error.message
                  : String(findings.error)}
              </p>
            )}
            {findings.data && findings.data.items.length === 0 && (
              <p className="mt-2 text-sm text-slate-600 dark:text-slate-400">
                {t('projects.noFindings')}
              </p>
            )}
            {findings.data && findings.data.items.length > 0 && (
              <div className="mt-3 overflow-x-auto">
                <table className="w-full text-left text-sm">
                  <thead className="text-xs uppercase text-slate-500 dark:text-slate-400">
                    <tr>
                      <th className="py-1 pr-3">{t('vulnerabilities.table.id')}</th>
                      <th className="py-1 pr-3">{t('vulnerabilities.table.severity')}</th>
                      <th className="py-1 pr-3 text-right">{t('vulnerabilities.table.cvss')}</th>
                      <th className="py-1 pr-3 text-right">{t('vulnerabilities.table.epss')}</th>
                      <th className="py-1 pr-3">{t('projects.table.component')}</th>
                      <th className="py-1 pr-3">{t('projects.table.fixedIn')}</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                    {findings.data.items.map((finding) => (
                      <tr key={`${finding.source}-${finding.vuln_id}-${finding.component_name}-${finding.component_version}`}>
                        <td className="py-1 pr-3">
                          {dtUiUrl ? (
                            <a
                              href={`${dtUiUrl}/vulnerabilities/${finding.source}/${finding.vuln_id}`}
                              target="_blank"
                              rel="noreferrer"
                              className="underline hover:no-underline"
                            >
                              {finding.vuln_id}
                            </a>
                          ) : (
                            finding.vuln_id
                          )}
                          {finding.cwe && (
                            <span className="block text-[11px] text-slate-500 dark:text-slate-400">
                              {finding.cwe}
                            </span>
                          )}
                        </td>
                        <td className="py-1 pr-3">
                          <SeverityLabel severity={finding.severity} />
                        </td>
                        <td className="py-1 pr-3 text-right tabular-nums">
                          {finding.cvss_v3_score?.toFixed(1) ?? '—'}
                        </td>
                        <td className="py-1 pr-3 text-right tabular-nums">
                          {finding.epss_score !== null
                            ? `${(finding.epss_score * 100).toFixed(1)} %`
                            : '—'}
                        </td>
                        <td className="py-1 pr-3">
                          <code className="text-xs">
                            {finding.component_name}
                            {finding.component_version ? `@${finding.component_version}` : ''}
                          </code>
                          {finding.purl && (
                            <span className="block truncate text-[11px] text-slate-500 dark:text-slate-400">
                              {finding.purl}
                            </span>
                          )}
                        </td>
                        <td className="py-1 pr-3 text-xs">{finding.latest_version ?? '—'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>

          <section className="rounded-lg border border-slate-200 bg-white p-4 dark:border-slate-800 dark:bg-slate-900">
            <h2 className="text-lg font-semibold">{t('projects.history')}</h2>
            {history.data && history.data.items.length === 0 && (
              <p className="mt-2 text-sm text-slate-600 dark:text-slate-400">{t('projects.noHistory')}</p>
            )}
            {history.data && history.data.items.length > 0 && (
              <ul className="mt-3 divide-y divide-slate-100 text-sm dark:divide-slate-800">
                {history.data.items.map((item) => (
                  <li key={item.job_id} className="flex flex-wrap items-center justify-between gap-2 py-2">
                    <span className="flex flex-wrap items-center gap-2">
                      <StatusBadge status={item.status as never} kind="job" />
                      <Link to={`/runs/${item.run_id}`} className="text-xs underline hover:no-underline">
                        #{item.run_id}
                      </Link>
                      <span className="text-xs text-slate-500 dark:text-slate-400">
                        {formatDateTime(item.finished_at ?? item.started_at, i18n.language)}
                        {item.commit_sha && ` · ${shortSha(item.commit_sha)}`}
                        {item.duration_ms !== null && ` · ${formatDuration(item.duration_ms, i18n.language)}`}
                      </span>
                    </span>
                    {(item.error_message || item.skip_message) && (
                      <span className="text-xs text-slate-600 dark:text-slate-400">
                        {item.error_message ?? item.skip_message}
                      </span>
                    )}
                  </li>
                ))}
              </ul>
            )}
          </section>
        </>
      )}
    </section>
  )
}
