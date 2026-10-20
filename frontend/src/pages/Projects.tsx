// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>

import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router-dom'

import { ApiError } from '../api/client'
import { SEVERITIES } from '../api/dashboard'
import { type ProjectFilters, useProjects } from '../api/projects'
import { useStatus } from '../api/status'
import { useTargets } from '../api/targets'
import SeverityBadges from '../components/SeverityBadges'
import { formatDateTime } from '../lib/format'

const SORTS = ['risk', 'critical', 'path', 'last_scan'] as const
const SCAN_STATUSES = ['done', 'failed', 'skipped'] as const

export default function Projects() {
  const { t, i18n } = useTranslation()
  const [filters, setFilters] = useState<ProjectFilters>({ branch: 'default', sort: 'risk', page: 1 })
  const { data, isLoading, isError, error } = useProjects(filters)
  const targets = useTargets()
  const { data: status } = useStatus()
  const dtUiUrl = status?.runtime.dt_ui_url ?? null

  const update = (patch: Partial<ProjectFilters>) =>
    setFilters((current) => ({ ...current, ...patch, page: patch.page ?? 1 }))

  const inputClass =
    'rounded-md border border-slate-300 bg-white px-2 py-1 text-sm dark:border-slate-700 dark:bg-slate-900'

  return (
    <section className="space-y-4">
      <header className="space-y-1">
        <h1 className="text-2xl font-semibold tracking-tight">{t('projects.title')}</h1>
        <p className="text-sm text-slate-600 dark:text-slate-400">{t('projects.description')}</p>
      </header>

      {/* Filters in one row above the table. */}
      <div className="flex flex-wrap items-end gap-3">
        <label className="flex flex-col gap-1 text-xs">
          {t('projects.filter.search')}
          <input
            value={filters.search ?? ''}
            onChange={(event) => update({ search: event.target.value })}
            placeholder={t('projects.filter.searchPlaceholder')}
            className={inputClass}
          />
        </label>

        <label className="flex flex-col gap-1 text-xs">
          {t('projects.filter.target')}
          <select
            value={filters.target_id ?? ''}
            onChange={(event) =>
              update({ target_id: event.target.value ? Number(event.target.value) : null })
            }
            className={inputClass}
          >
            <option value="">{t('projects.filter.allTargets')}</option>
            {(targets.data?.items ?? []).map((target) => (
              <option key={target.id} value={target.id}>
                {target.name}
              </option>
            ))}
          </select>
        </label>

        <label className="flex flex-col gap-1 text-xs">
          {t('projects.filter.minSeverity')}
          <select
            value={filters.min_severity ?? ''}
            onChange={(event) => update({ min_severity: event.target.value || null })}
            className={inputClass}
          >
            <option value="">{t('projects.filter.anySeverity')}</option>
            {SEVERITIES.map((severity) => (
              <option key={severity} value={severity}>
                {t(`severity.${severity}`)}
              </option>
            ))}
          </select>
        </label>

        <label className="flex flex-col gap-1 text-xs">
          {t('projects.filter.scanStatus')}
          <select
            value={filters.status ?? ''}
            onChange={(event) => update({ status: event.target.value || null })}
            className={inputClass}
          >
            <option value="">{t('projects.filter.anyStatus')}</option>
            {SCAN_STATUSES.map((value) => (
              <option key={value} value={value}>
                {t(`runs.jobStatus.${value}`)}
              </option>
            ))}
          </select>
        </label>

        <label className="flex flex-col gap-1 text-xs">
          {t('projects.filter.branch')}
          <select
            value={filters.branch ?? 'default'}
            onChange={(event) => update({ branch: event.target.value as 'default' | 'all' })}
            className={inputClass}
          >
            <option value="default">{t('projects.filter.branchDefault')}</option>
            <option value="all">{t('projects.filter.branchAll')}</option>
          </select>
        </label>

        <label className="flex flex-col gap-1 text-xs">
          {t('projects.filter.sort')}
          <select
            value={filters.sort ?? 'risk'}
            onChange={(event) => update({ sort: event.target.value })}
            className={inputClass}
          >
            {SORTS.map((value) => (
              <option key={value} value={value}>
                {t(`projects.sort.${value}`)}
              </option>
            ))}
          </select>
        </label>
      </div>

      {isLoading && <p className="text-sm text-slate-600 dark:text-slate-400">{t('common.loading')}</p>}

      {isError && (
        <p className="rounded-md border border-red-300 bg-red-50 px-3 py-2 text-sm text-red-900 dark:border-red-500/40 dark:bg-red-500/10 dark:text-red-100">
          {error instanceof ApiError ? error.message : String(error)}
        </p>
      )}

      {data && data.items.length === 0 && (
        <div className="rounded-lg border border-dashed border-slate-300 p-6 text-sm dark:border-slate-700">
          <p className="font-medium">{t('projects.emptyTitle')}</p>
          <p className="mt-1 text-slate-600 dark:text-slate-400">{t('projects.emptyDescription')}</p>
        </div>
      )}

      {data && data.items.length > 0 && (
        <>
          <div className="overflow-x-auto rounded-lg border border-slate-200 dark:border-slate-800">
            <table className="w-full text-left text-sm">
              <thead className="bg-slate-50 text-xs uppercase text-slate-500 dark:bg-slate-900 dark:text-slate-400">
                <tr>
                  <th className="px-3 py-2">{t('projects.table.project')}</th>
                  <th className="px-3 py-2">{t('projects.table.target')}</th>
                  <th className="px-3 py-2">{t('projects.table.branch')}</th>
                  <th className="px-3 py-2">{t('projects.table.findings')}</th>
                  <th className="px-3 py-2 text-right">{t('projects.riskScore')}</th>
                  <th className="px-3 py-2">{t('projects.table.lastScan')}</th>
                  <th className="px-3 py-2 text-right">{t('projects.table.links')}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                {data.items.map((project) => (
                  <tr key={project.id}>
                    <td className="px-3 py-2">
                      <Link
                        to={`/projects/${project.id}`}
                        className="font-medium underline hover:no-underline"
                      >
                        <code className="text-xs">{project.path_with_namespace}</code>
                      </Link>
                    </td>
                    <td className="px-3 py-2 text-xs text-slate-600 dark:text-slate-400">
                      {project.targets.join(', ') || '—'}
                    </td>
                    <td className="px-3 py-2">
                      <code className="text-xs">{project.branch}</code>
                      {project.is_default_branch && (
                        <span className="ml-1 rounded bg-slate-200 px-1 text-[10px] uppercase dark:bg-slate-700">
                          {t('targets.preview.defaultBranch')}
                        </span>
                      )}
                    </td>
                    <td className="px-3 py-2">
                      <SeverityBadges counts={project.severities} compact />
                    </td>
                    <td className="px-3 py-2 text-right tabular-nums">
                      {project.risk_score?.toFixed(1) ?? '—'}
                    </td>
                    <td className="px-3 py-2 text-xs">
                      {formatDateTime(project.last_scan_at, i18n.language)}
                      {project.last_scan_status && (
                        <span className="block text-slate-500 dark:text-slate-400">
                          {t(`runs.jobStatus.${project.last_scan_status}`)}
                        </span>
                      )}
                    </td>
                    <td className="px-3 py-2 text-right text-xs">
                      <a
                        href={project.web_url}
                        target="_blank"
                        rel="noreferrer"
                        className="underline hover:no-underline"
                      >
                        {t('projects.openInSource')}
                      </a>
                      {project.dt_project_uuid && dtUiUrl && (
                        <>
                          {' · '}
                          <a
                            href={`${dtUiUrl}/projects/${project.dt_project_uuid}`}
                            target="_blank"
                            rel="noreferrer"
                            className="underline hover:no-underline"
                          >
                            {t('runs.openInDtrack')}
                          </a>
                        </>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="flex items-center justify-between text-xs">
            <span className="text-slate-600 dark:text-slate-400">
              {t('projects.pageInfo', {
                from: (data.page - 1) * data.page_size + 1,
                to: Math.min(data.page * data.page_size, data.total),
                total: data.total,
              })}
            </span>
            <span className="flex gap-2">
              <button
                type="button"
                disabled={data.page <= 1}
                onClick={() => update({ page: data.page - 1 })}
                className="underline hover:no-underline disabled:opacity-40"
              >
                {t('common.previous')}
              </button>
              <button
                type="button"
                disabled={data.page * data.page_size >= data.total}
                onClick={() => update({ page: data.page + 1 })}
                className="underline hover:no-underline disabled:opacity-40"
              >
                {t('common.next')}
              </button>
            </span>
          </div>
        </>
      )}
    </section>
  )
}
