// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>

import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router-dom'

import { ApiError } from '../api/client'
import {
  TREND_WINDOWS,
  useSummary,
  useTargetSummaries,
  useTopProjects,
  useTrend,
} from '../api/dashboard'
import SeverityBadges from '../components/SeverityBadges'
import StatTile from '../components/StatTile'
import LazyTrendChart from '../components/LazyTrendChart'
import { formatDateTime } from '../lib/format'
import { SEVERITY_CHIP, SEVERITY_ORDER } from '../lib/severity'

export default function Dashboard() {
  const { t, i18n } = useTranslation()
  const [days, setDays] = useState<number>(30)
  const [targetId, setTargetId] = useState<number | null>(null)
  const summary = useSummary()
  const trend = useTrend(days, targetId)
  const top = useTopProjects(10)
  const targets = useTargetSummaries(days)

  return (
    <section className="space-y-6">
      <header className="space-y-1">
        <h1 className="text-2xl font-semibold tracking-tight">{t('dashboard.title')}</h1>
        <p className="text-sm text-slate-600 dark:text-slate-400">{t('dashboard.description')}</p>
      </header>

      {summary.isError && (
        <p className="rounded-md border border-red-300 bg-red-50 px-3 py-2 text-sm text-red-900 dark:border-red-500/40 dark:bg-red-500/10 dark:text-red-100">
          {summary.error instanceof ApiError ? summary.error.message : String(summary.error)}
        </p>
      )}

      {summary.isLoading && (
        <p className="text-sm text-slate-600 dark:text-slate-400">{t('common.loading')}</p>
      )}

      {summary.data && (
        <>
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
            {SEVERITY_ORDER.map((severity) => (
              <StatTile
                key={severity}
                label={t(`severity.${severity}`)}
                value={summary.data.severities[severity]}
                chipClass={SEVERITY_CHIP[severity]}
              />
            ))}
          </div>

          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            <StatTile
              label={t('dashboard.findingsTotal')}
              value={summary.data.findings_total}
              hint={t('dashboard.defaultBranchOnly')}
            />
            <StatTile
              label={t('dashboard.vulnerableProjects')}
              value={`${summary.data.projects_vulnerable} / ${summary.data.projects_total}`}
              hint={t('dashboard.scannedProjects', { count: summary.data.projects_scanned })}
            />
            <StatTile
              label={t('dashboard.components')}
              value={summary.data.components}
              hint={t('dashboard.vulnerableComponents', {
                count: summary.data.vulnerable_components,
              })}
            />
            <StatTile
              label={t('dashboard.failedJobs')}
              value={summary.data.scan_state.failed_jobs_24h}
              hint={t('dashboard.failedJobsHint')}
            />
          </div>

          <section className="rounded-lg border border-slate-200 bg-white p-4 dark:border-slate-800 dark:bg-slate-900">
            <header className="flex flex-wrap items-center justify-between gap-3">
              <h2 className="text-lg font-semibold">{t('dashboard.trend.title')}</h2>
              {/* Filters sit in one row above the chart. */}
              <div className="flex flex-wrap items-center gap-2">
                <select
                  value={targetId ?? ''}
                  onChange={(event) => setTargetId(event.target.value ? Number(event.target.value) : null)}
                  aria-label={t('dashboard.trend.target')}
                  className="rounded-md border border-slate-300 bg-white px-2 py-1 text-xs dark:border-slate-700 dark:bg-slate-900"
                >
                  <option value="">{t('dashboard.trend.allTargets')}</option>
                  {(targets.data?.items ?? []).map((item) => (
                    <option key={item.target_id} value={item.target_id}>
                      {item.name}
                    </option>
                  ))}
                </select>
                <div className="flex gap-1" role="group" aria-label={t('dashboard.trend.range')}>
                  {TREND_WINDOWS.map((window) => (
                    <button
                      key={window}
                      type="button"
                      onClick={() => setDays(window)}
                      aria-pressed={days === window}
                      className={`rounded-md px-2 py-1 text-xs font-medium ${
                        days === window
                          ? 'bg-slate-900 text-white dark:bg-slate-100 dark:text-slate-900'
                          : 'border border-slate-300 hover:bg-slate-100 dark:border-slate-700 dark:hover:bg-slate-800'
                      }`}
                    >
                      {t('dashboard.trend.days', { count: window })}
                    </button>
                  ))}
                </div>
              </div>
            </header>
            <div className="mt-3 text-slate-500 dark:text-slate-400">
              {trend.isLoading ? (
                <p className="text-sm">{t('common.loading')}</p>
              ) : (
                <LazyTrendChart points={trend.data?.points ?? []} />
              )}
            </div>
          </section>

          {targets.data && targets.data.items.length > 0 && (
            <section className="rounded-lg border border-slate-200 bg-white p-4 dark:border-slate-800 dark:bg-slate-900">
              <h2 className="text-lg font-semibold">{t('dashboard.byTarget.title')}</h2>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                {t('dashboard.byTarget.description', { count: days })}
              </p>
              <div className="mt-3 overflow-x-auto">
                <table className="w-full text-left text-sm">
                  <thead className="text-xs uppercase text-slate-500 dark:text-slate-400">
                    <tr>
                      <th className="py-1 pr-3">{t('dashboard.byTarget.target')}</th>
                      <th className="py-1 pr-3 text-right">{t('dashboard.byTarget.projects')}</th>
                      <th className="py-1 pr-3">{t('projects.table.findings')}</th>
                      <th className="py-1 pr-3 text-right">{t('dashboard.byTarget.change')}</th>
                      <th className="py-1 pr-3 text-right">{t('projects.riskScore')}</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                    {targets.data.items.map((item) => (
                      <tr key={item.target_id}>
                        <td className="py-2 pr-3">
                          <button
                            type="button"
                            onClick={() => setTargetId(item.target_id)}
                            className="font-medium underline hover:no-underline"
                          >
                            {item.name}
                          </button>
                          <code className="block text-xs text-slate-500 dark:text-slate-400">
                            {item.source_path}
                          </code>
                          {!item.enabled && (
                            <span className="text-xs text-slate-500 dark:text-slate-400">
                              {t('targets.table.disabled')}
                            </span>
                          )}
                        </td>
                        <td className="py-2 pr-3 text-right tabular-nums">
                          {item.projects_vulnerable} / {item.projects_total}
                        </td>
                        <td className="py-2 pr-3">
                          <SeverityBadges counts={item.severities} compact />
                        </td>
                        <td className="py-2 pr-3 text-right tabular-nums">
                          {item.change === null
                            ? '—'
                            : item.change === 0
                              ? t('dashboard.byTarget.noChange')
                              : `${item.change > 0 ? '+' : '−'}${Math.abs(item.change)}`}
                        </td>
                        <td className="py-2 pr-3 text-right tabular-nums">
                          {item.risk_score.toFixed(1)}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>
          )}

          <div className="grid gap-4 lg:grid-cols-3">
            <section className="rounded-lg border border-slate-200 bg-white p-4 lg:col-span-2 dark:border-slate-800 dark:bg-slate-900">
              <h2 className="text-lg font-semibold">{t('dashboard.topProjects')}</h2>
              {top.isLoading && (
                <p className="mt-2 text-sm text-slate-600 dark:text-slate-400">{t('common.loading')}</p>
              )}
              {top.data && top.data.length === 0 && (
                <p className="mt-2 text-sm text-slate-600 dark:text-slate-400">
                  {t('dashboard.topProjectsEmpty')}
                </p>
              )}
              {top.data && top.data.length > 0 && (
                <ul className="mt-3 divide-y divide-slate-100 dark:divide-slate-800">
                  {top.data.map((project) => (
                    <li key={project.id} className="flex flex-wrap items-center justify-between gap-2 py-2">
                      <div className="min-w-0">
                        <Link
                          to={`/projects/${project.id}`}
                          className="text-sm font-medium underline hover:no-underline"
                        >
                          <code className="text-xs">{project.path_with_namespace}</code>
                        </Link>
                        <p className="text-xs text-slate-500 dark:text-slate-400">
                          {t('projects.riskScore')}: {project.risk_score?.toFixed(1) ?? '—'}
                        </p>
                      </div>
                      <SeverityBadges counts={project.severities} compact />
                    </li>
                  ))}
                </ul>
              )}
            </section>

            <section className="rounded-lg border border-slate-200 bg-white p-4 dark:border-slate-800 dark:bg-slate-900">
              <h2 className="text-lg font-semibold">{t('dashboard.scanState')}</h2>
              <dl className="mt-3 space-y-2 text-sm">
                <div className="flex justify-between gap-2">
                  <dt className="text-slate-600 dark:text-slate-400">{t('dashboard.lastRun')}</dt>
                  <dd>
                    {summary.data.scan_state.last_run_id ? (
                      <Link
                        to={`/runs/${summary.data.scan_state.last_run_id}`}
                        className="underline hover:no-underline"
                      >
                        #{summary.data.scan_state.last_run_id}
                      </Link>
                    ) : (
                      '—'
                    )}
                  </dd>
                </div>
                <div className="flex justify-between gap-2">
                  <dt className="text-slate-600 dark:text-slate-400">{t('dashboard.lastRunFinished')}</dt>
                  <dd>{formatDateTime(summary.data.scan_state.last_run_finished_at, i18n.language)}</dd>
                </div>
                <div className="flex justify-between gap-2">
                  <dt className="text-slate-600 dark:text-slate-400">{t('dashboard.nextRun')}</dt>
                  <dd>{formatDateTime(summary.data.scan_state.next_run_at, i18n.language)}</dd>
                </div>
              </dl>
            </section>
          </div>
        </>
      )}
    </section>
  )
}
