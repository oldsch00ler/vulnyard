// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>

import { Fragment, useState } from 'react'
import { useTranslation } from 'react-i18next'

import { ApiError } from '../api/client'
import { SEVERITIES } from '../api/dashboard'
import { useStatus } from '../api/status'
import { useVulnerabilities } from '../api/vulnerabilities'
import { SeverityLabel } from '../components/SeverityBadges'
import VulnerabilityDetail from '../components/VulnerabilityDetail'
import { smallButton } from '../lib/buttons'
import { formatDateTime } from '../lib/format'

export default function Vulnerabilities() {
  const { t, i18n } = useTranslation()
  const [minSeverity, setMinSeverity] = useState<string | null>(null)
  const [search, setSearch] = useState('')
  const [page, setPage] = useState(1)
  const [expanded, setExpanded] = useState<{ source: string; vulnId: string } | null>(null)
  const [includeIgnored, setIncludeIgnored] = useState(false)
  const [ignoring, setIgnoring] = useState<string | null>(null)

  const { data, isLoading, isError, error } = useVulnerabilities(
    minSeverity,
    search,
    page,
    includeIgnored,
  )
  const { data: status } = useStatus()
  const dtUiUrl = status?.runtime.dt_ui_url ?? null

  const inputClass =
    'rounded-md border border-slate-300 bg-white px-2 py-1 text-sm dark:border-slate-700 dark:bg-slate-900'

  return (
    <section className="space-y-4">
      <header className="space-y-1">
        <h1 className="text-2xl font-semibold tracking-tight">{t('vulnerabilities.title')}</h1>
        <p className="text-sm text-slate-600 dark:text-slate-400">{t('vulnerabilities.description')}</p>
      </header>

      <div className="flex flex-wrap items-end gap-3">
        <label className="flex flex-col gap-1 text-xs">
          {t('vulnerabilities.filter.search')}
          <input
            value={search}
            onChange={(event) => {
              setSearch(event.target.value)
              setPage(1)
            }}
            placeholder="CVE-2026-"
            className={inputClass}
          />
        </label>
        <label className="flex flex-col gap-1 text-xs">
          {t('projects.filter.minSeverity')}
          <select
            value={minSeverity ?? ''}
            onChange={(event) => {
              setMinSeverity(event.target.value || null)
              setPage(1)
            }}
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
        <label className="flex items-center gap-2 pb-1 text-xs">
          <input
            type="checkbox"
            checked={includeIgnored}
            onChange={(event) => {
              setIncludeIgnored(event.target.checked)
              setPage(1)
            }}
            className="size-4"
          />
          {t('ignores.showIgnored')}
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
          <p className="font-medium">{t('vulnerabilities.emptyTitle')}</p>
          <p className="mt-1 text-slate-600 dark:text-slate-400">
            {t('vulnerabilities.emptyDescription')}
          </p>
        </div>
      )}

      {data && data.items.length > 0 && (
        <>
          <div className="overflow-x-auto rounded-lg border border-slate-200 dark:border-slate-800">
            <table className="w-full text-left text-sm">
              <thead className="bg-slate-50 text-xs uppercase text-slate-500 dark:bg-slate-900 dark:text-slate-400">
                <tr>
                  <th className="px-3 py-2">{t('vulnerabilities.table.id')}</th>
                  <th className="px-3 py-2">{t('vulnerabilities.table.severity')}</th>
                  <th className="px-3 py-2 text-right">{t('vulnerabilities.table.cvss')}</th>
                  <th className="px-3 py-2 text-right">{t('vulnerabilities.table.projects')}</th>
                  <th className="px-3 py-2">{t('vulnerabilities.table.published')}</th>
                  <th className="px-3 py-2" />
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                {data.items.map((item) => {
                  const isOpen =
                    expanded?.vulnId === item.vuln_id && expanded?.source === item.source
                  const isIgnoringThis = ignoring === item.vuln_id
                  return (
                    // The key belongs to the fragment: a row pair per vulnerability.
                    <Fragment key={`${item.source}-${item.vuln_id}`}>
                      <tr>
                        <td className="px-3 py-2">
                          {dtUiUrl ? (
                            <a
                              href={`${dtUiUrl}/vulnerabilities/${item.source}/${item.vuln_id}`}
                              target="_blank"
                              rel="noreferrer"
                              className="font-medium underline hover:no-underline"
                            >
                              {item.vuln_id}
                            </a>
                          ) : (
                            <span className="font-medium">{item.vuln_id}</span>
                          )}
                          <span className="block text-[11px] text-slate-500 dark:text-slate-400">
                            {item.source}
                            {item.ignored && (
                              <span className="ml-2 rounded-sm bg-slate-200 px-1 py-0.5 font-medium text-slate-700 dark:bg-slate-700 dark:text-slate-200">
                                {t('ignores.badge')}
                              </span>
                            )}
                          </span>
                        </td>
                        <td className="px-3 py-2">
                          <SeverityLabel severity={item.severity} />
                        </td>
                        <td className="px-3 py-2 text-right tabular-nums">
                          {item.cvss_v3_score?.toFixed(1) ?? '—'}
                        </td>
                        <td className="px-3 py-2 text-right tabular-nums">
                          {item.affected_project_count}
                        </td>
                        <td className="px-3 py-2 text-xs">
                          {formatDateTime(item.published, i18n.language)}
                        </td>
                        <td className="px-3 py-2 text-right">
                          <span className="flex justify-end gap-3">
                            <button
                              type="button"
                              onClick={() =>
                                setExpanded(
                                  isOpen ? null : { source: item.source, vulnId: item.vuln_id },
                                )
                              }
                              aria-expanded={isOpen}
                              className={smallButton}
                            >
                              {isOpen
                                ? t('vulnerabilities.hideProjects')
                                : t('vulnerabilities.showProjects')}
                            </button>
                            <button
                              type="button"
                              onClick={() => {
                                setIgnoring(isIgnoringThis ? null : item.vuln_id)
                                // The pattern suggestions come from the affected
                                // components, so the row has to be open.
                                if (!isIgnoringThis) {
                                  setExpanded({ source: item.source, vulnId: item.vuln_id })
                                }
                              }}
                              className={smallButton}
                            >
                              {t('ignores.ignore')}
                            </button>
                          </span>
                        </td>
                      </tr>
                      {isOpen && (
                        <tr className="bg-slate-50 dark:bg-slate-900/60">
                          <td colSpan={6} className="px-3 py-2">
                            <VulnerabilityDetail
                              source={item.source}
                              vulnId={item.vuln_id}
                              ignoring={isIgnoringThis}
                              onIgnoreClose={() => setIgnoring(null)}
                            />
                          </td>
                        </tr>
                      )}
                    </Fragment>
                  )
                })}
              </tbody>
            </table>
          </div>

          <div className="flex items-center justify-between text-xs">
            <span className="text-slate-600 dark:text-slate-400">
              {t('vulnerabilities.pageInfo', { total: data.total })}
            </span>
            <span className="flex gap-2">
              <button
                type="button"
                disabled={page <= 1}
                onClick={() => setPage((value) => value - 1)}
                className={smallButton}
              >
                {t('common.previous')}
              </button>
              <button
                type="button"
                disabled={page * data.page_size >= data.total}
                onClick={() => setPage((value) => value + 1)}
                className={smallButton}
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
