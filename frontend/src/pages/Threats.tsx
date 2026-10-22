// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>

import { Fragment, useState } from 'react'
import { useTranslation } from 'react-i18next'

import { ApiError } from '../api/client'
import { useStatus } from '../api/status'
import {
  THREAT_REASONS,
  type ThreatItem,
  type ThreatList,
  type ThreatReason,
  useThreats,
} from '../api/threats'
import { SeverityLabel } from '../components/SeverityBadges'
import VulnerabilityDetail from '../components/VulnerabilityDetail'
import { smallButton } from '../lib/buttons'
import { formatDate } from '../lib/format'

const EPSS_THRESHOLDS = [0.01, 0.05, 0.1, 0.25, 0.5]
const NEW_DAYS = [7, 14, 30, 90]

/** Accent per reason; exploited is the most urgent one. */
const REASON_ACCENT: Record<ThreatReason, string> = {
  exploited: 'bg-severity-critical',
  likely: 'bg-severity-high',
  new: 'bg-severity-low',
}
const REASON_BADGE: Record<ThreatReason, string> = {
  exploited: 'bg-red-100 text-red-900 dark:bg-red-500/20 dark:text-red-100',
  likely: 'bg-orange-100 text-orange-900 dark:bg-orange-500/20 dark:text-orange-100',
  new: 'bg-blue-100 text-blue-900 dark:bg-blue-500/20 dark:text-blue-100',
}

export default function Threats() {
  const { t, i18n } = useTranslation()
  const [reason, setReason] = useState<ThreatReason | null>(null)
  const [epss, setEpss] = useState(0.1)
  const [days, setDays] = useState(7)
  const [page, setPage] = useState(1)
  const [expanded, setExpanded] = useState<string | null>(null)
  const [ignoring, setIgnoring] = useState<string | null>(null)

  const { data, isLoading, isError, error } = useThreats(reason, epss, days, page)
  const { data: status } = useStatus()
  const dtUiUrl = status?.runtime.dt_ui_url ?? null

  const inputClass =
    'rounded-md border border-slate-300 bg-white px-2 py-1 text-sm dark:border-slate-700 dark:bg-slate-900'
  const percent = (value: number) => `${(value * 100).toFixed(value < 0.1 ? 1 : 0)} %`

  return (
    <section className="space-y-4">
      <header className="space-y-1">
        <h1 className="text-2xl font-semibold tracking-tight">{t('threats.title')}</h1>
        <p className="text-sm text-slate-600 dark:text-slate-400">{t('threats.description')}</p>
      </header>

      {/* One card per reason; a card also filters the list. */}
      <div className="grid gap-3 sm:grid-cols-3">
        {THREAT_REASONS.map((name) => {
          const selected = reason === name
          return (
            <button
              key={name}
              type="button"
              aria-pressed={selected}
              onClick={() => {
                setReason(selected ? null : name)
                setPage(1)
              }}
              className={`relative overflow-hidden rounded-lg border bg-white p-4 pl-5 text-left enabled:hover:bg-slate-50 dark:bg-slate-900 dark:enabled:hover:bg-slate-800 ${
                selected
                  ? 'border-slate-900 ring-1 ring-slate-900 dark:border-slate-100 dark:ring-slate-100'
                  : 'border-slate-200 dark:border-slate-800'
              }`}
            >
              <span aria-hidden="true" className={`absolute inset-y-0 left-0 w-1 ${REASON_ACCENT[name]}`} />
              <p className="text-2xl font-semibold tabular-nums">{data ? data.counts[name] : '–'}</p>
              <p className="text-sm font-medium">{t(`threats.reason.${name}`)}</p>
              <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
                {t(`threats.reasonHint.${name}`, { epss: percent(epss), days })}
              </p>
            </button>
          )
        })}
      </div>

      <div className="flex flex-wrap items-end gap-3">
        <label className="flex flex-col gap-1 text-xs">
          {t('threats.filter.epss')}
          <select
            value={epss}
            onChange={(event) => {
              setEpss(Number(event.target.value))
              setPage(1)
            }}
            className={inputClass}
          >
            {EPSS_THRESHOLDS.map((value) => (
              <option key={value} value={value}>
                {t('threats.filter.epssOption', { value: percent(value) })}
              </option>
            ))}
          </select>
        </label>
        <label className="flex flex-col gap-1 text-xs">
          {t('threats.filter.days')}
          <select
            value={days}
            onChange={(event) => {
              setDays(Number(event.target.value))
              setPage(1)
            }}
            className={inputClass}
          >
            {NEW_DAYS.map((value) => (
              <option key={value} value={value}>
                {t('threats.filter.daysOption', { count: value })}
              </option>
            ))}
          </select>
        </label>
        {reason && (
          <button
            type="button"
            onClick={() => {
              setReason(null)
              setPage(1)
            }}
            className={smallButton}
          >
            {t('threats.filter.showAll')}
          </button>
        )}
      </div>

      {data && <SourceNotices data={data} />}

      {isLoading && <p className="text-sm text-slate-600 dark:text-slate-400">{t('common.loading')}</p>}

      {isError && (
        <p className="rounded-md border border-red-300 bg-red-50 px-3 py-2 text-sm text-red-900 dark:border-red-500/40 dark:bg-red-500/10 dark:text-red-100">
          {error instanceof ApiError ? error.message : String(error)}
        </p>
      )}

      {data && data.items.length === 0 && (
        <div className="rounded-lg border border-dashed border-slate-300 p-6 text-sm dark:border-slate-700">
          <p className="font-medium">{t('threats.emptyTitle')}</p>
          <p className="mt-1 text-slate-600 dark:text-slate-400">
            {reason ? t('threats.emptyFiltered') : t('threats.emptyDescription')}
          </p>
        </div>
      )}

      {data && data.items.length > 0 && (
        <>
          <div className="overflow-x-auto rounded-lg border border-slate-200 dark:border-slate-800">
            <table className="w-full text-left text-sm">
              <thead className="bg-slate-50 text-xs uppercase text-slate-500 dark:bg-slate-900 dark:text-slate-400">
                <tr>
                  <th className="px-3 py-2">{t('threats.table.id')}</th>
                  <th className="px-3 py-2">{t('threats.table.why')}</th>
                  <th className="px-3 py-2">{t('threats.table.severity')}</th>
                  <th className="px-3 py-2 text-right">{t('threats.table.epss')}</th>
                  <th className="px-3 py-2">{t('threats.table.kev')}</th>
                  <th className="px-3 py-2">{t('threats.table.firstSeen')}</th>
                  <th className="px-3 py-2 text-right">{t('threats.table.projects')}</th>
                  <th className="px-3 py-2" />
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                {data.items.map((item) => {
                  const key = `${item.source}/${item.vuln_id}`
                  const isOpen = expanded === key
                  const isIgnoringThis = ignoring === key
                  return (
                    <Fragment key={key}>
                      <tr>
                        <td className="px-3 py-2">
                          <VulnerabilityId item={item} dtUiUrl={dtUiUrl} />
                        </td>
                        <td className="px-3 py-2">
                          <span className="flex flex-wrap gap-1">
                            {item.reasons.map((name) => (
                              <span
                                key={name}
                                className={`whitespace-nowrap rounded-sm px-1.5 py-0.5 text-[11px] font-medium ${REASON_BADGE[name]}`}
                              >
                                {t(`threats.badge.${name}`)}
                              </span>
                            ))}
                          </span>
                        </td>
                        <td className="px-3 py-2">
                          <SeverityLabel severity={item.severity} />
                        </td>
                        <td className="px-3 py-2 text-right tabular-nums">
                          {item.epss_score !== null ? percent(item.epss_score) : '—'}
                          {item.epss_percentile !== null && (
                            <span className="block text-[11px] text-slate-500 dark:text-slate-400">
                              {t('threats.percentile', {
                                // Floor: 0.999 is "99", not a misleading "100".
                                value: Math.floor(item.epss_percentile * 100),
                              })}
                            </span>
                          )}
                        </td>
                        <td className="px-3 py-2 text-xs">
                          {item.kev ? (
                            <>
                              <span className="block">
                                {t('threats.kev.added', {
                                  date: formatDate(item.kev.date_added, i18n.language),
                                })}
                              </span>
                              {item.kev.due_date && (
                                <span className="block text-slate-500 dark:text-slate-400">
                                  {t('threats.kev.due', {
                                    date: formatDate(item.kev.due_date, i18n.language),
                                  })}
                                </span>
                              )}
                              {item.kev.ransomware && (
                                <span className="mt-1 inline-block rounded-sm bg-red-700 px-1.5 py-0.5 text-[11px] font-medium text-white">
                                  {t('threats.kev.ransomware')}
                                </span>
                              )}
                            </>
                          ) : (
                            '—'
                          )}
                        </td>
                        <td className="px-3 py-2 text-xs">{formatDate(item.first_seen, i18n.language)}</td>
                        <td className="px-3 py-2 text-right tabular-nums">{item.affected_project_count}</td>
                        <td className="px-3 py-2 text-right">
                          <span className="flex justify-end gap-2">
                            <button
                              type="button"
                              onClick={() => setExpanded(isOpen ? null : key)}
                              aria-expanded={isOpen}
                              className={smallButton}
                            >
                              {isOpen ? t('vulnerabilities.hideProjects') : t('vulnerabilities.showProjects')}
                            </button>
                            <button
                              type="button"
                              onClick={() => {
                                setIgnoring(isIgnoringThis ? null : key)
                                // The pattern suggestions come from the affected
                                // components, so the row has to be open.
                                if (!isIgnoringThis) {
                                  setExpanded(key)
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
                          <td colSpan={8} className="px-3 py-2">
                            <VulnerabilityDetail
                              source={item.source}
                              vulnId={item.vuln_id}
                              ignoring={isIgnoringThis}
                              onIgnoreClose={() => setIgnoring(null)}
                            >
                              {item.kev && (
                                <div className="mb-3 max-w-3xl text-xs">
                                  <p className="font-medium">
                                    {t('threats.kev.detailTitle', { cve: item.kev.cve_id })}
                                    {item.kev.name && ` · ${item.kev.name}`}
                                  </p>
                                  {item.kev.required_action && (
                                    <p className="mt-1 text-slate-600 dark:text-slate-400">
                                      {t('threats.kev.requiredAction')}{' '}
                                      <span lang="en">{item.kev.required_action}</span>
                                    </p>
                                  )}
                                </div>
                              )}
                            </VulnerabilityDetail>
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
              {t('threats.pageInfo', { total: data.total })}
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

/** The id, linked to Dependency-Track, with its CVE when it is reported under another id. */
function VulnerabilityId({ item, dtUiUrl }: { item: ThreatItem; dtUiUrl: string | null }) {
  const { t } = useTranslation()
  const otherCves = item.cve_ids.filter((cve) => cve !== item.vuln_id.toUpperCase())
  return (
    <>
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
        {otherCves.length > 0 ? otherCves.join(', ') : item.source}
      </span>
      {item.newer_version_available && (
        <span className="block text-[11px] text-emerald-700 dark:text-emerald-300">
          {t('threats.newerVersion')}
        </span>
      )}
    </>
  )
}

/** Where the evidence comes from, and what is missing. */
function SourceNotices({ data }: { data: ThreatList }) {
  const { t, i18n } = useTranslation()
  const warning =
    'rounded-md border border-amber-300 bg-amber-50 px-3 py-2 text-xs text-amber-900 dark:border-amber-500/40 dark:bg-amber-500/10 dark:text-amber-100'
  const note = 'text-xs text-slate-500 dark:text-slate-400'

  return (
    <div className="space-y-2">
      {!data.kev.enabled && <p className={warning}>{t('threats.notice.kevDisabled')}</p>}
      {data.kev.enabled && !data.kev.available && (
        <p className={warning}>{t('threats.notice.kevUnavailable')}</p>
      )}
      {data.kev.available && data.kev.error_code && (
        <p className={warning}>
          {t('threats.notice.kevStale', {
            date: formatDate(data.kev.fetched_at, i18n.language),
          })}
        </p>
      )}
      {!data.epss_available && <p className={warning}>{t('threats.notice.epssMissing')}</p>}
      {data.kev.available && (
        <p className={note}>
          {t('threats.notice.kevSource', {
            entries: data.kev.count,
            date: formatDate(data.kev.released_at, i18n.language),
          })}
        </p>
      )}
    </div>
  )
}
