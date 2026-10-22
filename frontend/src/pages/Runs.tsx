// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>

import { useTranslation } from 'react-i18next'
import { Link } from 'react-router-dom'

import { ApiError } from '../api/client'
import { ACTIVE_RUN_STATUSES, useCancelRun, useRuns, useScanEverything } from '../api/runs'
import StatusBadge from '../components/StatusBadge'
import { primaryButton, secondaryButton, smallButton } from '../lib/buttons'
import { formatDateTime } from '../lib/format'

export default function Runs() {
  const { t, i18n } = useTranslation()
  const { data, isLoading, isError, error } = useRuns()
  const scanEverything = useScanEverything()
  const cancelRun = useCancelRun()

  return (
    <section className="space-y-4">
      <header className="flex flex-wrap items-start justify-between gap-3">
        <div className="space-y-1">
          <h1 className="text-2xl font-semibold tracking-tight">{t('runs.title')}</h1>
          <p className="text-sm text-slate-600 dark:text-slate-400">{t('runs.description')}</p>
        </div>
        <div className="flex flex-wrap gap-2">
          <button
            type="button"
            onClick={() => scanEverything.mutate(false)}
            disabled={scanEverything.isPending}
            className={primaryButton}
          >
            {scanEverything.isPending ? t('common.loading') : t('runs.scanEverything')}
          </button>
          <button
            type="button"
            onClick={() => scanEverything.mutate(true)}
            disabled={scanEverything.isPending}
            title={t('runs.forceHint')}
            className={secondaryButton}
          >
            {t('runs.scanEverythingForced')}
          </button>
        </div>
      </header>

      {scanEverything.isError && (
        <p className="rounded-md border border-red-300 bg-red-50 px-3 py-2 text-sm text-red-900 dark:border-red-500/40 dark:bg-red-500/10 dark:text-red-100">
          {scanEverything.error instanceof ApiError
            ? scanEverything.error.message
            : String(scanEverything.error)}
        </p>
      )}

      {isLoading && <p className="text-sm text-slate-600 dark:text-slate-400">{t('common.loading')}</p>}

      {isError && (
        <p className="rounded-md border border-red-300 bg-red-50 px-3 py-2 text-sm text-red-900 dark:border-red-500/40 dark:bg-red-500/10 dark:text-red-100">
          {error instanceof ApiError ? error.message : String(error)}
        </p>
      )}

      {data && data.items.length === 0 && (
        <div className="rounded-lg border border-dashed border-slate-300 p-6 text-sm dark:border-slate-700">
          <p className="font-medium">{t('runs.emptyTitle')}</p>
          <p className="mt-1 text-slate-600 dark:text-slate-400">{t('runs.emptyDescription')}</p>
        </div>
      )}

      {data && data.items.length > 0 && (
        <div className="overflow-x-auto rounded-lg border border-slate-200 dark:border-slate-800">
          <table className="w-full text-left text-sm">
            <thead className="bg-slate-50 text-xs uppercase text-slate-500 dark:bg-slate-900 dark:text-slate-400">
              <tr>
                <th className="px-3 py-2">{t('runs.table.run')}</th>
                <th className="px-3 py-2">{t('runs.table.target')}</th>
                <th className="px-3 py-2">{t('runs.table.trigger')}</th>
                <th className="px-3 py-2">{t('runs.table.status')}</th>
                <th className="px-3 py-2">{t('runs.table.result')}</th>
                <th className="px-3 py-2">{t('runs.table.started')}</th>
                <th className="px-3 py-2 text-right">{t('targets.table.actions')}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
              {data.items.map((run) => (
                <tr key={run.id}>
                  <td className="px-3 py-2">
                    <Link to={`/runs/${run.id}`} className="font-medium underline hover:no-underline">
                      #{run.id}
                    </Link>
                  </td>
                  <td className="px-3 py-2">{run.target_name ?? t('runs.allTargets')}</td>
                  <td className="px-3 py-2">{t(`runs.trigger.${run.trigger}`)}</td>
                  <td className="px-3 py-2">
                    <StatusBadge status={run.status} kind="run" />
                  </td>
                  <td className="px-3 py-2">
                    {t('runs.table.counts', {
                      succeeded: run.succeeded,
                      failed: run.failed,
                      skipped: run.skipped,
                      total: run.total,
                    })}
                  </td>
                  <td className="px-3 py-2">{formatDateTime(run.started_at ?? run.created_at, i18n.language)}</td>
                  <td className="px-3 py-2 text-right">
                    {ACTIVE_RUN_STATUSES.includes(run.status) && (
                      <button
                        type="button"
                        onClick={() => cancelRun.mutate(run.id)}
                        disabled={cancelRun.isPending}
                        className={smallButton}
                      >
                        {t('runs.cancel')}
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  )
}
