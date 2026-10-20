// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>

import { useTranslation } from 'react-i18next'

import type { JobStatus, RunStatus } from '../api/runs'

const TONES: Record<string, string> = {
  queued: 'bg-slate-200 text-slate-800 dark:bg-slate-700 dark:text-slate-100',
  running: 'bg-sky-100 text-sky-900 dark:bg-sky-500/20 dark:text-sky-100',
  cloning: 'bg-sky-100 text-sky-900 dark:bg-sky-500/20 dark:text-sky-100',
  scanning: 'bg-sky-100 text-sky-900 dark:bg-sky-500/20 dark:text-sky-100',
  uploading: 'bg-sky-100 text-sky-900 dark:bg-sky-500/20 dark:text-sky-100',
  processing: 'bg-sky-100 text-sky-900 dark:bg-sky-500/20 dark:text-sky-100',
  done: 'bg-emerald-100 text-emerald-900 dark:bg-emerald-500/20 dark:text-emerald-100',
  skipped: 'bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300',
  failed: 'bg-red-100 text-red-900 dark:bg-red-500/20 dark:text-red-100',
  cancelled: 'bg-amber-100 text-amber-900 dark:bg-amber-500/20 dark:text-amber-100',
}

interface StatusBadgeProps {
  status: RunStatus | JobStatus
  kind: 'run' | 'job'
}

/** Status as a coloured badge that always carries its text label too. */
export default function StatusBadge({ status, kind }: StatusBadgeProps) {
  const { t } = useTranslation()
  const tone = TONES[status] ?? TONES.queued

  return (
    <span className={`inline-block rounded-full px-2 py-0.5 text-xs font-medium ${tone}`}>
      {t(`runs.${kind}Status.${status}`)}
    </span>
  )
}
