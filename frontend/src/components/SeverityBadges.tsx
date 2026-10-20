// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>

import { useTranslation } from 'react-i18next'

import type { Severity, SeverityCounts } from '../api/dashboard'
import { SEVERITY_CHIP, SEVERITY_ORDER } from '../lib/severity'

interface SeverityBadgesProps {
  counts: SeverityCounts
  /** Hide severities with no findings (used in dense tables). */
  compact?: boolean
}

/**
 * Counts per severity. The colour is a small chip and the number is always
 * written next to it, so the meaning never rests on colour alone (SPEC 12).
 */
export default function SeverityBadges({ counts, compact = false }: SeverityBadgesProps) {
  const { t } = useTranslation()
  const shown = compact ? SEVERITY_ORDER.filter((severity) => counts[severity] > 0) : SEVERITY_ORDER

  if (shown.length === 0) {
    return <span className="text-xs text-slate-500 dark:text-slate-400">{t('severity.none')}</span>
  }

  return (
    <ul className="flex flex-wrap items-center gap-2">
      {shown.map((severity) => (
        <li key={severity} className="flex items-center gap-1 text-xs">
          <span
            aria-hidden="true"
            className={`inline-block size-2.5 rounded-sm ${SEVERITY_CHIP[severity]}`}
          />
          <span className="tabular-nums font-medium">{counts[severity]}</span>
          <span className="text-slate-600 dark:text-slate-400">{t(`severity.${severity}`)}</span>
        </li>
      ))}
    </ul>
  )
}

interface SeverityLabelProps {
  severity: Severity | string
}

/** One severity as a chip plus its name, for a findings table row. */
export function SeverityLabel({ severity }: SeverityLabelProps) {
  const { t } = useTranslation()
  const key = (SEVERITY_ORDER as string[]).includes(String(severity).toLowerCase())
    ? (String(severity).toLowerCase() as Severity)
    : 'unassigned'

  return (
    <span className="inline-flex items-center gap-1.5 whitespace-nowrap">
      <span aria-hidden="true" className={`inline-block size-2.5 rounded-sm ${SEVERITY_CHIP[key]}`} />
      {t(`severity.${key}`)}
    </span>
  )
}
