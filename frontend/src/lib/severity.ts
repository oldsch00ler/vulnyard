// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>

import type { Severity, SeverityCounts } from '../api/dashboard'

/**
 * Severity is an ordered scale, so the order is fixed everywhere: the stack, the
 * legend, the badges and the tables all read critical first.
 */
export const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'unassigned']

/** CSS variables from index.css; both modes are validated against their surface. */
export const SEVERITY_VAR: Record<Severity, string> = {
  critical: 'var(--color-severity-critical)',
  high: 'var(--color-severity-high)',
  medium: 'var(--color-severity-medium)',
  low: 'var(--color-severity-low)',
  unassigned: 'var(--color-severity-unassigned)',
}

/** Badge classes: the colour is a filled chip, the number stays in ink. */
export const SEVERITY_CHIP: Record<Severity, string> = {
  critical: 'bg-severity-critical',
  high: 'bg-severity-high',
  medium: 'bg-severity-medium',
  low: 'bg-severity-low',
  unassigned: 'bg-severity-unassigned',
}

export function totalFindings(counts: SeverityCounts): number {
  return SEVERITY_ORDER.reduce((sum, severity) => sum + counts[severity], 0)
}

/** Severity name as Dependency-Track reports it, lower-cased for our keys. */
export function normaliseSeverity(value: string): Severity {
  const lowered = value.toLowerCase()
  return (SEVERITY_ORDER as string[]).includes(lowered) ? (lowered as Severity) : 'unassigned'
}
