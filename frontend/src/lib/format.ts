// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>

/** Formatting helpers using Intl with the current locale (SPEC section 15). */

export function formatDateTime(value: string | null, locale: string): string {
  if (!value) {
    return '—'
  }
  return new Intl.DateTimeFormat(locale, { dateStyle: 'short', timeStyle: 'short' }).format(
    new Date(value),
  )
}

/** A plain date (no time), for values that are a day rather than an instant. */
export function formatDate(value: string | null, locale: string): string {
  if (!value) {
    return '—'
  }
  return new Intl.DateTimeFormat(locale, { dateStyle: 'medium' }).format(new Date(value))
}

export function formatDuration(milliseconds: number | null, locale: string): string {
  if (milliseconds === null) {
    return '—'
  }
  const seconds = milliseconds / 1000
  const unit = (value: number, name: 'second' | 'minute') =>
    new Intl.NumberFormat(locale, {
      style: 'unit',
      unit: name,
      unitDisplay: 'short',
      maximumFractionDigits: 1,
    }).format(value)
  if (seconds < 60) {
    return unit(seconds, 'second')
  }
  return `${unit(Math.floor(seconds / 60), 'minute')} ${unit(Math.round(seconds % 60), 'second')}`
}

export function formatBytes(bytes: number | null, locale: string): string {
  if (bytes === null) {
    return '—'
  }
  const units = ['B', 'kB', 'MB']
  let value = bytes
  let unit = 0
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024
    unit += 1
  }
  return `${new Intl.NumberFormat(locale, { maximumFractionDigits: 1 }).format(value)} ${units[unit]}`
}

export function shortSha(sha: string | null): string {
  return sha ? sha.slice(0, 8) : '—'
}
