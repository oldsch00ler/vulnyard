// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>

/**
 * Human readable description of the common cron expressions offered as
 * presets. Anything else is shown as the raw expression; the text itself comes
 * from the translation catalogue, this module only decides which key to use.
 */
export interface CronDescription {
  key: string
  params?: Record<string, string | number>
}

const DAILY = /^(\d{1,2}) (\d{1,2}) \* \* \*$/
const HOURLY = /^(\d{1,2}) \* \* \* \*$/
const EVERY_N_HOURS = /^(\d{1,2}) \*\/(\d{1,2}) \* \* \*$/
const WEEKLY = /^(\d{1,2}) (\d{1,2}) \* \* ([a-z]{3}|\d)$/i

const WEEKDAY_KEYS = ['sun', 'mon', 'tue', 'wed', 'thu', 'fri', 'sat'] as const

export function describeCron(expression: string | null): CronDescription {
  if (!expression) {
    return { key: 'targets.schedule.manual' }
  }

  const daily = DAILY.exec(expression)
  if (daily) {
    return { key: 'targets.schedule.daily', params: { time: formatTime(daily[2], daily[1]) } }
  }

  const everyNHours = EVERY_N_HOURS.exec(expression)
  if (everyNHours) {
    return { key: 'targets.schedule.everyHours', params: { count: Number(everyNHours[2]) } }
  }

  if (HOURLY.test(expression)) {
    return { key: 'targets.schedule.hourly' }
  }

  const weekly = WEEKLY.exec(expression)
  if (weekly) {
    const raw = weekly[3].toLowerCase()
    const day = /^\d$/.test(raw) ? WEEKDAY_KEYS[Number(raw) % 7] : raw
    if ((WEEKDAY_KEYS as readonly string[]).includes(day)) {
      return {
        key: `targets.schedule.weekly.${day}`,
        params: { time: formatTime(weekly[2], weekly[1]) },
      }
    }
  }

  return { key: 'targets.schedule.custom', params: { expression } }
}

function formatTime(hour: string, minute: string): string {
  return `${hour.padStart(2, '0')}:${minute.padStart(2, '0')}`
}

/** Presets offered in the form; `null` means manual runs only. */
export const CRON_PRESETS: Array<{ value: string | null; labelKey: string }> = [
  { value: '0 2 * * *', labelKey: 'targets.cronPreset.dailyNight' },
  { value: '0 6 * * *', labelKey: 'targets.cronPreset.dailyMorning' },
  { value: '0 */6 * * *', labelKey: 'targets.cronPreset.everySixHours' },
  { value: '0 3 * * mon', labelKey: 'targets.cronPreset.weeklyMonday' },
  { value: null, labelKey: 'targets.cronPreset.manual' },
]
