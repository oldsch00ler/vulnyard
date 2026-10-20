// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>

import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import {
  Area,
  AreaChart,
  CartesianGrid,
  Legend,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'

import type { TrendPoint } from '../api/dashboard'
import { SEVERITY_CHIP, SEVERITY_ORDER, SEVERITY_VAR } from '../lib/severity'

interface TrendChartProps {
  points: TrendPoint[]
  /** Height in pixels; the detail page uses a smaller chart. */
  height?: number
}

/**
 * Stacked area of findings per severity over time.
 *
 * Severity is an ordered scale, so the stack order is fixed (critical at the
 * bottom) and never re-sorted. The chart ships the mitigations the palette needs:
 * a legend, a 2px surface gap between stacked fills, a crosshair tooltip and a
 * table view of the same numbers.
 */
export default function TrendChart({ points, height = 260 }: TrendChartProps) {
  const { t, i18n } = useTranslation()
  const [asTable, setAsTable] = useState(false)

  const formatDay = (value: string) =>
    new Intl.DateTimeFormat(i18n.language, { day: 'numeric', month: 'numeric' }).format(
      new Date(value),
    )

  if (points.length === 0) {
    return (
      <p className="text-sm text-slate-600 dark:text-slate-400">{t('dashboard.trend.empty')}</p>
    )
  }

  return (
    <div className="space-y-2">
      <div className="flex justify-end">
        <button
          type="button"
          onClick={() => setAsTable((value) => !value)}
          className="text-xs underline hover:no-underline"
          aria-pressed={asTable}
        >
          {asTable ? t('dashboard.trend.showChart') : t('dashboard.trend.showTable')}
        </button>
      </div>

      {asTable ? (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="text-slate-500 dark:text-slate-400">
              <tr>
                <th className="py-1 pr-3">{t('dashboard.trend.day')}</th>
                {SEVERITY_ORDER.map((severity) => (
                  <th key={severity} className="py-1 pr-3 text-right">
                    {t(`severity.${severity}`)}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
              {points.map((point) => (
                <tr key={point.date}>
                  <td className="py-1 pr-3">{formatDay(point.date)}</td>
                  {SEVERITY_ORDER.map((severity) => (
                    <td key={severity} className="py-1 pr-3 text-right tabular-nums">
                      {point[severity]}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <ResponsiveContainer width="100%" height={height}>
          <AreaChart data={points} margin={{ top: 8, right: 8, bottom: 0, left: 0 }}>
            {/* Recessive grid: horizontal guides only. */}
            <CartesianGrid vertical={false} stroke="currentColor" strokeOpacity={0.12} />
            <XAxis
              dataKey="date"
              tickFormatter={formatDay}
              tickLine={false}
              axisLine={false}
              tick={{ fontSize: 11, fill: 'currentColor', opacity: 0.7 }}
              minTickGap={24}
            />
            <YAxis
              tickLine={false}
              axisLine={false}
              width={36}
              tick={{ fontSize: 11, fill: 'currentColor', opacity: 0.7 }}
            />
            <Tooltip
              // Crosshair plus the counts per severity for that day. The default
              // tooltip paints each row in the series stroke, which here is the
              // surface colour (it draws the gap between stacked fills) - so it
              // rendered white on white. Our own content keeps text in ink and
              // lets a colour chip carry the severity.
              cursor={{ stroke: 'currentColor', strokeOpacity: 0.3, strokeWidth: 1 }}
              content={<DayTooltip />}
            />
            {/* Own content for the same reason: the default icon takes the
                series stroke, which here is the surface colour. */}
            <Legend content={<SeverityLegend />} />
            {SEVERITY_ORDER.map((severity) => (
              <Area
                key={severity}
                type="monotone"
                dataKey={severity}
                stackId="findings"
                fill={SEVERITY_VAR[severity]}
                fillOpacity={0.9}
                // 2px gap in the surface colour between stacked fills.
                stroke="var(--color-chart-surface)"
                strokeWidth={2}
                activeDot={{ r: 4, stroke: 'var(--color-chart-surface)', strokeWidth: 2 }}
              />
            ))}
          </AreaChart>
        </ResponsiveContainer>
      )}
    </div>
  )
}

interface DayTooltipProps {
  active?: boolean
  payload?: { payload?: TrendPoint }[]
  label?: string | number
}

/**
 * Tooltip listing the findings of one day per severity.
 *
 * Severities with no findings are left out so the reader sees what is there,
 * and the order stays fixed (critical first) so rows never jump around.
 */
function DayTooltip({ active, payload, label }: DayTooltipProps) {
  const { t, i18n } = useTranslation()
  const point = payload?.[0]?.payload
  if (!active || !point) return null

  const rows = SEVERITY_ORDER.filter((severity) => point[severity] > 0)
  const total = SEVERITY_ORDER.reduce((sum, severity) => sum + point[severity], 0)
  const day = new Intl.DateTimeFormat(i18n.language, { dateStyle: 'medium' }).format(
    new Date(String(label ?? point.date)),
  )

  return (
    <div className="rounded-lg border border-slate-400/40 bg-chart-surface px-3 py-2 text-xs shadow-lg">
      <p className="font-medium text-slate-900 dark:text-slate-100">{day}</p>
      <p className="mb-1 text-slate-500 dark:text-slate-400">
        {t('dashboard.trend.projects', { count: point.projects })}
      </p>
      {rows.length === 0 ? (
        <p className="text-slate-600 dark:text-slate-400">{t('dashboard.trend.noFindings')}</p>
      ) : (
        <>
          <table className="w-full">
            <tbody>
              {rows.map((severity) => (
                <tr key={severity}>
                  <td className="py-0.5 pr-3">
                    <span className="flex items-center gap-1.5 text-slate-700 dark:text-slate-300">
                      <span
                        aria-hidden="true"
                        className={`inline-block size-2.5 rounded-xs ${SEVERITY_CHIP[severity]}`}
                      />
                      {t(`severity.${severity}`)}
                    </span>
                  </td>
                  <td className="py-0.5 text-right font-medium tabular-nums text-slate-900 dark:text-slate-100">
                    {point[severity]}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <p className="mt-1 border-t border-slate-200 pt-1 text-right tabular-nums text-slate-600 dark:border-slate-700 dark:text-slate-400">
            {t('dashboard.trend.total')} {total}
          </p>
        </>
      )}
    </div>
  )
}

/** Legend of the fixed severity scale; identity is never colour alone. */
function SeverityLegend() {
  const { t } = useTranslation()

  return (
    <ul className="flex flex-wrap justify-center gap-x-4 gap-y-1 pt-2">
      {SEVERITY_ORDER.map((severity) => (
        <li
          key={severity}
          className="flex items-center gap-1.5 text-xs text-slate-700 dark:text-slate-300"
        >
          <span
            aria-hidden="true"
            className={`inline-block size-2.5 rounded-xs ${SEVERITY_CHIP[severity]}`}
          />
          {t(`severity.${severity}`)}
        </li>
      ))}
    </ul>
  )
}
