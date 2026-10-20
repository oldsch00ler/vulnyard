// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>

import { Suspense, lazy } from 'react'
import { useTranslation } from 'react-i18next'

import type { TrendPoint } from '../api/dashboard'

// The charting library is only needed on the pages that draw a trend, so it is
// loaded separately instead of in the initial bundle.
const TrendChart = lazy(() => import('./TrendChart'))

interface LazyTrendChartProps {
  points: TrendPoint[]
  height?: number
}

export default function LazyTrendChart({ points, height }: LazyTrendChartProps) {
  const { t } = useTranslation()
  return (
    <Suspense fallback={<p className="text-sm">{t('common.loading')}</p>}>
      <TrendChart points={points} height={height} />
    </Suspense>
  )
}
