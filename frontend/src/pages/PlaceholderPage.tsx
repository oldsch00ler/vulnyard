// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>

import { useTranslation } from 'react-i18next'

interface PlaceholderPageProps {
  titleKey: string
  descriptionKey: string
}

/** Page shell for parts that are implemented in the following milestones. */
export default function PlaceholderPage({ titleKey, descriptionKey }: PlaceholderPageProps) {
  const { t } = useTranslation()

  return (
    <section className="space-y-4">
      <header className="space-y-1">
        <h1 className="text-2xl font-semibold tracking-tight">{t(titleKey)}</h1>
        <p className="text-sm text-slate-600 dark:text-slate-400">{t(descriptionKey)}</p>
      </header>

      <div className="rounded-lg border border-dashed border-slate-300 bg-white/60 p-6 dark:border-slate-700 dark:bg-slate-900/60">
        <p className="font-medium">{t('placeholder.title')}</p>
        <p className="mt-1 text-sm text-slate-600 dark:text-slate-400">{t('placeholder.description')}</p>
      </div>
    </section>
  )
}
