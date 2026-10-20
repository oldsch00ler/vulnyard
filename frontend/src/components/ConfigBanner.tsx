// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>

import { useTranslation } from 'react-i18next'

import type { AppStatus } from '../api/status'

interface ConfigBannerProps {
  status: AppStatus
}

/**
 * Banner for incomplete configuration (SPEC 3.1/12). The list of variables
 * comes from the backend, the texts from the catalogue.
 */
export default function ConfigBanner({ status }: ConfigBannerProps) {
  const { t } = useTranslation()
  const missing = status.config.missing
  const missingTools = [
    !status.tools.trivy.available ? t('banner.trivyMissing') : null,
    !status.tools.git.available ? t('banner.gitMissing') : null,
  ].filter((message): message is string => message !== null)

  const showAuthWarning = status.runtime.auth_mode === 'none'

  if (missing.length === 0 && missingTools.length === 0 && !showAuthWarning) {
    return null
  }

  return (
    <div className="space-y-3">
      {missing.length > 0 && (
        <Notice tone="warning" title={t('banner.configMissingTitle')}>
          {t('banner.configMissing', { count: missing.length, variables: missing.join(', ') })}
        </Notice>
      )}

      {missingTools.length > 0 && (
        <Notice tone="warning" title={t('banner.toolMissingTitle')}>
          <ul className="list-inside list-disc space-y-1">
            {missingTools.map((message) => (
              <li key={message}>{message}</li>
            ))}
          </ul>
        </Notice>
      )}

      {showAuthWarning && (
        <Notice tone="info" title={t('banner.authNoneTitle')}>
          {t('banner.authNone')}
        </Notice>
      )}
    </div>
  )
}

interface NoticeProps {
  tone: 'warning' | 'info'
  title: string
  children: React.ReactNode
}

function Notice({ tone, title, children }: NoticeProps) {
  const tones = {
    warning:
      'border-amber-300 bg-amber-50 text-amber-900 dark:border-amber-500/40 dark:bg-amber-500/10 dark:text-amber-100',
    info: 'border-sky-300 bg-sky-50 text-sky-900 dark:border-sky-500/40 dark:bg-sky-500/10 dark:text-sky-100',
  } as const

  return (
    <div role="status" className={`rounded-lg border px-4 py-3 text-sm ${tones[tone]}`}>
      <p className="font-semibold">{title}</p>
      <div className="mt-1">{children}</div>
    </div>
  )
}
