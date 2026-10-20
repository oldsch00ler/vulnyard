// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>

import { useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { NavLink } from 'react-router-dom'

import { type AppStatus, useIdentity } from '../api/status'
import { chooseLocale, languages, matchLocale } from '../i18n'
import ConfigBanner from './ConfigBanner'

interface LayoutProps {
  status: AppStatus | undefined
  children: React.ReactNode
}

const NAV_ITEMS = [
  { to: '/', labelKey: 'nav.dashboard' },
  { to: '/projects', labelKey: 'nav.projects' },
  { to: '/vulnerabilities', labelKey: 'nav.vulnerabilities' },
  { to: '/targets', labelKey: 'nav.targets' },
  { to: '/runs', labelKey: 'nav.runs' },
  { to: '/settings', labelKey: 'nav.settings' },
] as const

export default function Layout({ status, children }: LayoutProps) {
  const { t, i18n } = useTranslation()
  const queryClient = useQueryClient()
  const scanRunning = (status?.worker.active_jobs ?? 0) > 0
  const identity = useIdentity(status?.runtime.auth_mode === 'proxy-header')

  return (
    <div className="flex min-h-full flex-col md:flex-row">
      <aside className="border-b border-slate-200 bg-white md:w-64 md:shrink-0 md:border-b-0 md:border-r dark:border-slate-800 dark:bg-slate-900">
        <div className="px-4 py-4">
          {/* The wordmark has its own dark variant. <picture> picks the one
              that matches the colour scheme, so only that file is downloaded. */}
          <picture>
            <source srcSet="/vulnyard-logo-dark.svg" media="(prefers-color-scheme: dark)" />
            <img
              src="/vulnyard-logo.svg"
              alt={t('app.name')}
              width={262}
              height={64}
              className="h-8 w-auto"
            />
          </picture>
          <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">{t('app.tagline')}</p>
        </div>
        <nav className="flex flex-wrap gap-1 px-2 pb-3 md:flex-col md:flex-nowrap">
          {NAV_ITEMS.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.to === '/'}
              className={({ isActive }) =>
                `rounded-md px-3 py-2 text-sm font-medium transition-colors ${
                  isActive
                    ? 'bg-slate-900 text-white dark:bg-slate-100 dark:text-slate-900'
                    : 'text-slate-700 hover:bg-slate-100 dark:text-slate-300 dark:hover:bg-slate-800'
                }`
              }
            >
              {t(item.labelKey)}
            </NavLink>
          ))}
        </nav>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex items-center justify-end gap-2 border-b border-slate-200 bg-white px-4 py-3 text-sm dark:border-slate-800 dark:bg-slate-900">
          <span
            aria-hidden="true"
            className={`size-2 rounded-full ${scanRunning ? 'bg-emerald-500' : 'bg-slate-300 dark:bg-slate-600'}`}
          />
          <span className="text-slate-600 dark:text-slate-400">
            {scanRunning ? t('header.scanRunning') : t('header.scanIdle')}
          </span>
          {/* Shown once there is something to choose from (SPEC 15). */}
          {languages.length > 1 && (
            <label className="ml-2 flex items-center gap-1 border-l border-slate-200 pl-3 text-slate-600 dark:border-slate-700 dark:text-slate-400">
              <span className="sr-only">{t('language.label')}</span>
              <select
                value={matchLocale(i18n.language) ?? ''}
                onChange={(event) =>
                  // Texts rendered by the backend (errors, job notes) follow the
                  // language too, so everything already loaded is fetched again.
                  void chooseLocale(event.target.value).then(() => queryClient.invalidateQueries())
                }
                className="rounded-md border border-slate-300 bg-white px-2 py-1 text-xs dark:border-slate-700 dark:bg-slate-900"
              >
                {languages.map((language) => (
                  <option key={language.locale} value={language.locale} lang={language.locale}>
                    {language.name}
                  </option>
                ))}
              </select>
            </label>
          )}
          {identity.data?.email && (
            <span className="ml-2 border-l border-slate-200 pl-3 text-slate-600 dark:border-slate-700 dark:text-slate-400">
              {identity.data.email}
            </span>
          )}
        </header>

        <main className="flex-1 space-y-4 px-4 py-6">
          {status && <ConfigBanner status={status} />}
          {children}
        </main>

        <footer className="border-t border-slate-200 px-4 py-3 text-xs text-slate-500 dark:border-slate-800 dark:text-slate-500">
          <span>{t('footer.credits')}</span>
          {' · '}
          <a className="underline hover:no-underline" href="https://vulnyard.eu" target="_blank" rel="noreferrer">
            {t('footer.projectSite')}
          </a>
          {' · '}
          <a className="underline hover:no-underline" href="https://zuzanak.eu" target="_blank" rel="noreferrer">
            {t('footer.authorSite')}
          </a>
        </footer>
      </div>
    </div>
  )
}
