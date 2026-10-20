// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>

import { useEffect } from 'react'
import { useTranslation } from 'react-i18next'
import { Navigate, Route, Routes } from 'react-router-dom'

import { useStatus } from './api/status'
import Layout from './components/Layout'
import { applyLocale } from './i18n'
import Dashboard from './pages/Dashboard'
import ProjectDetail from './pages/ProjectDetail'
import Projects from './pages/Projects'
import RunDetail from './pages/RunDetail'
import Runs from './pages/Runs'
import Settings from './pages/Settings'
import Targets from './pages/Targets'
import Vulnerabilities from './pages/Vulnerabilities'

export default function App() {
  const { t } = useTranslation()
  const { data: status, isLoading, isError, refetch } = useStatus()

  // The language comes from the runtime configuration, never from the build.
  useEffect(() => {
    applyLocale(status?.runtime.default_locale)
  }, [status?.runtime.default_locale])

  return (
    <Layout status={status}>
      {isLoading && <p className="text-sm text-slate-600 dark:text-slate-400">{t('status.loading')}</p>}

      {isError && (
        <div className="rounded-lg border border-red-300 bg-red-50 px-4 py-3 text-sm text-red-900 dark:border-red-500/40 dark:bg-red-500/10 dark:text-red-100">
          <p>{t('status.error')}</p>
          <button
            type="button"
            onClick={() => void refetch()}
            className="mt-2 rounded-md border border-red-400 px-2 py-1 text-xs font-medium hover:bg-red-100 dark:hover:bg-red-500/20"
          >
            {t('status.retry')}
          </button>
        </div>
      )}

      <Routes>
        <Route path="/" element={<Dashboard />} />
        <Route path="/projects" element={<Projects />} />
        <Route path="/projects/:projectId" element={<ProjectDetail />} />
        <Route path="/vulnerabilities" element={<Vulnerabilities />} />
        <Route path="/targets" element={<Targets />} />
        <Route path="/runs" element={<Runs />} />
        <Route path="/runs/:runId" element={<RunDetail />} />
        <Route path="/settings" element={<Settings />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </Layout>
  )
}
