// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>

import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'

import { ApiError } from '../api/client'
import {
  type SettingsPatch,
  useAppSettings,
  useConnectionTest,
  useSaveSettings,
  useWebhookTest,
} from '../api/settings'
import { SEVERITIES } from '../api/dashboard'
import {
  type IgnoreRule,
  type IgnoreRulePayload,
  useApplyIgnoreRules,
  useCreateIgnoreRule,
  useDeleteIgnoreRule,
  useIgnoreRules,
} from '../api/ignores'
import { useStatus } from '../api/status'
import ApiTokensSection from '../components/ApiTokensSection'
import ChipInput from '../components/ChipInput'
import IgnoreRuleForm from '../components/IgnoreRuleForm'
import IgnoreRulesTable from '../components/IgnoreRulesTable'
import { formatDateTime } from '../lib/format'

export default function Settings() {
  const { t, i18n } = useTranslation()
  const { data: status } = useStatus()
  const { data: settings, isLoading, isError, error } = useAppSettings()
  const save = useSaveSettings()
  const testSource = useConnectionTest('source')
  const testDtrack = useConnectionTest('dtrack')
  const testWebhook = useWebhookTest()
  const ignoreRules = useIgnoreRules()
  const createRule = useCreateIgnoreRule()
  const deleteRule = useDeleteIgnoreRule()
  const applyRules = useApplyIgnoreRules()
  const [ruleFormOpen, setRuleFormOpen] = useState(false)

  const [concurrency, setConcurrency] = useState(2)
  const [cron, setCron] = useState('')
  const [retention, setRetention] = useState(90)
  const [patterns, setPatterns] = useState<string[]>([])
  const [notifyEnabled, setNotifyEnabled] = useState(false)
  const [webhook, setWebhook] = useState('')
  const [minSeverity, setMinSeverity] = useState('high')

  useEffect(() => {
    if (!settings) {
      return
    }
    setConcurrency(settings.scan_concurrency)
    setCron(settings.default_schedule_cron ?? '')
    setRetention(settings.history_retention_days)
    setPatterns(settings.global_exclude_patterns)
    setNotifyEnabled(settings.notifications.enabled)
    setMinSeverity(settings.notifications.min_severity)
    // The stored webhook never comes back in full, so the field starts empty
    // and an empty field means "keep what is stored".
    setWebhook('')
  }, [settings])

  const submit = () => {
    const patch: SettingsPatch = {
      scan_concurrency: concurrency,
      default_schedule_cron: cron.trim() ? cron.trim() : null,
      history_retention_days: retention,
      global_exclude_patterns: patterns,
      notifications_enabled: notifyEnabled,
      notification_min_severity: minSeverity,
    }
    if (webhook.trim()) {
      patch.notification_webhook_url = webhook.trim()
    }
    save.mutate(patch)
  }

  const inputClass =
    'w-32 rounded-md border border-slate-300 bg-white px-2 py-1 text-sm dark:border-slate-700 dark:bg-slate-900'

  return (
    <section className="space-y-4">
      <header className="space-y-1">
        <h1 className="text-2xl font-semibold tracking-tight">{t('settings.title')}</h1>
        <p className="text-sm text-slate-600 dark:text-slate-400">{t('settings.description')}</p>
      </header>

      {isLoading && <p className="text-sm text-slate-600 dark:text-slate-400">{t('common.loading')}</p>}

      {isError && (
        <p className="rounded-md border border-red-300 bg-red-50 px-3 py-2 text-sm text-red-900 dark:border-red-500/40 dark:bg-red-500/10 dark:text-red-100">
          {error instanceof ApiError ? error.message : String(error)}
        </p>
      )}

      {/* Connections with their tests. */}
      <section className="space-y-3 rounded-lg border border-slate-200 bg-white p-4 dark:border-slate-800 dark:bg-slate-900">
        <h2 className="text-lg font-semibold">{t('settings.sectionConnections')}</h2>

        <div className="flex flex-wrap items-center justify-between gap-2 text-sm">
          <div>
            <p className="font-medium">{t('settings.source')}</p>
            <p className="text-xs text-slate-600 dark:text-slate-400">
              {status?.source.configured
                ? `${status.source.url}${status.source.version ? ` · ${status.source.version}` : ''}`
                : t('settings.valueNotConfigured')}
            </p>
          </div>
          <button
            type="button"
            onClick={() => testSource.mutate()}
            disabled={testSource.isPending}
            className="rounded-md border border-slate-300 px-3 py-1.5 text-sm font-medium disabled:opacity-40 dark:border-slate-700"
          >
            {testSource.isPending ? t('common.loading') : t('settings.test.run')}
          </button>
        </div>
        {testSource.data && (
          <p
            className={`rounded-md border px-3 py-2 text-xs ${
              testSource.data.ok
                ? 'border-emerald-300 bg-emerald-50 text-emerald-900 dark:border-emerald-500/40 dark:bg-emerald-500/10 dark:text-emerald-100'
                : 'border-red-300 bg-red-50 text-red-900 dark:border-red-500/40 dark:bg-red-500/10 dark:text-red-100'
            }`}
          >
            {testSource.data.detail}
          </p>
        )}

        <div className="flex flex-wrap items-center justify-between gap-2 border-t border-slate-200 pt-3 text-sm dark:border-slate-800">
          <div>
            <p className="font-medium">{t('settings.dtrack')}</p>
            <p className="text-xs text-slate-600 dark:text-slate-400">
              {status?.dtrack.configured
                ? `${status.dtrack.version ?? '?'}${
                    status.dtrack.supported === false
                      ? ` · ${t('settings.dtrackUnsupported', {
                          minimum: status.dtrack.minimum_version ?? '4.12',
                        })}`
                      : ''
                  }`
                : t('settings.valueNotConfigured')}
            </p>
          </div>
          <button
            type="button"
            onClick={() => testDtrack.mutate()}
            disabled={testDtrack.isPending}
            className="rounded-md border border-slate-300 px-3 py-1.5 text-sm font-medium disabled:opacity-40 dark:border-slate-700"
          >
            {testDtrack.isPending ? t('common.loading') : t('settings.test.run')}
          </button>
        </div>
        {testDtrack.data && (
          <p
            className={`rounded-md border px-3 py-2 text-xs ${
              testDtrack.data.ok
                ? 'border-emerald-300 bg-emerald-50 text-emerald-900 dark:border-emerald-500/40 dark:bg-emerald-500/10 dark:text-emerald-100'
                : 'border-red-300 bg-red-50 text-red-900 dark:border-red-500/40 dark:bg-red-500/10 dark:text-red-100'
            }`}
          >
            {testDtrack.data.detail}
          </p>
        )}
      </section>

      {/* Editable settings, stored in the database. */}
      {settings && (
        <section className="space-y-3 rounded-lg border border-slate-200 bg-white p-4 dark:border-slate-800 dark:bg-slate-900">
          <h2 className="text-lg font-semibold">{t('settings.sectionScanning')}</h2>

          <label className="flex flex-wrap items-center justify-between gap-2 text-sm">
            <span>
              {t('settings.concurrency')}
              <span className="block text-xs text-slate-500 dark:text-slate-400">
                {t('settings.concurrencyHint')}
              </span>
            </span>
            <input
              type="number"
              min={1}
              max={16}
              value={concurrency}
              onChange={(event) => setConcurrency(Number(event.target.value))}
              className={inputClass}
            />
          </label>

          <label className="flex flex-wrap items-center justify-between gap-2 text-sm">
            <span>
              {t('settings.defaultCron')}
              <span className="block text-xs text-slate-500 dark:text-slate-400">
                {t('settings.defaultCronHint')}
              </span>
            </span>
            <input
              value={cron}
              placeholder="0 2 * * *"
              onChange={(event) => setCron(event.target.value)}
              className={inputClass}
            />
          </label>

          <label className="flex flex-wrap items-center justify-between gap-2 text-sm">
            <span>
              {t('settings.retention')}
              <span className="block text-xs text-slate-500 dark:text-slate-400">
                {t('settings.retentionHint')}
              </span>
            </span>
            <input
              type="number"
              min={1}
              max={3650}
              value={retention}
              onChange={(event) => setRetention(Number(event.target.value))}
              className={inputClass}
            />
          </label>

          <ChipInput
            inputId="global-exclude"
            label={t('settings.globalExcludes')}
            hint={t('settings.globalExcludesHint')}
            placeholder="sandbox/*"
            values={patterns}
            onChange={setPatterns}
          />

          {save.isError && (
            <p className="rounded-md border border-red-300 bg-red-50 px-3 py-2 text-sm text-red-900 dark:border-red-500/40 dark:bg-red-500/10 dark:text-red-100">
              {save.error instanceof ApiError ? save.error.message : String(save.error)}
            </p>
          )}
          {save.isSuccess && (
            <p className="text-xs text-emerald-700 dark:text-emerald-300">{t('settings.saved')}</p>
          )}

          <button
            type="button"
            onClick={submit}
            disabled={save.isPending}
            className="rounded-md bg-slate-900 px-3 py-2 text-sm font-medium text-white disabled:opacity-40 dark:bg-slate-100 dark:text-slate-900"
          >
            {save.isPending ? t('common.loading') : t('common.save')}
          </button>
        </section>
      )}

      {/* Chat notifications. */}
      {settings && (
        <section className="space-y-3 rounded-lg border border-slate-200 bg-white p-4 dark:border-slate-800 dark:bg-slate-900">
          <div className="flex flex-wrap items-start justify-between gap-2">
            <div>
              <h2 className="text-lg font-semibold">{t('settings.notifications.title')}</h2>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                {t('settings.notifications.description')}
              </p>
            </div>
            <button
              type="button"
              onClick={() => testWebhook.mutate(undefined)}
              disabled={testWebhook.isPending}
              className="rounded-md border border-slate-300 px-3 py-1.5 text-sm font-medium disabled:opacity-40 dark:border-slate-700"
            >
              {testWebhook.isPending ? t('common.loading') : t('settings.notifications.test')}
            </button>
          </div>

          {testWebhook.data && (
            <p
              className={`rounded-md border px-3 py-2 text-xs ${
                testWebhook.data.ok
                  ? 'border-emerald-300 bg-emerald-50 text-emerald-900 dark:border-emerald-500/40 dark:bg-emerald-500/10 dark:text-emerald-100'
                  : 'border-red-300 bg-red-50 text-red-900 dark:border-red-500/40 dark:bg-red-500/10 dark:text-red-100'
              }`}
            >
              {testWebhook.data.detail}
            </p>
          )}

          <label className="flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              checked={notifyEnabled}
              onChange={(event) => setNotifyEnabled(event.target.checked)}
            />
            {t('settings.notifications.enabled')}
          </label>

          <div className="space-y-1">
            <label htmlFor="webhook" className="block text-sm font-medium">
              {t('settings.notifications.webhook')}
            </label>
            <input
              id="webhook"
              value={webhook}
              onChange={(event) => setWebhook(event.target.value)}
              placeholder={
                settings.notifications.webhook_url_masked ??
                'https://chat.googleapis.com/v1/spaces/…/messages?key=…&token=…'
              }
              className="w-full rounded-md border border-slate-300 bg-white px-2 py-1 text-sm dark:border-slate-700 dark:bg-slate-900"
            />
            <p className="text-xs text-slate-500 dark:text-slate-400">
              {settings.notifications.webhook_configured
                ? t('settings.notifications.webhookStored', {
                    masked: settings.notifications.webhook_url_masked ?? '',
                  })
                : t('settings.notifications.webhookHint')}
            </p>
          </div>

          <label className="flex flex-wrap items-center justify-between gap-2 text-sm">
            <span>
              {t('settings.notifications.minSeverity')}
              <span className="block text-xs text-slate-500 dark:text-slate-400">
                {t('settings.notifications.minSeverityHint')}
              </span>
            </span>
            <select
              value={minSeverity}
              onChange={(event) => setMinSeverity(event.target.value)}
              className={inputClass}
            >
              {SEVERITIES.map((severity) => (
                <option key={severity} value={severity}>
                  {t(`severity.${severity}`)}
                </option>
              ))}
            </select>
          </label>
        </section>
      )}

      {/* Ignore rules: findings we decided not to act on (SPEC 12.4). */}
      <section className="rounded-lg border border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900">
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-200 px-4 py-3 dark:border-slate-800">
          <h2 className="text-sm font-semibold">{t('ignores.title')}</h2>
          <span className="flex gap-3">
            <button
              type="button"
              onClick={() => applyRules.mutate()}
              disabled={applyRules.isPending}
              className="text-xs underline hover:no-underline disabled:opacity-40"
            >
              {t('ignores.applyNow')}
            </button>
            <button
              type="button"
              onClick={() => {
                createRule.reset()
                setRuleFormOpen((open) => !open)
              }}
              className="text-xs underline hover:no-underline"
            >
              {ruleFormOpen ? t('common.cancel') : t('ignores.add')}
            </button>
          </span>
        </div>

        <div className="space-y-3 px-4 py-4">
          <p className="text-xs text-slate-600 dark:text-slate-400">{t('ignores.description')}</p>

          {applyRules.isSuccess && (
            <p className="text-xs text-slate-600 dark:text-slate-400">
              {t('ignores.applyResult', {
                suppressed: applyRules.data.suppressed,
                reverted: applyRules.data.reverted,
                projects: applyRules.data.projects,
              })}
              {applyRules.data.failed > 0 &&
                ` ${t('ignores.applyFailed', { failed: applyRules.data.failed })}`}
            </p>
          )}

          {ruleFormOpen && (
            <IgnoreRuleForm
              submitting={createRule.isPending}
              error={
                createRule.error instanceof ApiError
                  ? createRule.error.message
                  : createRule.error
                    ? String(createRule.error)
                    : null
              }
              onSubmit={(payload: IgnoreRulePayload) =>
                createRule.mutate(payload, { onSuccess: () => setRuleFormOpen(false) })
              }
              onCancel={() => setRuleFormOpen(false)}
            />
          )}

          {deleteRule.isError && (
            <p className="rounded-md border border-red-300 bg-red-50 px-3 py-2 text-sm text-red-900 dark:border-red-500/40 dark:bg-red-500/10 dark:text-red-100">
              {deleteRule.error instanceof ApiError
                ? deleteRule.error.message
                : String(deleteRule.error)}
            </p>
          )}

          {ignoreRules.data && (
            <IgnoreRulesTable
              rules={ignoreRules.data.items}
              deletingId={deleteRule.isPending ? deleteRule.variables : null}
              onDelete={(rule: IgnoreRule) => {
                if (window.confirm(t('ignores.confirmDelete', { vulnId: rule.vuln_id }))) {
                  deleteRule.mutate(rule.id)
                }
              }}
            />
          )}
        </div>
      </section>

      {/* API tokens for other systems calling the API (SPEC 13). */}
      <ApiTokensSection />

      {/* Runtime state and which variables are set. */}
      {status && (
        <section className="rounded-lg border border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900">
          <h2 className="border-b border-slate-200 px-4 py-3 text-sm font-semibold dark:border-slate-800">
            {t('settings.sectionEnvironment')}
          </h2>
          <dl className="divide-y divide-slate-100 text-sm dark:divide-slate-800">
            {[
              { label: t('settings.appVersion'), value: status.app.version },
              {
                label: t('settings.trivy'),
                value: status.tools.trivy.available
                  ? (status.tools.trivy.version ?? t('settings.valueConfigured'))
                  : t('settings.valueMissing'),
              },
              {
                label: t('settings.git'),
                value: status.tools.git.available
                  ? (status.tools.git.version ?? t('settings.valueConfigured'))
                  : t('settings.valueMissing'),
              },
              { label: t('settings.authMode'), value: status.runtime.auth_mode },
              {
                label: t('settings.scheduler'),
                value: status.scheduler.running
                  ? t('settings.schedulerRunning', { count: status.scheduler.scheduled_targets })
                  : t('settings.schedulerStopped'),
              },
              {
                label: t('settings.nextRun'),
                value: status.scheduler.next_run_at
                  ? formatDateTime(status.scheduler.next_run_at, i18n.language)
                  : t('settings.nextRunNone'),
              },
              {
                label: t('settings.worker'),
                value: status.worker.running
                  ? t('settings.workerRunning', {
                      active: status.worker.active_jobs ?? 0,
                      queued: status.worker.queued_jobs ?? 0,
                    })
                  : t('settings.workerStopped'),
              },
            ].map((row) => (
              <div key={row.label} className="flex items-center justify-between gap-4 px-4 py-2">
                <dt className="text-slate-600 dark:text-slate-400">{row.label}</dt>
                <dd className="font-medium">{row.value}</dd>
              </div>
            ))}
          </dl>

          {settings && (
            <div className="border-t border-slate-200 px-4 py-3 dark:border-slate-800">
              <h3 className="text-sm font-semibold">{t('settings.variables')}</h3>
              <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
                {t('settings.variablesHint')}
              </p>
              <ul className="mt-2 flex flex-wrap gap-2">
                {settings.environment.variables.map((variable) => (
                  <li
                    key={variable.name}
                    className={`rounded-full px-2 py-0.5 text-xs ${
                      variable.set
                        ? 'bg-emerald-100 text-emerald-900 dark:bg-emerald-500/20 dark:text-emerald-100'
                        : 'bg-slate-200 text-slate-700 dark:bg-slate-700 dark:text-slate-200'
                    }`}
                  >
                    <code>{variable.name}</code> ·{' '}
                    {variable.set ? t('settings.valueConfigured') : t('settings.valueMissing')}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </section>
      )}

      <p className="text-xs text-slate-500 dark:text-slate-500">{t('settings.timezoneHint')}</p>
    </section>
  )
}
