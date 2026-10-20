// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>

import { useState } from 'react'
import { useTranslation } from 'react-i18next'

import { useWebhookTest } from '../api/settings'
import { useBranchSuggestions, useSourceTest } from '../api/source'
import type { BranchMode, Target, TargetKind, TargetPayload, TargetSelection } from '../api/targets'
import { CRON_PRESETS } from '../lib/cron'
import ChipInput from './ChipInput'
import SourcePicker, { type SourceSelection } from './SourcePicker'

interface TargetFormProps {
  target?: Target
  submitting: boolean
  error: string | null
  onSubmit: (payload: TargetPayload) => void
  onPreview: (selection: TargetSelection) => void
  previewing: boolean
  onCancel: () => void
}

export default function TargetForm({
  target,
  submitting,
  error,
  onSubmit,
  onPreview,
  previewing,
  onCancel,
}: TargetFormProps) {
  const { t } = useTranslation()
  const editing = target !== undefined

  const [kind, setKind] = useState<TargetKind>(target?.kind ?? 'group')
  const [selection, setSelection] = useState<SourceSelection | null>(
    target ? { ref: target.source_ref, path: target.source_path, name: target.name } : null,
  )
  const [name, setName] = useState(target?.name ?? '')
  const [includeSubgroups, setIncludeSubgroups] = useState(target?.include_subgroups ?? true)
  const [branchMode, setBranchMode] = useState<BranchMode>(target?.branch_mode ?? 'default')
  const [branchPatterns, setBranchPatterns] = useState<string[]>(target?.branch_patterns ?? [])
  const [includeDefaultBranch, setIncludeDefaultBranch] = useState(target?.include_default_branch ?? true)
  const [maxBranches, setMaxBranches] = useState(target?.max_branches_per_project ?? 10)
  const [cron, setCron] = useState<string | null>(target ? target.schedule_cron : '0 2 * * *')
  const [customCron, setCustomCron] = useState(
    target?.schedule_cron && !CRON_PRESETS.some((preset) => preset.value === target.schedule_cron)
      ? target.schedule_cron
      : '',
  )
  const [excludePatterns, setExcludePatterns] = useState<string[]>(target?.exclude_patterns ?? [])
  const [skipUnchanged, setSkipUnchanged] = useState(target?.skip_unchanged ?? true)
  const [enabled, setEnabled] = useState(target?.enabled ?? true)
  const [webhook, setWebhook] = useState('')
  const [webhookTouched, setWebhookTouched] = useState(false)
  const testWebhook = useWebhookTest()

  // Own instance and token. Empty means the ones from the environment; the
  // stored token never comes back to the browser, so an untouched field keeps it.
  const [sourceUrl, setSourceUrl] = useState(target?.source_url ?? '')
  const [sourceToken, setSourceToken] = useState('')
  const [credentialsTouched, setCredentialsTouched] = useState(false)
  const testSource = useSourceTest()

  const credentials = {
    source_url: sourceUrl.trim() || undefined,
    source_token: sourceToken.trim() || undefined,
  }

  // Real branches of the picked project help with the custom selection.
  const branchQuery = useBranchSuggestions(
    kind === 'project' && branchMode === 'custom' ? (selection?.ref ?? null) : null,
    '',
  )

  const currentSelection = (): TargetSelection | null => {
    if (!selection) {
      return null
    }
    return {
      kind,
      source_ref: selection.ref,
      include_subgroups: kind === 'group' ? includeSubgroups : false,
      branch_mode: branchMode,
      branch_patterns: branchMode === 'custom' ? branchPatterns : [],
      include_default_branch: includeDefaultBranch,
      max_branches_per_project: maxBranches,
      exclude_patterns: excludePatterns,
    }
  }

  const submit = () => {
    const base = currentSelection()
    if (!base) {
      return
    }
    onSubmit({
      ...base,
      name: name.trim() || selection?.name || null,
      source_path: selection?.path ?? null,
      schedule_cron: customCron.trim() ? customCron.trim() : cron,
      skip_unchanged: skipUnchanged,
      enabled,
      // Only sent when the field was touched, so an untouched form keeps the
      // stored webhook (which never comes back to the browser in full).
      ...(webhookTouched ? { notify_webhook_url: webhook.trim() } : {}),
      ...(credentialsTouched
        ? { source_url: sourceUrl.trim(), source_token: sourceToken.trim() }
        : {}),
    })
  }

  const inputClass =
    'w-full rounded-md border border-slate-300 bg-white px-3 py-2 text-sm dark:border-slate-700 dark:bg-slate-900'

  return (
    <form
      onSubmit={(event) => {
        event.preventDefault()
        submit()
      }}
      className="space-y-5 rounded-lg border border-slate-200 bg-white p-4 dark:border-slate-800 dark:bg-slate-900"
    >
      <h2 className="text-lg font-semibold">{editing ? t('targets.form.editTitle') : t('targets.form.createTitle')}</h2>

      {!editing && (
        <fieldset className="space-y-1">
          <legend className="text-sm font-medium">{t('targets.form.kind')}</legend>
          <div className="flex gap-4 text-sm">
            {(['group', 'project'] as TargetKind[]).map((option) => (
              <label key={option} className="inline-flex items-center gap-2">
                <input
                  type="radio"
                  name="kind"
                  value={option}
                  checked={kind === option}
                  onChange={() => {
                    setKind(option)
                    setSelection(null)
                  }}
                />
                {option === 'group' ? t('targets.form.kindGroup') : t('targets.form.kindProject')}
              </label>
            ))}
          </div>
        </fieldset>
      )}

      {editing ? (
        <div className="text-sm">
          <span className="font-medium">{kind === 'group' ? t('targets.form.group') : t('targets.form.project')}: </span>
          <code>{target.source_path}</code>
        </div>
      ) : (
        <SourcePicker
          kind={kind}
          value={selection}
          onChange={setSelection}
          inputId="target-source"
          credentials={credentials}
        />
      )}

      <div className="space-y-1">
        <label htmlFor="target-name" className="block text-sm font-medium">
          {t('targets.form.name')}
        </label>
        <input
          id="target-name"
          value={name}
          onChange={(event) => setName(event.target.value)}
          placeholder={selection?.name ?? ''}
          className={inputClass}
        />
        <p className="text-xs text-slate-500 dark:text-slate-400">{t('targets.form.nameHint')}</p>
      </div>

      {kind === 'group' && (
        <label className="flex items-center gap-2 text-sm">
          <input
            type="checkbox"
            checked={includeSubgroups}
            onChange={(event) => setIncludeSubgroups(event.target.checked)}
          />
          {t('targets.form.includeSubgroups')}
        </label>
      )}

      <fieldset className="space-y-2">
        <legend className="text-sm font-medium">{t('targets.form.branches')}</legend>
        <label className="flex items-start gap-2 text-sm">
          <input
            type="radio"
            name="branchMode"
            checked={branchMode === 'default'}
            onChange={() => setBranchMode('default')}
            className="mt-1"
          />
          <span>
            {t('targets.form.branchModeDefault')}
            <span className="block text-xs text-slate-500 dark:text-slate-400">
              {t('targets.form.branchModeDefaultHint')}
            </span>
          </span>
        </label>
        <label className="flex items-start gap-2 text-sm">
          <input
            type="radio"
            name="branchMode"
            checked={branchMode === 'custom'}
            onChange={() => setBranchMode('custom')}
            className="mt-1"
          />
          <span>
            {t('targets.form.branchModeCustom')}
            <span className="block text-xs text-slate-500 dark:text-slate-400">
              {t('targets.form.branchModeCustomHint')}
            </span>
          </span>
        </label>

        {branchMode === 'custom' && (
          <div className="space-y-3 rounded-md border border-slate-200 p-3 dark:border-slate-700">
            <ChipInput
              inputId="target-branch-patterns"
              label={t('targets.form.branchPatterns')}
              hint={t('targets.form.branchPatternsHint')}
              placeholder="release/*"
              values={branchPatterns}
              onChange={setBranchPatterns}
              suggestions={(branchQuery.data ?? []).map((branch) => branch.name)}
            />
            <label className="flex items-center gap-2 text-sm">
              <input
                type="checkbox"
                checked={includeDefaultBranch}
                onChange={(event) => setIncludeDefaultBranch(event.target.checked)}
              />
              {t('targets.form.includeDefaultBranch')}
            </label>
            <div className="space-y-1">
              <label htmlFor="target-max-branches" className="block text-sm font-medium">
                {t('targets.form.maxBranches')}
              </label>
              <input
                id="target-max-branches"
                type="number"
                min={1}
                max={100}
                value={maxBranches}
                onChange={(event) => setMaxBranches(Number(event.target.value))}
                className="w-24 rounded-md border border-slate-300 bg-white px-2 py-1 text-sm dark:border-slate-700 dark:bg-slate-900"
              />
              <p className="text-xs text-slate-500 dark:text-slate-400">{t('targets.form.maxBranchesHint')}</p>
            </div>
          </div>
        )}
      </fieldset>

      <div className="space-y-1">
        <label htmlFor="target-cron" className="block text-sm font-medium">
          {t('targets.form.schedule')}
        </label>
        <select
          id="target-cron"
          value={cron ?? ''}
          onChange={(event) => {
            setCron(event.target.value === '' ? null : event.target.value)
            setCustomCron('')
          }}
          className={inputClass}
        >
          {CRON_PRESETS.map((preset) => (
            <option key={preset.labelKey} value={preset.value ?? ''}>
              {t(preset.labelKey)}
            </option>
          ))}
        </select>
        <input
          id="target-cron-custom"
          value={customCron}
          onChange={(event) => setCustomCron(event.target.value)}
          placeholder={t('targets.form.cronCustomPlaceholder')}
          className={inputClass}
        />
        <p className="text-xs text-slate-500 dark:text-slate-400">{t('targets.form.cronCustomHint')}</p>
      </div>

      <ChipInput
        inputId="target-exclude-patterns"
        label={t('targets.form.excludePatterns')}
        hint={t('targets.form.excludePatternsHint')}
        placeholder="sandbox/*"
        values={excludePatterns}
        onChange={setExcludePatterns}
      />

      <label className="flex items-center gap-2 text-sm">
        <input type="checkbox" checked={skipUnchanged} onChange={(event) => setSkipUnchanged(event.target.checked)} />
        {t('targets.form.skipUnchanged')}
      </label>

      <label className="flex items-center gap-2 text-sm">
        <input type="checkbox" checked={enabled} onChange={(event) => setEnabled(event.target.checked)} />
        {t('targets.form.enabled')}
      </label>

      <fieldset className="space-y-2 rounded-md border border-slate-200 p-3 dark:border-slate-700">
        <legend className="px-1 text-sm font-medium">{t('targets.form.credentials')}</legend>
        <p className="text-xs text-slate-500 dark:text-slate-400">
          {t('targets.form.credentialsHint', {
            url: target?.source_url_effective ?? t('targets.form.credentialsDefault'),
          })}
        </p>

        <div className="space-y-1">
          <label htmlFor="target-source-url" className="block text-xs font-medium">
            {t('targets.form.sourceUrl')}
          </label>
          <input
            id="target-source-url"
            value={sourceUrl}
            onChange={(event) => {
              setSourceUrl(event.target.value)
              setCredentialsTouched(true)
            }}
            placeholder={t('targets.form.sourceUrlPlaceholder')}
            className={inputClass}
          />
        </div>

        <div className="space-y-1">
          <label htmlFor="target-source-token" className="block text-xs font-medium">
            {t('targets.form.sourceToken')}
          </label>
          <input
            id="target-source-token"
            type="password"
            autoComplete="off"
            value={sourceToken}
            onChange={(event) => {
              setSourceToken(event.target.value)
              setCredentialsTouched(true)
            }}
            placeholder={
              target?.source_token_configured
                ? t('targets.form.sourceTokenStored')
                : t('targets.form.sourceTokenPlaceholder')
            }
            className={inputClass}
          />
          <p className="text-xs text-slate-500 dark:text-slate-400">
            {t('targets.form.sourceTokenHint')}
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={() => testSource.mutate(credentials)}
            disabled={testSource.isPending}
            className="rounded-md border border-slate-300 px-2 py-1 text-sm disabled:opacity-40 dark:border-slate-700"
          >
            {testSource.isPending ? t('common.loading') : t('targets.form.testSource')}
          </button>
          {testSource.data && (
            <span
              className={`text-xs ${
                testSource.data.ok
                  ? 'text-emerald-700 dark:text-emerald-300'
                  : 'text-red-600 dark:text-red-400'
              }`}
            >
              {testSource.data.detail}
            </span>
          )}
        </div>
      </fieldset>

      <div className="space-y-1">
        <label htmlFor="target-webhook" className="block text-sm font-medium">
          {t('targets.form.webhook')}
        </label>
        <div className="flex flex-wrap gap-2">
          <input
            id="target-webhook"
            value={webhook}
            onChange={(event) => {
              setWebhook(event.target.value)
              setWebhookTouched(true)
            }}
            placeholder={target?.notify_webhook_url_masked ?? t('targets.form.webhookPlaceholder')}
            className={`${inputClass} flex-1`}
          />
          {editing && target?.notify_webhook_configured && (
            <button
              type="button"
              onClick={() => testWebhook.mutate(target.id)}
              disabled={testWebhook.isPending}
              className="rounded-md border border-slate-300 px-2 py-1 text-sm disabled:opacity-40 dark:border-slate-700"
            >
              {testWebhook.isPending ? t('common.loading') : t('settings.notifications.test')}
            </button>
          )}
        </div>
        <p className="text-xs text-slate-500 dark:text-slate-400">
          {target?.notify_webhook_configured
            ? t('targets.form.webhookStored', { masked: target.notify_webhook_url_masked ?? '' })
            : t('targets.form.webhookHint')}
        </p>
        {testWebhook.data && (
          <p
            className={`text-xs ${
              testWebhook.data.ok
                ? 'text-emerald-700 dark:text-emerald-300'
                : 'text-red-600 dark:text-red-400'
            }`}
          >
            {testWebhook.data.detail}
          </p>
        )}
      </div>

      {error && (
        <p className="rounded-md border border-red-300 bg-red-50 px-3 py-2 text-sm text-red-900 dark:border-red-500/40 dark:bg-red-500/10 dark:text-red-100">
          {error}
        </p>
      )}

      <div className="flex flex-wrap gap-2">
        <button
          type="submit"
          disabled={submitting || !selection}
          className="rounded-md bg-slate-900 px-3 py-2 text-sm font-medium text-white disabled:opacity-40 dark:bg-slate-100 dark:text-slate-900"
        >
          {editing ? t('common.save') : t('targets.form.create')}
        </button>
        <button
          type="button"
          disabled={previewing || !selection}
          onClick={() => {
            const base = currentSelection()
            if (base) {
              onPreview(base)
            }
          }}
          className="rounded-md border border-slate-300 px-3 py-2 text-sm font-medium disabled:opacity-40 dark:border-slate-700"
        >
          {previewing ? t('common.loading') : t('targets.form.preview')}
        </button>
        <button type="button" onClick={onCancel} className="px-3 py-2 text-sm underline hover:no-underline">
          {t('common.cancel')}
        </button>
      </div>
    </form>
  )
}
