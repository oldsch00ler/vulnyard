// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>

import { useId, useState } from 'react'
import { useTranslation } from 'react-i18next'

import {
  ANALYSIS_STATES,
  ANY_COMPONENT,
  type AnalysisState,
  type IgnoreRulePayload,
} from '../api/ignores'
import { useTargets } from '../api/targets'
import { primaryButton, secondaryButton } from '../lib/buttons'

interface IgnoreRuleFormProps {
  /** Pre-filled when the form is opened from a vulnerability in the summary. */
  vulnId?: string
  /** Purls of the affected components, offered as suggestions for the pattern. */
  suggestions?: string[]
  submitting?: boolean
  error?: string | null
  onSubmit: (payload: IgnoreRulePayload) => void
  onCancel: () => void
}

/**
 * Form for one ignore rule.
 *
 * The scope (a target, or everything) and the pattern are the two decisions that
 * matter, so they come first; the rest has sensible defaults.
 */
export default function IgnoreRuleForm({
  vulnId = '',
  suggestions = [],
  submitting = false,
  error = null,
  onSubmit,
  onCancel,
}: IgnoreRuleFormProps) {
  const { t } = useTranslation()
  const targets = useTargets()
  const listId = useId()

  const [vuln, setVuln] = useState(vulnId)
  const [pattern, setPattern] = useState(ANY_COMPONENT)
  const [scope, setScope] = useState<string>('')
  const [state, setState] = useState<AnalysisState>('NOT_AFFECTED')
  const [reason, setReason] = useState('')
  const [expiresOn, setExpiresOn] = useState('')

  const inputClass =
    'w-full rounded-md border border-slate-300 bg-white px-3 py-2 text-sm dark:border-slate-700 dark:bg-slate-900'
  const today = new Date().toISOString().slice(0, 10)

  return (
    <form
      onSubmit={(event) => {
        event.preventDefault()
        onSubmit({
          vuln_id: vuln.trim(),
          purl_pattern: pattern.trim() || ANY_COMPONENT,
          target_id: scope === '' ? null : Number(scope),
          analysis_state: state,
          reason: reason.trim(),
          expires_on: expiresOn || null,
        })
      }}
      className="space-y-4 rounded-lg border border-slate-200 bg-white p-4 text-left dark:border-slate-800 dark:bg-slate-900"
    >
      <h3 className="text-sm font-semibold">{t('ignores.form.title')}</h3>

      <div className="grid gap-4 sm:grid-cols-2">
        <label className="block text-sm">
          <span className="font-medium">{t('ignores.form.vulnId')}</span>
          <input
            value={vuln}
            onChange={(event) => setVuln(event.target.value)}
            required
            placeholder="CVE-2026-47764"
            className={`mt-1 ${inputClass}`}
          />
        </label>

        <label className="block text-sm">
          <span className="font-medium">{t('ignores.form.scope')}</span>
          <select
            value={scope}
            onChange={(event) => setScope(event.target.value)}
            className={`mt-1 ${inputClass}`}
          >
            <option value="">{t('ignores.form.scopeGlobal')}</option>
            {(targets.data?.items ?? []).map((target) => (
              <option key={target.id} value={String(target.id)}>
                {target.name}
              </option>
            ))}
          </select>
        </label>
      </div>

      <label className="block text-sm">
        <span className="font-medium">{t('ignores.form.pattern')}</span>
        <input
          value={pattern}
          onChange={(event) => setPattern(event.target.value)}
          list={suggestions.length > 0 ? listId : undefined}
          placeholder="pkg:npm/express@5.*"
          className={`mt-1 ${inputClass}`}
        />
        {suggestions.length > 0 && (
          <datalist id={listId}>
            {suggestions.map((purl) => (
              <option key={purl} value={purl} />
            ))}
          </datalist>
        )}
        <span className="mt-1 block text-xs text-slate-600 dark:text-slate-400">
          {t('ignores.form.patternHelp')}
        </span>
      </label>

      <div className="grid gap-4 sm:grid-cols-2">
        <label className="block text-sm">
          <span className="font-medium">{t('ignores.form.analysisState')}</span>
          <select
            value={state}
            onChange={(event) => setState(event.target.value as AnalysisState)}
            className={`mt-1 ${inputClass}`}
          >
            {ANALYSIS_STATES.map((option) => (
              <option key={option} value={option}>
                {t(`ignores.state.${option}`)}
              </option>
            ))}
          </select>
        </label>

        <label className="block text-sm">
          <span className="font-medium">{t('ignores.form.expiresOn')}</span>
          <input
            type="date"
            value={expiresOn}
            min={today}
            onChange={(event) => setExpiresOn(event.target.value)}
            className={`mt-1 ${inputClass}`}
          />
          <span className="mt-1 block text-xs text-slate-600 dark:text-slate-400">
            {t('ignores.form.expiresOnHelp')}
          </span>
        </label>
      </div>

      <label className="block text-sm">
        <span className="font-medium">{t('ignores.form.reason')}</span>
        <textarea
          value={reason}
          onChange={(event) => setReason(event.target.value)}
          rows={2}
          placeholder={t('ignores.form.reasonPlaceholder')}
          className={`mt-1 ${inputClass}`}
        />
        <span className="mt-1 block text-xs text-slate-600 dark:text-slate-400">
          {t('ignores.form.reasonHelp')}
        </span>
      </label>

      {error && (
        <p className="rounded-md border border-red-300 bg-red-50 px-3 py-2 text-sm text-red-900 dark:border-red-500/40 dark:bg-red-500/10 dark:text-red-100">
          {error}
        </p>
      )}

      <div className="flex gap-2">
        <button
          type="submit"
          disabled={submitting || !vuln.trim()}
          className={primaryButton}
        >
          {submitting ? t('common.saving') : t('ignores.form.save')}
        </button>
        <button type="button" onClick={onCancel} className={secondaryButton}>
          {t('common.cancel')}
        </button>
      </div>
    </form>
  )
}
