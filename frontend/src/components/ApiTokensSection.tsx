// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>

import { useState } from 'react'
import { useTranslation } from 'react-i18next'

import { ApiError } from '../api/client'
import {
  API_TOKEN_SCOPES,
  type ApiTokenScope,
  type CreatedApiToken,
  useApiTokens,
  useCreateApiToken,
  useDeleteApiToken,
} from '../api/tokens'
import { primaryButton, smallButton, smallDangerButton } from '../lib/buttons'
import { formatDate, formatDateTime } from '../lib/format'

function errorText(error: unknown): string | null {
  if (!error) return null
  return error instanceof ApiError ? error.message : String(error)
}

/**
 * API tokens for other systems (Settings).
 *
 * A new token is shown exactly once, right after it is created; the list only
 * ever has its first characters, so that one can tell which entry is which.
 */
export default function ApiTokensSection() {
  const { t, i18n } = useTranslation()
  const tokens = useApiTokens()
  const create = useCreateApiToken()
  const remove = useDeleteApiToken()

  const [formOpen, setFormOpen] = useState(false)
  const [name, setName] = useState('')
  const [scope, setScope] = useState<ApiTokenScope>('write')
  const [expiresOn, setExpiresOn] = useState('')
  const [created, setCreated] = useState<CreatedApiToken | null>(null)
  const [copied, setCopied] = useState(false)

  const inputClass =
    'w-full rounded-md border border-slate-300 bg-white px-3 py-2 text-sm dark:border-slate-700 dark:bg-slate-900'
  const today = new Date().toISOString().slice(0, 10)

  const openForm = () => {
    create.reset()
    setName('')
    setScope('write')
    setExpiresOn('')
    setFormOpen((open) => !open)
  }

  const copy = async (token: string) => {
    try {
      await navigator.clipboard.writeText(token)
      setCopied(true)
    } catch {
      setCopied(false)
    }
  }

  return (
    <section className="rounded-lg border border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-200 px-4 py-3 dark:border-slate-800">
        <h2 className="text-sm font-semibold">{t('tokens.title')}</h2>
        <button type="button" onClick={openForm} className={smallButton}>
          {formOpen ? t('common.cancel') : t('tokens.add')}
        </button>
      </div>

      <div className="space-y-3 px-4 py-4">
        <p className="text-xs text-slate-600 dark:text-slate-400">{t('tokens.description')}</p>

        {created && (
          <div className="space-y-2 rounded-md border border-amber-300 bg-amber-50 px-3 py-3 text-sm text-amber-950 dark:border-amber-500/40 dark:bg-amber-500/10 dark:text-amber-100">
            <p className="font-medium">{t('tokens.created.title', { name: created.name })}</p>
            <p className="text-xs">{t('tokens.created.once')}</p>
            <div className="flex flex-wrap items-center gap-2">
              <code className="break-all rounded bg-white px-2 py-1 text-xs text-slate-900 dark:bg-slate-950 dark:text-slate-100">
                {created.token}
              </code>
              <button
                type="button"
                onClick={() => void copy(created.token)}
                className="rounded-md border border-amber-400 px-2 py-1 text-xs font-medium hover:bg-amber-100 dark:border-amber-500/60 dark:hover:bg-amber-500/20"
              >
                {copied ? t('tokens.created.copied') : t('tokens.created.copy')}
              </button>
            </div>
            <p className="text-xs">
              {t('tokens.created.usage')}{' '}
              <code className="text-[11px]">Authorization: Bearer {created.token_prefix}…</code>
            </p>
            <button
              type="button"
              onClick={() => {
                setCreated(null)
                setCopied(false)
              }}
              className="rounded-md border border-amber-400 px-2 py-1 text-xs font-medium hover:bg-amber-100 dark:border-amber-500/60 dark:hover:bg-amber-500/20"
            >
              {t('tokens.created.done')}
            </button>
          </div>
        )}

        {formOpen && (
          <form
            onSubmit={(event) => {
              event.preventDefault()
              create.mutate(
                { name: name.trim(), scope, expires_on: expiresOn || null },
                {
                  onSuccess: (token) => {
                    setCreated(token)
                    setCopied(false)
                    setFormOpen(false)
                  },
                },
              )
            }}
            className="space-y-4 rounded-lg border border-slate-200 p-4 dark:border-slate-800"
          >
            <div className="grid gap-4 sm:grid-cols-3">
              <label className="block text-sm">
                <span className="font-medium">{t('tokens.form.name')}</span>
                <input
                  value={name}
                  onChange={(event) => setName(event.target.value)}
                  required
                  maxLength={128}
                  placeholder={t('tokens.form.namePlaceholder')}
                  className={`mt-1 ${inputClass}`}
                />
              </label>

              <label className="block text-sm">
                <span className="font-medium">{t('tokens.form.scope')}</span>
                <select
                  value={scope}
                  onChange={(event) => setScope(event.target.value as ApiTokenScope)}
                  className={`mt-1 ${inputClass}`}
                >
                  {API_TOKEN_SCOPES.map((option) => (
                    <option key={option} value={option}>
                      {t(`tokens.scope.${option}`)}
                    </option>
                  ))}
                </select>
              </label>

              <label className="block text-sm">
                <span className="font-medium">{t('tokens.form.expiresOn')}</span>
                <input
                  type="date"
                  value={expiresOn}
                  min={today}
                  onChange={(event) => setExpiresOn(event.target.value)}
                  className={`mt-1 ${inputClass}`}
                />
                <span className="mt-1 block text-xs text-slate-600 dark:text-slate-400">
                  {t('tokens.form.expiresOnHelp')}
                </span>
              </label>
            </div>

            {create.isError && (
              <p className="rounded-md border border-red-300 bg-red-50 px-3 py-2 text-sm text-red-900 dark:border-red-500/40 dark:bg-red-500/10 dark:text-red-100">
                {errorText(create.error)}
              </p>
            )}

            <button
              type="submit"
              disabled={create.isPending || !name.trim()}
              className={primaryButton}
            >
              {create.isPending ? t('common.saving') : t('tokens.form.create')}
            </button>
          </form>
        )}

        {(tokens.isError || remove.isError) && (
          <p className="rounded-md border border-red-300 bg-red-50 px-3 py-2 text-sm text-red-900 dark:border-red-500/40 dark:bg-red-500/10 dark:text-red-100">
            {errorText(tokens.error ?? remove.error)}
          </p>
        )}

        {tokens.data && tokens.data.items.length === 0 && (
          <p className="text-sm text-slate-600 dark:text-slate-400">{t('tokens.empty')}</p>
        )}

        {tokens.data && tokens.data.items.length > 0 && (
          <div className="overflow-x-auto rounded-lg border border-slate-200 dark:border-slate-800">
            <table className="w-full text-left text-sm">
              <thead className="bg-slate-50 text-xs uppercase text-slate-500 dark:bg-slate-900 dark:text-slate-400">
                <tr>
                  <th className="px-3 py-2">{t('tokens.table.name')}</th>
                  <th className="px-3 py-2">{t('tokens.table.token')}</th>
                  <th className="px-3 py-2">{t('tokens.table.scope')}</th>
                  <th className="px-3 py-2">{t('tokens.table.validity')}</th>
                  <th className="px-3 py-2">{t('tokens.table.lastUsed')}</th>
                  <th className="px-3 py-2">{t('tokens.table.created')}</th>
                  <th className="px-3 py-2" />
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                {tokens.data.items.map((token) => (
                  <tr key={token.id} className={token.active ? undefined : 'opacity-60'}>
                    <td className="px-3 py-2 font-medium">{token.name}</td>
                    <td className="px-3 py-2">
                      <code className="text-xs">{token.token_prefix}…</code>
                    </td>
                    <td className="px-3 py-2 text-xs">{t(`tokens.scope.${token.scope}`)}</td>
                    <td className="px-3 py-2 text-xs">
                      {!token.active ? (
                        <span className="font-medium">{t('tokens.expired')}</span>
                      ) : token.expires_on ? (
                        t('tokens.expiresOn', { date: formatDate(token.expires_on, i18n.language) })
                      ) : (
                        '—'
                      )}
                    </td>
                    <td className="px-3 py-2 text-xs">
                      {token.last_used_at
                        ? formatDateTime(token.last_used_at, i18n.language)
                        : t('tokens.neverUsed')}
                    </td>
                    <td className="px-3 py-2 text-xs">
                      {formatDate(token.created_at, i18n.language)}
                      {token.created_by && (
                        <span className="block text-[11px] text-slate-500 dark:text-slate-400">
                          {token.created_by}
                        </span>
                      )}
                    </td>
                    <td className="px-3 py-2 text-right">
                      <button
                        type="button"
                        onClick={() => {
                          if (window.confirm(t('tokens.confirmDelete', { name: token.name }))) {
                            remove.mutate(token.id)
                          }
                        }}
                        disabled={remove.isPending && remove.variables === token.id}
                        className={smallDangerButton}
                      >
                        {t('common.delete')}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </section>
  )
}
