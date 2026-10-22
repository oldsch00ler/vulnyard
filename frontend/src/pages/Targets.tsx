// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>

import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router-dom'

import { ApiError } from '../api/client'
import { useScanTarget } from '../api/runs'
import {
  type Target,
  type TargetPayload,
  type TargetSelection,
  useCreateTarget,
  useDeleteTarget,
  toUpdatePayload,
  usePreviewTarget,
  useTargets,
  useUpdateTarget,
} from '../api/targets'
import PreviewPanel from '../components/PreviewPanel'
import TargetForm from '../components/TargetForm'
import { primaryButton, smallButton, smallDangerButton } from '../lib/buttons'
import { describeCron } from '../lib/cron'

export default function Targets() {
  const { t } = useTranslation()
  const { data, isLoading, isError, error } = useTargets()
  const createTarget = useCreateTarget()
  const updateTarget = useUpdateTarget()
  const deleteTarget = useDeleteTarget()
  const preview = usePreviewTarget()
  const scanTarget = useScanTarget()

  const [formOpen, setFormOpen] = useState(false)
  const [editing, setEditing] = useState<Target | undefined>(undefined)
  const [confirmDelete, setConfirmDelete] = useState<number | null>(null)

  const mutation = editing ? updateTarget : createTarget
  const formError = errorMessage(mutation.error)

  const closeForm = () => {
    setFormOpen(false)
    setEditing(undefined)
    mutation.reset()
  }

  const submit = (payload: TargetPayload) => {
    if (editing) {
      // Only the changeable fields; the kind and the source reference are fixed.
      updateTarget.mutate(
        { id: editing.id, ...toUpdatePayload(payload) },
        { onSuccess: () => closeForm() },
      )
    } else {
      createTarget.mutate(payload, { onSuccess: () => closeForm() })
    }
  }

  const runPreview = (selection: TargetSelection) => preview.mutate(selection)

  return (
    <section className="space-y-4">
      <header className="flex flex-wrap items-start justify-between gap-3">
        <div className="space-y-1">
          <h1 className="text-2xl font-semibold tracking-tight">{t('targets.title')}</h1>
          <p className="text-sm text-slate-600 dark:text-slate-400">{t('targets.description')}</p>
        </div>
        {!formOpen && (
          <button
            type="button"
            onClick={() => {
              setEditing(undefined)
              setFormOpen(true)
            }}
            className={primaryButton}
          >
            {t('targets.add')}
          </button>
        )}
      </header>

      {formOpen && (
        <TargetForm
          target={editing}
          submitting={mutation.isPending}
          error={formError}
          onSubmit={submit}
          onPreview={runPreview}
          previewing={preview.isPending}
          onCancel={closeForm}
        />
      )}

      {scanTarget.isError && (
        <p className="rounded-md border border-red-300 bg-red-50 px-3 py-2 text-sm text-red-900 dark:border-red-500/40 dark:bg-red-500/10 dark:text-red-100">
          {errorMessage(scanTarget.error)}
        </p>
      )}

      {scanTarget.isSuccess && scanTarget.data && (
        <p className="rounded-md border border-emerald-300 bg-emerald-50 px-3 py-2 text-sm text-emerald-900 dark:border-emerald-500/40 dark:bg-emerald-500/10 dark:text-emerald-100">
          {t('targets.scanQueued', { count: scanTarget.data.total })}{' '}
          <Link to={`/runs/${scanTarget.data.id}`} className="underline hover:no-underline">
            {t('targets.openRun', { id: scanTarget.data.id })}
          </Link>
        </p>
      )}

      {preview.isError && (
        <p className="rounded-md border border-red-300 bg-red-50 px-3 py-2 text-sm text-red-900 dark:border-red-500/40 dark:bg-red-500/10 dark:text-red-100">
          {errorMessage(preview.error)}
        </p>
      )}

      {preview.data && <PreviewPanel result={preview.data} onClose={() => preview.reset()} />}

      {isLoading && <p className="text-sm text-slate-600 dark:text-slate-400">{t('common.loading')}</p>}

      {isError && (
        <p className="rounded-md border border-red-300 bg-red-50 px-3 py-2 text-sm text-red-900 dark:border-red-500/40 dark:bg-red-500/10 dark:text-red-100">
          {errorMessage(error)}
        </p>
      )}

      {data && data.items.length === 0 && !formOpen && (
        <div className="rounded-lg border border-dashed border-slate-300 p-6 text-sm dark:border-slate-700">
          <p className="font-medium">{t('targets.emptyTitle')}</p>
          <p className="mt-1 text-slate-600 dark:text-slate-400">{t('targets.emptyDescription')}</p>
        </div>
      )}

      {data && data.items.length > 0 && (
        <div className="overflow-x-auto rounded-lg border border-slate-200 dark:border-slate-800">
          <table className="w-full text-left text-sm">
            <thead className="bg-slate-50 text-xs uppercase text-slate-500 dark:bg-slate-900 dark:text-slate-400">
              <tr>
                <th className="px-3 py-2">{t('targets.table.name')}</th>
                <th className="px-3 py-2">{t('targets.table.kind')}</th>
                <th className="px-3 py-2">{t('targets.table.source')}</th>
                <th className="px-3 py-2">{t('targets.table.branches')}</th>
                <th className="px-3 py-2">{t('targets.table.schedule')}</th>
                <th className="px-3 py-2">{t('targets.table.state')}</th>
                <th className="px-3 py-2 text-right">{t('targets.table.actions')}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
              {data.items.map((target) => {
                const schedule = describeCron(target.schedule_cron)
                return (
                  <tr key={target.id}>
                    <td className="px-3 py-2">
                      <span className="font-medium">{target.name}</span>
                      <code className="block text-xs text-slate-500 dark:text-slate-400">{target.source_path}</code>
                    </td>
                    <td className="px-3 py-2">
                      {target.kind === 'group' ? t('targets.form.kindGroup') : t('targets.form.kindProject')}
                      {target.kind === 'group' && target.include_subgroups && (
                        <span className="block text-xs text-slate-500 dark:text-slate-400">
                          {t('targets.table.withSubgroups')}
                        </span>
                      )}
                    </td>
                    <td className="px-3 py-2 text-xs">
                      {target.source_url ? (
                        <>
                          <code>{new URL(target.source_url).host}</code>
                          <span className="block text-slate-500 dark:text-slate-400">
                            {t('targets.table.ownToken')}
                          </span>
                        </>
                      ) : (
                        <span className="text-slate-500 dark:text-slate-400">
                          {target.source_token_configured
                            ? t('targets.table.ownToken')
                            : t('targets.table.defaultSource')}
                        </span>
                      )}
                    </td>
                    <td className="px-3 py-2">
                      {target.branch_mode === 'default'
                        ? t('targets.table.branchesDefault')
                        : target.branch_patterns.join(', ') || t('targets.table.branchesDefault')}
                    </td>
                    <td className="px-3 py-2">{t(schedule.key, schedule.params)}</td>
                    <td className="px-3 py-2">
                      <button
                        type="button"
                        onClick={() => updateTarget.mutate({ id: target.id, enabled: !target.enabled })}
                        className={`rounded-full px-2 py-0.5 text-xs font-medium ${
                          target.enabled
                            ? 'bg-emerald-100 text-emerald-900 hover:bg-emerald-200 dark:bg-emerald-500/20 dark:text-emerald-100 dark:hover:bg-emerald-500/30'
                            : 'bg-slate-200 text-slate-700 hover:bg-slate-300 dark:bg-slate-700 dark:text-slate-200 dark:hover:bg-slate-600'
                        }`}
                      >
                        {target.enabled ? t('targets.table.enabled') : t('targets.table.disabled')}
                      </button>
                    </td>
                    <td className="px-3 py-2">
                      <div className="flex justify-end gap-2">
                        <button
                          type="button"
                          onClick={() => scanTarget.mutate({ targetId: target.id })}
                          disabled={scanTarget.isPending}
                          className={smallButton}
                        >
                          {t('targets.scanNow')}
                        </button>
                        <button
                          type="button"
                          onClick={() => {
                            setEditing(target)
                            setFormOpen(true)
                          }}
                          className={smallButton}
                        >
                          {t('common.edit')}
                        </button>
                        {confirmDelete === target.id ? (
                          <>
                            <button
                              type="button"
                              onClick={() =>
                                deleteTarget.mutate(target.id, { onSuccess: () => setConfirmDelete(null) })
                              }
                              className={smallDangerButton}
                            >
                              {t('targets.confirmDelete')}
                            </button>
                            <button
                              type="button"
                              onClick={() => setConfirmDelete(null)}
                              className={smallButton}
                            >
                              {t('common.cancel')}
                            </button>
                          </>
                        ) : (
                          <button
                            type="button"
                            onClick={() => setConfirmDelete(target.id)}
                            className={smallButton}
                          >
                            {t('common.delete')}
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
    </section>
  )
}

/** Message of an API error; the backend already translated it. */
function errorMessage(error: unknown): string | null {
  if (!error) {
    return null
  }
  if (error instanceof ApiError) {
    return error.message
  }
  return error instanceof Error ? error.message : String(error)
}
