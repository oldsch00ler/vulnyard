// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>

import { useTranslation } from 'react-i18next'

import { ANY_COMPONENT, type IgnoreRule } from '../api/ignores'
import { smallDangerButton } from '../lib/buttons'
import { formatDate } from '../lib/format'

interface IgnoreRulesTableProps {
  rules: IgnoreRule[]
  deletingId?: number | null
  onDelete: (rule: IgnoreRule) => void
}

/** The rules as a table; the scope and what a rule really suppresses are the point. */
export default function IgnoreRulesTable({
  rules,
  deletingId = null,
  onDelete,
}: IgnoreRulesTableProps) {
  const { t, i18n } = useTranslation()

  if (rules.length === 0) {
    return <p className="text-sm text-slate-600 dark:text-slate-400">{t('ignores.empty')}</p>
  }

  return (
    <div className="overflow-x-auto rounded-lg border border-slate-200 dark:border-slate-800">
      <table className="w-full text-left text-sm">
        <thead className="bg-slate-50 text-xs uppercase text-slate-500 dark:bg-slate-900 dark:text-slate-400">
          <tr>
            <th className="px-3 py-2">{t('ignores.table.vulnId')}</th>
            <th className="px-3 py-2">{t('ignores.table.pattern')}</th>
            <th className="px-3 py-2">{t('ignores.table.scope')}</th>
            <th className="px-3 py-2">{t('ignores.table.state')}</th>
            <th className="px-3 py-2">{t('ignores.table.validity')}</th>
            <th className="px-3 py-2 text-right">{t('ignores.table.applied')}</th>
            <th className="px-3 py-2" />
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
          {rules.map((rule) => (
            <tr key={rule.id} className={rule.active ? undefined : 'opacity-60'}>
              <td className="px-3 py-2 font-medium">{rule.vuln_id}</td>
              <td className="px-3 py-2">
                {rule.purl_pattern === ANY_COMPONENT ? (
                  <span className="text-slate-600 dark:text-slate-400">
                    {t('ignores.anyComponent')}
                  </span>
                ) : (
                  <code className="text-xs">{rule.purl_pattern}</code>
                )}
              </td>
              <td className="px-3 py-2">
                {rule.target_name ?? (
                  <span className="text-slate-600 dark:text-slate-400">
                    {t('ignores.scopeGlobal')}
                  </span>
                )}
              </td>
              <td className="px-3 py-2 text-xs">{t(`ignores.state.${rule.analysis_state}`)}</td>
              <td className="px-3 py-2 text-xs">
                {!rule.active ? (
                  <span className="font-medium">{t('ignores.expired')}</span>
                ) : rule.expires_on ? (
                  t('ignores.expiresOn', { date: formatDate(rule.expires_on, i18n.language) })
                ) : (
                  '—'
                )}
              </td>
              <td className="px-3 py-2 text-right text-xs tabular-nums">
                {t('ignores.appliedCount', { count: rule.applied_count })}
              </td>
              <td className="px-3 py-2 text-right">
                <button
                  type="button"
                  onClick={() => onDelete(rule)}
                  disabled={deletingId === rule.id}
                  className={smallDangerButton}
                >
                  {t('common.delete')}
                </button>
                {rule.reason && (
                  <span className="mt-1 block max-w-60 text-[11px] text-slate-500 dark:text-slate-400">
                    {rule.reason}
                  </span>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
