// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>

import { useTranslation } from 'react-i18next'

import type { PreviewResult } from '../api/targets'
import { smallButton } from '../lib/buttons'

interface PreviewPanelProps {
  result: PreviewResult
  onClose: () => void
}

/** Result of "Náhled projektů": what would be scanned and what would not. */
export default function PreviewPanel({ result, onClose }: PreviewPanelProps) {
  const { t } = useTranslation()

  return (
    <section className="space-y-3 rounded-lg border border-slate-200 bg-white p-4 dark:border-slate-800 dark:bg-slate-900">
      <header className="flex items-start justify-between gap-4">
        <div>
          <h2 className="text-lg font-semibold">{t('targets.preview.title')}</h2>
          <p className="text-sm text-slate-600 dark:text-slate-400">
            {t('targets.preview.summary', {
              projects: t('targets.preview.projectsCount', { count: result.project_count }),
              branches: t('targets.preview.branchesCount', { count: result.branch_count }),
              skipped: t('targets.preview.skippedCount', { count: result.skipped_count }),
            })}
          </p>
        </div>
        <button type="button" onClick={onClose} className={smallButton}>
          {t('common.close')}
        </button>
      </header>

      {result.warnings.length > 0 && (
        <ul className="space-y-1 text-sm text-amber-800 dark:text-amber-200">
          {result.warnings.map((warning, index) => (
            <li key={`${warning.code}-${index}`}>{warning.message}</li>
          ))}
        </ul>
      )}

      {result.projects.length === 0 ? (
        <p className="text-sm text-slate-600 dark:text-slate-400">{t('targets.preview.empty')}</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="text-xs uppercase text-slate-500 dark:text-slate-400">
              <tr>
                <th className="py-1 pr-4">{t('targets.preview.project')}</th>
                <th className="py-1 pr-4">{t('targets.preview.branches')}</th>
                <th className="py-1">{t('targets.preview.notes')}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
              {result.projects.map((project) => (
                <tr key={project.source_ref} className="align-top">
                  <td className="py-2 pr-4">
                    <a
                      href={project.web_url}
                      target="_blank"
                      rel="noreferrer"
                      className="underline hover:no-underline"
                    >
                      <code className="text-xs">{project.path_with_namespace}</code>
                    </a>
                  </td>
                  <td className="py-2 pr-4">
                    <ul className="space-y-0.5">
                      {project.branches.map((branch) => (
                        <li key={branch.branch}>
                          <code className="text-xs">{branch.branch}</code>
                          {branch.is_default_branch && (
                            <span className="ml-1 rounded bg-slate-200 px-1 text-[10px] uppercase dark:bg-slate-700">
                              {t('targets.preview.defaultBranch')}
                            </span>
                          )}
                        </li>
                      ))}
                    </ul>
                  </td>
                  <td className="py-2 text-xs text-slate-600 dark:text-slate-400">
                    <ul className="space-y-0.5">
                      {project.notes.map((note, index) => (
                        <li key={`${note.code}-${index}`}>{note.message}</li>
                      ))}
                    </ul>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {result.skipped.length > 0 && (
        <details className="text-sm">
          <summary className="cursor-pointer font-medium">
            {t('targets.preview.skippedTitle', { count: result.skipped_count })}
          </summary>
          <ul className="mt-2 space-y-1">
            {result.skipped.map((item) => (
              <li key={item.source_ref} className="flex flex-wrap gap-2">
                <code className="text-xs">{item.path_with_namespace}</code>
                <span className="text-xs text-slate-600 dark:text-slate-400">{item.reason.message}</span>
              </li>
            ))}
          </ul>
        </details>
      )}
    </section>
  )
}
