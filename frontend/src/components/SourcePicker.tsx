// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>

import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'

import {
  MIN_SEARCH_LENGTH,
  type SourceCredentials,
  useGroupSuggestions,
  useProjectSuggestions,
} from '../api/source'
import type { TargetKind } from '../api/targets'

export interface SourceSelection {
  ref: string
  path: string
  name: string
  defaultBranch?: string | null
}

interface SourcePickerProps {
  kind: TargetKind
  value: SourceSelection | null
  onChange: (selection: SourceSelection | null) => void
  inputId: string
  /** Credentials of the target being created; empty uses the configured ones. */
  credentials?: SourceCredentials
}

/** Autocomplete over groups or projects of the repository source. */
export default function SourcePicker({
  kind,
  value,
  onChange,
  inputId,
  credentials = {},
}: SourcePickerProps) {
  const { t } = useTranslation()
  const [search, setSearch] = useState('')
  const [debounced, setDebounced] = useState('')

  useEffect(() => {
    const timer = window.setTimeout(() => setDebounced(search), 300)
    return () => window.clearTimeout(timer)
  }, [search])

  const groups = useGroupSuggestions(kind === 'group' ? debounced : '', credentials)
  const projects = useProjectSuggestions(kind === 'project' ? debounced : '', credentials)
  const query = kind === 'group' ? groups : projects

  const options: SourceSelection[] =
    kind === 'group'
      ? (groups.data ?? []).map((group) => ({ ref: group.ref, path: group.path, name: group.name }))
      : (projects.data ?? []).map((project) => ({
          ref: project.ref,
          path: project.path_with_namespace,
          name: project.name,
          defaultBranch: project.default_branch,
        }))

  if (value) {
    return (
      <div className="space-y-1">
        <span className="block text-sm font-medium">
          {kind === 'group' ? t('targets.form.group') : t('targets.form.project')}
        </span>
        <div className="flex items-center justify-between gap-2 rounded-md border border-slate-300 bg-white px-3 py-2 text-sm dark:border-slate-700 dark:bg-slate-900">
          <span>
            <code>{value.path}</code>
            {value.defaultBranch && (
              <span className="ml-2 text-xs text-slate-500 dark:text-slate-400">
                {t('targets.form.defaultBranchIs', { branch: value.defaultBranch })}
              </span>
            )}
          </span>
          <button
            type="button"
            onClick={() => {
              onChange(null)
              setSearch('')
            }}
            className="text-xs underline hover:no-underline"
          >
            {t('common.change')}
          </button>
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-1">
      <label htmlFor={inputId} className="block text-sm font-medium">
        {kind === 'group' ? t('targets.form.group') : t('targets.form.project')}
      </label>
      <input
        id={inputId}
        value={search}
        onChange={(event) => setSearch(event.target.value)}
        placeholder={t('targets.form.searchPlaceholder', { min: MIN_SEARCH_LENGTH })}
        className="w-full rounded-md border border-slate-300 bg-white px-3 py-2 text-sm dark:border-slate-700 dark:bg-slate-900"
      />

      {search.trim().length > 0 && search.trim().length < MIN_SEARCH_LENGTH && (
        <p className="text-xs text-slate-500 dark:text-slate-400">
          {t('targets.form.searchTooShort', { min: MIN_SEARCH_LENGTH })}
        </p>
      )}

      {query.isFetching && <p className="text-xs text-slate-500 dark:text-slate-400">{t('common.loading')}</p>}

      {query.isError && (
        <p className="text-xs text-red-600 dark:text-red-400">{t('targets.form.searchFailed')}</p>
      )}

      {options.length > 0 && (
        <ul className="max-h-56 divide-y divide-slate-100 overflow-auto rounded-md border border-slate-200 dark:divide-slate-800 dark:border-slate-700">
          {options.map((option) => (
            <li key={option.ref}>
              <button
                type="button"
                onClick={() => onChange(option)}
                className="flex w-full flex-col items-start px-3 py-2 text-left text-sm hover:bg-slate-100 dark:hover:bg-slate-800"
              >
                <code className="text-xs">{option.path}</code>
                <span className="text-slate-600 dark:text-slate-400">{option.name}</span>
              </button>
            </li>
          ))}
        </ul>
      )}

      {!query.isFetching && debounced.trim().length >= MIN_SEARCH_LENGTH && options.length === 0 && (
        <p className="text-xs text-slate-500 dark:text-slate-400">{t('targets.form.noResults')}</p>
      )}
    </div>
  )
}
