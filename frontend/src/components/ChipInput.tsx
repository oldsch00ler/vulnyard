// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>

import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { inputButton } from '../lib/buttons'

interface ChipInputProps {
  values: string[]
  onChange: (values: string[]) => void
  placeholder?: string
  label: string
  hint?: string
  suggestions?: string[]
  inputId: string
}

/** Small tag editor used for branch patterns and exclude patterns. */
export default function ChipInput({
  values,
  onChange,
  placeholder,
  label,
  hint,
  suggestions = [],
  inputId,
}: ChipInputProps) {
  const { t } = useTranslation()
  const [draft, setDraft] = useState('')

  const add = (value: string) => {
    const trimmed = value.trim()
    if (trimmed && !values.includes(trimmed)) {
      onChange([...values, trimmed])
    }
    setDraft('')
  }

  const remove = (value: string) => onChange(values.filter((item) => item !== value))

  return (
    <div className="space-y-1">
      <label htmlFor={inputId} className="block text-sm font-medium">
        {label}
      </label>

      <div className="flex flex-wrap gap-1">
        {values.map((value) => (
          <span
            key={value}
            className="inline-flex items-center gap-1 rounded-full bg-slate-200 px-2 py-0.5 text-xs dark:bg-slate-700"
          >
            <code>{value}</code>
            <button
              type="button"
              onClick={() => remove(value)}
              aria-label={t('common.remove', { value })}
              className="text-slate-500 hover:text-slate-900 dark:hover:text-slate-100"
            >
              ×
            </button>
          </span>
        ))}
      </div>

      <div className="flex gap-2">
        <input
          id={inputId}
          value={draft}
          placeholder={placeholder}
          onChange={(event) => setDraft(event.target.value)}
          onKeyDown={(event) => {
            if (event.key === 'Enter' || event.key === ',') {
              event.preventDefault()
              add(draft)
            }
          }}
          className="w-full rounded-md border border-slate-300 bg-white px-2 py-1 text-sm dark:border-slate-700 dark:bg-slate-900"
        />
        <button
          type="button"
          onClick={() => add(draft)}
          disabled={!draft.trim()}
          className={inputButton}
        >
          {t('common.add')}
        </button>
      </div>

      {suggestions.length > 0 && (
        <div className="flex flex-wrap gap-1 pt-1">
          {suggestions
            .filter((suggestion) => !values.includes(suggestion))
            .slice(0, 8)
            .map((suggestion) => (
              <button
                key={suggestion}
                type="button"
                onClick={() => add(suggestion)}
                className="rounded-full border border-dashed border-slate-300 px-2 py-0.5 text-xs text-slate-600 hover:bg-slate-100 dark:border-slate-600 dark:text-slate-300 dark:hover:bg-slate-800"
              >
                + {suggestion}
              </button>
            ))}
        </div>
      )}

      {hint && <p className="text-xs text-slate-500 dark:text-slate-400">{hint}</p>}
    </div>
  )
}
