// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>

interface StatTileProps {
  label: string
  value: string | number
  hint?: string
  /** Optional colour chip, always accompanied by the label text. */
  chipClass?: string
}

/** One number with its label; no chart, so no hover layer. */
export default function StatTile({ label, value, hint, chipClass }: StatTileProps) {
  return (
    <div className="rounded-lg border border-slate-200 bg-white p-4 dark:border-slate-800 dark:bg-slate-900">
      <div className="flex items-center gap-2">
        {chipClass && <span aria-hidden="true" className={`inline-block size-2.5 rounded-sm ${chipClass}`} />}
        <p className="text-xs uppercase tracking-wide text-slate-500 dark:text-slate-400">{label}</p>
      </div>
      <p className="mt-1 text-2xl font-semibold tabular-nums">{value}</p>
      {hint && <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">{hint}</p>}
    </div>
  )
}
