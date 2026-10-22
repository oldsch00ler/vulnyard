// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>

// Shared button looks, so an action is recognisable as one wherever it sits.
// Hover uses `enabled:` so a disabled button does not pretend to react.

/** Main action of a page or form (save, create, scan). */
export const primaryButton =
  'rounded-md bg-slate-900 px-3 py-2 text-sm font-medium text-white enabled:hover:bg-slate-700 disabled:opacity-40 dark:bg-slate-100 dark:text-slate-900 dark:enabled:hover:bg-slate-300'

/** Secondary action next to a primary one (cancel, test). */
export const secondaryButton =
  'rounded-md border border-slate-300 px-3 py-2 text-sm font-medium enabled:hover:bg-slate-100 disabled:opacity-40 dark:border-slate-700 dark:enabled:hover:bg-slate-800'

/** Primary action in a tight spot (a header next to a title, an inline form). */
export const compactPrimaryButton =
  'rounded-md bg-slate-900 px-3 py-1.5 text-sm font-medium text-white enabled:hover:bg-slate-700 disabled:opacity-40 dark:bg-slate-100 dark:text-slate-900 dark:enabled:hover:bg-slate-300'

/** Secondary action in a tight spot (connection tests, header actions). */
export const compactSecondaryButton =
  'rounded-md border border-slate-300 px-3 py-1.5 text-sm font-medium enabled:hover:bg-slate-100 disabled:opacity-40 dark:border-slate-700 dark:enabled:hover:bg-slate-800'

/** Button next to an input, matching its height. */
export const inputButton =
  'rounded-md border border-slate-300 px-2 py-1 text-sm enabled:hover:bg-slate-100 disabled:opacity-40 dark:border-slate-700 dark:enabled:hover:bg-slate-800'

/** Small action in a section header, a table row or a pager. */
export const smallButton =
  'rounded-md border border-slate-300 px-2.5 py-1 text-xs font-medium enabled:hover:bg-slate-100 disabled:opacity-40 dark:border-slate-700 dark:enabled:hover:bg-slate-800'

/** Small main action, e.g. saving an inline form. */
export const smallPrimaryButton =
  'rounded-md bg-slate-900 px-2.5 py-1 text-xs font-medium text-white enabled:hover:bg-slate-700 disabled:opacity-40 dark:bg-slate-100 dark:text-slate-900 dark:enabled:hover:bg-slate-300'

/** Small destructive action. */
export const smallDangerButton =
  'rounded-md border border-red-300 px-2.5 py-1 text-xs font-medium text-red-700 enabled:hover:bg-red-50 disabled:opacity-40 dark:border-red-500/40 dark:text-red-300 dark:enabled:hover:bg-red-500/10'
