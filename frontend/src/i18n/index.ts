// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>

import i18next from 'i18next'
import { initReactI18next } from 'react-i18next'

/**
 * Every catalogue in ./locales is picked up at build time: adding a language
 * means adding `locales/<locale>.json` (e.g. `de.json`, `pt-BR.json`) and
 * nothing else. Each catalogue names itself in `language.name`, which is what
 * the language switcher shows.
 */
type Catalog = { language?: { name?: string } } & Record<string, unknown>

const modules = import.meta.glob<Catalog>('./locales/*.json', {
  eager: true,
  import: 'default',
})

const catalogs: Record<string, Catalog> = Object.fromEntries(
  Object.entries(modules).map(([path, catalog]) => [
    path.replace(/^.*\/([^/]+)\.json$/, '$1'),
    catalog,
  ]),
)

/** Complete catalogue every other one falls back to for a missing text. */
export const REFERENCE_LOCALE = 'en'
const STORAGE_KEY = 'vulnyard.locale'

export const resources = Object.fromEntries(
  Object.entries(catalogs).map(([locale, catalog]) => [locale, { translation: catalog }]),
)

export interface LanguageOption {
  locale: string
  name: string
}

/** Languages of the UI, named in their own language and sorted by that name. */
export const languages: LanguageOption[] = Object.entries(catalogs)
  .map(([locale, catalog]) => ({ locale, name: catalog.language?.name ?? locale }))
  .sort((a, b) => a.name.localeCompare(b.name))

/** The available locale `value` names, ignoring case (`pt-br` → `pt-BR`). */
export function matchLocale(value: string | null | undefined): string | null {
  if (!value) return null
  const wanted = value.replace('_', '-').toLowerCase()
  return Object.keys(catalogs).find((locale) => locale.toLowerCase() === wanted) ?? null
}

export function storedLocale(): string | null {
  try {
    return matchLocale(window.localStorage.getItem(STORAGE_KEY))
  } catch {
    return null
  }
}

export function storeLocale(locale: string): void {
  try {
    window.localStorage.setItem(STORAGE_KEY, locale)
  } catch {
    // Private mode or blocked storage – the language simply is not remembered.
  }
}

function setDocumentLanguage(locale: string): void {
  document.documentElement.lang = locale
  document
    .querySelector('meta[name="description"]')
    ?.setAttribute('content', i18next.t('app.description'))
}

/** Language selection: stored choice, otherwise default_locale from /api/status. */
export function applyLocale(defaultLocale: string | undefined): void {
  const locale = storedLocale() ?? matchLocale(defaultLocale) ?? REFERENCE_LOCALE
  if (i18next.language !== locale) {
    void i18next.changeLanguage(locale).then(() => setDocumentLanguage(locale))
  } else {
    setDocumentLanguage(locale)
  }
}

/** The user picked a language in the switcher; it wins over default_locale. */
export async function chooseLocale(locale: string): Promise<void> {
  storeLocale(locale)
  await i18next.changeLanguage(locale)
  setDocumentLanguage(locale)
}

void i18next.use(initReactI18next).init({
  resources,
  lng: storedLocale() ?? REFERENCE_LOCALE,
  fallbackLng: REFERENCE_LOCALE,
  interpolation: { escapeValue: false },
})

export default i18next
