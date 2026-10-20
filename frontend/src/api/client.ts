// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>

import i18next from '../i18n'

/** Error returned by the API: {"error": {code, params, message}} (SPEC 11). */
export interface ApiErrorBody {
  code: string
  params: Record<string, unknown>
  message: string
}

export class ApiError extends Error {
  readonly status: number
  readonly code: string
  readonly params: Record<string, unknown>

  constructor(status: number, body?: ApiErrorBody) {
    super(body?.message ?? `HTTP ${status}`)
    this.name = 'ApiError'
    this.status = status
    this.code = body?.code ?? `http_${status}`
    this.params = body?.params ?? {}
  }
}

/**
 * Headers of every request. The backend renders its messages (errors, job
 * notes) in the language the UI shows, not in the browser's preference.
 */
function baseHeaders(): Record<string, string> {
  return {
    Accept: 'application/json',
    ...(i18next.language ? { 'Accept-Language': i18next.language } : {}),
  }
}

/** GET a JSON endpoint of our own backend (never GitLab or Dependency-Track). */
export async function getJson<T>(path: string, signal?: AbortSignal): Promise<T> {
  const response = await fetch(path, {
    signal,
    headers: baseHeaders(),
  })

  if (!response.ok) {
    let body: ApiErrorBody | undefined
    try {
      const payload = (await response.json()) as { error?: ApiErrorBody }
      body = payload.error
    } catch {
      body = undefined
    }
    throw new ApiError(response.status, body)
  }

  return (await response.json()) as T
}

/** Send a JSON request to our backend and parse the response (204 → null). */
export async function sendJson<T>(
  method: 'POST' | 'PUT' | 'PATCH' | 'DELETE',
  path: string,
  body?: unknown,
): Promise<T> {
  const response = await fetch(path, {
    method,
    headers: {
      ...baseHeaders(),
      ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  })

  if (!response.ok) {
    let error: ApiErrorBody | undefined
    try {
      const payload = (await response.json()) as { error?: ApiErrorBody }
      error = payload.error
    } catch {
      error = undefined
    }
    throw new ApiError(response.status, error)
  }

  if (response.status === 204) {
    return null as T
  }
  return (await response.json()) as T
}
