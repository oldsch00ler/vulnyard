// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>

import { useQuery } from '@tanstack/react-query'

import { getJson } from './client'

export interface ToolStatus {
  available: boolean
  path: string | null
  version: string | null
}

export interface AppStatus {
  app: { name: string; version: string }
  config: { complete: boolean; missing: string[]; scanning_enabled: boolean }
  tools: { trivy: ToolStatus; git: ToolStatus }
  source: { kind: string; url: string; configured: boolean; reachable: boolean | null; version: string | null }
  dtrack: {
    configured: boolean
    ui_url: string | null
    reachable: boolean | null
    version: string | null
    supported: boolean | null
    minimum_version: string | null
  }
  scheduler: { running: boolean; scheduled_targets: number; next_run_at: string | null }
  worker: { running: boolean; active_jobs: number | null; queued_jobs: number | null }
  runtime: {
    dt_ui_url: string | null
    source_url: string | null
    auth_mode: string
    default_locale: string
    available_locales: string[]
  }
}

export const statusQueryKey = ['status'] as const

/** Runtime configuration and application state; nothing is baked in at build time. */
export function useStatus() {
  return useQuery({
    queryKey: statusQueryKey,
    queryFn: ({ signal }) => getJson<AppStatus>('/api/status', signal),
    staleTime: 30_000,
    refetchOnWindowFocus: true,
    // While something is being scanned, keep the header indicator fresh.
    refetchInterval: (query) => {
      const worker = query.state.data?.worker
      const busy = (worker?.active_jobs ?? 0) > 0 || (worker?.queued_jobs ?? 0) > 0
      return busy ? 5_000 : false
    },
  })
}

export interface Identity {
  email: string | null
  auth_mode: string
}

/** Who is signed in; only meaningful in proxy-header mode. */
export function useIdentity(enabled: boolean) {
  return useQuery({
    queryKey: ['me'],
    queryFn: ({ signal }) => getJson<Identity>('/api/me', signal),
    enabled,
    staleTime: 300_000,
  })
}
