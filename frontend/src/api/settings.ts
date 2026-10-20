// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'

import { getJson, sendJson } from './client'

export interface EnvironmentVariableState {
  name: string
  set: boolean
  secret: boolean
}

export interface NotificationSettings {
  enabled: boolean
  webhook_configured: boolean
  /** The webhook is never sent in full; this is a shortened form for display. */
  webhook_url_masked: string | null
  min_severity: string
}

export interface AppSettings {
  scan_concurrency: number
  default_schedule_cron: string | null
  history_retention_days: number
  global_exclude_patterns: string[]
  notifications: NotificationSettings
  environment: {
    app_name: string
    app_version: string
    variables: EnvironmentVariableState[]
  }
}

export interface ConnectionTestResult {
  ok: boolean
  detail: string
  code: string | null
  version: string | null
}

export type SettingsPatch = Partial<
  Pick<
    AppSettings,
    'scan_concurrency' | 'default_schedule_cron' | 'history_retention_days' | 'global_exclude_patterns'
  >
> & {
  notifications_enabled?: boolean
  /** Full URL; an empty string clears it. */
  notification_webhook_url?: string
  notification_min_severity?: string
}

export const settingsQueryKey = ['settings'] as const

export function useAppSettings() {
  return useQuery({
    queryKey: settingsQueryKey,
    queryFn: ({ signal }) => getJson<AppSettings>('/api/settings', signal),
  })
}

export function useSaveSettings() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (patch: SettingsPatch) => sendJson<AppSettings>('PUT', '/api/settings', patch),
    onSuccess: (settings) => queryClient.setQueryData(settingsQueryKey, settings),
  })
}

/** Connection test; the backend answers with a translated message. */
export function useConnectionTest(what: 'source' | 'dtrack') {
  return useMutation({
    mutationFn: () => sendJson<ConnectionTestResult>('POST', `/api/settings/test-${what}`),
  })
}

/** Send a test message to the global webhook, or to a target's own one. */
export function useWebhookTest() {
  return useMutation({
    mutationFn: (targetId?: number) =>
      sendJson<ConnectionTestResult>(
        'POST',
        targetId ? `/api/settings/test-webhook?target_id=${targetId}` : '/api/settings/test-webhook',
      ),
  })
}
