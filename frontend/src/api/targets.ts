// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'

import { getJson, sendJson } from './client'

export type TargetKind = 'group' | 'project'
export type BranchMode = 'default' | 'custom'

export interface Target {
  id: number
  name: string
  source: string
  kind: TargetKind
  source_ref: string
  source_path: string
  include_subgroups: boolean
  branch_mode: BranchMode
  branch_patterns: string[]
  include_default_branch: boolean
  max_branches_per_project: number
  schedule_cron: string | null
  exclude_patterns: string[]
  skip_unchanged: boolean
  enabled: boolean
  dt_parent_uuid: string | null
  /** Own instance; null means the one from the environment. */
  source_url: string | null
  /** Which instance this target actually talks to. */
  source_url_effective: string | null
  /** Whether the target has its own token; the token never leaves the server. */
  source_token_configured: boolean
  notify_webhook_configured: boolean
  notify_webhook_url_masked: string | null
  created_at: string
  updated_at: string
  updated_by: string | null
}

export interface TargetSelection {
  kind: TargetKind
  source_ref: string
  /** Own instance and token; empty means the ones from the environment. */
  source_url?: string
  source_token?: string
  include_subgroups: boolean
  branch_mode: BranchMode
  branch_patterns: string[]
  include_default_branch: boolean
  max_branches_per_project: number
  exclude_patterns: string[]
}

export interface TargetPayload extends TargetSelection {
  name?: string | null
  source_path?: string | null
  schedule_cron: string | null
  skip_unchanged: boolean
  enabled: boolean
  /** Own chat webhook; empty means "use the global one". */
  notify_webhook_url?: string
}

/**
 * Fields the API allows to change. The kind of the target and its identity in
 * the source are immutable, so an update must not send them at all.
 */
export interface TargetUpdatePayload {
  name?: string
  include_subgroups?: boolean
  branch_mode?: BranchMode
  branch_patterns?: string[]
  include_default_branch?: boolean
  max_branches_per_project?: number
  schedule_cron?: string | null
  exclude_patterns?: string[]
  skip_unchanged?: boolean
  enabled?: boolean
  notify_webhook_url?: string
  source_url?: string
  source_token?: string
}

/** Take the changeable part of a form payload for a PUT. */
export function toUpdatePayload(payload: TargetPayload): TargetUpdatePayload {
  const update: TargetUpdatePayload = {
    include_subgroups: payload.include_subgroups,
    branch_mode: payload.branch_mode,
    branch_patterns: payload.branch_patterns,
    include_default_branch: payload.include_default_branch,
    max_branches_per_project: payload.max_branches_per_project,
    schedule_cron: payload.schedule_cron,
    exclude_patterns: payload.exclude_patterns,
    skip_unchanged: payload.skip_unchanged,
    enabled: payload.enabled,
  }
  // An empty name means "keep the current one", never "clear it".
  if (payload.name && payload.name.trim()) {
    update.name = payload.name.trim()
  }
  // These are sent whenever the field was touched, so they can be cleared.
  if (payload.notify_webhook_url !== undefined) {
    update.notify_webhook_url = payload.notify_webhook_url
  }
  if (payload.source_url !== undefined) {
    update.source_url = payload.source_url
  }
  if (payload.source_token !== undefined) {
    update.source_token = payload.source_token
  }
  return update
}

export interface Note {
  code: string
  params: Record<string, unknown>
  message: string
}

export interface PreviewBranch {
  branch: string
  is_default_branch: boolean
  commit_sha: string | null
}

export interface PreviewProject {
  source_ref: string
  path_with_namespace: string
  name: string
  web_url: string
  default_branch: string | null
  branches: PreviewBranch[]
  notes: Note[]
}

export interface PreviewSkipped {
  source_ref: string
  path_with_namespace: string
  name: string
  web_url: string
  reason: Note
}

export interface PreviewResult {
  projects: PreviewProject[]
  skipped: PreviewSkipped[]
  warnings: Note[]
  project_count: number
  branch_count: number
  skipped_count: number
}

export const targetsQueryKey = ['targets'] as const

export function useTargets() {
  return useQuery({
    queryKey: targetsQueryKey,
    queryFn: ({ signal }) => getJson<{ items: Target[]; total: number }>('/api/targets', signal),
  })
}

export function useCreateTarget() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (payload: TargetPayload) => sendJson<Target>('POST', '/api/targets', payload),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: targetsQueryKey }),
  })
}

export function useUpdateTarget() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ id, ...payload }: TargetUpdatePayload & { id: number }) =>
      sendJson<Target>('PUT', `/api/targets/${id}`, payload),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: targetsQueryKey }),
  })
}

export function useDeleteTarget() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (id: number) => sendJson<null>('DELETE', `/api/targets/${id}`),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: targetsQueryKey }),
  })
}

/** Test the credentials a saved target uses. */
export function useTargetSourceTest() {
  return useMutation({
    mutationFn: (targetId: number) =>
      sendJson<{ ok: boolean; detail: string }>('POST', `/api/targets/${targetId}/test-source`),
  })
}

export function usePreviewTarget() {
  return useMutation({
    mutationFn: (selection: TargetSelection) =>
      sendJson<PreviewResult>('POST', '/api/targets/preview', selection),
  })
}
