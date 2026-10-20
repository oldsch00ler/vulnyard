// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'

import { getJson, sendJson } from './client'
import { statusQueryKey } from './status'

export type RunStatus = 'queued' | 'running' | 'done' | 'failed' | 'cancelled'
export type JobStatus =
  | 'queued'
  | 'cloning'
  | 'scanning'
  | 'uploading'
  | 'processing'
  | 'done'
  | 'skipped'
  | 'failed'
  | 'cancelled'

/** Statuses that mean the run is still being worked on. */
export const ACTIVE_RUN_STATUSES: RunStatus[] = ['queued', 'running']
/** Pages with a running scan refresh every 5 seconds (SPEC section 12). */
export const ACTIVE_REFETCH_MS = 5_000

export interface Job {
  id: number
  project_id: number
  path_with_namespace: string
  name: string
  branch: string
  is_default_branch: boolean
  web_url: string
  status: JobStatus
  commit_sha: string | null
  components_count: number | null
  sbom_bytes: number | null
  dt_project_uuid: string | null
  skip_reason: string | null
  skip_message: string | null
  error_code: string | null
  error_params: Record<string, unknown>
  error_message: string | null
  error_detail: string | null
  log_tail: string | null
  queued_at: string
  started_at: string | null
  finished_at: string | null
  duration_ms: number | null
}

export interface Run {
  id: number
  trigger: 'manual' | 'schedule'
  target_id: number | null
  target_name: string | null
  triggered_by: string | null
  status: RunStatus
  created_at: string
  started_at: string | null
  finished_at: string | null
  total: number
  succeeded: number
  failed: number
  skipped: number
}

export interface RunDetail extends Run {
  jobs: Job[]
}

export const runsQueryKey = ['runs'] as const

export function useRuns() {
  return useQuery({
    queryKey: runsQueryKey,
    queryFn: ({ signal }) => getJson<{ items: Run[]; total: number }>('/api/runs', signal),
    refetchInterval: (query) =>
      (query.state.data?.items ?? []).some((run) => ACTIVE_RUN_STATUSES.includes(run.status))
        ? ACTIVE_REFETCH_MS
        : false,
  })
}

export function useRun(runId: number | null) {
  return useQuery({
    queryKey: ['runs', runId],
    queryFn: ({ signal }) => getJson<RunDetail>(`/api/runs/${runId}`, signal),
    enabled: runId !== null,
    refetchInterval: (query) =>
      query.state.data && ACTIVE_RUN_STATUSES.includes(query.state.data.status)
        ? ACTIVE_REFETCH_MS
        : false,
  })
}

/** Queue a run for one target; `force` rescans even unchanged commits. */
export function useScanTarget() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ targetId, force = false }: { targetId: number; force?: boolean }) =>
      sendJson<Run>('POST', `/api/targets/${targetId}/scan?force=${force}`),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: runsQueryKey })
      void queryClient.invalidateQueries({ queryKey: statusQueryKey })
    },
  })
}

/** Queue a run for every enabled target. */
export function useScanEverything() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (force: boolean) => sendJson<RunDetail>('POST', `/api/runs?force=${force}`),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: runsQueryKey })
      void queryClient.invalidateQueries({ queryKey: statusQueryKey })
    },
  })
}

/** Cancel a queued or running run. */
export function useCancelRun() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (runId: number) => sendJson<RunDetail>('POST', `/api/runs/${runId}/cancel`),
    onSuccess: (run) => {
      queryClient.setQueryData(['runs', run.id], run)
      void queryClient.invalidateQueries({ queryKey: runsQueryKey })
      void queryClient.invalidateQueries({ queryKey: statusQueryKey })
    },
  })
}
