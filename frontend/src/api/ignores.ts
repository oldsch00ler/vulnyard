// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'

import { getJson, sendJson } from './client'

/** Dependency-Track analysis state a suppressed finding is given. */
export type AnalysisState = 'NOT_AFFECTED' | 'FALSE_POSITIVE' | 'RESOLVED'

export const ANALYSIS_STATES: AnalysisState[] = [
  'NOT_AFFECTED',
  'FALSE_POSITIVE',
  'RESOLVED',
]

/** Pattern that covers any component of the scope. */
export const ANY_COMPONENT = '*'

export interface IgnoreRule {
  id: number
  vuln_id: string
  purl_pattern: string
  /** null = the whole application. */
  target_id: number | null
  target_name: string | null
  analysis_state: AnalysisState
  reason: string
  expires_on: string | null
  /** False once the end date has passed; the rule stays as history. */
  active: boolean
  /** How many findings it really suppresses in Dependency-Track. */
  applied_count: number
  created_at: string
  created_by: string | null
}

export interface IgnoreRulePayload {
  vuln_id: string
  purl_pattern?: string
  target_id?: number | null
  analysis_state?: AnalysisState
  reason?: string
  expires_on?: string | null
}

export interface IgnoreRuleUpdatePayload {
  purl_pattern?: string
  analysis_state?: AnalysisState
  reason?: string
  expires_on?: string | null
  clear_expiry?: boolean
}

export interface IgnoreApplyResult {
  suppressed: number
  reverted: number
  failed: number
  projects: number
  errors: string[]
}

export const ignoresQueryKey = ['ignores']

export function useIgnoreRules(targetId?: number | null) {
  const params = new URLSearchParams()
  if (targetId != null) params.set('target_id', String(targetId))

  return useQuery({
    queryKey: [...ignoresQueryKey, targetId ?? null],
    queryFn: ({ signal }) =>
      getJson<{ items: IgnoreRule[]; total: number }>(
        `/api/ignores${params.size ? `?${params.toString()}` : ''}`,
        signal,
      ),
  })
}

/** Everything a rule touches: the rules, the summary and the dashboard counts. */
function useInvalidateAfterChange() {
  const queryClient = useQueryClient()
  return () => {
    void queryClient.invalidateQueries({ queryKey: ignoresQueryKey })
    void queryClient.invalidateQueries({ queryKey: ['vulnerabilities'] })
    void queryClient.invalidateQueries({ queryKey: ['threats'] })
    void queryClient.invalidateQueries({ queryKey: ['dashboard'] })
    void queryClient.invalidateQueries({ queryKey: ['projects'] })
  }
}

export function useCreateIgnoreRule() {
  const invalidate = useInvalidateAfterChange()
  return useMutation({
    mutationFn: (payload: IgnoreRulePayload) =>
      sendJson<IgnoreRule>('POST', '/api/ignores', payload),
    onSuccess: invalidate,
  })
}

export function useUpdateIgnoreRule() {
  const invalidate = useInvalidateAfterChange()
  return useMutation({
    mutationFn: ({ id, ...payload }: IgnoreRuleUpdatePayload & { id: number }) =>
      sendJson<IgnoreRule>('PATCH', `/api/ignores/${id}`, payload),
    onSuccess: invalidate,
  })
}

export function useDeleteIgnoreRule() {
  const invalidate = useInvalidateAfterChange()
  return useMutation({
    mutationFn: (id: number) => sendJson<null>('DELETE', `/api/ignores/${id}`),
    onSuccess: invalidate,
  })
}

/** Re-apply every rule, for instance after a Dependency-Track outage. */
export function useApplyIgnoreRules() {
  const invalidate = useInvalidateAfterChange()
  return useMutation({
    mutationFn: () => sendJson<IgnoreApplyResult>('POST', '/api/ignores/apply'),
    onSuccess: invalidate,
  })
}
