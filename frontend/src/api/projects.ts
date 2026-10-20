// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'

import type { ProjectListItem, SeverityCounts, TrendPoint } from './dashboard'
import { getJson, sendJson } from './client'
import type { Run } from './runs'

export interface BranchOverride {
  branch_mode: 'default' | 'custom'
  branch_patterns: string[]
  include_default_branch: boolean
}

export interface ProjectBranchSummary {
  id: number
  branch: string
  is_default_branch: boolean
  last_scan_at: string | null
}

export interface ProjectDetail extends ProjectListItem {
  default_branch: string | null
  last_commit_sha: string | null
  last_scanned_sha: string | null
  dt_last_import: string | null
  branches: ProjectBranchSummary[]
  branch_override: BranchOverride | null
}

export interface Finding {
  vuln_id: string
  source: string
  severity: string
  cvss_v3_score: number | null
  epss_score: number | null
  epss_percentile: number | null
  cwe: string | null
  published: string | null
  component_name: string
  component_version: string | null
  purl: string | null
  latest_version: string | null
  suppressed: boolean
  attributed_on: string | null
}

export interface ProjectHistoryItem {
  job_id: number
  run_id: number
  status: string
  commit_sha: string | null
  components_count: number | null
  skip_reason: string | null
  skip_message: string | null
  error_code: string | null
  error_message: string | null
  started_at: string | null
  finished_at: string | null
  duration_ms: number | null
}

export interface ProjectFilters {
  target_id?: number | null
  search?: string
  min_severity?: string | null
  status?: string | null
  branch?: 'default' | 'all'
  sort?: string
  page?: number
}

export function projectListKey(filters: ProjectFilters) {
  return ['projects', filters] as const
}

function toQuery(filters: ProjectFilters): string {
  const params = new URLSearchParams()
  if (filters.target_id) params.set('target_id', String(filters.target_id))
  if (filters.search) params.set('search', filters.search)
  if (filters.min_severity) params.set('min_severity', filters.min_severity)
  if (filters.status) params.set('status', filters.status)
  params.set('branch', filters.branch ?? 'default')
  params.set('sort', filters.sort ?? 'risk')
  params.set('page', String(filters.page ?? 1))
  return params.toString()
}

export function useProjects(filters: ProjectFilters) {
  return useQuery({
    queryKey: projectListKey(filters),
    queryFn: ({ signal }) =>
      getJson<{ items: ProjectListItem[]; total: number; page: number; page_size: number }>(
        `/api/projects?${toQuery(filters)}`,
        signal,
      ),
    staleTime: 30_000,
  })
}

export function useProject(projectId: number | null) {
  return useQuery({
    queryKey: ['projects', projectId],
    queryFn: ({ signal }) => getJson<ProjectDetail>(`/api/projects/${projectId}`, signal),
    enabled: projectId !== null,
  })
}

export function useProjectFindings(projectId: number | null, enabled: boolean) {
  return useQuery({
    queryKey: ['projects', projectId, 'findings'],
    queryFn: ({ signal }) =>
      getJson<{ items: Finding[]; total: number }>(`/api/projects/${projectId}/findings`, signal),
    enabled: projectId !== null && enabled,
    staleTime: 60_000,
  })
}

export function useProjectHistory(projectId: number | null) {
  return useQuery({
    queryKey: ['projects', projectId, 'history'],
    queryFn: ({ signal }) =>
      getJson<{ items: ProjectHistoryItem[]; snapshots: TrendPoint[] }>(
        `/api/projects/${projectId}/history`,
        signal,
      ),
    enabled: projectId !== null,
  })
}

export function useScanProject() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (projectId: number) => sendJson<Run>('POST', `/api/projects/${projectId}/scan`),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['runs'] })
      void queryClient.invalidateQueries({ queryKey: ['status'] })
    },
  })
}

export function useSetProjectExcluded() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ projectId, excluded }: { projectId: number; excluded: boolean }) =>
      sendJson<ProjectDetail>('PATCH', `/api/projects/${projectId}`, { excluded }),
    onSuccess: (project) => {
      queryClient.setQueryData(['projects', project.id], project)
      void queryClient.invalidateQueries({ queryKey: ['projects'] })
      void queryClient.invalidateQueries({ queryKey: ['dashboard'] })
    },
  })
}

export function useSaveBranchOverride() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ projectId, override }: { projectId: number; override: BranchOverride }) =>
      sendJson<unknown>('PUT', `/api/projects/${projectId}/branch-override`, override),
    onSuccess: (_data, variables) => {
      void queryClient.invalidateQueries({ queryKey: ['projects', variables.projectId] })
    },
  })
}

export function useDeleteBranchOverride() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (projectId: number) =>
      sendJson<null>('DELETE', `/api/projects/${projectId}/branch-override`),
    onSuccess: (_data, projectId) => {
      void queryClient.invalidateQueries({ queryKey: ['projects', projectId] })
    },
  })
}

export type { ProjectListItem, SeverityCounts }
