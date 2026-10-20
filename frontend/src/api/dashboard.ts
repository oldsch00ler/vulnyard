// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>

import { useQuery } from '@tanstack/react-query'

import { getJson } from './client'

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'unassigned'

export const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'unassigned']

export interface SeverityCounts {
  critical: number
  high: number
  medium: number
  low: number
  unassigned: number
}

export interface DashboardSummary {
  severities: SeverityCounts
  findings_total: number
  projects_total: number
  projects_scanned: number
  projects_vulnerable: number
  components: number
  vulnerable_components: number
  scan_state: {
    last_run_id: number | null
    last_run_status: string | null
    last_run_finished_at: string | null
    failed_jobs_24h: number
    next_run_at: string | null
  }
}

export interface TrendPoint {
  date: string
  critical: number
  high: number
  medium: number
  low: number
  unassigned: number
  projects: number
}

export interface ProjectListItem {
  id: number
  source: string
  source_project_id: string
  path_with_namespace: string
  name: string
  branch: string
  is_default_branch: boolean
  web_url: string
  targets: string[]
  severities: SeverityCounts
  findings_total: number
  components: number
  vulnerable_components: number
  risk_score: number | null
  last_scan_at: string | null
  last_scan_status: string | null
  dt_project_uuid: string | null
  excluded: boolean
}

export interface TargetSummary {
  target_id: number
  name: string
  kind: string
  source_path: string
  enabled: boolean
  projects_total: number
  projects_vulnerable: number
  severities: SeverityCounts
  findings_total: number
  components: number
  vulnerable_components: number
  risk_score: number
  /** Change of the findings total over the window; null without snapshots. */
  change: number | null
}

export const TREND_WINDOWS = [30, 90, 180] as const

export function useSummary() {
  return useQuery({
    queryKey: ['dashboard', 'summary'],
    queryFn: ({ signal }) => getJson<DashboardSummary>('/api/dashboard/summary', signal),
    staleTime: 30_000,
  })
}

export function useTrend(days: number, targetId: number | null = null) {
  return useQuery({
    queryKey: ['dashboard', 'trend', days, targetId],
    queryFn: ({ signal }) =>
      getJson<{ days: number; points: TrendPoint[]; target_id: number | null }>(
        `/api/dashboard/trend?days=${days}${targetId ? `&target_id=${targetId}` : ''}`,
        signal,
      ),
    staleTime: 60_000,
  })
}

/** Totals per scan target, so it is visible whose numbers are growing. */
export function useTargetSummaries(days: number) {
  return useQuery({
    queryKey: ['dashboard', 'by-target', days],
    queryFn: ({ signal }) =>
      getJson<{ days: number; items: TargetSummary[] }>(
        `/api/dashboard/by-target?days=${days}`,
        signal,
      ),
    staleTime: 60_000,
  })
}

export function useTopProjects(limit = 10) {
  return useQuery({
    queryKey: ['dashboard', 'top-projects', limit],
    queryFn: ({ signal }) =>
      getJson<ProjectListItem[]>(`/api/dashboard/top-projects?limit=${limit}`, signal),
    staleTime: 30_000,
  })
}
