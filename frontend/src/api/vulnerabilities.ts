// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>

import { useQuery } from '@tanstack/react-query'

import { getJson } from './client'

export interface VulnerabilityItem {
  vuln_id: string
  source: string
  severity: string
  cvss_v3_score: number | null
  epss_score: number | null
  /** Only our own projects are counted; a shared Dependency-Track holds others. */
  affected_project_count: number
  published: string | null
  /** True when every occurrence is suppressed by an ignore rule. */
  ignored: boolean
}

export interface AffectedComponent {
  project_id: number
  path_with_namespace: string
  branch: string
  web_url: string
  is_default_branch: boolean
  component_name: string
  component_version: string | null
  purl: string | null
  latest_version: string | null
  suppressed: boolean
}

export interface AffectedProject {
  dt_project_uuid: string
  dt_name: string
  dt_version: string | null
  project_id: number | null
  path_with_namespace: string | null
  branch: string | null
  web_url: string | null
  is_default_branch: boolean | null
}

export function useVulnerabilities(
  minSeverity: string | null,
  search: string,
  page: number,
  includeIgnored = false,
) {
  const params = new URLSearchParams({ page: String(page) })
  if (minSeverity) params.set('min_severity', minSeverity)
  if (search.trim()) params.set('search', search.trim())
  if (includeIgnored) params.set('include_ignored', 'true')

  return useQuery({
    queryKey: ['vulnerabilities', minSeverity, search.trim(), page, includeIgnored],
    queryFn: ({ signal }) =>
      getJson<{ items: VulnerabilityItem[]; total: number; page: number; page_size: number }>(
        `/api/vulnerabilities?${params.toString()}`,
        signal,
      ),
    staleTime: 60_000,
  })
}

export function useAffectedProjects(source: string | null, vulnId: string | null) {
  return useQuery({
    queryKey: ['vulnerabilities', source, vulnId, 'projects'],
    queryFn: ({ signal }) =>
      getJson<{
        items: AffectedProject[]
        components: AffectedComponent[]
        total: number
        ours: number
      }>(
        `/api/vulnerabilities/${encodeURIComponent(source ?? '')}/${encodeURIComponent(vulnId ?? '')}/projects`,
        signal,
      ),
    enabled: Boolean(source && vulnId),
    staleTime: 60_000,
  })
}
