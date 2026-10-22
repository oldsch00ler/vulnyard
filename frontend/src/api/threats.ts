// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>

import { useQuery } from '@tanstack/react-query'

import { getJson } from './client'

export const THREAT_REASONS = ['exploited', 'likely', 'new'] as const
export type ThreatReason = (typeof THREAT_REASONS)[number]

export interface KevInfo {
  cve_id: string
  name: string
  date_added: string | null
  due_date: string | null
  ransomware: boolean
  /** Text from the CISA catalog, in English. */
  required_action: string
}

export interface ThreatItem {
  vuln_id: string
  source: string
  severity: string
  cvss_v3_score: number | null
  epss_score: number | null
  epss_percentile: number | null
  reasons: ThreatReason[]
  cve_ids: string[]
  kev: KevInfo | null
  first_seen: string | null
  affected_project_count: number
  newer_version_available: boolean
}

export interface ThreatList {
  items: ThreatItem[]
  total: number
  page: number
  page_size: number
  counts: Record<ThreatReason, number>
  kev: {
    enabled: boolean
    available: boolean
    count: number
    fetched_at: string | null
    released_at: string | null
    error_code: string | null
  }
  epss_available: boolean
  epss_threshold: number
  new_days: number
}

export function useThreats(
  reason: ThreatReason | null,
  epss: number,
  days: number,
  page: number,
) {
  const params = new URLSearchParams({ epss: String(epss), days: String(days), page: String(page) })
  if (reason) params.set('reason', reason)

  return useQuery({
    queryKey: ['threats', reason, epss, days, page],
    queryFn: ({ signal }) => getJson<ThreatList>(`/api/threats?${params.toString()}`, signal),
    staleTime: 60_000,
  })
}
