// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>

import { useMutation, useQuery } from '@tanstack/react-query'

import { getJson, sendJson } from './client'

/** Minimum length of a search term the source accepts (mirrors the backend). */
export const MIN_SEARCH_LENGTH = 3

export interface SourceGroup {
  ref: string
  path: string
  name: string
  web_url: string | null
}

export interface SourceProject {
  ref: string
  path_with_namespace: string
  name: string
  web_url: string
  default_branch: string | null
  archived: boolean
  empty_repo: boolean
}

export interface SourceBranch {
  name: string
  commit_sha: string | null
  is_default: boolean
  protected: boolean
}

/** Credentials a target will use; empty means the ones from the environment. */
export interface SourceCredentials {
  source_url?: string | null
  source_token?: string | null
}

/**
 * Suggestions go through POST when credentials are involved: a token belongs in
 * the body, never in a URL that ends up in logs and browser history.
 */
export function useGroupSuggestions(search: string, credentials: SourceCredentials = {}) {
  const enabled = search.trim().length >= MIN_SEARCH_LENGTH
  return useQuery({
    queryKey: [
      'source',
      'groups',
      search.trim(),
      credentials.source_url ?? '',
      Boolean(credentials.source_token),
    ],
    queryFn: () =>
      sendJson<SourceGroup[]>('POST', '/api/source/groups', { search: search.trim(), ...credentials }),
    enabled,
    staleTime: 60_000,
  })
}

export function useProjectSuggestions(search: string, credentials: SourceCredentials = {}) {
  const enabled = search.trim().length >= MIN_SEARCH_LENGTH
  return useQuery({
    queryKey: [
      'source',
      'projects',
      search.trim(),
      credentials.source_url ?? '',
      Boolean(credentials.source_token),
    ],
    queryFn: () =>
      sendJson<SourceProject[]>('POST', '/api/source/projects', {
        search: search.trim(),
        ...credentials,
      }),
    enabled,
    staleTime: 60_000,
  })
}

/** Check credentials before a target is saved with them. */
export function useSourceTest() {
  return useMutation({
    mutationFn: (credentials: SourceCredentials) =>
      sendJson<{ ok: boolean; detail: string; code: string | null; version: string | null }>(
        'POST',
        '/api/source/test',
        credentials,
      ),
  })
}

export function useBranchSuggestions(projectRef: string | null, search: string) {
  return useQuery({
    queryKey: ['source', 'branches', projectRef, search.trim()],
    queryFn: ({ signal }) =>
      getJson<SourceBranch[]>(
        `/api/source/projects/${encodeURIComponent(projectRef ?? '')}/branches?search=${encodeURIComponent(search.trim())}`,
        signal,
      ),
    enabled: Boolean(projectRef),
    staleTime: 60_000,
  })
}
