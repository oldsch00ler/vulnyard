// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'

import { getJson, sendJson } from './client'

/** What another system may do with the token; `write` includes `read`. */
export type ApiTokenScope = 'read' | 'write'

export const API_TOKEN_SCOPES: ApiTokenScope[] = ['read', 'write']

export interface ApiToken {
  id: number
  name: string
  /** First characters of the token, to tell tokens apart; never the token. */
  token_prefix: string
  scope: ApiTokenScope
  expires_on: string | null
  /** False once the end date has passed. */
  active: boolean
  last_used_at: string | null
  created_at: string
  created_by: string | null
}

/** Response to creating a token: the only time the token itself comes back. */
export interface CreatedApiToken extends ApiToken {
  token: string
}

export interface ApiTokenPayload {
  name: string
  scope: ApiTokenScope
  expires_on?: string | null
}

export const tokensQueryKey = ['tokens']

export function useApiTokens() {
  return useQuery({
    queryKey: tokensQueryKey,
    queryFn: ({ signal }) =>
      getJson<{ items: ApiToken[]; total: number }>('/api/tokens', signal),
  })
}

export function useCreateApiToken() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (payload: ApiTokenPayload) =>
      sendJson<CreatedApiToken>('POST', '/api/tokens', payload),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: tokensQueryKey }),
  })
}

export function useDeleteApiToken() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (id: number) => sendJson<null>('DELETE', `/api/tokens/${id}`),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: tokensQueryKey }),
  })
}
