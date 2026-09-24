// The DNS API through the gateway: the kit client bound to this module's base.
import { createApi, ApiError, csrfToken, describe, type Method, type RequestOptions } from '@go-tangra/ui/api'
import { registerReasons } from '@go-tangra/ui/forms'
import type { paths } from './schema.d'

export { ApiError, csrfToken, describe }
export type { Method, RequestOptions }

// Path names are checked against the OpenAPI contract at compile time.
export type ApiPath = keyof paths
export const BASE = '/api/dns/v1'

// DNS-specific refusal reasons (closed vocabulary, api/openapi/dns.yaml).
registerReasons({
  invalid_name: 'That is not a valid DNS name.',
  invalid_record: 'The record is not valid for its type.',
  invalid_kind: 'That operation is not available for this zone kind.',
  invalid_config: 'The server configuration is not valid.',
  zone_not_found: 'The zone no longer exists.',
  record_not_found: 'The record set no longer exists.',
  template_not_found: 'The template no longer exists.',
  duplicate: 'That zone name is already taken or overlaps an existing zone.',
  pdns_unavailable: 'The DNS server is unavailable; try again shortly.',
  metrics_unavailable: 'DNS metrics are unavailable.',
})

export const api = createApi({ base: BASE })

/**
 * describe() plus the server's own explanation of a validation refusal
 * (invalid_record / invalid_name / bad_request carry detail.message).
 */
export function explain(err: unknown): string {
  const base = describe(err)
  if (err instanceof ApiError && typeof err.detail?.message === 'string' && err.detail.message) return `${base} ${err.detail.message}`
  return base
}
