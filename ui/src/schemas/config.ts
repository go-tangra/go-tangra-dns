import { z } from 'zod'
import { listField } from './zone'

export const DNSSEC_MODES = ['off', 'process', 'validate'] as const
export const MAX_CONFIG_LIST = 32

const IPV4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/
const IPV6 = /^[0-9a-fA-F:.]+$/

/** An IPv4 or IPv6 literal (light client check; the server is authoritative). */
export function ipLiteral(s: string): boolean {
  return IPV4.test(s) || (s.includes(':') && IPV6.test(s) && !s.includes(':::'))
}

/** An IP or CIDR. */
export function networkOk(s: string): boolean {
  const [ip, bits, ...rest] = s.split('/')
  if (rest.length || !ip || !ipLiteral(ip)) return false
  if (bits === undefined) return true
  const n = Number(bits)
  return /^\d{1,3}$/.test(bits) && n >= 0 && n <= (ip.includes(':') ? 128 : 32)
}

/** IP, IPv4:port or [IPv6]:port. */
export function upstreamOk(s: string): boolean {
  const v6 = /^\[([0-9a-fA-F:.]+)\]:(\d{1,5})$/.exec(s)
  if (v6) return ipLiteral(v6[1] ?? '') && Number(v6[2]) >= 1 && Number(v6[2]) <= 65535
  const v4 = /^([\d.]+):(\d{1,5})$/.exec(s)
  if (v4) return IPV4.test(v4[1] ?? '') && Number(v4[2]) >= 1 && Number(v4[2]) <= 65535
  return ipLiteral(s)
}

export const isOpenNetwork = (n: string): boolean => n === '0.0.0.0/0' || n === '::/0'

const port = z.coerce.number().int('A whole number.').min(1, 'At least 1.').max(65535, 'At most 65535.')

function checkList(ctx: z.RefinementCtx, path: string, items: string[], ok: (s: string) => boolean, what: string, required = false): void {
  if (required && items.length === 0) ctx.addIssue({ code: 'custom', path: [path], message: 'At least one entry is required.' })
  if (items.length > MAX_CONFIG_LIST) ctx.addIssue({ code: 'custom', path: [path], message: `At most ${MAX_CONFIG_LIST} entries.` })
  for (const i of items) if (!ok(i)) ctx.addIssue({ code: 'custom', path: [path], message: `${i} is not ${what}.` })
}

/**
 * The configuration form (flat fields; lists are comma/space/newline
 * separated). The server validates and canonicalises every value again.
 */
export const configSchema = z
  .object({
    recursor_listen: listField(),
    recursor_port: port,
    recursor_allowed: listField(),
    recursor_upstreams: listField(),
    dnssec_validation: z.enum(DNSSEC_MODES),
    allow_open_resolver: z.boolean().optional().transform((v) => v ?? false),
    auth_listen: listField(),
    auth_port: port,
    auth_peers: listField(),
  })
  .superRefine((v, ctx) => {
    checkList(ctx, 'recursor_listen', v.recursor_listen, ipLiteral, 'an IP address', true)
    checkList(ctx, 'recursor_allowed', v.recursor_allowed, networkOk, 'an IP address or CIDR')
    checkList(ctx, 'recursor_upstreams', v.recursor_upstreams, upstreamOk, 'an IP[:port]')
    checkList(ctx, 'auth_listen', v.auth_listen, ipLiteral, 'an IP address', true)
    checkList(ctx, 'auth_peers', v.auth_peers, networkOk, 'an IP address or CIDR')
    if (!v.allow_open_resolver && v.recursor_allowed.some(isOpenNetwork))
      ctx.addIssue({ code: 'custom', path: ['recursor_allowed'], message: 'This opens the resolver to every client; confirm with "Allow an open resolver".' })
  })
export type ConfigFormOutput = z.output<typeof configSchema>
