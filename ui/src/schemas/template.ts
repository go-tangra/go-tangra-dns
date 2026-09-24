import { z } from 'zod'
import { optionalString } from '@go-tangra/ui/forms'
import { RECORD_TYPES, TTL_MAX, TTL_MIN } from './record'
import { zoneNameOk } from './zone'

/** Replaced by the zone name (without its trailing dot) when a zone is created. */
export const ZONE_PLACEHOLDER = '[ZONE]'
export const MAX_TEMPLATE_RECORDS = 200
/** Types whose priority is a separate field. */
export const PRIORITY_TYPES = ['MX', 'SRV'] as const
export const hasPriority = (type: string): boolean => (PRIORITY_TYPES as readonly string[]).includes(type)

function noControl(s: string): boolean {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i)
    if (c < 0x20 || c === 0x7f) return false
  }
  return true
}

const templateRecordSchema = z
  .object({
    name: z.string().trim().max(254).refine(noControl, 'No control characters.').default(''),
    type: z.enum(RECORD_TYPES),
    ttl: z.coerce.number().int().min(TTL_MIN, `At least ${TTL_MIN} seconds.`).max(TTL_MAX, `At most ${TTL_MAX} seconds.`),
    content: z.string().trim().min(1, 'A value is required.').max(4096).refine(noControl, 'No control characters.'),
    priority: z.preprocess((v) => (v === '' || v === null ? undefined : v), z.coerce.number().int().min(0).max(65535).optional()),
  })
  .superRefine((r, ctx) => {
    if (r.priority !== undefined && r.priority !== 0 && !hasPriority(r.type)) ctx.addIssue({ code: 'custom', path: ['priority'], message: 'Priority applies to MX and SRV records only.' })
  })

/** POST/PUT /templates (the server re-validates every record against a zone). */
export const templateSchema = z.object({
  name: z.string().trim().min(1, 'A name is required.').max(100).refine(noControl, 'No control characters.'),
  description: optionalString(1000),
  records: z.array(templateRecordSchema).max(MAX_TEMPLATE_RECORDS, `At most ${MAX_TEMPLATE_RECORDS} records.`),
})
export type TemplateFormInput = z.output<typeof templateSchema>

/** Shows a template record name as it will look in zone `zone`. */
export function expandName(name: string, zone = 'example.com'): string {
  const z = zone.replace(/\.$/, '')
  const n = name.trim().split(ZONE_PLACEHOLDER).join(z)
  if (!n || n === '@') return z + '.'
  return n.endsWith('.') ? n : `${n}.${z}.`
}

const IPV4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/
const IPV6 = /^[0-9a-fA-F:.]+$/

/** An IP literal (the server applies the unicast/SSRF guard). */
export function ipOk(raw: string): boolean {
  const s = raw.trim()
  if (IPV4.test(s)) return true
  return s.includes(':') && IPV6.test(s) && s.split('::').length <= 2
}

/** POST /supermasters. */
export const supermasterSchema = z.object({
  ip: z.string().trim().min(2).max(64).refine(ipOk, 'An IPv4 or IPv6 address.'),
  nameserver: z.string().trim().min(1).max(254).refine(zoneNameOk, 'A fully qualified host name (ns1.example.com).'),
})
export type SupermasterFormInput = z.output<typeof supermasterSchema>
