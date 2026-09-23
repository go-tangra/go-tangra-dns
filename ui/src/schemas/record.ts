import { z } from 'zod'
import { optionalString } from '@freya/ui/forms'

export const RECORD_TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'PTR', 'SRV', 'TXT', 'CAA', 'DS', 'DNSKEY', 'TLSA', 'SSHFP', 'SPF', 'NAPTR'] as const
export type RecordType = (typeof RECORD_TYPES)[number]

export const TTL_MIN = 60
export const TTL_MAX = 604800

/** TTL presets offered by the inline editor (seconds). */
export const TTL_PRESETS: { title: string; value: string }[] = [
  { title: '1 minute', value: '60' },
  { title: '5 minutes', value: '300' },
  { title: '1 hour', value: '3600' },
  { title: '4 hours', value: '14400' },
  { title: '1 day', value: '86400' },
  { title: '1 week', value: '604800' },
]

/** Per-type placeholder and hint for a value (presentation format). */
export const RECORD_HINTS: Record<RecordType, { placeholder: string; hint: string }> = {
  A: { placeholder: '192.0.2.10', hint: 'IPv4 address' },
  AAAA: { placeholder: '2001:db8::10', hint: 'IPv6 address' },
  CNAME: { placeholder: 'target.example.com.', hint: 'Target host name; alone at its name, never at the apex' },
  MX: { placeholder: '10 mail.example.com.', hint: 'Priority and mail server' },
  NS: { placeholder: 'ns1.example.com.', hint: 'Name server host name' },
  PTR: { placeholder: 'host.example.com.', hint: 'Host name the address points to' },
  SRV: { placeholder: '10 60 5060 sip.example.com.', hint: 'Priority, weight, port and target' },
  TXT: { placeholder: 'v=spf1 -all', hint: 'Text; quoted and split at 255 characters automatically' },
  CAA: { placeholder: '0 issue "letsencrypt.org"', hint: 'Flags (0/128), tag (issue, issuewild, iodef) and value' },
  DS: { placeholder: '60485 13 2 <64 hex digits>', hint: 'Key tag, algorithm, digest type (1, 2, 4) and digest' },
  DNSKEY: { placeholder: '257 3 13 <base64 key>', hint: 'Flags (256/257), protocol 3, algorithm and public key' },
  TLSA: { placeholder: '3 1 1 <64 hex digits>', hint: 'Usage, selector, matching type and certificate data' },
  SSHFP: { placeholder: '4 2 <64 hex digits>', hint: 'Algorithm, fingerprint type (1/2) and fingerprint' },
  SPF: { placeholder: 'v=spf1 mx -all', hint: 'SPF text (prefer TXT)' },
  NAPTR: { placeholder: '100 10 "U" "E2U+sip" "!^.*$!sip:info@example.com!" .', hint: 'Order, preference, flags, service, regexp, replacement' },
}

/** Raw control characters (CR, LF, TAB, NUL, DEL …) can never be part of a value. */
function hasControl(s: string): boolean {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i)
    if (c < 0x20 || c === 0x7f) return true
  }
  return false
}

const IPV4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/
const HEX = /^[0-9a-fA-F]+$/

/**
 * Light per-type checks for instant feedback; the server's parser is the
 * authority (it canonicalises and refuses what these miss). Returns a message
 * or '' when the value looks acceptable.
 */
export function checkContent(type: string, raw: string): string {
  const v = raw.trim()
  if (!v) return 'A value is required.'
  if (hasControl(raw)) return 'Line breaks and control characters are not allowed.'
  if (/\$(include|origin|ttl|generate)/i.test(v)) return 'Zone-file directives are not allowed.'
  const f = v.split(/\s+/)
  switch (type) {
    case 'A':
      return IPV4.test(v) ? '' : 'Enter an IPv4 address.'
    case 'AAAA':
      return v.includes(':') && /^[0-9a-fA-F:.]+$/.test(v) && !/^::ffff:/i.test(v) ? '' : 'Enter an IPv6 address.'
    case 'CNAME':
    case 'NS':
    case 'PTR':
      return f.length === 1 && v !== '.' ? '' : 'Enter one host name.'
    case 'MX':
      return f.length === 2 && /^\d+$/.test(f[0]!) && Number(f[0]) <= 65535 ? '' : 'Enter a priority and a host name (10 mail.example.com.).'
    case 'SRV':
      return f.length === 4 && f.slice(0, 3).every((n) => /^\d+$/.test(n) && Number(n) <= 65535) ? '' : 'Enter priority, weight, port and target.'
    case 'CAA':
      return /^(0|128)\s+(issue|issuewild|iodef)\s+\S/i.test(v) ? '' : 'Enter flags (0 or 128), a tag (issue, issuewild, iodef) and a value.'
    case 'DS':
      return f.length === 4 && ['1', '2', '4'].includes(f[2]!) && HEX.test(f[3]!) ? '' : 'Enter key tag, algorithm, digest type and hex digest.'
    case 'TLSA':
      return f.length === 4 && /^[0-3]$/.test(f[0]!) && /^[01]$/.test(f[1]!) && /^[0-2]$/.test(f[2]!) && HEX.test(f[3]!) ? '' : 'Enter usage (0-3), selector (0-1), matching type (0-2) and hex data.'
    case 'SSHFP':
      return f.length === 3 && /^[1-46]$/.test(f[0]!) && /^[12]$/.test(f[1]!) && HEX.test(f[2]!) ? '' : 'Enter algorithm, fingerprint type (1 or 2) and hex fingerprint.'
    case 'DNSKEY':
      return f.length >= 4 && ['0', '256', '257'].includes(f[0]!) && f[1] === '3' ? '' : 'Enter flags (256/257), protocol 3, algorithm and key.'
  }
  return ''
}

const recordValueSchema = z.object({
  content: z.string().max(4096),
  disabled: z.boolean().default(false),
})

/** POST /zones/{id}/records (and the `record` of PUT): one record set. */
export const recordSetSchema = z
  .object({
    name: z.string().trim().max(254).transform((s) => s || '@'),
    type: z.enum(RECORD_TYPES),
    ttl: z.coerce.number().int().min(TTL_MIN, `At least ${TTL_MIN} seconds.`).max(TTL_MAX, `At most ${TTL_MAX} seconds.`),
    values: z.array(recordValueSchema).min(1, 'Add at least one value.').max(100, 'At most 100 values.'),
    comment: optionalString(512),
  })
  .superRefine((v, ctx) => {
    if (/\s/.test(v.name)) ctx.addIssue({ code: 'custom', path: ['name'], message: 'Names cannot contain spaces.' })
    if (v.type === 'CNAME' && v.name === '@') ctx.addIssue({ code: 'custom', path: ['name'], message: 'A CNAME is not allowed at the zone apex.' })
    if (v.type === 'CNAME' && v.values.length > 1) ctx.addIssue({ code: 'custom', path: ['values'], message: 'A CNAME holds exactly one value.' })
    const seen = new Set<string>()
    v.values.forEach((val, i) => {
      const msg = checkContent(v.type, val.content)
      if (msg) ctx.addIssue({ code: 'custom', path: ['values', i, 'content'], message: msg })
      const key = val.content.trim()
      if (seen.has(key)) ctx.addIssue({ code: 'custom', path: ['values', i, 'content'], message: 'Duplicate value.' })
      seen.add(key)
    })
  })
export type RecordSetFormInput = z.output<typeof recordSetSchema>

/** Relative form of a qualified owner name inside zone ("@" for the apex). */
export function relativeName(name: string, zone: string): string {
  if (name === zone) return '@'
  return name.endsWith('.' + zone) ? name.slice(0, -(zone.length + 1)) : name
}
