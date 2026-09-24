import { z } from 'zod'
import { optionalString } from '@go-tangra/ui/forms'

export const ZONE_KINDS = ['native', 'master', 'slave', 'producer', 'consumer'] as const
export type ZoneKindValue = (typeof ZONE_KINDS)[number]

/** Secondary kinds take their data from primaries and need at least one. */
export const needsMasters = (kind: string | undefined): boolean => kind === 'slave' || kind === 'consumer'

const LABEL = /^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$/

/**
 * Light client-side zone-name rules (the server is authoritative: public
 * suffixes and other tenants' zones are refused there): lower-case LDH labels
 * of 1–63 octets, at most 253 octets, at least two labels, trailing dot optional.
 */
export function zoneNameOk(raw: string): boolean {
  const s = raw.trim().toLowerCase().replace(/\.$/, '')
  if (!s || s.length > 253) return false
  const labels = s.split('.')
  return labels.length >= 2 && labels.every((l) => LABEL.test(l))
}

/** Comma/space separated list ⇄ string[] (primaries, nameservers). */
export const listField = (max = 2000) =>
  z.preprocess((v) => (Array.isArray(v) ? v.join(', ') : (v ?? '')), z.string().max(max)).transform((s) =>
    s
      .split(/[\s,]+/)
      .map((x) => x.trim())
      .filter(Boolean),
  )

const MASTER = /^(\[[0-9a-fA-F:.]+\]|[0-9a-fA-F:.]+)(:\d{1,5})?$/

function checkMasters(v: { kind?: string | undefined; masters?: string[] | undefined }, ctx: z.RefinementCtx): void {
  const masters = v.masters ?? []
  if (needsMasters(v.kind) && masters.length === 0) ctx.addIssue({ code: 'custom', path: ['masters'], message: 'Secondary zones need at least one primary.' })
  if (!needsMasters(v.kind) && masters.length > 0) ctx.addIssue({ code: 'custom', path: ['masters'], message: 'Primaries apply to slave and consumer zones only.' })
  if (masters.length > 16) ctx.addIssue({ code: 'custom', path: ['masters'], message: 'At most 16 primaries.' })
  for (const m of masters) if (!MASTER.test(m)) ctx.addIssue({ code: 'custom', path: ['masters'], message: `${m} is not an IP address (optionally with :port).` })
}

/** POST /zones. */
export const zoneSchema = z
  .object({
    name: z.string().trim().min(1).max(254).refine(zoneNameOk, 'Not a valid zone name (e.g. example.com).'),
    kind: z.enum(ZONE_KINDS).default('native'),
    masters: listField(),
    nameservers: listField(),
    dnssec: z.boolean().optional(),
    description: optionalString(1000),
    template_id: optionalString(64),
  })
  .superRefine((v, ctx) => {
    checkMasters(v, ctx)
    if (v.template_id && needsMasters(v.kind)) ctx.addIssue({ code: 'custom', path: ['template_id'], message: 'Templates apply to native, master and producer zones.' })
    if (v.nameservers.length > 16) ctx.addIssue({ code: 'custom', path: ['nameservers'], message: 'At most 16 nameservers.' })
    for (const n of v.nameservers) if (!zoneNameOk(n)) ctx.addIssue({ code: 'custom', path: ['nameservers'], message: `${n} is not a host name.` })
  })
export type ZoneFormInput = z.output<typeof zoneSchema>

/** PUT /zones/{id}: the name is fixed after creation. */
export const zoneUpdateSchema = z
  .object({
    kind: z.enum(ZONE_KINDS),
    masters: listField(),
    dnssec: z.boolean().optional(),
    description: optionalString(1000),
  })
  .superRefine(checkMasters)
export type ZoneUpdateFormInput = z.output<typeof zoneUpdateSchema>

export const ZONE_ORIGINS = ['manual', 'ipam'] as const

export const zoneFilterSchema = z.object({
  q: z.string().trim().max(254).optional(),
  kind: z.enum(ZONE_KINDS).optional(),
  origin: z.enum(ZONE_ORIGINS).optional(),
})
