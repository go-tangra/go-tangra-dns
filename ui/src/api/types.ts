// Domain types mirror the DNS OpenAPI responses (api/openapi/dns.yaml).
// Response projections use optional (`?:`) fields; inputs use explicit
// `T | undefined` to satisfy exactOptionalPropertyTypes.

export type ZoneKind = 'native' | 'master' | 'slave' | 'producer' | 'consumer'
export type ZoneOrigin = 'manual' | 'ipam'

export interface Zone {
  id: string
  name: string
  kind: ZoneKind
  masters: string[]
  dnssec: boolean
  description?: string
  template_id?: string
  origin: ZoneOrigin
  nameservers?: string[]
  created_by?: string
  created_at: string
  updated_at: string
  /** Only on GET /zones/{id}, read from PowerDNS (absent when it is unreachable). */
  serial?: number
  notified_serial?: number
}

export interface ZoneCreate {
  name: string
  kind: ZoneKind
  masters?: string[] | undefined
  nameservers?: string[] | undefined
  dnssec?: boolean | undefined
  description?: string | undefined
  template_id?: string | undefined
}

export interface ZoneUpdate {
  kind?: ZoneKind | undefined
  masters?: string[] | undefined
  dnssec?: boolean | undefined
  description?: string | undefined
}

export interface Page<T> {
  items: T[]
  total: number
}

export type RecordValue = {
  content: string
  disabled: boolean
}

// Type aliases (not interfaces) so rows satisfy the table's Record<string, unknown> bound.
export type RecordSet = {
  /** Qualified owner name (trailing dot). */
  name: string
  type: string
  ttl: number
  values: RecordValue[]
  comment?: string
  /** SOA (and any type the module does not edit). */
  read_only: boolean
}

export interface RecordSetInput {
  name: string
  type: string
  ttl: number
  values: { content: string; disabled?: boolean | undefined }[]
  comment?: string | undefined
}

export interface RecordKey {
  name: string
  type: string
}

/** GET /zones/{id}/export. */
export interface ZoneExport {
  zone: string
  text: string
}

export type TemplateRecord = {
  /** "@", empty, relative or absolute; may contain [ZONE]. */
  name: string
  type: string
  ttl: number
  /** May contain [ZONE]; MX/SRV without their priority when priority is set. */
  content: string
  priority?: number
}

export type Template = {
  id: string
  name: string
  description?: string
  records: TemplateRecord[]
  created_at: string
  updated_at: string
}

export interface TemplateInput {
  name: string
  description?: string | undefined
  records: { name: string; type: string; ttl: number; content: string; priority?: number | undefined }[]
}

export type Supermaster = {
  id: string
  ip: string
  nameserver: string
  created_by?: string
  created_at: string
}

export interface SupermasterInput {
  ip: string
  nameserver: string
}

// --- Server configuration (US5; platform administrators only) ---

export type DnssecMode = 'off' | 'process' | 'validate'

export interface RecursorSettings {
  listen_addresses: string[]
  port: number
  allowed_networks: string[]
  upstream_resolvers: string[]
  dnssec_validation: DnssecMode
  allow_open_resolver?: boolean | undefined
}

export interface AuthoritativeSettings {
  listen_addresses: string[]
  port: number
  transfer_peers: string[]
}

export interface ServerConfigInput {
  recursor: RecursorSettings
  authoritative: AuthoritativeSettings
}

export interface ServerConfig extends ServerConfigInput {
  /** True while nothing was saved (the defaults are shown). */
  defaults: boolean
  restarter: { enabled: boolean; containers: { auth?: string; recursor?: string } }
}

export interface ConfigResult extends ServerConfigInput {
  changed: Array<'recursor' | 'authoritative'>
  restarted: string[]
  restart_required: string[]
  errors: Array<{ server?: 'recursor' | 'authoritative'; reason?: string }>
}

// --- Dashboard (US6; fixed panel catalogue) ---

export type DashboardWindow = '1h' | '6h' | '24h'

export interface DashboardSeries {
  labels: Record<string, string>
  points: Array<[number, number]>
}

export interface DashboardPanel {
  id: string
  kind: 'stat' | 'series'
  unit?: string
  value?: number
  unavailable?: boolean
  series?: DashboardSeries[]
}

export interface Dashboard {
  available: boolean
  window: DashboardWindow
  step_seconds?: number
  panels?: DashboardPanel[]
}
