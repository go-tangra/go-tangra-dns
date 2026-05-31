/**
 * Hand-written TypeScript types for the DNS module API.
 *
 * Field names follow the proto JSON names (camelCase) exposed by the
 * admin gateway under /admin/v1/modules/dns/v1.
 */

// ==================== Enums ====================

export type ZoneKind =
  | 'ZONE_KIND_UNSPECIFIED'
  | 'ZONE_KIND_NATIVE'
  | 'ZONE_KIND_MASTER'
  | 'ZONE_KIND_SLAVE'
  | 'ZONE_KIND_PRODUCER'
  | 'ZONE_KIND_CONSUMER';

export type RecordType =
  | 'RECORD_TYPE_UNSPECIFIED'
  | 'RECORD_TYPE_A'
  | 'RECORD_TYPE_AAAA'
  | 'RECORD_TYPE_CNAME'
  | 'RECORD_TYPE_MX'
  | 'RECORD_TYPE_NS'
  | 'RECORD_TYPE_PTR'
  | 'RECORD_TYPE_SRV'
  | 'RECORD_TYPE_TXT'
  | 'RECORD_TYPE_SOA'
  | 'RECORD_TYPE_CAA'
  | 'RECORD_TYPE_DS'
  | 'RECORD_TYPE_DNSKEY'
  | 'RECORD_TYPE_TLSA'
  | 'RECORD_TYPE_SSHFP'
  | 'RECORD_TYPE_SPF'
  | 'RECORD_TYPE_NAPTR';

// ==================== Entities ====================

export interface Zone {
  id?: string;
  tenantId?: number;
  pdnsId?: string;
  name?: string;
  kind?: ZoneKind;
  masters?: string;
  serial?: number;
  dnssecEnabled?: boolean;
  description?: string;
  templateId?: string;
  createTime?: string;
  updateTime?: string;
}

export interface RecordContent {
  content?: string;
  disabled?: boolean;
}

export interface Record {
  name?: string;
  type?: RecordType | string;
  ttl?: number;
  contents?: RecordContent[];
  comment?: string;
}

export interface TemplateRecord {
  name?: string;
  type?: string;
  ttl?: number;
  content?: string;
  priority?: number;
}

export interface ZoneTemplate {
  id?: string;
  tenantId?: number;
  name?: string;
  description?: string;
  records?: TemplateRecord[];
  createTime?: string;
  updateTime?: string;
}

export interface Supermaster {
  id?: string;
  tenantId?: number;
  ip?: string;
  nameserver?: string;
  account?: string;
  createTime?: string;
}

// ==================== Zone requests / responses ====================

export interface ListZonesParams {
  page?: number;
  pageSize?: number;
  search?: string;
  kind?: ZoneKind;
}

export interface ListZonesResponse {
  zones?: Zone[];
  total?: number;
}

export interface GetZoneResponse {
  zone?: Zone;
}

export interface CreateZoneRequest {
  name: string;
  kind: ZoneKind;
  nameservers?: string[];
  masters?: string;
  description?: string;
  templateId?: string;
  dnssecEnabled?: boolean;
}

export interface CreateZoneResponse {
  zone?: Zone;
}

export interface UpdateZoneRequest {
  id: string;
  kind?: ZoneKind;
  masters?: string;
  description?: string;
  dnssecEnabled?: boolean;
}

export interface UpdateZoneResponse {
  zone?: Zone;
}

export interface ExportZoneResponse {
  bindZone?: string;
}

// ==================== Record requests / responses ====================

export interface ListRecordsParams {
  type?: RecordType;
  search?: string;
}

export interface ListRecordsResponse {
  records?: Record[];
  total?: number;
}

export interface CreateRecordRequest {
  zoneId: string;
  name: string;
  type: RecordType;
  ttl?: number;
  contents?: RecordContent[];
  comment?: string;
}

export interface CreateRecordResponse {
  record?: Record;
}

export interface UpdateRecordRequest {
  zoneId: string;
  name: string;
  type: string;
  ttl?: number;
  contents?: RecordContent[];
  comment?: string;
}

export interface UpdateRecordResponse {
  record?: Record;
}

// ==================== ZoneTemplate requests / responses ====================

export interface ListZoneTemplatesParams {
  page?: number;
  pageSize?: number;
}

export interface ListZoneTemplatesResponse {
  templates?: ZoneTemplate[];
  total?: number;
}

export interface GetZoneTemplateResponse {
  template?: ZoneTemplate;
}

export interface CreateZoneTemplateRequest {
  name: string;
  description?: string;
  records?: TemplateRecord[];
}

export interface CreateZoneTemplateResponse {
  template?: ZoneTemplate;
}

export interface UpdateZoneTemplateRequest {
  id: string;
  name?: string;
  description?: string;
  records?: TemplateRecord[];
}

export interface UpdateZoneTemplateResponse {
  template?: ZoneTemplate;
}

// ==================== Supermaster requests / responses ====================

export interface ListSupermastersParams {
  page?: number;
  pageSize?: number;
}

export interface ListSupermastersResponse {
  supermasters?: Supermaster[];
  total?: number;
}

export interface GetSupermasterResponse {
  supermaster?: Supermaster;
}

export interface CreateSupermasterRequest {
  ip: string;
  nameserver: string;
  account?: string;
}

export interface CreateSupermasterResponse {
  supermaster?: Supermaster;
}

// ==================== Config (recursor / authoritative) ====================

export interface RecursorConfig {
  localAddress?: string[];
  localPort?: number;
  allowFrom?: string[];
  upstreamResolvers?: string[];
  dnssecDisabled?: boolean;
}

export interface AuthConfig {
  localAddress?: string[];
  localPort?: number;
  allowAxfr?: string[];
}

export interface GetDnsConfigResponse {
  recursor?: RecursorConfig;
  authoritative?: AuthConfig;
}

export interface UpdateDnsConfigRequest {
  recursor?: RecursorConfig;
  authoritative?: AuthConfig;
}

export interface UpdateDnsConfigResponse {
  recursor?: RecursorConfig;
  authoritative?: AuthConfig;
  restarted?: string[];
}

// ==================== Dashboard (Prometheus pass-through) ====================

// InstantSample is a single point-in-time PromQL evaluation result.
// protojson omits zero-valued scalars from the wire form, so a real 0
// arrives as undefined `value` while `hasValue` stays true.
export interface InstantSample {
  labels: Record<string, string>;
  timestamp?: string;
  value: number;
  hasValue: boolean;
}

// RangeSeries is a windowed PromQL evaluation: parallel timestamp/value
// arrays for one label set.
export interface RangeSeries {
  labels: Record<string, string>;
  timestamps: string[];
  values: number[];
}

export interface InstantQueryRequest {
  query: string;
  time?: string;
}

export interface InstantQueryResponse {
  series: InstantSample[];
}

export interface RangeQueryRequest {
  query: string;
  start: string;
  end: string;
  stepSeconds: number;
}

export interface RangeQueryResponse {
  series: RangeSeries[];
}
