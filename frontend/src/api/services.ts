/**
 * DNS Module Service Functions
 *
 * Typed service methods for the DNS API using dynamic module routing.
 * Base URL: /admin/v1/modules/dns/v1
 */

import { dnsApi, type RequestOptions } from './client';
import type {
  ListZonesParams,
  ListZonesResponse,
  GetZoneResponse,
  CreateZoneRequest,
  CreateZoneResponse,
  UpdateZoneRequest,
  UpdateZoneResponse,
  ExportZoneResponse,
  ListRecordsParams,
  ListRecordsResponse,
  CreateRecordRequest,
  CreateRecordResponse,
  UpdateRecordRequest,
  UpdateRecordResponse,
  ListZoneTemplatesParams,
  ListZoneTemplatesResponse,
  GetZoneTemplateResponse,
  CreateZoneTemplateRequest,
  CreateZoneTemplateResponse,
  UpdateZoneTemplateRequest,
  UpdateZoneTemplateResponse,
  ListSupermastersParams,
  ListSupermastersResponse,
  GetSupermasterResponse,
  CreateSupermasterRequest,
  CreateSupermasterResponse,
  GetDnsConfigResponse,
  UpdateDnsConfigRequest,
  UpdateDnsConfigResponse,
  InstantQueryRequest,
  InstantQueryResponse,
  RangeQueryRequest,
  RangeQueryResponse,
} from './types';

// Re-export entity & request/response types for convenience.
export * from './types';

// Helper to build query string
export function buildQuery(params: Record<string, unknown>): string {
  const searchParams = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && value !== '') {
      if (Array.isArray(value)) {
        value.forEach((v) => searchParams.append(key, String(v)));
      } else {
        searchParams.append(key, String(value));
      }
    }
  }
  const query = searchParams.toString();
  return query ? `?${query}` : '';
}

// Encode a path segment (record names may contain dots / wildcards).
function seg(value: string): string {
  return encodeURIComponent(value);
}

// ==================== Zone Service ====================

export const ZoneService = {
  list: async (
    params?: ListZonesParams,
    options?: RequestOptions
  ): Promise<ListZonesResponse> => {
    return dnsApi.get<ListZonesResponse>(`/zones${buildQuery(params || {})}`, options);
  },

  get: async (id: string, options?: RequestOptions): Promise<GetZoneResponse> => {
    return dnsApi.get<GetZoneResponse>(`/zones/${seg(id)}`, options);
  },

  create: async (
    data: CreateZoneRequest,
    options?: RequestOptions
  ): Promise<CreateZoneResponse> => {
    return dnsApi.post<CreateZoneResponse>('/zones', data, options);
  },

  update: async (
    id: string,
    data: UpdateZoneRequest,
    options?: RequestOptions
  ): Promise<UpdateZoneResponse> => {
    return dnsApi.put<UpdateZoneResponse>(`/zones/${seg(id)}`, data, options);
  },

  delete: async (id: string, options?: RequestOptions): Promise<void> => {
    await dnsApi.delete(`/zones/${seg(id)}`, options);
  },

  export: async (id: string, options?: RequestOptions): Promise<ExportZoneResponse> => {
    return dnsApi.get<ExportZoneResponse>(`/zones/${seg(id)}/export`, options);
  },

  notify: async (id: string, options?: RequestOptions): Promise<void> => {
    await dnsApi.post(`/zones/${seg(id)}/notify`, {}, options);
  },
};

// ==================== Record Service (zone-scoped) ====================

export const RecordService = {
  list: async (
    zoneId: string,
    params?: ListRecordsParams,
    options?: RequestOptions
  ): Promise<ListRecordsResponse> => {
    return dnsApi.get<ListRecordsResponse>(
      `/zones/${seg(zoneId)}/records${buildQuery(params || {})}`,
      options
    );
  },

  create: async (
    zoneId: string,
    data: Omit<CreateRecordRequest, 'zoneId'>,
    options?: RequestOptions
  ): Promise<CreateRecordResponse> => {
    return dnsApi.post<CreateRecordResponse>(
      `/zones/${seg(zoneId)}/records`,
      { ...data, zoneId },
      options
    );
  },

  update: async (
    zoneId: string,
    name: string,
    type: string,
    data: Omit<UpdateRecordRequest, 'zoneId' | 'name' | 'type'>,
    options?: RequestOptions
  ): Promise<UpdateRecordResponse> => {
    return dnsApi.put<UpdateRecordResponse>(
      `/zones/${seg(zoneId)}/records/${seg(name)}/${seg(type)}`,
      { ...data, zoneId, name, type },
      options
    );
  },

  delete: async (
    zoneId: string,
    name: string,
    type: string,
    options?: RequestOptions
  ): Promise<void> => {
    await dnsApi.delete(`/zones/${seg(zoneId)}/records/${seg(name)}/${seg(type)}`, options);
  },
};

// ==================== Zone Template Service ====================

export const ZoneTemplateService = {
  list: async (
    params?: ListZoneTemplatesParams,
    options?: RequestOptions
  ): Promise<ListZoneTemplatesResponse> => {
    return dnsApi.get<ListZoneTemplatesResponse>(
      `/zone-templates${buildQuery(params || {})}`,
      options
    );
  },

  get: async (id: string, options?: RequestOptions): Promise<GetZoneTemplateResponse> => {
    return dnsApi.get<GetZoneTemplateResponse>(`/zone-templates/${seg(id)}`, options);
  },

  create: async (
    data: CreateZoneTemplateRequest,
    options?: RequestOptions
  ): Promise<CreateZoneTemplateResponse> => {
    return dnsApi.post<CreateZoneTemplateResponse>('/zone-templates', data, options);
  },

  update: async (
    id: string,
    data: UpdateZoneTemplateRequest,
    options?: RequestOptions
  ): Promise<UpdateZoneTemplateResponse> => {
    return dnsApi.put<UpdateZoneTemplateResponse>(`/zone-templates/${seg(id)}`, data, options);
  },

  delete: async (id: string, options?: RequestOptions): Promise<void> => {
    await dnsApi.delete(`/zone-templates/${seg(id)}`, options);
  },
};

// ==================== Supermaster Service ====================

export const SupermasterService = {
  list: async (
    params?: ListSupermastersParams,
    options?: RequestOptions
  ): Promise<ListSupermastersResponse> => {
    return dnsApi.get<ListSupermastersResponse>(
      `/supermasters${buildQuery(params || {})}`,
      options
    );
  },

  get: async (id: string, options?: RequestOptions): Promise<GetSupermasterResponse> => {
    return dnsApi.get<GetSupermasterResponse>(`/supermasters/${seg(id)}`, options);
  },

  create: async (
    data: CreateSupermasterRequest,
    options?: RequestOptions
  ): Promise<CreateSupermasterResponse> => {
    return dnsApi.post<CreateSupermasterResponse>('/supermasters', data, options);
  },

  delete: async (id: string, options?: RequestOptions): Promise<void> => {
    await dnsApi.delete(`/supermasters/${seg(id)}`, options);
  },
};

// ==================== Config Service ====================

export const ConfigService = {
  get: async (options?: RequestOptions): Promise<GetDnsConfigResponse> => {
    return dnsApi.get<GetDnsConfigResponse>('/config', options);
  },

  update: async (
    data: UpdateDnsConfigRequest,
    options?: RequestOptions
  ): Promise<UpdateDnsConfigResponse> => {
    return dnsApi.put<UpdateDnsConfigResponse>('/config', data, options);
  },
};

// ==================== Dashboard Service (Prometheus pass-through) ====================

export const DashboardService = {
  // instantQuery — single point-in-time PromQL evaluation.
  instantQuery: async (
    params: InstantQueryRequest,
    options?: RequestOptions
  ): Promise<InstantQueryResponse> => {
    return dnsApi.get<InstantQueryResponse>(
      `/dashboard/query${buildQuery(params as Record<string, unknown>)}`,
      options
    );
  },

  // rangeQuery — windowed PromQL evaluation. start/end are RFC3339
  // strings (the proto field is google.protobuf.Timestamp, which
  // gRPC-Gateway serializes as RFC3339).
  rangeQuery: async (
    params: RangeQueryRequest,
    options?: RequestOptions
  ): Promise<RangeQueryResponse> => {
    return dnsApi.get<RangeQueryResponse>(
      `/dashboard/query_range${buildQuery(params as Record<string, unknown>)}`,
      options
    );
  },
};
