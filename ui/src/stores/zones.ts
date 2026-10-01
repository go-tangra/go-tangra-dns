import { defineStore } from 'pinia'
import { api } from '@/api/client'
import type { Zone, ZoneCreate, ZoneExport, ZoneKind, ZoneOrigin, ZoneUpdate } from '@/api/types'
import { pagedList } from './paged'

export interface ZoneFilter {
  query?: string | undefined
  kind?: ZoneKind | undefined
  origin?: ZoneOrigin | undefined
}

/** Sort fields the zones list accepts (server Spec store.ZoneList). */
export const ZONE_SORTABLE = ['name', 'kind', 'updated_at']

/** The tenant's zones: one server-side page at a time with the total count. */
export const useZones = defineStore('dns-zones', () => {
  const page = pagedList<Zone>(() => 'zones')

  /** One zone with its PowerDNS serials. */
  const get = (id: string) => api<Zone>('GET', 'zones/' + id)

  const create = (body: ZoneCreate) => api<Zone>('POST', 'zones', body)

  async function update(id: string, body: ZoneUpdate): Promise<Zone> {
    const z = await api<Zone>('PUT', 'zones/' + id, body)
    page.items.value = page.items.value.map((x) => (x.id === id ? z : x))
    return z
  }

  /** Deletes the zone from PowerDNS and the resolver; the view reloads its page. */
  const remove = (id: string) => api('DELETE', 'zones/' + id)

  /** BIND text of the zone (for display and copying). */
  const exportText = (id: string) => api<ZoneExport>('GET', 'zones/' + id + '/export')

  /** Asks the DNS server to NOTIFY the secondaries (master/producer zones). */
  const notify = (id: string) => api('POST', 'zones/' + id + '/notify')

  return { ...page, get, create, update, remove, exportText, notify }
})
