import { defineStore } from 'pinia'
import { ref } from 'vue'
import { api, describe } from '@/api/client'
import type { Page, Zone, ZoneCreate, ZoneExport, ZoneKind, ZoneOrigin, ZoneUpdate } from '@/api/types'

export interface ZoneFilter {
  query?: string | undefined
  kind?: ZoneKind | undefined
  origin?: ZoneOrigin | undefined
}

/** The tenant's zones: one server-side page at a time with the total count. */
export const useZones = defineStore('dns-zones', () => {
  const items = ref<Zone[]>([])
  const total = ref(0)
  const page = ref(1)
  const pageSize = ref(25)
  const filter = ref<ZoneFilter>({})
  const loading = ref(false)
  const error = ref('')

  /** Loads a page (a new filter restarts at page 1). */
  async function list(f?: ZoneFilter, p = f ? 1 : page.value): Promise<void> {
    if (f) filter.value = { ...f }
    loading.value = true
    error.value = ''
    try {
      const res = await api<Page<Zone>>('GET', 'zones', undefined, {
        query: { query: filter.value.query, kind: filter.value.kind, origin: filter.value.origin, page: p, page_size: pageSize.value },
      })
      items.value = res.items ?? []
      total.value = res.total ?? 0
      page.value = p
    } catch (e) {
      error.value = describe(e)
    } finally {
      loading.value = false
    }
  }

  const goTo = (p: number) => list(undefined, p)

  /** One zone with its PowerDNS serials. */
  const get = (id: string) => api<Zone>('GET', 'zones/' + id)

  async function create(body: ZoneCreate): Promise<Zone> {
    return api<Zone>('POST', 'zones', body)
  }

  async function update(id: string, body: ZoneUpdate): Promise<Zone> {
    const z = await api<Zone>('PUT', 'zones/' + id, body)
    items.value = items.value.map((x) => (x.id === id ? z : x))
    return z
  }

  /** Deletes the zone from PowerDNS, the resolver and the list. */
  async function remove(id: string): Promise<void> {
    await api('DELETE', 'zones/' + id)
    items.value = items.value.filter((x) => x.id !== id)
    total.value = Math.max(0, total.value - 1)
  }

  /** BIND text of the zone (for display and copying). */
  const exportText = (id: string) => api<ZoneExport>('GET', 'zones/' + id + '/export')

  /** Asks the DNS server to NOTIFY the secondaries (master/producer zones). */
  const notify = (id: string) => api('POST', 'zones/' + id + '/notify')

  return { items, total, page, pageSize, filter, loading, error, list, goTo, get, create, update, remove, exportText, notify }
})
