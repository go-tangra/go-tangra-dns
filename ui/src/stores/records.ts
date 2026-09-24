import { defineStore } from 'pinia'
import { ref } from 'vue'
import { api, describe } from '@/api/client'
import type { Page, RecordKey, RecordSet, RecordSetInput } from '@/api/types'

export interface RecordFilter {
  type?: string | undefined
  query?: string | undefined
}

/** Record sets of one zone (PowerDNS is the source of truth; paged server-side). */
export const useRecords = defineStore('dns-records', () => {
  const zoneId = ref('')
  const items = ref<RecordSet[]>([])
  const total = ref(0)
  const page = ref(1)
  const pageSize = ref(50)
  const filter = ref<RecordFilter>({})
  const loading = ref(false)
  const error = ref('')

  const base = () => 'zones/' + zoneId.value + '/records'

  /** Loads a page of zone `id` (switching zone or filter restarts at page 1). */
  async function list(id = zoneId.value, f?: RecordFilter, p?: number): Promise<void> {
    if (id !== zoneId.value) {
      zoneId.value = id
      filter.value = {}
      p = 1
    }
    if (f) filter.value = { ...f }
    const target = p ?? (f ? 1 : page.value)
    loading.value = true
    error.value = ''
    try {
      const res = await api<Page<RecordSet>>('GET', base(), undefined, {
        query: { type: filter.value.type, query: filter.value.query, page: target, page_size: pageSize.value },
      })
      items.value = res.items ?? []
      total.value = res.total ?? 0
      page.value = target
    } catch (e) {
      error.value = describe(e)
    } finally {
      loading.value = false
    }
  }

  const goTo = (p: number) => list(zoneId.value, undefined, p)

  /** Creates or replaces the (name, type) set. */
  const upsert = (body: RecordSetInput) => api<RecordSet>('POST', base(), body)

  /** Replaces the set identified by original (a rename moves it). */
  const update = (original: RecordKey, record: RecordSetInput) => api<RecordSet>('PUT', base(), { original, record })

  async function remove(key: RecordKey): Promise<void> {
    await api('DELETE', base(), undefined, { query: { name: key.name, type: key.type } })
    items.value = items.value.filter((x) => !(x.name === key.name && x.type === key.type))
    total.value = Math.max(0, total.value - 1)
  }

  return { zoneId, items, total, page, pageSize, filter, loading, error, list, goTo, upsert, update, remove }
})
