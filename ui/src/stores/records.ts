import { defineStore } from 'pinia'
import { ref } from 'vue'
import { api } from '@/api/client'
import type { RecordKey, RecordSet, RecordSetInput } from '@/api/types'
import { pagedList } from './paged'

export interface RecordFilter {
  type?: string | undefined
  query?: string | undefined
}

/** Sort fields the records list accepts (server Spec store.RecordList). */
export const RECORD_SORTABLE = ['name', 'type', 'ttl']

/** Record sets of one zone (PowerDNS is the source of truth; paged server-side). */
export const useRecords = defineStore('dns-records', () => {
  const zoneId = ref('')
  const base = () => 'zones/' + zoneId.value + '/records'
  const page = pagedList<RecordSet>(base)

  /** Loads a page of zone `id` with q (filters plus page/size/sort/order). */
  function load(id: string, q: Parameters<typeof page.list>[0]) {
    zoneId.value = id
    return page.list(q)
  }

  /** Creates or replaces the (name, type) set. */
  const upsert = (body: RecordSetInput) => api<RecordSet>('POST', base(), body)

  /** Replaces the set identified by original (a rename moves it). */
  const update = (original: RecordKey, record: RecordSetInput) => api<RecordSet>('PUT', base(), { original, record })

  /** Deletes the set, then reloads the current page so rows and total stay consistent. */
  async function remove(key: RecordKey): Promise<number | null> {
    await api('DELETE', base(), undefined, { query: { name: key.name, type: key.type } })
    return page.reload()
  }

  return { ...page, zoneId, load, upsert, update, remove }
})
