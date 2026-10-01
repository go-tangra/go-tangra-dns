import { ref, type Ref } from 'vue'
import { api, describe } from '@/api/client'
import type { Page } from '@/api/types'

/** Query values sent to a list endpoint (filters plus page/page_size/sort/order). */
export type ListQuery = Record<string, string | number | undefined>

/**
 * One server-paged list: the current page of rows and the total. `list(q)`
 * loads a page (and remembers q), `reload()` refetches the current page.
 * A response overtaken by a newer request is dropped. Both resolve with the
 * page the server returned (it clamps a page beyond the last) or null.
 */
export function pagedList<T>(path: () => string) {
  const items = ref([]) as Ref<T[]>
  const total = ref(0)
  const loading = ref(false)
  const error = ref('')
  const query = ref<ListQuery>({})
  let seq = 0

  async function list(q?: ListQuery): Promise<number | null> {
    if (q) query.value = { ...q }
    const mine = ++seq
    loading.value = true
    error.value = ''
    try {
      const res = await api<Page<T>>('GET', path(), undefined, { query: query.value })
      if (mine !== seq) return null
      items.value = res.items ?? []
      total.value = res.total ?? 0
      return res.page ?? null
    } catch (e) {
      if (mine === seq) error.value = describe(e)
      return null
    } finally {
      if (mine === seq) loading.value = false
    }
  }

  return { items, total, loading, error, query, list, reload: () => list() }
}
