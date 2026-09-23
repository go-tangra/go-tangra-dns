import { defineStore } from 'pinia'
import { ref } from 'vue'
import { api, describe } from '@/api/client'
import type { Supermaster, SupermasterInput } from '@/api/types'

/** The tenant's supermasters (create/delete need platform administration). */
export const useSupermasters = defineStore('dns-supermasters', () => {
  const items = ref<Supermaster[]>([])
  const loading = ref(false)
  const error = ref('')

  async function list(): Promise<void> {
    loading.value = true
    error.value = ''
    try {
      items.value = (await api<{ items: Supermaster[] }>('GET', 'supermasters')).items ?? []
    } catch (e) {
      error.value = describe(e)
    } finally {
      loading.value = false
    }
  }

  async function create(body: SupermasterInput): Promise<Supermaster> {
    const s = await api<Supermaster>('POST', 'supermasters', body)
    items.value = [...items.value, s]
    return s
  }

  async function remove(id: string): Promise<void> {
    await api('DELETE', 'supermasters/' + id)
    items.value = items.value.filter((x) => x.id !== id)
  }

  return { items, loading, error, list, create, remove }
})
