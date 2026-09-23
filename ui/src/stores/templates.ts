import { defineStore } from 'pinia'
import { ref } from 'vue'
import { api, describe } from '@/api/client'
import type { Template, TemplateInput } from '@/api/types'

/** The tenant's zone templates (name order, not paged: at most a few dozen). */
export const useTemplates = defineStore('dns-templates', () => {
  const items = ref<Template[]>([])
  const loading = ref(false)
  const error = ref('')

  async function list(): Promise<void> {
    loading.value = true
    error.value = ''
    try {
      items.value = (await api<{ items: Template[] }>('GET', 'templates')).items ?? []
    } catch (e) {
      error.value = describe(e)
    } finally {
      loading.value = false
    }
  }

  const get = (id: string) => api<Template>('GET', 'templates/' + id)

  async function create(body: TemplateInput): Promise<Template> {
    const t = await api<Template>('POST', 'templates', body)
    items.value = [...items.value, t].sort((a, b) => a.name.localeCompare(b.name))
    return t
  }

  async function update(id: string, body: TemplateInput): Promise<Template> {
    const t = await api<Template>('PUT', 'templates/' + id, body)
    items.value = items.value.map((x) => (x.id === id ? t : x))
    return t
  }

  async function remove(id: string): Promise<void> {
    await api('DELETE', 'templates/' + id)
    items.value = items.value.filter((x) => x.id !== id)
  }

  return { items, loading, error, list, get, create, update, remove }
})
