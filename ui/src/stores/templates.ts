import { defineStore } from 'pinia'
import { ref } from 'vue'
import { api } from '@/api/client'
import type { Page, Template, TemplateInput } from '@/api/types'
import { pagedList } from './paged'

/** The tenant's zone templates, paged server-side (name order by default). */
export const useTemplates = defineStore('dns-templates', () => {
  const page = pagedList<Template>(() => 'templates')
  /** Choices for the new-zone form: the first 200 templates by name. */
  const options = ref<Template[]>([])

  async function loadOptions(): Promise<void> {
    try {
      options.value = (await api<Page<Template>>('GET', 'templates', undefined, { query: { page_size: 200, sort: 'name', order: 'asc' } })).items ?? []
    } catch {
      options.value = []
    }
  }

  const get = (id: string) => api<Template>('GET', 'templates/' + id)
  const create = (body: TemplateInput) => api<Template>('POST', 'templates', body)
  const update = (id: string, body: TemplateInput) => api<Template>('PUT', 'templates/' + id, body)
  const remove = (id: string) => api('DELETE', 'templates/' + id)

  return { ...page, options, loadOptions, get, create, update, remove }
})
