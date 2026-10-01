import { defineStore } from 'pinia'
import { api } from '@/api/client'
import type { Supermaster, SupermasterInput } from '@/api/types'
import { pagedList } from './paged'

/** The tenant's supermasters, paged server-side (create/delete need platform administration). */
export const useSupermasters = defineStore('dns-supermasters', () => {
  const page = pagedList<Supermaster>(() => 'supermasters')
  const create = (body: SupermasterInput) => api<Supermaster>('POST', 'supermasters', body)
  const remove = (id: string) => api('DELETE', 'supermasters/' + id)
  return { ...page, create, remove }
})
