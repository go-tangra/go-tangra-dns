import { defineStore } from 'pinia'
import { ref } from 'vue'
import { api, describe } from '@/api/client'
import type { Dashboard, DashboardWindow } from '@/api/types'

/** The curated DNS dashboard (fixed panels; only the window is chosen). */
export const useDashboard = defineStore('dns-dashboard', () => {
  const data = ref<Dashboard | null>(null)
  const window = ref<DashboardWindow>('1h')
  const loading = ref(false)
  const error = ref('')

  async function load(): Promise<void> {
    loading.value = true
    error.value = ''
    try {
      data.value = await api<Dashboard>('GET', 'dashboard', undefined, { query: { window: window.value } })
    } catch (e) {
      error.value = describe(e)
    } finally {
      loading.value = false
    }
  }

  return { data, window, loading, error, load }
})
