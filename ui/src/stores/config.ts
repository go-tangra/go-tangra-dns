import { defineStore } from 'pinia'
import { ref } from 'vue'
import { api, describe } from '@/api/client'
import type { ConfigResult, ServerConfig, ServerConfigInput } from '@/api/types'

/** The DNS server configuration (platform administrators only). */
export const useServerConfig = defineStore('dns-config', () => {
  const config = ref<ServerConfig | null>(null)
  const last = ref<ConfigResult | null>(null)
  const loading = ref(false)
  const error = ref('')

  async function load(): Promise<void> {
    loading.value = true
    error.value = ''
    try {
      config.value = await api<ServerConfig>('GET', 'config')
    } catch (e) {
      config.value = null
      error.value = describe(e)
    } finally {
      loading.value = false
    }
  }

  async function save(body: ServerConfigInput): Promise<ConfigResult> {
    const res = await api<ConfigResult>('PUT', 'config', body)
    last.value = res
    if (config.value) config.value = { ...config.value, recursor: res.recursor, authoritative: res.authoritative, defaults: false }
    return res
  }

  return { config, last, loading, error, load, save }
})
