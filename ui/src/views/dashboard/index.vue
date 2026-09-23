<script setup lang="ts">
// DNS health dashboard: a fixed set of resolver and authoritative panels over
// 1 h / 6 h / 24 h, refreshed every 30 seconds. Only the window is chosen
// here — the queries are a server-side catalogue. Without a metrics endpoint
// a notice replaces the panels.
import { computed, onMounted, onUnmounted, watch } from 'vue'
import { UiPage, UiAlert, UiCard, UiButton, UiTabs, UiStatGrid, UiStatTile, UiSkeleton, UiEmptyState, type TabItem } from '@freya/ui'
import { useDashboard } from '@/stores/dashboard'
import type { DashboardPanel, DashboardWindow } from '@/api/types'
import SeriesChart from '@/components/SeriesChart.vue'
import { formatValue } from '@/components/format'

/** Auto-refresh period (US6-1). */
const REFRESH_MS = 30_000

const store = useDashboard()
const windows: TabItem[] = [
  { key: '1h', label: '1 hour' },
  { key: '6h', label: '6 hours' },
  { key: '24h', label: '24 hours' },
]
const TITLES: Record<string, { title: string; icon: string }> = {
  recursor_qps: { title: 'Resolver queries', icon: 'mdi-pulse' },
  recursor_cache_hit: { title: 'Resolver cache hits', icon: 'mdi-check-circle-outline' },
  recursor_concurrent: { title: 'Concurrent queries', icon: 'mdi-progress-clock' },
  recursor_uptime: { title: 'Resolver uptime', icon: 'mdi-clock-outline' },
  recursor_latency: { title: 'Resolver answer latency', icon: 'mdi-chart-line' },
  recursor_answers: { title: 'Resolver answer codes', icon: 'mdi-chart-line' },
  recursor_questions_outqueries: { title: 'Questions vs outgoing queries', icon: 'mdi-chart-line' },
  auth_qps: { title: 'Authoritative queries', icon: 'mdi-server' },
  auth_packetcache_hit: { title: 'Packet cache hits', icon: 'mdi-check-circle-outline' },
  auth_querycache_hit: { title: 'Query cache hits', icon: 'mdi-check-circle-outline' },
  auth_queries: { title: 'Authoritative query rate', icon: 'mdi-chart-line' },
  auth_errors: { title: 'Authoritative SERVFAIL / NXDOMAIN', icon: 'mdi-chart-line' },
}
const titleOf = (p: DashboardPanel) => TITLES[p.id]?.title ?? p.id
const iconOf = (p: DashboardPanel) => TITLES[p.id]?.icon ?? 'mdi-chart-line'

const panels = computed(() => store.data?.panels ?? [])
const stats = computed(() => panels.value.filter((p) => p.kind === 'stat'))
const series = computed(() => panels.value.filter((p) => p.kind === 'series'))
const windowKey = computed({
  get: () => store.window as string,
  set: (v: string) => {
    store.window = v as DashboardWindow
  },
})

let timer: ReturnType<typeof setInterval> | undefined
onMounted(() => {
  void store.load()
  timer = setInterval(() => void store.load(), REFRESH_MS)
})
onUnmounted(() => {
  if (timer) clearInterval(timer)
})
watch(() => store.window, () => void store.load())
</script>

<template>
  <UiPage title="Dashboard" subtitle="Resolver and authoritative server health">
    <template #actions>
      <UiButton variant="text" icon="mdi-refresh" icon-only label="Refresh" data-test="dashboard-refresh" @click="store.load()" />
    </template>
    <UiTabs v-model="windowKey" :tabs="windows" data-test="dashboard-window" />
    <UiAlert v-if="store.error" kind="error" data-test="dashboard-error">{{ store.error }}</UiAlert>
    <UiSkeleton v-if="store.loading && !store.data" />
    <UiCard v-else-if="store.data && !store.data.available" data-test="dashboard-unavailable">
      <UiEmptyState title="Metrics unavailable" text="DNS metrics collection is not configured on this deployment, so there is nothing to chart yet." icon="mdi-chart-line" />
    </UiCard>
    <template v-else-if="store.data">
      <UiStatGrid :cols="4" data-test="dashboard-stats">
        <UiStatTile v-for="p in stats" :key="p.id" :title="titleOf(p)" :value="p.unavailable ? 'unavailable' : formatValue(p.value, p.unit)" :icon="iconOf(p)" :color="p.unavailable ? 'warning' : 'primary'" :data-test="'stat-' + p.id" />
      </UiStatGrid>
      <div class="grid grid-cols-1 gap-3 lg:grid-cols-2">
        <UiCard v-for="p in series" :key="p.id" :title="titleOf(p)" :data-test="'panel-' + p.id">
          <UiAlert v-if="p.unavailable" kind="warning">This panel could not be loaded.</UiAlert>
          <SeriesChart v-else :series="p.series ?? []" :label="titleOf(p)" :unit="p.unit" />
        </UiCard>
      </div>
    </template>
  </UiPage>
</template>
