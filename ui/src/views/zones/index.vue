<script setup lang="ts">
// Zones: name search + kind and origin filters, a paged table and a
// right-hand drawer that shows a zone and carries every action on it (records,
// edit, NOTIFY, export, delete). "New zone" opens a record drawer (optionally
// from a template) that closes on save. Zones the IPAM sync created carry an
// "IPAM" badge.
import { computed, onMounted, ref, watch } from 'vue'
import { UiPage, UiAlert, UiCard, UiInput, UiSelect, UiButton, UiBadge, UiDataTable, UiPagination, UiStatusChip, UiRecordDrawer, type Column, type SelectOption } from '@freya/ui'
import { zodToFields } from '@freya/ui/forms'
import { useZones } from '@/stores/zones'
import { useTemplates } from '@/stores/templates'
import { zoneSchema, ZONE_KINDS, type ZoneFormInput } from '@/schemas'
import type { Zone, ZoneKind, ZoneOrigin } from '@/api/types'
import ZoneDrawer, { type ZoneDrawerMode } from './drawer.vue'

const store = useZones()
const templates = useTemplates()
const query = ref('')
const kind = ref<ZoneKind | ''>('')
const origin = ref<ZoneOrigin | ''>('')
const kindOptions: SelectOption[] = ZONE_KINDS.map((k) => ({ title: k, value: k }))
const originOptions: SelectOption[] = [
  { title: 'Manual', value: 'manual' },
  { title: 'IPAM', value: 'ipam' },
]

const reload = () => store.list({ query: query.value.trim() || undefined, kind: kind.value || undefined, origin: origin.value || undefined })
onMounted(() => void reload())

const pages = computed(() => Math.max(1, Math.ceil(store.total / store.pageSize)))
const pageLabel = computed(() => `Page ${store.page} of ${pages.value} · ${store.total} zone${store.total === 1 ? '' : 's'}`)

const columns: Column<Zone>[] = [
  { key: 'name', label: 'Zone', sortable: true },
  { key: 'kind', label: 'Kind', width: 'sm' },
  { key: 'origin', label: 'Origin', width: 'sm', hideOnStack: true },
  { key: 'dnssec', label: 'DNSSEC', width: 'sm', hideOnStack: true, format: (z) => (z.dnssec ? 'on' : 'off') },
  { key: 'description', label: 'Description', hideOnStack: true },
]
const kindColors = { native: 'neutral', master: 'primary', slave: 'info', producer: 'accent', consumer: 'secondary' } as const

// --- drawer (view / edit an existing zone) ---
const drawer = ref<{ id: string | null; mode: ZoneDrawerMode }>({ id: null, mode: 'view' })
const openZone = (id: string) => (drawer.value = { id, mode: 'view' })
const navigate = (id: string, mode: ZoneDrawerMode) => (drawer.value = { id, mode })
const closeDrawer = () => (drawer.value = { id: null, mode: 'view' })

// --- new zone ---
const creating = ref(false)
watch(creating, (open) => open && void templates.list())
const templateOptions = computed<SelectOption[]>(() => templates.items.map((t) => ({ title: t.name, value: t.id })))
const fields = computed(() => zodToFields(zoneSchema, {
  name: { label: 'Zone name', required: true, placeholder: 'example.com', cols: 8 },
  kind: { type: 'select', cols: 4, options: kindOptions },
  nameservers: { label: 'Nameservers', placeholder: 'ns1.example.com., ns2.example.com.', hint: 'Comma-separated; used for the initial NS set (native/master zones).' },
  masters: { label: 'Primaries', placeholder: '192.0.2.53, 192.0.2.54:5300', hint: 'Slave and consumer zones only: IP[:port], comma-separated.' },
  dnssec: { label: 'DNSSEC' },
  template_id: { type: 'select', label: 'Template', options: templateOptions.value, placeholder: 'No template', hint: 'Adds the template\'s records; [ZONE] becomes the zone name.' },
}))
async function create(v: Record<string, unknown>): Promise<Zone> {
  const f = v as unknown as ZoneFormInput
  return store.create({ name: f.name, kind: f.kind, masters: f.masters, nameservers: f.nameservers, dnssec: f.dnssec, description: f.description, template_id: f.template_id })
}
function onCreated(z: unknown): void {
  void reload()
  openZone((z as Zone).id)
}
</script>

<template>
  <UiPage title="Zones">
    <template #actions>
      <UiButton icon="mdi-plus" data-test="zone-new" @click="creating = true">New zone</UiButton>
      <UiButton variant="text" icon="mdi-refresh" icon-only label="Refresh" @click="reload" />
    </template>
    <template #filters>
      <UiInput id="zone-search" v-model="query" label="Search" sr-only-label placeholder="Search zones" type="search" size="sm" class="w-full md:max-w-sm" data-test="zone-search" @enter="reload" />
      <UiSelect id="zone-kind" v-model="kind" label="Kind" sr-only-label placeholder="All kinds" :options="kindOptions" size="sm" class="w-full md:max-w-48" data-test="zone-kind" @change="reload" />
      <UiSelect id="zone-origin" v-model="origin" label="Origin" sr-only-label placeholder="All origins" :options="originOptions" size="sm" class="w-full md:max-w-48" data-test="zone-origin" @change="reload" />
    </template>
    <UiAlert v-if="store.error" kind="error">{{ store.error }}</UiAlert>
    <UiCard :padded="false">
      <UiDataTable :items="store.items" :columns="columns" :loading="store.loading" caption="Zones — select one to view and act on it" empty-title="No zones" empty-text="Create a zone to start managing its records." clickable :row-attrs="(z) => ({ 'data-test': 'zone-row-' + z.id })" data-test="zones-table" @row-click="openZone($event.id)">
        <template #cell-name="{ row }"><span class="font-mono">{{ row.name }}</span></template>
        <template #cell-kind="{ row }"><UiBadge :color="kindColors[row.kind]">{{ row.kind }}</UiBadge></template>
        <template #cell-origin="{ row }">
          <UiBadge v-if="row.origin === 'ipam'" color="info" :data-test="'zone-ipam-' + row.id">IPAM</UiBadge>
          <UiStatusChip v-else :status="row.origin" :colors="{ manual: 'neutral', ipam: 'info' }" />
        </template>
      </UiDataTable>
    </UiCard>
    <div class="flex justify-end">
      <UiPagination :has-prev="store.page > 1" :has-next="store.page < pages" :label="pageLabel" data-test="zone-pager" @prev="store.goTo(store.page - 1)" @next="store.goTo(store.page + 1)" />
    </div>

    <UiRecordDrawer v-model="creating" close-on-save title="New zone" :schema="zoneSchema" :fields="fields" :initial="{ kind: 'native' }" :submit="create" size="lg" save-label="Create" data-test="zone-create" @saved="onCreated" />
    <ZoneDrawer :zone-id="drawer.id" :mode="drawer.mode" @close="closeDrawer" @changed="reload" @navigate="navigate" />
  </UiPage>
</template>
