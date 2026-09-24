<script setup lang="ts">
// Right-hand zone drawer: one panel that shows a zone (details, the current
// PowerDNS serial) and carries the actions on it — open its records, edit the
// metadata (kind, primaries, DNSSEC, description), NOTIFY the secondaries
// (master/producer zones), view and copy the BIND export, delete with
// confirmation.
import { computed, ref, shallowRef, watch } from 'vue'
import type { z } from 'zod'
import { UiDrawer, UiButton, UiAlert, UiBadge, UiKeyValueTable, UiRecordForm, UiToolbar, UiTabs, UiCopyButton, UiSkeleton, useConfirm, type KeyValue, type TabItem } from '@go-tangra/ui'
import { zodToFields, type ZodForm } from '@go-tangra/ui/forms'
import { useRouter } from 'vue-router'
import { useZones } from '@/stores/zones'
import { zoneUpdateSchema, ZONE_KINDS, type ZoneUpdateFormInput } from '@/schemas'
import type { Zone } from '@/api/types'
import { describe, explain } from '@/api/client'

export type ZoneDrawerMode = 'view' | 'edit'

const props = defineProps<{ zoneId: string | null; mode: ZoneDrawerMode }>()
const emit = defineEmits<{
  (e: 'close'): void
  (e: 'changed'): void
  (e: 'navigate', id: string, mode: ZoneDrawerMode): void
}>()

const store = useZones()
const router = useRouter()
const confirm = useConfirm()
const zone = ref<Zone | null>(null)
const error = ref('')
const notice = ref('')
const tab = ref('details')
const exported = ref<string | null>(null)
const exporting = ref(false)

async function load(): Promise<void> {
  error.value = ''
  notice.value = ''
  tab.value = 'details'
  exported.value = null
  if (!props.zoneId) {
    zone.value = null
    return
  }
  try {
    zone.value = await store.get(props.zoneId)
  } catch (e) {
    zone.value = null
    error.value = describe(e)
  }
}
watch(() => props.zoneId, () => void load(), { immediate: true })

const details = computed<KeyValue[]>(() => {
  const z = zone.value
  if (!z) return []
  return [
    { label: 'Name', value: z.name, copyable: true },
    { label: 'Kind', value: z.kind },
    { label: 'Primaries', value: z.masters },
    { label: 'Nameservers', value: z.nameservers },
    { label: 'DNSSEC', value: z.dnssec ? 'enabled' : 'disabled' },
    { label: 'Origin', value: z.origin === 'ipam' ? 'created by IPAM sync' : 'manual' },
    { label: 'Notified serial', value: z.notified_serial },
    { label: 'Updated', value: z.updated_at },
  ]
})

// --- edit ---
const fields = zodToFields(zoneUpdateSchema, {
  kind: { type: 'select', options: ZONE_KINDS.map((k) => ({ title: k, value: k })), required: true },
  masters: { label: 'Primaries', placeholder: '192.0.2.53, 192.0.2.54:5300', hint: 'Slave and consumer zones only: IP[:port], comma-separated.' },
  dnssec: { label: 'DNSSEC' },
})
const initial = computed(() => {
  const z = zone.value
  return z ? { kind: z.kind, masters: z.masters.join(', '), dnssec: z.dnssec, description: z.description ?? '' } : {}
})
const form = shallowRef<ZodForm<z.ZodType> | null>(null)
async function submit(v: Record<string, unknown>): Promise<Zone> {
  const z = zone.value
  if (!z) throw new Error('no zone')
  const f = v as unknown as ZoneUpdateFormInput
  try {
    return await store.update(z.id, { kind: f.kind, masters: f.masters, dnssec: f.dnssec ?? false, description: f.description ?? '' })
  } catch (e) {
    error.value = explain(e)
    throw e
  }
}
function onSaved(): void {
  emit('changed')
  if (zone.value) emit('navigate', zone.value.id, 'view')
  void load()
}

async function remove(): Promise<void> {
  const z = zone.value
  if (!z) return
  if (!(await confirm.ask({ title: `Delete ${z.name}?`, text: 'The zone and all its records are removed from the DNS server and the resolver.', danger: true, confirmLabel: 'Delete' }))) return
  try {
    await store.remove(z.id)
    emit('changed')
    emit('close')
  } catch (e) {
    error.value = describe(e)
  }
}

// --- NOTIFY (master/producer only) ---
const canNotify = computed(() => zone.value?.kind === 'master' || zone.value?.kind === 'producer')
const notifying = ref(false)
async function notify(): Promise<void> {
  const z = zone.value
  if (!z) return
  error.value = ''
  notice.value = ''
  notifying.value = true
  try {
    await store.notify(z.id)
    notice.value = 'NOTIFY sent to the secondaries.'
  } catch (e) {
    error.value = describe(e)
  } finally {
    notifying.value = false
  }
}

// --- export (BIND text) ---
const tabs: TabItem[] = [
  { key: 'details', label: 'Details', icon: 'mdi-information-outline' },
  { key: 'export', label: 'Export', icon: 'mdi-download' },
]
watch(tab, async (t) => {
  const z = zone.value
  if (t !== 'export' || !z || exported.value !== null) return
  exporting.value = true
  try {
    exported.value = (await store.exportText(z.id)).text
  } catch (e) {
    error.value = describe(e)
  } finally {
    exporting.value = false
  }
})

const openRecords = () => zone.value && void router.push({ name: 'dns-zone-records', params: { id: zone.value.id } })
const title = computed(() => (zone.value ? (props.mode === 'edit' ? `Edit ${zone.value.name}` : zone.value.name) : 'Zone'))
</script>

<template>
  <UiDrawer :model-value="zoneId !== null" :title="title" size="lg" data-test="zone-drawer" @update:model-value="emit('close')">
    <UiAlert v-if="error" kind="error" class="mb-4" data-test="zone-error">{{ error }}</UiAlert>

    <template v-if="mode === 'view' && zone">
      <UiToolbar class="mb-4">
        <UiButton size="sm" icon="mdi-file-document-multiple-outline" data-test="zone-records" @click="openRecords">Records</UiButton>
        <UiButton size="sm" variant="soft" icon="mdi-pencil-outline" data-test="zone-edit" @click="emit('navigate', zone.id, 'edit')">Edit</UiButton>
        <UiButton v-if="canNotify" size="sm" variant="soft" icon="mdi-broadcast" :loading="notifying" data-test="zone-notify" @click="notify">Notify</UiButton>
        <span class="grow" />
        <UiButton size="sm" variant="text" color="error" icon="mdi-delete-outline" data-test="zone-delete" @click="remove">Delete</UiButton>
      </UiToolbar>
      <UiAlert v-if="notice" kind="success" class="mb-4" data-test="zone-notice">{{ notice }}</UiAlert>
      <UiTabs v-model="tab" :tabs="tabs" class="mb-4" data-test="zone-tabs" />
      <template v-if="tab === 'details'">
        <div class="mb-4 flex flex-wrap items-center gap-2">
          <UiBadge v-if="zone.serial !== undefined" color="info" data-test="zone-serial">serial {{ zone.serial }}</UiBadge>
          <UiBadge v-else color="warning" data-test="zone-serial">serial unavailable</UiBadge>
          <UiBadge :color="zone.dnssec ? 'success' : 'neutral'">DNSSEC {{ zone.dnssec ? 'on' : 'off' }}</UiBadge>
          <UiBadge v-if="zone.origin === 'ipam'" color="info" data-test="zone-origin-ipam">IPAM</UiBadge>
        </div>
        <p v-if="zone.description" class="mb-4 text-sm">{{ zone.description }}</p>
        <UiKeyValueTable :items="details" :columns="1" />
      </template>
      <section v-else role="tabpanel" aria-labelledby="tab-export" class="flex flex-col gap-3" data-test="zone-export">
        <UiSkeleton v-if="exporting" :lines="6" />
        <template v-else-if="exported !== null">
          <div class="flex items-center justify-between gap-2">
            <p class="text-sm text-base-content/70">BIND zone file as served by the DNS server.</p>
            <UiCopyButton :value="exported" label="Copy" data-test="zone-export-copy" />
          </div>
          <pre class="max-h-96 overflow-auto rounded-box bg-base-200 p-3 font-mono text-xs whitespace-pre" data-test="zone-export-text">{{ exported }}</pre>
        </template>
      </section>
    </template>

    <UiRecordForm v-else-if="mode === 'edit' && zone" :key="zone.id + zone.updated_at" :schema="zoneUpdateSchema" :fields="fields" :initial="initial" :submit="submit" @ready="form = $event" @saved="onSaved" />

    <template v-if="mode === 'edit' && zone" #actions>
      <UiButton variant="text" color="neutral" icon="mdi-arrow-left" @click="emit('navigate', zone.id, 'view')">Back</UiButton>
      <UiButton :loading="form?.submitting.value ?? false" data-test="zone-save" @click="form?.submit()">Save</UiButton>
    </template>
  </UiDrawer>
</template>
