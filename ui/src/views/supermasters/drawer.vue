<script setup lang="ts">
// New supermaster: a trusted primary (IP + nameserver) allowed to
// auto-provision secondary zones on the shared DNS server. Platform
// administrators only; the account is always the current tenant.
import { UiRecordDrawer, UiAlert } from '@go-tangra/ui'
import { zodToFields } from '@go-tangra/ui/forms'
import { useSupermasters } from '@/stores/supermasters'
import { supermasterSchema, type SupermasterFormInput } from '@/schemas'
import type { Supermaster } from '@/api/types'

defineProps<{ modelValue: boolean }>()
const emit = defineEmits<{ (e: 'update:modelValue', v: boolean): void; (e: 'saved', s: Supermaster): void }>()
const store = useSupermasters()
const fields = zodToFields(supermasterSchema, {
  ip: { label: 'IP address', placeholder: '192.0.2.53', hint: 'Unicast address of the primary (no loopback or link-local).' },
  nameserver: { label: 'Nameserver', placeholder: 'ns1.primary.example', hint: 'The NS host name the primary announces.' },
})
async function submit(v: Record<string, unknown>): Promise<Supermaster> {
  const f = v as unknown as SupermasterFormInput
  return store.create({ ip: f.ip, nameserver: f.nameserver })
}
</script>

<template>
  <UiRecordDrawer :model-value="modelValue" close-on-save title="New supermaster" :schema="supermasterSchema" :fields="fields" :submit="submit" save-label="Create" data-test="supermaster-create" @update:model-value="emit('update:modelValue', $event)" @saved="emit('saved', $event as Supermaster)">
    <template #before>
      <UiAlert kind="warning">A supermaster may create any zone on the shared server. Register only primaries you trust.</UiAlert>
    </template>
  </UiRecordDrawer>
</template>
