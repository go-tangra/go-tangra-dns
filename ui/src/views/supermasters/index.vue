<script setup lang="ts">
// Supermasters of this tenant: trusted primaries allowed to auto-provision
// secondary zones. Everyone with the permission can list them; adding and
// removing needs platform administration (the actions are hidden otherwise
// and the server refuses them anyway). There is no edit: delete and re-create.
import { computed, inject, onMounted, ref } from 'vue'
import { ABILITY_TOKEN } from '@casl/vue'
import type { AnyAbility } from '@casl/ability'
import { UiPage, UiAlert, UiCard, UiButton, UiDataTable, useConfirm, type Column } from '@freya/ui'
import { useSupermasters } from '@/stores/supermasters'
import type { Supermaster } from '@/api/types'
import { describe } from '@/api/client'
import SupermasterDrawer from './drawer.vue'

const store = useSupermasters()
const confirm = useConfirm()
const ability = inject<AnyAbility | null>(ABILITY_TOKEN, null)
const canCreate = computed(() => ability?.can('create', 'DnsSupermaster') ?? false)
const canDelete = computed(() => ability?.can('delete', 'DnsSupermaster') ?? false)
onMounted(() => void store.list())

const columns: Column<Supermaster>[] = [
  { key: 'ip', label: 'IP address', sortable: true },
  { key: 'nameserver', label: 'Nameserver' },
  { key: 'created_at', label: 'Added', hideOnStack: true },
]
const creating = ref(false)

async function remove(s: Supermaster): Promise<void> {
  if (!(await confirm.ask({ title: `Remove ${s.ip} (${s.nameserver})?`, text: 'The primary can no longer create zones on the DNS server. Zones it created are kept.', danger: true, confirmLabel: 'Remove' }))) return
  try {
    await store.remove(s.id)
  } catch (e) {
    store.error = describe(e)
  }
}
</script>

<template>
  <UiPage title="Supermasters" subtitle="Primaries allowed to create secondary zones">
    <template #actions>
      <UiButton v-if="canCreate" icon="mdi-plus" data-test="supermaster-new" @click="creating = true">Add supermaster</UiButton>
      <UiButton variant="text" icon="mdi-refresh" icon-only label="Refresh" @click="store.list()" />
    </template>
    <UiAlert v-if="!canCreate" kind="info" data-test="supermaster-admin-hint">Adding or removing supermasters requires platform administration.</UiAlert>
    <UiAlert v-if="store.error" kind="error">{{ store.error }}</UiAlert>
    <UiCard :padded="false">
      <UiDataTable :items="store.items" :columns="columns" :loading="store.loading" caption="Supermasters" empty-title="No supermasters" :row-attrs="(s) => ({ 'data-test': 'supermaster-row-' + s.id })" data-test="supermasters-table">
        <template #cell-ip="{ row }"><span class="font-mono">{{ row.ip }}</span></template>
        <template #cell-nameserver="{ row }"><span class="font-mono">{{ row.nameserver }}</span></template>
        <template #actions="{ row }">
          <UiButton v-if="canDelete" size="xs" variant="text" color="error" icon="mdi-delete-outline" icon-only label="Remove" :data-test="'supermaster-delete-' + row.id" @click="remove(row)" />
        </template>
      </UiDataTable>
    </UiCard>
    <SupermasterDrawer v-if="canCreate" v-model="creating" />
  </UiPage>
</template>
