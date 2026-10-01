<script setup lang="ts">
// Zone templates: a server-paged table of the tenant's templates; selecting
// one (or "New template") opens the template drawer with its record rows.
import { computed, inject, onMounted, ref, watch } from 'vue'
import { ABILITY_TOKEN } from '@casl/vue'
import type { AnyAbility } from '@casl/ability'
import { UiPage, UiAlert, UiCard, UiButton, UiDataTable, useListQuery, type Column } from '@go-tangra/ui'
import { useTemplates } from '@/stores/templates'
import type { Template } from '@/api/types'
import TemplateDrawer from './drawer.vue'

const store = useTemplates()
const ability = inject<AnyAbility | null>(ABILITY_TOKEN, null)
// Without an ability provider (standalone dev) the server stays the judge.
const canManage = computed(() => (ability ? ability.can('manage', 'DnsTemplate') : true))
const lq = useListQuery('templates', { sortable: ['name'], defaultSort: { key: 'name', dir: 'asc' } })
async function reload(): Promise<void> {
  const p = await store.list({ ...lq.query.value })
  if (p) lq.clampTo(p)
}
watch(lq.query, () => void reload())
onMounted(() => void reload())

const columns: Column<Template>[] = [
  { key: 'name', label: 'Name', sortable: true },
  { key: 'records', label: 'Records', width: 'sm', align: 'end', format: (t) => String(t.records.length) },
  { key: 'description', label: 'Description', hideOnStack: true },
]

const drawer = ref(false)
const selected = ref<Template | null>(null)
function open(t: Template | null): void {
  selected.value = t
  drawer.value = true
}
</script>

<template>
  <UiPage title="Templates" subtitle="Reusable record sets for new zones">
    <template #actions>
      <UiButton v-if="canManage" icon="mdi-plus" data-test="template-new" @click="open(null)">New template</UiButton>
      <UiButton variant="text" icon="mdi-refresh" icon-only label="Refresh" @click="reload" />
    </template>
    <UiAlert v-if="store.error" kind="error">{{ store.error }}</UiAlert>
    <UiCard :padded="false">
      <UiDataTable :items="store.items" :columns="columns" :loading="store.loading" :total="store.total" :page="lq.page.value" :page-size="lq.pageSize.value" :sort="lq.sort.value" caption="Zone templates — select one to view or edit it" empty-title="No templates" empty-text="Create a template to start new zones with standard records." clickable :row-attrs="(t) => ({ 'data-test': 'template-row-' + t.id })" data-test="templates-table" @row-click="open($event)" @update:page="lq.setPage" @update:page-size="lq.setPageSize" @update:sort="lq.setSort" />
    </UiCard>
    <TemplateDrawer v-model="drawer" :template="selected" :can-manage="canManage" @saved="reload" @deleted="reload" />
  </UiPage>
</template>
