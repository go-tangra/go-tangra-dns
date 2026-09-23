<script setup lang="ts">
// Record sets of one zone: type filter + name search, a paged table and an
// inline editor above it (no dialog) with per-type placeholders and hints,
// TTL presets, multi-value rows with per-value disabled toggles and a comment.
// SOA is shown read-only. Server refusals (invalid_record with the parser's
// reason) are shown inline in the editor. Record sets the IPAM sync maintains
// carry an "IPAM" hint (their comment marks them; edits are overwritten on the
// next IPAM change).
import { computed, onMounted, reactive, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { UiPage, UiAlert, UiCard, UiInput, UiSelect, UiNumberInput, UiCheckbox, UiButton, UiBadge, UiDataTable, UiPagination, useConfirm, type Column, type SelectOption } from '@freya/ui'
import { useZones } from '@/stores/zones'
import { useRecords } from '@/stores/records'
import { recordSetSchema, relativeName, RECORD_HINTS, RECORD_TYPES, TTL_PRESETS, type RecordType } from '@/schemas'
import type { RecordKey, RecordSet, Zone } from '@/api/types'
import { describe, explain } from '@/api/client'

const route = useRoute()
const router = useRouter()
const zones = useZones()
const store = useRecords()
const confirm = useConfirm()
const zoneId = computed(() => String(route.params.id ?? ''))
const zone = ref<Zone | null>(null)
const zoneError = ref('')
const readOnlyZone = computed(() => zone.value?.kind === 'slave' || zone.value?.kind === 'consumer')

const typeFilter = ref('')
const query = ref('')
const typeOptions: SelectOption[] = [...RECORD_TYPES, 'SOA'].map((t) => ({ title: t, value: t }))
const reload = () => store.list(zoneId.value, { type: typeFilter.value || undefined, query: query.value.trim() || undefined })

async function loadZone(): Promise<void> {
  zoneError.value = ''
  try {
    zone.value = await zones.get(zoneId.value)
  } catch (e) {
    zone.value = null
    zoneError.value = describe(e)
  }
}
onMounted(() => {
  void loadZone()
  void reload()
})
watch(zoneId, () => {
  closeEditor()
  void loadZone()
  void reload()
})

const pages = computed(() => Math.max(1, Math.ceil(store.total / store.pageSize)))
const pageLabel = computed(() => `Page ${store.page} of ${pages.value} · ${store.total} record set${store.total === 1 ? '' : 's'}`)
const short = (name: string) => (zone.value ? relativeName(name, zone.value.name) : name)
/** The comment the IPAM sync writes on the record sets it maintains. */
const IPAM_COMMENT = 'managed by IPAM sync'
const fromIPAM = (r: RecordSet) => r.comment === IPAM_COMMENT
type Row = RecordSet & { key: string }
const rows = computed<Row[]>(() => store.items.map((r) => ({ ...r, key: r.name + '|' + r.type })))
const columns: Column<Row>[] = [
  { key: 'name', label: 'Name', sortable: true },
  { key: 'type', label: 'Type', width: 'sm' },
  { key: 'ttl', label: 'TTL', width: 'sm', align: 'end' },
  { key: 'values', label: 'Values', width: 'lg' },
  { key: 'comment', label: 'Comment', hideOnStack: true },
]

// --- inline editor ---
interface Draft {
  name: string
  type: RecordType
  ttlPreset: string
  ttl: number | string
  values: { content: string; disabled: boolean }[]
  comment: string
}
const editor = reactive<{ open: boolean; original: RecordKey | null; saving: boolean; error: string; errors: Record<string, string>; draft: Draft }>({
  open: false,
  original: null,
  saving: false,
  error: '',
  errors: {},
  draft: { name: '', type: 'A', ttlPreset: '3600', ttl: 3600, values: [{ content: '', disabled: false }], comment: '' },
})
const presetValues = new Set(TTL_PRESETS.map((p) => p.value))
const ttlOptions: SelectOption[] = [...TTL_PRESETS, { title: 'Custom…', value: 'custom' }]
const editableTypes: SelectOption[] = RECORD_TYPES.map((t) => ({ title: t, value: t }))
const hint = computed(() => RECORD_HINTS[editor.draft.type])
const qualified = computed(() => {
  const z = zone.value?.name ?? ''
  const n = editor.draft.name.trim()
  if (!n || n === '@') return z
  return n.endsWith('.') ? n : `${n}.${z}`
})

function openEditor(r?: RecordSet): void {
  editor.error = ''
  editor.errors = {}
  if (r) {
    const ttl = String(r.ttl)
    editor.original = { name: r.name, type: r.type }
    editor.draft = { name: short(r.name), type: r.type as RecordType, ttlPreset: presetValues.has(ttl) ? ttl : 'custom', ttl: r.ttl,
      values: r.values.map((v) => ({ content: v.content, disabled: v.disabled })), comment: r.comment ?? '' }
  } else {
    editor.original = null
    editor.draft = { name: '', type: 'A', ttlPreset: '3600', ttl: 3600, values: [{ content: '', disabled: false }], comment: '' }
  }
  editor.open = true
}
function closeEditor(): void {
  editor.open = false
  editor.original = null
}
const addValue = () => editor.draft.values.push({ content: '', disabled: false })
const removeValue = (i: number) => editor.draft.values.splice(i, 1)
function onPreset(v: unknown): void {
  editor.draft.ttlPreset = String(v ?? '')
  if (editor.draft.ttlPreset && editor.draft.ttlPreset !== 'custom') editor.draft.ttl = Number(editor.draft.ttlPreset)
}

async function save(): Promise<void> {
  editor.error = ''
  editor.errors = {}
  const d = editor.draft
  const parsed = recordSetSchema.safeParse({ name: d.name, type: d.type, ttl: d.ttlPreset === 'custom' ? d.ttl : d.ttlPreset, values: d.values, comment: d.comment })
  if (!parsed.success) {
    for (const issue of parsed.error.issues) {
      const key = issue.path.join('.')
      editor.errors[key] ??= issue.message
    }
    return
  }
  editor.saving = true
  try {
    const body = { ...parsed.data, comment: parsed.data.comment ?? '' }
    if (editor.original) await store.update(editor.original, body)
    else await store.upsert(body)
    closeEditor()
    await store.list()
  } catch (e) {
    editor.error = explain(e)
  } finally {
    editor.saving = false
  }
}

async function remove(r: RecordSet): Promise<void> {
  if (!(await confirm.ask({ title: `Delete ${short(r.name)} ${r.type}?`, text: 'All values of this record set are removed from the DNS server.', danger: true, confirmLabel: 'Delete' }))) return
  try {
    await store.remove({ name: r.name, type: r.type })
    if (editor.original?.name === r.name && editor.original.type === r.type) closeEditor()
  } catch (e) {
    store.error = describe(e)
  }
}
</script>

<template>
  <UiPage :title="zone ? zone.name : 'Records'" subtitle="Record sets">
    <template #before-title>
      <UiButton variant="text" icon="mdi-arrow-left" icon-only label="Back to zones" @click="router.push({ name: 'dns-zones' })" />
    </template>
    <template #badges>
      <UiBadge v-if="zone" color="info">{{ zone.kind }}</UiBadge>
      <UiBadge v-if="zone?.serial !== undefined" data-test="records-serial">serial {{ zone.serial }}</UiBadge>
    </template>
    <template #actions>
      <UiButton v-if="!readOnlyZone" icon="mdi-plus" data-test="record-new" @click="openEditor()">Add record set</UiButton>
      <UiButton variant="text" icon="mdi-refresh" icon-only label="Refresh" @click="reload" />
    </template>
    <template #filters>
      <UiSelect id="record-type" v-model="typeFilter" label="Type" sr-only-label placeholder="All types" :options="typeOptions" size="sm" class="w-full md:max-w-40" data-test="record-type" @change="reload" />
      <UiInput id="record-search" v-model="query" label="Search" sr-only-label placeholder="Search names" type="search" size="sm" class="w-full md:max-w-sm" data-test="record-search" @enter="reload" />
    </template>

    <UiAlert v-if="zoneError" kind="error">{{ zoneError }}</UiAlert>
    <UiAlert v-if="readOnlyZone" kind="info">Records of {{ zone?.kind }} zones come from their primaries and cannot be edited here.</UiAlert>
    <UiAlert v-if="store.error" kind="error">{{ store.error }}</UiAlert>

    <UiCard v-if="editor.open" :title="editor.original ? `Edit ${short(editor.original.name)} ${editor.original.type}` : 'New record set'" data-test="record-editor">
      <div class="grid grid-cols-1 gap-3 md:grid-cols-12">
        <div class="md:col-span-5"><UiInput id="rec-name" v-model="editor.draft.name" label="Name" placeholder="@ or www" :hint="qualified" :error="editor.errors.name" data-test="rec-name" /></div>
        <div class="md:col-span-3"><UiSelect id="rec-type" v-model="editor.draft.type" label="Type" :options="editableTypes" required :clearable="false" :error="editor.errors.type" data-test="rec-type" /></div>
        <div class="md:col-span-2"><UiSelect id="rec-ttl-preset" :model-value="editor.draft.ttlPreset" label="TTL" :options="ttlOptions" required :clearable="false" data-test="rec-ttl" @update:model-value="onPreset" /></div>
        <div class="md:col-span-2"><UiNumberInput v-if="editor.draft.ttlPreset === 'custom'" id="rec-ttl" v-model="editor.draft.ttl" label="Seconds" :min="60" :max="604800" :step="1" :error="editor.errors.ttl" /></div>
      </div>

      <fieldset class="flex flex-col gap-2">
        <legend class="mb-1 text-sm font-medium">Values <span class="text-xs font-normal text-base-content/70">— {{ hint.hint }}</span></legend>
        <div v-for="(v, i) in editor.draft.values" :key="i" class="grid grid-cols-12 items-start gap-2" :data-test="'rec-value-' + i">
          <div class="col-span-12 md:col-span-8"><UiInput :id="'rec-value-' + i" v-model="v.content" :label="'Value ' + (i + 1)" sr-only-label :placeholder="hint.placeholder" :error="editor.errors['values.' + i + '.content']" /></div>
          <div class="col-span-8 md:col-span-3"><UiCheckbox :id="'rec-disabled-' + i" v-model="v.disabled" label="Disabled" /></div>
          <div class="col-span-4 flex justify-end md:col-span-1"><UiButton size="sm" variant="text" color="neutral" icon="mdi-close" icon-only :label="'Remove value ' + (i + 1)" :disabled="editor.draft.values.length === 1" @click="removeValue(i)" /></div>
        </div>
        <p v-if="editor.errors.values" class="text-xs text-error" role="alert">{{ editor.errors.values }}</p>
        <div><UiButton size="sm" variant="soft" icon="mdi-plus" :disabled="editor.draft.type === 'CNAME' || editor.draft.values.length >= 100" data-test="rec-add-value" @click="addValue">Add value</UiButton></div>
      </fieldset>

      <UiInput id="rec-comment" v-model="editor.draft.comment" label="Comment" placeholder="Optional" :error="editor.errors.comment" />
      <UiAlert v-if="editor.error" kind="error" data-test="rec-error">{{ editor.error }}</UiAlert>
      <template #footer>
        <UiButton variant="text" color="neutral" @click="closeEditor">Cancel</UiButton>
        <UiButton icon="mdi-check" :loading="editor.saving" data-test="rec-save" @click="save">Save</UiButton>
      </template>
    </UiCard>

    <UiCard :padded="false">
      <UiDataTable :items="rows" :columns="columns" :loading="store.loading" row-key="key" caption="Record sets" empty-title="No record sets match" :row-attrs="(r) => ({ 'data-test': 'record-row-' + r.type + '-' + short(r.name) })" data-test="records-table">
        <template #cell-name="{ row }">
          <span class="font-mono">{{ short(row.name) }}</span>
          <UiBadge v-if="fromIPAM(row)" size="xs" color="info" class="ms-2" title="Maintained by the IPAM sync" :data-test="'record-ipam-' + row.type + '-' + short(row.name)">IPAM</UiBadge>
        </template>
        <template #cell-type="{ row }"><UiBadge :color="row.read_only ? 'neutral' : 'primary'">{{ row.type }}</UiBadge></template>
        <template #cell-values="{ row }">
          <ul class="flex flex-col gap-0.5">
            <li v-for="(v, i) in row.values" :key="i" class="font-mono text-xs break-all" :class="v.disabled ? 'text-base-content/50 line-through' : ''">
              {{ v.content }} <UiBadge v-if="v.disabled" size="xs" color="warning">disabled</UiBadge>
            </li>
          </ul>
        </template>
        <template #actions="{ row }">
          <UiBadge v-if="row.read_only" size="xs">read-only</UiBadge>
          <template v-else-if="!readOnlyZone">
            <UiButton size="xs" variant="text" icon="mdi-pencil-outline" icon-only label="Edit" :data-test="'record-edit-' + row.type + '-' + short(row.name)" @click="openEditor(row)" />
            <UiButton size="xs" variant="text" color="error" icon="mdi-delete-outline" icon-only label="Delete" :data-test="'record-delete-' + row.type + '-' + short(row.name)" @click="remove(row)" />
          </template>
        </template>
      </UiDataTable>
    </UiCard>
    <div class="flex justify-end">
      <UiPagination :has-prev="store.page > 1" :has-next="store.page < pages" :label="pageLabel" data-test="record-pager" @prev="store.goTo(store.page - 1)" @next="store.goTo(store.page + 1)" />
    </div>
  </UiPage>
</template>
