<script setup lang="ts">
// Template drawer: name, description and the record rows (name, type, TTL,
// value, MX/SRV priority) of a zone template. [ZONE] in names and values is
// replaced by the zone name when a zone is created from the template; the
// server re-validates every row. Server refusals point at the offending row.
import { computed, reactive, ref, watch } from 'vue'
import { UiDrawer, UiAlert, UiButton, UiInput, UiTextarea, UiSelect, UiNumberInput, useConfirm, type SelectOption } from '@freya/ui'
import { useTemplates } from '@/stores/templates'
import { templateSchema, expandName, hasPriority, MAX_TEMPLATE_RECORDS, RECORD_HINTS, RECORD_TYPES, ZONE_PLACEHOLDER, type RecordType } from '@/schemas'
import type { Template } from '@/api/types'
import { ApiError, describe, explain } from '@/api/client'

const props = defineProps<{ modelValue: boolean; template: Template | null; canManage: boolean }>()
const emit = defineEmits<{
  (e: 'update:modelValue', v: boolean): void
  (e: 'saved', t: Template): void
  (e: 'deleted', id: string): void
}>()

const store = useTemplates()
const confirm = useConfirm()
interface Row {
  name: string
  type: RecordType
  ttl: number | string
  content: string
  priority: number | string
}
const draft = reactive<{ name: string; description: string; records: Row[] }>({ name: '', description: '', records: [] })
const errors = ref<Record<string, string>>({})
const error = ref('')
const saving = ref(false)
const typeOptions: SelectOption[] = RECORD_TYPES.map((t) => ({ title: t, value: t }))

function reset(): void {
  const t = props.template
  errors.value = {}
  error.value = ''
  draft.name = t?.name ?? ''
  draft.description = t?.description ?? ''
  draft.records = (t?.records ?? []).map((r) => ({ name: r.name, type: r.type as RecordType, ttl: r.ttl, content: r.content, priority: r.priority ?? '' }))
}
watch(() => [props.modelValue, props.template], () => props.modelValue && reset(), { immediate: true })

const addRow = () => draft.records.push({ name: '@', type: 'A', ttl: 3600, content: '', priority: '' })
const removeRow = (i: number) => draft.records.splice(i, 1)
const title = computed(() => (props.template ? (props.canManage ? `Edit ${props.template.name}` : props.template.name) : 'New template'))

/** "records[3].content" (server) → "records.3.content" (form keys). */
const fieldKey = (f: string) => f.replace(/\[(\d+)\]/g, '.$1')

async function save(): Promise<void> {
  errors.value = {}
  error.value = ''
  const parsed = templateSchema.safeParse({ name: draft.name, description: draft.description, records: draft.records })
  if (!parsed.success) {
    for (const issue of parsed.error.issues) errors.value[issue.path.join('.')] ??= issue.message
    return
  }
  saving.value = true
  try {
    const body = { ...parsed.data, records: parsed.data.records.map((r) => ({ ...r, priority: hasPriority(r.type) ? r.priority : undefined })) }
    const t = props.template ? await store.update(props.template.id, body) : await store.create(body)
    emit('saved', t)
    emit('update:modelValue', false)
  } catch (e) {
    error.value = explain(e)
    if (e instanceof ApiError && typeof e.detail?.field === 'string') errors.value[fieldKey(e.detail.field)] = String(e.detail.message ?? 'Not valid.')
  } finally {
    saving.value = false
  }
}

async function remove(): Promise<void> {
  const t = props.template
  if (!t || !(await confirm.ask({ title: `Delete ${t.name}?`, text: 'Zones created from this template are kept.', danger: true, confirmLabel: 'Delete' }))) return
  try {
    await store.remove(t.id)
    emit('deleted', t.id)
    emit('update:modelValue', false)
  } catch (e) {
    error.value = describe(e)
  }
}
</script>

<template>
  <UiDrawer :model-value="modelValue" :title="title" size="xl" data-test="template-drawer" @update:model-value="emit('update:modelValue', $event)">
    <div class="flex flex-col gap-4">
      <UiAlert v-if="error" kind="error" data-test="template-error">{{ error }}</UiAlert>
      <UiInput id="tpl-name" v-model="draft.name" label="Name" required :disabled="!canManage" :error="errors.name" data-test="tpl-name" />
      <UiTextarea id="tpl-description" v-model="draft.description" label="Description" :rows="2" :disabled="!canManage" :error="errors.description" />
      <UiAlert kind="info">
        Use <code class="font-mono">{{ ZONE_PLACEHOLDER }}</code> in names and values for the zone name, and <code class="font-mono">@</code> (or an empty name) for the zone apex.
        MX and SRV values leave out the priority when it is set in its own field.
      </UiAlert>

      <fieldset class="flex flex-col gap-3" data-test="tpl-records">
        <legend class="mb-1 text-sm font-medium">Records <span class="text-xs font-normal text-base-content/70">— {{ draft.records.length }} of {{ MAX_TEMPLATE_RECORDS }}</span></legend>
        <p v-if="draft.records.length === 0" class="text-sm text-base-content/70">No records yet.</p>
        <div v-for="(r, i) in draft.records" :key="i" class="grid grid-cols-12 items-start gap-2 border-b border-base-300 pb-3" :data-test="'tpl-row-' + i">
          <div class="col-span-12 md:col-span-3"><UiInput :id="'tpl-rec-name-' + i" v-model="r.name" :label="'Name ' + (i + 1)" placeholder="@ or www" :hint="expandName(r.name)" :disabled="!canManage" :error="errors['records.' + i + '.name']" /></div>
          <div class="col-span-6 md:col-span-2"><UiSelect :id="'tpl-rec-type-' + i" v-model="r.type" label="Type" :options="typeOptions" :clearable="false" :disabled="!canManage" :error="errors['records.' + i + '.type']" /></div>
          <div class="col-span-6 md:col-span-2"><UiNumberInput :id="'tpl-rec-ttl-' + i" v-model="r.ttl" label="TTL" :min="60" :max="604800" :disabled="!canManage" :error="errors['records.' + i + '.ttl']" /></div>
          <div class="col-span-12" :class="hasPriority(r.type) ? 'md:col-span-3' : 'md:col-span-4'">
            <UiInput :id="'tpl-rec-content-' + i" v-model="r.content" label="Value" :placeholder="RECORD_HINTS[r.type]?.placeholder" :disabled="!canManage" :error="errors['records.' + i + '.content']" />
          </div>
          <div v-if="hasPriority(r.type)" class="col-span-8 md:col-span-1"><UiNumberInput :id="'tpl-rec-prio-' + i" v-model="r.priority" label="Priority" :min="0" :max="65535" :disabled="!canManage" :error="errors['records.' + i + '.priority']" /></div>
          <div class="col-span-4 flex justify-end pt-7 md:col-span-1">
            <UiButton v-if="canManage" size="sm" variant="text" color="neutral" icon="mdi-close" icon-only :label="'Remove record ' + (i + 1)" :data-test="'tpl-remove-' + i" @click="removeRow(i)" />
          </div>
        </div>
        <p v-if="errors.records" class="text-xs text-error" role="alert">{{ errors.records }}</p>
        <div v-if="canManage"><UiButton size="sm" variant="soft" icon="mdi-plus" :disabled="draft.records.length >= MAX_TEMPLATE_RECORDS" data-test="tpl-add" @click="addRow">Add record</UiButton></div>
      </fieldset>
    </div>

    <template v-if="canManage" #actions>
      <UiButton v-if="template" variant="text" color="error" icon="mdi-delete-outline" data-test="tpl-delete" @click="remove">Delete</UiButton>
      <span class="grow" />
      <UiButton variant="text" color="neutral" @click="emit('update:modelValue', false)">Cancel</UiButton>
      <UiButton icon="mdi-check" :loading="saving" data-test="tpl-save" @click="save">Save</UiButton>
    </template>
  </UiDrawer>
</template>
