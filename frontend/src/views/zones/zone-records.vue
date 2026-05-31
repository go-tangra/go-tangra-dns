<script lang="ts" setup>
import { h, ref, computed, onMounted } from 'vue';
import { useRoute, useRouter } from 'vue-router';

import { Page } from 'shell/vben/common-ui';
import {
  LucideArrowLeft,
  LucidePencil,
  LucideTrash,
  LucidePlus,
  LucideCopy,
} from 'shell/vben/icons';

import {
  notification,
  Table,
  Tag,
  Button,
  Space,
  Select,
  Input,
  InputNumber,
  Textarea,
  Modal,
  Card,
  Spin,
} from 'ant-design-vue';

import {
  type Record as DnsRecord,
  type RecordType,
  type Zone,
} from '../../api/services';
import { $t } from 'shell/locales';
import { useDnsZoneStore } from '../../stores/dns-zone.state';
import { useDnsRecordStore } from '../../stores/dns-record.state';

const route = useRoute();
const router = useRouter();
const zoneStore = useDnsZoneStore();
const recordStore = useDnsRecordStore();

const zoneId = computed(() => String(route.params.zoneId ?? ''));

const zone = ref<Zone | undefined>(undefined);
const records = ref<DnsRecord[]>([]);
const loading = ref(false);

// ---- Type options (common first, then the rest) ----
const typeOptions = [
  { value: 'RECORD_TYPE_A', label: 'A' },
  { value: 'RECORD_TYPE_AAAA', label: 'AAAA' },
  { value: 'RECORD_TYPE_CNAME', label: 'CNAME' },
  { value: 'RECORD_TYPE_TXT', label: 'TXT' },
  { value: 'RECORD_TYPE_MX', label: 'MX' },
  { value: 'RECORD_TYPE_NS', label: 'NS' },
  { value: 'RECORD_TYPE_SRV', label: 'SRV' },
  { value: 'RECORD_TYPE_CAA', label: 'CAA' },
  { value: 'RECORD_TYPE_PTR', label: 'PTR' },
  { value: 'RECORD_TYPE_SOA', label: 'SOA' },
  { value: 'RECORD_TYPE_SPF', label: 'SPF' },
  { value: 'RECORD_TYPE_NAPTR', label: 'NAPTR' },
  { value: 'RECORD_TYPE_TLSA', label: 'TLSA' },
  { value: 'RECORD_TYPE_SSHFP', label: 'SSHFP' },
  { value: 'RECORD_TYPE_DS', label: 'DS' },
  { value: 'RECORD_TYPE_DNSKEY', label: 'DNSKEY' },
];

const ttlOptions = [
  { value: 3600, label: 'dns.page.record.ttlAuto' },
  { value: 60, label: 'dns.page.record.ttl1min' },
  { value: 300, label: 'dns.page.record.ttl5min' },
  { value: 1800, label: 'dns.page.record.ttl30min' },
  { value: 86400, label: 'dns.page.record.ttl1day' },
];

const DEFAULT_TTL = 3600;

// Type -> colored Tag.
function typeColor(type: string): string {
  switch (type) {
    case 'A':
    case 'AAAA':
      return 'blue';
    case 'CNAME':
      return 'purple';
    case 'MX':
      return 'orange';
    case 'TXT':
    case 'SPF':
      return 'green';
    case 'NS':
      return 'geekblue';
    case 'SRV':
      return 'cyan';
    case 'CAA':
      return 'gold';
    default:
      return 'default';
  }
}

// Maps a record type (enum or short string) to its short display label.
function typeToLabel(type: string | undefined): string {
  if (!type) return '';
  return type.startsWith('RECORD_TYPE_') ? type.replace('RECORD_TYPE_', '') : type;
}

// Maps a short label / enum to the full enum form used by the API.
function typeToEnum(type: string | undefined): RecordType {
  if (!type) return 'RECORD_TYPE_A';
  return (type.startsWith('RECORD_TYPE_') ? type : `RECORD_TYPE_${type}`) as RecordType;
}

// ---- Name helpers ----
function stripDot(value: string): string {
  return value.replace(/\.$/, '');
}

const zoneName = computed(() => zone.value?.name ?? '');
const zoneDisplay = computed(() => stripDot(zoneName.value));

const kindLabelMap: Record<string, string> = {
  ZONE_KIND_NATIVE: 'dns.enum.zoneKind.native',
  ZONE_KIND_MASTER: 'dns.enum.zoneKind.master',
  ZONE_KIND_SLAVE: 'dns.enum.zoneKind.slave',
  ZONE_KIND_PRODUCER: 'dns.enum.zoneKind.producer',
  ZONE_KIND_CONSUMER: 'dns.enum.zoneKind.consumer',
};
const kindLabel = computed(() => {
  const key = zone.value?.kind ? kindLabelMap[zone.value.kind] : undefined;
  return key ? $t(key) : (zone.value?.kind ?? '');
});

// Display a full record name relative to the zone (Cloudflare-style).
function displayName(fullName: string | undefined): string {
  if (!fullName) return '@';
  const name = stripDot(fullName);
  const zname = stripDot(zoneName.value);
  if (name === zname || name === '') return '@';
  if (zname && name.endsWith(`.${zname}`)) {
    return name.slice(0, name.length - zname.length - 1);
  }
  return name;
}

// Convert a relative input into a FQDN with exactly one trailing dot.
function toFqdn(input: string): string {
  const zname = stripDot(zoneName.value);
  const trimmed = input.trim();
  if (trimmed === '' || trimmed === '@') {
    return `${zname}.`;
  }
  const bare = stripDot(trimmed);
  if (zname && (bare === zname || bare.endsWith(`.${zname}`))) {
    return `${bare}.`;
  }
  return `${bare}.${zname}.`;
}

// ---- TTL humanization ----
function humanizeTtl(ttl: number | undefined): string {
  const value = ttl ?? DEFAULT_TTL;
  if (value === DEFAULT_TTL) return $t('dns.page.record.ttlAuto');
  if (value === 60) return $t('dns.page.record.ttl1min');
  if (value === 300) return $t('dns.page.record.ttl5min');
  if (value === 1800) return $t('dns.page.record.ttl30min');
  if (value === 86400) return $t('dns.page.record.ttl1day');
  if (value % 86400 === 0) return `${value / 86400} d`;
  if (value % 3600 === 0) return `${value / 3600} h`;
  if (value % 60 === 0) return `${value / 60} min`;
  return `${value}s`;
}

// ---- Content label / placeholder adapt to type ----
function contentMeta(type: string): { label: string; placeholder: string } {
  switch (typeToLabel(type)) {
    case 'A':
      return { label: $t('dns.page.record.contentA'), placeholder: '192.0.2.1' };
    case 'AAAA':
      return { label: $t('dns.page.record.contentAAAA'), placeholder: '2001:db8::1' };
    case 'CNAME':
      return { label: $t('dns.page.record.contentCNAME'), placeholder: 'example.com.' };
    case 'NS':
      return { label: $t('dns.page.record.contentNS'), placeholder: 'ns1.example.com.' };
    case 'PTR':
      return { label: $t('dns.page.record.contentPTR'), placeholder: 'host.example.com.' };
    case 'MX':
      return { label: $t('dns.page.record.contentMX'), placeholder: 'mail.example.com.' };
    case 'TXT':
      return { label: $t('dns.page.record.contentTXT'), placeholder: 'v=spf1 -all' };
    case 'CAA':
      return { label: $t('dns.page.record.contentCAA'), placeholder: '0 issue "letsencrypt.org"' };
    case 'SRV':
      return { label: $t('dns.page.record.contentSRV'), placeholder: '5 5060 sip.example.com.' };
    default:
      return { label: $t('dns.page.record.content'), placeholder: $t('dns.page.record.content') };
  }
}

const currentContentMeta = computed(() => contentMeta(form.value.type));
const showPriority = computed(
  () => form.value.type === 'RECORD_TYPE_MX' || form.value.type === 'RECORD_TYPE_SRV',
);

// ---- Inline form state ----
const formVisible = ref(false);
const formMode = ref<'create' | 'edit'>('create');
const saving = ref(false);
// Holds the original FQDN + type when editing (identifies the RRset).
const editFullName = ref('');

const form = ref<{
  name: string;
  type: RecordType;
  content: string;
  priority: number;
  ttl: number;
}>({
  name: '',
  type: 'RECORD_TYPE_A',
  content: '',
  priority: 10,
  ttl: DEFAULT_TTL,
});

function resetForm() {
  form.value = {
    name: '',
    type: 'RECORD_TYPE_A',
    content: '',
    priority: 10,
    ttl: DEFAULT_TTL,
  };
}

// ---- Data loading ----
async function loadZone() {
  try {
    const resp = await zoneStore.getZone(zoneId.value);
    zone.value = resp.zone;
  } catch (e) {
    console.error('Failed to load zone:', e);
    notification.error({ message: $t('ui.notification.failed') });
  }
}

async function loadRecords() {
  if (!zoneId.value) return;
  loading.value = true;
  try {
    const resp = await recordStore.listRecords(zoneId.value);
    records.value = resp.records ?? [];
  } catch (e) {
    console.error('Failed to load records:', e);
    notification.error({ message: $t('ui.notification.failed') });
  } finally {
    loading.value = false;
  }
}

// ---- Header actions ----
function goBack() {
  router.push('/dns/zones');
}

const exportVisible = ref(false);
const exportContent = ref('');

async function handleExport() {
  if (!zoneId.value) return;
  try {
    const resp = await zoneStore.exportZone(zoneId.value);
    exportContent.value = resp.bindZone ?? '';
    exportVisible.value = true;
  } catch {
    notification.error({ message: $t('ui.notification.failed') });
  }
}

async function copyExport() {
  try {
    await navigator.clipboard.writeText(exportContent.value);
    notification.success({ message: $t('dns.page.record.copied') });
  } catch {
    notification.error({ message: $t('ui.notification.failed') });
  }
}

async function handleNotify() {
  if (!zoneId.value) return;
  try {
    await zoneStore.notifyZone(zoneId.value);
    notification.success({ message: $t('dns.page.zone.notifySuccess') });
  } catch {
    notification.error({ message: $t('ui.notification.failed') });
  }
}

// ---- Add / Edit form ----
function openCreate() {
  resetForm();
  formMode.value = 'create';
  editFullName.value = '';
  formVisible.value = true;
}

function openEdit(row: DnsRecord) {
  const label = typeToLabel(row.type);
  const lines = (row.contents ?? []).map((c) => c.content ?? '');
  let priority = 10;
  let contentLines = lines;
  if (label === 'MX' || label === 'SRV') {
    // For MX, content is "10 mail.example.com." — split the priority off.
    const parsed = lines.map((line) => {
      const match = line.match(/^(\d+)\s+(.*)$/);
      if (match) {
        priority = Number(match[1]);
        return match[2] ?? '';
      }
      return line;
    });
    contentLines = parsed;
  }
  form.value = {
    name: displayName(row.name),
    type: typeToEnum(row.type),
    content: contentLines.join('\n'),
    priority,
    ttl: row.ttl ?? DEFAULT_TTL,
  };
  formMode.value = 'edit';
  editFullName.value = row.name ?? '';
  formVisible.value = true;
}

function cancelForm() {
  formVisible.value = false;
  resetForm();
}

function buildContents() {
  const label = typeToLabel(form.value.type);
  const lines = form.value.content
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l.length > 0);
  if (label === 'MX') {
    return lines.map((line) => ({ content: `${form.value.priority} ${line}` }));
  }
  return lines.map((line) => ({ content: line }));
}

async function handleSave() {
  if (!zoneId.value) return;
  const contents = buildContents();
  if (contents.length === 0) {
    notification.error({ message: $t('dns.page.record.contentRequired') });
    return;
  }
  saving.value = true;
  try {
    if (formMode.value === 'create') {
      await recordStore.createRecord(zoneId.value, {
        name: toFqdn(form.value.name),
        type: form.value.type,
        ttl: form.value.ttl,
        contents,
      });
      notification.success({ message: $t('dns.page.record.createSuccess') });
    } else {
      await recordStore.updateRecord(
        zoneId.value,
        editFullName.value,
        typeToLabel(form.value.type),
        {
          ttl: form.value.ttl,
          contents,
        },
      );
      notification.success({ message: $t('dns.page.record.updateSuccess') });
    }
    formVisible.value = false;
    resetForm();
    await loadRecords();
  } catch (e) {
    console.error('Failed to save record:', e);
    notification.error({
      message:
        formMode.value === 'create'
          ? $t('ui.notification.create_failed')
          : $t('ui.notification.update_failed'),
    });
  } finally {
    saving.value = false;
  }
}

function confirmDelete(row: DnsRecord) {
  Modal.confirm({
    title: $t('dns.page.record.confirmDelete'),
    okText: $t('ui.button.ok'),
    cancelText: $t('ui.button.cancel'),
    okType: 'danger',
    onOk: () => handleDelete(row),
  });
}

async function handleDelete(row: DnsRecord) {
  if (!zoneId.value || !row.name || !row.type) return;
  try {
    await recordStore.deleteRecord(zoneId.value, row.name, typeToLabel(row.type));
    notification.success({ message: $t('dns.page.record.deleteSuccess') });
    await loadRecords();
  } catch {
    notification.error({ message: $t('ui.notification.delete_failed') });
  }
}

const columns = computed(() => [
  { title: $t('dns.page.record.type'), key: 'type', width: 110 },
  { title: $t('dns.page.record.name'), key: 'name', minWidth: 180 },
  { title: $t('dns.page.record.content'), key: 'content', minWidth: 260 },
  { title: $t('dns.page.record.ttl'), key: 'ttl', width: 110 },
  { title: $t('ui.table.action'), key: 'action', width: 120, align: 'right' as const },
]);

onMounted(async () => {
  await Promise.all([loadZone(), loadRecords()]);
});
</script>

<template>
  <Page auto-content-height>
    <div class="flex flex-col gap-4">
      <!-- Header -->
      <div class="flex flex-wrap items-center justify-between gap-3">
        <div class="flex flex-col gap-1">
          <a
            class="text-muted-foreground hover:text-primary flex w-fit items-center gap-1 text-sm"
            @click="goBack"
          >
            <LucideArrowLeft class="size-4" />
            {{ $t('dns.page.record.allZones') }}
          </a>
          <div class="flex flex-wrap items-center gap-2">
            <h2 class="m-0 font-mono text-xl font-semibold">{{ zoneDisplay || '—' }}</h2>
            <Tag>{{ kindLabel }}</Tag>
            <Tag :color="zone?.dnssecEnabled ? 'success' : 'default'">
              {{
                zone?.dnssecEnabled
                  ? $t('dns.page.record.dnssecOn')
                  : $t('dns.page.record.dnssecOff')
              }}
            </Tag>
          </div>
        </div>
        <Space>
          <Button @click="handleExport">{{ $t('dns.page.zone.export') }}</Button>
          <Button @click="handleNotify">{{ $t('dns.page.zone.notify') }}</Button>
        </Space>
      </div>

      <!-- Add record button -->
      <div v-if="!formVisible">
        <Button type="primary" @click="openCreate">
          <span style="display: inline-flex; align-items: center; gap: 4px">
            <component :is="LucidePlus" class="size-4" />
            {{ $t('dns.page.record.addRecord') }}
          </span>
        </Button>
      </div>

      <!-- Inline add/edit form -->
      <Card v-if="formVisible" size="small" class="bg-muted/30">
        <div class="flex flex-wrap items-start gap-4">
          <div class="flex min-w-[120px] flex-col gap-1">
            <span class="text-xs font-medium">{{ $t('dns.page.record.type') }}</span>
            <Select
              v-model:value="form.type"
              :options="typeOptions"
              :disabled="formMode === 'edit'"
              style="width: 130px"
            />
          </div>

          <div class="flex min-w-[200px] flex-1 flex-col gap-1">
            <span class="text-xs font-medium">{{ $t('dns.page.record.name') }}</span>
            <Input v-model:value="form.name" :disabled="formMode === 'edit'" placeholder="@">
              <template #addonAfter>.{{ zoneDisplay }}</template>
            </Input>
            <span class="text-muted-foreground text-xs">{{ $t('dns.page.record.nameHelp') }}</span>
          </div>

          <div
            v-if="showPriority"
            class="flex min-w-[100px] flex-col gap-1"
          >
            <span class="text-xs font-medium">{{ $t('dns.page.record.priority') }}</span>
            <InputNumber v-model:value="form.priority" :min="0" :max="65535" style="width: 100px" />
          </div>

          <div class="flex min-w-[240px] flex-1 flex-col gap-1">
            <span class="text-xs font-medium">{{ currentContentMeta.label }}</span>
            <Textarea
              v-model:value="form.content"
              :placeholder="currentContentMeta.placeholder"
              :auto-size="{ minRows: 1, maxRows: 5 }"
              class="font-mono"
            />
          </div>

          <div class="flex min-w-[120px] flex-col gap-1">
            <span class="text-xs font-medium">{{ $t('dns.page.record.ttl') }}</span>
            <Select v-model:value="form.ttl" style="width: 120px">
              <Select.Option
                v-for="opt in ttlOptions"
                :key="opt.value"
                :value="opt.value"
              >
                {{ $t(opt.label) }}
              </Select.Option>
            </Select>
          </div>

          <div class="flex flex-col gap-1">
            <span class="text-xs font-medium">&nbsp;</span>
            <Space>
              <Button type="primary" :loading="saving" @click="handleSave">
                {{ $t('ui.button.save') }}
              </Button>
              <Button @click="cancelForm">{{ $t('ui.button.cancel') }}</Button>
            </Space>
          </div>
        </div>
      </Card>

      <!-- Records table -->
      <Spin :spinning="loading">
        <Table
          :columns="columns"
          :data-source="records"
          :pagination="false"
          :row-key="(r: DnsRecord) => `${r.name}-${r.type}`"
          size="middle"
        >
          <template #bodyCell="{ column, record }">
            <template v-if="column.key === 'type'">
              <Tag :color="typeColor(typeToLabel(record.type))">
                {{ typeToLabel(record.type) }}
              </Tag>
            </template>
            <template v-else-if="column.key === 'name'">
              <span class="font-mono">{{ displayName(record.name) }}</span>
            </template>
            <template v-else-if="column.key === 'content'">
              <div class="flex flex-col gap-0.5">
                <span
                  v-for="(c, idx) in record.contents || []"
                  :key="idx"
                  class="font-mono text-xs"
                  :class="{ 'text-muted-foreground line-through': c.disabled }"
                >
                  {{ c.content }}
                </span>
              </div>
            </template>
            <template v-else-if="column.key === 'ttl'">
              {{ humanizeTtl(record.ttl) }}
            </template>
            <template v-else-if="column.key === 'action'">
              <Space>
                <Button
                  type="link"
                  size="small"
                  :icon="h(LucidePencil)"
                  :title="$t('ui.button.edit')"
                  @click="openEdit(record)"
                />
                <Button
                  danger
                  type="link"
                  size="small"
                  :icon="h(LucideTrash)"
                  :title="$t('ui.button.delete', { moduleName: '' })"
                  @click="confirmDelete(record)"
                />
              </Space>
            </template>
          </template>
        </Table>
      </Spin>
    </div>

    <!-- Export modal -->
    <Modal
      v-model:open="exportVisible"
      :title="$t('dns.page.zone.exportTitle')"
      :footer="null"
      width="700px"
    >
      <div class="mb-2 flex justify-end">
        <Button size="small" @click="copyExport">
          <span style="display: inline-flex; align-items: center; gap: 4px">
            <component :is="LucideCopy" class="size-4" />
            {{ $t('dns.page.record.copy') }}
          </span>
        </Button>
      </div>
      <pre
        class="bg-muted max-h-96 overflow-auto rounded p-3 font-mono text-xs"
      >{{ exportContent || $t('dns.page.zone.noBindData') }}</pre>
    </Modal>
  </Page>
</template>
