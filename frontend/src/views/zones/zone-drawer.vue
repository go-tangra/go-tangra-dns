<script lang="ts" setup>
import { ref, computed } from 'vue';

import { useVbenDrawer } from 'shell/vben/common-ui';

import {
  Form,
  FormItem,
  Input,
  Button,
  notification,
  Textarea,
  Select,
  Switch,
  Descriptions,
  DescriptionsItem,
  Divider,
  Tag,
  Modal,
  Empty,
} from 'ant-design-vue';

import { type Zone, type ZoneKind, type ZoneTemplate } from '../../api/services';
import { $t } from 'shell/locales';
import { useDnsZoneStore } from '../../stores/dns-zone.state';
import { useDnsTemplateStore } from '../../stores/dns-template.state';

const zoneStore = useDnsZoneStore();
const templateStore = useDnsTemplateStore();

const data = ref<{
  mode: 'create' | 'edit' | 'view';
  row?: Zone;
}>();
const loading = ref(false);
const templates = ref<Array<{ value: string; label: string }>>([]);

const exportVisible = ref(false);
const exportContent = ref('');

const kindOptions = computed(() => [
  { value: 'ZONE_KIND_NATIVE', label: $t('dns.enum.zoneKind.native') },
  { value: 'ZONE_KIND_MASTER', label: $t('dns.enum.zoneKind.master') },
  { value: 'ZONE_KIND_SLAVE', label: $t('dns.enum.zoneKind.slave') },
  { value: 'ZONE_KIND_PRODUCER', label: $t('dns.enum.zoneKind.producer') },
  { value: 'ZONE_KIND_CONSUMER', label: $t('dns.enum.zoneKind.consumer') },
]);

const formState = ref<{
  name: string;
  kind: ZoneKind;
  nameservers: string;
  masters: string;
  description: string;
  templateId?: string;
  dnssecEnabled: boolean;
}>({
  name: '',
  kind: 'ZONE_KIND_NATIVE',
  nameservers: '',
  masters: '',
  description: '',
  templateId: undefined,
  dnssecEnabled: false,
});

const title = computed(() => {
  switch (data.value?.mode) {
    case 'create':
      return $t('dns.page.zone.create');
    case 'edit':
      return $t('dns.page.zone.edit');
    default:
      return $t('dns.page.zone.view');
  }
});

const isCreateMode = computed(() => data.value?.mode === 'create');
const isEditMode = computed(() => data.value?.mode === 'edit');
const isViewMode = computed(() => data.value?.mode === 'view');

const isSlaveKind = computed(() => formState.value.kind === 'ZONE_KIND_SLAVE');

function kindToColor(kind: string | undefined) {
  switch (kind) {
    case 'ZONE_KIND_NATIVE':
      return '#1890FF';
    case 'ZONE_KIND_MASTER':
      return '#52C41A';
    case 'ZONE_KIND_SLAVE':
      return '#FAAD14';
    case 'ZONE_KIND_PRODUCER':
      return '#722ED1';
    case 'ZONE_KIND_CONSUMER':
      return '#13C2C2';
    default:
      return '#C9CDD4';
  }
}

function kindToName(kind: string | undefined) {
  const option = kindOptions.value.find((o) => o.value === kind);
  return option?.label ?? kind ?? '';
}

function formatDateTime(value: string | undefined) {
  if (!value) return '-';
  try {
    return new Date(value).toLocaleString();
  } catch {
    return value;
  }
}

async function loadTemplates() {
  try {
    const resp = await templateStore.listTemplates({ page: 1, pageSize: 100 });
    templates.value = (resp.templates ?? []).map((t: ZoneTemplate) => ({
      value: t.id ?? '',
      label: t.name ?? '',
    }));
  } catch (e) {
    console.error('Failed to load templates:', e);
  }
}

function parseList(value: string): string[] | undefined {
  const items = value
    .split(',')
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
  return items.length > 0 ? items : undefined;
}

async function handleSubmit() {
  loading.value = true;
  try {
    if (isCreateMode.value) {
      await zoneStore.createZone({
        name: formState.value.name,
        kind: formState.value.kind,
        nameservers: parseList(formState.value.nameservers),
        masters: formState.value.masters || undefined,
        description: formState.value.description || undefined,
        templateId: formState.value.templateId,
        dnssecEnabled: formState.value.dnssecEnabled,
      });
      notification.success({ message: $t('dns.page.zone.createSuccess') });
    } else if (isEditMode.value && data.value?.row?.id) {
      await zoneStore.updateZone(data.value.row.id, {
        kind: formState.value.kind,
        masters: formState.value.masters || undefined,
        description: formState.value.description || undefined,
        dnssecEnabled: formState.value.dnssecEnabled,
      });
      notification.success({ message: $t('dns.page.zone.updateSuccess') });
    }
    drawerApi.close();
  } catch (e) {
    console.error('Failed to save zone:', e);
    notification.error({
      message: isCreateMode.value
        ? $t('ui.notification.create_failed')
        : $t('ui.notification.update_failed'),
    });
  } finally {
    loading.value = false;
  }
}

async function handleExport() {
  if (!data.value?.row?.id) return;
  try {
    const resp = await zoneStore.exportZone(data.value.row.id);
    exportContent.value = resp.bindZone ?? '';
    exportVisible.value = true;
  } catch {
    notification.error({ message: $t('ui.notification.failed') });
  }
}

async function handleNotify() {
  if (!data.value?.row?.id) return;
  try {
    await zoneStore.notifyZone(data.value.row.id);
    notification.success({ message: $t('dns.page.zone.notifySuccess') });
  } catch {
    notification.error({ message: $t('ui.notification.failed') });
  }
}

function resetForm() {
  formState.value = {
    name: '',
    kind: 'ZONE_KIND_NATIVE',
    nameservers: '',
    masters: '',
    description: '',
    templateId: undefined,
    dnssecEnabled: false,
  };
}

const [Drawer, drawerApi] = useVbenDrawer({
  onCancel() {
    drawerApi.close();
  },

  async onOpenChange(isOpen) {
    if (isOpen) {
      data.value = drawerApi.getData() as {
        mode: 'create' | 'edit' | 'view';
        row?: Zone;
      };

      await loadTemplates();

      if (data.value?.mode === 'create') {
        resetForm();
      } else if (data.value?.row) {
        formState.value = {
          name: data.value.row.name ?? '',
          kind: data.value.row.kind ?? 'ZONE_KIND_NATIVE',
          nameservers: '',
          masters: data.value.row.masters ?? '',
          description: data.value.row.description ?? '',
          templateId: data.value.row.templateId,
          dnssecEnabled: data.value.row.dnssecEnabled ?? false,
        };
      }
    }
  },
});

const zone = computed(() => data.value?.row);
</script>

<template>
  <Drawer :title="title" :footer="false">
    <!-- View Mode -->
    <template v-if="zone && isViewMode">
      <Descriptions :column="1" bordered size="small">
        <DescriptionsItem :label="$t('dns.page.zone.name')">
          <code class="bg-muted rounded px-1.5 py-0.5 font-mono">{{ zone.name }}</code>
        </DescriptionsItem>
        <DescriptionsItem :label="$t('dns.page.zone.kind')">
          <Tag :color="kindToColor(zone.kind)">{{ kindToName(zone.kind) }}</Tag>
        </DescriptionsItem>
        <DescriptionsItem :label="$t('dns.page.zone.pdnsId')">
          {{ zone.pdnsId || '-' }}
        </DescriptionsItem>
        <DescriptionsItem :label="$t('dns.page.zone.serial')">
          {{ zone.serial ?? '-' }}
        </DescriptionsItem>
        <DescriptionsItem :label="$t('dns.page.zone.masters')">
          {{ zone.masters || '-' }}
        </DescriptionsItem>
        <DescriptionsItem :label="$t('dns.page.zone.dnssecEnabled')">
          <Tag :color="zone.dnssecEnabled ? 'success' : 'default'">
            {{ zone.dnssecEnabled ? $t('ui.button.yes') : $t('ui.button.no') }}
          </Tag>
        </DescriptionsItem>
        <DescriptionsItem :label="$t('dns.page.zone.description')">
          {{ zone.description || '-' }}
        </DescriptionsItem>
      </Descriptions>

      <Divider>{{ $t('ui.table.timestamps') }}</Divider>
      <Descriptions :column="1" bordered size="small">
        <DescriptionsItem :label="$t('ui.table.createdAt')">
          {{ formatDateTime(zone.createTime) }}
        </DescriptionsItem>
        <DescriptionsItem :label="$t('ui.table.updatedAt')">
          {{ formatDateTime(zone.updateTime) }}
        </DescriptionsItem>
      </Descriptions>

      <div class="mt-4 flex gap-2">
        <Button @click="handleExport">{{ $t('dns.page.zone.export') }}</Button>
        <Button
          v-if="zone.kind === 'ZONE_KIND_MASTER'"
          @click="handleNotify"
        >
          {{ $t('dns.page.zone.notify') }}
        </Button>
      </div>
    </template>

    <!-- Create/Edit Mode -->
    <template v-else-if="isCreateMode || isEditMode">
      <Form layout="vertical" :model="formState" @finish="handleSubmit">
        <FormItem
          :label="$t('dns.page.zone.name')"
          name="name"
          :rules="[{ required: true, message: $t('ui.formRules.required') }]"
        >
          <Input
            v-model:value="formState.name"
            placeholder="example.com."
            :maxlength="255"
            :disabled="isEditMode"
          />
        </FormItem>

        <FormItem
          :label="$t('dns.page.zone.kind')"
          name="kind"
          :rules="[{ required: true, message: $t('ui.formRules.required') }]"
        >
          <Select v-model:value="formState.kind" :options="kindOptions" />
        </FormItem>

        <FormItem
          v-if="isCreateMode"
          :label="$t('dns.page.zone.nameservers')"
          name="nameservers"
        >
          <Input
            v-model:value="formState.nameservers"
            :placeholder="$t('dns.page.zone.nameserversPlaceholder')"
            :maxlength="1024"
          />
          <div class="text-muted-foreground mt-1 text-xs">
            {{ $t('dns.page.zone.nameserversHelp') }}
          </div>
        </FormItem>

        <FormItem
          v-if="isSlaveKind"
          :label="$t('dns.page.zone.masters')"
          name="masters"
        >
          <Input
            v-model:value="formState.masters"
            :placeholder="$t('dns.page.zone.mastersPlaceholder')"
            :maxlength="1024"
          />
          <div class="text-muted-foreground mt-1 text-xs">
            {{ $t('dns.page.zone.mastersHelp') }}
          </div>
        </FormItem>

        <FormItem
          v-if="isCreateMode"
          :label="$t('dns.page.zone.template')"
          name="templateId"
        >
          <Select
            v-model:value="formState.templateId"
            :options="templates"
            :placeholder="$t('dns.page.zone.templateNone')"
            allow-clear
            show-search
            :filter-option="(input: string, option: any) =>
              option.label.toLowerCase().includes(input.toLowerCase())"
          />
        </FormItem>

        <FormItem :label="$t('dns.page.zone.dnssecEnabled')" name="dnssecEnabled">
          <Switch v-model:checked="formState.dnssecEnabled" />
        </FormItem>

        <FormItem :label="$t('dns.page.zone.description')" name="description">
          <Textarea
            v-model:value="formState.description"
            :rows="3"
            :maxlength="1024"
            :placeholder="$t('ui.placeholder.input')"
          />
        </FormItem>

        <FormItem>
          <Button type="primary" html-type="submit" :loading="loading" block>
            {{ isCreateMode ? $t('ui.button.create', { moduleName: '' }) : $t('ui.button.save') }}
          </Button>
        </FormItem>
      </Form>
    </template>

    <!-- Export Modal -->
    <Modal
      v-model:open="exportVisible"
      :title="$t('dns.page.zone.exportTitle')"
      :footer="null"
      width="700px"
    >
      <pre
        v-if="exportContent"
        class="bg-muted max-h-96 overflow-auto rounded p-3 font-mono text-xs"
      >{{ exportContent }}</pre>
      <Empty v-else :description="$t('dns.page.zone.noBindData')" />
    </Modal>
  </Drawer>
</template>
