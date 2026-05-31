<script lang="ts" setup>
import { ref, computed } from 'vue';

import { useVbenDrawer } from 'shell/vben/common-ui';
import { LucidePlus, LucideTrash } from 'shell/vben/icons';

import {
  Form,
  FormItem,
  Input,
  InputNumber,
  Button,
  notification,
  Textarea,
  Descriptions,
  DescriptionsItem,
  Divider,
  Table,
} from 'ant-design-vue';

import { type ZoneTemplate, type TemplateRecord } from '../../api/services';
import { $t } from 'shell/locales';
import { useDnsTemplateStore } from '../../stores/dns-template.state';

const templateStore = useDnsTemplateStore();

const data = ref<{
  mode: 'create' | 'edit' | 'view';
  row?: ZoneTemplate;
}>();
const loading = ref(false);

const formState = ref<{
  name: string;
  description: string;
  records: TemplateRecord[];
}>({
  name: '',
  description: '',
  records: [],
});

const title = computed(() => {
  switch (data.value?.mode) {
    case 'create':
      return $t('dns.page.template.create');
    case 'edit':
      return $t('dns.page.template.edit');
    default:
      return $t('dns.page.template.view');
  }
});

const isCreateMode = computed(() => data.value?.mode === 'create');
const isEditMode = computed(() => data.value?.mode === 'edit');
const isViewMode = computed(() => data.value?.mode === 'view');

const viewColumns = [
  { title: $t('dns.page.template.recordName'), dataIndex: 'name', key: 'name' },
  { title: $t('dns.page.template.recordType'), dataIndex: 'type', key: 'type' },
  { title: $t('dns.page.template.recordTtl'), dataIndex: 'ttl', key: 'ttl' },
  { title: $t('dns.page.template.recordContent'), dataIndex: 'content', key: 'content' },
  { title: $t('dns.page.template.recordPriority'), dataIndex: 'priority', key: 'priority' },
];

function addRecord() {
  formState.value.records.push({
    name: '[ZONE]',
    type: 'A',
    ttl: 3600,
    content: '',
    priority: 0,
  });
}

function removeRecord(index: number) {
  formState.value.records.splice(index, 1);
}

function cleanRecords(): TemplateRecord[] {
  return formState.value.records.map((r) => ({
    name: r.name,
    type: r.type,
    ttl: r.ttl,
    content: r.content,
    priority: r.priority,
  }));
}

async function handleSubmit() {
  loading.value = true;
  try {
    if (isCreateMode.value) {
      await templateStore.createTemplate({
        name: formState.value.name,
        description: formState.value.description || undefined,
        records: cleanRecords(),
      });
      notification.success({ message: $t('dns.page.template.createSuccess') });
    } else if (isEditMode.value && data.value?.row?.id) {
      await templateStore.updateTemplate(data.value.row.id, {
        name: formState.value.name,
        description: formState.value.description || undefined,
        records: cleanRecords(),
      });
      notification.success({ message: $t('dns.page.template.updateSuccess') });
    }
    drawerApi.close();
  } catch (e) {
    console.error('Failed to save template:', e);
    notification.error({
      message: isCreateMode.value
        ? $t('ui.notification.create_failed')
        : $t('ui.notification.update_failed'),
    });
  } finally {
    loading.value = false;
  }
}

function resetForm() {
  formState.value = {
    name: '',
    description: '',
    records: [],
  };
}

const [Drawer, drawerApi] = useVbenDrawer({
  onCancel() {
    drawerApi.close();
  },

  onOpenChange(isOpen) {
    if (isOpen) {
      data.value = drawerApi.getData() as {
        mode: 'create' | 'edit' | 'view';
        row?: ZoneTemplate;
      };

      if (data.value?.mode === 'create') {
        resetForm();
      } else if (data.value?.row) {
        formState.value = {
          name: data.value.row.name ?? '',
          description: data.value.row.description ?? '',
          records: (data.value.row.records ?? []).map((r) => ({ ...r })),
        };
      }
    }
  },
});

const template = computed(() => data.value?.row);
</script>

<template>
  <Drawer :title="title" :footer="false" class="w-[720px]">
    <!-- View Mode -->
    <template v-if="template && isViewMode">
      <Descriptions :column="1" bordered size="small">
        <DescriptionsItem :label="$t('dns.page.template.name')">
          {{ template.name || '-' }}
        </DescriptionsItem>
        <DescriptionsItem :label="$t('dns.page.template.description')">
          {{ template.description || '-' }}
        </DescriptionsItem>
      </Descriptions>

      <Divider>{{ $t('dns.page.template.records') }}</Divider>
      <Table
        :columns="viewColumns"
        :data-source="template.records || []"
        :pagination="false"
        size="small"
        row-key="name"
      />
    </template>

    <!-- Create/Edit Mode -->
    <template v-else-if="isCreateMode || isEditMode">
      <Form layout="vertical" :model="formState" @finish="handleSubmit">
        <FormItem
          :label="$t('dns.page.template.name')"
          name="name"
          :rules="[{ required: true, message: $t('ui.formRules.required') }]"
        >
          <Input
            v-model:value="formState.name"
            :placeholder="$t('ui.placeholder.input')"
            :maxlength="255"
          />
        </FormItem>

        <FormItem :label="$t('dns.page.template.description')" name="description">
          <Textarea
            v-model:value="formState.description"
            :rows="2"
            :maxlength="1024"
            :placeholder="$t('ui.placeholder.input')"
          />
        </FormItem>

        <Divider class="!my-3">{{ $t('dns.page.template.records') }}</Divider>
        <div class="text-muted-foreground mb-2 text-xs">
          {{ $t('dns.page.template.recordsHelp') }}
        </div>

        <div class="mb-3 flex flex-col gap-2">
          <div
            v-for="(rec, index) in formState.records"
            :key="index"
            class="flex items-center gap-2"
          >
            <Input
              v-model:value="rec.name"
              :placeholder="$t('dns.page.template.recordName')"
              style="width: 140px"
            />
            <Input
              v-model:value="rec.type"
              :placeholder="$t('dns.page.template.recordType')"
              style="width: 80px"
            />
            <InputNumber
              v-model:value="rec.ttl"
              :min="0"
              :placeholder="$t('dns.page.template.recordTtl')"
              style="width: 90px"
            />
            <Input
              v-model:value="rec.content"
              :placeholder="$t('dns.page.template.recordContent')"
              class="flex-1 font-mono"
            />
            <InputNumber
              v-model:value="rec.priority"
              :min="0"
              :placeholder="$t('dns.page.template.recordPriority')"
              style="width: 80px"
            />
            <Button type="text" danger size="small" @click="removeRecord(index)">
              <LucideTrash class="size-4" />
            </Button>
          </div>
        </div>

        <Button size="small" class="mb-4" @click="addRecord">
          <span style="display: inline-flex; align-items: center; gap: 4px">
            <LucidePlus class="size-4" />
            {{ $t('dns.page.template.addRecord') }}
          </span>
        </Button>

        <FormItem>
          <Button type="primary" html-type="submit" :loading="loading" block>
            {{ isCreateMode ? $t('ui.button.create', { moduleName: '' }) : $t('ui.button.save') }}
          </Button>
        </FormItem>
      </Form>
    </template>
  </Drawer>
</template>
