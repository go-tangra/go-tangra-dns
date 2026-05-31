<script lang="ts" setup>
import type { VxeGridProps } from 'shell/adapter/vxe-table';

import { h } from 'vue';

import { Page, useVbenDrawer, type VbenFormProps } from 'shell/vben/common-ui';
import {
  LucideEye,
  LucideTrash,
  LucidePencil,
} from 'shell/vben/icons';

import { notification, Space, Button, Tag } from 'ant-design-vue';

import { useVbenVxeGrid } from 'shell/adapter/vxe-table';
import { type ZoneTemplate } from '../../api/services';
import { $t } from 'shell/locales';
import { useDnsTemplateStore } from '../../stores/dns-template.state';

import TemplateDrawer from './template-drawer.vue';

const templateStore = useDnsTemplateStore();

const formOptions: VbenFormProps = {
  collapsed: false,
  showCollapseButton: false,
  submitOnEnter: true,
  schema: [
    {
      component: 'Input',
      fieldName: 'search',
      label: $t('ui.table.search'),
      componentProps: {
        placeholder: $t('ui.placeholder.input'),
        allowClear: true,
      },
    },
  ],
};

const gridOptions: VxeGridProps<ZoneTemplate> = {
  height: 'auto',
  stripe: false,
  toolbarConfig: {
    custom: true,
    export: true,
    import: false,
    refresh: true,
    zoom: true,
  },
  exportConfig: {},
  rowConfig: {
    isHover: true,
  },
  pagerConfig: {
    enabled: true,
    pageSize: 20,
    pageSizes: [10, 20, 50, 100],
  },

  proxyConfig: {
    ajax: {
      query: async ({ page }) => {
        const resp = await templateStore.listTemplates({
          page: page.currentPage,
          pageSize: page.pageSize,
        });
        return {
          items: resp.templates ?? [],
          total: resp.total ?? 0,
        };
      },
    },
  },

  columns: [
    { title: $t('ui.table.seq'), type: 'seq', width: 50 },
    { title: $t('dns.page.template.name'), field: 'name', minWidth: 180 },
    {
      title: $t('dns.page.template.records'),
      field: 'records',
      width: 120,
      slots: { default: 'records' },
    },
    { title: $t('dns.page.template.description'), field: 'description', minWidth: 250 },
    {
      title: $t('ui.table.action'),
      field: 'action',
      fixed: 'right',
      slots: { default: 'action' },
      width: 150,
    },
  ],
};

const [Grid, gridApi] = useVbenVxeGrid({ gridOptions, formOptions });

const [TemplateDrawerComponent, templateDrawerApi] = useVbenDrawer({
  connectedComponent: TemplateDrawer,
  onOpenChange(isOpen: boolean) {
    if (!isOpen) {
      gridApi.query();
    }
  },
});

function openDrawer(row: ZoneTemplate, mode: 'create' | 'edit' | 'view') {
  templateDrawerApi.setData({ row, mode });
  templateDrawerApi.open();
}

function handleView(row: ZoneTemplate) {
  openDrawer(row, 'view');
}

function handleEdit(row: ZoneTemplate) {
  openDrawer(row, 'edit');
}

function handleCreate() {
  openDrawer({} as ZoneTemplate, 'create');
}

async function handleDelete(row: ZoneTemplate) {
  if (!row.id) return;
  try {
    await templateStore.deleteTemplate(row.id);
    notification.success({ message: $t('dns.page.template.deleteSuccess') });
    await gridApi.query();
  } catch {
    notification.error({ message: $t('ui.notification.delete_failed') });
  }
}
</script>

<template>
  <Page auto-content-height>
    <Grid :table-title="$t('dns.page.template.title')">
      <template #toolbar-tools>
        <Button class="mr-2" type="primary" @click="handleCreate">
          {{ $t('dns.page.template.create') }}
        </Button>
      </template>
      <template #records="{ row }">
        <Tag>{{ (row.records || []).length }}</Tag>
      </template>
      <template #action="{ row }">
        <Space>
          <Button
            type="link"
            size="small"
            :icon="h(LucideEye)"
            :title="$t('ui.button.view')"
            @click.stop="handleView(row)"
          />
          <Button
            type="link"
            size="small"
            :icon="h(LucidePencil)"
            :title="$t('ui.button.edit')"
            @click.stop="handleEdit(row)"
          />
          <a-popconfirm
            :cancel-text="$t('ui.button.cancel')"
            :ok-text="$t('ui.button.ok')"
            :title="$t('dns.page.template.confirmDelete')"
            @confirm="handleDelete(row)"
          >
            <Button
              danger
              type="link"
              size="small"
              :icon="h(LucideTrash)"
              :title="$t('ui.button.delete', { moduleName: '' })"
            />
          </a-popconfirm>
        </Space>
      </template>
    </Grid>

    <TemplateDrawerComponent />
  </Page>
</template>
