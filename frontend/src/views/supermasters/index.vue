<script lang="ts" setup>
import type { VxeGridProps } from 'shell/adapter/vxe-table';

import { h } from 'vue';

import { Page, useVbenDrawer, type VbenFormProps } from 'shell/vben/common-ui';
import {
  LucideEye,
  LucideTrash,
} from 'shell/vben/icons';

import { notification, Space, Button } from 'ant-design-vue';

import { useVbenVxeGrid } from 'shell/adapter/vxe-table';
import { type Supermaster } from '../../api/services';
import { $t } from 'shell/locales';
import { useDnsSupermasterStore } from '../../stores/dns-supermaster.state';

import SupermasterDrawer from './supermaster-drawer.vue';

const supermasterStore = useDnsSupermasterStore();

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

const gridOptions: VxeGridProps<Supermaster> = {
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
        const resp = await supermasterStore.listSupermasters({
          page: page.currentPage,
          pageSize: page.pageSize,
        });
        return {
          items: resp.supermasters ?? [],
          total: resp.total ?? 0,
        };
      },
    },
  },

  columns: [
    { title: $t('ui.table.seq'), type: 'seq', width: 50 },
    {
      title: $t('dns.page.supermaster.ip'),
      field: 'ip',
      minWidth: 160,
      slots: { default: 'ip' },
    },
    {
      title: $t('dns.page.supermaster.nameserver'),
      field: 'nameserver',
      minWidth: 200,
      slots: { default: 'nameserver' },
    },
    { title: $t('dns.page.supermaster.account'), field: 'account', minWidth: 150 },
    {
      title: $t('ui.table.action'),
      field: 'action',
      fixed: 'right',
      slots: { default: 'action' },
      width: 120,
    },
  ],
};

const [Grid, gridApi] = useVbenVxeGrid({ gridOptions, formOptions });

const [SupermasterDrawerComponent, supermasterDrawerApi] = useVbenDrawer({
  connectedComponent: SupermasterDrawer,
  onOpenChange(isOpen: boolean) {
    if (!isOpen) {
      gridApi.query();
    }
  },
});

function handleView(row: Supermaster) {
  supermasterDrawerApi.setData({ row, mode: 'view' });
  supermasterDrawerApi.open();
}

function handleCreate() {
  supermasterDrawerApi.setData({ row: {}, mode: 'create' });
  supermasterDrawerApi.open();
}

async function handleDelete(row: Supermaster) {
  if (!row.id) return;
  try {
    await supermasterStore.deleteSupermaster(row.id);
    notification.success({ message: $t('dns.page.supermaster.deleteSuccess') });
    await gridApi.query();
  } catch {
    notification.error({ message: $t('ui.notification.delete_failed') });
  }
}
</script>

<template>
  <Page auto-content-height>
    <Grid :table-title="$t('dns.page.supermaster.title')">
      <template #toolbar-tools>
        <Button class="mr-2" type="primary" @click="handleCreate">
          {{ $t('dns.page.supermaster.create') }}
        </Button>
      </template>
      <template #ip="{ row }">
        <span class="font-mono">{{ row.ip }}</span>
      </template>
      <template #nameserver="{ row }">
        <span class="font-mono">{{ row.nameserver }}</span>
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
          <a-popconfirm
            :cancel-text="$t('ui.button.cancel')"
            :ok-text="$t('ui.button.ok')"
            :title="$t('dns.page.supermaster.confirmDelete')"
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

    <SupermasterDrawerComponent />
  </Page>
</template>
