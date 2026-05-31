<script lang="ts" setup>
import type { VxeGridProps } from 'shell/adapter/vxe-table';

import { h, computed } from 'vue';
import { useRouter } from 'vue-router';

import { Page, useVbenDrawer, type VbenFormProps } from 'shell/vben/common-ui';
import {
  LucideFileText,
  LucideTrash,
  LucidePencil,
} from 'shell/vben/icons';

import { notification, Space, Button, Tag } from 'ant-design-vue';

import { useVbenVxeGrid } from 'shell/adapter/vxe-table';
import { type Zone, type ZoneKind } from '../../api/services';
import { $t } from 'shell/locales';
import { useDnsZoneStore } from '../../stores/dns-zone.state';

import ZoneDrawer from './zone-drawer.vue';

const router = useRouter();
const zoneStore = useDnsZoneStore();

const kindOptions = computed(() => [
  { value: 'ZONE_KIND_NATIVE', label: $t('dns.enum.zoneKind.native') },
  { value: 'ZONE_KIND_MASTER', label: $t('dns.enum.zoneKind.master') },
  { value: 'ZONE_KIND_SLAVE', label: $t('dns.enum.zoneKind.slave') },
  { value: 'ZONE_KIND_PRODUCER', label: $t('dns.enum.zoneKind.producer') },
  { value: 'ZONE_KIND_CONSUMER', label: $t('dns.enum.zoneKind.consumer') },
]);

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

function goToRecords(row: Zone) {
  if (!row.id) return;
  router.push(`/dns/zones/${row.id}`);
}

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
    {
      component: 'Select',
      fieldName: 'kind',
      label: $t('dns.page.zone.kind'),
      componentProps: {
        options: kindOptions,
        placeholder: $t('ui.placeholder.select'),
        allowClear: true,
      },
    },
  ],
};

const gridOptions: VxeGridProps<Zone> = {
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
      query: async ({ page }, formValues) => {
        const resp = await zoneStore.listZones(
          { page: page.currentPage, pageSize: page.pageSize },
          {
            search: formValues?.search,
            kind: formValues?.kind as ZoneKind | undefined,
          },
        );
        return {
          items: resp.zones ?? [],
          total: resp.total ?? 0,
        };
      },
    },
  },

  columns: [
    { title: $t('ui.table.seq'), type: 'seq', width: 50 },
    {
      title: $t('dns.page.zone.name'),
      field: 'name',
      minWidth: 240,
      slots: { default: 'name' },
    },
    {
      title: $t('dns.page.zone.kind'),
      field: 'kind',
      width: 120,
      slots: { default: 'kind' },
    },
    {
      title: $t('dns.page.zone.dnssecEnabled'),
      field: 'dnssecEnabled',
      width: 140,
      slots: { default: 'dnssec' },
    },
    { title: $t('dns.page.zone.description'), field: 'description', minWidth: 200 },
    {
      title: $t('ui.table.action'),
      field: 'action',
      fixed: 'right',
      slots: { default: 'action' },
      width: 220,
    },
  ],
};

const [Grid, gridApi] = useVbenVxeGrid({ gridOptions, formOptions });

const [ZoneDrawerComponent, zoneDrawerApi] = useVbenDrawer({
  connectedComponent: ZoneDrawer,
  onOpenChange(isOpen: boolean) {
    if (!isOpen) {
      gridApi.query();
    }
  },
});

function openDrawer(row: Zone, mode: 'create' | 'edit' | 'view') {
  zoneDrawerApi.setData({ row, mode });
  zoneDrawerApi.open();
}

function handleEdit(row: Zone) {
  openDrawer(row, 'edit');
}

function handleCreate() {
  openDrawer({} as Zone, 'create');
}

async function handleDelete(row: Zone) {
  if (!row.id) return;
  try {
    await zoneStore.deleteZone(row.id);
    notification.success({ message: $t('dns.page.zone.deleteSuccess') });
    await gridApi.query();
  } catch {
    notification.error({ message: $t('ui.notification.delete_failed') });
  }
}
</script>

<template>
  <Page auto-content-height>
    <Grid :table-title="$t('dns.page.zone.title')">
      <template #toolbar-tools>
        <Button class="mr-2" type="primary" @click="handleCreate">
          {{ $t('dns.page.zone.addZone') }}
        </Button>
      </template>
      <template #name="{ row }">
        <a class="font-mono text-primary hover:underline" @click.stop="goToRecords(row)">
          {{ row.name }}
        </a>
      </template>
      <template #kind="{ row }">
        <Tag :color="kindToColor(row.kind)">
          {{ kindToName(row.kind) }}
        </Tag>
      </template>
      <template #dnssec="{ row }">
        <Tag :color="row.dnssecEnabled ? 'success' : 'default'">
          {{ row.dnssecEnabled ? $t('ui.button.yes') : $t('ui.button.no') }}
        </Tag>
      </template>
      <template #action="{ row }">
        <Space>
          <Button
            type="link"
            size="small"
            @click.stop="goToRecords(row)"
          >
            <span style="display: inline-flex; align-items: center; gap: 4px">
              <component :is="LucideFileText" class="size-4" />
              {{ $t('dns.page.zone.manageRecords') }}
            </span>
          </Button>
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
            :title="$t('dns.page.zone.confirmDelete')"
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

    <ZoneDrawerComponent />
  </Page>
</template>
