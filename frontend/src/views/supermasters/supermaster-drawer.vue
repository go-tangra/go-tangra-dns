<script lang="ts" setup>
import { ref, computed } from 'vue';

import { useVbenDrawer } from 'shell/vben/common-ui';

import {
  Form,
  FormItem,
  Input,
  Button,
  notification,
  Descriptions,
  DescriptionsItem,
  Divider,
} from 'ant-design-vue';

import { type Supermaster } from '../../api/services';
import { $t } from 'shell/locales';
import { useDnsSupermasterStore } from '../../stores/dns-supermaster.state';

const supermasterStore = useDnsSupermasterStore();

const data = ref<{
  mode: 'create' | 'edit' | 'view';
  row?: Supermaster;
}>();
const loading = ref(false);

const formState = ref<{
  ip: string;
  nameserver: string;
  account: string;
}>({
  ip: '',
  nameserver: '',
  account: '',
});

const title = computed(() => {
  switch (data.value?.mode) {
    case 'create':
      return $t('dns.page.supermaster.create');
    default:
      return $t('dns.page.supermaster.view');
  }
});

const isCreateMode = computed(() => data.value?.mode === 'create');
const isViewMode = computed(() => data.value?.mode === 'view');

function formatDateTime(value: string | undefined) {
  if (!value) return '-';
  try {
    return new Date(value).toLocaleString();
  } catch {
    return value;
  }
}

async function handleSubmit() {
  loading.value = true;
  try {
    await supermasterStore.createSupermaster({
      ip: formState.value.ip,
      nameserver: formState.value.nameserver,
      account: formState.value.account || undefined,
    });
    notification.success({ message: $t('dns.page.supermaster.createSuccess') });
    drawerApi.close();
  } catch (e) {
    console.error('Failed to save supermaster:', e);
    notification.error({ message: $t('ui.notification.create_failed') });
  } finally {
    loading.value = false;
  }
}

function resetForm() {
  formState.value = {
    ip: '',
    nameserver: '',
    account: '',
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
        row?: Supermaster;
      };

      if (data.value?.mode === 'create') {
        resetForm();
      } else if (data.value?.row) {
        formState.value = {
          ip: data.value.row.ip ?? '',
          nameserver: data.value.row.nameserver ?? '',
          account: data.value.row.account ?? '',
        };
      }
    }
  },
});

const supermaster = computed(() => data.value?.row);
</script>

<template>
  <Drawer :title="title" :footer="false">
    <!-- View Mode -->
    <template v-if="supermaster && isViewMode">
      <Descriptions :column="1" bordered size="small">
        <DescriptionsItem :label="$t('dns.page.supermaster.ip')">
          <code class="bg-muted rounded px-1.5 py-0.5 font-mono">{{ supermaster.ip }}</code>
        </DescriptionsItem>
        <DescriptionsItem :label="$t('dns.page.supermaster.nameserver')">
          <code class="bg-muted rounded px-1.5 py-0.5 font-mono">{{ supermaster.nameserver }}</code>
        </DescriptionsItem>
        <DescriptionsItem :label="$t('dns.page.supermaster.account')">
          {{ supermaster.account || '-' }}
        </DescriptionsItem>
      </Descriptions>

      <Divider>{{ $t('ui.table.timestamps') }}</Divider>
      <Descriptions :column="1" bordered size="small">
        <DescriptionsItem :label="$t('ui.table.createdAt')">
          {{ formatDateTime(supermaster.createTime) }}
        </DescriptionsItem>
      </Descriptions>
    </template>

    <!-- Create Mode -->
    <template v-else-if="isCreateMode">
      <Form layout="vertical" :model="formState" @finish="handleSubmit">
        <FormItem
          :label="$t('dns.page.supermaster.ip')"
          name="ip"
          :rules="[{ required: true, message: $t('ui.formRules.required') }]"
        >
          <Input
            v-model:value="formState.ip"
            placeholder="192.0.2.1"
            :maxlength="45"
          />
        </FormItem>

        <FormItem
          :label="$t('dns.page.supermaster.nameserver')"
          name="nameserver"
          :rules="[{ required: true, message: $t('ui.formRules.required') }]"
        >
          <Input
            v-model:value="formState.nameserver"
            placeholder="ns1.example.com."
            :maxlength="255"
          />
        </FormItem>

        <FormItem :label="$t('dns.page.supermaster.account')" name="account">
          <Input
            v-model:value="formState.account"
            :placeholder="$t('ui.placeholder.input')"
            :maxlength="255"
          />
        </FormItem>

        <FormItem>
          <Button type="primary" html-type="submit" :loading="loading" block>
            {{ $t('ui.button.create', { moduleName: '' }) }}
          </Button>
        </FormItem>
      </Form>
    </template>
  </Drawer>
</template>
