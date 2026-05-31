<script lang="ts" setup>
import { ref, onMounted } from 'vue';

import { Page } from 'shell/vben/common-ui';

import {
  Alert,
  Button,
  Card,
  InputNumber,
  Spin,
  Switch,
  Textarea,
  notification,
} from 'ant-design-vue';

import {
  type RecursorConfig,
  type AuthConfig,
} from '../../api/services';
import { $t } from 'shell/locales';
import { useDnsConfigStore } from '../../stores/dns-config.state';

const configStore = useDnsConfigStore();

const loading = ref(false);
const saving = ref(false);

// Form state uses newline-joined text for the string-array fields.
const recursorForm = ref<{
  localAddress: string;
  localPort: number | undefined;
  allowFrom: string;
  upstreamResolvers: string;
  dnssecDisabled: boolean;
}>({
  localAddress: '',
  localPort: undefined,
  allowFrom: '',
  upstreamResolvers: '',
  dnssecDisabled: false,
});

const authForm = ref<{
  localAddress: string;
  localPort: number | undefined;
  allowAxfr: string;
}>({
  localAddress: '',
  localPort: undefined,
  allowAxfr: '',
});

// Array <-> newline-separated text helpers.
function linesToArray(text: string): string[] {
  return text
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.length > 0);
}

function arrayToLines(arr: string[] | undefined): string {
  return (arr ?? []).join('\n');
}

async function loadConfig() {
  loading.value = true;
  try {
    const resp = await configStore.getConfig();
    const recursor = resp.recursor ?? {};
    const auth = resp.authoritative ?? {};
    recursorForm.value = {
      localAddress: arrayToLines(recursor.localAddress),
      localPort: recursor.localPort,
      allowFrom: arrayToLines(recursor.allowFrom),
      upstreamResolvers: arrayToLines(recursor.upstreamResolvers),
      dnssecDisabled: recursor.dnssecDisabled ?? false,
    };
    authForm.value = {
      localAddress: arrayToLines(auth.localAddress),
      localPort: auth.localPort,
      allowAxfr: arrayToLines(auth.allowAxfr),
    };
  } catch (e) {
    console.error('Failed to load DNS config:', e);
    notification.error({ message: $t('ui.notification.failed') });
  } finally {
    loading.value = false;
  }
}

async function handleSave() {
  saving.value = true;
  try {
    const recursor: RecursorConfig = {
      localAddress: linesToArray(recursorForm.value.localAddress),
      localPort: recursorForm.value.localPort,
      allowFrom: linesToArray(recursorForm.value.allowFrom),
      upstreamResolvers: linesToArray(recursorForm.value.upstreamResolvers),
      dnssecDisabled: recursorForm.value.dnssecDisabled,
    };
    const authoritative: AuthConfig = {
      localAddress: linesToArray(authForm.value.localAddress),
      localPort: authForm.value.localPort,
      allowAxfr: linesToArray(authForm.value.allowAxfr),
    };
    const resp = await configStore.updateConfig({ recursor, authoritative });
    const restarted = resp.restarted ?? [];
    const message = restarted.length
      ? `${$t('dns.page.config.saveSuccess')} ${$t('dns.page.config.restarted')}: ${restarted.join(', ')}`
      : $t('dns.page.config.saveSuccess');
    notification.success({ message });
  } catch (e) {
    console.error('Failed to save DNS config:', e);
    notification.error({ message: $t('ui.notification.update_failed') });
  } finally {
    saving.value = false;
  }
}

onMounted(loadConfig);
</script>

<template>
  <Page auto-content-height>
    <Spin :spinning="loading">
      <div class="flex flex-col gap-4">
        <Alert
          type="info"
          show-icon
          :message="$t('dns.page.config.restartNote')"
        />

        <!-- Recursor -->
        <Card :title="$t('dns.page.config.recursorTitle')" size="small">
          <div class="flex flex-col gap-4">
            <div class="flex flex-col gap-1">
              <span class="text-sm font-medium">{{ $t('dns.page.config.localAddress') }}</span>
              <Textarea
                v-model:value="recursorForm.localAddress"
                :auto-size="{ minRows: 2, maxRows: 6 }"
                :placeholder="$t('dns.page.config.localAddressPlaceholder')"
                class="font-mono"
              />
              <span class="text-muted-foreground text-xs">
                {{ $t('dns.page.config.localAddressHelp') }}
              </span>
            </div>

            <div class="flex flex-col gap-1">
              <span class="text-sm font-medium">{{ $t('dns.page.config.localPort') }}</span>
              <InputNumber
                v-model:value="recursorForm.localPort"
                :min="1"
                :max="65535"
                style="width: 160px"
              />
              <span class="text-muted-foreground text-xs">
                {{ $t('dns.page.config.localPortHelp') }}
              </span>
            </div>

            <div class="flex flex-col gap-1">
              <span class="text-sm font-medium">{{ $t('dns.page.config.allowFrom') }}</span>
              <Textarea
                v-model:value="recursorForm.allowFrom"
                :auto-size="{ minRows: 2, maxRows: 6 }"
                :placeholder="$t('dns.page.config.allowFromPlaceholder')"
                class="font-mono"
              />
              <span class="text-muted-foreground text-xs">
                {{ $t('dns.page.config.allowFromHelp') }}
              </span>
            </div>

            <div class="flex flex-col gap-1">
              <span class="text-sm font-medium">{{ $t('dns.page.config.upstreamResolvers') }}</span>
              <Textarea
                v-model:value="recursorForm.upstreamResolvers"
                :auto-size="{ minRows: 2, maxRows: 6 }"
                :placeholder="$t('dns.page.config.upstreamResolversPlaceholder')"
                class="font-mono"
              />
              <span class="text-muted-foreground text-xs">
                {{ $t('dns.page.config.upstreamResolversHelp') }}
              </span>
            </div>

            <div class="flex flex-col gap-1">
              <div class="flex items-center gap-2">
                <Switch v-model:checked="recursorForm.dnssecDisabled" />
                <span class="text-sm font-medium">{{ $t('dns.page.config.dnssecDisabled') }}</span>
              </div>
              <span class="text-muted-foreground text-xs">
                {{ $t('dns.page.config.dnssecDisabledHelp') }}
              </span>
            </div>
          </div>
        </Card>

        <!-- Authoritative -->
        <Card :title="$t('dns.page.config.authTitle')" size="small">
          <div class="flex flex-col gap-4">
            <div class="flex flex-col gap-1">
              <span class="text-sm font-medium">{{ $t('dns.page.config.localAddress') }}</span>
              <Textarea
                v-model:value="authForm.localAddress"
                :auto-size="{ minRows: 2, maxRows: 6 }"
                :placeholder="$t('dns.page.config.localAddressPlaceholder')"
                class="font-mono"
              />
              <span class="text-muted-foreground text-xs">
                {{ $t('dns.page.config.localAddressHelp') }}
              </span>
            </div>

            <div class="flex flex-col gap-1">
              <span class="text-sm font-medium">{{ $t('dns.page.config.localPort') }}</span>
              <InputNumber
                v-model:value="authForm.localPort"
                :min="1"
                :max="65535"
                style="width: 160px"
              />
              <span class="text-muted-foreground text-xs">
                {{ $t('dns.page.config.localPortHelp') }}
              </span>
            </div>

            <div class="flex flex-col gap-1">
              <span class="text-sm font-medium">{{ $t('dns.page.config.allowAxfr') }}</span>
              <Textarea
                v-model:value="authForm.allowAxfr"
                :auto-size="{ minRows: 2, maxRows: 6 }"
                :placeholder="$t('dns.page.config.allowAxfrPlaceholder')"
                class="font-mono"
              />
              <span class="text-muted-foreground text-xs">
                {{ $t('dns.page.config.allowAxfrHelp') }}
              </span>
            </div>
          </div>
        </Card>

        <div>
          <Button type="primary" :loading="saving" @click="handleSave">
            {{ $t('ui.button.save') }}
          </Button>
        </div>
      </div>
    </Spin>
  </Page>
</template>
