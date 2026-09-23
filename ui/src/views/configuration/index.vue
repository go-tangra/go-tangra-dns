<script setup lang="ts">
// DNS server configuration (platform administrators only): the resolver
// (listen addresses, port, allowed client networks, upstream resolvers,
// DNSSEC validation) and the authoritative server (listen addresses, port,
// zone-transfer peers). Saving renders the managed include files and restarts
// only the container whose configuration changed; the result lists what was
// restarted (or still needs a restart when restarts are disabled).
import { computed, inject, onMounted, ref, watch } from 'vue'
import { ABILITY_TOKEN } from '@casl/vue'
import type { AnyAbility } from '@casl/ability'
import { UiPage, UiAlert, UiCard, UiButton, UiBadge, UiForm, UiSection, UiTextarea, UiNumberInput, UiSelect, UiSwitch, UiSkeleton, type SelectOption } from '@freya/ui'
import { useZodForm } from '@freya/ui/forms'
import { useServerConfig } from '@/stores/config'
import { configSchema, DNSSEC_MODES, type ConfigFormOutput } from '@/schemas'
import type { ServerConfig, ServerConfigInput } from '@/api/types'
import { explain } from '@/api/client'

const store = useServerConfig()
const ability = inject<AnyAbility | null>(ABILITY_TOKEN, null)
const canManage = computed(() => ability?.can('manage', 'DnsConfig') ?? false)
onMounted(() => {
  if (canManage.value) void store.load()
})

const modeOptions: SelectOption[] = DNSSEC_MODES.map((m) => ({ title: m, value: m }))
const join = (v: string[] | undefined) => (v ?? []).join(', ')

function toForm(c: ServerConfig) {
  return {
    recursor_listen: join(c.recursor.listen_addresses),
    recursor_port: c.recursor.port,
    recursor_allowed: join(c.recursor.allowed_networks),
    recursor_upstreams: join(c.recursor.upstream_resolvers),
    dnssec_validation: c.recursor.dnssec_validation,
    allow_open_resolver: c.recursor.allow_open_resolver ?? false,
    auth_listen: join(c.authoritative.listen_addresses),
    auth_port: c.authoritative.port,
    auth_peers: join(c.authoritative.transfer_peers),
  }
}

function toInput(v: ConfigFormOutput): ServerConfigInput {
  return {
    recursor: {
      listen_addresses: v.recursor_listen,
      port: v.recursor_port,
      allowed_networks: v.recursor_allowed,
      upstream_resolvers: v.recursor_upstreams,
      dnssec_validation: v.dnssec_validation,
      allow_open_resolver: v.allow_open_resolver,
    },
    authoritative: { listen_addresses: v.auth_listen, port: v.auth_port, transfer_peers: v.auth_peers },
  }
}

// The server's explanation of a refusal (invalid_config names the field).
const saveError = ref('')
const form = useZodForm(configSchema, {
  onSubmit: async (v) => {
    saveError.value = ''
    try {
      return await store.save(toInput(v))
    } catch (e) {
      saveError.value = explain(e)
      throw e
    }
  },
})
watch(() => store.config, (c) => c && form.reset(toForm(c)), { immediate: true })

const restarter = computed(() => store.config?.restarter)
const containers = computed(() => [restarter.value?.containers.recursor, restarter.value?.containers.auth].filter(Boolean).join(' and '))
const openResolver = computed(() => form.values.allow_open_resolver === true)
const result = computed(() => store.last)
const serverLabel = (s: string | undefined) => (s === 'authoritative' ? 'Authoritative server' : 'Resolver')
const reasonLabel: Record<string, string> = {
  write_failed: 'the configuration file could not be written',
  restart_failed: 'the container could not be restarted',
  not_managed: 'its configuration file is not managed on this deployment',
}
</script>

<template>
  <UiPage title="Configuration" subtitle="Resolver and authoritative server settings">
    <template #actions>
      <UiButton v-if="canManage" variant="text" icon="mdi-refresh" icon-only label="Reload" @click="store.load()" />
    </template>
    <UiAlert v-if="!canManage" kind="info" data-test="config-admin-only">The DNS server configuration can only be changed by platform administrators.</UiAlert>
    <template v-else>
      <UiAlert v-if="store.error" kind="error" data-test="config-error">{{ store.error }}</UiAlert>
      <UiSkeleton v-if="store.loading && !store.config" />
      <template v-if="store.config">
        <UiAlert v-if="restarter?.enabled" kind="warning" title="Saving restarts DNS servers" data-test="config-restart-warning">
          Only the server whose configuration changed is restarted ({{ containers }}); it stops answering queries for a few seconds.
        </UiAlert>
        <UiAlert v-else kind="info" data-test="config-restart-disabled">
          Automatic restarts are disabled on this deployment: after saving, restart {{ containers || 'the DNS containers' }} to apply the changes.
        </UiAlert>
        <UiAlert v-if="store.config.defaults" kind="info" data-test="config-defaults">No configuration has been saved yet; the safe defaults are shown.</UiAlert>
        <UiAlert v-if="saveError" kind="error" data-test="config-save-error">{{ saveError }}</UiAlert>
        <div v-if="result" class="flex flex-col gap-2" data-test="config-result">
          <UiAlert v-if="result.changed.length === 0" kind="success">Saved. Nothing changed, so nothing was restarted.</UiAlert>
          <UiAlert v-else kind="success" title="Saved and applied">
            <span>Changed: {{ result.changed.map(serverLabel).join(', ') }}.</span>
            <span v-if="result.restarted.length" class="ms-1">Restarted:</span>
            <UiBadge v-for="c in result.restarted" :key="'r-' + c" color="success" class="ms-1" :data-test="'config-restarted-' + c">{{ c }}</UiBadge>
          </UiAlert>
          <UiAlert v-if="result.restart_required.length" kind="warning" data-test="config-restart-required">
            Restart required to apply: <UiBadge v-for="c in result.restart_required" :key="'q-' + c" color="warning" class="ms-1">{{ c }}</UiBadge>
          </UiAlert>
          <UiAlert v-for="e in result.errors" :key="(e.server ?? '') + (e.reason ?? '')" kind="error">
            {{ serverLabel(e.server) }}: {{ reasonLabel[e.reason ?? ''] ?? e.reason }}.
          </UiAlert>
        </div>
        <UiCard>
          <UiForm :form="form">
            <div class="flex flex-col gap-4">
              <UiSection title="Resolver" description="The recursive resolver clients query; managed zones are forwarded to the authoritative server.">
                <div class="grid grid-cols-1 gap-3 md:grid-cols-2">
                  <UiTextarea v-bind="form.field('recursor_listen')" label="Listen addresses" :rows="2" hint="IP addresses, comma- or line-separated." required data-test="config-recursor-listen" />
                  <UiNumberInput v-bind="form.field('recursor_port')" label="Port" :min="1" :max="65535" required data-test="config-recursor-port" />
                  <UiTextarea v-bind="form.field('recursor_allowed')" label="Allowed client networks" :rows="3" hint="CIDRs or IP addresses allowed to query the resolver." data-test="config-recursor-allowed" />
                  <UiTextarea v-bind="form.field('recursor_upstreams')" label="Upstream resolvers" :rows="3" hint="IP or IP:port; empty = full recursion from the root." data-test="config-recursor-upstreams" />
                  <UiSelect v-bind="form.field('dnssec_validation')" label="DNSSEC validation" :options="modeOptions" :clearable="false" required data-test="config-dnssec" />
                  <UiSwitch v-bind="form.field('allow_open_resolver')" label="Allow an open resolver" hint="Required to allow 0.0.0.0/0 or ::/0." data-test="config-open-resolver" />
                </div>
                <UiAlert v-if="openResolver" kind="error" class="mt-3" data-test="config-open-warning">
                  An open resolver answers anyone on the internet and can be abused for amplification attacks. Allow it only behind a firewall.
                </UiAlert>
              </UiSection>
              <UiSection title="Authoritative server" description="The server that answers for the managed zones.">
                <div class="grid grid-cols-1 gap-3 md:grid-cols-2">
                  <UiTextarea v-bind="form.field('auth_listen')" label="Listen addresses" :rows="2" hint="IP addresses, comma- or line-separated." required data-test="config-auth-listen" />
                  <UiNumberInput v-bind="form.field('auth_port')" label="Port" :min="1" :max="65535" required data-test="config-auth-port" />
                  <UiTextarea v-bind="form.field('auth_peers')" label="Zone-transfer peers" :rows="3" hint="CIDRs or IP addresses allowed to transfer zones (AXFR); empty = loopback only." data-test="config-auth-peers" />
                </div>
              </UiSection>
            </div>
          </UiForm>
          <div class="mt-4 flex justify-end gap-2">
            <UiButton variant="text" :disabled="!form.dirty.value" @click="store.config && form.reset(toForm(store.config))">Discard</UiButton>
            <UiButton icon="mdi-restart" :loading="form.submitting.value" data-test="config-save" @click="form.submit()">Save and apply</UiButton>
          </div>
        </UiCard>
      </template>
    </template>
  </UiPage>
</template>
