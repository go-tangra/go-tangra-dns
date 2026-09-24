import { beforeEach, describe, expect, it } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import { flushPromises, mount } from '@vue/test-utils'
import Configuration from '@/views/configuration/index.vue'
import { configSchema, networkOk, upstreamOk, ipLiteral } from '@/schemas'
import { abilities, fetchMock, makeRouter, reply, type } from './helpers'

const cfg = (over: Record<string, unknown> = {}) => ({
  recursor: { listen_addresses: ['0.0.0.0', '::'], port: 53, allowed_networks: ['10.0.0.0/8'], upstream_resolvers: [], dnssec_validation: 'off', allow_open_resolver: false },
  authoritative: { listen_addresses: ['0.0.0.0'], port: 53, transfer_peers: [] },
  defaults: true,
  restarter: { enabled: true, containers: { auth: 'freya-pdns-auth', recursor: 'freya-pdns-recursor' } },
  ...over,
})

const formValues = {
  recursor_listen: '0.0.0.0, ::',
  recursor_port: 53,
  recursor_allowed: '10.0.0.0/8',
  recursor_upstreams: '9.9.9.9, [2620:fe::fe]:53',
  dnssec_validation: 'process',
  allow_open_resolver: false,
  auth_listen: '0.0.0.0',
  auth_port: 5353,
  auth_peers: '',
}

describe('config schema', () => {
  it('validates addresses, networks, upstreams, ports and the open-resolver guard', () => {
    expect(ipLiteral('192.0.2.1') && ipLiteral('2001:db8::1') && !ipLiteral('host') && !ipLiteral('300.1.1.1')).toBe(true)
    expect(networkOk('10.0.0.0/8') && networkOk('2001:db8::/32') && networkOk('192.0.2.1') && !networkOk('10.0.0.0/33') && !networkOk('x/8')).toBe(true)
    expect(upstreamOk('9.9.9.9') && upstreamOk('1.1.1.1:5353') && upstreamOk('[2620:fe::fe]:53') && !upstreamOk('dns.google') && !upstreamOk('1.1.1.1:0')).toBe(true)
    const ok = configSchema.safeParse(formValues)
    expect(ok.success).toBe(true)
    if (ok.success) expect(ok.data.recursor_upstreams).toEqual(['9.9.9.9', '[2620:fe::fe]:53'])
    const paths = (v: Record<string, unknown>) => {
      const r = configSchema.safeParse(v)
      return r.success ? [] : r.error.issues.map((i) => String(i.path[0]))
    }
    expect(paths({ ...formValues, recursor_listen: '' })).toContain('recursor_listen')
    expect(paths({ ...formValues, recursor_port: 70000 })).toContain('recursor_port')
    expect(paths({ ...formValues, recursor_allowed: '0.0.0.0/0' })).toContain('recursor_allowed')
    expect(paths({ ...formValues, recursor_allowed: '0.0.0.0/0', allow_open_resolver: true })).toEqual([])
    expect(paths({ ...formValues, auth_peers: 'peer.example' })).toContain('auth_peers')
    expect(paths({ ...formValues, dnssec_validation: 'strict' })).toContain('dnssec_validation')
    expect(paths({ ...formValues, recursor_upstreams: Array.from({ length: 33 }, (_, i) => `10.0.0.${i + 1}`).join(',') })).toContain('recursor_upstreams')
  })
})

describe('configuration view', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    document.cookie = '__Host-csrf=tok; Secure; Path=/'
  })

  it('platform admin: shows the restart warning, saves and lists the restarted container', async () => {
    const calls = fetchMock((_url, init) => {
      if (init.method === 'PUT') {
        const body = JSON.parse(String(init.body))
        return { ...body, changed: ['recursor'], restarted: ['freya-pdns-recursor'], restart_required: [], errors: [] }
      }
      return cfg()
    })
    const w = mount(Configuration, { global: { plugins: [makeRouter(), abilities()] }, attachTo: document.body })
    await flushPromises()
    expect(w.find('[data-test=config-restart-warning]').text()).toContain('freya-pdns-recursor')
    expect(w.find('[data-test=config-defaults]').exists()).toBe(true)
    expect(w.find('[style]').exists()).toBe(false)
    // An open network is refused client-side until confirmed.
    type(w.find('[data-test=config-recursor-allowed] textarea').element, '0.0.0.0/0')
    await w.find('[data-test=config-save]').trigger('click')
    await flushPromises()
    expect(calls.some((c) => c.init.method === 'PUT')).toBe(false)
    type(w.find('[data-test=config-recursor-allowed] textarea').element, '10.20.0.0/16, 192.168.1.1')
    await w.find('[data-test=config-save]').trigger('click')
    await flushPromises()
    const put = calls.find((c) => c.init.method === 'PUT')!
    expect(put.url).toBe('/api/dns/v1/config')
    expect(JSON.parse(String(put.init.body))).toEqual({
      recursor: { listen_addresses: ['0.0.0.0', '::'], port: 53, allowed_networks: ['10.20.0.0/16', '192.168.1.1'], upstream_resolvers: [], dnssec_validation: 'off', allow_open_resolver: false },
      authoritative: { listen_addresses: ['0.0.0.0'], port: 53, transfer_peers: [] },
    })
    expect(w.find('[data-test="config-restarted-freya-pdns-recursor"]').exists()).toBe(true)
    expect(w.find('[data-test=config-result]').text()).toContain('Resolver')
    w.unmount()
  })

  it('reports restart_required when restarts are disabled, and server refusals', async () => {
    let fail = true
    fetchMock((_url, init) => {
      if (init.method === 'PUT') {
        if (fail) {
          fail = false
          return reply(422, { reason: 'invalid_config', detail: { field: 'recursor.listen_addresses[0]', message: 'must be an IP address literal' } })
        }
        const body = JSON.parse(String(init.body))
        return { ...body, changed: ['authoritative'], restarted: [], restart_required: ['freya-pdns-auth'], errors: [{ server: 'authoritative', reason: 'write_failed' }] }
      }
      return cfg({ defaults: false, restarter: { enabled: false, containers: { auth: 'freya-pdns-auth', recursor: 'freya-pdns-recursor' } } })
    })
    const w = mount(Configuration, { global: { plugins: [makeRouter(), abilities()] }, attachTo: document.body })
    await flushPromises()
    expect(w.find('[data-test=config-restart-disabled]').exists()).toBe(true)
    expect(w.find('[data-test=config-restart-warning]').exists()).toBe(false)
    await w.find('[data-test=config-save]').trigger('click')
    await flushPromises()
    expect(w.find('[data-test=config-save-error]').text()).toContain('must be an IP address literal')
    await w.find('[data-test=config-save]').trigger('click')
    await flushPromises()
    expect(w.find('[data-test=config-restart-required]').text()).toContain('freya-pdns-auth')
    expect(w.find('[data-test=config-result]').text()).toContain('could not be written')
    // The open-resolver switch shows the warning.
    await w.find('[data-test=config-open-resolver] input').setValue(true)
    await flushPromises()
    expect(w.find('[data-test=config-open-warning]').exists()).toBe(true)
    w.unmount()
  })

  it('non platform admins see a notice and nothing is requested', async () => {
    const calls = fetchMock(() => cfg())
    const w = mount(Configuration, { global: { plugins: [makeRouter(), abilities([{ action: 'read', subject: 'DnsZone' }])] }, attachTo: document.body })
    await flushPromises()
    expect(w.find('[data-test=config-admin-only]').exists()).toBe(true)
    expect(w.find('[data-test=config-save]').exists()).toBe(false)
    expect(calls.length).toBe(0)
    w.unmount()
    setActivePinia(createPinia())
    fetchMock(() => reply(403, { reason: 'forbidden' }))
    const w2 = mount(Configuration, { global: { plugins: [makeRouter(), abilities()] }, attachTo: document.body })
    await flushPromises()
    expect(w2.find('[data-test=config-error]').exists()).toBe(true)
    w2.unmount()
  })
})
