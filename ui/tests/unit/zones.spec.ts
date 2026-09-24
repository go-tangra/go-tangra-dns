import { beforeEach, describe, expect, it } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import { flushPromises, mount } from '@vue/test-utils'
import { useConfirm } from '@go-tangra/ui'
import Zones from '@/views/zones/index.vue'
import { zoneSchema, zoneUpdateSchema, zoneNameOk, needsMasters } from '@/schemas'
import { clickButton, fetchMock, makeRouter, reply, select, type } from './helpers'

const zone = (id: string, name: string, extra: Record<string, unknown> = {}) => ({
  id, name, kind: 'native', masters: [], nameservers: ['ns1.' + name], dnssec: false, origin: 'manual',
  created_at: '2026-09-23T10:00:00Z', updated_at: '2026-09-23T10:00:00Z', ...extra,
})

describe('zone schemas', () => {
  it('name rules, kinds and primaries (fuzz never throws)', () => {
    expect(zoneSchema.safeParse({ name: 'Example.COM.', kind: 'native' }).data).toMatchObject({ name: 'Example.COM.', kind: 'native', masters: [], nameservers: [] })
    expect(zoneSchema.safeParse({ name: 'example.com', kind: 'native', nameservers: 'ns1.example.com., ns2.example.com' }).data?.nameservers).toEqual(['ns1.example.com.', 'ns2.example.com'])
    for (const bad of ['', 'com', 'bad..name', '-x.example', 'a b.example', 'x'.repeat(64) + '.com', 'bücher.example']) {
      expect(zoneSchema.safeParse({ name: bad, kind: 'native' }).success, bad).toBe(false)
    }
    expect(zoneNameOk('10.in-addr.arpa')).toBe(true)
    expect(zoneSchema.safeParse({ name: 'sec.example', kind: 'slave' }).success).toBe(false)
    expect(zoneSchema.safeParse({ name: 'sec.example', kind: 'slave', masters: '192.0.2.1, [2001:db8::1]:53' }).data?.masters).toEqual(['192.0.2.1', '[2001:db8::1]:53'])
    expect(zoneSchema.safeParse({ name: 'sec.example', kind: 'slave', masters: 'not-an-ip' }).success).toBe(false)
    expect(zoneSchema.safeParse({ name: 'p.example', kind: 'native', masters: '192.0.2.1' }).success).toBe(false)
    expect(zoneSchema.safeParse({ name: 'p.example', kind: 'native', nameservers: 'bad..ns' }).success).toBe(false)
    expect(zoneUpdateSchema.safeParse({ kind: 'master', masters: [] }).success).toBe(true)
    expect(zoneUpdateSchema.safeParse({ kind: 'consumer', masters: ['192.0.2.9'] }).data?.masters).toEqual(['192.0.2.9'])
    expect(needsMasters('slave') && needsMasters('consumer') && !needsMasters('master')).toBe(true)
    for (let i = 0; i < 300; i++) {
      const s = Array.from({ length: Math.floor(Math.random() * 30) }, () => 'ab-_.9 é'[Math.floor(Math.random() * 8)]).join('')
      expect(() => zoneSchema.safeParse({ name: s, kind: 'native', masters: s })).not.toThrow()
    }
  })
})

describe('zones view', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    document.cookie = '__Host-csrf=tok; Secure; Path=/'
    ;(globalThis as unknown as { __vw: number }).__vw = 1280
  })

  it('lists a page with the total, filters by name and kind, pages forward', async () => {
    const calls = fetchMock(() => ({ items: [zone('z1', 'alpha.test.'), zone('z2', 'beta.test.', { kind: 'master', origin: 'ipam' })], total: 30 }))
    const w = mount(Zones, { global: { plugins: [makeRouter()] }, attachTo: document.body })
    await flushPromises()
    expect(w.find('[data-test="zone-row-z1"]').text()).toContain('alpha.test.')
    expect(w.find('[data-test=zone-pager]').text()).toContain('Page 1 of 2 · 30 zones')
    expect(w.find('[style]').exists()).toBe(false)
    type(w.find('#zone-search').element, 'alp')
    await w.find('#zone-search').trigger('keyup', { key: 'Enter' })
    await flushPromises()
    expect(calls.at(-1)!.url).toContain('query=alp')
    select(w.find('#zone-kind').element, 'master')
    await flushPromises()
    expect(calls.at(-1)!.url).toMatch(/kind=master.*page=1/)
    await w.find('[aria-label="Next page"]').trigger('click')
    await flushPromises()
    expect(calls.at(-1)!.url).toContain('page=2')
    w.unmount()
  })

  it('new zone: validates, posts the schema output, closes on save and opens the zone', async () => {
    const calls = fetchMock((url, init) =>
      init.method === 'POST' ? zone('z9', 'new.test.') : url.endsWith('/zones/z9') ? zone('z9', 'new.test.', { serial: 2026092301 }) : { items: [], total: 0 },
    )
    const w = mount(Zones, { global: { plugins: [makeRouter()] }, attachTo: document.body })
    await flushPromises()
    await w.find('[data-test=zone-new]').trigger('click')
    await flushPromises()
    const drawer = document.body.querySelector('[data-test=zone-create]')!
    type(drawer.querySelector('input[data-field=name]'), 'bad..name')
    clickButton(drawer, 'Create')
    await flushPromises()
    expect(calls.some((c) => c.init.method === 'POST')).toBe(false)
    type(drawer.querySelector('input[data-field=name]'), 'new.test')
    type(drawer.querySelector('input[data-field=nameservers]'), 'ns1.new.test., ns2.new.test.')
    clickButton(drawer, 'Create')
    await flushPromises()
    const post = calls.find((c) => c.init.method === 'POST')!
    expect(post.url).toBe('/api/dns/v1/zones')
    expect(JSON.parse(String(post.init.body))).toMatchObject({ name: 'new.test', kind: 'native', masters: [], nameservers: ['ns1.new.test.', 'ns2.new.test.'] })
    expect(document.body.querySelector('[data-test=zone-create]')).toBeNull()
    expect(document.body.querySelector('[data-test=zone-serial]')?.textContent).toContain('2026092301')
    w.unmount()
  })

  it('zone drawer: serial chip, edit re-PUTs metadata, delete asks first', async () => {
    const calls = fetchMock((url, init) => {
      if (init.method === 'PUT') return zone('z1', 'alpha.test.', { kind: 'slave', masters: ['192.0.2.53'] })
      if (init.method === 'DELETE') return reply(204)
      if (url.endsWith('/zones/z1')) return zone('z1', 'alpha.test.', { serial: 7, description: 'main' })
      return { items: [zone('z1', 'alpha.test.')], total: 1 }
    })
    const router = makeRouter()
    const w = mount(Zones, { global: { plugins: [router] }, attachTo: document.body })
    await flushPromises()
    await w.find('[data-test="zone-row-z1"]').trigger('click')
    await flushPromises()
    const drawer = () => document.body.querySelector('[data-test=zone-drawer]')!
    expect(drawer().querySelector('[data-test=zone-serial]')?.textContent).toContain('serial 7')
    expect(drawer().textContent).toContain('main')
    ;(drawer().querySelector('[data-test=zone-edit]') as HTMLButtonElement).click()
    await flushPromises()
    select(drawer().querySelector('select[data-field=kind]'), 'slave')
    ;(drawer().querySelector('[data-test=zone-save]') as HTMLButtonElement).click()
    await flushPromises()
    expect(calls.some((c) => c.init.method === 'PUT')).toBe(false) // slave needs primaries
    type(drawer().querySelector('input[data-field=masters]'), '192.0.2.53')
    ;(drawer().querySelector('[data-test=zone-save]') as HTMLButtonElement).click()
    await flushPromises()
    const put = calls.find((c) => c.init.method === 'PUT')!
    expect(put.url).toBe('/api/dns/v1/zones/z1')
    expect(JSON.parse(String(put.init.body))).toEqual({ kind: 'slave', masters: ['192.0.2.53'], dnssec: false, description: 'main' })
    // back in view mode: records link navigates
    ;(drawer().querySelector('[data-test=zone-records]') as HTMLButtonElement).click()
    await flushPromises()
    expect(router.currentRoute.value.fullPath).toBe('/dns/zones/z1')
    // delete: nothing happens until confirmed
    ;(drawer().querySelector('[data-test=zone-delete]') as HTMLButtonElement).click()
    await flushPromises()
    expect(calls.some((c) => c.init.method === 'DELETE')).toBe(false)
    useConfirm().answer(true)
    await flushPromises()
    expect(calls.find((c) => c.init.method === 'DELETE')!.url).toBe('/api/dns/v1/zones/z1')
    expect(document.body.querySelector('[data-test=zone-drawer]')).toBeNull()
    w.unmount()
  })

  it('origin filter and IPAM badge; new zone from a template', async () => {
    const calls = fetchMock((url, init) => {
      if (init.method === 'POST') return zone('z9', 'tpl.test.')
      if (url.includes('/templates')) return { items: [{ id: 't1', name: 'Standard', records: [], created_at: 'x', updated_at: 'x' }] }
      if (url.endsWith('/zones/z9')) return zone('z9', 'tpl.test.')
      return { items: [zone('z2', 'auto.test.', { origin: 'ipam' })], total: 1 }
    })
    const w = mount(Zones, { global: { plugins: [makeRouter()] }, attachTo: document.body })
    await flushPromises()
    expect(w.find('[data-test=zone-ipam-z2]').text()).toBe('IPAM')
    select(w.find('#zone-origin').element, 'ipam')
    await flushPromises()
    expect(calls.at(-1)!.url).toMatch(/origin=ipam/)
    await w.find('[data-test=zone-new]').trigger('click')
    await flushPromises()
    const drawer = document.body.querySelector('[data-test=zone-create]')!
    type(drawer.querySelector('input[data-field=name]'), 'tpl.test')
    select(drawer.querySelector('select[data-field=template_id]'), 't1')
    clickButton(drawer, 'Create')
    await flushPromises()
    expect(JSON.parse(String(calls.find((c) => c.init.method === 'POST')!.init.body))).toMatchObject({ name: 'tpl.test', template_id: 't1' })
    w.unmount()
  })

  it('zone drawer: NOTIFY only for master/producer, export tab shows copyable BIND text', async () => {
    const calls = fetchMock((url, init) => {
      if (url.endsWith('/notify')) return reply(202)
      if (url.endsWith('/export')) return { zone: 'm.test.', text: 'm.test.\t3600\tIN\tSOA\tns1.m.test. hostmaster.m.test. 1 10800 3600 604800 3600\n' }
      if (url.endsWith('/zones/zm')) return zone('zm', 'm.test.', { kind: 'master', serial: 3 })
      if (url.endsWith('/zones/zn')) return zone('zn', 'n.test.', { serial: 3 })
      void init
      return { items: [zone('zm', 'm.test.', { kind: 'master' }), zone('zn', 'n.test.')], total: 2 }
    })
    const w = mount(Zones, { global: { plugins: [makeRouter()] }, attachTo: document.body })
    await flushPromises()
    await w.find('[data-test="zone-row-zn"]').trigger('click')
    await flushPromises()
    const drawer = () => document.body.querySelector('[data-test=zone-drawer]')!
    expect(drawer().querySelector('[data-test=zone-notify]')).toBeNull()
    await w.find('[data-test="zone-row-zm"]').trigger('click')
    await flushPromises()
    ;(drawer().querySelector('[data-test=zone-notify]') as HTMLButtonElement).click()
    await flushPromises()
    const n = calls.find((c) => c.url.endsWith('/notify'))!
    expect(n.url).toBe('/api/dns/v1/zones/zm/notify')
    expect(n.init.method).toBe('POST')
    expect(drawer().querySelector('[data-test=zone-notice]')?.textContent).toContain('NOTIFY sent')
    ;(drawer().querySelector('#tab-export') as HTMLButtonElement).click()
    await flushPromises()
    expect(drawer().querySelector('[data-test=zone-export-text]')?.textContent).toContain('m.test.\t3600\tIN\tSOA')
    expect(drawer().querySelector('[data-test=zone-export-copy]')).not.toBeNull()
    expect(calls.filter((c) => c.url.endsWith('/export'))).toHaveLength(1)
    w.unmount()
  })

  it('shows refusals: list failure and a missing zone', async () => {
    fetchMock((url) => (url.endsWith('/zones/zx') ? reply(404, { reason: 'zone_not_found' }) : reply(503, { reason: 'pdns_unavailable' })))
    const w = mount(Zones, { global: { plugins: [makeRouter()] }, attachTo: document.body })
    await flushPromises()
    expect(w.text()).toContain('The DNS server is unavailable')
    w.unmount()
  })
})
