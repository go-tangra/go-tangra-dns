import { beforeEach, describe, expect, it } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import { flushPromises, mount } from '@vue/test-utils'
import { useConfirm } from '@freya/ui'
import Supermasters from '@/views/supermasters/index.vue'
import { supermasterSchema, ipOk } from '@/schemas'
import { abilities, clickButton, fetchMock, makeRouter, reply, type } from './helpers'

const sm = (id: string, ip: string) => ({ id, ip, nameserver: 'ns1.primary.example.', created_at: '2026-09-23T10:00:00Z' })

describe('supermaster schema', () => {
  it('ip literal and host name', () => {
    expect(supermasterSchema.safeParse({ ip: '192.0.2.53', nameserver: 'ns1.example.com' }).success).toBe(true)
    expect(supermasterSchema.safeParse({ ip: '2001:db8::53', nameserver: 'ns1.example.com.' }).success).toBe(true)
    for (const bad of ['ns.example.com', '300.1.1.1', '1::2::3', '']) expect(ipOk(bad), bad).toBe(false)
    expect(supermasterSchema.safeParse({ ip: '192.0.2.53', nameserver: 'ns1' }).success).toBe(false)
  })
})

describe('supermasters view', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    document.cookie = '__Host-csrf=tok; Secure; Path=/'
  })

  it('platform admin: lists, adds (drawer) and removes after confirmation', async () => {
    const calls = fetchMock((_url, init) => {
      if (init.method === 'POST') return sm('s2', '192.0.2.54')
      if (init.method === 'DELETE') return reply(204)
      return { items: [sm('s1', '192.0.2.53')] }
    })
    const w = mount(Supermasters, { global: { plugins: [makeRouter(), abilities()] }, attachTo: document.body })
    await flushPromises()
    expect(w.find('[data-test="supermaster-row-s1"]').text()).toContain('192.0.2.53')
    expect(w.find('[data-test=supermaster-admin-hint]').exists()).toBe(false)
    expect(w.find('[style]').exists()).toBe(false)
    await w.find('[data-test=supermaster-new]').trigger('click')
    await flushPromises()
    const drawer = document.body.querySelector('[data-test=supermaster-create]')!
    type(drawer.querySelector('input[data-field=ip]'), 'not-an-ip')
    type(drawer.querySelector('input[data-field=nameserver]'), 'ns1.primary.example')
    clickButton(drawer, 'Create')
    await flushPromises()
    expect(calls.some((c) => c.init.method === 'POST')).toBe(false)
    type(drawer.querySelector('input[data-field=ip]'), '192.0.2.54')
    clickButton(drawer, 'Create')
    await flushPromises()
    const post = calls.find((c) => c.init.method === 'POST')!
    expect(post.url).toBe('/api/dns/v1/supermasters')
    expect(JSON.parse(String(post.init.body))).toEqual({ ip: '192.0.2.54', nameserver: 'ns1.primary.example' })
    await w.find('[data-test=supermaster-delete-s1]').trigger('click')
    await flushPromises()
    expect(calls.some((c) => c.init.method === 'DELETE')).toBe(false)
    useConfirm().answer(true)
    await flushPromises()
    expect(calls.find((c) => c.init.method === 'DELETE')!.url).toBe('/api/dns/v1/supermasters/s1')
    expect(w.find('[data-test="supermaster-row-s1"]').exists()).toBe(false)
    w.unmount()
  })

  it('tenant admin: read-only list, no add/remove, a refusal is shown', async () => {
    fetchMock(() => ({ items: [sm('s1', '192.0.2.53')] }))
    const w = mount(Supermasters, { global: { plugins: [makeRouter(), abilities([{ action: 'read', subject: 'DnsSupermaster' }])] }, attachTo: document.body })
    await flushPromises()
    expect(w.find('[data-test=supermaster-new]').exists()).toBe(false)
    expect(w.find('[data-test=supermaster-delete-s1]').exists()).toBe(false)
    expect(w.find('[data-test=supermaster-admin-hint]').exists()).toBe(true)
    w.unmount()
    fetchMock(() => reply(403, { reason: 'forbidden' }))
    setActivePinia(createPinia())
    const w2 = mount(Supermasters, { global: { plugins: [makeRouter()] }, attachTo: document.body })
    await flushPromises()
    expect(w2.find('[data-test=supermaster-new]').exists()).toBe(false)
    expect(w2.text().length).toBeGreaterThan(0)
    w2.unmount()
  })
})
