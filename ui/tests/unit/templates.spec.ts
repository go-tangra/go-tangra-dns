import { beforeEach, describe, expect, it } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import { flushPromises, mount } from '@vue/test-utils'
import { useConfirm } from '@freya/ui'
import Templates from '@/views/templates/index.vue'
import { templateSchema, expandName, hasPriority } from '@/schemas'
import { abilities, fetchMock, makeRouter, reply, select, type } from './helpers'

const tpl = (id: string, name: string, records: unknown[] = []) => ({ id, name, description: 'd', records, created_at: '2026-09-23T10:00:00Z', updated_at: '2026-09-23T10:00:00Z' })

describe('template schema', () => {
  it('validates rows, priority only for MX/SRV, expands names for the hint', () => {
    const ok = templateSchema.safeParse({ name: ' Std ', records: [{ name: '@', type: 'MX', ttl: '3600', content: 'mail.[ZONE].', priority: '10' }] })
    expect(ok.success && ok.data.records[0]).toMatchObject({ name: '@', ttl: 3600, priority: 10 })
    expect(templateSchema.safeParse({ name: 'x', records: [{ name: '@', type: 'A', ttl: 3600, content: '192.0.2.1', priority: 5 }] }).success).toBe(false)
    expect(templateSchema.safeParse({ name: 'x', records: [{ name: '@', type: 'A', ttl: 30, content: '192.0.2.1' }] }).success).toBe(false)
    expect(templateSchema.safeParse({ name: '', records: [] }).success).toBe(false)
    expect(templateSchema.safeParse({ name: 'x', records: [{ name: '@', type: 'SOA', ttl: 3600, content: 'x' }] }).success).toBe(false)
    expect(expandName('@', 'example.com.')).toBe('example.com.')
    expect(expandName('www')).toBe('www.example.com.')
    expect(expandName('mail.[ZONE].', 'corp.test')).toBe('mail.corp.test.')
    expect(hasPriority('SRV') && !hasPriority('A')).toBe(true)
    for (let i = 0; i < 200; i++) {
      const s = Array.from({ length: Math.floor(Math.random() * 20) }, () => 'a@[ZONE]. \u0001é9'[Math.floor(Math.random() * 12)]).join('')
      expect(() => templateSchema.safeParse({ name: s, records: [{ name: s, type: 'TXT', ttl: s, content: s, priority: s }] })).not.toThrow()
    }
  })
})

describe('templates view', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    document.cookie = '__Host-csrf=tok; Secure; Path=/'
  })

  it('lists templates; creates one with record rows and a priority', async () => {
    const calls = fetchMock((_url, init) => (init.method === 'POST' ? tpl('t9', 'Std') : { items: [tpl('t1', 'Mail', [{ name: '@', type: 'MX', ttl: 3600, content: 'mail.[ZONE].', priority: 10 }])] }))
    const w = mount(Templates, { global: { plugins: [makeRouter(), abilities()] }, attachTo: document.body })
    await flushPromises()
    expect(w.find('[data-test="template-row-t1"]').text()).toContain('Mail')
    expect(w.find('[style]').exists()).toBe(false)
    await w.find('[data-test=template-new]').trigger('click')
    await flushPromises()
    const drawer = () => document.body.querySelector('[data-test=template-drawer]')!
    type(drawer().querySelector('#tpl-name'), 'Std')
    ;(drawer().querySelector('[data-test=tpl-add]') as HTMLButtonElement).click()
    await flushPromises()
    select(drawer().querySelector('#tpl-rec-type-0'), 'MX')
    await flushPromises()
    type(drawer().querySelector('#tpl-rec-content-0'), 'mail.[ZONE].')
    type(drawer().querySelector('#tpl-rec-prio-0'), '10')
    ;(drawer().querySelector('[data-test=tpl-add]') as HTMLButtonElement).click()
    await flushPromises()
    // the second row is left empty: nothing is posted
    ;(drawer().querySelector('[data-test=tpl-save]') as HTMLButtonElement).click()
    await flushPromises()
    expect(calls.some((c) => c.init.method === 'POST')).toBe(false)
    expect(drawer().textContent).toContain('A value is required.')
    ;(drawer().querySelector('[data-test=tpl-remove-1]') as HTMLButtonElement).click()
    await flushPromises()
    ;(drawer().querySelector('[data-test=tpl-save]') as HTMLButtonElement).click()
    await flushPromises()
    const post = calls.find((c) => c.init.method === 'POST')!
    expect(post.url).toBe('/api/dns/v1/templates')
    expect(JSON.parse(String(post.init.body))).toEqual({ name: 'Std', records: [{ name: '@', type: 'MX', ttl: 3600, content: 'mail.[ZONE].', priority: 10 }] })
    expect(document.body.querySelector('[data-test=template-drawer]')).toBeNull()
    w.unmount()
  })

  it('edits (PUT), shows a server refusal on the row, deletes after confirmation', async () => {
    let fail = true
    const calls = fetchMock((_url, init) => {
      if (init.method === 'PUT') {
        if (fail) {
          fail = false
          return reply(422, { reason: 'invalid_record', detail: { field: 'records[0].content', message: 'not an IPv4 address' } })
        }
        return tpl('t1', 'Web')
      }
      if (init.method === 'DELETE') return reply(204)
      return { items: [tpl('t1', 'Web', [{ name: 'www', type: 'A', ttl: 300, content: '192.0.2.1' }])] }
    })
    const w = mount(Templates, { global: { plugins: [makeRouter(), abilities()] }, attachTo: document.body })
    await flushPromises()
    await w.find('[data-test="template-row-t1"]').trigger('click')
    await flushPromises()
    const drawer = () => document.body.querySelector('[data-test=template-drawer]')!
    expect((drawer().querySelector('#tpl-rec-content-0') as HTMLInputElement).value).toBe('192.0.2.1')
    ;(drawer().querySelector('[data-test=tpl-save]') as HTMLButtonElement).click()
    await flushPromises()
    expect(drawer().textContent).toContain('not an IPv4 address')
    ;(drawer().querySelector('[data-test=tpl-save]') as HTMLButtonElement).click()
    await flushPromises()
    expect(calls.filter((c) => c.init.method === 'PUT').at(-1)!.url).toBe('/api/dns/v1/templates/t1')
    await w.find('[data-test="template-row-t1"]').trigger('click')
    await flushPromises()
    ;(drawer().querySelector('[data-test=tpl-delete]') as HTMLButtonElement).click()
    await flushPromises()
    expect(calls.some((c) => c.init.method === 'DELETE')).toBe(false)
    useConfirm().answer(true)
    await flushPromises()
    expect(calls.find((c) => c.init.method === 'DELETE')!.url).toBe('/api/dns/v1/templates/t1')
    w.unmount()
  })

  it('read-only without templates:manage', async () => {
    fetchMock(() => ({ items: [tpl('t1', 'Web', [{ name: 'www', type: 'A', ttl: 300, content: '192.0.2.1' }])] }))
    const w = mount(Templates, { global: { plugins: [makeRouter(), abilities([{ action: 'read', subject: 'DnsTemplate' }])] }, attachTo: document.body })
    await flushPromises()
    expect(w.find('[data-test=template-new]').exists()).toBe(false)
    await w.find('[data-test="template-row-t1"]').trigger('click')
    await flushPromises()
    const drawer = document.body.querySelector('[data-test=template-drawer]')!
    expect(drawer.querySelector('[data-test=tpl-save]')).toBeNull()
    expect((drawer.querySelector('#tpl-name') as HTMLInputElement).disabled).toBe(true)
    w.unmount()
  })
})
