import { beforeEach, describe, expect, it } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import { flushPromises, mount } from '@vue/test-utils'
import { useConfirm } from '@freya/ui'
import Records from '@/views/zones/records.vue'
import { checkContent, recordSetSchema, relativeName, RECORD_HINTS, RECORD_TYPES } from '@/schemas'
import { fetchMock, makeRouter, reply, select, type, type Call } from './helpers'

const zone = { id: 'z1', name: 'example.test.', kind: 'native', masters: [], dnssec: false, origin: 'manual', serial: 12, created_at: '', updated_at: '' }
const sets = [
  { name: 'example.test.', type: 'SOA', ttl: 3600, values: [{ content: 'ns1.example.test. hostmaster.example.test. 12 10800 3600 604800 3600', disabled: false }], read_only: true },
  { name: 'www.example.test.', type: 'A', ttl: 300, values: [{ content: '192.0.2.10', disabled: false }, { content: '192.0.2.11', disabled: true }], comment: 'web', read_only: false },
  { name: 'odd.example.test.', type: 'TXT', ttl: 1234, values: [{ content: '"hello"', disabled: false }], read_only: false },
]

describe('record schemas', () => {
  it('per-type light checks, TTL bounds, CNAME rules (fuzz never throws)', () => {
    const ok: [string, string][] = [['A', '192.0.2.1'], ['AAAA', '2001:db8::1'], ['CNAME', 'x.example.'], ['MX', '10 mail.example.'], ['SRV', '0 5 5060 sip.example.'],
      ['CAA', '0 issue "letsencrypt.org"'], ['DS', '1 13 2 ABCDEF'], ['TLSA', '3 1 1 ABCD'], ['SSHFP', '4 2 ABCD'], ['DNSKEY', '257 3 13 AwEAAa=='], ['TXT', 'anything'], ['NAPTR', '100 10 "U" "E2U+sip" "" .']]
    for (const [t, v] of ok) expect(checkContent(t, v), t + ' ' + v).toBe('')
    const bad: [string, string][] = [['A', '999.1.1.1'], ['AAAA', '::ffff:192.0.2.1'], ['AAAA', '192.0.2.1'], ['CNAME', 'a b'], ['MX', 'mail.example.'], ['SRV', '1 2 sip.'],
      ['CAA', '5 issue "x"'], ['DS', '1 13 3 AB'], ['TLSA', '4 1 1 AB'], ['SSHFP', '9 1 AB'], ['DNSKEY', '1 3 8 k'], ['TXT', 'a\nb'], ['TXT', '$INCLUDE /etc/passwd'], ['A', '']]
    for (const [t, v] of bad) expect(checkContent(t, v), t + ' ' + v).not.toBe('')
    for (const t of RECORD_TYPES) expect(RECORD_HINTS[t].placeholder).toBeTruthy()
    expect(recordSetSchema.safeParse({ name: '', type: 'A', ttl: '300', values: [{ content: '192.0.2.1' }] }).data).toEqual({ name: '@', type: 'A', ttl: 300, values: [{ content: '192.0.2.1', disabled: false }] })
    expect(recordSetSchema.safeParse({ name: 'x', type: 'A', ttl: 30, values: [{ content: '192.0.2.1' }] }).success).toBe(false)
    expect(recordSetSchema.safeParse({ name: '@', type: 'CNAME', ttl: 300, values: [{ content: 'x.example.' }] }).success).toBe(false)
    expect(recordSetSchema.safeParse({ name: 'c', type: 'CNAME', ttl: 300, values: [{ content: 'a.' }, { content: 'b.' }] }).success).toBe(false)
    expect(recordSetSchema.safeParse({ name: 'a b', type: 'A', ttl: 300, values: [{ content: '192.0.2.1' }] }).success).toBe(false)
    expect(recordSetSchema.safeParse({ name: 'd', type: 'A', ttl: 300, values: [{ content: '192.0.2.1' }, { content: '192.0.2.1' }] }).success).toBe(false)
    expect(recordSetSchema.safeParse({ name: 'x', type: 'SOA', ttl: 300, values: [{ content: 'x' }] }).success).toBe(false)
    expect(relativeName('example.test.', 'example.test.')).toBe('@')
    expect(relativeName('www.example.test.', 'example.test.')).toBe('www')
    expect(relativeName('other.', 'example.test.')).toBe('other.')
    for (let i = 0; i < 300; i++) {
      const s = Array.from({ length: Math.floor(Math.random() * 30) }, () => '0123456789.: "ab\n$'[Math.floor(Math.random() * 18)]).join('')
      for (const t of RECORD_TYPES) expect(() => checkContent(t, s)).not.toThrow()
    }
  })
})

describe('records view', () => {
  let calls: Call[]
  const mountAt = async (handler: (url: string, init: RequestInit) => unknown) => {
    calls = fetchMock(handler)
    const router = makeRouter()
    await router.push('/dns/zones/z1')
    const w = mount(Records, { global: { plugins: [router] }, attachTo: document.body })
    await flushPromises()
    return w
  }
  const list = (url: string, init: RequestInit) => (url.endsWith('/zones/z1') ? zone : init.method === 'GET' ? { items: sets, total: 120 } : undefined)

  beforeEach(() => {
    setActivePinia(createPinia())
    document.cookie = '__Host-csrf=tok; Secure; Path=/'
    ;(globalThis as unknown as { __vw: number }).__vw = 1280
  })

  it('lists sets with SOA read-only, relative names, disabled values, filters and pages', async () => {
    const w = await mountAt(list)
    expect(w.text()).toContain('example.test.')
    expect(w.find('[data-test=records-serial]').text()).toContain('12')
    const soa = w.find('[data-test="record-row-SOA-@"]')
    expect(soa.text()).toContain('read-only')
    expect(soa.find('[data-test^=record-edit]').exists()).toBe(false)
    const www = w.find('[data-test="record-row-A-www"]')
    expect(www.text()).toContain('disabled')
    expect(www.find('.line-through').text()).toContain('192.0.2.11')
    expect(w.find('[data-test=record-pager]').text()).toContain('Page 1 of 3 · 120 record sets')
    expect(w.find('[style]').exists()).toBe(false)
    select(w.find('#record-type').element, 'A')
    await flushPromises()
    expect(calls.at(-1)!.url).toMatch(/\/zones\/z1\/records\?type=A&page=1&page_size=50$/)
    type(w.find('#record-search').element, 'ww')
    await w.find('#record-search').trigger('keyup', { key: 'Enter' })
    await flushPromises()
    expect(calls.at(-1)!.url).toContain('query=ww')
    await w.find('[aria-label="Next page"]').trigger('click')
    await flushPromises()
    expect(calls.at(-1)!.url).toContain('page=2')
    w.unmount()
  })

  it('inline editor: type-aware hints, multi-value with disabled flags, client and server errors inline', async () => {
    let refuse = true
    const w = await mountAt((url, init) => {
      if (init.method === 'POST') {
        if (refuse) return reply(422, { reason: 'invalid_record', detail: { field: 'values[0].content', message: 'the TLSA certificate data is not hex' } })
        return sets[1]
      }
      return list(url, init)
    })
    await w.find('[data-test=record-new]').trigger('click')
    await flushPromises()
    const ed = () => w.find('[data-test=record-editor]')
    select(ed().find('#rec-type').element, 'MX')
    await flushPromises()
    expect(ed().find('#rec-value-0').attributes('placeholder')).toBe('10 mail.example.com.')
    type(ed().find('#rec-name').element, 'mail')
    await flushPromises()
    expect(ed().text()).toContain('mail.example.test.')
    type(ed().find('#rec-value-0').element, 'mail.example.test.')
    await ed().find('[data-test=rec-save]').trigger('click')
    await flushPromises()
    expect(calls.some((c) => c.init.method === 'POST')).toBe(false)
    expect(ed().text()).toContain('Enter a priority and a host name')
    // switch to A with two values, the second disabled, TTL preset 1 day
    select(ed().find('#rec-type').element, 'A')
    select(ed().find('#rec-ttl-preset').element, '86400')
    type(ed().find('#rec-value-0').element, '192.0.2.20')
    await ed().find('[data-test=rec-add-value]').trigger('click')
    await flushPromises()
    type(ed().find('#rec-value-1').element, '192.0.2.21')
    const cb = ed().find('#rec-disabled-1').element as HTMLInputElement
    cb.checked = true
    cb.dispatchEvent(new Event('change'))
    type(ed().find('#rec-comment').element, 'pool')
    await ed().find('[data-test=rec-save]').trigger('click')
    await flushPromises()
    const post = calls.find((c) => c.init.method === 'POST')!
    expect(post.url).toBe('/api/dns/v1/zones/z1/records')
    expect(JSON.parse(String(post.init.body))).toEqual({ name: 'mail', type: 'A', ttl: 86400, values: [{ content: '192.0.2.20', disabled: false }, { content: '192.0.2.21', disabled: true }], comment: 'pool' })
    expect(w.find('[data-test=rec-error]').text()).toContain('the TLSA certificate data is not hex')
    refuse = false
    await ed().find('[data-test=rec-save]').trigger('click')
    await flushPromises()
    expect(w.find('[data-test=record-editor]').exists()).toBe(false)
    w.unmount()
  })

  it('edit keeps the original key (rename = PUT), custom TTL, delete asks first', async () => {
    const w = await mountAt((url, init) => (init.method === 'PUT' ? sets[2] : init.method === 'DELETE' ? reply(204) : list(url, init)))
    await w.find('[data-test="record-edit-TXT-odd"]').trigger('click')
    await flushPromises()
    const ed = w.find('[data-test=record-editor]')
    expect((ed.find('#rec-ttl-preset').element as HTMLSelectElement).value).toBe('custom')
    expect((ed.find('#rec-ttl').element as HTMLInputElement).value).toBe('1234')
    type(ed.find('#rec-name').element, 'even')
    await ed.find('[data-test=rec-save]').trigger('click')
    await flushPromises()
    const put = calls.find((c) => c.init.method === 'PUT')!
    expect(JSON.parse(String(put.init.body))).toEqual({ original: { name: 'odd.example.test.', type: 'TXT' }, record: { name: 'even', type: 'TXT', ttl: 1234, values: [{ content: '"hello"', disabled: false }], comment: '' } })
    await w.find('[data-test="record-delete-A-www"]').trigger('click')
    await flushPromises()
    expect(calls.some((c) => c.init.method === 'DELETE')).toBe(false)
    useConfirm().answer(true)
    await flushPromises()
    expect(calls.find((c) => c.init.method === 'DELETE')!.url).toBe('/api/dns/v1/zones/z1/records?name=www.example.test.&type=A')
    expect(w.find('[data-test="record-row-A-www"]').exists()).toBe(false)
    w.unmount()
  })

  it('secondary zones are read-only; a missing zone is reported', async () => {
    const w = await mountAt((url, init) => (url.endsWith('/zones/z1') ? { ...zone, kind: 'slave', masters: ['192.0.2.1'] } : list(url, init)))
    expect(w.find('[data-test=record-new]').exists()).toBe(false)
    expect(w.text()).toContain('come from their primaries')
    expect(w.find('[data-test^=record-edit]').exists()).toBe(false)
    w.unmount()
    const m = await mountAt(() => reply(404, { reason: 'zone_not_found' }))
    expect(m.text()).toContain('The zone no longer exists.')
    m.unmount()
  })
})
