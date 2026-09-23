import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import { flushPromises, mount } from '@vue/test-utils'
import Dashboard from '@/views/dashboard/index.vue'
import { formatValue, formatDuration } from '@/components/format'
import { abilities, fetchMock, makeRouter } from './helpers'

const data = (window = '1h') => ({
  available: true,
  window,
  step_seconds: 60,
  panels: [
    { id: 'recursor_qps', kind: 'stat', unit: 'qps', value: 12.5 },
    { id: 'recursor_uptime', kind: 'stat', unit: 's', value: 93784 },
    { id: 'auth_qps', kind: 'stat', unit: 'qps', unavailable: true },
    { id: 'recursor_answers', kind: 'series', unit: 'qps', series: [
      { labels: { series: 'noerror' }, points: [[1000, 1], [1060, 3]] },
      { labels: { series: 'nxdomain' }, points: [[1000, 0.5], [1060, 0.25]] },
    ] },
    { id: 'auth_errors', kind: 'series', unit: 'pps', series: [] },
    { id: 'auth_queries', kind: 'series', unit: 'qps', unavailable: true },
  ],
})

describe('dashboard formatting', () => {
  it('formats units and durations', () => {
    expect(formatValue(undefined)).toBe('—')
    expect(formatValue(12.345, 'qps')).toBe('12.35 qps')
    expect(formatValue(250, '%')).toBe('250 %')
    expect(formatValue(3)).toBe('3.00')
    expect(formatDuration(93784)).toBe('1d 2h')
    expect(formatDuration(3720)).toBe('1h 2m')
    expect(formatDuration(120)).toBe('2m')
    expect(formatDuration(5)).toBe('5s')
    expect(formatValue(5, 's')).toBe('5s')
  })
})

describe('dashboard view', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    vi.useFakeTimers()
  })
  afterEach(() => {
    vi.useRealTimers()
  })

  it('renders tiles and charts, switches windows and refreshes every 30 s', async () => {
    const calls = fetchMock((url) => data(new URL(url, 'https://x').searchParams.get('window') ?? '1h'))
    const w = mount(Dashboard, { global: { plugins: [makeRouter(), abilities()] }, attachTo: document.body })
    await flushPromises()
    expect(calls[0]!.url).toBe('/api/dns/v1/dashboard?window=1h')
    expect(w.find('[data-test=stat-recursor_qps]').text()).toContain('12.50 qps')
    expect(w.find('[data-test=stat-recursor_uptime]').text()).toContain('1d 2h')
    expect(w.find('[data-test=stat-auth_qps]').text()).toContain('unavailable')
    const chart = w.find('[data-test=panel-recursor_answers] [data-test=chart]')
    expect(chart.exists()).toBe(true)
    expect(chart.findAll('polyline').length).toBe(2)
    expect(w.find('[data-test=panel-recursor_answers]').text()).toContain('nxdomain')
    expect(w.find('[data-test=panel-auth_errors] [data-test=chart-empty]').exists()).toBe(true)
    expect(w.find('[data-test=panel-auth_queries]').text()).toContain('could not be loaded')
    expect(w.find('[style]').exists()).toBe(false)
    // No query text is ever sent: only the window.
    for (const c of calls) expect([...new URL(c.url, 'https://x').searchParams.keys()]).toEqual(['window'])
    // Window switch.
    const tab = w.findAll('[data-test=dashboard-window] [role=tab], [data-test=dashboard-window] button').find((b) => b.text().includes('6 hours'))!
    await tab.trigger('click')
    await flushPromises()
    expect(calls[calls.length - 1]!.url).toBe('/api/dns/v1/dashboard?window=6h')
    // Auto-refresh.
    const before = calls.length
    vi.advanceTimersByTime(30_000)
    await flushPromises()
    expect(calls.length).toBe(before + 1)
    w.unmount()
    vi.advanceTimersByTime(60_000)
    await flushPromises()
    expect(calls.length).toBe(before + 1)
  })

  it('shows a notice when metrics are not configured', async () => {
    fetchMock(() => ({ available: false, window: '1h', step_seconds: 60, panels: [] }))
    const w = mount(Dashboard, { global: { plugins: [makeRouter(), abilities()] }, attachTo: document.body })
    await flushPromises()
    expect(w.find('[data-test=dashboard-unavailable]').text()).toContain('Metrics unavailable')
    expect(w.find('[data-test=dashboard-stats]').exists()).toBe(false)
    w.unmount()
  })
})
