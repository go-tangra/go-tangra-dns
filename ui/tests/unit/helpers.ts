import { vi } from 'vitest'
import type { Plugin } from 'vue'
import { createRouter, createMemoryHistory } from 'vue-router'
import { abilitiesPlugin } from '@casl/vue'
import { createMongoAbility } from '@casl/ability'

export interface Call {
  url: string
  init: RequestInit
}
export interface Reply {
  status?: number
  body?: unknown
}

/** Stubs fetch; the handler returns a body (200) or a {status, body} reply. */
export function fetchMock(handler: (url: string, init: RequestInit) => unknown): Call[] {
  const calls: Call[] = []
  vi.stubGlobal('fetch', vi.fn(async (url: string, init: RequestInit = {}) => {
    calls.push({ url, init })
    const out = handler(url, init)
    const reply = (out && typeof out === 'object' && '__reply' in out ? (out as { __reply: Reply }).__reply : { status: 200, body: out }) as Reply
    const status = reply.status ?? 200
    if (status === 204) return new Response(null, { status })
    return new Response(JSON.stringify(reply.body ?? {}), { status, headers: { 'Content-Type': 'application/json' } })
  }))
  return calls
}

export const reply = (status: number, body?: unknown) => ({ __reply: { status, body } })

export const makeRouter = () =>
  createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: '/dns', name: 'dns-zones', component: { template: '<div/>' } },
      { path: '/dns/zones/:id', name: 'dns-zone-records', component: { template: '<div/>' } },
    ],
  })

/** Sets an input's value and fires the event the kit listens to. */
export function type(el: Element | null | undefined, value: string): void {
  const input = el as HTMLInputElement
  input.value = value
  input.dispatchEvent(new Event('input'))
}

export function select(el: Element | null | undefined, value: string): void {
  const s = el as HTMLSelectElement
  s.value = value
  s.dispatchEvent(new Event('change'))
}

export function clickButton(root: ParentNode, text: string): void {
  const b = Array.from(root.querySelectorAll('button')).find((x) => x.textContent?.trim() === text)
  if (!b) throw new Error('no button ' + text)
  ;(b as HTMLButtonElement).click()
}

/** The CASL abilities plugin with the given rules (default: everything). */
export const abilities = (rules: Array<{ action: string | string[]; subject: string | string[] }> = [{ action: 'manage', subject: 'all' }]): [Plugin, ...unknown[]] => [
  abilitiesPlugin as Plugin,
  createMongoAbility(rules),
  { useGlobalProperties: true },
]
