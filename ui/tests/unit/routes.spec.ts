import { describe, expect, it } from 'vitest'
import { routes } from '@/remote/routes'
import { nav } from '@/remote/nav'

describe('dns remote', () => {
  it('exports the module routes, all tagged with the dns module', () => {
    expect(routes.map((r) => r.path)).toEqual(['/dns', '/dns/zones/:id', '/dns/templates', '/dns/supermasters', '/dns/dashboard', '/dns/configuration'])
    for (const r of routes) expect(r.meta?.module).toBe('dns')
    expect(nav()).toEqual([])
  })
  it('every route lazily resolves a component', async () => {
    for (const r of routes) {
      const load = r.component as () => Promise<{ default: unknown }>
      expect((await load()).default).toBeTruthy()
    }
  })
})
