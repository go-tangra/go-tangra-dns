import { expect, test } from '@playwright/test'
import AxeBuilder from '@axe-core/playwright'
import { base, signIn } from './helpers'

// Every DNS view inside the shell, both themes, zero serious or critical axe
// findings. Needs a full platform; skips without operator credentials.
const password = process.env.E2E_OPERATOR_PASSWORD ?? ''
const email = process.env.E2E_OPERATOR_EMAIL ?? 'ops@example.org'
const routes = ['/dns', '/dns/templates', '/dns/supermasters', '/dns/dashboard', '/dns/configuration']

test.describe('dns accessibility', () => {
  test.skip(!password, 'E2E_OPERATOR_PASSWORD not set')

  for (const theme of ['freya-light', 'freya-dark']) {
    test(`views are axe clean in ${theme}`, async ({ page }) => {
      await page.addInitScript((t) => localStorage.setItem('freya.theme', t), theme)
      await page.goto(base + '/')
      await signIn(page, email, password)
      for (const route of routes) {
        await page.goto(base + route)
        await expect(page.locator('main h1, main h2').first()).toBeVisible({ timeout: 15_000 })
        expect(await page.evaluate(() => document.documentElement.getAttribute('data-theme'))).toBe(theme)
        const results = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa']).analyze()
        const blocking = results.violations.filter((v) => v.impact === 'serious' || v.impact === 'critical')
        expect(blocking, route + ': ' + JSON.stringify(blocking.map((v) => ({ id: v.id, nodes: v.nodes.map((n) => n.target) })))).toEqual([])
        expect(await page.locator('[style]').count(), route + ': no inline styles').toBe(0)
      }
    })
  }

  test('drawers and the records view are axe clean', async ({ page }) => {
    const scan = async (label: string) => {
      const results = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa']).analyze()
      const blocking = results.violations.filter((v) => v.impact === 'serious' || v.impact === 'critical')
      expect(blocking, label + ': ' + JSON.stringify(blocking.map((v) => ({ id: v.id, nodes: v.nodes.map((n) => n.target) })))).toEqual([])
    }
    await page.goto(base + '/')
    await signIn(page, email, password)
    await page.goto(base + '/dns')
    await expect(page.getByTestId('zones-table')).toBeVisible({ timeout: 15_000 })
    await page.getByTestId('zone-new').click()
    await expect(page.getByTestId('zone-create')).toBeVisible()
    await scan('new zone drawer')
    await page.keyboard.press('Escape')
    const first = page.locator('[data-test^=zone-row-]').first()
    if (await first.isVisible()) {
      await first.click()
      await expect(page.getByTestId('zone-drawer')).toBeVisible()
      await scan('zone drawer')
      await page.getByTestId('zone-records').click()
      await expect(page.getByTestId('records-table')).toBeVisible()
      await scan('records view')
    }
    await page.goto(base + '/dns/templates')
    await expect(page.getByTestId('templates-table')).toBeVisible()
    if (await page.getByTestId('template-new').isVisible()) {
      await page.getByTestId('template-new').click()
      await page.getByTestId('template-drawer').getByTestId('tpl-add').click()
      await scan('template drawer')
    }
  })
})
