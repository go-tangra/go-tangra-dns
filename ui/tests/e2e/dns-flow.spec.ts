import { expect, test, type Page } from '@playwright/test'
import { base, signIn } from '../../../../gateway/shell/tests/e2e/helpers'

// Quickstart flow for the DNS remote at the three reference widths:
// zones list → new zone drawer → zone drawer → records (inline editor: add,
// edit, delete) → export → templates (create with a record row, delete) →
// supermasters (create gated to platform admins) → configuration (platform
// admin only) → dashboard ("Metrics unavailable" without Prometheus). Runs
// through the gateway against the stack's PowerDNS; skips without operator
// credentials.
const password = process.env.E2E_OPERATOR_PASSWORD ?? ''
const email = process.env.E2E_OPERATOR_EMAIL ?? 'ops@example.org'
const viewports = [{ name: 'phone', width: 320, height: 640 }, { name: 'tablet', width: 768, height: 1024 }, { name: 'desktop', width: 1280, height: 800 }]

async function openNav(page: Page, entry: string): Promise<void> {
  const burger = page.getByRole('button', { name: 'Open navigation' })
  if (await burger.isVisible()) await burger.click()
  const g = page.getByTestId('nav-group-dns')
  if ((await g.getAttribute('aria-expanded')) !== 'true') await g.click()
  await page.getByTestId('nav-dns').filter({ hasText: entry }).first().click()
}

async function confirmDialog(page: Page, title: RegExp, button: string): Promise<void> {
  const dialog = page.getByRole('dialog', { name: title })
  await expect(dialog).toBeVisible()
  await dialog.getByRole('button', { name: button, exact: true }).click()
  await expect(dialog).toBeHidden()
}

test.describe('dns remote', () => {
  test.skip(!password, 'E2E_OPERATOR_PASSWORD not set')
  for (const vp of viewports) {
    test(`${vp.name}: zone create, records inline edit, export, templates, supermasters, configuration, dashboard`, async ({ page }) => {
      const run = `${vp.name}-${Date.now().toString(36)}`
      const zoneName = `e2e-${run}.example.test`
      const tplName = `e2e-${run}`
      await page.setViewportSize({ width: vp.width, height: vp.height })
      const violations: string[] = []
      await page.addInitScript(() => document.addEventListener('securitypolicyviolation', (e) => console.error('CSP:' + (e as SecurityPolicyViolationEvent).violatedDirective)))
      page.on('console', (m) => { if (m.text().startsWith('CSP:')) violations.push(m.text()) })
      await page.goto(base + '/')
      await signIn(page, email, password)

      // Templates: create one with a [ZONE]-relative A record (used by the zone below).
      await openNav(page, 'Templates')
      await expect(page.getByTestId('templates-table')).toBeVisible()
      await page.getByTestId('template-new').click()
      const tpl = page.getByTestId('template-drawer')
      await tpl.locator('input#tpl-name').fill(tplName)
      await tpl.getByTestId('tpl-add').click()
      await tpl.locator('input#tpl-rec-name-0').fill('app')
      await tpl.locator('select#tpl-rec-type-0').selectOption('A')
      await tpl.locator('input#tpl-rec-content-0').fill('192.0.2.20')
      await tpl.getByTestId('tpl-save').click()
      await expect(tpl).toBeHidden()
      await expect(page.getByTestId('templates-table')).toContainText(tplName)

      // Zones list → new zone drawer (invalid name refused, then created from the template).
      await openNav(page, 'Zones')
      await expect(page.locator('main h1')).toHaveText('Zones')
      await expect(page.getByTestId('zones-table')).toBeVisible()
      await page.getByTestId('zone-new').click()
      const create = page.getByTestId('zone-create')
      await create.locator('input#name').fill('bad zone name')
      await create.getByRole('button', { name: 'Create', exact: true }).click()
      await expect(create.getByRole('alert').first()).toBeVisible()
      await create.locator('input#name').fill(zoneName)
      await create.locator('select#kind').selectOption('master')
      await create.locator('input#nameservers').fill('ns1.example.test., ns2.example.test.')
      const tplPick = create.locator('select#template_id, input#template_id').first()
      if (await tplPick.evaluate((el) => el.tagName === 'SELECT')) {
        await tplPick.selectOption({ label: tplName })
      }
      await create.getByRole('button', { name: 'Create', exact: true }).click()

      // The zone drawer opens on the new zone with its serial.
      const drawer = page.getByTestId('zone-drawer')
      await expect(drawer).toBeVisible()
      await expect(drawer).toContainText(zoneName)
      await expect(drawer.getByTestId('zone-serial')).toBeVisible()

      // NOTIFY is offered for master zones.
      await drawer.getByTestId('zone-notify').click()
      await expect(drawer.getByTestId('zone-notice').or(drawer.getByTestId('zone-error')).first()).toBeVisible()

      // Export tab: BIND text with the SOA, copyable.
      await drawer.getByRole('tab', { name: /Export/ }).click()
      await expect(drawer.getByTestId('zone-export-text')).toContainText('SOA')
      await expect(drawer.getByTestId('zone-export-copy')).toBeVisible()
      await drawer.getByRole('tab', { name: /Details/ }).click()

      // Records: the template row is there; add, edit inline, delete.
      await drawer.getByTestId('zone-records').click()
      await expect(page.getByTestId('records-table')).toBeVisible()
      await expect(page.getByTestId('record-row-A-app')).toBeVisible()

      await page.getByTestId('record-new').click()
      const editor = page.getByTestId('record-editor')
      await editor.locator('input#rec-name').fill('www')
      await editor.locator('select#rec-type').selectOption('A')
      await editor.locator('input#rec-value-0').fill('not-an-ip')
      await editor.getByTestId('rec-save').click()
      await expect(editor.getByRole('alert').first()).toBeVisible()
      await editor.locator('input#rec-value-0').fill('192.0.2.10')
      await editor.getByTestId('rec-add-value').click()
      await editor.locator('input#rec-value-1').fill('192.0.2.11')
      await editor.getByTestId('rec-save').click()
      await expect(editor).toBeHidden()
      const row = page.getByTestId('record-row-A-www')
      await expect(row).toContainText('192.0.2.10')
      await expect(row).toContainText('192.0.2.11')

      await page.getByTestId('record-edit-A-www').click()
      await expect(editor).toBeVisible()
      await editor.locator('input#rec-value-1').fill('192.0.2.12')
      await editor.locator('input#rec-comment').fill('edited by e2e')
      await editor.getByTestId('rec-save').click()
      await expect(editor).toBeHidden()
      await expect(row).toContainText('192.0.2.12')
      await expect(row).not.toContainText('192.0.2.11')

      await page.getByTestId('record-delete-A-www').click()
      await confirmDialog(page, /Delete www A\?/, 'Delete')
      await expect(page.getByTestId('record-row-A-www')).toHaveCount(0)

      // Back to the zone: delete it (confirmation).
      await openNav(page, 'Zones')
      await page.locator('input#zone-search').fill(zoneName)
      await page.locator('input#zone-search').press('Enter')
      const zoneRow = page.locator('[data-test^=zone-row-]').filter({ hasText: zoneName }).first()
      await zoneRow.click()
      await expect(drawer).toBeVisible()
      await drawer.getByTestId('zone-delete').click()
      await confirmDialog(page, new RegExp(`Delete ${zoneName.replace(/\./g, '\\.')}`), 'Delete')
      await expect(page.getByTestId('zones-table')).not.toContainText(zoneName)

      // Template clean-up.
      await openNav(page, 'Templates')
      await page.locator('[data-test^=template-row-]').filter({ hasText: tplName }).first().click()
      await tpl.getByTestId('tpl-delete').click()
      await confirmDialog(page, /Delete .*\?/, 'Delete')
      await expect(page.getByTestId('templates-table')).not.toContainText(tplName)

      // Supermasters: listed; creating one is platform-admin only.
      const smNav = page.getByTestId('nav-dns').filter({ hasText: 'Supermasters' })
      await openNav(page, 'Zones')
      if (await smNav.count()) {
        await openNav(page, 'Supermasters')
        await expect(page.getByTestId('supermasters-table')).toBeVisible()
        const add = page.getByTestId('supermaster-new')
        if (await add.isVisible()) {
          await add.click()
          const sm = page.getByTestId('supermaster-create')
          await sm.locator('input#ip').fill('127.0.0.1')
          await sm.locator('input#nameserver').fill(`ns-${run}.primary.example`)
          await sm.getByRole('button', { name: 'Create', exact: true }).click()
          await expect(sm.getByRole('alert').first()).toBeVisible() // loopback refused
          await sm.locator('input#ip').fill('192.0.2.53')
          await sm.getByRole('button', { name: 'Create', exact: true }).click()
          await expect(sm).toBeHidden()
          const smRow = page.locator('[data-test^=supermaster-row-]').filter({ hasText: `ns-${run}.primary.example` }).first()
          await expect(smRow).toBeVisible()
          await smRow.locator('[data-test^=supermaster-delete-]').click()
          await confirmDialog(page, /Remove 192\.0\.2\.53/, 'Remove')
          await expect(page.getByTestId('supermasters-table')).not.toContainText(`ns-${run}.primary.example`)
        } else {
          await expect(page.getByTestId('supermaster-admin-hint')).toBeVisible()
        }
      }

      // Configuration: platform admins see the form (restart notice), others the admin-only notice.
      await page.goto(base + '/dns/configuration')
      await expect(page.locator('main h1')).toBeVisible()
      await expect(page.getByTestId('config-admin-only')
        .or(page.getByTestId('config-restart-warning'))
        .or(page.getByTestId('config-restart-disabled')).first()).toBeVisible({ timeout: 15_000 })
      if (await page.getByTestId('config-save').isVisible()) {
        // An open resolver without the explicit opt-in is flagged before saving.
        await page.getByTestId('config-recursor-allowed').locator('textarea').fill('0.0.0.0/0')
        await expect(page.getByTestId('config-open-warning')).toBeVisible()
        await page.reload()
      }

      // Dashboard: without the metrics profile the "Metrics unavailable" notice shows.
      await openNav(page, 'Dashboard')
      await expect(page.getByTestId('dashboard-unavailable').or(page.getByTestId('dashboard-stats')).first()).toBeVisible({ timeout: 15_000 })
      if (await page.getByTestId('dashboard-unavailable').isVisible()) {
        await expect(page.getByTestId('dashboard-unavailable')).toContainText('Metrics unavailable')
      }

      expect(await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)).toBeLessThanOrEqual(0)
      expect(await page.locator('main [style]').count()).toBe(0)
      expect(violations).toEqual([])
    })
  }
})
