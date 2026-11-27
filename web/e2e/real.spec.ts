import { expect, test, type Page } from '@playwright/test'
import { createHmac } from 'node:crypto'
import { readFileSync } from 'node:fs'
import path from 'node:path'
import { semViolacoes } from './ajuda'

/**
 * Ponta a ponta REAL contra o W1: login pelo navegador no realm `auditor` (senha + OTP) via BFF, até o Início e a lista
 * de investigações. Precisa da API do W1 em :8100 (ver web/README.md) e do Keycloak em :8090.
 * O OTP sai do segredo em chaves/totp_teste.json, como em tests/navegador_kc.py (HMAC-SHA1 sobre o segredo em texto).
 */
const USUARIO = process.env.E2E_USUARIO ?? 'solicitante1'
const SEGREDOS = path.resolve(import.meta.dirname, '../../chaves/totp_teste.json')

function totp(segredo: string, t = Date.now() / 1000): string {
  const c = Buffer.alloc(8)
  c.writeBigUInt64BE(BigInt(Math.floor(t / 30)))
  const h = createHmac('sha1', Buffer.from(segredo, 'utf8')).update(c).digest()
  const o = h[h.length - 1] & 0x0f
  return String((h.readUInt32BE(o) & 0x7fffffff) % 1_000_000).padStart(6, '0')
}

async function preencherOtp(page: Page, segredo: string) {
  for (let tentativa = 0; tentativa < 3; tentativa++) {
    await page.locator('input[name="otp"]').fill(totp(segredo))
    await page.locator('#kc-login, input[type="submit"], button[type="submit"]').first().click()
    await page.waitForLoadState('domcontentloaded')
    if (!(await page.locator('input[name="otp"]').isVisible().catch(() => false))) return
    // código já usado nesta janela (o Keycloak não aceita repetido): espera a próxima
    await page.waitForTimeout((30 - (Date.now() / 1000) % 30 + 1) * 1000)
  }
  throw new Error('OTP recusado três vezes')
}

test('login real (senha + OTP) até o Início e a lista de investigações', async ({ page }) => {
  const segredo = (JSON.parse(readFileSync(SEGREDOS, 'utf8')) as Record<string, string>)[USUARIO]
  expect(segredo, `segredo TOTP de ${USUARIO}`).toBeTruthy()
  const hosts = new Set<string>()
  page.on('request', (r) => hosts.add(new URL(r.url()).host))

  await page.goto('/')
  // sem sessão: a tela manda para /auth/entrar?volta=/ → Keycloak
  await page.waitForURL(/localhost:8090\/realms\/auditor\//)
  await page.locator('#username').fill(USUARIO)
  await page.locator('#password').fill(`senha-${USUARIO}`)
  await page.locator('#kc-login, input[type="submit"], button[type="submit"]').first().click()
  await page.locator('input[name="otp"]').waitFor()
  await preencherOtp(page, segredo)

  await page.waitForURL('http://localhost:5173/')
  await expect(page.getByRole('heading', { level: 1 })).toContainText('Olá')
  await expect(page.locator('.usuario-papeis')).toContainText('Solicitante')
  await expect(page.getByRole('navigation', { name: 'Navegação principal' }).getByRole('link'))
    .toHaveText(['Início', 'Investigações', 'Verificar pacote'])
  await expect(page.getByRole('heading', { name: 'Minhas investigações' })).toBeVisible()
  await page.screenshot({ path: 'test-results/real-inicio.png' })

  await page.getByRole('navigation', { name: 'Navegação principal' }).getByRole('link', { name: 'Investigações' }).click()
  await expect(page.getByRole('heading', { name: 'Investigações', level: 1 })).toBeVisible()
  await expect(page.locator('.esqueleto')).toHaveCount(0)
  const contagem = await page.locator('.contagem').textContent()
  console.log(`lista real: ${contagem}`)
  await expect(page.getByRole('region', { name: 'Lista de investigações' }).or(page.getByText('Nenhuma investigação'))).toBeVisible()
  await semViolacoes(page, 'lista real')
  // o cookie de sessão é HttpOnly: a página não o vê
  expect(await page.evaluate(() => document.cookie)).not.toContain('kc_auditor_sessao')
  expect([...hosts].sort()).toEqual(['localhost:5173', 'localhost:8090'])
})
