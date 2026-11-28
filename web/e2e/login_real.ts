import { expect, type Browser, type Page } from '@playwright/test'
import { createHmac } from 'node:crypto'
import { readFileSync } from 'node:fs'
import path from 'node:path'

/** Login real (senha + OTP do segredo de teste) no realm `auditor`, para os testes de aceite contra a API em :8000. */
const RAIZ = path.resolve(import.meta.dirname, '../..')
const SEGREDOS = JSON.parse(readFileSync(path.join(RAIZ, 'chaves/totp_teste.json'), 'utf8')) as Record<string, string>
const ALVO = (JSON.parse(readFileSync(path.join(RAIZ, 'dados/pessoas.json'), 'utf8')) as { casos: { ALVO: { cpf?: string } | string } }).casos.ALVO
export const CPF = typeof ALVO === 'string' ? ALVO : String(ALVO.cpf)
export const DIGITOS = CPF.replace(/\D/g, '')

function totp(segredo: string, t = Date.now() / 1000): string {
  const c = Buffer.alloc(8)
  c.writeBigUInt64BE(BigInt(Math.floor(t / 30)))
  const h = createHmac('sha1', Buffer.from(segredo, 'utf8')).update(c).digest()
  const o = h[h.length - 1] & 0x0f
  return String((h.readUInt32BE(o) & 0x7fffffff) % 1_000_000).padStart(6, '0')
}

export async function login(browser: Browser, usuario: string, rota: string, tema: 'claro' | 'escuro' = 'claro'): Promise<Page> {
  const page = await (await browser.newContext()).newPage()
  await page.addInitScript((t) => { try { localStorage.setItem('kc-auditor:tema', t) } catch { /* */ } }, tema)
  page.on('request', (r) => { expect(r.url(), 'CPF em URL').not.toContain(DIGITOS) })
  await page.goto(rota)
  await page.waitForURL(/localhost:8090\/realms\/auditor\//)
  await page.locator('#username').fill(usuario)
  await page.locator('#password').fill(`senha-${usuario}`)
  await page.locator('#kc-login, input[type="submit"]').first().click()
  for (let k = 0; k < 3; k++) {
    await page.locator('input[name="otp"]').fill(totp(SEGREDOS[usuario]))
    await page.locator('#kc-login, input[type="submit"]').first().click()
    await page.waitForLoadState('domcontentloaded')
    if (!(await page.locator('input[name="otp"]').isVisible().catch(() => false))) break
    await page.waitForTimeout((31 - (Date.now() / 1000) % 30) * 1000)
  }
  await page.waitForURL((u) => u.host === 'localhost:8000')
  await expect(page.locator('#titulo-tela')).toBeVisible()
  await expect(page.locator('.esqueleto')).toHaveCount(0, { timeout: 15_000 })
  return page
}

