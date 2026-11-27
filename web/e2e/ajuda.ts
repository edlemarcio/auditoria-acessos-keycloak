import AxeBuilder from '@axe-core/playwright'
import { expect, type Page } from '@playwright/test'

export type Perfil = 'solicitante' | 'investigador' | 'aprovador' | 'auditor_interno' | 'admin_tecnico' | 'gestor_acesso' | 'aprovinvest'
export type Tema = 'claro' | 'escuro'

/** Entra nos dublês com um perfil (cookies do dublê) e um tema (preferência local). */
export async function entrar(page: Page, perfil: Perfil, tema: Tema = 'claro', stepUp = false) {
  const agora = Date.now()
  await page.context().addCookies([
    { name: 'dubles_sessao', value: '1', url: 'http://localhost:5173' },
    { name: 'dubles_perfil', value: perfil, url: 'http://localhost:5173' },
    ...(stepUp ? [{ name: 'dubles_step_up', value: String(agora), url: 'http://localhost:5173' }] : []),
  ])
  await page.addInitScript((t) => { try { localStorage.setItem('kc-auditor:tema', t) } catch { /* */ } }, tema)
}

export async function abrir(page: Page, rota: string) {
  await page.goto(rota)
  await expect(page.locator('#titulo-tela')).toBeVisible()
  await expect(page.locator('.esqueleto')).toHaveCount(0, { timeout: 10_000 })
}

/** axe-core com as regras WCAG 2.0/2.1/2.2 A e AA: precisa dar 0 violações. */
export async function semViolacoes(page: Page, rotulo: string) {
  const r = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa', 'best-practice'])
    .disableRules(['region']).analyze()
  const resumo = r.violations.map((v) => `${v.id} (${v.impact}): ${v.nodes.slice(0, 3).map((n) => n.target.join(' ')).join(' | ')}`)
  expect(resumo, `axe em ${rotulo}`).toEqual([])
  return r
}
