import { expect, test, type Page } from '@playwright/test'
import { semViolacoes } from './ajuda'
import { CPF, login } from './login_real'

/**
 * Aceite das telas da W3 contra a API integrada em :8000 (servindo web/dist, papel kc_api com RLS) e o worker:
 * Dashboard, Eventos (com o painel de detalhe), Contas e Cobertura do investigador designado, e a visão agregada no
 * Resumo do solicitante, nos temas claro e escuro, com axe sem violações. Interação entre telas: destaque, ponto do
 * gráfico (teclado) e IP do ranking abrem Eventos já filtrado, com a mesma contagem.
 * A investigação usada é E2E_INV (padrão: a do aceite da W2).
 */
const INV = Number(process.env.E2E_INV ?? 14)

async function pronto(p: Page) {
  await expect(p.locator('#titulo-tela')).toBeVisible()
  await expect(p.locator('.esqueleto')).toHaveCount(0, { timeout: 30_000 })
}

for (const tema of ['claro', 'escuro'] as const) {
  test(`W3 (${tema}): investigador analisa e o solicitante vê a visão agregada`, async ({ browser }) => {
    const ivg = await login(browser, 'investigador1', `/investigacoes/${INV}/dashboard`, tema)
    await pronto(ivg)
    const abas = ivg.getByRole('navigation', { name: 'Seções da investigação' })
    await expect(abas.getByRole('link')).toHaveText(['Resumo', 'Dashboard', 'Eventos', 'Contas', 'Cobertura', 'Pacotes'])
    await expect(ivg.getByText('Logins', { exact: true }).first()).toBeVisible()
    await semViolacoes(ivg, `dashboard (${tema})`)
    await ivg.screenshot({ path: `test-results/w3-dashboard-${tema}.png`, fullPage: true })

    // destaque → Eventos com a mesma contagem
    const dz = ivg.locator('.destaque').filter({ hasText: 'Rajada' }).first()
    const n = Number((await dz.locator('.meta-destaque').textContent())!.split(' ')[0].replace(/\D/g, ''))
    await dz.click()
    await expect(ivg).toHaveURL(new RegExp(`/investigacoes/${INV}/eventos\\?`))
    await pronto(ivg)
    await expect(ivg.getByRole('status').filter({ hasText: /de .* eventos/ })).toContainText(`${n.toLocaleString('pt-BR')} de`)
    await semViolacoes(ivg, `eventos filtrados (${tema})`)

    // painel de detalhe
    await ivg.getByRole('button', { name: /^Detalhe/ }).first().click()
    const painel = ivg.locator('.painel-evento')
    await expect(painel).toContainText('Folha (Merkle)')
    await expect(painel).toContainText('Selo da fatia', { timeout: 15_000 })
    await expect(painel).not.toContainText(CPF)
    await semViolacoes(ivg, `detalhe do evento (${tema})`)
    await ivg.screenshot({ path: `test-results/w3-eventos-${tema}.png`, fullPage: true })

    // gráfico pelo teclado: foco, seta, Enter → eventos da janela
    await ivg.goto(`/investigacoes/${INV}/dashboard`)
    await pronto(ivg)
    const svg = ivg.locator('.grafico-area svg').first()
    await svg.focus()
    await ivg.keyboard.press('End')
    await expect(ivg.locator('.dica')).toBeVisible()
    await ivg.keyboard.press('Enter')
    await expect(ivg).toHaveURL(/eventos\?.*de=\d+.*ate=\d+/)
    await pronto(ivg)

    // ranking de IP → filtro pelo rótulo
    await ivg.goto(`/investigacoes/${INV}/dashboard`)
    await pronto(ivg)
    const ipBtn = ivg.locator('.barras').first().locator('button').first()
    const rotIp = (await ipBtn.locator('.barra-rotulo').textContent())!.trim()
    await ipBtn.click()
    await expect(ivg).toHaveURL(new RegExp(`ip=${encodeURIComponent(rotIp).replace(/%20/g, '(\\+|%20)')}`))
    await pronto(ivg)
    await expect(ivg.getByRole('list', { name: 'Filtros aplicados' })).toContainText(`IP: ${rotIp}`)

    // contas (abre e cancela a exclusão) e cobertura
    await ivg.goto(`/investigacoes/${INV}/contas`)
    await pronto(ivg)
    await semViolacoes(ivg, `contas (${tema})`)
    await ivg.getByRole('button', { name: /^Excluir/ }).first().click()
    const dlgExcluir = ivg.getByRole('dialog', { name: /^Excluir/ })
    await expect(dlgExcluir).toBeVisible()
    await semViolacoes(ivg, `diálogo de exclusão (${tema})`)
    await dlgExcluir.getByRole('button', { name: 'Cancelar' }).click()
    await ivg.screenshot({ path: `test-results/w3-contas-${tema}.png`, fullPage: true })
    await ivg.goto(`/investigacoes/${INV}/cobertura`)
    await pronto(ivg)
    await expect(ivg.getByRole('region', { name: 'Cobertura por realm' })).toBeVisible()
    await semViolacoes(ivg, `cobertura (${tema})`)
    await ivg.screenshot({ path: `test-results/w3-cobertura-${tema}.png`, fullPage: true })
    await expect(ivg.locator('body')).not.toContainText(CPF)

    // solicitante: visão agregada no Resumo, sem abas de dados nem IPs
    const sol = await login(browser, 'solicitante1', `/investigacoes/${INV}`, tema)
    await pronto(sol)
    await expect(sol.getByRole('heading', { name: 'Visão agregada' })).toBeVisible()
    await expect(sol.getByRole('navigation', { name: 'Seções da investigação' }).getByRole('link')).toHaveText(['Resumo', 'Pacotes'])
    await expect(sol.locator('#t-agregada').locator('..').locator('..')).not.toContainText(/\bIP \d+|Conta \d+/)
    await semViolacoes(sol, `visão agregada (${tema})`)
    await sol.screenshot({ path: `test-results/w3-visao-agregada-${tema}.png`, fullPage: true })
    // o solicitante não abre o dashboard nem por URL
    await sol.goto(`/investigacoes/${INV}/dashboard`)
    await expect(sol.locator('body')).toContainText(/não|sem acesso|perfil/i)
  })
}
