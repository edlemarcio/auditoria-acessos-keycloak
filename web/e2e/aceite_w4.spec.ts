import { expect, test, type Page } from '@playwright/test'
import { semViolacoes } from './ajuda'
import { CPF, login } from './login_real'

/**
 * Aceite das telas da W4 contra a API integrada em :8000: o investigador inicia a sessão de análise (motivo), revela
 * um IP ao lado do pseudônimo (coluna "Valor revelado", marca d'água), junta o IP à lista para ofício e a envia; o
 * aprovador decide na tela de decisão (sem ver valores); o investigador encerra a sessão e os valores somem.
 * Nos temas claro e escuro, com axe sem violações. Investigação E2E_INV (padrão: a do aceite da W2).
 */
const INV = Number(process.env.E2E_INV ?? 14)

async function pronto(p: Page) {
  await expect(p.locator('#titulo-tela')).toBeVisible()
  await expect(p.locator('.esqueleto')).toHaveCount(0, { timeout: 30_000 })
}

for (const tema of ['claro', 'escuro'] as const) {
  test(`W4 (${tema}): sessão de análise, revelação, lista para ofício e decisão`, async ({ browser }) => {
    const ivg = await login(browser, 'investigador1', `/investigacoes/${INV}/eventos`, tema)
    await pronto(ivg)
    const barra = ivg.getByRole('region', { name: 'Sessão de análise' })
    if (await barra.getByRole('button', { name: 'Encerrar' }).isVisible()) {   // sobra de uma rodada anterior
      await barra.getByRole('button', { name: 'Encerrar' }).click()
    }
    await barra.getByRole('button', { name: /Iniciar sessão de análise/ }).click()
    const dlg = ivg.getByRole('dialog', { name: 'Iniciar sessão de análise' })
    await expect(dlg).toBeVisible()
    await semViolacoes(ivg, `diálogo de início (${tema})`)
    await dlg.locator('label', { hasText: 'Identificar a autoria de acessos' }).click()
    await expect(dlg.getByLabel('Identificar a autoria de acessos')).toBeChecked()
    await dlg.getByRole('button', { name: 'Iniciar sessão' }).click()
    await expect(barra).toContainText('Sessão de análise ativa', { timeout: 15_000 })
    await expect(barra).toContainText('0 de 30 revelados')

    // revelar o IP do primeiro evento, ao lado do pseudônimo
    await ivg.getByRole('button', { name: /^Detalhe/ }).first().click()
    const painel = ivg.locator('.painel-evento')
    await expect(painel).toContainText('Folha (Merkle)')
    const ipRot = (await painel.locator('dt:text-is("IP") + dd').textContent())!.split(' ').slice(0, 2).join(' ')
    await painel.locator('dt:text-is("IP") + dd').getByRole('button', { name: /Revelar/ }).click()
    await expect(painel.locator('dt:text-is("IP") + dd .valor-revelado')).toBeVisible({ timeout: 15_000 })
    const valor = (await painel.locator('dt:text-is("IP") + dd .valor-revelado').textContent())!.trim()
    expect(valor).toMatch(/^[0-9a-f.:]+$/i)
    await expect(barra).toContainText('1 de 30 revelados')
    await expect(ivg.getByRole('columnheader', { name: 'Valor revelado' })).toBeVisible()
    await expect(ivg.locator('.marca-dagua')).toHaveCount(1)
    expect(ivg.url()).not.toContain(valor)
    await semViolacoes(ivg, `valor revelado (${tema})`)
    await ivg.screenshot({ path: `test-results/w4-revelado-${tema}.png`, fullPage: true })

    // lista para ofício
    await painel.getByRole('button', { name: /Adicionar à lista para ofício/ }).click()
    const lista = ivg.locator('.lista-oficio')
    await expect(lista).toContainText(ipRot)
    await lista.getByLabel(/^Motivo/).fill('Identificar o assinante do IP da rajada de falhas')
    await lista.getByLabel(/^Fundamento/).fill('Ordem judicial no processo 0001234-12.2026')
    await lista.getByLabel('Provedor de destino').fill('Provedor de teste')
    await semViolacoes(ivg, `lista para ofício (${tema})`)
    await lista.getByRole('button', { name: 'Enviar a lista ao aprovador' }).click()
    await expect(lista).toContainText(/Lista nº \d+ enviada/)
    const nLista = Number((await lista.textContent())!.match(/Lista nº (\d+) enviada/)![1])

    // aprovador decide sem ver valores
    const apr = await login(browser, 'aprovador1', `/aprovacoes/${nLista}?inv=${INV}&tipo=lista_oficio`, tema)
    await pronto(apr)
    await expect(apr.getByRole('heading', { level: 1 })).toContainText('Lista para ofício')
    await expect(apr.locator('.decisao')).toContainText('Ordem judicial')
    await expect(apr.locator('.decisao')).not.toContainText(valor)
    await semViolacoes(apr, `decisão da lista (${tema})`)
    await apr.screenshot({ path: `test-results/w4-decisao-${tema}.png`, fullPage: true })
    await apr.getByLabel(/Motivo da decisão/).fill('Fundamento e destinatário competentes')
    await apr.getByRole('button', { name: 'Aprovar' }).click()
    await expect(apr.getByText(/aprovada/)).toBeVisible({ timeout: 15_000 })

    // investigador: tabela do ofício disponível; encerrar a sessão apaga os valores da tela
    await ivg.reload()
    await pronto(ivg)
    await expect(ivg.locator('.lista-oficio').getByRole('link', { name: new RegExp(`Baixar tabela.*lista ${nLista}`) })).toBeVisible({ timeout: 15_000 })
    await barra.getByRole('button', { name: 'Encerrar' }).click()
    await expect(barra.getByRole('button', { name: /Iniciar sessão de análise/ })).toBeVisible({ timeout: 15_000 })
    await expect(ivg.getByRole('columnheader', { name: 'Valor revelado' })).toHaveCount(0)
    await expect(ivg.locator('.marca-dagua')).toHaveCount(0)
    await expect(ivg.locator('body')).not.toContainText(valor)
    await expect(ivg.locator('body')).not.toContainText(CPF)
  })
}
