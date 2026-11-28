import { expect, test, type Page } from '@playwright/test'
import { readFileSync } from 'node:fs'
import { semViolacoes } from './ajuda'
import { CPF, login } from './login_real'

/**
 * Aceite das telas da W5 contra a API integrada em :8000 (worker de pacotes com a ACT de homologação):
 * o investigador gera o pacote v2 e vê a verificação em linguagem simples (detalhe técnico recolhível); baixa o pacote
 * e o confere em "Verificar pacote" (upload para o worker, só chaves publicadas); abre o diálogo de reexecução; vê
 * "Comparar execuções" numa reexecução (E2E_INV_COMPARAR). O Solicitante baixa o relatório agregado em PDF.
 * Nos temas claro e escuro, com axe sem violações. Investigação E2E_INV (padrão: a do aceite da W2).
 */
const INV = Number(process.env.E2E_INV ?? 14)
const COMPARAR = process.env.E2E_INV_COMPARAR ? Number(process.env.E2E_INV_COMPARAR) : null

async function pronto(p: Page) {
  await expect(p.locator('#titulo-tela')).toBeVisible()
  await expect(p.locator('.esqueleto')).toHaveCount(0, { timeout: 30_000 })
}

for (const tema of ['claro', 'escuro'] as const) {
  test(`W5 (${tema}): pacote v2 verificado, verificação pela web, reexecução, comparação e relatório agregado`, async ({ browser }) => {
    const ivg = await login(browser, 'investigador1', `/investigacoes/${INV}/pacotes`, tema)
    await pronto(ivg)
    const linhas = ivg.getByRole('region', { name: 'Pacotes' }).locator('tbody tr')
    const antes = await linhas.count().catch(() => 0)
    await ivg.getByRole('button', { name: 'Gerar pacote mascarado' }).click()
    await expect(ivg.getByText(/Pacote mascarado pedido/)).toBeVisible()
    await expect(linhas).toHaveCount(antes + 1, { timeout: 30_000 })
    const novo = linhas.last()
    await expect(novo).toContainText(/Pacote íntegro, assinado pela chave/, { timeout: 300_000 })
    await expect(novo).toContainText(/_v\d+\.zip/)
    await novo.locator('summary').click()
    await expect(novo.locator('.itens-verificacao')).toContainText('recalcular: KPIs')
    await semViolacoes(ivg, `pacotes v2 (${tema})`)
    await ivg.screenshot({ path: `test-results/w5-pacotes-${tema}.png`, fullPage: true })

    // download (link de uso único) e verificação pela web
    await novo.getByRole('button', { name: /Gerar link de download/ }).click()
    const dl = ivg.waitForEvent('download')
    await novo.getByRole('link', { name: /^Baixar investigacao_/ }).click()
    const arquivo = await (await dl).path()
    expect(readFileSync(arquivo).subarray(0, 2).toString()).toBe('PK')
    await ivg.goto('/verificar-pacote')
    await pronto(ivg)
    await semViolacoes(ivg, `verificar pacote (${tema})`)
    await ivg.getByLabel(/Pacote \(\.zip/).setInputFiles({ name: 'pacote.zip', mimeType: 'application/zip',
      buffer: readFileSync(arquivo) })
    await ivg.getByRole('button', { name: 'Verificar' }).click()
    await expect(ivg.getByText(/Pacote íntegro, assinado pela chave/)).toBeVisible({ timeout: 180_000 })
    await expect(ivg.getByText(/SHA-256 do arquivo enviado/)).toBeVisible()
    await semViolacoes(ivg, `resultado da verificação (${tema})`)
    await ivg.screenshot({ path: `test-results/w5-verificar-${tema}.png`, fullPage: true })
    // um pacote adulterado (um byte trocado no fim) não confere
    const ruim = Buffer.from(readFileSync(arquivo))
    ruim[ruim.length - 30] ^= 0xff
    await ivg.getByLabel(/Pacote \(\.zip/).setInputFiles({ name: 'adulterado.zip', mimeType: 'application/zip', buffer: ruim })
    await ivg.getByRole('button', { name: 'Verificar' }).click()
    await expect(ivg.getByText(/Pacote NÃO íntegro|Não foi possível verificar|não confere/).first()).toBeVisible({ timeout: 180_000 })

    // reexecução: diálogo (não cria nada)
    await ivg.goto(`/investigacoes/${INV}`)
    await pronto(ivg)
    await ivg.getByRole('button', { name: 'Reexecutar' }).click()
    const dlg = ivg.getByRole('dialog', { name: /^Reexecutar/ })
    await expect(dlg).toContainText('nova investigação vinculada')
    await semViolacoes(ivg, `diálogo de reexecução (${tema})`)
    await dlg.getByRole('button', { name: 'Voltar' }).click()

    // comparar execuções
    if (COMPARAR) {
      await ivg.goto(`/investigacoes/${COMPARAR}/comparar`)
      await pronto(ivg)
      await expect(ivg.getByRole('list', { name: 'Totais da comparação' })).toBeVisible({ timeout: 60_000 })
      await expect(ivg.getByRole('heading', { name: /Eventos que deixaram de existir/ })).toBeVisible()
      await expect(ivg.locator('body')).not.toContainText(/\b\d{1,3}(\.\d{1,3}){3}\b/)
      await semViolacoes(ivg, `comparar execuções (${tema})`)
      await ivg.screenshot({ path: `test-results/w5-comparar-${tema}.png`, fullPage: true })
    }
    await expect(ivg.locator('body')).not.toContainText(CPF)

    // solicitante: relatório agregado em PDF, sem a lista de pacotes
    const sol = await login(browser, 'solicitante1', `/investigacoes/${INV}/pacotes`, tema)
    await pronto(sol)
    const link = sol.getByRole('link', { name: /relatório agregado em PDF/ })
    await expect(link).toBeVisible()
    await semViolacoes(sol, `pacotes do solicitante (${tema})`)
    const r = await sol.request.get(await link.getAttribute('href') as string)
    expect(r.status()).toBe(200)
    expect(r.headers()['content-type']).toBe('application/pdf')
    expect((await r.body()).subarray(0, 5).toString()).toBe('%PDF-')
  })
}
