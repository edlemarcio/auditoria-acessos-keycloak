import { expect, test } from '@playwright/test'
import { semViolacoes } from './ajuda'

/**
 * Aceite do W2: pedir, aprovar, coletar, pausar, retomar e concluir uma investigação de 180 dias só pela web,
 * com três pessoas diferentes (solicitante1, aprovador1, investigador1), cada uma com login real (senha + OTP).
 * O CPF do alvo vem da massa de teste (dados/pessoas.json) e não pode aparecer em URL nem na tela depois de validado.
 */
import { CPF as cpf, login } from './login_real'

const iso = (d: Date) => d.toISOString().slice(0, 10)

test('W2: investigação de 180 dias do pedido à conclusão só pela web', async ({ browser }) => {
  // ---- solicitante: assistente
  const sol = await login(browser, 'solicitante1', '/nova')
  await sol.getByRole('textbox', { name: 'CPF' }).fill(cpf)
  await sol.getByRole('textbox', { name: 'CPF' }).press('Tab')
  await expect(sol.getByRole('textbox', { name: 'CPF' })).not.toHaveValue(cpf)
  await sol.getByRole('button', { name: /Próximo/ }).click()
  const ate = new Date(); const de = new Date(ate.getTime() - 179 * 86_400_000)
  await sol.getByLabel(/Início do período/).fill(iso(de))
  await sol.getByLabel(/Fim do período/).fill(iso(ate))
  await expect(sol.locator('.expiracao .esqueleto')).toHaveCount(0, { timeout: 20_000 })
  await semViolacoes(sol, 'assistente passo 2 (real)')
  await sol.getByRole('button', { name: /Próximo/ }).click()
  await sol.getByRole('button', { name: /Próximo/ }).click()
  await sol.getByRole('combobox', { name: /Tipo de processo/ }).selectOption({ index: 1 })
  await sol.getByRole('textbox', { name: /Nº do processo/ }).fill('0009999-12.2026.6.05.0000')
  await sol.getByRole('textbox', { name: /Justificativa/ }).fill('Aceite do W2: acessos no período de 180 dias')
  await sol.getByRole('button', { name: /Próximo/ }).click()
  await expect(sol.getByText(/\d+ tarefas/)).toBeVisible({ timeout: 20_000 })
  await sol.getByRole('button', { name: /Enviar pedido/ }).click()
  await expect(sol).toHaveURL(/\/investigacoes\/\d+$/)
  const inv = Number(sol.url().split('/').pop())
  await expect(sol.locator('.cabecalho-investigacao')).toContainText('Aguardando aprovação')
  await expect(sol.locator('body')).not.toContainText(cpf)
  await semViolacoes(sol, 'resumo do solicitante (real)')
  console.log(`investigação ${inv} pedida`)

  // ---- aprovador: fila → decisão → aprovar designando investigador1
  const apr = await login(browser, 'aprovador1', '/aprovacoes')
  await semViolacoes(apr, 'fila de aprovações (real)')
  await apr.locator(`a[href*="inv=${inv}&"]`).first().click()
  await expect(apr.getByRole('heading', { level: 1 })).toContainText(String(inv))
  await semViolacoes(apr, 'tela de decisão (real)')
  await apr.getByRole('button', { name: 'Aprovar', exact: true }).click()
  await apr.getByRole('textbox', { name: /Investigador designado/ }).fill('investigador1')
  await apr.getByRole('textbox', { name: /Motivo/ }).fill('Pedido completo e com fundamento')
  await apr.getByRole('button', { name: /Confirmar: aprovar/ }).click()
  await expect(apr.getByText(/aprovado/i).first()).toBeVisible({ timeout: 20_000 })

  // ---- investigador: iniciar, pausar, retomar, concluir
  const ivg = await login(browser, 'investigador1', `/investigacoes/${inv}`)
  const cab = ivg.locator('.cabecalho-investigacao')
  await expect(cab).toContainText('Aprovada', { timeout: 30_000 })
  await ivg.getByRole('button', { name: 'Iniciar coleta' }).click()
  await expect(cab).toContainText(/Coletando|Preparando/, { timeout: 30_000 })
  await expect(ivg.getByRole('button', { name: 'Pausar' })).toBeVisible({ timeout: 120_000 })
  await expect(ivg.locator('.acompanhamento')).toContainText('Ao vivo', { timeout: 30_000 })
  await semViolacoes(ivg, 'acompanhamento ao vivo (real)')
  await ivg.getByRole('button', { name: 'Pausar' }).click()
  await expect(cab).toContainText('Pausada', { timeout: 60_000 })
  await ivg.getByRole('button', { name: 'Retomar' }).click()
  await expect(cab).toContainText(/Coletando|Preparando|Concluída/, { timeout: 60_000 })
  await expect(cab).toContainText(/Concluída/, { timeout: 780_000 })
  await semViolacoes(ivg, 'investigação concluída (real)')
  await ivg.screenshot({ path: 'test-results/aceite-concluida.png', fullPage: true })

  // ---- solicitante vê a conclusão, sem o CPF
  await sol.reload()
  await expect(sol.locator('.cabecalho-investigacao')).toContainText(/Concluída/, { timeout: 20_000 })
  await expect(sol.locator('body')).not.toContainText(cpf)
})
