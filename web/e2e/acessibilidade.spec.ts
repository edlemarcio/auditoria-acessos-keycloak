import { test } from '@playwright/test'
import { abrir, entrar, semViolacoes, type Tema } from './ajuda'
import { TELAS } from './telas'

for (const tema of ['claro', 'escuro'] as Tema[]) {
  test.describe(`axe · tema ${tema}`, () => {
    for (const t of TELAS) {
      test(`${t.nome}`, async ({ page }) => {
        await entrar(page, t.perfil, tema)
        await abrir(page, t.rota)
        if (t.preparar) await t.preparar(page)
        await semViolacoes(page, `${t.nome} (${tema})`)
      })
    }
  })
}
