import { test } from '@playwright/test'
import path from 'node:path'
import { abrir, entrar, type Tema } from './ajuda'
import { TELAS } from './telas'

/** Capturas das telas principais (só dados dos dublês) em docs/capturas/w2/. Rode com `npm run capturas`. */
const PRINCIPAIS = ['inicio-solicitante', 'inicio-aprovador', 'investigacoes', 'nova-passo1', 'nova-passo2-expiracao', 'resumo-devolvida',
  'acompanhamento', 'pacotes', 'aprovacoes', 'decisao-investigacao', 'decisao-aprovar-dialogo', 'decisao-pacote', 'administracao', 'perfis',
  'trilha-global', 'sem-acesso', 'erro-servidor', 'notificacoes', 'sessao-expirada']
const DESTINO = path.resolve(import.meta.dirname, '../../docs/capturas/w2')

test.skip(!process.env.CAPTURAS, 'só com CAPTURAS=1')

for (const tema of ['claro', 'escuro'] as Tema[]) {
  for (const t of TELAS.filter((x) => PRINCIPAIS.includes(x.nome))) {
    test(`captura ${t.nome} ${tema}`, async ({ page }) => {
      await entrar(page, t.perfil, tema)
      await abrir(page, t.rota)
      if (t.preparar) await t.preparar(page)
      await page.waitForTimeout(300)
      await page.screenshot({ path: `${DESTINO}/${t.nome}-${tema}.png`, fullPage: !t.nome.includes('dialogo') })
    })
  }
}
