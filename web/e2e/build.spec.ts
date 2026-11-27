import { expect, test } from '@playwright/test'

test('build sob CSP default-src self: sem violação, sem dublês, fontes e ícones locais', async ({ page }) => {
  const problemas: string[] = []
  const hosts = new Set<string>()
  page.on('console', (m) => { if (/Content Security Policy|Refused to/i.test(m.text())) problemas.push(m.text()) })
  page.on('pageerror', (e) => problemas.push(String(e)))
  page.on('request', (r) => hosts.add(new URL(r.url()).host))
  // sem API por trás do preview: respostas mínimas só para a tela montar; o que importa aqui é o carregamento sob a CSP
  // (no Playwright a rota registrada por último tem prioridade)
  await page.route('**/api/**', (r) => r.fulfill({ status: 200, contentType: 'application/json', body: '[]' }))
  await page.route('**/api/inicio', (r) => r.fulfill({ status: 200, contentType: 'application/json',
    body: JSON.stringify({ perfil: ['admin_tecnico'], aguardando_minha_decisao: [], minhas_por_estado: {}, alertas: [], nao_lidas: 0 }) }))
  await page.route('**/api/eu', (r) => r.fulfill({ status: 200, contentType: 'application/json',
    body: JSON.stringify({ sub: 'x', usuario: 'teste', nome: 'Teste', papeis: ['admin_tecnico'] }) }))
  await page.goto('/')
  await expect(page.getByRole('heading', { level: 1 })).toContainText('Olá')
  const fontes = () => page.evaluate(async () => {
    await document.fonts.ready
    return [...new Set([...document.fonts].filter((f) => f.status === 'loaded').map((f) => f.family.replace(/"/g, '')))]
  })
  await expect.poll(fontes).toEqual(expect.arrayContaining(['Raleway']))
  await expect.poll(async () => (await fontes()).some((f) => /Font Awesome/.test(f))).toBe(true)
  expect(problemas).toEqual([])
  expect([...hosts]).toEqual(['localhost:4173'])
  expect(await page.evaluate(() => 'msw' in window || !!navigator.serviceWorker?.controller)).toBe(false)
})
