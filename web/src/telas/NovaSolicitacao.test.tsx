import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { servidor, sessaoDuble } from '../testes/preparar'
import { EU, localAtual, renderizar } from '../testes/renderizar'
import { completarTitulo } from '../dominio/documentos'
import { NovaSolicitacao } from './NovaSolicitacao'

const CPF = '529.982.247-25'
const DIGITOS = '52998224725'

function capturarPedidos() {
  const corpos: Record<string, unknown>[] = []
  servidor.events.on('request:start', async ({ request }) => {
    if (request.method === 'POST' && new URL(request.url).pathname === '/api/investigacoes') corpos.push(await request.clone().json())
  })
  return corpos
}

describe('assistente de nova solicitação (§7.4)', () => {
  beforeEach(() => sessaoDuble('solicitante'))
  afterEach(() => servidor.events.removeAllListeners())

  it('valida o DV ao sair do campo, liga o erro ao campo e não avança', async () => {
    const u = userEvent.setup()
    renderizar(<NovaSolicitacao />, { rota: '/nova' })
    const campo = screen.getByRole('textbox', { name: /CPF/ })
    await u.type(campo, '123.456.789-00')
    await u.tab()
    await screen.findAllByText(/dígitos verificadores/)
    expect(campo).toHaveAttribute('aria-invalid', 'true')
    const descr = campo.getAttribute('aria-describedby')!.split(' ').map((id) => document.getElementById(id)?.textContent).join(' ')
    expect(descr).toMatch(/dígitos verificadores/)
    await u.click(screen.getByRole('button', { name: /Próximo/ }))
    expect(screen.getByRole('heading', { name: /Passo 1 de 5/ })).toBeInTheDocument()
    expect(screen.getByRole('alert', { name: /erros/ })).toBeInTheDocument()
  })

  it('depois de validado mostra só a máscara; o valor completo nunca reaparece nem vai para o armazenamento', async () => {
    const u = userEvent.setup()
    const corpos = capturarPedidos()
    const { container } = renderizar(<NovaSolicitacao />, { rota: '/nova' })
    await u.type(screen.getByRole('textbox', { name: /CPF/ }), CPF)
    await u.tab()
    expect(await screen.findByDisplayValue('***.982.247-**')).toHaveAttribute('readonly')
    const semVazar = () => {
      expect(container.innerHTML).not.toContain(DIGITOS)
      expect(container.innerHTML).not.toContain(CPF)
      expect(container.innerHTML).not.toContain('982.247-25')
    }
    semVazar()
    // passo 2: estimativa e alerta de expiração com "Pedir preservação urgente"
    await u.click(screen.getByRole('button', { name: /Próximo/ }))
    expect(screen.getByRole('heading', { name: /Passo 2 de 5 · Quando/ })).toHaveFocus()
    const pedirPreservacao = await screen.findByRole('button', { name: 'Pedir preservação urgente' })
    await u.click(pedirPreservacao)
    expect(screen.getByRole('button', { name: 'Preservação urgente pedida' })).toHaveAttribute('aria-pressed', 'true')
    semVazar()
    await u.click(screen.getByRole('button', { name: /Próximo/ }))
    await u.click(screen.getByRole('button', { name: /Próximo/ }))
    // passo 4: tipo de processo, processo e justificativa obrigatórios
    await u.click(screen.getByRole('button', { name: /Próximo/ }))
    expect(screen.getAllByText(/Escolha o tipo de processo/).length).toBeGreaterThan(0)
    await u.selectOptions(screen.getByRole('combobox', { name: /Tipo de processo/ }), 'apuracao_disciplinar')
    await u.type(screen.getByRole('textbox', { name: /Nº do processo/ }), '0001234-12.2026.6.05.0000')
    await u.type(screen.getByRole('textbox', { name: /Justificativa/ }), `Acessos do ${CPF} fora do expediente`)
    await u.click(screen.getByRole('button', { name: /Próximo/ }))
    expect(screen.getAllByText(/Não repita o CPF/).length).toBeGreaterThan(0)
    await u.clear(screen.getByRole('textbox', { name: /Justificativa/ }))
    await u.type(screen.getByRole('textbox', { name: /Justificativa/ }), 'Acessos fora do expediente ao sistema de pessoal')
    await u.click(screen.getByRole('button', { name: /Próximo/ }))
    // passo 5: revisão com a máscara e a estimativa
    const revisao = screen.getByRole('heading', { name: /Passo 5 de 5/ }).parentElement!
    expect(within(revisao).getByText('***.982.247-**')).toBeInTheDocument()
    await waitFor(() => expect(within(revisao).getByText(/tarefas/)).toBeInTheDocument())
    semVazar()
    await u.click(screen.getByRole('button', { name: /Enviar pedido/ }))
    await waitFor(() => expect(localAtual).toMatch(/^\/investigacoes\/\d+$/))
    expect(corpos).toHaveLength(1)
    expect(corpos[0]).toMatchObject({ cpf: DIGITOS, preservacao_urgente: true, tipo_processo: 'apuracao_disciplinar', rascunho: false })
    expect(JSON.stringify({ ...localStorage })).not.toContain(DIGITOS)
    expect(JSON.stringify({ ...sessionStorage })).not.toContain(DIGITOS)
    expect(localAtual).not.toContain(DIGITOS)
  })

  it('aceita título de eleitor e salva rascunho', async () => {
    const u = userEvent.setup()
    const corpos = capturarPedidos()
    renderizar(<NovaSolicitacao />, { rota: '/nova' })
    await u.click(screen.getByRole('radio', { name: 'Título de Eleitor' }))
    const t = completarTitulo('10234567', '05')
    await u.type(screen.getByRole('textbox', { name: /Título de Eleitor/ }), `${t.slice(0, 4)} ${t.slice(4, 8)} ${t.slice(8)}`)
    await u.tab()
    expect(await screen.findByDisplayValue('**** 4567 ****')).toBeInTheDocument()
    await u.click(screen.getByRole('button', { name: /Salvar rascunho/ }))
    expect(await screen.findByText(/Rascunho nº \d+ salvo/)).toBeInTheDocument()
    expect(corpos[0]).toMatchObject({ titulo: t, rascunho: true })
  })

  it('"Trocar identificador" limpa tudo e pede de novo', async () => {
    const u = userEvent.setup()
    renderizar(<NovaSolicitacao />, { rota: '/nova' })
    await u.type(screen.getByRole('textbox', { name: /CPF/ }), CPF)
    await u.tab()
    await u.click(await screen.findByRole('button', { name: 'Trocar identificador' }))
    expect(screen.getByRole('textbox', { name: /CPF/ })).toHaveValue('')
  })

  it('pedido externo exige órgão, ofício, fundamento e documento; envia como rascunho, anexa e envia', async () => {
    sessaoDuble('investigador')
    const u = userEvent.setup()
    const caminho: string[] = []
    servidor.events.on('request:start', ({ request }) => { if (request.method !== 'GET') caminho.push(`${request.method} ${new URL(request.url).pathname}`) })
    renderizar(<NovaSolicitacao />, { rota: '/nova?externo=1', eu: EU.investigador })
    expect(screen.getByRole('heading', { name: 'Registrar pedido externo', level: 1 })).toBeInTheDocument()
    await u.type(screen.getByRole('textbox', { name: /CPF/ }), CPF)
    await u.tab()
    for (let k = 0; k < 3; k++) await u.click(screen.getByRole('button', { name: /Próximo/ }))
    await u.type(screen.getByRole('textbox', { name: /Nº do processo/ }), '0009-1')
    await u.type(screen.getByRole('textbox', { name: /Justificativa/ }), 'Ofício do MPE pedindo os acessos')
    await u.click(screen.getByRole('button', { name: /Próximo/ }))
    expect(screen.getAllByText(/exige o documento de origem/).length).toBeGreaterThan(0)
    await u.type(screen.getByRole('textbox', { name: /Órgão de origem/ }), 'Ministério Público Eleitoral')
    await u.type(screen.getByRole('textbox', { name: /Nº do ofício/ }), 'Ofício 9/2026')
    await u.type(screen.getByRole('textbox', { name: /Fundamento legal/ }), 'Requisição em procedimento')
    await u.upload(screen.getByLabelText(/Documento de origem/), new File(['%PDF'], 'oficio.pdf', { type: 'application/pdf' }))
    await u.click(screen.getByRole('button', { name: /Próximo/ }))
    await u.click(screen.getByRole('button', { name: /Enviar pedido/ }))
    await waitFor(() => expect(localAtual).toMatch(/^\/investigacoes\/\d+$/), { timeout: 5000 })
    expect(caminho.filter((c) => !c.includes('estimativas'))).toEqual(['POST /api/investigacoes', expect.stringMatching(/POST \/api\/investigacoes\/\d+\/documento/),
      expect.stringMatching(/POST \/api\/investigacoes\/\d+\/enviar/)])
  })

  it('mostra o erro do servidor sem perder o que foi preenchido', async () => {
    servidor.use(http.post('/api/investigacoes', () => HttpResponse.json({ codigo: 'interno', texto: 'x', correlacao: 'AB12-CD34' }, { status: 500 })))
    const u = userEvent.setup()
    renderizar(<NovaSolicitacao />, { rota: '/nova' })
    await u.type(screen.getByRole('textbox', { name: /CPF/ }), CPF)
    await u.tab()
    await u.click(screen.getByRole('button', { name: /Salvar rascunho/ }))
    expect(await screen.findByText(/AB12-CD34/)).toBeInTheDocument()
    expect(screen.getByDisplayValue('***.982.247-**')).toBeInTheDocument()
  })
})
