import { http, HttpResponse } from 'msw'
import { vi } from 'vitest'
import { servidor } from '../testes/preparar'
import { api, ErroApi, navegador, postar, quandoSessaoExpirar } from './cliente'
import { lerEventos } from './aoVivo'
import { listarInvestigacoes } from './rotas'

describe('cliente da API', () => {
  it('manda X-Requisicao em POST/PUT/DELETE e não em GET', async () => {
    const vistos: (string | null)[] = []
    servidor.use(http.all('/api/x', ({ request }) => { vistos.push(request.headers.get('X-Requisicao')); return HttpResponse.json({}) }))
    await api('/api/x')
    await postar('/api/x', {})
    await api('/api/x', { metodo: 'PUT', corpo: {} })
    await api('/api/x', { metodo: 'DELETE' })
    expect(vistos).toEqual([null, 'kc-auditor', 'kc-auditor', 'kc-auditor'])
  })

  it('401 step_up leva ao login com step_up=1 e volta para a tela', async () => {
    const ir = vi.spyOn(navegador, 'ir').mockImplementation(() => {})
    window.history.pushState({}, '', '/aprovacoes/7?inv=3')
    servidor.use(http.post('/api/y', () => HttpResponse.json({ codigo: 'step_up', texto: 'recente' }, { status: 401 })))
    await expect(postar('/api/y', {}, 'aprovar:3')).rejects.toBeInstanceOf(ErroApi)
    expect(ir).toHaveBeenCalledWith('/auth/entrar?step_up=1&volta=%2Faprovacoes%2F7%3Finv%3D3')
    // guarda só o nome da ação, nada digitado
    expect(sessionStorage.getItem('kc-auditor:retomar')).toContain('"acao":"aprovar:3"')
    ir.mockRestore()
  })

  it('401 sem sessão avisa a tela (sessão expirada)', async () => {
    const f = vi.fn()
    quandoSessaoExpirar(f)
    servidor.use(http.get('/api/z', () => HttpResponse.json({ erro: 'sem_sessao', mensagem: 'Autenticação exigida' }, { status: 401 })))
    await expect(api('/api/z')).rejects.toMatchObject({ status: 401, codigo: 'sem_sessao' })
    expect(f).toHaveBeenCalled()
  })

  it('erro 500 traz o código de correlação; formato do W1 também é lido', async () => {
    servidor.use(http.get('/api/a', () => HttpResponse.json({ codigo: 'interno', texto: 'x', correlacao: '7F2A-91C0' }, { status: 500 })),
      http.get('/api/b', () => HttpResponse.json({ erro: 'perfil', mensagem: 'Exige o perfil aprovador' }, { status: 403 })))
    await expect(api('/api/a')).rejects.toMatchObject({ correlacao: '7F2A-91C0', codigo: 'interno' })
    await expect(api('/api/b')).rejects.toMatchObject({ codigo: 'perfil', message: 'Exige o perfil aprovador' })
  })

  it('lista do W1 (array puro) vira página do contrato', async () => {
    servidor.use(http.get('/api/investigacoes', () => HttpResponse.json([{ id: 3, status: 'aprovada', alvo: '***.1-**', inicio_ms: 0, fim_ms: 86_400_000, externo: true }])))
    const p = await listarInvestigacoes({})
    expect(p).toMatchObject({ total: 1, pagina: 1, itens: [{ id: 3, alvo_mascarado: '***.1-**', origem_externa: true, acoes: [] }] })
  })
})

describe('SSE', () => {
  it('separa eventos, ids e guarda o resto incompleto', () => {
    const { eventos, resto } = lerEventos('id: 4\nevent: progresso\ndata: {"a":1}\n\n: comentario\n\nevent: heartbeat\ndata: \n\nid: 5\ndata: {"b"')
    expect(eventos).toEqual([{ id: '4', event: 'progresso', data: '{"a":1}' }, { event: 'heartbeat', data: '' }])
    expect(resto).toBe('id: 5\ndata: {"b"')
  })
})
