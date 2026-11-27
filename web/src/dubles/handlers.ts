/**
 * Dublês das rotas do contrato W2 (docs/W2_CONTRATO.md) e das rotas do W1, à risca: mesmas URLs, corpos e erros.
 * Escolha do perfil: cookie `dubles_perfil` (solicitante, investigador, aprovador, auditor_interno, admin_tecnico,
 * gestor_acesso, aprovinvest). Sessão: cookie `dubles_sessao` (posto pelo /auth/entrar de mentira do vite.config.ts).
 * Step-up: cookie `dubles_step_up` com o horário do último /auth/entrar?step_up=1 (vale 5 min).
 */
import { http, HttpResponse, delay } from 'msw'
import type { Acompanhamento, Detalhe, Estimativa, Notificacao, Pacote } from '../api/tipos'
import { acoesPara, notificacoesSemente, pacotesSemente, PERFIS, podeVer, semente, USUARIOS, type InvDuble,
  type UsuarioDuble } from './dados'

interface Estado { invs: InvDuble[]; notif: Notificacao[]; pacotes: Record<number, Pacote[]>; seq: number;
  substitutos: Record<string, string | null>; recert: { id: number; criada_em: string; prazo: string; concluida_em: string | null;
    pendentes: { username: string; papeis: string[] }[] }[]; papeis: Record<string, string[]> }

export let estado: Estado
export function reiniciar() {
  estado = { invs: semente(), notif: notificacoesSemente(), pacotes: pacotesSemente(), seq: 42, substitutos: { aprovador1: 'aprovinvest1' },
    recert: [], papeis: Object.fromEntries(PERFIS.map((p) => [p.username, [...p.papeis]])) }
}
reiniciar()

type C = Record<string, string>
const erro = (status: number, codigo: string, texto: string, extra: object = {}) =>
  HttpResponse.json({ codigo, texto, ...extra }, { status })
const semAcesso = () => erro(404, 'sem_acesso', 'Investigação inexistente ou sem vínculo')

function quem(c: C): UsuarioDuble | null {
  if (!c.dubles_sessao) return null
  return USUARIOS[c.dubles_perfil ?? 'solicitante'] ?? USUARIOS.solicitante
}
const recente = (c: C) => Date.now() - Number(c.dubles_step_up ?? 0) < 5 * 60_000

function csrf(r: Request) { return r.headers.get('X-Requisicao') === 'kc-auditor' }

/** Envolve um resolver com sessão, CSRF e step-up. */
function com<P extends Record<string, string>>(f: (x: { u: UsuarioDuble; request: Request; params: P; cookies: C }) => Response | Promise<Response>,
  opc: { stepUp?: boolean; papeis?: string[] } = {}) {
  return async ({ request, params, cookies }: { request: Request; params: P; cookies: C }) => {
    await delay(60)
    const u = quem(cookies)
    if (!u) return erro(401, 'sem_sessao', 'Autenticação exigida')
    if (request.method !== 'GET' && !csrf(request)) return erro(403, 'csrf', 'Cabeçalho X-Requisicao ausente')
    if (opc.papeis && !opc.papeis.some((p) => u.papeis.includes(p))) return erro(403, 'perfil', `Exige o perfil ${opc.papeis.join(' ou ')}`)
    if (opc.stepUp && !recente(cookies)) return erro(401, 'step_up', 'Esta ação exige autenticação recente')
    return f({ u, request, params, cookies })
  }
}

function achar(id: string | number, u: UsuarioDuble): InvDuble | Response {
  if (Number(id) === 999) return erro(500, 'interno', 'Erro inesperado', { correlacao: '7F2A-91C0' })
  const i = estado.invs.find((x) => x.id === Number(id))
  if (!i || !podeVer(i, u)) return semAcesso()
  return i
}

function visaoLista(i: InvDuble, u: UsuarioDuble) {
  const auditor = u.papeis.includes('auditor_interno') && !podeVerComoParte(i, u)
  return { id: i.id, status: i.status, ...(auditor ? {} : { alvo_mascarado: i.alvo_mascarado }), de: i.de, ate: i.ate, fuso: i.fuso,
    processo: i.processo, solicitante: i.solicitante, investigador: i.investigador, criado_em: i.criado_em,
    atualizado_em: i.atualizado_em, progresso_pct: i.progresso_pct, origem_externa: i.origem_externa, sigilosa: i.sigilosa,
    acoes: acoesPara(i, u) }
}
const podeVerComoParte = (i: InvDuble, u: UsuarioDuble) => i.solicitante_usuario === u.usuario || i.investigador_usuario === u.usuario

function visaoDetalhe(i: InvDuble, u: UsuarioDuble): Detalhe {
  const auditor = u.papeis.includes('auditor_interno') && !podeVerComoParte(i, u)
  const parte = !auditor
  const d = { ...visaoLista(i, u), tipo: parte ? i.tipo : undefined, tipo_processo: i.tipo_processo, granularidade: i.granularidade,
    instancias: i.instancias, varredura: i.varredura, base_dias: i.base_dias,
    justificativa: parte ? i.justificativa : undefined, origem: parte ? i.origem : undefined,
    linha_do_tempo: i.linha_do_tempo.map((p) => ({ ...p, motivo: parte ? p.motivo : undefined })),
    expiracao: i.expiracao, estimativa: i.estimativa, documento: i.documento, preservacao: i.preservacao } as Detalhe
  return d
}

function marcar(i: InvDuble, status: string, u: UsuarioDuble, motivo?: string) {
  i.status = status
  i.atualizado_em = new Date().toISOString()
  i.linha_do_tempo = [...i.linha_do_tempo, { status, quando: i.atualizado_em, por: u.nome, motivo }]
}

const motivoOk = (m: unknown) => typeof m === 'string' && m.trim().length >= 5
const faltaMotivo = () => erro(422, 'motivo', 'Motivo obrigatório (mínimo de 5 caracteres)')

function transicao(acao: string, aplicar: (i: InvDuble, u: UsuarioDuble, corpo: Record<string, unknown>) => Response | void,
  opc: { stepUp?: boolean; motivo?: boolean } = {}) {
  return http.post(`/api/investigacoes/:id/${acao.replace(/_/g, '-')}`, com<{ id: string }>(async ({ u, request, params }) => {
    const i = achar(params.id, u)
    if (i instanceof Response) return i
    if (!acoesPara(i, u).includes(acao as never)) return erro(409, 'estado', 'Ação indisponível neste estado')
    const corpo = (await request.json().catch(() => ({}))) as Record<string, unknown>
    if (opc.motivo && !motivoOk(corpo.motivo)) return faltaMotivo()
    const r = aplicar(i, u, corpo)
    return r ?? HttpResponse.json({ investigacao: i.id, status: i.status })
  }, { stepUp: opc.stepUp }))
}

function expiracaoPara(de: string): Estimativa['expiracao'] {
  const antigo = new Date(de).getTime() < Date.now() - 178 * 86_400_000
  return [
    { instancia: 'kc26', realm: 'intranet', eventos_desde: new Date(Date.now() - 181 * 86_400_000).toISOString(), expira_antes_da_aprovacao: antigo },
    { instancia: 'kc26', realm: 'portal', eventos_desde: new Date(Date.now() - 365 * 86_400_000).toISOString(), expira_antes_da_aprovacao: false },
    { instancia: 'kc18', realm: 'legado', eventos_desde: null, expira_antes_da_aprovacao: false },
  ]
}

function corpoParaInv(c: Record<string, unknown>, u: UsuarioDuble, id: number, base?: InvDuble): InvDuble {
  const tipo = c.titulo ? 'titulo' : c.cpf ? 'cpf' : base?.tipo ?? 'cpf'
  const d = String(c.cpf ?? c.titulo ?? '').replace(/\D/g, '')
  const alvo = d ? (tipo === 'cpf' ? `***.${d.slice(3, 6)}.${d.slice(6, 9)}-**` : `**** ${d.slice(4, 8)} ****`) : base?.alvo_mascarado
  const origem = (c.origem as Record<string, string> | null) ?? null
  return { ...(base ?? {} as InvDuble), id, status: base?.status ?? 'rascunho', alvo_mascarado: alvo, tipo, de: String(c.de), ate: String(c.ate),
    fuso: String(c.fuso ?? 'America/Bahia'), granularidade: String(c.granularidade ?? 'dia'), processo: (c.processo as string) ?? null,
    instancias: (c.instancias as string[]) ?? null, varredura: Boolean(c.varredura), base_dias: Number(c.base_dias ?? 0),
    justificativa: String(c.justificativa ?? ''), tipo_processo: String(c.tipo_processo ?? ''), origem, origem_externa: Boolean(origem),
    solicitante: origem ? origem.orgao : u.nome, solicitante_usuario: u.usuario, criado_em: base?.criado_em ?? new Date().toISOString(),
    atualizado_em: new Date().toISOString(), sigilosa: false, preservacao_pedida: Boolean(c.preservacao_urgente),
    expiracao: expiracaoPara(String(c.de)), estimativa: { tarefas: 360, segundos: 1500 }, documento: base?.documento ?? null,
    preservacao: null, linha_do_tempo: base?.linha_do_tempo ?? [] }
}

function validarPedido(c: Record<string, unknown>, u: UsuarioDuble, rascunho: boolean): Response | null {
  if (c.origem ? !u.papeis.some((p) => p === 'investigador' || p === 'solicitante') : !u.papeis.includes('solicitante'))
    return erro(403, 'perfil', 'Exige o perfil solicitante')
  if (!rascunho && !motivoOk(c.justificativa)) return faltaMotivo()
  if (!c.de || !c.ate) return erro(422, 'periodo', 'Informe o período')
  return null
}

const progressoDe = (i: InvDuble, passo: number): Acompanhamento => {
  const pct = Math.min(99, (i.progresso_interno ?? 0) + (i.status === 'coletando' ? passo : 0))
  const concl = Math.round(pct * 0.6)
  return { status: i.status, progresso_pct: pct, eventos: pct * 260, falhas: 1, retentativas: 4,
    termino_estimado: new Date(Date.now() + (100 - pct) * 60_000).toISOString(),
    instancias: [
      { nome: 'kc26', tarefas: { pendente: 60 - concl, executando: i.status === 'coletando' ? 2 : 0, concluida: concl, falhou: 1 },
        req_por_s: i.status === 'coletando' ? 4.2 : 0, orcamento_req_por_s: 5, fora_do_ar_desde: null },
      { nome: 'kc18', tarefas: { pendente: 12, executando: 0, concluida: 8, falhou: 0 }, req_por_s: 0, orcamento_req_por_s: 3,
        fora_do_ar_desde: i.status === 'coletando' ? new Date(Date.now() - 12 * 60_000).toISOString() : null },
    ] }
}

export const handlers = [
  http.get('/api/eu', com(({ u }) => HttpResponse.json({ sub: u.sub, usuario: u.usuario, nome: u.nome, unidade: u.unidade,
    papeis: u.papeis, porta: 'web' }))),

  http.get('/api/inicio', com(({ u }) => {
    const minhas = estado.invs.filter((i) => podeVerComoParte(i, u))
    const porEstado: Record<string, number> = {}
    for (const i of minhas) porEstado[i.status] = (porEstado[i.status] ?? 0) + 1
    const fila = u.papeis.includes('aprovador') ? estado.invs.filter((i) => acoesPara(i, u).includes('aprovar')).map((i) => ({
      tipo: i.status === 'preservacao_urgente' || i.preservacao_pedida ? 'preservacao_urgente' : 'investigacao', pedido: 100 + i.id,
      investigacao: i.id, desde: i.criado_em, prazo: new Date(new Date(i.criado_em!).getTime() + 2 * 86_400_000).toISOString(),
      escalonado: i.id === 40 })) : []
    if (u.papeis.includes('aprovador')) fila.push({ tipo: 'pacote_sem_mascara', pedido: 77, investigacao: 33,
      desde: new Date(Date.now() - 3_600_000).toISOString(), prazo: new Date(Date.now() + 20 * 3_600_000).toISOString(), escalonado: false })
    const alertas = []
    if (u.papeis.includes('investigador') || u.papeis.includes('admin_tecnico'))
      alertas.push({ tipo: 'instancia_fora', texto: 'kc18 não responde desde 14:02; a coleta dessa instância está em espera.',
        investigacao: u.papeis.includes('investigador') ? 36 : null, quando: new Date(Date.now() - 720_000).toISOString() })
    if (u.papeis.includes('aprovador'))
      alertas.push({ tipo: 'preservacao_expira', texto: 'Eventos de intranet da investigação 40 expiram antes do prazo de aprovação.',
        investigacao: 40, quando: new Date().toISOString() })
    if (u.papeis.includes('auditor_interno'))
      alertas.push({ tipo: 'papel_alterado', texto: 'Papel investigador concedido a investigador2 por gestor1.', investigacao: null,
        quando: new Date(Date.now() - 86_400_000).toISOString() })
    return HttpResponse.json({ perfil: u.papeis, aguardando_minha_decisao: fila, minhas_por_estado: porEstado, alertas,
      nao_lidas: estado.notif.filter((n) => !n.lida).length })
  })),

  http.get('/api/investigacoes', com(({ u, request }) => {
    if (!u.papeis.some((p) => ['solicitante', 'investigador', 'aprovador', 'auditor_interno'].includes(p)))
      return erro(403, 'perfil', 'Exige o perfil solicitante, investigador, aprovador ou auditor_interno')
    const q = new URL(request.url).searchParams
    let l = estado.invs.filter((i) => podeVer(i, u))
    const visao = q.get('visao')
    if (visao === 'minhas') l = l.filter((i) => podeVerComoParte(i, u) || i.aprovador_usuario === u.usuario)
    if (visao === 'aguardando') l = l.filter((i) => acoesPara(i, u).includes('aprovar'))
    if (visao === 'lacunas') l = l.filter((i) => i.status === 'concluida_com_lacunas')
    if (visao === 'retencao') l = l.filter((i) => i.status === 'retencao_legal')
    const est = q.get('estado')?.split(',').filter(Boolean)
    if (est?.length) l = l.filter((i) => est.includes(i.status))
    const busca = (q.get('q') ?? '').replace(/[.\-/\s]/g, '')
    if (busca) l = l.filter((i) => String(i.id) === busca || (i.processo ?? '').replace(/[.\-/\s]/g, '').includes(busca))
    if (q.get('de')) l = l.filter((i) => (i.criado_em ?? '') >= q.get('de')!)
    if (q.get('ate')) l = l.filter((i) => (i.criado_em ?? '').slice(0, 10) <= q.get('ate')!)
    const pagina = Math.max(1, Number(q.get('pagina') ?? 1))
    const por = 25
    return HttpResponse.json({ itens: l.slice((pagina - 1) * por, pagina * por).map((i) => visaoLista(i, u)), total: l.length, pagina,
      por_pagina: por })
  })),

  http.get('/api/investigacoes/:id', com<{ id: string }>(({ u, params }) => {
    const i = achar(params.id, u)
    return i instanceof Response ? i : HttpResponse.json(visaoDetalhe(i, u))
  })),

  http.post('/api/estimativas', com(async ({ request }) => {
    const c = (await request.json()) as Record<string, unknown>
    const dias = Math.max(1, Math.round((new Date(String(c.ate)).getTime() - new Date(String(c.de)).getTime()) / 86_400_000) + 1)
    const inst = (c.instancias as string[] | undefined)?.length || 2
    const exp = expiracaoPara(String(c.de))
    return HttpResponse.json({ tarefas: dias * inst, segundos: dias * inst * 4, expiracao: exp,
      preservacao_recomendada: exp.some((e) => e.expira_antes_da_aprovacao) } satisfies Estimativa)
  })),

  http.post('/api/investigacoes', com(async ({ u, request }) => {
    const c = (await request.json()) as Record<string, unknown>
    const rasc = Boolean(c.rascunho)
    const v = validarPedido(c, u, rasc)
    if (v) return v
    if (!c.cpf && !c.titulo) return erro(422, 'identificador', 'Informe cpf ou titulo')
    const id = estado.seq++
    const i = corpoParaInv(c, u, id)
    estado.invs.unshift(i)
    marcar(i, rasc ? 'rascunho' : 'aguardando_aprovacao', u)
    return HttpResponse.json({ investigacao: id, status: i.status }, { status: 201 })
  })),

  http.put('/api/investigacoes/:id', com<{ id: string }>(async ({ u, request, params }) => {
    const i = achar(params.id, u)
    if (i instanceof Response) return i
    if (!acoesPara(i, u).includes('editar')) return erro(409, 'estado', 'Só rascunho ou devolvida pode ser editada')
    const c = (await request.json()) as Record<string, unknown>
    const v = validarPedido(c, u, true)
    if (v) return v
    Object.assign(i, corpoParaInv(c, u, i.id, i))
    return HttpResponse.json({ investigacao: i.id, status: i.status })
  })),

  http.delete('/api/investigacoes/:id', com<{ id: string }>(({ u, params }) => {
    const i = achar(params.id, u)
    if (i instanceof Response) return i
    if (!acoesPara(i, u).includes('descartar')) return erro(409, 'estado', 'Só rascunho pode ser descartado')
    estado.invs = estado.invs.filter((x) => x !== i)
    return new HttpResponse(null, { status: 204 })
  })),

  http.post('/api/investigacoes/:id/documento', com<{ id: string }>(async ({ u, request, params }) => {
    const i = achar(params.id, u)
    if (i instanceof Response) return i
    if (!acoesPara(i, u).includes('enviar_documento')) return erro(409, 'estado', 'Documento só no rascunho')
    const f = (await request.formData()).get('arquivo') as File | string | null
    if (!f || typeof f === 'string') return erro(422, 'arquivo', 'Envie o campo arquivo')
    if (f.size > 10 * 1024 * 1024) return erro(413, 'tamanho', 'Arquivo acima de 10 MB')
    if (!/^(application\/pdf|image\/)/.test(f.type)) return erro(415, 'tipo', 'Só PDF ou imagem')
    i.documento = { nome: f.name, sha256: 'c0ffee00'.repeat(8), tamanho: f.size }
    return HttpResponse.json(i.documento, { status: 201 })
  })),
  http.get('/api/investigacoes/:id/documento', com<{ id: string }>(({ u, params }) => {
    const i = achar(params.id, u)
    if (i instanceof Response) return i
    if (!acoesPara(i, u).includes('baixar_documento')) return semAcesso()
    return new HttpResponse('%PDF-1.4 dublê', { headers: { 'Content-Type': 'application/pdf',
      'Content-Disposition': `attachment; filename="${i.documento?.nome ?? 'documento.pdf'}"` } })
  })),

  transicao('enviar', (i, u) => {
    if (i.origem_externa && !i.documento) return erro(422, 'documento', 'Pedido externo exige o documento de origem antes de enviar')
    if (!motivoOk(i.justificativa)) return faltaMotivo()
    marcar(i, 'aguardando_aprovacao', u)
  }),
  transicao('reenviar', (i, u, c) => marcar(i, 'aguardando_aprovacao', u, String(c.motivo)), { motivo: true }),
  transicao('cancelar', (i, u, c) => marcar(i, 'cancelada', u, String(c.motivo)), { motivo: true }),
  transicao('devolver', (i, u, c) => marcar(i, 'devolvida', u, String(c.motivo)), { motivo: true }),
  transicao('recusar', (i, u, c) => marcar(i, 'recusada', u, String(c.motivo)), { motivo: true, stepUp: true }),
  transicao('aprovar', (i, u, c) => {
    if (!c.investigador) return erro(422, 'investigador', 'Designe o investigador')
    const d = Object.values(USUARIOS).find((x) => x.usuario === c.investigador)
    if (!d || !d.papeis.includes('investigador')) return erro(422, 'investigador', 'Usuário não é investigador')
    if (d.usuario === i.solicitante_usuario && !i.origem_externa || d.usuario === u.usuario)
      return erro(409, 'segregacao', 'Solicitante, aprovador e investigador devem ser pessoas diferentes')
    i.investigador_usuario = d.usuario
    i.investigador = d.nome
    i.aprovador_usuario = u.usuario
    i.sigilosa = Boolean(c.sigilosa)
    marcar(i, i.status === 'preservacao_urgente' ? 'coletando' : 'aprovada', u, String(c.motivo))
  }, { motivo: true, stepUp: true }),
  transicao('autorizar_preservacao', (i, u, c) => {
    const d = Object.values(USUARIOS).find((x) => x.usuario === c.investigador)
    if (!d || !d.papeis.includes('investigador')) return erro(422, 'investigador', 'Usuário não é investigador')
    i.investigador_usuario = d.usuario
    i.investigador = d.nome
    i.aprovador_usuario = u.usuario
    const dia = 86_400_000
    i.preservacao = { autorizada_em: new Date().toISOString(), escalona_em: new Date(Date.now() + 3 * dia).toISOString(),
      destroi_em: new Date(Date.now() + 5 * dia).toISOString(), prorrogada: false }
    marcar(i, 'preservacao_urgente', u, String(c.motivo))
  }, { motivo: true, stepUp: true }),
  transicao('prorrogar_preservacao', (i, u, c) => {
    if (i.preservacao) i.preservacao = { ...i.preservacao, prorrogada: true,
      destroi_em: new Date(new Date(i.preservacao.destroi_em).getTime() + 14 * 86_400_000).toISOString() }
    i.linha_do_tempo.push({ status: i.status, quando: new Date().toISOString(), por: u.nome, motivo: String(c.motivo) })
  }, { motivo: true }),
  transicao('iniciar', (i, u) => { i.progresso_interno = 0; i.progresso_pct = 0; marcar(i, 'coletando', u) }),
  transicao('pausar', (i, u) => marcar(i, 'pausada', u)),
  transicao('retomar', (i, u) => marcar(i, 'coletando', u)),

  http.get('/api/investigacoes/:id/acompanhamento', com<{ id: string }>(({ u, params }) => {
    const i = achar(params.id, u)
    return i instanceof Response ? i : HttpResponse.json(progressoDe(i, 0))
  })),
  http.get('/api/investigacoes/:id/acompanhamento/stream', com<{ id: string }>(({ u, params, request }) => {
    const i = achar(params.id, u)
    if (i instanceof Response) return i
    let n = Number(request.headers.get('Last-Event-ID') ?? 0)
    const enc = new TextEncoder()
    let t: ReturnType<typeof setInterval>
    const corpo = new ReadableStream({
      start(ctl) {
        const mandar = () => {
          n += 1
          const ev = progressoDe(i, n)
          if (i.status === 'coletando') { i.progresso_interno = ev.progresso_pct; i.progresso_pct = ev.progresso_pct }
          ctl.enqueue(enc.encode(`id: ${n}\nevent: progresso\ndata: ${JSON.stringify(ev)}\n\n`))
          // a cada 6 eventos o dublê derruba a conexão, para exercitar "Reconectando…" e o Last-Event-ID
          if (n % 6 === 0) { clearInterval(t); ctl.close() }
        }
        mandar()
        t = setInterval(mandar, 1000)
      },
      cancel() { clearInterval(t) },
    })
    return new HttpResponse(corpo, { headers: { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-store' } })
  })),

  http.get('/api/investigacoes/:id/pacotes', com<{ id: string }>(({ u, params }) => {
    const i = achar(params.id, u)
    if (i instanceof Response) return i
    if (i.investigador_usuario !== u.usuario) return semAcesso()
    return HttpResponse.json(estado.pacotes[i.id] ?? [])
  })),
  http.post('/api/investigacoes/:id/pacotes', com<{ id: string }>(async ({ u, params, request }) => {
    const i = achar(params.id, u)
    if (i instanceof Response) return i
    const c = (await request.json()) as { sem_mascara?: boolean; destino?: string }
    const acao = c.sem_mascara ? 'pedir_sem_mascara' : 'gerar_pacote'
    if (!acoesPara(i, u).includes(acao)) return erro(409, 'estado', 'Ação indisponível neste estado')
    if (c.sem_mascara) {
      if (!motivoOk(c.destino)) return erro(422, 'destino', 'Informe o destinatário e o destino')
      return HttpResponse.json({ pedido: 78, status: 'aguardando' }, { status: 202 })
    }
    const l = (estado.pacotes[i.id] ??= [])
    const p: Pacote = { pacote: 100 + l.length, sem_mascara: false, status: 'pronto', sha256: '1234abcd'.repeat(8),
      criado_em: new Date().toISOString(), expira_em: null }
    l.unshift(p)
    return HttpResponse.json({ pacote: p.pacote, status: 'gerando' }, { status: 202 })
  })),
  http.post('/api/pacotes/:p/link', com<{ p: string }>(({ params }) => {
    const p = Object.values(estado.pacotes).flat().find((x) => x.pacote === Number(params.p))
    if (!p) return erro(404, 'inexistente', 'Pacote inexistente')
    if (p.expira_em && new Date(p.expira_em).getTime() < Date.now())
      return erro(410, 'expirado', 'O pacote sem máscara ficou disponível por 24 h e foi apagado. Peça novamente.')
    return HttpResponse.json({ link: `/api/download/dubl${p.pacote}x`, expira_em: new Date(Date.now() + 600_000).toISOString() })
  })),

  http.get('/api/aprovacoes', com(({ u }) => HttpResponse.json([
    ...estado.invs.filter((i) => acoesPara(i, u).includes('aprovar')).map((i) => ({ pedido: 100 + i.id,
      tipo: i.status === 'preservacao_urgente' || i.preservacao_pedida ? 'preservacao_urgente' : 'investigacao', investigacao: i.id,
      criado_em: i.criado_em })),
    { pedido: 77, tipo: 'pacote_sem_mascara', investigacao: 33, criado_em: new Date(Date.now() - 3_600_000).toISOString(),
      parametros: { destino: 'Processo 0001234-12.2026 · sigilo nível 2 · Promotoria Eleitoral', arquivos: 4, eventos: 11946 } },
  ]), { papeis: ['aprovador'] })),
  http.post('/api/aprovacoes/:pedido/decidir', com(async ({ request }) => {
    const c = (await request.json()) as { motivo?: string; aprovar?: boolean }
    if (!motivoOk(c.motivo)) return faltaMotivo()
    return HttpResponse.json({ pedido: 77, status: c.aprovar ? 'aprovado' : 'recusado' })
  }, { stepUp: true, papeis: ['aprovador'] })),

  http.get('/api/substitutos', com(() => HttpResponse.json(Object.entries(estado.substitutos)
    .map(([aprovador, substituto]) => ({ aprovador, substituto }))), { papeis: ['aprovador'] })),
  http.put('/api/substitutos/eu', com(async ({ u, request }) => {
    const c = (await request.json()) as { substituto?: string }
    const s = Object.values(USUARIOS).find((x) => x.usuario === c.substituto)
    if (!s || !s.papeis.includes('aprovador') || s.usuario === u.usuario) return erro(422, 'substituto', 'O substituto precisa ser outro aprovador')
    estado.substitutos[u.usuario] = s.usuario
    return HttpResponse.json({ aprovador: u.usuario, substituto: s.usuario })
  }, { papeis: ['aprovador'] })),

  http.get('/api/notificacoes', com(({ request }) => {
    const so = new URL(request.url).searchParams.get('nao_lidas') === '1'
    return HttpResponse.json(estado.notif.filter((n) => !so || !n.lida))
  })),
  http.post('/api/notificacoes/lidas', com(() => { estado.notif.forEach((n) => { n.lida = true }); return new HttpResponse(null, { status: 204 }) })),
  http.post('/api/notificacoes/:id/lida', com<{ id: string }>(({ params }) => {
    const n = estado.notif.find((x) => x.id === Number(params.id))
    if (n) n.lida = true
    return new HttpResponse(null, { status: 204 })
  })),

  http.post('/api/investigacoes/:id/pedir-acesso', com(() => new HttpResponse(null, { status: 202 }))),

  http.get('/api/instancias', com(() => HttpResponse.json([
    { nome: 'kc26', url: 'https://sso.exemplo.gov.br', versao: '26.1', concorrencia: 2, req_por_s: 5, modo: 'completo',
      sondas_em: new Date(Date.now() - 86_400_000).toISOString() },
    { nome: 'kc18', url: 'https://sso-legado.exemplo.gov.br', versao: '18.0', concorrencia: 1, req_por_s: 3, modo: 'parcial', sondas_em: null },
  ]), { papeis: ['admin_tecnico'] })),
  http.post('/api/instancias', com(() => HttpResponse.json({ instancia: 'nova' }, { status: 201 }), { papeis: ['admin_tecnico'], stepUp: true })),
  http.post('/api/instancias/:nome/testar', com<{ nome: string }>(({ params }) => params.nome === 'kc18'
    ? erro(502, 'conexao', 'kc18 não respondeu em 10 s')
    : HttpResponse.json({ instancia: params.nome, ok: true, latencia_ms: 84, versao: '26.1' }), { papeis: ['admin_tecnico'] })),
  http.post('/api/instancias/:nome/sondas', com<{ nome: string }>(({ params }) => HttpResponse.json({ instancia: params.nome, modo: 'completo',
    realms: [{ realm: 'intranet', status: 'ok' }, { realm: 'portal', status: 'ok' }, { realm: 'legado', status: 'sem_eventos' }] }),
    { papeis: ['admin_tecnico'] })),
  http.post('/api/instancias/:nome/orcamento', com<{ nome: string }>(async ({ params, request }) => {
    const c = (await request.json()) as { concorrencia: number; req_por_s: number }
    if (!(c.concorrencia >= 1 && c.concorrencia <= 8 && c.req_por_s >= 0.5 && c.req_por_s <= 20))
      return erro(422, 'faixa', 'Concorrência 1–8 e taxa 0,5–20 req/s')
    return HttpResponse.json({ instancia: params.nome, ...c })
  }, { papeis: ['admin_tecnico'], stepUp: true })),
  http.get('/api/servicos/saude', com(() => HttpResponse.json({
    jobs: { 'preparar:concluido': 12, 'fechar:pendente': 1 }, tarefas: { pendente: 72, executando: 2, concluida: 1203, falhou: 1 },
    filas: { tarefas: { pendente: 72, executando: 2, falhou: 1 }, jobs: { pendente: 1, executando: 0, falhou: 0 } },
    workers: [{ papel: 'coleta', visto_em: new Date(Date.now() - 4000).toISOString() },
      { papel: 'pacotes', visto_em: new Date(Date.now() - 9000).toISOString() },
      { papel: 'limpeza', visto_em: new Date(Date.now() - 400_000).toISOString() }] }), { papeis: ['admin_tecnico'] })),

  http.get('/api/perfis', com(() => HttpResponse.json(PERFIS.map((p) => ({ ...p, papeis: estado.papeis[p.username] }))),
    { papeis: ['gestor_acesso'] })),
  http.post('/api/perfis/:u/papeis', com<{ u: string }>(async ({ params, request }) => {
    const c = (await request.json()) as { conceder: string[]; revogar: string[]; motivo: string }
    if (!motivoOk(c.motivo)) return faltaMotivo()
    const novo = [...new Set([...(estado.papeis[params.u] ?? []).filter((p) => !c.revogar.includes(p)), ...c.conceder])]
    if (novo.length > 1 && novo.some((p) => p === 'gestor_acesso' || p === 'admin_tecnico'))
      return erro(409, 'papeis_conflitantes', 'Gestor de acesso e administrador técnico não acumulam outros perfis')
    estado.papeis[params.u] = novo
    return HttpResponse.json({ username: params.u, papeis: novo })
  }, { papeis: ['gestor_acesso'], stepUp: true })),
  http.get('/api/recertificacoes', com(() => HttpResponse.json(estado.recert), { papeis: ['gestor_acesso'] })),
  http.post('/api/recertificacoes', com(() => {
    const r = { id: estado.recert.length + 1, criada_em: new Date().toISOString(), prazo: new Date(Date.now() + 30 * 86_400_000).toISOString(),
      concluida_em: null, pendentes: PERFIS.map((p) => ({ username: p.username, papeis: estado.papeis[p.username] })) }
    estado.recert.unshift(r)
    return HttpResponse.json(r, { status: 201 })
  }, { papeis: ['gestor_acesso'] })),
  http.post('/api/recertificacoes/:id/confirmar', com<{ id: string }>(async ({ params, request }) => {
    const c = (await request.json()) as { username: string; manter: boolean }
    const r = estado.recert.find((x) => x.id === Number(params.id))
    if (!r) return erro(404, 'inexistente', 'Recertificação inexistente')
    r.pendentes = r.pendentes.filter((p) => p.username !== c.username)
    if (!c.manter) estado.papeis[c.username] = []
    if (!r.pendentes.length) r.concluida_em = new Date().toISOString()
    return HttpResponse.json(r)
  }, { papeis: ['gestor_acesso'] })),

  http.get('/api/trilha', com(({ request }) => {
    const inv = new URL(request.url).searchParams.get('investigacao')
    const base = Date.now() - 3 * 86_400_000
    const acoes = ['pedir_investigacao', 'aprovar', 'iniciar_coleta', 'consultar_trilha', 'pedir_pacote', 'baixar_pacote']
    const l = Array.from({ length: 18 }, (_, k) => ({ cadeia: 30 + (k % 4), seq: Math.floor(k / 4) + 1,
      quando: new Date(base + k * 3_600_000).toISOString(), operador: ['s-1', 'a-1', 'i-1', 'c-1'][k % 4], acao: acoes[k % acoes.length],
      investigacao_id: 30 + (k % 4), detalhe: { porta: 'web' }, hash: (k + 10).toString(16).repeat(32).slice(0, 64) }))
    return HttpResponse.json(inv ? l.filter((r) => r.investigacao_id === Number(inv)) : l)
  }, { papeis: ['auditor_interno'] })),
  http.get('/api/trilha/verificar', com(() => HttpResponse.json({ cadeias: 4, integras: 4, problemas: {} }), { papeis: ['auditor_interno'] })),
]
