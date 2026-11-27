/**
 * Chamadas da API. As rotas do W1 que mudam de forma no W2 (lista, detalhe) passam por `normalizar*`, para que as
 * telas funcionem contra o W1 de hoje (teste ponta a ponta real) e contra o contrato do W2.
 */
import { api, postar } from './cliente'
import type { Acompanhamento, Detalhe, Estimativa, Eu, Inicio, Instancia, Investigacao, ItemDecisao, Notificacao,
  Pacote, Pagina, Perfil, RegistroTrilha, Saude } from './tipos'

type Bruto = Record<string, unknown>
const iso = (ms: unknown) => (typeof ms === 'number' ? new Date(ms).toISOString() : undefined)

export function normalizarInvestigacao(b: Bruto): Investigacao {
  return {
    ...(b as unknown as Investigacao),
    alvo_mascarado: (b.alvo_mascarado ?? b.alvo ?? null) as string | null,
    de: (b.de ?? iso(b.inicio_ms) ?? null) as string | null,
    ate: (b.ate ?? iso(b.fim_ms) ?? null) as string | null,
    origem_externa: Boolean(b.origem_externa ?? b.externo),
    acoes: Array.isArray(b.acoes) ? (b.acoes as Investigacao['acoes']) : [],
  }
}

export function normalizarDetalhe(b: Bruto): Detalhe {
  const linha = Array.isArray(b.linha_do_tempo) ? (b.linha_do_tempo as Bruto[]) : []
  return {
    ...normalizarInvestigacao(b),
    ...(b as object),
    alvo_mascarado: (b.alvo_mascarado ?? b.alvo ?? null) as string | null,
    acoes: Array.isArray(b.acoes) ? (b.acoes as Detalhe['acoes']) : [],
    linha_do_tempo: linha.map((p) => ({ status: String(p.status ?? p.acao ?? ''), quando: String(p.quando ?? ''),
      por: (p.por as string) ?? null, motivo: (p.motivo as string) ?? null })),
    expiracao: Array.isArray(b.expiracao) ? (b.expiracao as Detalhe['expiracao']) : [],
  } as Detalhe
}

export interface FiltroLista { visao?: string; estado?: string[]; q?: string; de?: string; ate?: string; pagina?: number }

export async function listarInvestigacoes(f: FiltroLista, sinal?: AbortSignal): Promise<Pagina<Investigacao>> {
  const p = new URLSearchParams()
  if (f.visao) p.set('visao', f.visao)
  if (f.estado?.length) p.set('estado', f.estado.join(','))
  if (f.q) p.set('q', f.q)
  if (f.de) p.set('de', f.de)
  if (f.ate) p.set('ate', f.ate)
  p.set('pagina', String(f.pagina ?? 1))
  const r = await api<Bruto[] | Pagina<Bruto>>(`/api/investigacoes?${p}`, { sinal })
  if (Array.isArray(r)) {   // W1: lista pura, sem paginação
    return { itens: r.map(normalizarInvestigacao), total: r.length, pagina: 1, por_pagina: Math.max(r.length, 25) }
  }
  return { ...r, itens: r.itens.map(normalizarInvestigacao) }
}

export const eu = () => api<Eu>('/api/eu')
export const inicio = () => api<Inicio>('/api/inicio')
export const detalhe = async (id: number, sinal?: AbortSignal) =>
  normalizarDetalhe(await api<Bruto>(`/api/investigacoes/${id}`, { sinal }))
export const estimar = (corpo: unknown, sinal?: AbortSignal) =>
  api<Estimativa>('/api/estimativas', { metodo: 'POST', corpo, sinal })
export const acompanhamento = (id: number) => api<Acompanhamento>(`/api/investigacoes/${id}/acompanhamento`)

export interface CorpoPedido {
  cpf?: string; titulo?: string; de: string; ate: string; fuso: string; granularidade: string; instancias?: string[] | null
  varredura: boolean; base_dias: number; justificativa: string; tipo_processo: string; processo?: string
  rascunho?: boolean; preservacao_urgente?: boolean
  origem?: { orgao: string; documento: string; processo?: string; fundamento: string; destinatario?: string } | null
}
export const pedir = (c: CorpoPedido) => postar<{ investigacao: number; status: string }>('/api/investigacoes', c)
export const atualizarRascunho = (id: number, c: CorpoPedido) =>
  api<{ investigacao: number; status: string }>(`/api/investigacoes/${id}`, { metodo: 'PUT', corpo: c })
export const descartar = (id: number) => api(`/api/investigacoes/${id}`, { metodo: 'DELETE' })
export function enviarDocumento(id: number, arquivo: File) {
  const f = new FormData()
  f.append('arquivo', arquivo)
  return api<{ nome: string; sha256: string; tamanho: number }>(`/api/investigacoes/${id}/documento`, { metodo: 'POST', form: f })
}
export const urlDocumento = (id: number) => `/api/investigacoes/${id}/documento`

/** Ações de estado: rota = nome da ação no §7.2 (com hífen), corpo conforme o W1/W2. */
export function executar(id: number, acao: string, corpo: unknown = {}) {
  return postar(`/api/investigacoes/${id}/${acao.replace(/_/g, '-')}`, corpo, `${acao}:${id}`)
}

export const aprovacoes = () => api<ItemDecisao[]>('/api/aprovacoes')
export const decidirPacote = (pedido: number, aprovar: boolean, motivo: string) =>
  postar(`/api/aprovacoes/${pedido}/decidir`, { aprovar, motivo }, `decidir_${pedido}`)
export const substitutos = () => api<{ aprovador: string; substituto: string | null }[]>('/api/substitutos')
export const definirSubstituto = (substituto: string) =>
  api('/api/substitutos/eu', { metodo: 'PUT', corpo: { substituto } })

export const pacotes = (id: number) => api<Pacote[]>(`/api/investigacoes/${id}/pacotes`)
export const pedirPacote = (id: number, sem_mascara: boolean, destino?: string) =>
  postar<{ pacote?: number; pedido?: number; status: string }>(`/api/investigacoes/${id}/pacotes`, { sem_mascara, destino },
    `${sem_mascara ? 'pedir_sem_mascara' : 'gerar_pacote'}:${id}`)
export const linkPacote = (pacote: number) =>
  postar<{ link: string; expira_em: string }>(`/api/pacotes/${pacote}/link`, {}, 'link')

export const notificacoes = (soNaoLidas = false) => api<Notificacao[]>(`/api/notificacoes${soNaoLidas ? '?nao_lidas=1' : ''}`)
export const marcarLida = (id: number) => postar(`/api/notificacoes/${id}/lida`)
export const marcarTodasLidas = () => postar('/api/notificacoes/lidas')

export const pedirAcesso = (id: number, motivo: string) => postar(`/api/investigacoes/${id}/pedir-acesso`, { motivo })

export const instancias = () => api<Instancia[]>('/api/instancias')
export const cadastrarInstancia = (c: unknown) => postar('/api/instancias', c, 'cadastrar_instancia')
export const testarInstancia = (nome: string) =>
  postar<{ ok?: boolean; texto?: string; [k: string]: unknown }>(`/api/instancias/${encodeURIComponent(nome)}/testar`)
export const sondas = (nome: string) =>
  postar<{ instancia: string; modo: string | null; realms: { realm: string; status: string }[] }>(
    `/api/instancias/${encodeURIComponent(nome)}/sondas`)
export const orcamento = (nome: string, concorrencia: number, req_por_s: number) =>
  postar(`/api/instancias/${encodeURIComponent(nome)}/orcamento`, { concorrencia, req_por_s }, `orcamento_${nome}`)
export const saude = () => api<Saude>('/api/servicos/saude')

export const perfis = () => api<Perfil[]>('/api/perfis')
export const alterarPapeis = (username: string, conceder: string[], revogar: string[], motivo: string) =>
  postar(`/api/perfis/${encodeURIComponent(username)}/papeis`, { conceder, revogar, motivo }, `papeis_${username}`)
export interface Recertificacao { id: number; criada_em: string; prazo?: string | null; concluida_em?: string | null;
  pendentes?: { username: string; papeis: string[] }[] }
export const recertificacoes = () => api<Recertificacao[]>('/api/recertificacoes')
export const abrirRecertificacao = () => postar<Recertificacao>('/api/recertificacoes')
export const confirmarRecertificacao = (id: number, username: string, manter: boolean) =>
  postar(`/api/recertificacoes/${id}/confirmar`, { username, manter })

export const trilhaGlobal = (investigacao?: number) =>
  api<RegistroTrilha[]>(`/api/trilha${investigacao != null ? `?investigacao=${investigacao}` : ''}`)
export const verificarCadeia = (investigacao?: number) =>
  api<{ cadeias: number; integras: number; problemas: Record<string, unknown[]> }>(
    `/api/trilha/verificar${investigacao != null ? `?investigacao=${investigacao}` : ''}`)
