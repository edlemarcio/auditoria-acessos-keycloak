/**
 * Cliente da API (mesma origem, cookie HttpOnly do BFF; a tela nunca vê token).
 * Todo POST/PUT/DELETE leva `X-Requisicao: kc-auditor` (CSRF do W1).
 * 401 step_up → /auth/entrar?step_up=1&volta=<tela>; 401 sem sessão → aviso de sessão expirada (ou login no 1º acesso).
 */
import { guardarRetomada } from '../armazenamento'

export class ErroApi extends Error {
  status: number
  codigo: string
  correlacao?: string
  constructor(status: number, codigo: string, texto: string, correlacao?: string) {
    super(texto)
    this.status = status
    this.codigo = codigo
    this.correlacao = correlacao
  }
}

type Ouvinte = (e: ErroApi) => void
let aoPerderSessao: Ouvinte = () => {}
export function quandoSessaoExpirar(f: Ouvinte) { aoPerderSessao = f }

export const telaAtual = () => window.location.pathname + window.location.search

export function urlLogin(stepUp = false, volta = telaAtual()) {
  return `/auth/entrar?${stepUp ? 'step_up=1&' : ''}volta=${encodeURIComponent(volta)}`
}

/** Troca de página (isolado para os testes). */
export const navegador = { ir(url: string) { window.location.assign(url) } }

interface Opcoes { metodo?: 'GET' | 'POST' | 'PUT' | 'DELETE'; corpo?: unknown; form?: FormData; sinal?: AbortSignal;
  /** corpo binário (upload em streaming) e cabeçalhos extras */ arquivo?: Blob; cabecalhos?: Record<string, string>;
  /** ação a retomar depois do step-up (só o nome; nada do que foi digitado) */ retomar?: string }

async function lerErro(r: Response): Promise<ErroApi> {
  let j: Record<string, unknown> = {}
  try { j = await r.json() } catch { /* corpo vazio */ }
  // contrato: {codigo, texto, correlacao?}; W1: {erro, mensagem}
  const codigo = String(j.codigo ?? j.erro ?? (r.status === 404 ? 'rota_inexistente' : 'http_' + r.status))
  const texto = String(j.texto ?? j.mensagem ?? j.detail ?? r.statusText ?? 'Erro')
  return new ErroApi(r.status, codigo, texto, j.correlacao ? String(j.correlacao) : undefined)
}

export async function api<T = unknown>(caminho: string, o: Opcoes = {}): Promise<T> {
  const metodo = o.metodo ?? (o.corpo !== undefined || o.form || o.arquivo ? 'POST' : 'GET')
  const h: Record<string, string> = { Accept: 'application/json', ...(o.cabecalhos ?? {}) }
  if (metodo !== 'GET') h['X-Requisicao'] = 'kc-auditor'
  if (o.corpo !== undefined) h['Content-Type'] = 'application/json'
  const r = await fetch(caminho, { method: metodo, headers: h, credentials: 'same-origin', signal: o.sinal,
    body: o.arquivo ?? o.form ?? (o.corpo !== undefined ? JSON.stringify(o.corpo) : undefined) })
  if (r.ok) {
    if (r.status === 204 || r.status === 202 && r.headers.get('content-length') === '0') return undefined as T
    const t = await r.text()
    return (t ? JSON.parse(t) : undefined) as T
  }
  const e = await lerErro(r)
  if (r.status === 401 && e.codigo === 'step_up') {
    guardarRetomada(telaAtual(), o.retomar)
    navegador.ir(urlLogin(true))
  } else if (r.status === 401) {
    aoPerderSessao(e)
  }
  throw e
}

export const postar = <T = unknown>(caminho: string, corpo: unknown = {}, retomar?: string) =>
  api<T>(caminho, { metodo: 'POST', corpo, retomar })
