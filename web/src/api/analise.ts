/** Rotas da análise (W3): dashboard, eventos, contas, cobertura e visão agregada. Só rótulos de pseudônimo
 * ("IP 3", "Conta 2") e dimensões técnicas vão para a URL; valores reais nunca. */
import { api, postar } from './cliente'

export type Filtros = Partial<Record<'instancia' | 'realm' | 'cliente' | 'categorias' | 'tecnicos' | 'tipo' | 'resultado'
  | 'de' | 'ate' | 'destaque' | 'conta' | 'ip' | 'sessao', string>>

export const CHAVES_FILTRO = ['instancia', 'realm', 'cliente', 'categorias', 'tecnicos', 'tipo', 'resultado', 'de', 'ate',
  'destaque', 'conta', 'ip', 'sessao'] as const

export interface Kpis { logins: number; falhas: number; aplicacoes: number; ips: number; eventos: number;
  primeiro: string | null; ultimo: string | null }
export interface PontoSerie { janela: string; logins: number; falhas: number; eventos: number }
export interface LinhaApp { instancia: string; realm: string; cliente: string | null; logins: number; falhas: number; eventos: number }
export interface Celula { dia_semana: number; hora: number; n: number }
export interface LinhaIp { ip: string; eventos: number; falhas: number; contas: number; primeiro: string; ultimo: string }
export interface Destaque { tipo: 'fora_expediente' | 'rajada' | 'ip_novo'; titulo: string; n: number; inicio: string;
  fim?: string | null; conta?: string | null; ip?: string | null; ips?: string[]; instancia?: string; realm?: string;
  filtro: Record<string, string | number> }
export interface EstadoAnalise { versao: number; calculado_em: string | null; recalculando: boolean; motivo: string | null }
export interface SeloCobertura { calculada: boolean; realms_cobertos?: number; realms?: number; dias_cobertos?: number;
  dias?: number; completa?: boolean }
export interface SaudeProva { fatias: number; em_limite: number; relidas: number; divergentes: number; falharam: number;
  seladas: number; ultimo_selo: string | null; ultima_ancora: string | null }

export interface Dashboard {
  preliminar: boolean; rotulos_definitivos: boolean; filtros: Filtros; categorias: string[]
  kpis: Kpis; serie: PontoSerie[]; granularidade: string; fuso: string
  por_aplicacao: LinhaApp[]; mapa_calor: Celula[]; ranking_ips: LinhaIp[]
  ranking_aplicacoes: { instancia: string; realm: string; cliente: string | null; logins: number }[]
  destaques: Destaque[]; resumo_destaques: { fora_expediente: number; rajadas: number; ip_novo: number | null }
  saude_prova: SaudeProva; cobertura: SeloCobertura
  opcoes: { instancias: string[]; realms: string[]; clientes: string[]; categorias: string[] }
  analise: EstadoAnalise
}

export interface Evento { ref: string; horario: string; instancia: string; realm: string; aplicacao: string | null;
  tipo: string; tipo_nome: string; categoria: string; conta: string | null; ip: string | null; sessao: string | null;
  resultado: string; revelado?: Record<string, unknown> }
export interface PaginaEventos { total: number; total_filtrado: number; filtros: Filtros; preliminar: boolean; sessao_ativa?: boolean;
  rotulos_definitivos: boolean; proximo: string | null; itens: Evento[] }
export interface DetalheEvento extends Evento { detalhes: Record<string, unknown>; json: Record<string, unknown>;
  folha: string | null; hash_conteudo: string | null; evento_id: string
  selo: { id: number; raiz: string; versao: number; eventos: number; inicio: string; fim: string; selado_em: string } | null
  requisicao: { id: number; metodo: string; status: number; quando: string; ms: number; sha256: string } | null }

export interface Conta { id: number; conta: string | null; instancia: string; realm: string; via: string; origem: string | null;
  habilitada: boolean | null; criada_em: string | null; incluida: boolean; duplicidade: boolean; eventos: number;
  primeiro: string | null; ultimo: string | null; sessoes_ativas: number; alteracoes: number
  decisao: { incluida: boolean; por: string; quando: string; motivo?: string } | null }
export interface ExtrasConta { sessoes_ativas: { ip: string; inicio: string | null; ultimo_acesso: string | null; aplicacoes: string[] }[]
  alteracoes: { quando: string | null; operacao: string | null; recurso: string | null; autor_ip: string; dados: unknown }[] }

export interface FaixaCobertura { de: string; ate: string; classe: 'coberto' | 'parcial' | 'sem_dados' | 'pendente' | string }
export interface LinhaCobertura { instancia: string; realm: string; conta: string | null; classe: string; classe_nome: string;
  situacao: string; motivo: string | null; acao: string | null; desde: string | null; faixas: FaixaCobertura[] }
export interface Cobertura { selo: SeloCobertura; linhas: LinhaCobertura[]; de: string; ate: string }

export interface VisaoAgregada { kpis: { logins: number; falhas: number; aplicacoes: number };
  serie_dia: { dia: string; logins: number; falhas: number }[]; aplicacoes: { aplicacao: string; logins: number }[];
  cobertura: SeloCobertura; fuso: string }

const qs = (f: Record<string, string | number | undefined>) => {
  const p = new URLSearchParams()
  for (const [k, v] of Object.entries(f)) if (v !== undefined && v !== '') p.set(k, String(v))
  const s = p.toString()
  return s ? `?${s}` : ''
}

const base = (id: number) => `/api/investigacoes/${id}`
export const dashboard = (id: number, f: Filtros, sinal?: AbortSignal) => api<Dashboard>(`${base(id)}/dashboard${qs(f)}`, { sinal })
export const eventos = (id: number, f: Filtros & { apos?: string; limite?: number }, sinal?: AbortSignal) =>
  api<PaginaEventos>(`${base(id)}/eventos${qs(f)}`, { sinal })
export const evento = (id: number, ref: string, sinal?: AbortSignal) =>
  api<DetalheEvento>(`${base(id)}/eventos/${encodeURIComponent(ref)}`, { sinal })
export const contas = (id: number, sinal?: AbortSignal) =>
  api<{ contas: Conta[]; analise: EstadoAnalise; preliminar: boolean }>(`${base(id)}/contas`, { sinal })
export const extrasConta = (id: number, conta: number, sinal?: AbortSignal) =>
  api<ExtrasConta>(`${base(id)}/contas/${conta}/extras`, { sinal })
export const decidirConta = (id: number, conta: number, incluir: boolean, motivo: string) =>
  postar<{ conta: number; incluida: boolean; analise: EstadoAnalise }>(`${base(id)}/contas/${conta}/${incluir ? 'incluir' : 'excluir'}`, { motivo })
export const cobertura = (id: number, sinal?: AbortSignal) => api<Cobertura>(`${base(id)}/cobertura`, { sinal })
export const visaoAgregada = (id: number, sinal?: AbortSignal) => api<VisaoAgregada>(`${base(id)}/visao-agregada`, { sinal })

/** Filtros a partir da URL (só as chaves conhecidas). */
export function filtrosDaUrl(p: URLSearchParams): Filtros {
  const f: Filtros = {}
  for (const k of CHAVES_FILTRO) { const v = p.get(k); if (v) f[k] = v }
  return f
}
