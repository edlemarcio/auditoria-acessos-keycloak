/** Sessão de análise e revelação (W4, §5.5 e §7.5). Valores revelados vivem só na memória da tela: nada vai para o
 * armazenamento do navegador, para a URL ou para log; a API só os devolve enquanto a sessão está ativa. */
import { api, postar } from './cliente'

export interface Cota { sessao: number; sessao_limite: number; investigacao: number; investigacao_limite: number }
export interface Sessao { id: number; inicio: string; expira_em: string; prorrogacoes: number; pode_prorrogar: boolean;
  motivo_codigo: string; motivo: string; total: boolean; agora: string }
export interface Revelado { classe: 'conta' | 'ip' | 'sessao' | 'evento'; rotulo: string; chave?: string | null; valor: unknown;
  terceiro: boolean; quando: string }
export interface PedidoRev { pedido: number; tipo: string; status: string; quantidade: number; criado_em: string; decidido_em: string | null }
export interface EstadoSessao { motivos: Record<string, string>; sessao: Sessao | null; revelados: Revelado[]; pedidos: PedidoRev[];
  cota: Cota; teto_dia: { usado_s: number; limite_s: number } }
export interface ResultadoRevelar { classe: string; rotulo: string; valor: unknown; expira_em: string; cota: Cota }
export interface DetalhePedido { pedido: number; tipo: string; nome: string; investigacao: number; status: string; criado_em: string;
  investigador: string | null; quantidade: number; por_classe: Record<string, number>; terceiros: number; rotulos: string[];
  motivo: string | null; fundamento: string | null; destinatario: string | null; motivo_sessao: string | null;
  volume_investigacao: number; historico: { classe: string; n: number; terceiros: number; motivos: string[] }[]; avisos: string[] }

const b = (id: number) => `/api/investigacoes/${id}`
export const estado = (id: number, sinal?: AbortSignal) => api<EstadoSessao>(`${b(id)}/sessao-analise`, { sinal })
export const iniciar = (id: number, motivo_codigo: string, motivo?: string) =>
  postar<EstadoSessao>(`${b(id)}/sessao-analise`, { motivo_codigo, motivo: motivo || undefined }, 'iniciar_sessao_analise')
export const prorrogar = (id: number) => postar<EstadoSessao>(`${b(id)}/sessao-analise/prorrogar`)
export const encerrar = (id: number) => postar<EstadoSessao>(`${b(id)}/sessao-analise/encerrar`)
export const revelar = (id: number, classe: string, rotulo: string) => postar<ResultadoRevelar>(`${b(id)}/revelar`, { classe, rotulo })
export const pedir = (id: number, tipo: string, itens: { classe?: string; rotulo: string }[], motivo: string,
  fundamento?: string, destinatario?: string) =>
  postar<{ pedido: number; status: string; quantidade: number }>(`${b(id)}/pedidos-revelacao`, { tipo, itens, motivo, fundamento, destinatario })
export const detalhePedido = (pedido: number, sinal?: AbortSignal) => api<DetalhePedido>(`/api/aprovacoes/${pedido}`, { sinal })
export const decidir = (pedido: number, aprovar: boolean, motivo: string) =>
  postar<{ pedido: number; status: string }>(`/api/aprovacoes/${pedido}/decidir`, { aprovar, motivo }, `decidir_${pedido}`)
export const urlTabelaOficio = (id: number, pedido: number) => `${b(id)}/oficios/${pedido}/tabela`

export const TIPOS_REVELACAO = ['revelacao_cota', 'revelacao_terceiro', 'revelacao_total', 'lista_oficio'] as const

/** Texto do valor revelado (conta: username, e-mail ou id). */
export function textoValor(v: unknown): string {
  if (v == null) return '—'
  if (typeof v === 'string') return v
  if (typeof v === 'object') {
    const o = v as Record<string, unknown>
    if ('username' in o || 'email' in o) return [o.username, o.email].filter(Boolean).join(' · ') || String(o.user_id ?? '—')
    return JSON.stringify(v)
  }
  return String(v)
}
