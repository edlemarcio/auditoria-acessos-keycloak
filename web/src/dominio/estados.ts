/** Estados da investigação (PROPOSTA §7.2): cor + ícone + texto, nunca só cor. */
export type Tom = 'cinza' | 'ambar' | 'vermelho' | 'azul' | 'verde' | 'roxo'
export interface Indicador { rotulo: string; icone: string; tom: Tom; preparando?: boolean }

const MAPA: Record<string, Indicador> = {
  rascunho: { rotulo: 'Rascunho', icone: 'fa-pencil-alt', tom: 'cinza' },
  aguardando_aprovacao: { rotulo: 'Aguardando aprovação', icone: 'fa-clock', tom: 'ambar' },
  devolvida: { rotulo: 'Devolvida para correção', icone: 'fa-undo', tom: 'ambar' },
  recusada: { rotulo: 'Recusada', icone: 'fa-ban', tom: 'vermelho' },
  preservacao_urgente: { rotulo: 'Coleta lacrada', icone: 'fa-lock', tom: 'azul' },
  aprovada: { rotulo: 'Aprovada', icone: 'fa-check', tom: 'azul' },
  coletando: { rotulo: 'Coletando', icone: 'fa-spinner', tom: 'azul' },
  pausada: { rotulo: 'Pausada', icone: 'fa-pause', tom: 'cinza' },
  concluida: { rotulo: 'Concluída', icone: 'fa-check-double', tom: 'verde' },
  concluida_com_lacunas: { rotulo: 'Concluída com lacunas', icone: 'fa-exclamation-triangle', tom: 'ambar' },
  parcial: { rotulo: 'Concluída com lacunas', icone: 'fa-exclamation-triangle', tom: 'ambar' },
  falhou: { rotulo: 'Falhou', icone: 'fa-exclamation-circle', tom: 'vermelho' },
  cancelada: { rotulo: 'Cancelada', icone: 'fa-times', tom: 'cinza' },
  retencao_legal: { rotulo: 'Em retenção legal', icone: 'fa-balance-scale', tom: 'roxo' },
  expurgada: { rotulo: 'Expurgada', icone: 'fa-trash-alt', tom: 'cinza' },
}
const PASSAGEM = new Set(['abrindo', 'preparando', 'fechando', 'na_fila'])

export function indicador(status: string, progresso?: number | null): Indicador {
  if (PASSAGEM.has(status)) return { rotulo: 'Preparando…', icone: 'fa-hourglass-half', tom: 'cinza', preparando: true }
  const i = MAPA[status] ?? { rotulo: status, icone: 'fa-question-circle', tom: 'cinza' }
  if (status === 'coletando' && progresso != null) return { ...i, rotulo: `Coletando ${Math.round(progresso)}%` }
  return i
}

export const ESTADOS_FILTRO = ['rascunho', 'aguardando_aprovacao', 'devolvida', 'recusada', 'preservacao_urgente',
  'aprovada', 'coletando', 'pausada', 'concluida', 'concluida_com_lacunas', 'falhou', 'cancelada', 'retencao_legal',
  'expurgada'] as const

export const emColeta = (s: string) => s === 'coletando' || s === 'pausada' || s === 'preservacao_urgente' || PASSAGEM.has(s)
