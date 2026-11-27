/** Formatos do contrato W2 (docs/W2_CONTRATO.md) e do W1 (auditor/api.py). */
export type Acao = 'enviar' | 'editar' | 'descartar' | 'aprovar' | 'devolver' | 'recusar' | 'cancelar' | 'reenviar'
  | 'autorizar_preservacao' | 'prorrogar_preservacao' | 'iniciar' | 'pausar' | 'retomar' | 'gerar_pacote'
  | 'pedir_sem_mascara' | 'enviar_documento' | 'baixar_documento'

export interface Eu { sub: string; usuario: string; nome?: string | null; unidade?: string | null; papeis: string[] }

export interface Investigacao {
  id: number
  status: string
  alvo_mascarado?: string | null
  de?: string | null
  ate?: string | null
  fuso?: string | null
  processo?: string | null
  solicitante?: string | null
  investigador?: string | null
  criado_em?: string | null
  atualizado_em?: string | null
  progresso_pct?: number | null
  origem_externa?: boolean
  sigilosa?: boolean
  acoes: Acao[]
}

export interface Expiracao { instancia: string; realm: string; eventos_desde: string | null; expira_antes_da_aprovacao: boolean }
export interface PassoTempo { status: string; quando: string; por?: string | null; motivo?: string | null }

export interface Detalhe extends Investigacao {
  tipo?: string | null
  tipo_processo?: string | null
  granularidade?: string | null
  instancias?: string[] | null
  varredura?: boolean
  base_dias?: number
  justificativa?: string | null
  origem?: Record<string, string> | null
  linha_do_tempo: PassoTempo[]
  expiracao: Expiracao[]
  estimativa?: { tarefas: number; segundos: number } | null
  documento?: { nome: string; sha256: string; tamanho: number } | null
  preservacao?: { autorizada_em: string; escalona_em: string; destroi_em: string; prorrogada: boolean } | null
}

export interface Pagina<T> { itens: T[]; total: number; pagina: number; por_pagina: number }

export interface ItemDecisao { tipo: 'investigacao' | 'pacote_sem_mascara' | 'preservacao_urgente' | string; pedido: number;
  investigacao: number; desde?: string; prazo?: string | null; escalonado?: boolean; parametros?: Record<string, unknown> }
export interface Alerta { tipo: string; texto: string; investigacao?: number | null; quando: string }
export interface Inicio { perfil: string[]; aguardando_minha_decisao: ItemDecisao[]; minhas_por_estado: Record<string, number>;
  alertas: Alerta[]; nao_lidas: number }

export interface Estimativa { tarefas: number; segundos: number; expiracao: Expiracao[]; preservacao_recomendada: boolean }

export interface InstanciaAcomp { nome: string; tarefas: Record<'pendente' | 'executando' | 'concluida' | 'falhou', number>;
  req_por_s: number; orcamento_req_por_s: number; fora_do_ar_desde: string | null }
export interface Acompanhamento { status: string; progresso_pct: number; eventos: number; instancias: InstanciaAcomp[];
  falhas: number; retentativas: number; termino_estimado: string | null }

export interface Notificacao { id: number; tipo: string; texto: string; investigacao?: number | null; quando: string; lida: boolean }

export interface Pacote { pacote: number; sem_mascara: boolean; status: string; sha256: string | null; criado_em: string;
  expira_em: string | null }

export interface Instancia { nome: string; url: string; versao?: string | null; concorrencia: number; req_por_s: number;
  modo?: string | null; sondas_em?: string | null }

export interface Saude { jobs: Record<string, number>; tarefas: Record<string, number>;
  filas?: { tarefas: Record<string, number>; jobs: Record<string, number> }; workers?: { papel: string; visto_em: string }[] }

export interface Perfil { username: string; nome?: string | null; unidade?: string | null; papeis: string[];
  ultimo_login?: string | null; recertificado_em?: string | null }

export interface RegistroTrilha { cadeia: number | null; seq: number; quando: string; operador: string; acao: string;
  investigacao_id: number | null; detalhe?: Record<string, unknown> | null; hash: string }
