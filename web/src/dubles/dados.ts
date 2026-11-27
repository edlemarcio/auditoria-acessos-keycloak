/**
 * Dados de mentira dos dublês (só `vite dev` com VITE_DUBLES=1 e testes). Nenhum dado real: alvos já mascarados,
 * nomes inventados. O dublê faz o papel do servidor, inclusive calcular `acoes` — a tela não calcula nada disso.
 */
import type { Acao, Detalhe, Notificacao, Pacote, Perfil } from '../api/tipos'

export interface UsuarioDuble { sub: string; usuario: string; nome: string; unidade: string; papeis: string[]; coordenador?: boolean }

export const USUARIOS: Record<string, UsuarioDuble> = {
  solicitante: { sub: 's-1', usuario: 'solicitante1', nome: 'Sofia Lima', unidade: 'Corregedoria', papeis: ['solicitante'] },
  investigador: { sub: 'i-1', usuario: 'investigador1', nome: 'Igor Melo', unidade: 'STI', papeis: ['investigador'] },
  aprovador: { sub: 'a-1', usuario: 'aprovador1', nome: 'Ana Prado', unidade: 'Corregedoria', papeis: ['aprovador'], coordenador: true },
  auditor_interno: { sub: 'c-1', usuario: 'auditor1', nome: 'Caio Rocha', unidade: 'Controle interno', papeis: ['auditor_interno'] },
  admin_tecnico: { sub: 't-1', usuario: 'admin1', nome: 'Teresa Dias', unidade: 'Infraestrutura', papeis: ['admin_tecnico'] },
  gestor_acesso: { sub: 'g-1', usuario: 'gestor1', nome: 'Gil Souza', unidade: 'Segurança da informação', papeis: ['gestor_acesso'] },
  aprovinvest: { sub: 'ai-1', usuario: 'aprovinvest1', nome: 'Alice Vieira', unidade: 'STI', papeis: ['aprovador', 'investigador'] },
}

export interface InvDuble extends Omit<Detalhe, 'acoes'> {
  solicitante_usuario: string
  investigador_usuario?: string
  aprovador_usuario?: string
  preservacao_pedida?: boolean
  progresso_interno?: number
}

const dia = 86_400_000
const agora = Date.now()
const isoDias = (d: number) => new Date(agora + d * dia).toISOString()
const dataDias = (d: number) => isoDias(d).slice(0, 10)

const EXP_OK = [
  { instancia: 'kc26', realm: 'intranet', eventos_desde: isoDias(-200), expira_antes_da_aprovacao: false },
  { instancia: 'kc26', realm: 'portal', eventos_desde: isoDias(-190), expira_antes_da_aprovacao: false },
  { instancia: 'kc18', realm: 'legado', eventos_desde: isoDias(-400), expira_antes_da_aprovacao: false },
]
const EXP_RISCO = [
  { instancia: 'kc26', realm: 'intranet', eventos_desde: isoDias(-181), expira_antes_da_aprovacao: true },
  ...EXP_OK.slice(1),
]

function inv(id: number, status: string, extra: Partial<InvDuble> = {}): InvDuble {
  return {
    id, status, alvo_mascarado: '***.456.789-**', de: dataDias(-180), ate: dataDias(-1), fuso: 'America/Bahia',
    processo: `0000${id}-12.2026.6.05.0000`, solicitante: 'Sofia Lima', investigador: null,
    criado_em: isoDias(-3), atualizado_em: isoDias(-1), progresso_pct: null, origem_externa: false, sigilosa: false,
    tipo: 'cpf', tipo_processo: 'apuracao_disciplinar', granularidade: 'dia', instancias: ['kc26', 'kc18'],
    varredura: false, base_dias: 30, justificativa: 'Apuração de acessos fora do expediente ao sistema de pessoal.',
    origem: null, expiracao: EXP_OK, estimativa: { tarefas: 362, segundos: 1440 }, documento: null, preservacao: null,
    linha_do_tempo: [{ status: 'aguardando_aprovacao', quando: isoDias(-3), por: 'Sofia Lima' }],
    solicitante_usuario: 'solicitante1',
    ...extra,
  }
}

export function semente(): InvDuble[] {
  return [
    inv(41, 'rascunho', { processo: null, linha_do_tempo: [{ status: 'rascunho', quando: isoDias(-1), por: 'Sofia Lima' }] }),
    inv(40, 'aguardando_aprovacao', { alvo_mascarado: '***.111.222-**', expiracao: EXP_RISCO, preservacao_pedida: true,
      criado_em: isoDias(-2) }),
    inv(39, 'aguardando_aprovacao', { alvo_mascarado: '**** 5678 ****', tipo: 'titulo', criado_em: isoDias(-1),
      documento: { nome: 'oficio-123.pdf', sha256: '9f2c1e7a'.repeat(8), tamanho: 182_034 }, origem_externa: true,
      origem: { orgao: 'Ministério Público Eleitoral', documento: 'Ofício 123/2026', fundamento: 'Requisição em procedimento preparatório',
        destinatario: 'Promotoria Eleitoral da 1ª Zona' }, solicitante: 'Igor Melo', solicitante_usuario: 'investigador1' }),
    inv(38, 'devolvida', { linha_do_tempo: [
      { status: 'aguardando_aprovacao', quando: isoDias(-6), por: 'Sofia Lima' },
      { status: 'devolvida', quando: isoDias(-5), por: 'Ana Prado', motivo: 'Informe o número do processo disciplinar.' }] }),
    inv(37, 'preservacao_urgente', { expiracao: EXP_RISCO, investigador_usuario: 'investigador1', investigador: 'Igor Melo',
      aprovador_usuario: 'aprovador1', preservacao: { autorizada_em: isoDias(-1), escalona_em: isoDias(2), destroi_em: isoDias(4), prorrogada: false },
      linha_do_tempo: [
        { status: 'aguardando_aprovacao', quando: isoDias(-2), por: 'Sofia Lima' },
        { status: 'preservacao_urgente', quando: isoDias(-1), por: 'Ana Prado', motivo: 'Eventos de intranet expiram em 2 dias.' }] }),
    inv(36, 'coletando', { investigador_usuario: 'investigador1', investigador: 'Igor Melo', aprovador_usuario: 'aprovador1',
      progresso_pct: 45, progresso_interno: 45, linha_do_tempo: [
        { status: 'aguardando_aprovacao', quando: isoDias(-4), por: 'Sofia Lima' },
        { status: 'aprovada', quando: isoDias(-3), por: 'Ana Prado' },
        { status: 'coletando', quando: isoDias(-2), por: 'Igor Melo' }] }),
    inv(35, 'aprovada', { investigador_usuario: 'investigador1', investigador: 'Igor Melo', aprovador_usuario: 'aprovador1',
      linha_do_tempo: [{ status: 'aguardando_aprovacao', quando: isoDias(-5), por: 'Sofia Lima' },
        { status: 'aprovada', quando: isoDias(-4), por: 'Ana Prado' }] }),
    inv(34, 'pausada', { investigador_usuario: 'investigador1', investigador: 'Igor Melo', progresso_pct: 70, progresso_interno: 70 }),
    inv(33, 'concluida', { investigador_usuario: 'investigador1', investigador: 'Igor Melo', aprovador_usuario: 'aprovador1',
      progresso_pct: 100 }),
    inv(32, 'concluida_com_lacunas', { investigador_usuario: 'investigador1', investigador: 'Igor Melo', progresso_pct: 100 }),
    inv(31, 'falhou', { investigador_usuario: 'investigador1', investigador: 'Igor Melo', progresso_pct: 12 }),
    inv(30, 'recusada', { aprovador_usuario: 'aprovador1', linha_do_tempo: [
      { status: 'aguardando_aprovacao', quando: isoDias(-10), por: 'Sofia Lima' },
      { status: 'recusada', quando: isoDias(-9), por: 'Ana Prado', motivo: 'Fora da competência da corregedoria.' }] }),
    inv(29, 'cancelada'),
    inv(28, 'retencao_legal', { investigador_usuario: 'investigador1', investigador: 'Igor Melo' }),
    ...Array.from({ length: 24 }, (_, k) => inv(27 - k, 'concluida', { investigador_usuario: 'investigador2',
      investigador: 'Ivo Nunes', criado_em: isoDias(-20 - k) })),
  ]
}

export function acoesPara(i: InvDuble, u: UsuarioDuble): Acao[] {
  const p = u.papeis
  const a: Acao[] = []
  const soli = i.solicitante_usuario === u.usuario
  const invest = i.investigador_usuario === u.usuario
  if (soli && p.includes('solicitante') || soli && i.origem_externa) {
    if (i.status === 'rascunho') a.push('editar', 'enviar', 'descartar', 'enviar_documento')
    if (i.status === 'aguardando_aprovacao') a.push('cancelar')
    if (i.status === 'devolvida') a.push('editar', 'reenviar', 'cancelar', 'enviar_documento')
  }
  if (p.includes('aprovador') && !soli && !invest) {
    if (i.status === 'aguardando_aprovacao') {
      a.push('aprovar', 'devolver', 'recusar')
      if (i.preservacao_pedida) a.push('autorizar_preservacao')
    }
    if (i.status === 'preservacao_urgente') {
      a.push('aprovar', 'recusar')
      if (u.coordenador && !i.preservacao?.prorrogada) a.push('prorrogar_preservacao')
    }
    if (i.documento && ['aguardando_aprovacao', 'preservacao_urgente'].includes(i.status)) a.push('baixar_documento')
  }
  if (invest && p.includes('investigador')) {
    if (i.status === 'aprovada') a.push('iniciar')
    if (i.status === 'coletando') a.push('pausar', 'cancelar')
    if (i.status === 'pausada') a.push('retomar', 'cancelar')
    if (i.status === 'falhou') a.push('retomar')
    if (['concluida', 'concluida_com_lacunas'].includes(i.status)) a.push('gerar_pacote', 'pedir_sem_mascara')
    if (i.documento) a.push('baixar_documento')
  }
  return a
}

export function podeVer(i: InvDuble, u: UsuarioDuble): boolean {
  if (u.papeis.includes('auditor_interno')) return true
  if (i.solicitante_usuario === u.usuario || i.investigador_usuario === u.usuario) return true
  if (u.papeis.includes('aprovador') && (i.aprovador_usuario === u.usuario ||
    ['aguardando_aprovacao', 'preservacao_urgente'].includes(i.status))) return true
  return false
}

export function notificacoesSemente(): Notificacao[] {
  return [
    { id: 3, tipo: 'pedido_devolvido', texto: 'O pedido da investigação 38 foi devolvido para correção.', investigacao: 38, quando: isoDias(-0.2), lida: false },
    { id: 2, tipo: 'coleta_concluida', texto: 'A coleta da investigação 33 terminou.', investigacao: 33, quando: isoDias(-1), lida: false },
    { id: 1, tipo: 'pedido_recebido', texto: 'Há uma decisão pendente na investigação 40.', investigacao: 40, quando: isoDias(-2), lida: true },
  ]
}

export function pacotesSemente(): Record<number, Pacote[]> {
  return {
    33: [
      { pacote: 7, sem_mascara: false, status: 'pronto', sha256: 'ab12cd34'.repeat(8), criado_em: isoDias(-0.5), expira_em: null },
      { pacote: 6, sem_mascara: true, status: 'expirado', sha256: 'ef56ab78'.repeat(8), criado_em: isoDias(-3), expira_em: isoDias(-2) },
    ],
  }
}

export const PERFIS: Perfil[] = Object.values(USUARIOS).map((u, k) => ({ username: u.usuario, nome: u.nome, unidade: u.unidade,
  papeis: u.papeis, ultimo_login: isoDias(-k), recertificado_em: k % 2 ? isoDias(-90) : null }))
