/** Perfis do realm dedicado (PROPOSTA §4.1) e navegação filtrada (§7.1). Itens sem permissão não aparecem. */
export type Papel = 'solicitante' | 'investigador' | 'aprovador' | 'auditor_interno' | 'admin_tecnico' | 'gestor_acesso'

export const NOME_PAPEL: Record<Papel, string> = {
  solicitante: 'Solicitante', investigador: 'Investigador', aprovador: 'Aprovador',
  auditor_interno: 'Auditor interno', admin_tecnico: 'Administrador técnico', gestor_acesso: 'Gestor de acesso',
}
export const PAPEIS = Object.keys(NOME_PAPEL) as Papel[]

export interface ItemMenu { rota: string; rotulo: string; icone: string; papeis: Papel[] | 'todos' }

export const MENU: ItemMenu[] = [
  { rota: '/', rotulo: 'Início', icone: 'fa-home', papeis: 'todos' },
  { rota: '/investigacoes', rotulo: 'Investigações', icone: 'fa-search',
    papeis: ['solicitante', 'investigador', 'aprovador', 'auditor_interno'] },
  { rota: '/aprovacoes', rotulo: 'Aprovações', icone: 'fa-gavel', papeis: ['aprovador'] },
  { rota: '/verificar-pacote', rotulo: 'Verificar pacote', icone: 'fa-certificate',
    papeis: ['solicitante', 'investigador', 'aprovador', 'auditor_interno'] },
  { rota: '/trilha', rotulo: 'Trilha global', icone: 'fa-stream', papeis: ['auditor_interno'] },
  { rota: '/administracao', rotulo: 'Administração', icone: 'fa-server', papeis: ['admin_tecnico'] },
  { rota: '/perfis', rotulo: 'Perfis e acessos', icone: 'fa-users-cog', papeis: ['gestor_acesso'] },
]

export const tem = (papeis: readonly string[], ...p: Papel[]) => p.some((x) => papeis.includes(x))

export function menuPara(papeis: readonly string[]): ItemMenu[] {
  return MENU.filter((m) => m.papeis === 'todos' || tem(papeis, ...m.papeis))
}
