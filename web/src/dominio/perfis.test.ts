import { menuPara } from './perfis'

const rotas = (p: string[]) => menuPara(p).map((m) => m.rotulo)

describe('barra lateral filtrada por perfil (§7.1)', () => {
  it('solicitante', () => expect(rotas(['solicitante'])).toEqual(['Início', 'Investigações', 'Verificar pacote']))
  it('aprovador', () => expect(rotas(['aprovador'])).toEqual(['Início', 'Investigações', 'Aprovações', 'Verificar pacote']))
  it('auditor interno', () => expect(rotas(['auditor_interno'])).toEqual(['Início', 'Investigações', 'Verificar pacote', 'Trilha global']))
  it('administrador técnico não vê investigações', () => expect(rotas(['admin_tecnico'])).toEqual(['Início', 'Administração']))
  it('gestor de acesso', () => expect(rotas(['gestor_acesso'])).toEqual(['Início', 'Perfis e acessos']))
  it('sem perfil: só Início', () => expect(rotas([])).toEqual(['Início']))
})
