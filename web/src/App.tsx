import { BrowserRouter, Route, Routes } from 'react-router'
import { Estrutura } from './componentes/Estrutura'
import { ErroTela } from './componentes/Estado'
import { ProvedorPagina } from './componentes/Pagina'
import { ProvedorSessao } from './sessao'
import { Administracao } from './telas/Administracao'
import { Aprovacoes } from './telas/Aprovacoes'
import { Decisao } from './telas/Decisao'
import { Inicio } from './telas/Inicio'
import { Investigacao } from './telas/Investigacao'
import { Investigacoes } from './telas/Investigacoes'
import { NaoEncontrada, VerificarPacote } from './telas/Diversas'
import { NovaSolicitacao } from './telas/NovaSolicitacao'
import { Perfis } from './telas/Perfis'
import { SessaoExpirada } from './telas/SessaoExpirada'
import { TrilhaGlobal } from './telas/TrilhaGlobal'

export function Rotas() {
  return (
    <Routes>
      <Route path="/" element={<Inicio />} />
      <Route path="/investigacoes" element={<Investigacoes />} />
      <Route path="/investigacoes/:id" element={<Investigacao aba="resumo" />} />
      <Route path="/investigacoes/:id/dashboard" element={<Investigacao aba="dashboard" />} />
      <Route path="/investigacoes/:id/eventos" element={<Investigacao aba="eventos" />} />
      <Route path="/investigacoes/:id/contas" element={<Investigacao aba="contas" />} />
      <Route path="/investigacoes/:id/cobertura" element={<Investigacao aba="cobertura" />} />
      <Route path="/investigacoes/:id/pacotes" element={<Investigacao aba="pacotes" />} />
      <Route path="/investigacoes/:id/comparar" element={<Investigacao aba="comparar" />} />
      <Route path="/investigacoes/:id/trilha" element={<Investigacao aba="trilha" />} />
      <Route path="/nova" element={<NovaSolicitacao />} />
      <Route path="/aprovacoes" element={<Aprovacoes />} />
      <Route path="/aprovacoes/:pedido" element={<Decisao />} />
      <Route path="/administracao" element={<Administracao />} />
      <Route path="/perfis" element={<Perfis />} />
      <Route path="/trilha" element={<TrilhaGlobal />} />
      <Route path="/verificar-pacote" element={<VerificarPacote />} />
      <Route path="*" element={<NaoEncontrada />} />
    </Routes>
  )
}

export function App() {
  return (
    <BrowserRouter>
      <ProvedorSessao expirada={<SessaoExpirada />} erro={(e) => <main className="conteudo-solto"><h1>kc-auditor</h1><ErroTela erro={e} /></main>}>
        <ProvedorPagina>
          <Estrutura><Rotas /></Estrutura>
        </ProvedorPagina>
      </ProvedorSessao>
    </BrowserRouter>
  )
}
