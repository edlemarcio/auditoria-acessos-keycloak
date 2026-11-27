import { render } from '@testing-library/react'
import type { ReactElement } from 'react'
import { MemoryRouter, Route, Routes, useLocation } from 'react-router'
import type { Eu } from '../api/tipos'
import { ProvedorPagina } from '../componentes/Pagina'
import { SessaoFixa } from '../sessao'

export const EU: Record<string, Eu> = {
  solicitante: { sub: 's-1', usuario: 'solicitante1', nome: 'Sofia Lima', papeis: ['solicitante'] },
  investigador: { sub: 'i-1', usuario: 'investigador1', nome: 'Igor Melo', papeis: ['investigador'] },
  aprovador: { sub: 'a-1', usuario: 'aprovador1', nome: 'Ana Prado', papeis: ['aprovador'] },
}

export let localAtual = ''
function Espiao() { const l = useLocation(); localAtual = l.pathname + l.search; return null }

export function renderizar(el: ReactElement, { rota = '/', caminho = '*', eu = EU.solicitante } = {}) {
  return render(
    <MemoryRouter initialEntries={[rota]}>
      <SessaoFixa eu={eu}><ProvedorPagina>
        <Espiao />
        <Routes><Route path={caminho} element={el} /><Route path="*" element={<div>outra tela</div>} /></Routes>
      </ProvedorPagina></SessaoFixa>
    </MemoryRouter>,
  )
}
