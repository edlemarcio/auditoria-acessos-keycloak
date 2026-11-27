import { screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { vi } from 'vitest'
import { navegador } from '../api/cliente'
import { sessaoDuble } from '../testes/preparar'
import { EU, renderizar } from '../testes/renderizar'
import { AcoesInvestigacao } from './AcoesInvestigacao'

describe('ações por investigação', () => {
  it('mostra só o que veio em `acoes`', () => {
    renderizar(<AcoesInvestigacao inv={{ id: 7, status: 'coletando', acoes: ['pausar', 'cancelar'] }} aoMudar={() => {}} />)
    expect(screen.getAllByRole('button').map((b) => b.textContent?.trim())).toEqual(['Pausar', 'Cancelar investigação'])
  })
  it('sem ações, nada aparece', () => {
    const { container } = renderizar(<AcoesInvestigacao inv={{ id: 7, status: 'concluida', acoes: [] }} aoMudar={() => {}} />)
    expect(container.querySelector('.acoes')).toBeNull()
  })
  it('recusar exige motivo; sem step-up recente vai ao login e guarda só o nome da ação', async () => {
    sessaoDuble('aprovador')
    const ir = vi.spyOn(navegador, 'ir').mockImplementation(() => {})
    const u = userEvent.setup()
    renderizar(<AcoesInvestigacao inv={{ id: 40, status: 'aguardando_aprovacao', acoes: ['aprovar', 'devolver', 'recusar'] }} aoMudar={() => {}} />,
      { rota: '/aprovacoes/140', eu: EU.aprovador })
    await u.click(screen.getByRole('button', { name: 'Recusar' }))
    const dialogo = screen.getByRole('dialog')
    await u.click(screen.getByRole('button', { name: /Confirmar: recusar/ }))
    expect(await screen.findByText(/Escreva o motivo/)).toBeInTheDocument()
    await u.type(screen.getByRole('textbox', { name: /Motivo/ }), 'Fora da competência desta unidade')
    await u.click(screen.getByRole('button', { name: /Confirmar: recusar/ }))
    await vi.waitFor(() => expect(ir).toHaveBeenCalledWith(expect.stringContaining('/auth/entrar?step_up=1&volta=')))
    const guardado = sessionStorage.getItem('kc-auditor:retomar') ?? ''
    expect(guardado).toContain('recusar:40')
    expect(guardado).not.toContain('competência')
    expect(dialogo).toBeInTheDocument()
    ir.mockRestore()
  })
})
