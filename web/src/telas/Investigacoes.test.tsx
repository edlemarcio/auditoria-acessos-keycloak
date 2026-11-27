import { screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { sessaoDuble } from '../testes/preparar'
import { localAtual, renderizar } from '../testes/renderizar'
import { Investigacoes } from './Investigacoes'

describe('lista de investigações', () => {
  beforeEach(() => sessaoDuble('solicitante'))
  it('pagina, mostra ações só de `acoes` e busca por nº', async () => {
    const u = userEvent.setup()
    renderizar(<Investigacoes />, { rota: '/investigacoes' })
    expect(await screen.findByText('37 investigações')).toBeInTheDocument()
    expect(screen.getByText('Página 1 de 2')).toBeInTheDocument()
    expect(screen.getByRole('group', { name: 'Ações da investigação 41' })).toHaveTextContent(/Editar.*Enviar pedido.*Descartar/)
    expect(screen.queryByRole('group', { name: 'Ações da investigação 33' })).toBeNull()
    await u.type(screen.getByRole('textbox', { name: /Nº da investigação/ }), '000038-12.2026')
    await u.click(screen.getByRole('button', { name: /Buscar/ }))
    expect(await screen.findByText('1 investigação')).toBeInTheDocument()
  })
  it('um CPF digitado na busca nunca vai para a URL', async () => {
    const u = userEvent.setup()
    renderizar(<Investigacoes />, { rota: '/investigacoes' })
    await u.type(screen.getByRole('textbox', { name: /Nº da investigação/ }), '529.982.247-25')
    await u.click(screen.getByRole('button', { name: /Buscar/ }))
    expect(await screen.findByText(/Não digite CPF/)).toBeInTheDocument()
    expect(localAtual).toBe('/investigacoes')
  })
})
