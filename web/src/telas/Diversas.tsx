import { Link } from 'react-router'
import { Titulo, usePagina } from '../componentes/Pagina'
import { Mensagem } from '../componentes/Estado'

export function NaoEncontrada() {
  usePagina('Página não encontrada')
  return <section><Titulo>Página não encontrada</Titulo><p>O endereço não existe. <Link to="/">Voltar ao início</Link></p></section>
}

/** Verificar pacote: o verificador de pacotes v2 chega no W5 (PROPOSTA §6.5). */
export function VerificarPacote() {
  usePagina('Verificar pacote', [{ rotulo: 'Verificar pacote' }])
  return (
    <section>
      <Titulo>Verificar pacote</Titulo>
      <Mensagem tipo="info">A verificação de pacotes pela web chega com o pacote v2 (etapa W5). Até lá, use o verificador
        offline descrito em <code>docs/STACK_E_USO.md</code>.</Mensagem>
    </section>
  )
}
