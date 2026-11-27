import { useState, type FormEvent } from 'react'
import { pedirAcesso } from '../api/rotas'
import { Area } from '../componentes/Campo'
import { Mensagem, textoErro } from '../componentes/Estado'
import { pareceIdentificador } from '../dominio/documentos'

/** "Você não tem acesso a esta investigação" (§7.1): não revela se a investigação existe. */
export function SemAcesso({ investigacao }: { investigacao?: number }) {
  const [motivo, setMotivo] = useState('')
  const [erro, setErro] = useState<string | null>(null)
  const [feito, setFeito] = useState(false)
  const [abrindo, setAbrindo] = useState(false)

  async function enviar(e: FormEvent) {
    e.preventDefault()
    if (motivo.trim().length < 5) return setErro('Explique por que precisa do acesso (pelo menos 5 caracteres).')
    if (pareceIdentificador(motivo)) return setErro('Não escreva CPF ou título no motivo.')
    setErro(null)
    try { await pedirAcesso(investigacao!, motivo); setFeito(true) } catch (x) { setErro(textoErro(x)) }
  }

  return (
    <section className="sem-acesso" aria-labelledby="titulo-tela">
      <h1 id="titulo-tela" tabIndex={-1}><i className="fas fa-lock" aria-hidden="true" /> Você não tem acesso a esta investigação</h1>
      <p>Ela pode não existir ou você pode não ter vínculo com ela. Se precisa trabalhar nela, peça acesso ao aprovador:
        o pedido fica registrado na trilha.</p>
      {investigacao != null && (feito
        ? <Mensagem tipo="success" papel="status">Pedido de acesso registrado. O aprovador vai analisar.</Mensagem>
        : !abrindo
          ? <button type="button" className="br-button primary" onClick={() => setAbrindo(true)}>Pedir acesso ao aprovador</button>
          : <form onSubmit={enviar} noValidate className="form-estreito">
              <Area rotulo="Por que você precisa do acesso?" obrigatorio value={motivo} onChange={(e) => setMotivo(e.target.value)} erro={erro}
                rows={3} autoFocus />
              <button type="submit" className="br-button primary">Enviar pedido de acesso</button>
            </form>)}
    </section>
  )
}
