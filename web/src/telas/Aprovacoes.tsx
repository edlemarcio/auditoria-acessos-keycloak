import { useState, type FormEvent } from 'react'
import { Link } from 'react-router'
import { ErroApi } from '../api/cliente'
import { aprovacoes, definirSubstituto, inicio, substitutos } from '../api/rotas'
import type { ItemDecisao } from '../api/tipos'
import { Campo } from '../componentes/Campo'
import { ErroTela, Esqueleto, Icone, Mensagem, textoErro, Vazio } from '../componentes/Estado'
import { Titulo, usePagina } from '../componentes/Pagina'
import { dataHora, prazoRestante } from '../dominio/formato'
import { useSessao } from '../sessao'
import { useCarregar } from '../usar'

export const TIPO_PEDIDO: Record<string, { rotulo: string; icone: string }> = {
  investigacao: { rotulo: 'Pedido de investigação', icone: 'fa-search' },
  preservacao_urgente: { rotulo: 'Preservação urgente', icone: 'fa-lock' },
  pacote_sem_mascara: { rotulo: 'Pacote sem máscara', icone: 'fa-eye' },
}

/** Fila do W1 (/api/aprovacoes) com prazo e escalonamento vindos do /api/inicio (o contrato não os põe na fila). */
async function carregarFila(): Promise<(ItemDecisao & { criado_em?: string })[]> {
  const [fila, ini] = await Promise.all([aprovacoes(), inicio().catch(() => null)])
  const extra = new Map((ini?.aguardando_minha_decisao ?? []).map((x) => [x.pedido, x]))
  return (fila as (ItemDecisao & { criado_em?: string })[]).map((f) => ({ ...f, ...(extra.get(f.pedido) ?? {}), tipo: extra.get(f.pedido)?.tipo ?? f.tipo }))
    .sort((a, b) => (a.prazo ?? '9').localeCompare(b.prazo ?? '9'))
}

export function Aprovacoes() {
  usePagina('Aprovações', [{ rotulo: 'Aprovações' }])
  const { dados, erro, carregando, recarregar } = useCarregar(carregarFila, [])
  return (
    <section>
      <Titulo>Aprovações</Titulo>
      {carregando && !dados ? <Esqueleto linhas={5} rotulo="Carregando a fila" /> : erro ? <ErroTela erro={erro} tentar={recarregar} />
        : !dados?.length ? <Vazio>Nada aguardando sua decisão.</Vazio> : (
          <div className="br-table tabela-rolavel" tabIndex={0} role="region" aria-label="Fila de aprovações">
            <table>
              <caption className="sr-only">Pedidos aguardando sua decisão, os de prazo mais curto primeiro</caption>
              <thead><tr><th scope="col">Pedido</th><th scope="col">Tipo</th><th scope="col">Investigação</th><th scope="col">Desde</th>
                <th scope="col">Prazo</th><th scope="col">Risco</th><th scope="col"><span className="sr-only">Abrir</span></th></tr></thead>
              <tbody>{dados.map((d) => {
                const t = TIPO_PEDIDO[d.tipo] ?? { rotulo: d.tipo, icone: 'fa-question' }
                const p = prazoRestante(d.prazo)
                const risco = d.tipo === 'preservacao_urgente' || d.escalonado || p.vencido
                return (
                  <tr key={d.pedido} className={risco ? 'linha-risco' : undefined}>
                    <td>{d.pedido}</td>
                    <td><span className={`estado ${d.tipo === 'investigacao' ? 'tom-azul' : 'tom-ambar'}`}><Icone nome={t.icone} /> {t.rotulo}</span></td>
                    <td><Link to={`/investigacoes/${d.investigacao}`}>nº {d.investigacao}</Link></td>
                    <td>{dataHora(d.desde ?? d.criado_em)}</td>
                    <td className={p.vencido ? 'texto-perigo' : undefined}>{d.prazo ? p.texto : '—'}</td>
                    <td>{risco ? <span className="estado tom-ambar"><Icone nome="fa-exclamation-triangle" /> {d.tipo === 'preservacao_urgente'
                      ? 'Eventos expiram' : d.escalonado ? 'Escalonado' : 'Prazo vencido'}</span> : <span className="secundario">Normal</span>}</td>
                    <td><Link className="br-button small primary" to={`/aprovacoes/${d.pedido}?inv=${d.investigacao}&tipo=${d.tipo}`}>
                      Decidir<span className="sr-only"> o pedido {d.pedido}</span></Link></td>
                  </tr>
                )
              })}</tbody>
            </table>
          </div>
        )}
      <Substituto />
    </section>
  )
}

/** Substituto do aprovador (§4.2): pedido parado além de 1 dia útil escalona para ele. */
function Substituto() {
  const { eu } = useSessao()
  const { dados, erro, recarregar } = useCarregar(substitutos, [])
  const atual = dados?.find((s) => s.aprovador === eu.usuario)?.substituto
  const [novo, setNovo] = useState('')
  const [msg, setMsg] = useState<{ tipo: 'success' | 'danger'; texto: string } | null>(null)
  async function salvar(e: FormEvent) {
    e.preventDefault()
    if (!novo.trim()) return setMsg({ tipo: 'danger', texto: 'Informe o usuário do substituto.' })
    try { await definirSubstituto(novo.trim()); setMsg({ tipo: 'success', texto: 'Substituto atualizado.' }); setNovo(''); recarregar() }
    catch (x) { setMsg({ tipo: 'danger', texto: textoErro(x) }) }
  }
  if (erro instanceof ErroApi && erro.codigo === 'rota_inexistente') return null
  return (
    <section className="br-card mt-3" aria-labelledby="t-subst">
      <div className="card-header"><h2 id="t-subst">Meu substituto</h2></div>
      <div className="card-content">
        <p>{atual ? <>Hoje: <strong>{atual}</strong>.</> : 'Você ainda não tem substituto.'} Pedidos parados há mais de 1 dia útil vão para o
          substituto e, depois, para o coordenador.</p>
        <form onSubmit={salvar} className="linha-campos" noValidate>
          <Campo rotulo="Usuário do novo substituto (outro aprovador)" value={novo} onChange={(e) => setNovo(e.target.value)} autoComplete="off" />
          <button type="submit" className="br-button secondary alinhar-base">Salvar substituto</button>
        </form>
        <div aria-live="polite">{msg && <Mensagem tipo={msg.tipo}>{msg.texto}</Mensagem>}</div>
      </div>
    </section>
  )
}
