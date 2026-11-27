import { useState, type FormEvent } from 'react'
import { abrirRecertificacao, alterarPapeis, confirmarRecertificacao, perfis, recertificacoes } from '../api/rotas'
import type { Perfil } from '../api/tipos'
import { Area, Caixa } from '../componentes/Campo'
import { Dialogo } from '../componentes/Dialogo'
import { ErroTela, Esqueleto, Icone, Mensagem, textoErro, Vazio } from '../componentes/Estado'
import { Titulo, usePagina } from '../componentes/Pagina'
import { pareceIdentificador } from '../dominio/documentos'
import { data, dataHora } from '../dominio/formato'
import { NOME_PAPEL, PAPEIS, type Papel } from '../dominio/perfis'
import { useCarregar } from '../usar'

/** Perfis e acessos (gestor de acesso, §4.3): concessões, revogações e recertificação. Combinações proibidas: o servidor recusa. */
export function Perfis() {
  usePagina('Perfis e acessos', [{ rotulo: 'Perfis e acessos' }])
  const lista = useCarregar(perfis, [])
  const rec = useCarregar(recertificacoes, [])
  const [editando, setEditando] = useState<Perfil | null>(null)
  const [msg, setMsg] = useState<{ tipo: 'success' | 'danger'; texto: string } | null>(null)
  const aberta = rec.dados?.find((r) => !r.concluida_em)

  return (
    <section>
      <Titulo>Perfis e acessos</Titulo>
      <div aria-live="polite">{msg && <Mensagem tipo={msg.tipo}>{msg.texto}</Mensagem>}</div>
      <section aria-labelledby="t-perfis">
        <h2 id="t-perfis">Usuários do realm dedicado</h2>
        {lista.carregando && !lista.dados ? <Esqueleto linhas={5} /> : lista.erro ? <ErroTela erro={lista.erro} tentar={lista.recarregar} />
          : !lista.dados?.length ? <Vazio>Nenhum usuário.</Vazio> : (
            <div className="br-table tabela-rolavel" tabIndex={0} role="region" aria-label="Usuários e perfis">
              <table>
                <thead><tr><th scope="col">Usuário</th><th scope="col">Nome</th><th scope="col">Unidade</th><th scope="col">Perfis</th>
                  <th scope="col">Último login</th><th scope="col">Recertificado</th><th scope="col"><span className="sr-only">Ações</span></th></tr></thead>
                <tbody>{lista.dados.map((p) => (
                  <tr key={p.username}>
                    <td className="mono">{p.username}</td><td>{p.nome ?? '—'}</td><td>{p.unidade ?? '—'}</td>
                    <td>{p.papeis.length ? p.papeis.map((x) => NOME_PAPEL[x as Papel] ?? x).join(', ') : <span className="secundario">nenhum</span>}</td>
                    <td>{dataHora(p.ultimo_login)}</td><td>{p.recertificado_em ? data(p.recertificado_em) : 'nunca'}</td>
                    <td><button type="button" className="br-button small secondary" onClick={() => setEditando(p)}>
                      Alterar perfis<span className="sr-only"> de {p.username}</span></button></td>
                  </tr>
                ))}</tbody>
              </table>
            </div>
          )}
      </section>
      <section aria-labelledby="t-rec" className="mt-3">
        <h2 id="t-rec">Recertificação semestral</h2>
        {rec.carregando && !rec.dados ? <Esqueleto linhas={2} /> : rec.erro ? <ErroTela erro={rec.erro} tentar={rec.recarregar} /> : aberta ? <>
          <p>Recertificação aberta em {data(aberta.criada_em)}{aberta.prazo ? `, prazo ${data(aberta.prazo)}` : ''}. O que não for confirmado é revogado.</p>
          {!aberta.pendentes?.length ? <Vazio>Nenhum perfil pendente.</Vazio> : <ul className="lista-simples">
            {aberta.pendentes.map((p) => <li key={p.username}><span className="mono">{p.username}</span>
              <span>{p.papeis.map((x) => NOME_PAPEL[x as Papel] ?? x).join(', ') || 'sem perfis'}</span>
              <span className="acoes-botoes">
                <button type="button" className="br-button small primary" onClick={() => confirmarRecertificacao(aberta.id, p.username, true)
                  .then(() => { rec.recarregar(); setMsg({ tipo: 'success', texto: `Perfis de ${p.username} mantidos.` }) })
                  .catch((e) => setMsg({ tipo: 'danger', texto: textoErro(e) }))}>Manter<span className="sr-only"> {p.username}</span></button>
                <button type="button" className="br-button small secondary perigo" onClick={() => confirmarRecertificacao(aberta.id, p.username, false)
                  .then(() => { rec.recarregar(); lista.recarregar(); setMsg({ tipo: 'success', texto: `Perfis de ${p.username} revogados.` }) })
                  .catch((e) => setMsg({ tipo: 'danger', texto: textoErro(e) }))}>Revogar<span className="sr-only"> {p.username}</span></button>
              </span></li>)}
          </ul>}
        </> : <>
          <p>Nenhuma recertificação aberta.</p>
          <button type="button" className="br-button secondary" onClick={() => abrirRecertificacao().then(rec.recarregar)
            .catch((e) => setMsg({ tipo: 'danger', texto: textoErro(e) }))}><Icone nome="fa-clipboard-check" /> Abrir recertificação</button>
        </>}
      </section>
      {editando && <DialogoPapeis p={editando} aoFechar={() => setEditando(null)}
        aoSalvar={(t) => { setEditando(null); setMsg({ tipo: 'success', texto: t }); lista.recarregar() }} />}
    </section>
  )
}

function DialogoPapeis({ p, aoFechar, aoSalvar }: { p: Perfil; aoFechar: () => void; aoSalvar: (t: string) => void }) {
  const [sel, setSel] = useState<string[]>(p.papeis)
  const [motivo, setMotivo] = useState('')
  const [erro, setErro] = useState<string | null>(null)
  async function salvar(e: FormEvent) {
    e.preventDefault()
    const conceder = sel.filter((x) => !p.papeis.includes(x))
    const revogar = p.papeis.filter((x) => !sel.includes(x))
    if (!conceder.length && !revogar.length) return setErro('Nenhuma mudança.')
    if (motivo.trim().length < 5) return setErro('Escreva o motivo (pelo menos 5 caracteres).')
    if (pareceIdentificador(motivo)) return setErro('Não escreva CPF ou título no motivo.')
    try { await alterarPapeis(p.username, conceder, revogar, motivo); aoSalvar(`Perfis de ${p.username} atualizados. O auditor interno foi alertado.`) }
    catch (x) { setErro(textoErro(x)) }
  }
  return (
    <Dialogo aberto titulo={`Perfis de ${p.username}`} aoFechar={aoFechar}
      rodape={<><button type="button" className="br-button secondary" onClick={aoFechar}>Voltar</button>
        <button type="submit" form="form-papeis" className="br-button primary">Salvar perfis</button></>}>
      <form id="form-papeis" onSubmit={salvar} noValidate>
        {erro && <Mensagem tipo="danger" papel="alert">{erro}</Mensagem>}
        <fieldset className="grupo"><legend>Perfis no auditor</legend>
          {PAPEIS.map((x) => <Caixa key={x} rotulo={NOME_PAPEL[x]} checked={sel.includes(x)}
            onChange={(e) => setSel(e.target.checked ? [...sel, x] : sel.filter((y) => y !== x))} />)}
        </fieldset>
        <p className="ajuda">Gestor de acesso e administrador técnico não acumulam outros perfis; o servidor recusa combinações proibidas.</p>
        <Area rotulo="Motivo" obrigatorio rows={2} value={motivo} onChange={(e) => setMotivo(e.target.value)} ajuda="Fica na trilha e gera alerta ao auditor interno." />
      </form>
    </Dialogo>
  )
}
