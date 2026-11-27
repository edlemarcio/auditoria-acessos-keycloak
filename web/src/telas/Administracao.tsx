import { useState, type FormEvent } from 'react'
import { cadastrarInstancia, instancias, orcamento, saude, sondas, testarInstancia } from '../api/rotas'
import type { Instancia } from '../api/tipos'
import { Campo } from '../componentes/Campo'
import { Dialogo } from '../componentes/Dialogo'
import { ErroTela, Esqueleto, Icone, Mensagem, textoErro, Vazio } from '../componentes/Estado'
import { Titulo, usePagina } from '../componentes/Pagina'
import { dataHora } from '../dominio/formato'
import { useCarregar } from '../usar'

/** Administração técnica (§7.3): instâncias, testar conexão, sondas, orçamento, saúde dos workers e filas. */
export function Administracao() {
  usePagina('Administração', [{ rotulo: 'Administração' }])
  const lista = useCarregar(instancias, [])
  const sd = useCarregar(saude, [])
  const [resultado, setResultado] = useState<Record<string, { tipo: 'success' | 'danger' | 'info'; texto: string }>>({})
  const [orc, setOrc] = useState<Instancia | null>(null)
  const [nova, setNova] = useState(false)
  const [ocupado, setOcupado] = useState<string | null>(null)

  async function rodar(nome: string, oque: 'testar' | 'sondas') {
    setOcupado(`${oque}:${nome}`)
    try {
      if (oque === 'testar') {
        const r = await testarInstancia(nome)
        setResultado((x) => ({ ...x, [nome]: { tipo: 'success', texto: `Conexão ok${r.latencia_ms ? ` (${r.latencia_ms} ms)` : ''}.` } }))
      } else {
        const r = await sondas(nome)
        setResultado((x) => ({ ...x, [nome]: { tipo: 'info', texto: `Sondas: modo ${r.modo ?? '—'}; realms: ${r.realms.map((z) => `${z.realm} (${z.status})`).join(', ') || 'nenhum'}.` } }))
        lista.recarregar()
      }
    } catch (e) { setResultado((x) => ({ ...x, [nome]: { tipo: 'danger', texto: textoErro(e) } })) }
    finally { setOcupado(null) }
  }

  return (
    <section>
      <Titulo extra={<button type="button" className="br-button primary" onClick={() => setNova(true)}><Icone nome="fa-plus" /> Cadastrar instância</button>}>
        Administração</Titulo>
      <section aria-labelledby="t-inst">
        <h2 id="t-inst">Instâncias do Keycloak</h2>
        {lista.carregando && !lista.dados ? <Esqueleto linhas={3} /> : lista.erro ? <ErroTela erro={lista.erro} tentar={lista.recarregar} />
          : !lista.dados?.length ? <Vazio>Nenhuma instância cadastrada.</Vazio> : (
            <div className="br-table tabela-rolavel" tabIndex={0} role="region" aria-label="Instâncias">
              <table>
                <thead><tr><th scope="col">Nome</th><th scope="col">URL</th><th scope="col">Versão</th><th scope="col">Modo (sondas)</th>
                  <th scope="col">Orçamento</th><th scope="col">Ações</th></tr></thead>
                <tbody>{lista.dados.map((i) => (
                  <tr key={i.nome}>
                    <td>{i.nome}</td><td className="mono">{i.url}</td><td>{i.versao ?? '—'}</td>
                    <td>{i.modo ?? 'não sondada'}{i.sondas_em && <><br /><span className="secundario">{dataHora(i.sondas_em)}</span></>}</td>
                    <td>{i.concorrencia} {i.concorrencia === 1 ? 'conexão' : 'conexões'} · {i.req_por_s.toLocaleString('pt-BR')} req/s</td>
                    <td>
                      <div className="acoes-botoes" role="group" aria-label={`Ações da instância ${i.nome}`}>
                        <button type="button" className="br-button small secondary" disabled={ocupado != null} onClick={() => rodar(i.nome, 'testar')}>
                          Testar conexão<span className="sr-only"> de {i.nome}</span></button>
                        <button type="button" className="br-button small secondary" disabled={ocupado != null} onClick={() => rodar(i.nome, 'sondas')}>
                          Rodar sondas<span className="sr-only"> de {i.nome}</span></button>
                        <button type="button" className="br-button small secondary" onClick={() => setOrc(i)}>
                          Ajustar orçamento<span className="sr-only"> de {i.nome}</span></button>
                      </div>
                      <div aria-live="polite">{ocupado?.endsWith(`:${i.nome}`) ? <span>Executando…</span>
                        : resultado[i.nome] && <Mensagem tipo={resultado[i.nome].tipo}>{resultado[i.nome].texto}</Mensagem>}</div>
                    </td>
                  </tr>
                ))}</tbody>
              </table>
            </div>
          )}
      </section>
      <section aria-labelledby="t-saude" className="mt-3">
        <h2 id="t-saude">Saúde dos serviços e filas</h2>
        {sd.carregando && !sd.dados ? <Esqueleto linhas={3} /> : sd.erro ? <ErroTela erro={sd.erro} tentar={sd.recarregar} /> : sd.dados && (
          <div className="grade-inicio">
            <div className="br-card"><div className="card-header"><h3>Tarefas de coleta</h3></div><div className="card-content">
              <ul className="lista-kv">{Object.entries(sd.dados.filas?.tarefas ?? sd.dados.tarefas).map(([k, v]) => <li key={k}><span>{k}</span><strong>{v}</strong></li>)}</ul>
            </div></div>
            <div className="br-card"><div className="card-header"><h3>Jobs</h3></div><div className="card-content">
              <ul className="lista-kv">{Object.entries(sd.dados.filas?.jobs ?? sd.dados.jobs).map(([k, v]) => <li key={k}><span>{k}</span><strong>{v}</strong></li>)}</ul>
            </div></div>
            <div className="br-card"><div className="card-header"><h3>Workers</h3></div><div className="card-content">
              {!sd.dados.workers?.length ? <p>Sem informação de workers.</p> : <ul className="lista-kv">{sd.dados.workers.map((w) => {
                const atrasado = Date.now() - new Date(w.visto_em).getTime() > 120_000
                return <li key={w.papel}><span>{w.papel}</span><span className={`estado ${atrasado ? 'tom-vermelho' : 'tom-verde'}`}>
                  <Icone nome={atrasado ? 'fa-exclamation-circle' : 'fa-check'} /> {atrasado ? 'sem sinal' : 'ativo'} · {dataHora(w.visto_em)}</span></li>
              })}</ul>}
            </div></div>
          </div>
        )}
        <button type="button" className="br-button tertiary mt-1" onClick={sd.recarregar}><Icone nome="fa-sync" /> Atualizar</button>
      </section>
      {orc && <DialogoOrcamento inst={orc} aoFechar={() => setOrc(null)} aoSalvar={() => { setOrc(null); lista.recarregar() }} />}
      {nova && <DialogoInstancia aoFechar={() => setNova(false)} aoSalvar={() => { setNova(false); lista.recarregar() }} />}
    </section>
  )
}

function DialogoOrcamento({ inst, aoFechar, aoSalvar }: { inst: Instancia; aoFechar: () => void; aoSalvar: () => void }) {
  const [conc, setConc] = useState(String(inst.concorrencia))
  const [taxa, setTaxa] = useState(String(inst.req_por_s))
  const [erro, setErro] = useState<string | null>(null)
  async function salvar(e: FormEvent) {
    e.preventDefault()
    const c = Number(conc), t = Number(taxa.replace(',', '.'))
    if (!(Number.isInteger(c) && c >= 1 && c <= 8 && t >= 0.5 && t <= 20)) return setErro('Concorrência de 1 a 8 e taxa de 0,5 a 20 req/s.')
    try { await orcamento(inst.nome, c, t); aoSalvar() } catch (x) { setErro(textoErro(x)) }
  }
  return (
    <Dialogo aberto titulo={`Orçamento de carga · ${inst.nome}`} aoFechar={aoFechar}
      rodape={<><button type="button" className="br-button secondary" onClick={aoFechar}>Voltar</button>
        <button type="submit" form="form-orc" className="br-button primary">Salvar orçamento</button></>}>
      <form id="form-orc" onSubmit={salvar} noValidate>
        {erro && <Mensagem tipo="danger" papel="alert">{erro}</Mensagem>}
        <Campo rotulo="Conexões simultâneas (1 a 8)" type="number" min={1} max={8} value={conc} onChange={(e) => setConc(e.target.value)} />
        <Campo rotulo="Requisições por segundo (0,5 a 20)" inputMode="decimal" value={taxa} onChange={(e) => setTaxa(e.target.value)}
          ajuda="Vale para todos os processos de coleta juntos. Exige confirmar a identidade." />
      </form>
    </Dialogo>
  )
}

function DialogoInstancia({ aoFechar, aoSalvar }: { aoFechar: () => void; aoSalvar: () => void }) {
  const [f, setF] = useState({ nome: '', url: '', client_id: '', segredo: '', realm_auth: 'master', realms_esperados: '', homologacao: '', sonda: '' })
  const [erro, setErro] = useState<string | null>(null)
  const campo = (k: keyof typeof f) => ({ value: f[k], onChange: (e: { target: { value: string } }) => setF({ ...f, [k]: e.target.value }) })
  async function salvar(e: FormEvent) {
    e.preventDefault()
    if (!f.nome || !/^https?:\/\//.test(f.url) || !f.client_id || !f.segredo) return setErro('Preencha nome, URL (http/https), client_id e segredo.')
    try {
      await cadastrarInstancia({ ...f, realms_esperados: f.realms_esperados.split(',').map((x) => x.trim()).filter(Boolean),
        homologacao: f.homologacao || null, sonda: f.sonda || null })
      aoSalvar()
    } catch (x) { setErro(textoErro(x)) }
  }
  return (
    <Dialogo aberto largo titulo="Cadastrar instância" aoFechar={aoFechar}
      rodape={<><button type="button" className="br-button secondary" onClick={aoFechar}>Voltar</button>
        <button type="submit" form="form-inst" className="br-button primary">Cadastrar</button></>}>
      <form id="form-inst" onSubmit={salvar} noValidate>
        {erro && <Mensagem tipo="danger" papel="alert">{erro}</Mensagem>}
        <div className="linha-campos">
          <Campo rotulo="Nome" obrigatorio {...campo('nome')} />
          <Campo rotulo="URL" obrigatorio type="url" {...campo('url')} />
        </div>
        <div className="linha-campos">
          <Campo rotulo="Client ID" obrigatorio {...campo('client_id')} autoComplete="off" />
          <Campo rotulo="Segredo do client" obrigatorio type="password" {...campo('segredo')} autoComplete="new-password"
            ajuda="Vai cifrado no servidor e não volta para a tela." />
        </div>
        <div className="linha-campos">
          <Campo rotulo="Realm de autenticação" {...campo('realm_auth')} />
          <Campo rotulo="Realms esperados (separados por vírgula)" {...campo('realms_esperados')} />
        </div>
        <div className="linha-campos">
          <Campo rotulo="Realm de homologação (sondas)" {...campo('homologacao')} />
          <Campo rotulo="Usuário de sonda" {...campo('sonda')} autoComplete="off" />
        </div>
      </form>
    </Dialogo>
  )
}
