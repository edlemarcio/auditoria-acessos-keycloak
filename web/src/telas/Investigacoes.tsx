import { useState, type FormEvent } from 'react'
import { Link, useSearchParams } from 'react-router'
import { listarInvestigacoes } from '../api/rotas'
import { AcoesInvestigacao } from '../componentes/AcoesInvestigacao'
import { Caixa, Campo } from '../componentes/Campo'
import { ErroTela, Esqueleto, Icone, Indicador, Vazio } from '../componentes/Estado'
import { Titulo, usePagina } from '../componentes/Pagina'
import { pareceIdentificador } from '../dominio/documentos'
import { ESTADOS_FILTRO, indicador } from '../dominio/estados'
import { data, dataHora } from '../dominio/formato'
import { useSessao } from '../sessao'
import { useCarregar } from '../usar'

const VISOES = [
  { id: '', rotulo: 'Todas' },
  { id: 'minhas', rotulo: 'Minhas' },
  { id: 'aguardando', rotulo: 'Aguardando minha aprovação', so: 'aprovador' as const },
  { id: 'lacunas', rotulo: 'Com lacunas' },
  { id: 'retencao', rotulo: 'Em retenção legal' },
]

export function Investigacoes() {
  const { tem } = useSessao()
  usePagina('Investigações', [{ rotulo: 'Investigações', rota: '/investigacoes' }])
  const [sp, setSp] = useSearchParams()
  const filtro = { visao: sp.get('visao') ?? '', estado: sp.get('estado')?.split(',').filter(Boolean) ?? [], q: sp.get('q') ?? '',
    de: sp.get('de') ?? '', ate: sp.get('ate') ?? '', pagina: Number(sp.get('pagina') ?? 1) }
  const chave = sp.toString()
  const { dados, erro, carregando, recarregar } = useCarregar((s) => listarInvestigacoes(filtro, s), [chave])
  const [q, setQ] = useState(filtro.q)
  const [erroQ, setErroQ] = useState<string | null>(null)
  const [de, setDe] = useState(filtro.de)
  const [ate, setAte] = useState(filtro.ate)

  function mudar(m: Record<string, string | null>) {
    const n = new URLSearchParams(sp)
    for (const [k, v] of Object.entries(m)) { if (v) n.set(k, v); else n.delete(k) }
    if (!('pagina' in m)) n.delete('pagina')
    setSp(n)
  }
  function buscar(e: FormEvent) {
    e.preventDefault()
    // a busca é por nº ou processo; um CPF/título digitado aqui nunca vai para a URL
    if (pareceIdentificador(q)) { setErroQ('A busca é por nº da investigação ou do processo. Não digite CPF ou título.'); return }
    setErroQ(null)
    mudar({ q: q.trim() || null, de: de || null, ate: ate || null })
  }
  function alternarEstado(s: string) {
    const l = filtro.estado.includes(s) ? filtro.estado.filter((x) => x !== s) : [...filtro.estado, s]
    mudar({ estado: l.join(',') || null })
  }
  const paginas = dados ? Math.max(1, Math.ceil(dados.total / dados.por_pagina)) : 1
  const filtrado = filtro.q || filtro.estado.length || filtro.de || filtro.ate

  return (
    <section>
      <Titulo extra={<>
        {tem('solicitante') && <Link className="br-button primary" to="/nova"><Icone nome="fa-plus" /> Nova solicitação</Link>}
        {tem('investigador') && <Link className="br-button secondary" to="/nova?externo=1"><Icone nome="fa-file-import" /> Registrar pedido externo</Link>}
      </>}>Investigações</Titulo>

      <div className="visoes" role="group" aria-label="Visões salvas">
        {VISOES.filter((v) => !v.so || tem(v.so)).map((v) => (
          <button key={v.id} type="button" className={`br-button small ${filtro.visao === v.id ? 'primary' : 'secondary'}`}
            aria-pressed={filtro.visao === v.id} onClick={() => mudar({ visao: v.id || null })}>{v.rotulo}</button>
        ))}
      </div>

      <form className="filtros" onSubmit={buscar} role="search" aria-label="Buscar investigações" noValidate>
        <Campo rotulo="Nº da investigação ou do processo" value={q} onChange={(e) => setQ(e.target.value)} erro={erroQ}
          ajuda="Aceita com ou sem pontos, barras e traços." autoComplete="off" />
        <Campo rotulo="Criada de" type="date" value={de} onChange={(e) => setDe(e.target.value)} />
        <Campo rotulo="até" type="date" value={ate} onChange={(e) => setAte(e.target.value)} />
        <div className="filtros-botoes">
          <button type="submit" className="br-button primary"><Icone nome="fa-search" /> Buscar</button>
          {filtrado && <button type="button" className="br-button tertiary" onClick={() => { setQ(''); setDe(''); setAte('');
            mudar({ q: null, estado: null, de: null, ate: null }) }}>Limpar filtros</button>}
        </div>
        <details className="filtro-estados" open={filtro.estado.length > 0}>
          <summary>Estado{filtro.estado.length ? ` (${filtro.estado.length})` : ''}</summary>
          <fieldset>
            <legend className="sr-only">Filtrar por estado</legend>
            <div className="grade-caixas">
              {ESTADOS_FILTRO.map((s) => <Caixa key={s} rotulo={indicador(s).rotulo} checked={filtro.estado.includes(s)}
                onChange={() => alternarEstado(s)} />)}
            </div>
          </fieldset>
        </details>
      </form>

      <div aria-live="polite" className="contagem">{dados && !carregando && `${dados.total} investigaç${dados.total === 1 ? 'ão' : 'ões'}`}</div>
      {carregando && !dados ? <Esqueleto linhas={8} rotulo="Carregando investigações" /> : erro ? <ErroTela erro={erro} tentar={recarregar} />
        : dados && dados.itens.length === 0 ? (
          <Vazio acao={filtrado ? <button type="button" className="br-button secondary" onClick={() => mudar({ q: null, estado: null, de: null, ate: null })}>
            Limpar filtros</button> : undefined}>{filtrado ? 'Nenhuma investigação com estes filtros.' : 'Nenhuma investigação nesta visão.'}</Vazio>
        ) : dados && (
          <>
            <div className="br-table tabela-rolavel" tabIndex={0} role="region" aria-label="Lista de investigações">
              <table>
                <caption className="sr-only">Investigações, página {dados.pagina} de {paginas}</caption>
                <thead>
                  <tr>
                    <th scope="col">Nº</th><th scope="col">Estado</th><th scope="col">Alvo</th><th scope="col">Período</th>
                    <th scope="col">Processo</th><th scope="col">Responsáveis</th><th scope="col">Atualizada</th><th scope="col">Ações</th>
                  </tr>
                </thead>
                <tbody>
                  {dados.itens.map((i) => (
                    <tr key={i.id}>
                      <td><Link to={`/investigacoes/${i.id}`} aria-label={`Investigação ${i.id}`}>{i.id}</Link>
                        {i.origem_externa && <span className="selo-pequeno" title="Pedido externo"><Icone nome="fa-file-import" rotulo="Pedido externo" /></span>}
                        {i.sigilosa && <span className="selo-pequeno"><Icone nome="fa-user-secret" rotulo="Sigilosa" /></span>}</td>
                      <td><Indicador status={i.status} progresso={i.progresso_pct} />
                        {i.status === 'coletando' && i.progresso_pct != null && <progress max={100} value={i.progresso_pct}
                          aria-label={`Progresso da investigação ${i.id}`} />}</td>
                      <td className="mono">{i.alvo_mascarado ?? '—'}</td>
                      <td>{data(i.de, i.fuso ?? undefined)} – {data(i.ate, i.fuso ?? undefined)}</td>
                      <td className="mono">{i.processo ?? '—'}</td>
                      <td>{i.solicitante ?? '—'}{i.investigador && <><br /><span className="secundario">Inv.: {i.investigador}</span></>}</td>
                      <td>{dataHora(i.atualizado_em ?? i.criado_em)}</td>
                      <td><AcoesInvestigacao inv={i} aoMudar={recarregar} compacto ocultar={['baixar_documento', 'enviar_documento']} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {paginas > 1 && (
              <nav className="br-pagination paginacao" aria-label="Paginação">
                <button type="button" className="br-button secondary small" disabled={dados.pagina <= 1}
                  onClick={() => mudar({ pagina: String(dados.pagina - 1) })}><Icone nome="fa-angle-left" /> Anterior</button>
                <span aria-current="page">Página {dados.pagina} de {paginas}</span>
                <button type="button" className="br-button secondary small" disabled={dados.pagina >= paginas}
                  onClick={() => mudar({ pagina: String(dados.pagina + 1) })}>Próxima <Icone nome="fa-angle-right" /></button>
              </nav>
            )}
          </>
        )}
    </section>
  )
}
