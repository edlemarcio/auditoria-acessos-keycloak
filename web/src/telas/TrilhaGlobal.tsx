import { useMemo, useState } from 'react'
import { Link } from 'react-router'
import { trilhaGlobal, verificarCadeia } from '../api/rotas'
import { Campo } from '../componentes/Campo'
import { ErroTela, Esqueleto, Icone, Mensagem, textoErro, Vazio } from '../componentes/Estado'
import { Titulo, usePagina } from '../componentes/Pagina'
import { dataHora } from '../dominio/formato'
import { useCarregar } from '../usar'

/** Trilha global (auditor interno, §7.3): todas as investigações, filtros por ator, ação e período, "Verificar cadeia". */
export function TrilhaGlobal() {
  usePagina('Trilha global', [{ rotulo: 'Trilha global' }])
  const { dados, erro, carregando, recarregar } = useCarregar(() => trilhaGlobal(), [])
  const [ator, setAtor] = useState('')
  const [acao, setAcao] = useState('')
  const [de, setDe] = useState('')
  const [ate, setAte] = useState('')
  const [pagina, setPagina] = useState(1)
  const [verif, setVerif] = useState<{ tipo: 'success' | 'warning' | 'danger'; texto: string } | null>(null)
  const [verificando, setVerificando] = useState(false)

  const filtrada = useMemo(() => (dados ?? []).filter((r) => (!ator || r.operador.includes(ator)) && (!acao || r.acao.includes(acao))
    && (!de || r.quando.slice(0, 10) >= de) && (!ate || r.quando.slice(0, 10) <= ate)), [dados, ator, acao, de, ate])
  const por = 50
  const paginas = Math.max(1, Math.ceil(filtrada.length / por))
  const pg = Math.min(pagina, paginas)

  async function verificar() {
    setVerificando(true)
    try {
      const r = await verificarCadeia()
      setVerif(r.integras === r.cadeias ? { tipo: 'success', texto: `Todas as ${r.cadeias} cadeias estão íntegras.` }
        : { tipo: 'warning', texto: `${r.cadeias - r.integras} de ${r.cadeias} cadeias com problema: ${Object.keys(r.problemas).map((k) => `nº ${k}`).join(', ')}.` })
    } catch (e) { setVerif({ tipo: 'danger', texto: textoErro(e) }) } finally { setVerificando(false) }
  }

  return (
    <section>
      <Titulo extra={<button type="button" className="br-button primary" onClick={verificar} disabled={verificando}>
        <Icone nome="fa-link" /> {verificando ? 'Verificando…' : 'Verificar cadeia'}</button>}>Trilha global</Titulo>
      <div aria-live="polite">{verif && <Mensagem tipo={verif.tipo}>{verif.texto}</Mensagem>}</div>
      <div className="filtros" role="search" aria-label="Filtrar a trilha">
        <Campo rotulo="Ator (sub)" value={ator} onChange={(e) => { setAtor(e.target.value); setPagina(1) }} />
        <Campo rotulo="Ação" value={acao} onChange={(e) => { setAcao(e.target.value); setPagina(1) }} />
        <Campo rotulo="De" type="date" value={de} onChange={(e) => { setDe(e.target.value); setPagina(1) }} />
        <Campo rotulo="Até" type="date" value={ate} onChange={(e) => { setAte(e.target.value); setPagina(1) }} />
      </div>
      {carregando && !dados ? <Esqueleto linhas={8} /> : erro ? <ErroTela erro={erro} tentar={recarregar} />
        : !filtrada.length ? <Vazio>Nenhum registro com estes filtros.</Vazio> : <>
          <p aria-live="polite" className="contagem">{filtrada.length} registros</p>
          <div className="br-table tabela-rolavel" tabIndex={0} role="region" aria-label="Registros da trilha">
            <table>
              <thead><tr><th scope="col">Investigação</th><th scope="col">Seq.</th><th scope="col">Quando</th><th scope="col">Ação</th>
                <th scope="col">Ator</th><th scope="col">Hash</th></tr></thead>
              <tbody>{filtrada.slice((pg - 1) * por, pg * por).map((r) => (
                <tr key={`${r.cadeia}-${r.seq}`}>
                  <td>{r.investigacao_id != null ? <Link to={`/investigacoes/${r.investigacao_id}`}>nº {r.investigacao_id}</Link> : '—'}</td>
                  <td>{r.seq}</td><td>{dataHora(r.quando)}</td><td>{r.acao}</td><td className="mono">{r.operador}</td>
                  <td className="mono hash">{r.hash.slice(0, 12)}…</td>
                </tr>
              ))}</tbody>
            </table>
          </div>
          {paginas > 1 && <nav className="br-pagination paginacao" aria-label="Paginação da trilha">
            <button type="button" className="br-button secondary small" disabled={pg <= 1} onClick={() => setPagina(pg - 1)}>Anterior</button>
            <span aria-current="page">Página {pg} de {paginas}</span>
            <button type="button" className="br-button secondary small" disabled={pg >= paginas} onClick={() => setPagina(pg + 1)}>Próxima</button>
          </nav>}
        </>}
    </section>
  )
}
