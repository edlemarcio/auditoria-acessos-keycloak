import { useEffect, useRef } from 'react'
import { useAoVivo } from '../api/aoVivo'
import { dataHora, numero } from '../dominio/formato'
import { Esqueleto, Icone, Mensagem } from './Estado'

/** Acompanhamento ao vivo (§7.3, §7.12): tarefas por instância, req/s contra o orçamento, falhas, término. */
export function Acompanhamento({ id, fuso, aoMudarStatus }: { id: number; fuso?: string; aoMudarStatus?: (status: string) => void }) {
  const { dados, conexao, anuncio } = useAoVivo(id, true)
  const status = dados?.status
  // o estado mudou no servidor (concluída, falhou, pausada por outra pessoa): a tela recarrega o detalhe e as ações
  const aviso = useRef(aoMudarStatus)
  aviso.current = aoMudarStatus
  useEffect(() => { if (status) aviso.current?.(status) }, [status])
  const parado = conexao === 'reconectando'
  return (
    <section className="br-card acompanhamento" aria-labelledby="t-acomp" data-conexao={conexao}>
      <div className="card-header linha-titulo">
        <h2 id="t-acomp">Acompanhamento</h2>
        <span className={`conexao conexao-${conexao}`}>
          {conexao === 'ao_vivo' && <><Icone nome="fa-circle" /> Ao vivo</>}
          {conexao === 'reconectando' && <><Icone nome="fa-sync" /> Reconectando…</>}
          {conexao === 'conectando' && <><Icone nome="fa-hourglass-half" /> Conectando…</>}
          {conexao === 'consulta_periodica' && <><Icone nome="fa-clock" /> Atualiza a cada 15 s</>}
        </span>
      </div>
      <div className="card-content">
        <p className="sr-only" aria-live="polite">{anuncio}</p>
        {!dados ? <Esqueleto linhas={3} rotulo="Carregando o acompanhamento" /> : <div className={parado ? 'congelado' : ''}>
          <div className="kpis">
            <div className="kpi"><span className="kpi-rotulo">Progresso</span><span className="kpi-valor">{Math.round(dados.progresso_pct)}%</span>
              <progress max={100} value={dados.progresso_pct} aria-label="Progresso da coleta" /></div>
            <div className="kpi"><span className="kpi-rotulo">Eventos coletados</span><span className="kpi-valor">{numero(dados.eventos)}</span></div>
            <div className="kpi"><span className="kpi-rotulo">Falhas · retentativas</span><span className="kpi-valor">{dados.falhas} · {dados.retentativas}</span></div>
            <div className="kpi"><span className="kpi-rotulo">Término estimado</span><span className="kpi-valor kpi-menor">{dataHora(dados.termino_estimado, fuso)}</span></div>
          </div>
          {dados.instancias.filter((i) => i.fora_do_ar_desde).map((i) => (
            <Mensagem key={i.nome} tipo="warning">{i.nome} não responde desde {dataHora(i.fora_do_ar_desde, fuso)}; a coleta dessa instância está em
              espera e será retomada sozinha.</Mensagem>
          ))}
          <div className="br-table">
            <table>
              <caption className="sr-only">Tarefas por instância</caption>
              <thead><tr><th scope="col">Instância</th><th scope="col">Pendentes</th><th scope="col">Executando</th><th scope="col">Concluídas</th>
                <th scope="col">Falharam</th><th scope="col">Requisições/s (orçamento)</th></tr></thead>
              <tbody>{dados.instancias.map((i) => (
                <tr key={i.nome}><td>{i.nome}</td><td>{i.tarefas.pendente}</td><td>{i.tarefas.executando}</td><td>{i.tarefas.concluida}</td>
                  <td>{i.tarefas.falhou}</td><td>{i.req_por_s.toLocaleString('pt-BR')} de {i.orcamento_req_por_s.toLocaleString('pt-BR')}</td></tr>
              ))}</tbody>
            </table>
          </div>
        </div>}
      </div>
    </section>
  )
}
