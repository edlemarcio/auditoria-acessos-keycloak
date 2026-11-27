import { Link } from 'react-router'
import { ErroApi } from '../api/cliente'
import { inicio, listarInvestigacoes } from '../api/rotas'
import type { Inicio as TInicio } from '../api/tipos'
import { ErroTela, Esqueleto, Icone, Indicador, Mensagem, Vazio } from '../componentes/Estado'
import { Titulo, usePagina } from '../componentes/Pagina'
import { dataHora, prazoRestante } from '../dominio/formato'
import { NOME_PAPEL, type Papel } from '../dominio/perfis'
import { useSessao } from '../sessao'
import { useCarregar } from '../usar'

const TIPO_DECISAO: Record<string, string> = { investigacao: 'Pedido de investigação', pacote_sem_mascara: 'Pacote sem máscara',
  preservacao_urgente: 'Preservação urgente' }
const ICONE_ALERTA: Record<string, string> = { instancia_fora: 'fa-plug', coleta_falhou: 'fa-exclamation-circle',
  papel_alterado: 'fa-user-shield', escalonamento: 'fa-level-up-alt', preservacao_expira: 'fa-hourglass-end' }

/** W1 ainda não tem /api/inicio: monta o mínimo a partir da lista (mesmos dados, sem regra nova). */
async function carregarInicio(papeis: string[]): Promise<TInicio & { parcial?: boolean }> {
  try {
    const r = await inicio()
    return { ...r, aguardando_minha_decisao: r.aguardando_minha_decisao ?? [], minhas_por_estado: r.minhas_por_estado ?? {}, alertas: r.alertas ?? [] }
  } catch (e) {
    if (!(e instanceof ErroApi && e.codigo === 'rota_inexistente')) throw e
    const porEstado: Record<string, number> = {}
    if (papeis.some((p) => ['solicitante', 'investigador', 'aprovador', 'auditor_interno'].includes(p))) {
      const l = await listarInvestigacoes({})
      for (const i of l.itens) porEstado[i.status] = (porEstado[i.status] ?? 0) + 1
    }
    return { perfil: papeis, aguardando_minha_decisao: [], minhas_por_estado: porEstado, alertas: [], nao_lidas: 0, parcial: true }
  }
}

export function Inicio() {
  const { eu, tem } = useSessao()
  usePagina('Início')
  const { dados, erro, carregando, recarregar } = useCarregar(() => carregarInicio(eu.papeis), [eu.sub])

  const atalhos = [
    tem('solicitante') && <Link key="n" className="br-button primary" to="/nova"><Icone nome="fa-plus" /> Nova solicitação</Link>,
    tem('investigador') && <Link key="e" className="br-button secondary" to="/nova?externo=1"><Icone nome="fa-file-import" /> Registrar pedido externo</Link>,
    tem('aprovador') && <Link key="a" className="br-button secondary" to="/aprovacoes"><Icone nome="fa-gavel" /> Aprovações</Link>,
    tem('auditor_interno') && <Link key="t" className="br-button secondary" to="/trilha"><Icone nome="fa-stream" /> Trilha global</Link>,
    tem('admin_tecnico') && <Link key="ad" className="br-button secondary" to="/administracao"><Icone nome="fa-server" /> Administração</Link>,
    tem('gestor_acesso') && <Link key="p" className="br-button secondary" to="/perfis"><Icone nome="fa-users-cog" /> Perfis e acessos</Link>,
  ].filter(Boolean)
  const veInvestigacoes = tem('solicitante', 'investigador', 'aprovador', 'auditor_interno')

  return (
    <section>
      <Titulo>Olá, {eu.nome?.split(' ')[0] || eu.usuario}</Titulo>
      <p className="subtitulo-tela">Perfil: {eu.papeis.map((p) => NOME_PAPEL[p as Papel] ?? p).join(', ') || 'nenhum'}</p>
      {atalhos.length > 0 && <div className="atalhos" role="group" aria-label="Atalhos">{atalhos}</div>}
      {carregando && !dados ? <Esqueleto linhas={6} rotulo="Carregando o início" /> : erro ? <ErroTela erro={erro} tentar={recarregar} /> : dados && (
        <div className="grade-inicio">
          {tem('aprovador') && (
            <section className="br-card" aria-labelledby="t-decisao">
              <div className="card-header"><h2 id="t-decisao">Aguardando minha decisão</h2></div>
              <div className="card-content">
                {dados.aguardando_minha_decisao.length === 0 ? <Vazio>Nada aguardando sua decisão.</Vazio> : (
                  <ul className="lista-simples">
                    {dados.aguardando_minha_decisao.map((d) => {
                      const p = prazoRestante(d.prazo)
                      return (
                        <li key={d.pedido}>
                          <Link to={`/aprovacoes/${d.pedido}?inv=${d.investigacao}&tipo=${d.tipo}`}>
                            {TIPO_DECISAO[d.tipo] ?? d.tipo} · investigação {d.investigacao}</Link>
                          <span className={`prazo${p.vencido ? ' vencido' : ''}`}><Icone nome="fa-clock" /> {p.texto}</span>
                          {d.escalonado && <span className="estado tom-ambar"><Icone nome="fa-level-up-alt" /> Escalonado</span>}
                        </li>
                      )
                    })}
                  </ul>
                )}
              </div>
            </section>
          )}
          {veInvestigacoes && (
            <section className="br-card" aria-labelledby="t-minhas">
              <div className="card-header"><h2 id="t-minhas">{tem('auditor_interno') && !tem('solicitante', 'investigador') ? 'Investigações por estado' : 'Minhas investigações'}</h2></div>
              <div className="card-content">
                {Object.keys(dados.minhas_por_estado).length === 0 ? <Vazio>Nenhuma investigação ainda.</Vazio> : (
                  <ul className="lista-estados">
                    {Object.entries(dados.minhas_por_estado).map(([s, n]) => (
                      <li key={s}><Link to={`/investigacoes?visao=minhas&estado=${s}`}>
                        <span className="numero">{n}</span> <Indicador status={s} /></Link></li>
                    ))}
                  </ul>
                )}
                <Link to="/investigacoes" className="ver-todas">Ver todas as investigações</Link>
              </div>
            </section>
          )}
          <section className="br-card" aria-labelledby="t-alertas">
            <div className="card-header"><h2 id="t-alertas">Alertas</h2></div>
            <div className="card-content">
              {dados.parcial && <Mensagem tipo="info">Alertas e fila de decisões chegam com o servidor do W2.</Mensagem>}
              {dados.alertas.length === 0 ? <Vazio>Nenhum alerta.</Vazio> : (
                <ul className="lista-simples">
                  {dados.alertas.map((a, k) => (
                    <li key={k} className="alerta">
                      <Icone nome={ICONE_ALERTA[a.tipo] ?? 'fa-bell'} />
                      <span>{a.investigacao != null ? <Link to={`/investigacoes/${a.investigacao}`}>{a.texto}</Link> : a.texto}</span>
                      <span className="quando">{dataHora(a.quando)}</span>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </section>
        </div>
      )}
    </section>
  )
}
