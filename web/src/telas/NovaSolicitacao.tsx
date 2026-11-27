import { useEffect, useMemo, useRef, useState, type FormEvent, type ReactNode } from 'react'
import { useNavigate, useSearchParams } from 'react-router'
import { atualizarRascunho, detalhe, enviarDocumento, estimar, executar, pedir, type CorpoPedido } from '../api/rotas'
import type { Estimativa } from '../api/tipos'
import { Area, Caixa, Campo, Radio, Selecao } from '../componentes/Campo'
import { ErroTela, Esqueleto, Icone, Mensagem, textoErro } from '../componentes/Estado'
import { Titulo, usePagina } from '../componentes/Pagina'
import { mascarar, pareceIdentificador, soDigitos, validar, type TipoDocumento } from '../dominio/documentos'
import { data, duracao, numero } from '../dominio/formato'
import { useSessao } from '../sessao'

/** Tipo de processo → base legal (PROPOSTA §10.1). */
export const TIPOS_PROCESSO = [
  { id: 'apuracao_disciplinar', rotulo: 'Apuração administrativa ou disciplinar, controle interno', base: 'Art. 7º, II e art. 23, caput' },
  { id: 'processo_parte', rotulo: 'Instrução de processo judicial ou administrativo em que o órgão é parte', base: 'Art. 7º, VI' },
  { id: 'requisicao_externa', rotulo: 'Atendimento a requisição externa (juízo, MP, polícia, outro órgão)', base: 'Art. 7º, II, art. 23 e art. 26 (uso compartilhado)' },
]
const FUSOS = ['America/Bahia', 'America/Sao_Paulo', 'America/Manaus', 'America/Belem', 'America/Fortaleza', 'America/Recife',
  'America/Cuiaba', 'America/Porto_Velho', 'America/Rio_Branco', 'America/Noronha', 'UTC']
const PASSOS = ['Quem', 'Quando', 'Onde e como', 'Por quê', 'Revisão']
const hoje = () => new Date().toISOString().slice(0, 10)
const diasAtras = (n: number) => new Date(Date.now() - n * 86_400_000).toISOString().slice(0, 10)

interface Origem { orgao: string; documento: string; processo: string; fundamento: string; destinatario: string }
type Erros = Record<string, string>

export function NovaSolicitacao() {
  const { tem } = useSessao()
  const [sp] = useSearchParams()
  const navegar = useNavigate()
  const rascunhoParam = sp.get('rascunho')
  const externo = sp.get('externo') === '1' && tem('investigador') || undefined
  const tituloTela = rascunhoParam ? `Editar pedido nº ${rascunhoParam}` : externo ? 'Registrar pedido externo' : 'Nova solicitação'
  usePagina(tituloTela, [{ rotulo: 'Investigações', rota: '/investigacoes' }, { rotulo: tituloTela }])

  const [passo, setPasso] = useState(0)
  // ---- passo 1: o identificador completo só existe nesta ref (memória), até o POST/PUT
  const ident = useRef<string>('')
  const [tipoDoc, setTipoDoc] = useState<TipoDocumento>('cpf')
  const [digitado, setDigitado] = useState('')
  const [mascara, setMascara] = useState<string | null>(null)
  const [externoLigado, setExternoLigado] = useState(Boolean(externo))
  // ---- passo 2
  const [de, setDe] = useState(diasAtras(180))
  const [ate, setAte] = useState(diasAtras(1))
  const [fuso, setFuso] = useState('America/Bahia')
  const [granularidade, setGranularidade] = useState('dia')
  const [preservacao, setPreservacao] = useState(false)
  // ---- passo 3
  const [instSel, setInstSel] = useState<string[] | null>(null)
  const [varredura, setVarredura] = useState(false)
  const [baseDias, setBaseDias] = useState('30')
  // ---- passo 4
  const [tipoProcesso, setTipoProcesso] = useState(externo ? 'requisicao_externa' : '')
  const [processo, setProcesso] = useState('')
  const [justificativa, setJustificativa] = useState('')
  const [arquivo, setArquivo] = useState<File | null>(null)
  const [origem, setOrigem] = useState<Origem>({ orgao: '', documento: '', processo: '', fundamento: '', destinatario: '' })
  // ---- passo 5
  const [correcao, setCorrecao] = useState('')

  const [erros, setErros] = useState<Erros>({})
  const [est, setEst] = useState<{ v?: Estimativa; erro?: unknown; carregando: boolean }>({ carregando: false })
  const [rascunhoId, setRascunhoId] = useState<number | null>(rascunhoParam ? Number(rascunhoParam) : null)
  const [statusRascunho, setStatusRascunho] = useState<string | null>(null)
  const [carregandoRascunho, setCarregandoRascunho] = useState(Boolean(rascunhoParam))
  const [erroRascunho, setErroRascunho] = useState<unknown>(null)
  const [enviando, setEnviando] = useState(false)
  const [aviso, setAviso] = useState<{ tipo: 'success' | 'danger'; texto: string } | null>(null)
  const tituloPasso = useRef<HTMLHeadingElement>(null)
  const resumoErros = useRef<HTMLDivElement>(null)
  const montado = useRef(false)

  // edição de rascunho/devolvida: o servidor nunca devolve o identificador, só a máscara
  useEffect(() => {
    if (!rascunhoParam) return
    detalhe(Number(rascunhoParam)).then((d) => {
      setStatusRascunho(d.status)
      setTipoDoc((d.tipo as TipoDocumento) || 'cpf')
      setMascara(d.alvo_mascarado ?? null)
      if (d.de) setDe(d.de.slice(0, 10))
      if (d.ate) setAte(d.ate.slice(0, 10))
      setFuso(d.fuso ?? 'America/Bahia')
      setGranularidade(d.granularidade ?? 'dia')
      setInstSel(d.instancias ?? null)
      setVarredura(Boolean(d.varredura))
      setBaseDias(String(d.base_dias ?? 30))
      setTipoProcesso(d.tipo_processo ?? '')
      setProcesso(d.processo ?? '')
      setJustificativa(d.justificativa ?? '')
      if (d.origem) { setExternoLigado(true); setOrigem((o) => ({ ...o, ...d.origem })) }
    }).catch(setErroRascunho).finally(() => setCarregandoRascunho(false))
  }, [rascunhoParam])

  useEffect(() => {
    if (!montado.current) { montado.current = true; return }
    tituloPasso.current?.focus()
  }, [passo])

  // estimativa (passos 2 e 5): sem o identificador, não grava nada
  const corpoEstimativa = useMemo(() => ({ de, ate, fuso, granularidade, instancias: instSel ?? [], varredura,
    base_dias: Number(baseDias) || 0 }), [de, ate, fuso, granularidade, instSel, varredura, baseDias])
  useEffect(() => {
    if (!de || !ate || de > ate) return
    const c = new AbortController()
    const t = setTimeout(() => {
      setEst((e) => ({ ...e, carregando: true }))
      estimar(corpoEstimativa, c.signal).then((v) => setEst({ v, carregando: false }))
        .catch((erro) => { if (!c.signal.aborted) setEst({ erro, carregando: false }) })
    }, 350)
    return () => { clearTimeout(t); c.abort() }
  }, [corpoEstimativa, de, ate])

  const instanciasDisponiveis = useMemo(() => [...new Set((est.v?.expiracao ?? []).map((e) => e.instancia))], [est.v])
  const riscoExpiracao = Boolean(est.v?.preservacao_recomendada || est.v?.expiracao.some((e) => e.expira_antes_da_aprovacao))
  const externoAtivo = externoLigado && tem('investigador')

  // ---------------------------------------------------------------- passo 1: validação ao sair do campo
  function sairDoIdentificador() {
    if (mascara) return
    const e = validar(tipoDoc, digitado)
    if (e) { setErros((x) => ({ ...x, identificador: e })); return }
    ident.current = soDigitos(digitado)
    setMascara(mascarar(tipoDoc, ident.current))
    setDigitado('')
    setErros((x) => { const n = { ...x }; delete n.identificador; return n })
  }
  function trocarIdentificador() {
    ident.current = ''
    setMascara(null)
    setDigitado('')
    setTimeout(() => document.getElementById('campo-identificador')?.focus(), 0)
  }

  function validarPasso(p: number): Erros {
    const e: Erros = {}
    if (p === 0) {
      if (!mascara) e.identificador = validar(tipoDoc, digitado) ?? 'Saia do campo para validar.'
    }
    if (p === 1) {
      if (!de) e.de = 'Informe o início do período.'
      if (!ate) e.ate = 'Informe o fim do período.'
      if (de && ate && de > ate) e.ate = 'O fim do período deve ser depois do início.'
      if (ate && ate > hoje()) e.ate = 'O período não pode terminar no futuro.'
    }
    if (p === 2) {
      const b = Number(baseDias)
      if (!Number.isInteger(b) || b < 0 || b > 365) e.base_dias = 'Use um número de dias entre 0 e 365.'
      if (instSel && instSel.length === 0) e.instancias = 'Escolha pelo menos uma instância.'
    }
    if (p === 3) {
      if (!tipoProcesso) e.tipo_processo = 'Escolha o tipo de processo.'
      if (!processo.trim()) e.processo = 'Informe o número do processo.'
      if (justificativa.trim().length < 5) e.justificativa = 'Escreva a justificativa (pelo menos 5 caracteres).'
      else if (pareceIdentificador(justificativa)) e.justificativa = 'Não repita o CPF ou título na justificativa: ele já está no passo 1.'
      if (externoAtivo) {
        if (!origem.orgao.trim()) e.orgao = 'Informe o órgão de origem.'
        if (!origem.documento.trim()) e.documento_nr = 'Informe o nº do ofício ou da requisição.'
        if (!origem.fundamento.trim()) e.fundamento = 'Informe o fundamento legal da requisição.'
        if (!arquivo) e.arquivo = 'Pedido externo exige o documento de origem.'
      }
      if (arquivo && arquivo.size > 10 * 1024 * 1024) e.arquivo = 'O arquivo passa de 10 MB.'
      else if (arquivo && !/^(application\/pdf|image\/)/.test(arquivo.type)) e.arquivo = 'Envie um PDF ou uma imagem.'
    }
    if (p === 4 && statusRascunho === 'devolvida' && correcao.trim().length < 5) e.correcao = 'Diga o que foi corrigido (pelo menos 5 caracteres).'
    return e
  }

  function mostrarErros(e: Erros) {
    setErros(e)
    if (Object.keys(e).length) setTimeout(() => resumoErros.current?.focus(), 0)
  }

  function avancar(ev: FormEvent) {
    ev.preventDefault()
    if (passo === 0 && !mascara) sairDoIdentificador()
    const e = validarPasso(passo)
    if (passo === 0 && !mascara && !validar(tipoDoc, digitado)) delete e.identificador
    mostrarErros(e)
    if (Object.keys(e).length) return
    if (passo < 4) setPasso(passo + 1)
    else void enviar(false)
  }

  function corpo(rascunho: boolean): CorpoPedido {
    const c: CorpoPedido = { de, ate, fuso, granularidade, instancias: instSel, varredura, base_dias: Number(baseDias) || 0,
      justificativa: justificativa.trim(), tipo_processo: tipoProcesso, processo: processo.trim() || undefined, rascunho,
      preservacao_urgente: preservacao,
      origem: externoAtivo ? { ...origem, processo: origem.processo || processo } : null }
    if (ident.current) c[tipoDoc] = ident.current
    return c
  }

  async function enviar(soRascunho: boolean) {
    if (!soRascunho) {
      for (let p = 0; p < 5; p++) {
        const e = validarPasso(p)
        if (Object.keys(e).length) { setPasso(p); mostrarErros(e); return }
      }
    } else if (!mascara) {
      setPasso(0); mostrarErros({ identificador: 'Para salvar o rascunho, informe um CPF ou título válido.' }); return
    }
    setEnviando(true)
    setAviso(null)
    try {
      let id = rascunhoId
      const precisaRascunho = soRascunho || Boolean(arquivo) || id != null
      if (id == null) {
        const r = await pedir(corpo(precisaRascunho))
        id = r.investigacao
        setRascunhoId(id)
        setStatusRascunho(r.status)
      } else {
        await atualizarRascunho(id, corpo(true))
      }
      if (arquivo) { await enviarDocumento(id, arquivo); setArquivo(null) }
      if (soRascunho) {
        setAviso({ tipo: 'success', texto: `Rascunho nº ${id} salvo. Você pode continuar depois em Investigações.` })
        return
      }
      if (precisaRascunho) {
        if (statusRascunho === 'devolvida') await executar(id, 'reenviar', { motivo: correcao.trim() })
        else await executar(id, 'enviar')
      }
      ident.current = ''
      navegar(`/investigacoes/${id}`, { state: { aviso: 'Pedido enviado para aprovação.' } })
    } catch (e) {
      setAviso({ tipo: 'danger', texto: textoErro(e) })
    } finally { setEnviando(false) }
  }

  if (carregandoRascunho) return <section><Titulo>{tituloTela}</Titulo><Esqueleto linhas={6} /></section>
  if (erroRascunho) return <ErroTela erro={erroRascunho} investigacao={Number(rascunhoParam)} />

  const err = (k: string) => erros[k]
  const listaErros = Object.entries(erros)
  const ALVO_ERRO: Record<string, string> = { identificador: 'campo-identificador', de: 'campo-de', ate: 'campo-ate', base_dias: 'campo-base',
    instancias: 'grupo-instancias', tipo_processo: 'campo-tipo-processo', processo: 'campo-processo', justificativa: 'campo-justificativa',
    orgao: 'campo-orgao', documento_nr: 'campo-documento-nr', fundamento: 'campo-fundamento', arquivo: 'campo-arquivo', correcao: 'campo-correcao' }

  return (
    <section className="assistente">
      <Titulo>{tituloTela}</Titulo>
      <ol className="passos" aria-label="Passos do pedido">
        {PASSOS.map((p, k) => (
          <li key={p} className={k === passo ? 'atual' : k < passo ? 'feito' : ''} aria-current={k === passo ? 'step' : undefined}>
            <span className="passo-numero" aria-hidden="true">{k < passo ? <Icone nome="fa-check" /> : k + 1}</span>
            <span className="passo-rotulo"><span className="sr-only">Passo {k + 1} de 5: </span>{p}{k < passo && <span className="sr-only"> (concluído)</span>}</span>
          </li>
        ))}
      </ol>

      {aviso && <Mensagem tipo={aviso.tipo} papel={aviso.tipo === 'danger' ? 'alert' : 'status'}>{aviso.texto}</Mensagem>}
      {listaErros.length > 0 && (
        <div ref={resumoErros} tabIndex={-1} className="resumo-erros" role="alert" aria-labelledby="t-erros">
          <Mensagem tipo="danger" titulo={`Corrija ${listaErros.length === 1 ? 'o campo' : `os ${listaErros.length} campos`}:`}>
            <span id="t-erros" className="sr-only">Há erros no formulário</span>
            <ul>{listaErros.map(([k, v]) => <li key={k}><a href={`#${ALVO_ERRO[k] ?? k}`} onClick={(e) => { e.preventDefault();
              document.getElementById(ALVO_ERRO[k] ?? k)?.focus() }}>{v}</a></li>)}</ul>
          </Mensagem>
        </div>
      )}

      <form onSubmit={avancar} noValidate className="form-assistente">
        <h2 ref={tituloPasso} tabIndex={-1} className="titulo-passo">Passo {passo + 1} de 5 · {PASSOS[passo]}</h2>

        {passo === 0 && <>
          {externoAtivo && <Mensagem tipo="info">Pedido externo (ofício, requisição judicial): o solicitante é o órgão de origem, identificado
            pelo documento, que é obrigatório. Os dados do órgão vão no passo 4.</Mensagem>}
          <fieldset className="grupo">
            <legend>Identificador da pessoa investigada</legend>
            <div className="linha-radios">
              <Radio name="tipo-doc" rotulo="CPF" checked={tipoDoc === 'cpf'} disabled={Boolean(mascara)} onChange={() => setTipoDoc('cpf')} />
              <Radio name="tipo-doc" rotulo="Título de Eleitor" checked={tipoDoc === 'titulo'} disabled={Boolean(mascara)} onChange={() => setTipoDoc('titulo')} />
            </div>
          </fieldset>
          {mascara ? (
            <div className="identificador-mascarado">
              <Campo id="campo-identificador" rotulo={tipoDoc === 'cpf' ? 'CPF' : 'Título de Eleitor'} value={mascara} readOnly
                ajuda={<><Icone nome="fa-check-circle" /> Validado. Por segurança, o valor completo não é mostrado de novo.</>} />
              <button type="button" className="br-button secondary" onClick={trocarIdentificador}>Trocar identificador</button>
            </div>
          ) : (
            <Campo id="campo-identificador" rotulo={tipoDoc === 'cpf' ? 'CPF' : 'Título de Eleitor'} obrigatorio value={digitado}
              inputMode="numeric" autoComplete="off" spellCheck={false} erro={err('identificador')}
              ajuda={tipoDoc === 'cpf' ? 'Com ou sem pontuação. Ex.: 123.456.789-09' : '12 dígitos, com ou sem espaços.'}
              onChange={(e) => setDigitado(e.target.value)} onBlur={sairDoIdentificador} />
          )}
          {tem('investigador') && !rascunhoParam && <Caixa rotulo="É um pedido externo (ofício ou requisição)" checked={externoLigado}
            onChange={(e) => { setExternoLigado(e.target.checked); if (e.target.checked) setTipoProcesso('requisicao_externa') }} />}
        </>}

        {passo === 1 && <>
          <div className="linha-campos">
            <Campo id="campo-de" type="date" rotulo="Início do período" obrigatorio value={de} max={hoje()} onChange={(e) => setDe(e.target.value)} erro={err('de')} />
            <Campo id="campo-ate" type="date" rotulo="Fim do período" obrigatorio value={ate} max={hoje()} onChange={(e) => setAte(e.target.value)} erro={err('ate')} />
          </div>
          <div className="linha-campos">
            <Selecao rotulo="Fuso horário" value={fuso} onChange={(e) => setFuso(e.target.value)}
              ajuda="Horários da investigação aparecem neste fuso.">{FUSOS.map((f) => <option key={f} value={f}>{f}</option>)}</Selecao>
            <Selecao rotulo="Granularidade" value={granularidade} onChange={(e) => setGranularidade(e.target.value)}>
              <option value="dia">Dia</option><option value="hora">Hora</option></Selecao>
          </div>
          <Expiracao est={est} riscoExpiracao={riscoExpiracao} preservacao={preservacao} setPreservacao={setPreservacao} fuso={fuso} />
        </>}

        {passo === 2 && <>
          <fieldset className="grupo" id="grupo-instancias" tabIndex={-1} aria-describedby={err('instancias') ? 'erro-instancias' : undefined}>
            <legend>Instâncias do Keycloak</legend>
            {instanciasDisponiveis.length === 0 ? <p>Todas as instâncias cadastradas serão pesquisadas.</p> : <>
              <Caixa rotulo="Todas" checked={instSel == null} onChange={(e) => setInstSel(e.target.checked ? null : [...instanciasDisponiveis])} />
              {instanciasDisponiveis.map((n) => <Caixa key={n} rotulo={n} checked={instSel == null || instSel.includes(n)} onChange={(e) => {
                const base = instSel ?? [...instanciasDisponiveis]
                setInstSel(e.target.checked ? [...new Set([...base, n])] : base.filter((x) => x !== n))
              }} />)}
            </>}
            {err('instancias') && <span className="feedback danger" id="erro-instancias" role="alert">{err('instancias')}</span>}
          </fieldset>
          <Caixa rotulo="Varredura de falhas sem conta" checked={varredura} onChange={(e) => setVarredura(e.target.checked)}
            ajuda="Procura também tentativas de login com o identificador que não chegaram a uma conta. Aumenta o tempo de coleta." />
          <Campo id="campo-base" type="number" min={0} max={365} rotulo="Período de base para “IP novo” (dias)" value={baseDias}
            onChange={(e) => setBaseDias(e.target.value)} erro={err('base_dias')} ajuda="Dias antes do período usados para dizer se um IP é novo. 0 desliga." />
        </>}

        {passo === 3 && <>
          <Selecao id="campo-tipo-processo" rotulo="Tipo de processo" obrigatorio value={tipoProcesso} onChange={(e) => setTipoProcesso(e.target.value)}
            erro={err('tipo_processo')} ajuda={TIPOS_PROCESSO.find((t) => t.id === tipoProcesso)
              ? `Base legal registrada: LGPD, ${TIPOS_PROCESSO.find((t) => t.id === tipoProcesso)!.base}.` : 'Define a base legal registrada na investigação.'}>
            <option value="">Escolha…</option>
            {TIPOS_PROCESSO.map((t) => <option key={t.id} value={t.id}>{t.rotulo}</option>)}
          </Selecao>
          <Campo id="campo-processo" rotulo="Nº do processo" obrigatorio value={processo} onChange={(e) => setProcesso(e.target.value)} erro={err('processo')}
            autoComplete="off" ajuda="Ex.: 0001234-12.2026.6.05.0000 ou o nº do processo SEI." />
          <Area id="campo-justificativa" rotulo="Justificativa" obrigatorio rows={4} value={justificativa} onChange={(e) => setJustificativa(e.target.value)}
            erro={err('justificativa')} ajuda="Por que estes acessos precisam ser apurados. Fica cifrada; o aprovador lê para decidir." />
          {externoAtivo && <fieldset className="grupo">
            <legend>Pedido externo</legend>
            <Campo id="campo-orgao" rotulo="Órgão de origem" obrigatorio value={origem.orgao} onChange={(e) => setOrigem({ ...origem, orgao: e.target.value })} erro={err('orgao')} />
            <Campo id="campo-documento-nr" rotulo="Nº do ofício ou da requisição" obrigatorio value={origem.documento}
              onChange={(e) => setOrigem({ ...origem, documento: e.target.value })} erro={err('documento_nr')} />
            <Area id="campo-fundamento" rotulo="Fundamento legal da requisição" obrigatorio rows={2} value={origem.fundamento}
              onChange={(e) => setOrigem({ ...origem, fundamento: e.target.value })} erro={err('fundamento')} />
            <Campo rotulo="Destinatário dos dados" value={origem.destinatario} onChange={(e) => setOrigem({ ...origem, destinatario: e.target.value })}
              ajuda="O pacote sem máscara só pode ter como destino quem requisitou com fundamento." />
          </fieldset>}
          <Campo id="campo-arquivo" type="file" rotulo={`Documento de origem${externoAtivo ? '' : ' (opcional)'}`} obrigatorio={externoAtivo}
            accept="application/pdf,image/*" onChange={(e) => setArquivo(e.target.files?.[0] ?? null)} erro={err('arquivo')}
            ajuda={arquivo ? `Selecionado: ${arquivo.name} (${numero(Math.round(arquivo.size / 1024))} KB). Vai cifrado; o hash entra na trilha.`
              : 'PDF ou imagem, até 10 MB. Vai cifrado; o hash entra na trilha e no manifesto.'} />
        </>}

        {passo === 4 && <>
          <dl className="revisao">
            <Item rotulo={tipoDoc === 'cpf' ? 'CPF' : 'Título de Eleitor'}><span className="mono">{mascara}</span></Item>
            {externoAtivo && <Item rotulo="Órgão de origem">{origem.orgao} · {origem.documento}</Item>}
            <Item rotulo="Período">{data(de)} a {data(ate)} ({fuso}, por {granularidade})</Item>
            <Item rotulo="Instâncias">{instSel == null ? 'Todas' : instSel.join(', ')}</Item>
            <Item rotulo="Opções">{varredura ? 'Com' : 'Sem'} varredura de falhas sem conta · base de IP novo: {baseDias} dias</Item>
            <Item rotulo="Tipo de processo">{TIPOS_PROCESSO.find((t) => t.id === tipoProcesso)?.rotulo ?? '—'}</Item>
            <Item rotulo="Nº do processo">{processo || '—'}</Item>
            <Item rotulo="Justificativa">{justificativa}</Item>
            <Item rotulo="Documento de origem">{arquivo ? arquivo.name : 'Nenhum novo'}</Item>
            <Item rotulo="Preservação urgente">{preservacao ? 'Pedida' : 'Não'}</Item>
            <Item rotulo="Estimativa">{est.carregando ? 'Calculando…' : est.v ? `${numero(est.v.tarefas)} tarefas · ${duracao(est.v.segundos)}` : 'Indisponível'}</Item>
          </dl>
          {statusRascunho === 'devolvida' && <Area id="campo-correcao" rotulo="O que foi corrigido" obrigatorio rows={2} value={correcao}
            onChange={(e) => setCorrecao(e.target.value)} erro={err('correcao')} ajuda="Vai para o aprovador junto com o reenvio." />}
          <Mensagem tipo="info" titulo="Aviso de privacidade.">Os dados desta solicitação e os eventos coletados serão tratados conforme o aviso
            de privacidade do auditor, só para a finalidade informada, e cada acesso fica registrado na trilha.</Mensagem>
        </>}

        <div className="botoes-assistente">
          {passo > 0 && <button type="button" className="br-button secondary" onClick={() => { setErros({}); setPasso(passo - 1) }}>
            <Icone nome="fa-arrow-left" /> Voltar</button>}
          <button type="button" className="br-button tertiary" onClick={() => enviar(true)} disabled={enviando}>
            <Icone nome="fa-save" /> Salvar rascunho</button>
          <button type="submit" className="br-button primary" disabled={enviando}>
            {passo < 4 ? <>Próximo <Icone nome="fa-arrow-right" /></> : enviando ? 'Enviando…'
              : <><Icone nome="fa-paper-plane" /> {statusRascunho === 'devolvida' ? 'Reenviar pedido' : 'Enviar pedido'}</>}
          </button>
        </div>
      </form>
    </section>
  )
}

function Item({ rotulo, children }: { rotulo: string; children: ReactNode }) {
  return <div className="item-revisao"><dt>{rotulo}</dt><dd>{children}</dd></div>
}

function Expiracao({ est, riscoExpiracao, preservacao, setPreservacao, fuso }: { est: { v?: Estimativa; erro?: unknown; carregando: boolean };
  riscoExpiracao: boolean; preservacao: boolean; setPreservacao: (b: boolean) => void; fuso: string }) {
  return (
    <section className="expiracao" aria-labelledby="t-expiracao">
      <h3 id="t-expiracao">Até quando os eventos existem na origem</h3>
      {est.erro ? <ErroTela erro={est.erro} /> : !est.v ? <Esqueleto linhas={3} rotulo="Calculando a expiração por realm" /> : <>
        <div className="br-table">
          <table>
            <caption className="sr-only">Eventos mais antigos disponíveis por realm</caption>
            <thead><tr><th scope="col">Instância</th><th scope="col">Realm</th><th scope="col">Eventos desde</th><th scope="col">Situação</th></tr></thead>
            <tbody>{est.v.expiracao.map((e) => (
              <tr key={`${e.instancia}/${e.realm}`}>
                <td>{e.instancia}</td><td>{e.realm}</td><td>{e.eventos_desde ? data(e.eventos_desde, fuso) : 'Sem eventos gravados'}</td>
                <td>{e.expira_antes_da_aprovacao
                  ? <span className="estado tom-ambar"><Icone nome="fa-hourglass-end" /> Expira antes da aprovação</span>
                  : <span className="estado tom-verde"><Icone nome="fa-check" /> Dentro do prazo</span>}</td>
              </tr>))}</tbody>
          </table>
        </div>
        {riscoExpiracao && (
          <Mensagem tipo="warning" titulo="Risco de perder eventos." papel="status">
            Eventos de algum realm deste período expiram antes do prazo normal de aprovação. Você pode pedir a preservação urgente: um
            aprovador autoriza só a coleta lacrada, e nenhuma tela de dados abre até a aprovação do pedido completo.
            <div className="mt-1">
              <button type="button" className={`br-button ${preservacao ? 'primary' : 'secondary'}`} aria-pressed={preservacao}
                onClick={() => setPreservacao(!preservacao)}>
                <Icone nome="fa-lock" /> {preservacao ? 'Preservação urgente pedida' : 'Pedir preservação urgente'}
              </button>
            </div>
          </Mensagem>
        )}
      </>}
    </section>
  )
}
