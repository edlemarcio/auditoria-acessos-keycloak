import { useEffect, useState, type FormEvent } from 'react'
import { useLocation, useNavigate } from 'react-router'
import { descartar, enviarDocumento, executar, pedirPacote, urlDocumento } from '../api/rotas'
import type { Acao } from '../api/tipos'
import { tomarRetomada } from '../armazenamento'
import { pareceIdentificador } from '../dominio/documentos'
import { Area, Caixa, Campo } from './Campo'
import { Dialogo } from './Dialogo'
import { Mensagem, textoErro } from './Estado'

/** Rótulos das ações do §7.2. A tela só mostra o que veio em `acoes` (calculado no servidor). */
export const ROTULO: Record<Acao, string> = {
  enviar: 'Enviar pedido', editar: 'Editar', descartar: 'Descartar rascunho', aprovar: 'Aprovar', devolver: 'Devolver para correção',
  recusar: 'Recusar', cancelar: 'Cancelar investigação', reenviar: 'Reenviar', autorizar_preservacao: 'Autorizar preservação urgente',
  prorrogar_preservacao: 'Prorrogar preservação', iniciar: 'Iniciar coleta', pausar: 'Pausar', retomar: 'Retomar',
  gerar_pacote: 'Gerar pacote mascarado', pedir_sem_mascara: 'Pedir pacote sem máscara', enviar_documento: 'Anexar documento de origem',
  baixar_documento: 'Baixar documento de origem',
}
const ICONE: Partial<Record<Acao, string>> = { aprovar: 'fa-check', recusar: 'fa-ban', devolver: 'fa-undo', iniciar: 'fa-play',
  pausar: 'fa-pause', retomar: 'fa-play', cancelar: 'fa-times', editar: 'fa-pencil-alt', enviar: 'fa-paper-plane',
  baixar_documento: 'fa-download', gerar_pacote: 'fa-box', autorizar_preservacao: 'fa-lock' }
const PRIMARIAS: Acao[] = ['aprovar', 'enviar', 'iniciar', 'retomar', 'reenviar', 'gerar_pacote']
const DIRETAS: Acao[] = ['iniciar', 'pausar', 'retomar', 'gerar_pacote']
const COM_MOTIVO: Acao[] = ['devolver', 'recusar', 'cancelar', 'reenviar', 'prorrogar_preservacao']
const COM_INVESTIGADOR: Acao[] = ['aprovar', 'autorizar_preservacao']

export interface AlvoAcoes { id: number; status: string; acoes: Acao[] }

export function AcoesInvestigacao({ inv, aoMudar, compacto, ocultar = [] }: { inv: AlvoAcoes; aoMudar: () => void;
  compacto?: boolean; ocultar?: Acao[] }) {
  const navegar = useNavigate()
  const local = useLocation()
  const [aberta, setAberta] = useState<Acao | null>(null)
  const [retomada, setRetomada] = useState(false)
  const [aviso, setAviso] = useState<{ tipo: 'success' | 'danger'; texto: string } | null>(null)
  const [ocupado, setOcupado] = useState(false)

  useEffect(() => {
    // volta do step-up: reabre a mesma ação (sem nada do que foi digitado) para o usuário confirmar
    const a = tomarRetomada(local.pathname, (x) => {
      const [acao, id] = x.split(':')
      return Number(id) === inv.id && inv.acoes.includes(acao as Acao) && !DIRETAS.includes(acao as Acao)
    })
    if (a) { setAberta(a.split(':')[0] as Acao); setRetomada(true) }
  }, [inv.id, inv.acoes, local.pathname])

  const visiveis = inv.acoes.filter((a) => !ocultar.includes(a))
  if (!visiveis.length && !aviso) return null

  async function rodar(acao: Acao, f: () => Promise<unknown>, msg: string) {
    setOcupado(true)
    try {
      await f()
      setAberta(null)
      setAviso({ tipo: 'success', texto: msg })
      aoMudar()
    } catch (e) {
      setAviso({ tipo: 'danger', texto: textoErro(e) })
      if (!DIRETAS.includes(acao)) throw e
    } finally { setOcupado(false) }
  }

  function clicar(a: Acao) {
    setAviso(null)
    if (a === 'editar') return navegar(`/nova?rascunho=${inv.id}`)
    if (DIRETAS.includes(a)) {
      const f = a === 'gerar_pacote' ? () => pedirPacote(inv.id, false) : () => executar(inv.id, a)
      return void rodar(a, f, a === 'gerar_pacote' ? 'Pacote mascarado pedido. Ele aparece em Pacotes quando ficar pronto.'
        : `${ROTULO[a]}: feito.`).catch(() => {})
    }
    setRetomada(false)
    setAberta(a)
  }

  return (
    <div className={`acoes${compacto ? ' compacto' : ''}`}>
      {aviso && <div className="acoes-aviso" role={aviso.tipo === 'danger' ? 'alert' : 'status'}>
        <Mensagem tipo={aviso.tipo}>{aviso.texto}</Mensagem></div>}
      <div className="acoes-botoes" role="group" aria-label={`Ações da investigação ${inv.id}`}>
        {visiveis.map((a) => a === 'baixar_documento'
          ? <a key={a} className={`br-button secondary${compacto ? ' small' : ''}`} href={urlDocumento(inv.id)} download>
              <i className="fas fa-download" aria-hidden="true" /> {ROTULO[a]}{compacto && <span className="sr-only"> da investigação {inv.id}</span>}</a>
          : <button key={a} type="button" disabled={ocupado}
              className={`br-button ${PRIMARIAS.includes(a) ? 'primary' : a === 'recusar' || a === 'descartar' ? 'secondary perigo' : 'secondary'}${compacto ? ' small' : ''}`}
              onClick={() => clicar(a)}>
              {ICONE[a] && <i className={`fas ${ICONE[a]}`} aria-hidden="true" />} {ROTULO[a]}
              {compacto && <span className="sr-only"> da investigação {inv.id}</span>}
            </button>)}
      </div>
      {aberta && <DialogoAcao acao={aberta} inv={inv} retomada={retomada} ocupado={ocupado} aoFechar={() => setAberta(null)}
        aoConfirmar={(f, msg) => rodar(aberta, f, msg)} aoDescartar={() => navegar('/investigacoes')} />}
    </div>
  )
}

function DialogoAcao({ acao, inv, retomada, ocupado, aoFechar, aoConfirmar, aoDescartar }: { acao: Acao; inv: AlvoAcoes; retomada: boolean;
  ocupado: boolean; aoFechar: () => void; aoConfirmar: (f: () => Promise<unknown>, msg: string) => Promise<void>; aoDescartar: () => void }) {
  const [motivo, setMotivo] = useState('')
  const [investigador, setInvestigador] = useState('')
  const [sigilosa, setSigilosa] = useState(false)
  const [destino, setDestino] = useState('')
  const [arquivo, setArquivo] = useState<File | null>(null)
  const [erros, setErros] = useState<Record<string, string>>({})
  const [erroServidor, setErroServidor] = useState<string | null>(null)

  const precisaMotivo = COM_MOTIVO.includes(acao) || COM_INVESTIGADOR.includes(acao)
  const enviarComo = (f: () => Promise<unknown>, msg: string) => aoConfirmar(f, msg).catch((e) => setErroServidor(textoErro(e)))

  function confirmar(e: FormEvent) {
    e.preventDefault()
    const er: Record<string, string> = {}
    if (precisaMotivo && motivo.trim().length < 5) er.motivo = 'Escreva o motivo (pelo menos 5 caracteres).'
    if (precisaMotivo && pareceIdentificador(motivo)) er.motivo = 'Não escreva CPF ou título no motivo.'
    if (COM_INVESTIGADOR.includes(acao) && !investigador.trim()) er.investigador = 'Informe o usuário do investigador designado.'
    if (acao === 'pedir_sem_mascara' && destino.trim().length < 5) er.destino = 'Informe destinatário, processo e nível de sigilo.'
    if (acao === 'enviar_documento') {
      if (!arquivo) er.arquivo = 'Escolha o arquivo.'
      else if (arquivo.size > 10 * 1024 * 1024) er.arquivo = 'O arquivo passa de 10 MB.'
      else if (!/^(application\/pdf|image\/)/.test(arquivo.type)) er.arquivo = 'Envie um PDF ou uma imagem.'
    }
    setErros(er)
    setErroServidor(null)
    if (Object.keys(er).length) {
      document.getElementById(`acao-${Object.keys(er)[0]}`)?.focus()
      return
    }
    const id = inv.id
    switch (acao) {
      case 'aprovar': return void enviarComo(() => executar(id, 'aprovar', { investigador: investigador.trim(), motivo, sigilosa }),
        `Pedido aprovado e investigador ${investigador.trim()} designado.`)
      case 'autorizar_preservacao': return void enviarComo(() => executar(id, 'autorizar_preservacao', { investigador: investigador.trim(), motivo }),
        'Preservação urgente autorizada: a coleta roda lacrada até a decisão do pedido completo.')
      case 'pedir_sem_mascara': return void enviarComo(() => pedirPacote(id, true, destino), 'Pedido de pacote sem máscara enviado ao aprovador.')
      case 'enviar_documento': return void enviarComo(() => enviarDocumento(id, arquivo!), 'Documento de origem anexado.')
      case 'enviar': return void enviarComo(() => executar(id, 'enviar'), 'Pedido enviado para aprovação.')
      case 'descartar': return void aoConfirmar(() => descartar(id), 'Rascunho descartado.').then(aoDescartar).catch((er) => setErroServidor(textoErro(er)))
      default: return void enviarComo(() => executar(id, acao, { motivo }), `${ROTULO[acao]}: feito.`)
    }
  }

  return (
    <Dialogo aberto titulo={`${ROTULO[acao]} · investigação ${inv.id}`} aoFechar={aoFechar}
      rodape={<>
        <button type="button" className="br-button secondary" onClick={aoFechar}>Voltar</button>
        <button type="submit" form="form-acao" className={`br-button primary${acao === 'recusar' || acao === 'descartar' ? ' perigo' : ''}`}
          disabled={ocupado}>{ocupado ? 'Enviando…' : `Confirmar: ${ROTULO[acao].toLowerCase()}`}</button>
      </>}>
      <form id="form-acao" onSubmit={confirmar} noValidate>
        {retomada && <Mensagem tipo="info" papel="status">Identidade confirmada. Revise e confirme a ação de novo.</Mensagem>}
        {erroServidor && <Mensagem tipo="danger" papel="alert">{erroServidor}</Mensagem>}
        {acao === 'recusar' && inv.status === 'preservacao_urgente' && <Mensagem tipo="warning">Recusar agora <strong>destrói a chave e os dados
          já coletados</strong> nesta preservação. Isso fica registrado na trilha com o fundamento.</Mensagem>}
        {acao === 'autorizar_preservacao' && <p>Autoriza só a <strong>coleta lacrada</strong>: os eventos são coletados e cifrados, mas nenhuma
          tela de dados abre até a aprovação do pedido completo. Sem decisão, escalona ao coordenador em 3 dias úteis e destrói os dados em 5.</p>}
        {acao === 'enviar' && <p>O pedido segue para a fila de aprovação. Você acompanha o estado na tela da investigação.</p>}
        {acao === 'descartar' && <p>O rascunho será apagado. Esta ação não pode ser desfeita.</p>}
        {COM_INVESTIGADOR.includes(acao) && <Campo id="acao-investigador" rotulo="Investigador designado (usuário)" obrigatorio
          value={investigador} onChange={(e) => setInvestigador(e.target.value)} erro={erros.investigador} autoComplete="off"
          ajuda="Precisa ser outra pessoa: solicitante, aprovador e investigador são diferentes na mesma investigação." />}
        {acao === 'aprovar' && <Caixa rotulo="Investigação sigilosa" checked={sigilosa} onChange={(e) => setSigilosa(e.target.checked)}
          ajuda="Esconde a existência desta investigação em sugestões de histórico para quem não tem vínculo." />}
        {acao === 'pedir_sem_mascara' && <Area id="acao-destino" rotulo="Destinatário e destino" obrigatorio value={destino} rows={3}
          onChange={(e) => setDestino(e.target.value)} erro={erros.destino}
          ajuda="Processo, nível de sigilo e quem requisitou com fundamento. O aprovador decide; o pacote fica disponível por 24 h." />}
        {acao === 'enviar_documento' && <Campo id="acao-arquivo" type="file" rotulo="Documento de origem (PDF ou imagem, até 10 MB)" obrigatorio
          accept="application/pdf,image/*" onChange={(e) => setArquivo(e.target.files?.[0] ?? null)} erro={erros.arquivo} />}
        {precisaMotivo && <Area id="acao-motivo" rotulo="Motivo" obrigatorio value={motivo} rows={3} onChange={(e) => setMotivo(e.target.value)}
          erro={erros.motivo} ajuda="Fica registrado na trilha. Não escreva CPF, título ou outros dados pessoais." />}
      </form>
    </Dialogo>
  )
}
