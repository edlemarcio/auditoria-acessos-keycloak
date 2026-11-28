import { useEffect, useState, type FormEvent } from 'react'
import { Link } from 'react-router'
import { enviarVerificacao, verificacao } from '../api/rotas'
import type { Verificacao } from '../api/tipos'
import { Titulo, usePagina } from '../componentes/Pagina'
import { Campo } from '../componentes/Campo'
import { Mensagem, textoErro } from '../componentes/Estado'
import { ResultadoVerif } from '../componentes/Verificacao'
import { numero } from '../dominio/formato'

export function NaoEncontrada() {
  usePagina('Página não encontrada')
  return <section><Titulo>Página não encontrada</Titulo><p>O endereço não existe. <Link to="/">Voltar ao início</Link></p></section>
}

const LIMITE = 2 * 1024 ** 3

/** Verificar pacote (PROPOSTA §6.5): o arquivo vai para o worker de pacotes, que roda o verificador offline em streaming,
 * só com as chaves públicas publicadas, e apaga o arquivo em seguida. */
export function VerificarPacote() {
  usePagina('Verificar pacote', [{ rotulo: 'Verificar pacote' }])
  const [arquivo, setArquivo] = useState<File | null>(null)
  const [erro, setErro] = useState<string | null>(null)
  const [enviando, setEnviando] = useState(false)
  const [v, setV] = useState<Verificacao | null>(null)

  useEffect(() => {
    if (!v || v.status === 'pronta' || v.status === 'falhou') return
    const t = setInterval(() => { verificacao(v.verificacao).then(setV).catch((e) => setErro(textoErro(e))) }, 2000)
    return () => clearInterval(t)
  }, [v])

  async function enviar(e: FormEvent) {
    e.preventDefault()
    setErro(null)
    if (!arquivo) { setErro('Escolha o arquivo do pacote (.zip).'); document.getElementById('verif-arquivo')?.focus(); return }
    if (arquivo.size > LIMITE) { setErro('O pacote passa de 2 GB.'); return }
    setEnviando(true)
    setV(null)
    try { setV(await enviarVerificacao(arquivo)) } catch (er) { setErro(textoErro(er)) } finally { setEnviando(false) }
  }

  const andamento = v && (v.status === 'pendente' || v.status === 'verificando' || v.status === 'recebendo')
  return (
    <section>
      <Titulo>Verificar pacote</Titulo>
      <p>Confira um pacote de evidência (formato 2) já entregue: assinatura pela chave institucional publicada, carimbo do tempo,
        hashes de todos os arquivos, cadeia de custódia (folhas, fatias, trilha, âncoras diárias) e o recálculo dos resultados a
        partir dos eventos. É a mesma verificação do <code>kc-verificar</code>, que roda sem rede no computador de qualquer perito.</p>
      <form className="envio-arquivo" onSubmit={enviar} noValidate>
        <Campo id="verif-arquivo" type="file" rotulo="Pacote (.zip, até 2 GB)" obrigatorio accept=".zip,application/zip"
          onChange={(e) => setArquivo(e.target.files?.[0] ?? null)} erro={erro ?? undefined}
          ajuda="Só as chaves públicas publicadas são aceitas; uma chave enviada junto não vale. O arquivo é apagado depois da verificação." />
        <div><button type="submit" className="br-button primary" disabled={enviando || Boolean(andamento)}>
          {enviando ? 'Enviando…' : andamento ? 'Verificando…' : 'Verificar'}</button></div>
      </form>
      <div aria-live="polite">
        {andamento && <Mensagem tipo="info" papel="status">Pacote recebido ({numero(Math.round((v.tamanho ?? 0) / 1024))} KB). Verificando…</Mensagem>}
        {v?.status === 'falhou' && <Mensagem tipo="danger" papel="alert">Não foi possível verificar: {v.erro ?? 'erro no worker'}.</Mensagem>}
        {v?.status === 'pronta' && v.resultado && <>
          <ResultadoVerif r={v.resultado} titulo={v.nome ?? 'Pacote'} />
          <p className="secundario mono">SHA-256 do arquivo enviado: {v.sha256}</p>
        </>}
      </div>
    </section>
  )
}
