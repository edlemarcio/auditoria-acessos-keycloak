import type { ResultadoVerificacao } from '../api/tipos'
import { Icone, Mensagem } from './Estado'

const MARCA = { ok: { icone: 'fa-check-circle', rotulo: 'Confere', tom: 'tom-verde' },
  aviso: { icone: 'fa-exclamation-triangle', rotulo: 'Aviso', tom: 'tom-ambar' },
  falha: { icone: 'fa-times-circle', rotulo: 'Falha', tom: 'tom-vermelho' } } as const

/** Resultado do verificador offline em linguagem simples (§6.5), com o detalhe técnico recolhível. */
export function ResultadoVerif({ r, titulo = 'Verificação', compacto }: { r: ResultadoVerificacao; titulo?: string; compacto?: boolean }) {
  const falhas = r.itens.filter((i) => i.nivel === 'falha').length
  const avisos = r.itens.filter((i) => i.nivel === 'aviso').length
  return (
    <div className={`verificacao${compacto ? ' compacto' : ''}`}>
      <Mensagem tipo={r.integro ? (avisos ? 'warning' : 'success') : 'danger'} papel="status"
        titulo={compacto ? undefined : r.integro ? 'Pacote íntegro.' : 'Pacote não confere.'}>
        {r.frase}{avisos > 0 && r.integro ? ` ${avisos} aviso${avisos > 1 ? 's' : ''}.` : ''}
        {falhas > 0 ? ` ${falhas} falha${falhas > 1 ? 's' : ''}.` : ''}
      </Mensagem>
      <details className="detalhe-tecnico">
        <summary>{titulo}: detalhe técnico ({r.itens.length} conferências)</summary>
        <ul className="itens-verificacao">
          {r.itens.map((i, k) => <li key={k} className={MARCA[i.nivel].tom}>
            <Icone nome={MARCA[i.nivel].icone} /> <span className="sr-only">{MARCA[i.nivel].rotulo}: </span>{i.texto}</li>)}
        </ul>
        {r.resumo && <dl className="definicoes mono-dd">
          {['manifesto_sha256', 'raiz_merkle', 'key_id', 'carimbado_em', 'revogacao_conferida_ate'].filter((k) => r.resumo?.[k])
            .map((k) => <div key={k}><dt>{({ manifesto_sha256: 'SHA-256 do manifesto', raiz_merkle: 'Raiz Merkle', key_id: 'Chave',
              carimbado_em: 'Carimbo do tempo', revogacao_conferida_ate: 'Revogação conferida até' } as Record<string, string>)[k]}</dt>
              <dd className="mono">{String(r.resumo?.[k])}</dd></div>)}
        </dl>}
      </details>
    </div>
  )
}
