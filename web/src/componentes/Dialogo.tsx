import { useEffect, useId, useRef, type ReactNode } from 'react'

/**
 * Diálogo modal com <dialog> nativo: foco preso, Esc fecha, foco volta para quem abriu.
 * Visual do br-modal do gov.br DS.
 */
export function Dialogo({ aberto, titulo, aoFechar, children, rodape, largo }: { aberto: boolean; titulo: string;
  aoFechar: () => void; children: ReactNode; rodape?: ReactNode; largo?: boolean }) {
  const ref = useRef<HTMLDialogElement>(null)
  const id = useId()
  const antes = useRef<Element | null>(null)
  useEffect(() => {
    const d = ref.current
    if (!d) return
    if (aberto && !d.open) {
      antes.current = document.activeElement
      d.showModal()
      const alvo = d.querySelector<HTMLElement>('[data-foco-inicial], input, textarea, select, button:not(.fechar)')
      alvo?.focus()
    } else if (!aberto && d.open) {
      d.close()
      ;(antes.current as HTMLElement | null)?.focus?.()
    }
  }, [aberto])
  // desmontado aberto (o pai tirou o diálogo da tela): devolve o foco para quem abriu
  useEffect(() => () => {
    const el = antes.current as HTMLElement | null
    if (el && el.isConnected) setTimeout(() => el.focus(), 0)
  }, [])
  return (
    <dialog ref={ref} className={`br-modal dialogo${largo ? ' largo' : ''}`} aria-labelledby={id}
      onCancel={(e) => { e.preventDefault(); aoFechar() }}>
      {aberto && <>
        <div className="br-modal-header">
          <h2 id={id} className="dialogo-titulo">{titulo}</h2>
          <button type="button" className="br-button circle small fechar" aria-label="Fechar" onClick={aoFechar}>
            <i className="fas fa-times" aria-hidden="true" />
          </button>
        </div>
        <div className="br-modal-body">{children}</div>
        {rodape && <div className="br-modal-footer">{rodape}</div>}
      </>}
    </dialog>
  )
}
