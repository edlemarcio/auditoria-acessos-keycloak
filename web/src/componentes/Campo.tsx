import { useId, type InputHTMLAttributes, type ReactNode, type SelectHTMLAttributes, type TextareaHTMLAttributes } from 'react'

interface Base { rotulo: string; erro?: string | null; ajuda?: ReactNode; obrigatorio?: boolean }

function Rotulo({ id, rotulo, obrigatorio }: { id: string; rotulo: string; obrigatorio?: boolean }) {
  return <label htmlFor={id}>{rotulo}{obrigatorio && <span className="obrigatorio" aria-hidden="true"> *</span>}</label>
}

function Rodape({ id, erro, ajuda }: { id: string; erro?: string | null; ajuda?: ReactNode }) {
  return <>
    {ajuda && <p className="ajuda" id={`${id}-ajuda`}>{ajuda}</p>}
    {erro && <span className="feedback danger" role="alert" id={`${id}-erro`}><i className="fas fa-times-circle" aria-hidden="true" /> {erro}</span>}
  </>
}

const descr = (id: string, erro?: string | null, ajuda?: ReactNode) =>
  [ajuda ? `${id}-ajuda` : '', erro ? `${id}-erro` : ''].filter(Boolean).join(' ') || undefined

export function Campo({ rotulo, erro, ajuda, obrigatorio, id: idDado, ...p }: Base & InputHTMLAttributes<HTMLInputElement>) {
  const auto = useId()
  const id = idDado ?? auto
  return (
    <div className={`br-input campo${erro ? ' danger' : ''}`}>
      <Rotulo id={id} rotulo={rotulo} obrigatorio={obrigatorio} />
      <input id={id} aria-invalid={erro ? true : undefined} aria-required={obrigatorio || undefined}
        aria-describedby={descr(id, erro, ajuda)} {...p} />
      <Rodape id={id} erro={erro} ajuda={ajuda} />
    </div>
  )
}

export function Area({ rotulo, erro, ajuda, obrigatorio, id: idDado, ...p }: Base & TextareaHTMLAttributes<HTMLTextAreaElement>) {
  const auto = useId()
  const id = idDado ?? auto
  return (
    <div className={`br-textarea campo${erro ? ' danger' : ''}`}>
      <Rotulo id={id} rotulo={rotulo} obrigatorio={obrigatorio} />
      <textarea id={id} aria-invalid={erro ? true : undefined} aria-required={obrigatorio || undefined}
        aria-describedby={descr(id, erro, ajuda)} {...p} />
      <Rodape id={id} erro={erro} ajuda={ajuda} />
    </div>
  )
}

export function Selecao({ rotulo, erro, ajuda, obrigatorio, id: idDado, children, ...p }: Base & SelectHTMLAttributes<HTMLSelectElement>) {
  const auto = useId()
  const id = idDado ?? auto
  return (
    <div className={`br-input campo selecao${erro ? ' danger' : ''}`}>
      <Rotulo id={id} rotulo={rotulo} obrigatorio={obrigatorio} />
      <select id={id} aria-invalid={erro ? true : undefined} aria-describedby={descr(id, erro, ajuda)} {...p}>{children}</select>
      <Rodape id={id} erro={erro} ajuda={ajuda} />
    </div>
  )
}

export function Caixa({ rotulo, id: idDado, ajuda, ...p }: { rotulo: ReactNode; ajuda?: ReactNode } & InputHTMLAttributes<HTMLInputElement>) {
  const auto = useId()
  const id = idDado ?? auto
  return (
    <div className="br-checkbox">
      <input id={id} type="checkbox" aria-describedby={ajuda ? `${id}-ajuda` : undefined} {...p} />
      <label htmlFor={id}>{rotulo}</label>
      {ajuda && <p className="ajuda" id={`${id}-ajuda`}>{ajuda}</p>}
    </div>
  )
}

export function Radio({ rotulo, id: idDado, ...p }: { rotulo: ReactNode } & InputHTMLAttributes<HTMLInputElement>) {
  const auto = useId()
  const id = idDado ?? auto
  return (
    <div className="br-radio">
      <input id={id} type="radio" {...p} />
      <label htmlFor={id}>{rotulo}</label>
    </div>
  )
}
