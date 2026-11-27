/** Datas na tela: sempre no fuso da investigação (contrato: servidor em UTC). */
export function dataHora(iso?: string | null, fuso?: string): string {
  if (!iso) return '—'
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return iso
  return d.toLocaleString('pt-BR', { timeZone: fuso || undefined, day: '2-digit', month: '2-digit', year: 'numeric',
    hour: '2-digit', minute: '2-digit' })
}

export function data(iso?: string | null, fuso?: string): string {
  if (!iso) return '—'
  const d = new Date(iso.length === 10 ? `${iso}T12:00:00Z` : iso)
  if (Number.isNaN(d.getTime())) return iso
  return d.toLocaleDateString('pt-BR', { timeZone: fuso || undefined })
}

export function duracao(seg?: number | null): string {
  if (seg == null) return '—'
  if (seg < 60) return `${Math.round(seg)} s`
  const m = Math.round(seg / 60)
  if (m < 60) return `cerca de ${m} min`
  const h = Math.floor(m / 60)
  return `cerca de ${h} h${m % 60 ? ` ${m % 60} min` : ''}`
}

export const numero = (n?: number | null) => (n == null ? '—' : n.toLocaleString('pt-BR'))

export function prazoRestante(iso?: string | null, agora = Date.now()): { texto: string; vencido: boolean } {
  if (!iso) return { texto: 'sem prazo', vencido: false }
  const ms = new Date(iso).getTime() - agora
  const min = Math.round(Math.abs(ms) / 60_000)
  const h = Math.round(min / 60)
  const t = h >= 48 ? `${Math.round(h / 24)} dias` : min >= 60 ? `${h} h` : `${min} min`
  return ms < 0 ? { texto: `vencido há ${t}`, vencido: true } : { texto: `restam ${t}`, vencido: false }
}
