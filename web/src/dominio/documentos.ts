/**
 * CPF e Título de Eleitor: mesma regra de auditor/identificador.py (dígitos verificadores e máscara).
 * O valor completo só vive na memória do assistente até o POST; a tela mostra só a máscara.
 */
export type TipoDocumento = 'cpf' | 'titulo'

export const soDigitos = (v: string) => (v ?? '').replace(/\D/g, '')

function dvCpf(base9: string): string {
  const s1 = [...base9].reduce((s, d, i) => s + Number(d) * (10 - i), 0)
  const d1 = ((s1 * 10) % 11) % 10
  const s2 = [...(base9 + d1)].reduce((s, d, i) => s + Number(d) * (11 - i), 0)
  const d2 = ((s2 * 10) % 11) % 10
  return `${d1}${d2}`
}

export function cpfValido(v: string): boolean {
  const d = soDigitos(v)
  if (d.length !== 11 || d === d[0].repeat(11)) return false
  return dvCpf(d.slice(0, 9)) === d.slice(9)
}

function dvTitulo(seq8: string, uf: string): string {
  const s1 = [...seq8].reduce((s, d, i) => s + Number(d) * (i + 2), 0)
  const r1 = s1 % 11
  let d1 = r1 === 10 ? 0 : r1
  if (d1 === 0 && (uf === '01' || uf === '02')) d1 = 1
  const r2 = (Number(uf[0]) * 7 + Number(uf[1]) * 8 + d1 * 9) % 11
  let d2 = r2 === 10 ? 0 : r2
  if (d2 === 0 && (uf === '01' || uf === '02')) d2 = 1
  return `${d1}${d2}`
}

export function tituloValido(v: string): boolean {
  const d = soDigitos(v)
  if (d.length !== 12) return false
  const uf = d.slice(8, 10)
  if (!(uf >= '01' && uf <= '28')) return false
  return dvTitulo(d.slice(0, 8), uf) === d.slice(10)
}

export const completarCpf = (base9: string) => base9 + dvCpf(base9)
export const completarTitulo = (seq8: string, uf: string) => seq8 + uf + dvTitulo(seq8, uf)

export function validar(tipo: TipoDocumento, v: string): string | null {
  const d = soDigitos(v)
  if (!d) return tipo === 'cpf' ? 'Informe o CPF.' : 'Informe o Título de Eleitor.'
  if (tipo === 'cpf') {
    if (d.length !== 11) return 'O CPF tem 11 dígitos.'
    return cpfValido(d) ? null : 'CPF inválido: confira os dígitos verificadores.'
  }
  if (d.length !== 12) return 'O Título de Eleitor tem 12 dígitos.'
  return tituloValido(d) ? null : 'Título de Eleitor inválido: confira a UF e os dígitos verificadores.'
}

/** Mesma máscara do servidor (auditor/identificador.py: mascarar). */
export function mascarar(tipo: TipoDocumento, v: string): string {
  const d = soDigitos(v)
  if (tipo === 'cpf') return `***.${d.slice(3, 6)}.${d.slice(6, 9)}-**`
  return `**** ${d.slice(4, 8)} ****`
}

/** Um texto livre (busca, motivo) parece conter um CPF ou título válido? Usado para não mandá-lo para a URL. */
export function pareceIdentificador(texto: string): boolean {
  const blocos = texto.match(/[\d.\-/ ]{11,16}/g) ?? []
  return blocos.some((b) => {
    const d = soDigitos(b)
    return (d.length === 11 && cpfValido(d)) || (d.length === 12 && tituloValido(d))
  })
}
