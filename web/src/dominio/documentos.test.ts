import { completarCpf, completarTitulo, cpfValido, mascarar, pareceIdentificador, tituloValido, validar } from './documentos'

describe('CPF', () => {
  it('aceita CPF válido com e sem pontuação', () => {
    expect(cpfValido('529.982.247-25')).toBe(true)
    expect(cpfValido('52998224725')).toBe(true)
    expect(cpfValido(' 529 982 247 25 ')).toBe(true)
  })
  it('recusa DV errado, tamanho errado e dígitos repetidos', () => {
    expect(cpfValido('529.982.247-24')).toBe(false)
    expect(cpfValido('5299822472')).toBe(false)
    expect(cpfValido('111.111.111-11')).toBe(false)
  })
  it('completa os DV como o servidor', () => {
    expect(completarCpf('529982247')).toBe('52998224725')
    expect(completarCpf('123456789')).toBe('12345678909')
  })
  it('mascara como auditor/identificador.py', () => {
    expect(mascarar('cpf', '52998224725')).toBe('***.982.247-**')
  })
  it('mensagens de validação', () => {
    expect(validar('cpf', '')).toMatch(/Informe/)
    expect(validar('cpf', '123')).toMatch(/11 dígitos/)
    expect(validar('cpf', '12345678900')).toMatch(/dígitos verificadores/)
    expect(validar('cpf', '123.456.789-09')).toBeNull()
  })
})

describe('Título de Eleitor', () => {
  it('valida 12 dígitos com UF de 01 a 28', () => {
    const t = completarTitulo('10234567', '05')
    expect(tituloValido(t)).toBe(true)
    expect(tituloValido(`${t.slice(0, 4)} ${t.slice(4, 8)} ${t.slice(8)}`)).toBe(true)
    expect(tituloValido(t.slice(0, 10) + String((Number(t[10]) + 1) % 10) + t[11])).toBe(false)
    expect(tituloValido(completarTitulo('10234567', '05').slice(0, 8) + '29' + '00')).toBe(false)
    expect(tituloValido('12345678')).toBe(false)
  })
  it('SP (01) e MG (02): DV 0 vira 1', () => {
    // 00000000 → soma 0 → DV1 = 0 → vira 1 em SP
    expect(completarTitulo('00000000', '01').slice(10, 11)).toBe('1')
    expect(completarTitulo('00000000', '05').slice(10, 11)).toBe('0')
  })
  it('mascara como o servidor', () => {
    expect(mascarar('titulo', '102345670591')).toBe('**** 4567 ****')
  })
  it('mensagens', () => {
    expect(validar('titulo', '1234')).toMatch(/12 dígitos/)
    expect(validar('titulo', completarTitulo('10234567', '05'))).toBeNull()
  })
})

describe('pareceIdentificador', () => {
  it('acha CPF ou título válidos no meio de texto', () => {
    expect(pareceIdentificador('acessos do 529.982.247-25 ontem')).toBe(true)
    expect(pareceIdentificador(`titulo ${completarTitulo('10234567', '05')}`)).toBe(true)
    expect(pareceIdentificador('processo 0001234-12.2026.6.05.0000')).toBe(false)
    expect(pareceIdentificador('41')).toBe(false)
  })
})
