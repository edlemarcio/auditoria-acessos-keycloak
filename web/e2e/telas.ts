import { expect, type Page } from '@playwright/test'
import type { Perfil } from './ajuda'

/** Telas cobertas pelo axe e pelas capturas: perfil, rota e, se preciso, um passo para chegar ao estado. */
export interface Tela { nome: string; perfil: Perfil; rota: string; preparar?: (p: Page) => Promise<void>; sem_titulo?: boolean }

export const TELAS: Tela[] = [
  { nome: 'inicio-solicitante', perfil: 'solicitante', rota: '/' },
  { nome: 'inicio-aprovador', perfil: 'aprovador', rota: '/' },
  { nome: 'inicio-investigador', perfil: 'investigador', rota: '/' },
  { nome: 'inicio-auditor', perfil: 'auditor_interno', rota: '/' },
  { nome: 'inicio-admin', perfil: 'admin_tecnico', rota: '/' },
  { nome: 'inicio-gestor', perfil: 'gestor_acesso', rota: '/' },
  { nome: 'investigacoes', perfil: 'solicitante', rota: '/investigacoes' },
  { nome: 'investigacoes-filtros', perfil: 'aprovador', rota: '/investigacoes?visao=aguardando&estado=aguardando_aprovacao' },
  { nome: 'investigacoes-vazia', perfil: 'solicitante', rota: '/investigacoes?q=000000' },
  { nome: 'investigacoes-auditor', perfil: 'auditor_interno', rota: '/investigacoes' },
  { nome: 'nova-passo1', perfil: 'solicitante', rota: '/nova' },
  { nome: 'nova-passo1-erro', perfil: 'solicitante', rota: '/nova', preparar: async (p) => {
    await p.getByRole('textbox', { name: 'CPF' }).fill('123.456.789-00')
    await p.getByRole('button', { name: /Próximo/ }).click()
    await expect(p.locator('.resumo-erros')).toBeVisible()
  } },
  { nome: 'nova-passo2-expiracao', perfil: 'solicitante', rota: '/nova', preparar: async (p) => {
    await p.getByRole('textbox', { name: 'CPF' }).fill('52998224725')
    await p.getByRole('button', { name: /Próximo/ }).click()
    await expect(p.getByRole('button', { name: 'Pedir preservação urgente' })).toBeVisible()
  } },
  { nome: 'nova-rascunho', perfil: 'solicitante', rota: '/nova?rascunho=41' },
  { nome: 'nova-devolvida-revisao', perfil: 'solicitante', rota: '/nova?rascunho=38', preparar: async (p) => {
    for (let k = 0; k < 4; k++) await p.getByRole('button', { name: /Próximo/ }).click()
    await expect(p.getByRole('textbox', { name: /O que foi corrigido/ })).toBeVisible()
  } },
  { nome: 'nova-externo', perfil: 'investigador', rota: '/nova?externo=1' },
  { nome: 'resumo-devolvida', perfil: 'solicitante', rota: '/investigacoes/38' },
  { nome: 'resumo-recusada', perfil: 'solicitante', rota: '/investigacoes/30' },
  { nome: 'resumo-rascunho', perfil: 'solicitante', rota: '/investigacoes/41' },
  { nome: 'acompanhamento', perfil: 'investigador', rota: '/investigacoes/36', preparar: async (p) => {
    await expect(p.locator('.kpi-valor').first()).toBeVisible()
  } },
  { nome: 'resumo-lacrada', perfil: 'investigador', rota: '/investigacoes/37' },
  { nome: 'pacotes', perfil: 'investigador', rota: '/investigacoes/33/pacotes' },
  { nome: 'pacotes-solicitante', perfil: 'solicitante', rota: '/investigacoes/33/pacotes' },
  { nome: 'trilha-investigacao', perfil: 'auditor_interno', rota: '/investigacoes/33/trilha' },
  { nome: 'aprovacoes', perfil: 'aprovador', rota: '/aprovacoes' },
  { nome: 'decisao-investigacao', perfil: 'aprovador', rota: '/aprovacoes/140?inv=40&tipo=preservacao_urgente' },
  { nome: 'decisao-externo', perfil: 'aprovador', rota: '/aprovacoes/139?inv=39&tipo=investigacao' },
  { nome: 'decisao-aprovar-dialogo', perfil: 'aprovador', rota: '/aprovacoes/139?inv=39&tipo=investigacao', preparar: async (p) => {
    await p.getByRole('button', { name: /^Aprovar$/ }).click()
    await expect(p.getByRole('dialog')).toBeVisible()
  } },
  { nome: 'decisao-pacote', perfil: 'aprovador', rota: '/aprovacoes/77?inv=33&tipo=pacote_sem_mascara' },
  { nome: 'administracao', perfil: 'admin_tecnico', rota: '/administracao' },
  { nome: 'perfis', perfil: 'gestor_acesso', rota: '/perfis' },
  { nome: 'trilha-global', perfil: 'auditor_interno', rota: '/trilha' },
  { nome: 'verificar-pacote', perfil: 'solicitante', rota: '/verificar-pacote' },
  { nome: 'sem-acesso', perfil: 'solicitante', rota: '/investigacoes/12345' },
  { nome: 'erro-servidor', perfil: 'solicitante', rota: '/investigacoes/999', preparar: async (p) => {
    await expect(p.getByText('7F2A-91C0')).toBeVisible()
  } },
  { nome: 'notificacoes', perfil: 'solicitante', rota: '/', preparar: async (p) => {
    await p.getByRole('button', { name: /Notificações/ }).click()
    await expect(p.getByRole('region', { name: 'Central de notificações' })).toBeVisible()
  } },
  { nome: 'sessao-expirada', perfil: 'solicitante', rota: '/investigacoes', sem_titulo: true, preparar: async (p) => {
    await p.context().clearCookies()
    await p.getByRole('button', { name: 'Minhas' }).click()
    await expect(p.getByRole('heading', { name: 'Sua sessão expirou' })).toBeVisible()
  } },
]
