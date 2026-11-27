"""Faz o papel do navegador do usuário nos testes da W1: preenche o login do realm `auditor` (senha e OTP) e, no
primeiro acesso, configura o OTP e guarda o segredo em chaves/totp_teste.json (fora do git).

  logar(url_de_autorizacao, usuario) -> URL de retorno (com ?code=...)
  aprovar_dispositivo(verification_uri_complete, usuario)
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import html
import json
import re
import struct
import time
from pathlib import Path
from urllib.parse import urljoin

import httpx

RAIZ = Path(__file__).resolve().parents[1]
SEGREDOS = RAIZ / "chaves" / "totp_teste.json"
_ultimo: dict[str, int] = {}


def totp(segredo: str, t: float | None = None) -> str:
    c = int((t or time.time()) // 30)
    h = hmac.new(segredo.encode(), struct.pack(">Q", c), hashlib.sha1).digest()
    o = h[-1] & 0x0F
    return f"{(struct.unpack('>I', h[o:o + 4])[0] & 0x7FFFFFFF) % 1_000_000:06d}"


def _codigo(usuario: str, segredo: str) -> str:
    """O Keycloak não aceita o mesmo código duas vezes: espera a próxima janela se precisar."""
    janela = int(time.time() // 30)
    if _ultimo.get(usuario) == janela:
        time.sleep(30 - time.time() % 30 + 0.5)
        janela = int(time.time() // 30)
    _ultimo[usuario] = janela
    return totp(segredo)


def _segredos() -> dict:
    return json.loads(SEGREDOS.read_text()) if SEGREDOS.exists() else {}


def _attrs(tag: str) -> dict:
    return {k: html.unescape(v) for k, v in re.findall(r'([\w-]+)="([^"]*)"', tag)}


def _form(pagina: str, base: str, ident: str | None = None) -> tuple[str, dict]:
    forms = [_attrs(t) for t in re.findall(r"<form\b[^>]*>", pagina)]
    f = next((x for x in forms if not ident or x.get("id") == ident), None)
    if not f or "action" not in f:
        raise RuntimeError("formulário não encontrado na página do Keycloak")
    campos = {}
    for t in re.findall(r"<input\b[^>]*>", pagina):
        a = _attrs(t)
        if a.get("type") == "hidden" and a.get("name"):
            campos[a["name"]] = a.get("value", "")
    return urljoin(base, f["action"]), campos


def _seguir(cli: httpx.Client, r: httpx.Response, para: str | None) -> httpx.Response:
    while r.status_code in (302, 303):
        loc = r.headers["location"]
        if para and loc.startswith(para):
            return r
        r = cli.get(urljoin(str(r.url), loc))
    return r


def _autenticar(cli: httpx.Client, r: httpx.Response, usuario: str, retorno: str | None) -> httpx.Response:
    for _ in range(6):
        if r.status_code in (302, 303):
            return r
        p = r.text
        if 'id="kc-form-login"' in p:
            acao, campos = _form(p, str(r.url), "kc-form-login")
            r = cli.post(acao, data={**campos, "username": usuario, "password": f"senha-{usuario}"})
        elif 'name="totpSecret"' in p:   # primeiro acesso: configurar o OTP
            acao, campos = _form(p, str(r.url), "kc-totp-settings-form")
            segredo = campos["totpSecret"]
            s = _segredos()
            s[usuario] = segredo
            SEGREDOS.write_text(json.dumps(s, indent=1))
            r = cli.post(acao, data={**campos, "totp": _codigo(usuario, segredo), "userLabel": "teste"})
        elif 'id="kc-otp-login-form"' in p or 'name="otp"' in p:
            acao, campos = _form(p, str(r.url), "kc-otp-login-form")
            r = cli.post(acao, data={**campos, "otp": _codigo(usuario, _segredos()[usuario])})
        elif "kc-user-verify-device-user-code-form" in p or 'name="device_user_code"' in p:
            acao, campos = _form(p, str(r.url))
            r = cli.post(acao, data=campos)
        elif 'name="accept"' in p:   # consentimento do device flow
            acao, campos = _form(p, str(r.url))
            r = cli.post(acao, data={**campos, "accept": "Sim"})
        else:
            erro = re.search(r'kc-feedback-text">([^<]+)', p) or re.search(r'<title>([^<]+)', p)
            if "Device Login Successful" in p or "sucesso" in p.lower() or "successful" in p.lower():
                return r
            raise RuntimeError(f"página inesperada do Keycloak: {erro.group(1) if erro else p[:200]}")
        r = _seguir(cli, r, retorno)
    return r


def cliente() -> httpx.Client:
    """Como um navegador em localhost (contexto seguro), reenvia os cookies `Secure` do Keycloak também por http."""
    c = httpx.Client(timeout=20, trust_env=False)

    def inseguro(_r):
        for k in c.cookies.jar:
            k.secure = False
    c.event_hooks["response"] = [inseguro]
    return c


def logar(url: str, usuario: str, cli: httpx.Client | None = None, retorno: str = "") -> str:
    """Segue o login até o redirecionamento para `retorno`; devolve a URL de retorno com o código."""
    cli = cli or cliente()
    r = _seguir(cli, cli.get(url), retorno)
    r = _autenticar(cli, r, usuario, retorno)
    if r.status_code not in (302, 303):
        raise RuntimeError("login não terminou no retorno")
    return urljoin(str(r.url), r.headers["location"])


def aprovar_dispositivo(url: str, usuario: str):
    cli = cliente()
    r = _seguir(cli, cli.get(url), None)
    _autenticar(cli, r, usuario, None)
