"""Carimbo do tempo RFC 3161 (W5, PROPOSTA_WEB §6.2 e §6.3).

  AUDITOR_TSA_URL       endereço da ACT (POST application/timestamp-query). Em homologação, a ACT local de
                        infra/act_homologacao.py; em produção, a ACT ICP-Brasil contratada. Sem ela, o carimbo
                        continua simulado (ancora.py) e o pacote diz isso.
  AUDITOR_TSA_RAIZES    diretório com as raízes confiáveis (PEM) para conferir o carimbo recebido; padrão: as
                        AC-Raiz do verificador (verificador/kc_verificar/raizes/icp-brasil) e, se
                        AUDITOR_TSA_HOMOLOGACAO=1, também a raiz de homologação.

Só o hash sai para a ACT: o `messageImprint` é o SHA-256 do arquivo carimbado (manifesto.json) ou, para as âncoras
diárias, a própria raiz Merkle (32 bytes). O carimbo recebido é conferido antes de ser aceito; as LCRs da cadeia são
baixadas na exportação e vão no pacote (lcr/), para o verificador conferir a revogação sem rede.
"""
from __future__ import annotations

import base64
import hashlib
import os
import secrets
import sys
from pathlib import Path

import httpx
from asn1crypto import tsp
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

_VERIFICADOR = Path(__file__).resolve().parent.parent / "verificador"
if _VERIFICADOR.exists() and str(_VERIFICADOR) not in sys.path:
    sys.path.insert(0, str(_VERIFICADOR))
from kc_verificar import rfc3161  # noqa: E402  (o auditor usa a mesma validação do verificador offline)


class CarimboInvalido(RuntimeError):
    pass


def configurado() -> bool:
    return bool(os.environ.get("AUDITOR_TSA_URL"))


def raizes() -> list[x509.Certificate]:
    pastas = []
    if os.environ.get("AUDITOR_TSA_RAIZES"):
        pastas.append(Path(os.environ["AUDITOR_TSA_RAIZES"]))
    else:
        pastas.append(_VERIFICADOR / "kc_verificar" / "raizes" / "icp-brasil")
        if os.environ.get("AUDITOR_TSA_HOMOLOGACAO") == "1":
            pastas.append(_VERIFICADOR / "kc_verificar" / "raizes" / "homologacao")
    out = []
    for p in pastas:
        for f in sorted(p.glob("*.pem")) if p.exists() else ():
            out.append(x509.load_pem_x509_certificate(f.read_bytes()))
    return out


def pedir(hash_bytes: bytes) -> bytes:
    """Pede o carimbo de um SHA-256 e devolve a TimeStampResp (DER), já conferida."""
    url = os.environ["AUDITOR_TSA_URL"]
    nonce = secrets.randbits(63)
    req = tsp.TimeStampReq({"version": "v1", "message_imprint": {"hash_algorithm": {"algorithm": "sha256"},
                                                                 "hashed_message": hash_bytes},
                            "nonce": nonce, "cert_req": True}).dump()
    r = httpx.post(url, content=req, headers={"Content-Type": "application/timestamp-query"}, timeout=30)
    r.raise_for_status()
    resp = r.content
    tok = tsp.TimeStampResp.load(resp)
    if tok["status"]["status"].native not in ("granted", "granted_with_mods"):
        raise CarimboInvalido(f"ACT recusou o pedido: {tok['status']['status'].native}")
    info = tsp.TSTInfo.load(tok["time_stamp_token"]["content"]["encap_content_info"]["content"].contents)
    if info["nonce"].native != nonce:
        raise CarimboInvalido("ACT devolveu carimbo com nonce diferente do pedido")
    v = rfc3161.verificar(resp, hash_bytes, raizes())
    if not v.ok:
        raise CarimboInvalido("carimbo recebido não confere: " + "; ".join(v.problemas))
    return resp


def lcrs(tsr: bytes) -> dict[str, bytes]:
    """Baixa as LCRs apontadas pelos certificados do carimbo (para o pacote). Nome → DER."""
    out = {}
    for c in rfc3161.certificados(tsr):
        try:
            pontos = c.extensions.get_extension_for_class(x509.CRLDistributionPoints).value
        except x509.ExtensionNotFound:
            continue
        for p in pontos:
            for n in p.full_name or []:
                if isinstance(n, x509.UniformResourceIdentifier) and n.value.startswith(("http://", "https://")):
                    try:
                        r = httpx.get(n.value, timeout=30)
                        r.raise_for_status()
                    except httpx.HTTPError:
                        continue
                    dados = r.content
                    try:
                        x509.load_der_x509_crl(dados)
                    except ValueError:
                        dados = x509.load_pem_x509_crl(dados).public_bytes(Encoding.DER)
                    out[hashlib.sha256(n.value.encode()).hexdigest()[:16] + ".crl"] = dados
    return out


def carimbo_ancora(raiz_hex: str) -> dict:
    """Carimbo de uma âncora diária: RFC 3161 sobre a raiz (32 bytes)."""
    tsr = pedir(bytes.fromhex(raiz_hex))
    return {"tipo": "rfc3161", "raiz": raiz_hex, "carimbado_em": rfc3161.gen_time(tsr).isoformat(),
            "tsr": base64.b64encode(tsr).decode()}


def verificar_ancora(c: dict, raiz_hex: str) -> bool:
    if c.get("raiz") != raiz_hex:
        return False
    return rfc3161.verificar(base64.b64decode(c["tsr"]), bytes.fromhex(raiz_hex), raizes()).ok
