"""ACT de homologação: serviço de carimbo do tempo RFC 3161 local, com raiz de teste própria (PROPOSTA_WEB §6.2 e
dependência "Contratação da ACT ICP-Brasil").

NÃO é ICP-Brasil e não atesta data perante terceiros. Serve para exercitar, em homologação, o mesmo protocolo e a
mesma verificação que a ACT credenciada: o auditor pede o carimbo (TimeStampReq) e o verificador offline confere o
TimeStampToken, a cadeia até a raiz de teste e a LCR. Em produção, AUDITOR_TSA_URL aponta para a ACT contratada e o
verificador usa só as AC-Raiz da ICP-Brasil; a raiz de teste fica num diretório separado, aceito só com
`kc-verificar --homologacao`.

  python infra/act_homologacao.py --gerar            # cria raiz, certificado da ACT e LCR (chaves/act/)
  python infra/act_homologacao.py --porta 8318       # serve POST /tsa, GET /lcr.crl, /raiz.pem, /tsa.pem
  python infra/act_homologacao.py --revogar          # revoga o certificado da ACT na LCR (teste de revogação)
  python infra/act_homologacao.py --reemitir         # novo certificado da ACT (depois de um --revogar)

A raiz pública é copiada para verificador/kc_verificar/raizes/homologacao/, que vai para o repositório.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import secrets
import sys
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from asn1crypto import cms, tsp
from asn1crypto import x509 as ax509
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

RAIZ_DO_PROJETO = Path(__file__).resolve().parent.parent
PASTA = Path(os.environ.get("AUDITOR_ACT_PASTA", RAIZ_DO_PROJETO / "chaves" / "act"))
PUBLICA = RAIZ_DO_PROJETO / "verificador" / "kc_verificar" / "raizes" / "homologacao"
POLITICA = "1.3.6.1.4.1.99999.3161.1"   # arco privado de teste; a ACT ICP-Brasil tem a sua política (DOC-ICP-12)
URL_BASE = os.environ.get("AUDITOR_ACT_URL_PUBLICA", "http://localhost:8318")


def _nome(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, "BR"),
                      x509.NameAttribute(NameOID.ORGANIZATION_NAME, "kc-auditor - HOMOLOGACAO (nao ICP-Brasil)"),
                      x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _gravar_chave(p: Path, k):
    p.write_bytes(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()))
    os.chmod(p, 0o600)


def _carregar():
    raiz = x509.load_pem_x509_certificate((PASTA / "raiz.pem").read_bytes())
    k_raiz = serialization.load_pem_private_key((PASTA / "raiz.key").read_bytes(), None)
    tsa = x509.load_pem_x509_certificate((PASTA / "tsa.pem").read_bytes())
    k_tsa = serialization.load_pem_private_key((PASTA / "tsa.key").read_bytes(), None)
    return raiz, k_raiz, tsa, k_tsa


def _emitir_tsa(raiz, k_raiz):
    k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    agora = datetime.now(timezone.utc)
    c = (x509.CertificateBuilder().subject_name(_nome("ACT de homologacao kc-auditor")).issuer_name(raiz.subject)
         .public_key(k.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(agora - timedelta(minutes=5)).not_valid_after(agora + timedelta(days=3 * 365))
         .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
         .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=True, key_encipherment=False,
                                      data_encipherment=False, key_agreement=False, key_cert_sign=False,
                                      crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
         .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]), critical=True)
         .add_extension(x509.CRLDistributionPoints([x509.DistributionPoint(
             [x509.UniformResourceIdentifier(f"{URL_BASE}/lcr.crl")], None, None, None)]), critical=False)
         .add_extension(x509.SubjectKeyIdentifier.from_public_key(k.public_key()), critical=False)
         .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(k_raiz.public_key()), critical=False)
         .sign(k_raiz, hashes.SHA256()))
    _gravar_chave(PASTA / "tsa.key", k)
    (PASTA / "tsa.pem").write_bytes(c.public_bytes(serialization.Encoding.PEM))
    return c, k


def _lcr(raiz, k_raiz, revogados: list[tuple[int, datetime]]):
    agora = datetime.now(timezone.utc)
    b = (x509.CertificateRevocationListBuilder().issuer_name(raiz.subject).last_update(agora - timedelta(minutes=1))
         .next_update(agora + timedelta(days=7)))
    for serie, quando in revogados:
        b = b.add_revoked_certificate(x509.RevokedCertificateBuilder().serial_number(serie)
                                      .revocation_date(quando).build())
    (PASTA / "lcr.crl").write_bytes(b.sign(k_raiz, hashes.SHA256()).public_bytes(serialization.Encoding.DER))


def _revogados() -> list[tuple[int, datetime]]:
    p = PASTA / "revogados.txt"
    if not p.exists():
        return []
    out = []
    for l in p.read_text().split():
        s, q = l.split("@")
        out.append((int(s), datetime.fromisoformat(q)))
    return out


def gerar(forcar: bool = False):
    PASTA.mkdir(parents=True, exist_ok=True)
    if (PASTA / "raiz.pem").exists() and not forcar:
        raiz, k_raiz, _, _ = _carregar()
    else:
        k_raiz = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        agora = datetime.now(timezone.utc)
        raiz = (x509.CertificateBuilder().subject_name(_nome("AC Raiz de homologacao kc-auditor"))
                .issuer_name(_nome("AC Raiz de homologacao kc-auditor")).public_key(k_raiz.public_key())
                .serial_number(x509.random_serial_number()).not_valid_before(agora - timedelta(minutes=5))
                .not_valid_after(agora + timedelta(days=10 * 365))
                .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
                .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False,
                                             key_encipherment=False, data_encipherment=False, key_agreement=False,
                                             key_cert_sign=True, crl_sign=True, encipher_only=False,
                                             decipher_only=False), critical=True)
                .add_extension(x509.SubjectKeyIdentifier.from_public_key(k_raiz.public_key()), critical=False)
                .sign(k_raiz, hashes.SHA256()))
        _gravar_chave(PASTA / "raiz.key", k_raiz)
        (PASTA / "raiz.pem").write_bytes(raiz.public_bytes(serialization.Encoding.PEM))
        (PASTA / "revogados.txt").unlink(missing_ok=True)
        _emitir_tsa(raiz, k_raiz)
    _lcr(raiz, k_raiz, _revogados())
    PUBLICA.mkdir(parents=True, exist_ok=True)
    (PUBLICA / "act_homologacao_raiz.pem").write_bytes(raiz.public_bytes(serialization.Encoding.PEM))
    print(f"raiz: {hashlib.sha256(raiz.public_bytes(serialization.Encoding.DER)).hexdigest()}  ({PASTA})")


def revogar():
    raiz, k_raiz, tsa, _ = _carregar()
    with (PASTA / "revogados.txt").open("a") as f:
        f.write(f"{tsa.serial_number}@{datetime.now(timezone.utc).isoformat()}\n")
    _lcr(raiz, k_raiz, _revogados())
    print(f"revogado: {tsa.serial_number}")


def reemitir():
    raiz, k_raiz, _, _ = _carregar()
    _emitir_tsa(raiz, k_raiz)
    _lcr(raiz, k_raiz, _revogados())


# ------------------------------------------------------------------ protocolo
def carimbar(corpo: bytes) -> bytes:
    """TimeStampReq (DER) → TimeStampResp (DER). Lê as chaves a cada pedido (um --reemitir vale sem reiniciar)."""
    try:
        req = tsp.TimeStampReq.load(corpo)
        mi = req["message_imprint"]
        if mi["hash_algorithm"]["algorithm"].native not in ("sha256", "sha384", "sha512"):
            raise ValueError("algoritmo")
    except Exception:  # noqa: BLE001
        return tsp.TimeStampResp({"status": {"status": "rejection", "fail_info": {"bad_data_format"}}}).dump()
    _, _, tsa, k_tsa = _carregar()
    cert_der = tsa.public_bytes(serialization.Encoding.DER)
    cert = ax509.Certificate.load(cert_der)
    agora = datetime.now(timezone.utc).replace(microsecond=0)
    info = {"version": "v1", "policy": req["req_policy"].native or POLITICA, "message_imprint": mi,
            "serial_number": secrets.randbits(63), "gen_time": agora, "accuracy": {"seconds": 1}, "ordering": False}
    if req["nonce"].native is not None:
        info["nonce"] = req["nonce"].native
    tst = tsp.TSTInfo(info)
    tst_der = tst.dump()
    attrs = cms.CMSAttributes([
        cms.CMSAttribute({"type": "content_type", "values": ["tst_info"]}),
        cms.CMSAttribute({"type": "signing_time", "values": [cms.Time({"utc_time": agora})]}),
        cms.CMSAttribute({"type": "message_digest", "values": [hashlib.sha256(tst_der).digest()]}),
        cms.CMSAttribute({"type": "signing_certificate_v2", "values": [tsp.SigningCertificateV2({"certs": [
            tsp.ESSCertIDv2({"hash_algorithm": {"algorithm": "sha256"},
                             "cert_hash": hashlib.sha256(cert_der).digest()})]})]}),
    ])
    assinatura = k_tsa.sign(attrs.dump(), padding.PKCS1v15(), hashes.SHA256())
    si = cms.SignerInfo({
        "version": "v1",
        "sid": cms.SignerIdentifier({"issuer_and_serial_number": cms.IssuerAndSerialNumber(
            {"issuer": cert.issuer, "serial_number": cert.serial_number})}),
        "digest_algorithm": {"algorithm": "sha256"}, "signed_attrs": attrs,
        "signature_algorithm": {"algorithm": "sha256_rsa"}, "signature": assinatura})
    sd = {"version": "v3", "digest_algorithms": [{"algorithm": "sha256"}],
          "encap_content_info": {"content_type": "tst_info", "content": tst}, "signer_infos": [si]}
    if req["cert_req"].native:
        sd["certificates"] = [cert]
    token = cms.ContentInfo({"content_type": "signed_data", "content": cms.SignedData(sd)})
    return tsp.TimeStampResp({"status": {"status": "granted"}, "time_stamp_token": token}).dump()


class Tratador(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):   # sem log de corpo; só a linha de acesso padrão no stderr
        sys.stderr.write("act: " + fmt % args + "\n")

    def _enviar(self, codigo: int, tipo: str, corpo: bytes):
        self.send_response(codigo)
        self.send_header("Content-Type", tipo)
        self.send_header("Content-Length", str(len(corpo)))
        self.end_headers()
        self.wfile.write(corpo)

    def do_POST(self):  # noqa: N802
        if self.path != "/tsa":
            return self._enviar(404, "text/plain", b"")
        n = int(self.headers.get("Content-Length") or 0)
        if n <= 0 or n > 16_384:
            return self._enviar(400, "text/plain", b"pedido invalido")
        self._enviar(200, "application/timestamp-reply", carimbar(self.rfile.read(n)))

    def do_GET(self):  # noqa: N802
        arq = {"/lcr.crl": ("lcr.crl", "application/pkix-crl"), "/raiz.pem": ("raiz.pem", "application/x-pem-file"),
               "/tsa.pem": ("tsa.pem", "application/x-pem-file")}.get(self.path)
        if not arq:
            return self._enviar(404, "text/plain", b"")
        self._enviar(200, arq[1], (PASTA / arq[0]).read_bytes())


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--gerar", action="store_true")
    ap.add_argument("--forcar", action="store_true", help="com --gerar: nova raiz (invalida carimbos anteriores)")
    ap.add_argument("--revogar", action="store_true")
    ap.add_argument("--reemitir", action="store_true")
    ap.add_argument("--porta", type=int)
    a = ap.parse_args()
    if a.gerar:
        gerar(a.forcar)
    if a.revogar:
        revogar()
    if a.reemitir:
        reemitir()
    if a.porta:
        if not (PASTA / "raiz.pem").exists():
            gerar()
        print(f"ACT de homologação em http://127.0.0.1:{a.porta}/tsa (NÃO ICP-Brasil)")
        ThreadingHTTPServer(("127.0.0.1", a.porta), Tratador).serve_forever()


if __name__ == "__main__":
    main()
