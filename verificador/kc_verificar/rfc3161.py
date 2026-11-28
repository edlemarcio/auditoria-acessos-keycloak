"""Validação de carimbo do tempo RFC 3161 sem rede (FORMATO_PACOTE.md §8).

A `cryptography` não valida TimeStampToken; aqui o token é lido com `asn1crypto` e conferido passo a passo:
  1. status "granted" (quando é uma TimeStampResp) e conteúdo `id-ct-TSTInfo`;
  2. `messageImprint` igual ao hash esperado;
  3. atributo assinado `messageDigest` igual ao SHA-* do TSTInfo e assinatura do SignerInfo pela chave do certificado
     da ACT (RSA PKCS#1 v1.5 ou ECDSA);
  4. certificado da ACT com uso estendido exclusivo `timeStamping` e válido na data do carimbo;
  5. cadeia até uma das raízes confiáveis (assinatura de cada certificado pelo emissor, validade, CA);
  6. revogação pelas LCRs fornecidas (as que o exportador capturou e pôs no pacote): LCR assinada pelo emissor do
     certificado e certificado fora dela. Sem LCR do emissor, a revogação fica "não conferida" (aviso, não falha).
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone

from asn1crypto import cms, tsp
from asn1crypto import x509 as ax509
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID

HASHES = {"sha256": (hashlib.sha256, hashes.SHA256), "sha384": (hashlib.sha384, hashes.SHA384),
          "sha512": (hashlib.sha512, hashes.SHA512)}


@dataclass
class Resultado:
    ok: bool
    gen_time: datetime | None = None
    act: str | None = None
    politica: str | None = None
    raiz: str | None = None
    revogacao_ate: datetime | None = None     # thisUpdate da LCR usada (até quando a revogação foi conferida)
    problemas: list[str] = field(default_factory=list)
    avisos: list[str] = field(default_factory=list)


def _token(dados: bytes) -> cms.ContentInfo:
    try:
        r = tsp.TimeStampResp.load(dados)
        st = r["status"]["status"].native
        if st not in ("granted", "granted_with_mods"):
            raise ValueError(f"ACT recusou o pedido ({st})")
        return r["time_stamp_token"]
    except ValueError:
        raise
    except Exception:  # noqa: BLE001 — pode ser só o token (ContentInfo)
        return cms.ContentInfo.load(dados)


def _verificar_assinatura(pub, assinatura: bytes, dados: bytes, h) -> None:
    if isinstance(pub, rsa.RSAPublicKey):
        pub.verify(assinatura, dados, padding.PKCS1v15(), h())
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        pub.verify(assinatura, dados, ec.ECDSA(h()))
    else:
        raise InvalidSignature("algoritmo de chave não suportado")


def _assinado_por(cert: x509.Certificate, emissor: x509.Certificate) -> bool:
    try:
        cert.verify_directly_issued_by(emissor)
        return True
    except (ValueError, TypeError, InvalidSignature):
        return False


def _valido_em(c: x509.Certificate, quando: datetime) -> bool:
    return c.not_valid_before_utc <= quando <= c.not_valid_after_utc


def _eh_ca(c: x509.Certificate) -> bool:
    try:
        return c.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    except x509.ExtensionNotFound:
        return False


def verificar(dados_tsr: bytes, hash_esperado: bytes, raizes: list[x509.Certificate],
              lcrs: list[x509.CertificateRevocationList] = (), intermediarios: list[x509.Certificate] = ()
              ) -> Resultado:
    r = Resultado(ok=False)
    try:
        tok = _token(dados_tsr)
    except Exception as e:  # noqa: BLE001
        r.problemas.append(f"carimbo ilegível: {e}")
        return r
    if tok["content_type"].native != "signed_data":
        r.problemas.append("carimbo não é SignedData")
        return r
    sd = tok["content"]
    eci = sd["encap_content_info"]
    if eci["content_type"].native != "tst_info":
        r.problemas.append("conteúdo do carimbo não é TSTInfo")
        return r
    tst_der = eci["content"].contents
    tst = tsp.TSTInfo.load(tst_der)
    r.gen_time = tst["gen_time"].native.astimezone(timezone.utc)
    r.politica = tst["policy"].dotted
    mi = tst["message_imprint"]
    alg = mi["hash_algorithm"]["algorithm"].native
    if alg not in HASHES:
        r.problemas.append(f"algoritmo de hash do carimbo não suportado: {alg}")
        return r
    if mi["hashed_message"].native != hash_esperado:
        r.problemas.append("o carimbo é de outro conteúdo (messageImprint diferente)")
    # certificados: os do token e os intermediários fornecidos
    certs = []
    for c in sd["certificates"] or []:
        if c.name == "certificate":
            certs.append(x509.load_der_x509_certificate(c.chosen.dump()))
    certs += list(intermediarios)
    infos = sd["signer_infos"]
    if len(infos) != 1:
        r.problemas.append("carimbo com número inesperado de assinantes")
        return r
    si = infos[0]
    sid = si["sid"]
    act = None
    if sid.name == "issuer_and_serial_number":
        ias = sid.chosen
        for c in certs:
            if (c.serial_number == ias["serial_number"].native
                    and ax509.Name.load(c.issuer.public_bytes()) == ias["issuer"]):
                act = c
    else:
        ski = sid.chosen.native
        for c in certs:
            try:
                if c.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest == ski:
                    act = c
            except x509.ExtensionNotFound:
                pass
    if act is None:
        r.problemas.append("certificado da ACT ausente do carimbo")
        return r
    r.act = act.subject.rfc4514_string()
    dalg = si["digest_algorithm"]["algorithm"].native
    if dalg not in HASHES:
        r.problemas.append(f"algoritmo de resumo do assinante não suportado: {dalg}")
        return r
    hfun, hcls = HASHES[dalg]
    attrs = si["signed_attrs"]
    md = next((a["values"][0].native for a in attrs if a["type"].native == "message_digest"), None)
    ct = next((a["values"][0].native for a in attrs if a["type"].native == "content_type"), None)
    if md != hfun(tst_der).digest() or ct != "tst_info":
        r.problemas.append("atributos assinados não conferem com o TSTInfo")
    scv2 = next((a["values"][0] for a in attrs if a["type"].native == "signing_certificate_v2"), None)
    scv1 = next((a["values"][0] for a in attrs if a["type"].native == "signing_certificate"), None)
    from cryptography.hazmat.primitives import serialization
    act_der = act.public_bytes(serialization.Encoding.DER)
    if scv2 is not None:
        ess = scv2["certs"][0]
        halg = ess["hash_algorithm"]["algorithm"].native or "sha256"
        if ess["cert_hash"].native != HASHES.get(halg, HASHES["sha256"])[0](act_der).digest():
            r.problemas.append("signingCertificateV2 não corresponde ao certificado da ACT")
    elif scv1 is not None:
        if scv1["certs"][0]["cert_hash"].native != hashlib.sha1(act_der).digest():  # noqa: S324 — exigido pela RFC 2634
            r.problemas.append("signingCertificate não corresponde ao certificado da ACT")
    else:
        r.problemas.append("carimbo sem o atributo signingCertificate (RFC 5816)")
    dados_assinados = b"\x31" + attrs.dump()[1:]   # [0] IMPLICIT → SET OF, como foi assinado
    try:
        _verificar_assinatura(act.public_key(), si["signature"].native, dados_assinados, hcls)
    except InvalidSignature:
        r.problemas.append("assinatura do carimbo não confere")
    # uso do certificado da ACT
    try:
        eku = act.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        if list(eku.value) != [ExtendedKeyUsageOID.TIME_STAMPING] or not eku.critical:
            r.problemas.append("certificado da ACT sem uso exclusivo e crítico de carimbo do tempo")
    except x509.ExtensionNotFound:
        r.problemas.append("certificado da ACT sem uso estendido de carimbo do tempo")
    if not _valido_em(act, r.gen_time):
        r.problemas.append("certificado da ACT fora da validade na data do carimbo")
    # cadeia até uma raiz confiável
    cadeia, atual = [act], act
    pool = certs + list(intermediarios)
    raiz = None
    for _ in range(6):
        raiz = next((x for x in raizes if x.subject == atual.issuer and _assinado_por(atual, x)), None)
        if raiz:
            break
        prox = next((x for x in pool if x.subject == atual.issuer and x is not atual and _eh_ca(x)
                     and _assinado_por(atual, x)), None)
        if prox is None:
            break
        cadeia.append(prox)
        atual = prox
    if raiz is None:
        r.problemas.append("a cadeia do certificado da ACT não chega a uma raiz confiável")
    else:
        r.raiz = raiz.subject.rfc4514_string()
        for c in cadeia[1:] + [raiz]:
            if not _valido_em(c, r.gen_time):
                r.problemas.append(f"certificado {c.subject.rfc4514_string()} fora da validade na data do carimbo")
        # revogação
        emissores = cadeia[1:] + [raiz]
        datas = []
        for c, emissor in zip(cadeia, emissores):
            lcr = next((l for l in lcrs if l.issuer == emissor.subject and l.is_signature_valid(emissor.public_key())),
                       None)
            if lcr is None:
                r.avisos.append(f"revogação de {c.subject.rfc4514_string()} não conferida (sem LCR do emissor)")
                continue
            datas.append(lcr.last_update_utc)
            rev = lcr.get_revoked_certificate_by_serial_number(c.serial_number)
            if rev is not None:
                r.problemas.append(f"certificado {c.subject.rfc4514_string()} revogado em "
                                   f"{rev.revocation_date_utc.isoformat()}")
        if datas:
            r.revogacao_ate = min(datas)
    r.ok = not r.problemas
    return r


def gen_time(dados_tsr: bytes) -> datetime:
    tok = _token(dados_tsr)
    return tsp.TSTInfo.load(tok["content"]["encap_content_info"]["content"].contents)["gen_time"].native


def certificados(dados_tsr: bytes) -> list[x509.Certificate]:
    tok = _token(dados_tsr)
    return [x509.load_der_x509_certificate(c.chosen.dump()) for c in tok["content"]["certificates"] or []
            if c.name == "certificate"]
