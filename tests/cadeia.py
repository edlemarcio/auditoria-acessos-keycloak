"""Critérios de aceite da trilha encadeada e da âncora diária (docs/PROPOSTA_WEB.md §6.3, etapa W0b), modo local.

  AUDITOR_DSN=<kc_auditor_app> AUDITOR_DSN_DONO=<dono> KC_DSN_kc26=... KC_DSN_kc18=... python tests/cadeia.py

1. Todas as cadeias conferem (continuidade e hash de cada registro); nenhum registro fora de cadeia.
2. Campos livres (justificativa, motivo, alvo) fora do detalhe em claro; o cifrado abre com a DEK e confere com o
   compromisso com sal que entrou no hash.
3. Adulteração da trilha pelo DBA (alterar um registro, apagar um registro) é detectada.
4. Âncora: raiz recalculada das cabeças, carimbo (simulado) válido, prova de inclusão de cada cabeça.
5. Pacote: trilha.jsonl recalcula a cadeia sem nenhum dado do banco; as provas de ancoras/ verificam contra a raiz
   carimbada; a cabeça ancorada está no trilha.jsonl, e o selo de cada fatia de fatias.json está na cadeia.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import zipfile
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import psycopg
import psycopg.types.json
import rfc8785

RAIZ = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RAIZ))
from auditor import ancora, coleta, investigar, servicos, sigilo  # noqa: E402
from auditor.db import compromisso_livre, conectar, genese, verificar_cadeia  # noqa: E402

falhas: list[str] = []


def checar(ok: bool, nome: str, detalhe: str = ""):
    print(f"{'OK   ' if ok else 'FALHA'} {nome}{(' — ' + detalhe) if detalhe else ''}", flush=True)
    if not ok:
        falhas.append(nome)


def main():
    alvo = json.loads((RAIZ / "dados/pessoas.json").read_text())["casos"]["ALVO"]["cpf"]
    ate = date.today() - timedelta(days=1)
    inv = investigar.abrir("teste-cadeia", "Justificativa livre do teste da cadeia", "cpf", alvo,
                           (ate - timedelta(days=2)).isoformat(), ate.isoformat())
    investigar.preparar(inv)
    coleta.executar(inv)
    servicos.fechar(inv)
    c = investigar.abrir("teste-cadeia", "Outra investigação, para cancelar", "cpf", alvo, ate.isoformat(),
                         ate.isoformat())
    servicos.cancelar(c, "teste-cadeia", "Motivo livre do cancelamento")
    print(f"investigações {inv} e {c}", flush=True)

    # ---- 1
    with conectar() as cx:
        probs = verificar_cadeia(cx)
    ruins = {k: v for k, v in probs.items() if v}
    checar(not ruins, "1 todas as cadeias conferem, nenhum registro fora de cadeia",
           f"{len(probs)} cadeias; problemas: {dict(list(ruins.items())[:2])}")

    # ---- 2
    with conectar() as cx:
        claro = cx.execute("SELECT count(*) n FROM trilha_auditoria WHERE detalhe ?| array['justificativa','motivo',"
                           "'alvo']").fetchone()["n"]
        checar(claro == 0, "2 nenhum campo livre em claro no detalhe da trilha", f"{claro} registro(s)")
        ok_c = True
        for i_ in (inv, c):
            i = cx.execute("SELECT * FROM investigacao WHERE id=%s", (i_,)).fetchone()
            cf = sigilo.Cofre(i_, "exportar")
            for r in cx.execute("SELECT * FROM trilha_auditoria WHERE cadeia=%s AND livres_cifrado IS NOT NULL",
                                (i_,)):
                lv = sigilo.livres_trilha(cf, i, r)
                ok_c &= all(compromisso_livre(bytes.fromhex(v["sal"]), v["valor"]) == r["livres_compromisso"][k]
                            for k, v in lv.items())
                ok_c &= ("justificativa" in lv and "livre do teste" in lv["justificativa"]["valor"]) or \
                        ("motivo" in lv and "Motivo livre" in lv["motivo"]["valor"]) or "alvo" in lv
        checar(ok_c, "2 campos livres cifrados abrem com a DEK e conferem com o compromisso do hash")

    # ---- 3 adulteração pelo DBA (com o trigger desligado, como só o dono pode)
    dono = psycopg.connect(os.environ["AUDITOR_DSN_DONO"], autocommit=True)
    r = dono.execute("SELECT id, detalhe::text, seq FROM trilha_auditoria WHERE cadeia=%s ORDER BY seq LIMIT 1 OFFSET 2",
                     (inv,)).fetchone()
    dono.execute("ALTER TABLE trilha_auditoria DISABLE TRIGGER trg_trilha_ro")
    try:
        dono.execute("UPDATE trilha_auditoria SET detalhe = detalhe || '{\"adulterado\": true}' WHERE id=%s", (r[0],))
        with conectar() as cx:
            p1 = verificar_cadeia(cx, inv)[inv]
        dono.execute("UPDATE trilha_auditoria SET detalhe=%s::jsonb WHERE id=%s", (r[1], r[0]))
        linha = dono.execute("SELECT * FROM trilha_auditoria WHERE id=%s", (r[0],)).fetchone()
        cols = [d.name for d in dono.execute("SELECT * FROM trilha_auditoria LIMIT 0").description]
        dono.execute("DELETE FROM trilha_auditoria WHERE id=%s", (r[0],))
        with conectar() as cx:
            p2 = verificar_cadeia(cx, inv)[inv]
        dono.execute(f"INSERT INTO trilha_auditoria ({','.join(cols)}) VALUES ({','.join(['%s'] * len(cols))})",
                     [psycopg.types.json.Jsonb(v) if isinstance(v, (dict, list)) else v for v in linha])
    finally:
        dono.execute("ALTER TABLE trilha_auditoria ENABLE TRIGGER trg_trilha_ro")
    checar(any("alterado" in p for p in p1), "3 registro alterado na trilha é detectado", p1[0] if p1 else "")
    checar(any("faltando" in p for p in p2), "3 registro apagado da trilha é detectado", p2[0] if p2 else "")
    with conectar() as cx:
        checar(not verificar_cadeia(cx, inv)[inv], "3 cadeia íntegra de novo depois de desfeita a adulteração")

    # ---- 4 âncora sob demanda (a cadeia nova só tem registros de hoje)
    with conectar() as cx:
        ancora.ancorar_pendentes(cx)
        a = ancora.ancorar_agora(cx)
        folhas = [ancora.folha_cabeca(x) for x in a["cabecas"]]
        from auditor.merkle import raiz
        ok_p = all(ancora.verificar_prova(folhas[i], ancora.prova(folhas, i), a["raiz"]) for i in range(len(folhas)))
        checar(raiz(folhas) == a["raiz"] and ancora.verificar_carimbo(a["carimbo"], a["raiz"]) and ok_p,
               "4 âncora: raiz das cabeças, carimbo válido e prova de inclusão de todas as cabeças",
               f"{len(folhas)} cadeias, carimbo {a['carimbo']['tipo']}")
        falso = dict(a["carimbo"], raiz="00" * 32)
        checar(not ancora.verificar_carimbo(falso, "00" * 32), "4 carimbo não vale para outra raiz")

    # ---- 5 pacote
    from auditor.exportar import exportar
    pac = exportar(inv, RAIZ / "saida" / "teste_cadeia", "teste-cadeia")["pacote"]
    with zipfile.ZipFile(pac) as z:
        linhas = [json.loads(x) for x in z.read("trilha.jsonl").splitlines()]
        provas = [json.loads(z.read(n)) for n in z.namelist() if n.startswith("ancoras/")]
        fatias = json.loads(z.read("fatias.json"))
        trilha_bruta = z.read("trilha.jsonl")
    ant, ok_t = genese(inv), True
    for x in linhas:   # verificação independente: só o arquivo do pacote
        h = x.pop("hash")
        ok_t &= x["anterior"] == ant and hashlib.sha256(rfc8785.dumps(x)).hexdigest() == h
        ant = x["hash"] = h
    checar(ok_t and linhas, "5 trilha.jsonl recalcula a cadeia sozinho", f"{len(linhas)} registros")
    checar(b"livre do teste" not in trilha_bruta, "5 trilha.jsonl sem textos livres")
    por_seq = {x["seq"]: x["hash"] for x in linhas}
    ok_a = bool(provas) and all(
        ancora.verificar_prova(p["folha"], p["prova"], p["raiz"]) and ancora.verificar_carimbo(p["carimbo"], p["raiz"])
        and p["folha"] == ancora.folha_cabeca(p["cabeca"]) and por_seq.get(p["cabeca"]["seq"]) == p["cabeca"]["hash"]
        for p in provas)
    checar(ok_a, "5 provas de ancoras/ verificam contra a raiz carimbada e a cabeça está no trilha.jsonl",
           f"{len(provas)} prova(s)")
    selos = {x["detalhe"]["raiz"] for x in linhas if x["acao"] == "selar_fatia"}
    cab = max(p["cabeca"]["seq"] for p in provas) if provas else 0
    checar(all(f["raiz"] in selos for f in fatias) and all(x["seq"] <= cab for x in linhas if x["acao"] == "selar_fatia"),
           "5 todo selo de fatias.json está na cadeia, antes da cabeça ancorada", f"{len(fatias)} fatias")
    print(f"\n{'APROVADO' if not falhas else 'REPROVADO'}: {len(falhas)} falha(s)")
    sys.exit(1 if falhas else 0)


if __name__ == "__main__":
    main()
