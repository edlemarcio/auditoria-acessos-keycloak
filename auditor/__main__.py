"""Linha de comando do auditor.

  python -m auditor chave                       gera AUDITOR_CHAVE e o par de chaves de assinatura
  python -m auditor init                        cria o esquema no banco do auditor
  python -m auditor instancia-add ...           cadastra uma instância e roda o teste de conexão + sondas
  python -m auditor sondas --nome X             repete as sondas
  python -m auditor investigar ...              abre, prepara, coleta e fecha uma investigação
  python -m auditor investigar ... --fila       só abre e enfileira; o worker prepara, coleta e fecha
  python -m auditor worker [--threads N]        worker contínuo: atende a fila de todas as investigações
  python -m auditor pausar --id N --operador X  pausa a coleta (as fatias param no próximo checkpoint)
  python -m auditor retomar --id N [--fila]     continua do último ponto salvo (na hora ou pelo worker)
  python -m auditor cancelar --id N --operador X --motivo "..."
  python -m auditor exportar --id N --saida d/  gera XLSX, CSV, dashboard HTML e manifesto assinado
  python -m auditor verificar pacote.zip --chave-publica chaves/assinatura.pub.pem
  python -m auditor chaveiro [--porta 8443]     porteiro das chaves no modo vault (CHAVEIRO_DSN, token do Vault)
  python -m auditor ancorar [--ate AAAA-MM-DD]  âncora diária das cadeias da trilha (o worker faz sozinho)
  python -m auditor verificar-cadeia [--id N]   confere as cadeias da trilha e as âncoras
  python -m auditor conferir-migracao [--pasta saida]  manifestos entregues reproduzíveis a partir do cifrado (W4)

  python -m auditor api [--porta 8000]          API e BFF (W1)

AUDITOR_MODO é obrigatório: local (AUDITOR_CHAVE, só teste; recusa destino de produção), vault (serviços, chaves pelo
chaveiro por mTLS) ou producao (a CLI vira cliente da API: auditor/cliente.py). No modo vault a
identidade do processo é o certificado de chaves/servicos/: `worker` para o worker, `pacotes` para exportar e
`operador` para o resto (AUDITOR_IDENTIDADE muda). Investigar e retomar passam a usar sempre a fila do worker.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import threading
import time
from pathlib import Path

from psycopg.types.json import Jsonb

from . import chaves, coleta, investigar, servicos
from .db import conectar, criar_esquema, trilha


def cmd_init(a):
    feitos = criar_esquema()
    print("esquema ok")
    if feitos is None and chaves.modo() == "vault":
        print("modo vault: as chaves das investigações novas ficam no Vault (conversões do modo local não se aplicam)")
    elif feitos is None:
        print("chaves: AUDITOR_CHAVE não definida; conversão para o formato v2 não verificada")
    elif any(v for k, v in feitos.items() if k not in ("deks", "cifra")):
        print(f"chaves convertidas para o formato v2: {feitos}")
    if feitos and feitos.get("deks"):
        print(f"DEKs criadas para {feitos['deks']} investigação(ões) anteriores à W0b (alvo recifrado)")
    if feitos and any((feitos.get("cifra") or {}).values()):
        print(f"cifra na gravação aplicada aos dados antigos (hashes v1 conferidos): {feitos['cifra']}")


def cmd_chave(a):
    from .cripto import gerar_chaves
    k, d = gerar_chaves(Path(a.destino))
    print(f"export AUDITOR_CHAVE={k}")
    print(f"export AUDITOR_CHAVE_ED25519={d.resolve()}/assinatura.pem")


def cmd_instancia_add(a):
    from .descoberta import descobrir
    from .kc import ClienteKC
    from . import sondas
    with conectar() as cx:
        r = cx.execute(
            "INSERT INTO instancia (nome, url, realm_auth, client_id, segredo_cifrado, ca_path, concorrencia, "
            "req_por_s, versao_declarada, realms_esperados, realm_homologacao, usuario_sonda) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT (nome) DO UPDATE SET url=EXCLUDED.url, "
            "client_id=EXCLUDED.client_id, segredo_cifrado=EXCLUDED.segredo_cifrado, concorrencia=EXCLUDED.concorrencia,"
            " req_por_s=EXCLUDED.req_por_s, realms_esperados=EXCLUDED.realms_esperados, "
            "realm_homologacao=EXCLUDED.realm_homologacao, usuario_sonda=EXCLUDED.usuario_sonda RETURNING *",
            (a.nome, a.url, a.realm_auth, a.client_id, chaves.cifrar_segredo(a.nome, a.segredo), a.ca, a.concorrencia, a.req_por_s,
             a.versao, a.realms_esperados.split(",") if a.realms_esperados else [], a.homologacao, a.sonda)
        ).fetchone()
        trilha(cx, a.operador, "cadastrar_instancia", nome=a.nome, url=a.url)
    testar(r)


def testar(inst):
    from .descoberta import descobrir
    from .kc import ClienteKC
    from . import sondas
    cli = ClienteKC(inst, registrar=False)
    try:
        cli.token()
        print(f"[ok] token obtido em {inst['url']}")
        if inst["realm_homologacao"]:
            s = sondas.executar(cli, inst["realm_homologacao"], inst["usuario_sonda"],
                                inst["mapeamento"].get("cpf", "cpf"))
            with conectar() as cx:
                cx.execute("UPDATE instancia SET sondas=%s, sondas_em=now() WHERE id=%s", (Jsonb(s), inst["id"]))
            inst["sondas"] = s
            print(f"[sondas] modo={s.get('modo')} epoch={s.get('S1_epoch')} dateTo={s.get('S2_dateTo')} "
                  f"asc={s.get('S3_direction')} exact={s.get('S4_exact')} fuso={s.get('S6_fuso')} "
                  f"dateTo_semantica={s.get('S7_dateTo')} {s.get('inconclusiva', '')}")
        else:
            print("[aviso] sem realm de homologação: modo conservador 'dia'")
        with conectar() as cx:
            for r in descobrir(cx, inst, cli):
                cor = {"ok": "verde"}.get(r["status"], "vermelho" if r["status"] in (
                    "eventos_nao_gravados", "sem_permissao", "esperado_invisivel", "tipo_nao_gravado",
                    "atributo_nao_pesquisavel") else "amarelo")
                print(f"  [{cor:8s}] {r['realm']:16s} {r['status']:26s} {r['detalhe'] or ''}"
                      f"{' → ' + r['acao'] if r['acao'] else ''}")
    finally:
        cli.fechar()


def cmd_sondas(a):
    with conectar() as cx:
        inst = cx.execute("SELECT * FROM instancia WHERE nome=%s", (a.nome,)).fetchone()
    testar(inst)


def _progresso(total):
    t0 = time.time()

    def p(n):
        if n % 50 == 0 or n == total:
            print(f"  tarefas {n}/{total} ({time.time() - t0:.0f}s)", flush=True)
    return p


def cmd_investigar(a):
    tipo, valor = ("cpf", a.cpf) if a.cpf else ("titulo", a.titulo)
    inv_id = investigar.abrir(a.operador, a.justificativa, tipo, valor, a.de, a.ate, a.fuso, a.granularidade,
                              a.instancias.split(",") if a.instancias else None, a.varredura, a.base_dias)
    print(f"investigação {inv_id}")
    contas = [tuple(c.split(":", 2)) for c in a.conta or []]
    if a.fila or chaves.modo() == "vault":   # o worker prepara e coleta (python -m auditor worker)
        servicos.enfileirar(inv_id, a.operador, contas)
        print("na fila do worker")
        return
    r = investigar.preparar(inv_id, contas)
    print(json.dumps(r, ensure_ascii=False, default=str))
    _coletar(inv_id, a.threads, a.parar_apos)


def _coletar(inv_id, threads=None, parar_apos=None):
    with conectar() as cx:
        total = cx.execute("SELECT count(*) n FROM tarefa WHERE investigacao_id=%s AND status IN "
                           "('pendente','executando')", (inv_id,)).fetchone()["n"]
    t0 = time.time()
    coleta.executar(inv_id, threads, parar_apos, _progresso(total))
    print(f"coleta: {time.time() - t0:.1f}s")
    with conectar() as cx:
        st = cx.execute("SELECT status FROM investigacao WHERE id=%s", (inv_id,)).fetchone()["status"]
    if st in ("pausada", "cancelada"):
        print(json.dumps({"status": st}, ensure_ascii=False))
        return
    if parar_apos is None:
        print(json.dumps(servicos.fechar(inv_id), ensure_ascii=False))
    else:
        print(json.dumps(investigar.fechar(inv_id), ensure_ascii=False))


def cmd_retomar(a):
    try:
        servicos.retomar(a.id, a.operador)
    except servicos.TransicaoInvalida as e:
        sys.exit(str(e))
    if a.fila or chaves.modo() == "vault":
        print("retomada; o worker continua a coleta")
        return
    _coletar(a.id, a.threads)


def cmd_pausar(a):
    try:
        servicos.pausar(a.id, a.operador)
    except servicos.TransicaoInvalida as e:
        sys.exit(str(e))
    print(f"investigação {a.id} pausada; as fatias em andamento param no próximo checkpoint")


def cmd_cancelar(a):
    try:
        servicos.cancelar(a.id, a.operador, a.motivo)
    except (servicos.TransicaoInvalida, ValueError) as e:
        sys.exit(str(e))
    print(f"investigação {a.id} cancelada")


def cmd_worker(a):
    import signal
    parar = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: parar.set())
    signal.signal(signal.SIGINT, lambda *_: parar.set())
    print(f"worker com {a.threads} threads; Ctrl+C para parar", flush=True)
    n = servicos.worker(a.threads, a.ocioso, parar, (lambda s: print(" ", s, flush=True)) if a.verboso else None,
                        a.papel)
    print(f"worker encerrado: {n} itens")


def cmd_exportar(a):
    from .exportar import exportar
    print(exportar(a.id, Path(a.saida), a.operador, sem_mascara=a.sem_mascara))


def cmd_verificar(a):
    from .manifesto import verificar_pacote
    ok, msgs = verificar_pacote(Path(a.pacote), Path(a.chave_publica).read_bytes())
    for m in msgs:
        print(m)
    sys.exit(0 if ok else 1)


def cmd_ancorar(a):
    from datetime import date

    from .ancora import ancorar_pendentes
    with conectar() as cx:
        feitos = ancorar_pendentes(cx, date.fromisoformat(a.ate) if a.ate else None)
    print(f"{len(feitos)} dia(s) ancorado(s)" + (f": {feitos[0]} a {feitos[-1]}" if feitos else ""))


def cmd_verificar_cadeia(a):
    from .ancora import folha_cabeca, verificar_carimbo
    from .db import verificar_cadeia
    from .merkle import raiz
    ok = True
    with conectar() as cx:
        for cad, probs in sorted(verificar_cadeia(cx, a.id).items()):
            ok &= not probs
            print(f"[{'ok' if not probs else 'FALHA'}] cadeia {cad}" + "".join(f"\n    {p}" for p in probs[:10]))
        for an in cx.execute("SELECT * FROM ancora ORDER BY ate, id"):
            ok_a = raiz([folha_cabeca(c) for c in an["cabecas"]]) == an["raiz"] and verificar_carimbo(an["carimbo"],
                                                                                                    an["raiz"])
            for c in an["cabecas"]:   # a cabeça ancorada tem de existir na cadeia de hoje
                r = cx.execute("SELECT hash FROM trilha_auditoria WHERE cadeia=%s AND seq=%s",
                               (c["cadeia"], c["seq"])).fetchone()
                ok_a &= bool(r) and r["hash"] == c["hash"]
            ok &= ok_a
            if not ok_a or a.verboso:
                print(f"[{'ok' if ok_a else 'FALHA'}] âncora {an['tipo']} {an['dia']} ({an['carimbo']['tipo']})")
    print("cadeias e âncoras íntegras" if ok else "FALHA na verificação")
    sys.exit(0 if ok else 1)


def cmd_conferir_migracao(a):
    from . import conferir_migracao as cm
    with conectar() as cx:
        linhas = cm.conferir(cx, [Path(p) for p in a.pasta])
    for x in linhas:
        if x["resultado"] == "sem_registro":
            continue
        print(f"[{'ok' if x['resultado'] == 'confere' else 'DIVERGE'}] inv {x['investigacao']} ({x['algoritmo']}, coletor "
              f"{x['versao']}) eventos {x['eventos'][0]}/{x['eventos'][1]} requisições {x['requisicoes'][0]}/"
              f"{x['requisicoes'][1]} · {x['pacote']}")
    r = cm.resumo(linhas)
    print(json.dumps(r, ensure_ascii=False))
    return 1 if r["v1"]["divergem"] or r["atual"]["divergem"] else 0


def cmd_api(a):
    from .api import servir
    servir(a.porta)


def cmd_chaveiro(a):
    from .chaveiro import servir
    servir(a.porta, Path(a.certs))


def main():
    from . import guarda
    m = guarda.modo()                      # sem AUDITOR_MODO explícito, não inicia
    if m == "producao":                    # cliente fino da API: sem banco, sem chave, sem certificado
        guarda.exigir_cliente_limpo()
        from .cliente import main as cliente
        return cliente()
    if m == "local":
        guarda.exigir_local_seguro(instancias=guarda.instancias_cadastradas())
    ap = argparse.ArgumentParser(prog="auditor")
    sp = ap.add_subparsers(dest="cmd", required=True)
    p = sp.add_parser("chave"); p.add_argument("--destino", default="chaves"); p.set_defaults(f=cmd_chave)
    p = sp.add_parser("init"); p.set_defaults(f=cmd_init)
    p = sp.add_parser("instancia-add")
    for k in ("nome", "url", "client-id", "segredo"):
        p.add_argument(f"--{k}", required=True)
    p.add_argument("--realm-auth", default="master"); p.add_argument("--ca")
    p.add_argument("--concorrencia", type=int, default=2); p.add_argument("--req-por-s", type=float, default=5)
    p.add_argument("--versao"); p.add_argument("--realms-esperados", default="")
    p.add_argument("--homologacao"); p.add_argument("--sonda")
    p.add_argument("--operador", default="admin"); p.set_defaults(f=cmd_instancia_add)
    p = sp.add_parser("sondas"); p.add_argument("--nome", required=True); p.set_defaults(f=cmd_sondas)
    p = sp.add_parser("investigar")
    g = p.add_mutually_exclusive_group(required=True); g.add_argument("--cpf"); g.add_argument("--titulo")
    p.add_argument("--de", required=True); p.add_argument("--ate", required=True)
    p.add_argument("--operador", required=True); p.add_argument("--justificativa", required=True)
    p.add_argument("--fuso", default="America/Bahia")
    p.add_argument("--granularidade", default="dia", choices=["hora", "dia", "semana", "mes"])
    p.add_argument("--instancias"); p.add_argument("--varredura", action="store_true")
    p.add_argument("--base-dias", type=int, default=0)
    p.add_argument("--conta", action="append", help="instancia:realm:userId informado (ex.: conta excluída)")
    p.add_argument("--threads", type=int); p.add_argument("--parar-apos", type=int)
    p.add_argument("--fila", action="store_true", help="só enfileira; o worker prepara e coleta")
    p.set_defaults(f=cmd_investigar)
    p = sp.add_parser("retomar"); p.add_argument("--id", type=int, required=True); p.add_argument("--threads", type=int)
    p.add_argument("--operador", default="cli"); p.add_argument("--fila", action="store_true")
    p.set_defaults(f=cmd_retomar)
    p = sp.add_parser("pausar"); p.add_argument("--id", type=int, required=True)
    p.add_argument("--operador", required=True); p.set_defaults(f=cmd_pausar)
    p = sp.add_parser("cancelar"); p.add_argument("--id", type=int, required=True)
    p.add_argument("--operador", required=True); p.add_argument("--motivo", required=True)
    p.set_defaults(f=cmd_cancelar)
    p = sp.add_parser("worker"); p.add_argument("--threads", type=int, default=4)
    p.add_argument("--ocioso", type=float, help="encerra após N segundos sem trabalho")
    p.add_argument("--verboso", action="store_true")
    p.add_argument("--papel", choices=["todos", "coleta", "pacotes"], default="todos",
                   help="coleta: preparar, coletar e fechar; pacotes: só gerar pacotes (identidade própria)")
    p.set_defaults(f=cmd_worker)
    p = sp.add_parser("exportar"); p.add_argument("--id", type=int, required=True)
    p.add_argument("--saida", default="saida"); p.add_argument("--operador", default="auditor")
    p.add_argument("--sem-mascara", action="store_true"); p.set_defaults(f=cmd_exportar)
    p = sp.add_parser("verificar"); p.add_argument("pacote"); p.add_argument("--chave-publica", required=True)
    p.set_defaults(f=cmd_verificar)
    p = sp.add_parser("ancorar"); p.add_argument("--ate"); p.set_defaults(f=cmd_ancorar)
    p = sp.add_parser("verificar-cadeia"); p.add_argument("--id", type=int); p.add_argument("--verboso",
                                                                                        action="store_true")
    p.set_defaults(f=cmd_verificar_cadeia)
    p = sp.add_parser("api"); p.add_argument("--porta", type=int, default=8000); p.set_defaults(f=cmd_api)
    p = sp.add_parser("conferir-migracao"); p.add_argument("--pasta", action="append", default=None)
    p.set_defaults(f=lambda a: cmd_conferir_migracao(a) if a.pasta else cmd_conferir_migracao(
        argparse.Namespace(pasta=["saida"])))
    p = sp.add_parser("chaveiro"); p.add_argument("--porta", type=int, default=8443)
    p.add_argument("--certs", default="chaves/servicos"); p.set_defaults(f=cmd_chaveiro)
    a = ap.parse_args()
    # identidade mTLS do processo no modo vault (produção: cada host só tem o próprio certificado)
    os.environ.setdefault("AUDITOR_IDENTIDADE", {"worker": "pacotes" if getattr(a, "papel", "") == "pacotes"
                                                 else "worker", "exportar": "pacotes", "api": "api"}.get(a.cmd,
                                                                                                 "operador"))
    a.f(a)


if __name__ == "__main__":
    main()
