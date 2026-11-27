"""Gera o conjunto determinístico de pessoas e contas usado nas duas instâncias de teste.

Saída: JSON com instâncias, realms, pessoas (CPF e Título válidos, aleatórios) e contas.
As mesmas pessoas aparecem nas duas instâncias, para testar a consolidação multi-instância.

Casos especiais (para os testes de aceite):
  - ALVO: pessoa com contas em 5 realms das 2 instâncias (uma com CPF mascarado no atributo).
  - DUPLICADA: mesmo CPF em 2 contas do mesmo realm.
  - EXCLUIDA: conta que terá eventos, mas é removida do cadastro (só o histórico a encontra).
"""
from __future__ import annotations

import argparse
import json
import random
import unicodedata
import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from auditor.identificador import completar_cpf, completar_titulo, formatar_cpf  # noqa: E402

NOMES = ["Ana", "Bruno", "Carla", "Diego", "Elisa", "Fábio", "Gabriela", "Heitor", "Iara", "João",
         "Kátia", "Lucas", "Marina", "Nelson", "Olívia", "Paulo", "Quitéria", "Rafael", "Sofia", "Tiago",
         "Úrsula", "Vinícius", "Wesley", "Ximena", "Yasmin", "Zeca"]
SOBRENOMES = ["Silva", "Santos", "Oliveira", "Souza", "Lima", "Pereira", "Costa", "Rodrigues", "Almeida",
              "Nascimento", "Araújo", "Barbosa", "Ribeiro", "Carvalho", "Gomes", "Martins", "Rocha", "Dias"]

INSTANCIAS = {
    "kc26": {"realms": ["portal-cidadao", "intranet", "servicos"]},
    "kc18": {"realms": ["portal-cidadao", "legado", "rh"]},
}
CLIENTES = {
    "portal-cidadao": ["portal-web", "app-mobile", "agendamento"],
    "intranet": ["intranet-web", "sei", "chamados"],
    "servicos": ["servicos-api", "protocolo", "ouvidoria"],
    "legado": ["sistema-legado", "relatorios"],
    "rh": ["folha", "ponto-eletronico"],
}


def ascii_(t: str) -> str:
    return unicodedata.normalize("NFKD", t).encode("ascii", "ignore").decode().lower()


def gerar(n_pessoas: int, seed: int) -> dict:
    rnd = random.Random(seed)
    cpfs, titulos = set(), set()
    pessoas = []
    while len(pessoas) < n_pessoas:
        cpf = completar_cpf("".join(str(rnd.randint(0, 9)) for _ in range(9)))
        uf = f"{rnd.randint(1, 28):02d}"
        tit = completar_titulo("".join(str(rnd.randint(0, 9)) for _ in range(8)), uf)
        if cpf in cpfs or tit in titulos or cpf == cpf[0] * 11:
            continue
        cpfs.add(cpf); titulos.add(tit)
        nome = rnd.choice(NOMES); sob = rnd.choice(SOBRENOMES)
        pessoas.append({"cpf": cpf, "titulo": tit, "nome": nome, "sobrenome": sob,
                        "peso": rnd.paretovariate(1.3)})  # atividade desigual entre pessoas

    contas = []

    def nova_conta(p, inst, realm, cpf_attr=None, username=None, marca=None):
        contas.append({
            "id": str(uuid.UUID(int=rnd.getrandbits(128))),
            "instancia": inst, "realm": realm,
            "username": username or (p["cpf"] if rnd.random() < 0.7 else
                                     f"{ascii_(p['nome'])}.{ascii_(p['sobrenome'])}.{p['cpf'][-5:]}"),
            "email": f"{ascii_(p['nome'])}.{ascii_(p['sobrenome'])}.{p['cpf'][-5:]}@exemplo.gov.br",
            "nome": p["nome"], "sobrenome": p["sobrenome"],
            "cpf_attr": cpf_attr or (p["cpf"] if rnd.random() < 0.9 else formatar_cpf(p["cpf"])),
            "titulo_attr": p["titulo"],
            "cpf": p["cpf"], "peso": p["peso"], "marca": marca,
            "criado": None,
        })

    # Contas regulares: cada pessoa entra em 1..4 realms aleatórios.
    todos_realms = [(i, r) for i, v in INSTANCIAS.items() for r in v["realms"]]
    for p in pessoas[3:]:
        k = rnd.choices([1, 2, 3, 4], weights=[50, 30, 15, 5])[0]
        for inst, realm in rnd.sample(todos_realms, k):
            nova_conta(p, inst, realm)

    # Casos especiais
    alvo, dup, exc = pessoas[0], pessoas[1], pessoas[2]
    alvo["peso"] = 40.0
    for inst, realm in [("kc26", "portal-cidadao"), ("kc26", "intranet"), ("kc26", "servicos"),
                        ("kc18", "portal-cidadao"), ("kc18", "legado")]:
        attr = formatar_cpf(alvo["cpf"]) if realm == "legado" else alvo["cpf"]
        nova_conta(alvo, inst, realm, cpf_attr=attr, username=alvo["cpf"] if realm != "intranet" else None,
                   marca="ALVO")
    nova_conta(dup, "kc26", "intranet", username=dup["cpf"], marca="DUPLICADA")
    nova_conta(dup, "kc26", "intranet", username=f"{ascii_(dup['nome'])}.dup.{dup['cpf'][-5:]}", marca="DUPLICADA")
    nova_conta(exc, "kc26", "portal-cidadao", username=exc["cpf"], marca="EXCLUIDA")

    return {"seed": seed, "instancias": INSTANCIAS, "clientes": CLIENTES,
            "casos": {"ALVO": alvo, "DUPLICADA": dup, "EXCLUIDA": exc},
            "pessoas": pessoas, "contas": contas}


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--pessoas", type=int, default=6000)
    ap.add_argument("--seed", type=int, default=20261126)
    ap.add_argument("--saida", default="dados/pessoas.json")
    a = ap.parse_args()
    d = gerar(a.pessoas, a.seed)
    Path(a.saida).parent.mkdir(parents=True, exist_ok=True)
    Path(a.saida).write_text(json.dumps(d, ensure_ascii=False))
    from collections import Counter
    c = Counter((x["instancia"], x["realm"]) for x in d["contas"])
    print(f"pessoas={len(d['pessoas'])} contas={len(d['contas'])}")
    for k, v in sorted(c.items()):
        print(f"  {k[0]:5s} {k[1]:15s} {v}")
    print("ALVO CPF:", d["casos"]["ALVO"]["cpf"])
