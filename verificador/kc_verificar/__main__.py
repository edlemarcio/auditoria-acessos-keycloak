"""kc-verificar: verificador offline dos pacotes do kc-auditor (formato 2).

  kc-verificar pacote.zip                     confere assinatura, carimbo, hashes, folhas, fatias, trilha e âncoras
  kc-verificar pacote.zip --recalcular        refaz KPIs, consolidado, destaques e cobertura e compara
  kc-verificar pacote.zip --revelacao r.json  confere um evento entregue depois (revelação seletiva)
  kc-verificar pacote.zip --json              resultado em JSON

Sem banco e sem rede. Confia só nas chaves públicas publicadas (kc_verificar/chaves/chaves.json, ou --chaves) e nas
AC-Raiz da ICP-Brasil (kc_verificar/raizes/icp-brasil). --homologacao aceita também a raiz de teste da ACT de
homologação, que fica num diretório separado. Código de saída: 0 íntegro, 1 com falha, 2 erro de uso.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .pacote import verificar

MARCA = {"ok": "[ok]   ", "aviso": "[aviso]", "falha": "[FALHA]"}


def frase(r) -> str:
    s = r.resumo
    if not r.integro:
        return "Pacote NÃO íntegro: veja as falhas abaixo."
    partes = [f"Pacote íntegro, assinado pela chave {s.get('key_id')}"]
    if s.get("carimbado_em"):
        from datetime import datetime
        partes.append(f"carimbado em {datetime.fromisoformat(s['carimbado_em']):%d/%m/%Y %H:%M} (UTC)")
    else:
        partes.append("sem carimbo do tempo de terceiro")
    return ", ".join(partes) + "."


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="kc-verificar", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pacote", type=Path)
    ap.add_argument("--recalcular", action="store_true")
    ap.add_argument("--revelacao", type=Path)
    ap.add_argument("--homologacao", action="store_true", help="aceita a raiz de teste da ACT de homologação")
    ap.add_argument("--chaves", type=Path, help="lista adicional de chaves públicas (mesmo formato de chaves.json)")
    ap.add_argument("--raizes", type=Path, help="diretório adicional de raízes confiáveis (PEM ou DER)")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--versao", action="version", version=f"kc-verificar {__version__}")
    a = ap.parse_args(argv)
    if not a.pacote.exists():
        print(f"arquivo não encontrado: {a.pacote}", file=sys.stderr)
        return 2
    r = verificar(a.pacote, homologacao=a.homologacao, chaves_extra=a.chaves, raizes_extra=a.raizes,
                  recalcular=a.recalcular, revelacao=a.revelacao)
    if a.json:
        print(json.dumps({"integro": r.integro, "frase": frase(r), "resumo": r.resumo, "verificador": __version__,
                          "itens": [{"nivel": i.nivel, "texto": i.texto} for i in r.itens]}, ensure_ascii=False,
                         indent=1))
    else:
        print(frase(r))
        print()
        for i in r.itens:
            print(f"{MARCA[i.nivel]} {i.texto}")
        print()
        for k in ("manifesto_sha256", "pacote_sha256", "raiz_merkle", "revogacao_conferida_ate"):
            if r.resumo.get(k):
                print(f"{k}: {r.resumo[k]}")
    return 0 if r.integro else 1


if __name__ == "__main__":
    sys.exit(main())
