"""Cópia de eventos de segurança para o SIEM (PROPOSTA_WEB §6.3): só ação, ator, horário, investigação, ids e
hashes; nunca texto livre nem identificador.

  AUDITOR_SIEM   arquivo JSONL (padrão logs/siem.jsonl) ou udp://host:porta (syslog)
"""
from __future__ import annotations

import json
import logging
import logging.handlers
import os
import threading
from datetime import datetime, timezone
from pathlib import Path

PERMITIDOS = {"acao", "ator", "investigacao", "finalidade", "classe", "servico", "severidade", "motivo_codigo",
              "instancia", "quantidade", "janela_s", "sha256"}
_lock = threading.Lock()
_syslog: logging.Logger | None = None


def enviar(acao: str, severidade: str = "info", **campos):
    ev = {"quando": datetime.now(timezone.utc).isoformat(), "acao": acao, "severidade": severidade,
          **{k: v for k, v in campos.items() if k in PERMITIDOS}}
    destino = os.environ.get("AUDITOR_SIEM", "logs/siem.jsonl")
    linha = json.dumps(ev, ensure_ascii=False, sort_keys=True)
    with _lock:
        if destino.startswith("udp://"):
            global _syslog
            if _syslog is None:
                host, porta = destino[6:].rsplit(":", 1)
                _syslog = logging.getLogger("kc-auditor.siem")
                _syslog.addHandler(logging.handlers.SysLogHandler(address=(host, int(porta))))
                _syslog.setLevel(logging.INFO)
            _syslog.info("kc-auditor %s", linha)
        else:
            p = Path(destino)
            p.parent.mkdir(parents=True, exist_ok=True)
            with p.open("a", encoding="utf-8") as f:
                f.write(linha + "\n")
