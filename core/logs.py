#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Argus ASM — monitoramento de superfície de ataque
# Copyright (C) 2026  Bruno Santos
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""
logs.py — Trilha de AUDITORIA da aplicação (Syslog RFC 5424) — Argus ASM
========================================================================

Registra os EVENTOS DE APLICAÇÃO exigidos para auditoria/conformidade num log
DEDICADO e *append-only* (`/var/log/argus/audit/audit.log`), separado dos logs
operacionais dos scanners. Formato RFC 5424 — pronto para SIEM.

Cobertura (quem · o quê · quando · de onde · resultado):
  • Autorização       — AUTHZ_DENY  (ação bloqueada: CSRF / permissão)
  • Mudança de achado — FINDING_STATUS / FINDING_NOTE / FINDING_EVIDENCE
  (A autenticação — login OK/falho/logout — é registrada pelo Apache em
   `argus-auth.log`, pois a credencial é validada no Apache, não na aplicação.)

Campos estruturados (ordem estável p/ parsing): correlation_id · actor (user_id) ·
  src_ip · action · object (ex.: finding_id) · object_type · outcome
  (success|deny|error) · from_status → to_status · detail · user_agent.

Mapa de conformidade (o que cada evento atende):
  ISO/IEC 27001:2022  A.8.15 (Logging) · A.8.16 (Monitoring) · A.5.28 (evidências)
  CIS Controls v8     8.2 / 8.5 (logs detalhados) · 8.9 (centralizar) · 6.x (acesso)
  NIST SP 800-53      AU-2 / AU-3 / AU-8 / AU-9 / AU-12 · AC-6 / AC-7
  PCI-DSS v4.0        10.2 (registrar acessos) · 10.2.1.x · 10.3 (proteger) · 10.6 (tempo)

Postura: *best-effort* — uma falha de log NUNCA interrompe o fluxo da aplicação.
NUNCA registra segredos (senha/chave): quem chama é responsável por não passá-los.
"""

from __future__ import annotations

import datetime
import os
import socket
import sys
import uuid
from pathlib import Path

AUDIT_LOG = os.environ.get("ARGUS_AUDIT_LOG", "/var/log/argus/audit/audit.log")
APP_NAME = "argus-audit"

# Facility 13 (RFC 5424) = "log audit" — mensagens de auditoria de segurança.
_FACILITY = 13
_SEV = {"EMERG": 0, "ALERT": 1, "CRIT": 2, "ERR": 3, "ERROR": 3,
        "WARNING": 4, "WARN": 4, "NOTICE": 5, "INFO": 6, "DEBUG": 7}

# Ordem estável dos campos estruturados (facilita o parsing no SIEM).
_ORDER = ("correlation_id", "actor", "src_ip", "action", "object", "object_type",
          "outcome", "from_status", "to_status", "detail", "user_agent")


def _esc(v) -> str:
    """Escapa o valor de um SD-PARAM (RFC 5424 §6.3.3)."""
    return str(v).replace("\\", "\\\\").replace('"', '\\"').replace("]", "\\]")


class AuditLogger:
    """Logger de auditoria RFC 5424 — append em arquivo (fallback stderr).

    Best-effort: erro de escrita não interrompe o fluxo. Abra uma vez por
    processo (use `get_logger()`)."""

    def __init__(self, log_path: str = AUDIT_LOG):
        self.host = socket.gethostname() or "-"
        self.pid = os.getpid()
        self._fd = None
        try:
            p = Path(log_path)
            p.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(str(p), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o640)
            self._fd = os.fdopen(fd, "a", encoding="utf-8", errors="replace")
        except Exception:
            self._fd = None   # degrada para só-stderr

    def event(self, msgid: str, message: str = "", *, level: str = "NOTICE", **fields) -> None:
        sev = _SEV.get(str(level).upper(), 5)
        pri = _FACILITY * 8 + sev
        ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        cid = fields.pop("correlation_id", None) or str(uuid.uuid4())
        merged = {"correlation_id": cid}
        for k, v in fields.items():
            if v in (None, "", []):
                continue
            merged[k] = v
        ordered = [k for k in _ORDER if k in merged] + sorted(k for k in merged if k not in _ORDER)
        sd = " ".join(f'{k}="{_esc(merged[k])}"' for k in ordered)
        line = (f"<{pri}>1 {ts} {self.host} {APP_NAME} {self.pid} {msgid} "
                f"[argus@32473 {sd}] {str(message).replace(chr(10), ' ')}\n")
        try:
            if self._fd is not None:
                self._fd.write(line)
                self._fd.flush()
            else:
                sys.stderr.write(line)
        except Exception:
            pass

    def close(self) -> None:
        if self._fd is not None:
            try:
                self._fd.flush()
                self._fd.close()
            finally:
                self._fd = None


_LOGGER: "AuditLogger | None" = None


def get_logger() -> AuditLogger:
    """Singleton por processo (abre o arquivo uma vez)."""
    global _LOGGER
    if _LOGGER is None:
        _LOGGER = AuditLogger()
    return _LOGGER


def audit(msgid: str, message: str = "", **fields) -> None:
    """Emite um evento de auditoria. Best-effort — nunca levanta."""
    try:
        get_logger().event(msgid, message, **fields)
    except Exception:
        pass


# CLI de teste: `python3 logs.py` grava um evento de exemplo.
if __name__ == "__main__":
    audit("AUDIT_TEST", "evento de teste do argus-audit", actor="cli",
          action="selftest", outcome="success")
    print(f"[logs] evento de teste gravado em {AUDIT_LOG}")
