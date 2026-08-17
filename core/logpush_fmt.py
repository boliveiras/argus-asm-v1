#!/usr/bin/env python3
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
logpush_fmt — RFC 5424 para leitura humana.

O bucket recebe a linha original; o chat recebe isto. Linha de syslog crua num
chat é ilegível, e alerta que ninguém lê não serve para nada.
"""

from __future__ import annotations

import datetime
import re

from logpush_dest.base import Mensagem

# <PRI>1 TIMESTAMP HOST APP PID MSGID [SD-ID campo="valor" ...] mensagem
_RE = re.compile(
    r'^<(?P<pri>\d{1,3})>1 (?P<ts>\S+) (?P<host>\S+) (?P<app>\S+) (?P<pid>\S+) '
    r'(?P<msgid>\S+) \[(?P<sdid>[^\s\]]+)(?P<sd>[^\]]*)\] ?(?P<msg>.*)$'
)
_CAMPO = re.compile(r'(\w+)="((?:[^"\\]|\\.)*)"')

# severity do syslog (prival % 8) -> vocabulário de risco do Argus
_SEV = {2: "CRITICO", 3: "CRITICO", 4: "ALTO", 5: "MEDIO", 6: "BAIXO", 7: "BAIXO"}

_EMOJI = {"CRITICO": "🔴", "ALTO": "🟠", "MEDIO": "🟡", "BAIXO": "🟢", "INFO": "🔵"}

_TITULO = {
    "PORT_NEW":     "Nova porta exposta",
    "PORT_FIXED":   "Porta fechada",
    "HOST_NEW":     "Novo subdomínio",
    "HOST_GONE":    "Subdomínio removido",
    "CRED_LEAK":    "Credenciais expostas",
    "EMAIL_RISK":   "Postura de e-mail frágil",
    "TYPO_NEW":     "Domínio sósia registrado",
    "SCAN_START":   "Scan iniciado",
    "SCAN_END":     "Scan concluído",
    "SCAN_ERR":     "Falha no scan",
    "SCAN_OUTPUT":  "Saída de execução",
    "AUTHZ_DENY":   "Acesso negado",
    "LOGPUSH_TEST": "Teste de conexão",
}

# Campos mostrados no chat, na ordem. O resto fica só no log original.
_DETALHE = ("campanha", "ip", "port", "service", "hostname", "domain",
            "asn", "risk", "actor", "src_ip", "action", "outcome")


def _desescapar(v: str) -> str:
    return v.replace('\\"', '"').replace("\\\\", "\\").replace("\\]", "]")


def parse_rfc5424(linha: str, origem: str) -> Mensagem | None:
    """Converte uma linha RFC 5424 em Mensagem. Devolve None se não casar."""
    m = _RE.match((linha or "").strip())
    if not m:
        return None
    campos = {k: _desescapar(v) for k, v in _CAMPO.findall(m.group("sd") or "")}
    try:
        # O syslog grava em UTC (o timestamp termina em Z). Sem converter, um achado
        # das 17h apareceria no chat como 20h e os objetos no S3 ficariam com fusos
        # misturados conforme a origem. A linha ORIGINAL, com o UTC, segue intacta em
        # `texto` — quem indexa no SIEM continua com a marcação precisa.
        quando = (datetime.datetime.strptime(m.group("ts")[:19], "%Y-%m-%dT%H:%M:%S")
                  .replace(tzinfo=datetime.UTC).astimezone().replace(tzinfo=None))
    except ValueError:
        quando = datetime.datetime.now()
    sev = _SEV.get(int(m.group("pri")) % 8, "INFO")
    # O risco declarado no evento manda sobre a severidade do transporte.
    risco = (campos.get("risk") or "").upper()
    if risco in ("CRITICO", "ALTO", "MEDIO", "BAIXO", "INFO"):
        sev = risco
    return Mensagem(origem=origem, texto=linha.rstrip("\n"), quando=quando,
                    severidade=sev, msgid=m.group("msgid"), campos=campos)


def _corpo(m: Mensagem) -> str:
    titulo = _TITULO.get(m.msgid, m.msgid.replace("_", " ").title())
    linhas = [f"{_EMOJI.get(m.severidade, '🔵')} {m.severidade} · {titulo}"]
    detalhes = [f"{k}: {m.campos[k]}" for k in _DETALHE if m.campos.get(k)]
    if detalhes:
        linhas.append(" · ".join(detalhes))
    linhas.append(m.quando.strftime("%d/%m/%Y %H:%M"))
    return "\n".join(linhas)


def para_chat(m: Mensagem, plataforma: str) -> dict:
    """Payload pronto para a plataforma escolhida."""
    texto = _corpo(m)
    p = (plataforma or "google_chat").strip()
    if p == "discord":
        return {"content": texto[:1900]}
    if p == "teams":
        return {"@type": "MessageCard", "@context": "https://schema.org/extensions",
                "summary": "Argus", "text": texto.replace("\n", "\n\n")}
    if p == "telegram":
        return {"text": texto[:4000], "disable_web_page_preview": True}
    if p == "generico":
        return {"origem": m.origem, "severidade": m.severidade, "msgid": m.msgid,
                "quando": m.quando.isoformat(), "campos": m.campos, "texto": texto}
    # google_chat e slack usam o mesmo campo
    return {"text": texto[:3900]}
