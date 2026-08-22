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
providers.py — Fontes de inteligência: liga/desliga e chaves de API
====================================================================

Tudo o que antes era perguntado na instalação passa a ser configurável na Web:
cada fonte pode ser **ligada ou desligada** e, quando exige credencial, a chave é
informada aqui. Assim quem opera decide o que usar em cada rodada, sem reinstalar.

Onde fica: `threatintel/config.json` (o mesmo que os scanners já leem).

Postura de segurança:
  • A chave NUNCA volta inteira numa resposta da API — só um resumo mascarado
    (`••••1234`) e o indicador de "configurada". Quem tem acesso ao servidor lê o
    arquivo; a interface não serve de canal para exfiltrar credencial.
  • Gravação IN-PLACE (mesmo inode): o serviço precisa de permissão apenas NESTE
    arquivo, e não de criar arquivos no diretório do threatintel (que guarda cache
    e bancos). Preserva também a ACL e o dono (root:app 640).
  • Chave em ALLOWLIST de caracteres — nada de espaço/quebra de linha, que
    corromperiam o JSON ou vazariam para um cabeçalho HTTP.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

PLACEHOLDER = "SUA_API_KEY_AQUI"          # valor de fábrica = "não configurada"
_KEY_RE = re.compile(r"^[A-Za-z0-9._\-]{8,128}$")

# Catálogo das fontes. `key` = campo da chave no config.json (None = não exige).
# `enabled_field` = campo do liga/desliga. `needs_key` diz se a fonte só funciona
# com credencial (sem ela, fica indisponível mesmo se ligada).
CATALOG: list[dict] = [
    {"id": "abuseipdb", "label": "AbuseIPDB", "key": "abuseipdb_api_key",
     "needs_key": True, "free": "1.000 consultas/dia no plano gratuito",
     "what": "Reputação de IP: denúncias de abuso, saída TOR, país e provedor.",
     "used_by": "Portas · Subdomínios", "signup": "https://www.abuseipdb.com/register"},
    {"id": "virustotal", "label": "VirusTotal", "key": "virustotal_api_key",
     "needs_key": True, "free": "500 consultas/dia · 4 por minuto no plano gratuito",
     "what": "Veredito de antivírus e reputação de IP/domínio agregando dezenas de fontes.",
     "used_by": "Portas · Subdomínios", "signup": "https://www.virustotal.com/gui/join-us"},
    {"id": "urlscan", "label": "urlscan.io", "key": "urlscan_api_key",
     "needs_key": True, "free": "chave gratuita; sem ela, a descoberta passiva é limitada",
     "what": "Descoberta passiva de subdomínios e histórico de varreduras públicas.",
     "used_by": "Subdomínios", "signup": "https://urlscan.io/user/signup"},
    {"id": "nvd", "label": "NVD (NIST)", "key": "nvd_api_key",
     "needs_key": False, "free": "funciona sem chave; com chave o limite sobe de 5 para 50 req/30s",
     "what": "Nota CVSS oficial de cada CVE encontrada.",
     "used_by": "Portas · Subdomínios", "signup": "https://nvd.nist.gov/developers/request-an-api-key"},
    {"id": "cisa_kev", "label": "CISA KEV", "key": None,
     "needs_key": False, "free": "catálogo público, sem cadastro",
     "what": "Marca CVEs com exploração confirmada in-the-wild (eleva para crítico).",
     "used_by": "Portas · Subdomínios", "signup": ""},
    {"id": "internetdb", "label": "Shodan InternetDB", "key": None,
     "needs_key": False, "free": "API pública e gratuita, sem cadastro",
     "what": "CVEs conhecidas, portas e tags do ativo.",
     "used_by": "Portas · Subdomínios", "signup": ""},
    {"id": "hudsonrock", "label": "Hudson Rock", "key": None,
     "needs_key": False, "free": "API pública e gratuita",
     "what": "Credenciais expostas em logs de infostealer.",
     "used_by": "Credenciais", "signup": ""},
    {"id": "crtsh", "label": "crt.sh (Certificate Transparency)", "key": None,
     "needs_key": False, "free": "consulta pública, sem cadastro",
     "what": "Subdomínios revelados por certificados TLS emitidos.",
     "used_by": "Subdomínios", "signup": ""},
    {"id": "crtname", "label": "crt.name (Certificate Transparency)", "key": None,
     "needs_key": False, "free": "consulta pública, sem cadastro",
     "what": "Subdomínios em certificados TLS — fonte independente do crt.sh, cobre lacunas.",
     "used_by": "Subdomínios", "signup": ""},
    {"id": "whois", "label": "RDAP / WHOIS", "key": None,
     "needs_key": False, "free": "consulta pública, sem cadastro",
     "what": "Idade e dados de registro do domínio (apoia typosquat e triagem).",
     "used_by": "Subdomínios · Typosquat", "signup": ""},
]
BY_ID = {p["id"]: p for p in CATALOG}


class ProviderError(ValueError):
    """Erro de uso (fonte desconhecida, chave inválida)."""


def config_path() -> Path:
    base = os.environ.get("ARGUS_BASE", "")
    if not base:
        db = os.environ.get("ARGUS_DB", "")
        if db:
            p = Path(db).resolve().parent
            base = str(p.parent if p.name == "store" else p)
        else:
            base = "/etc/argus"
    return Path(os.environ.get("ARGUS_TI_CONFIG", str(Path(base) / "threatintel" / "config.json")))


def _read_config() -> dict:
    try:
        data = json.loads(config_path().read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _write_config(cfg: dict) -> None:
    """Grava IN-PLACE (ver docstring do módulo: permissão só no arquivo).
    Restaura o conteúdo anterior se a escrita falhar no meio."""
    path = config_path()
    body = json.dumps(cfg, ensure_ascii=False, indent=4) + "\n"
    try:
        previous = path.read_text(encoding="utf-8") if path.exists() else ""
    except OSError:
        previous = ""
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(body)
            fh.flush()
            os.fsync(fh.fileno())
    except Exception:
        if previous:
            try:
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write(previous)
                    fh.flush()
                    os.fsync(fh.fileno())
            except OSError:
                pass
        raise


def _enabled_field(pid: str) -> str:
    return f"{pid}_enabled"


def has_key(cfg: dict, prov: dict) -> bool:
    if not prov["key"]:
        return True
    v = str(cfg.get(prov["key"], "") or "").strip()
    return bool(v) and v != PLACEHOLDER


def mask(value: str) -> str:
    """Resumo seguro da chave — nunca devolve o valor real."""
    v = str(value or "").strip()
    if not v or v == PLACEHOLDER:
        return ""
    return "•" * 8 + v[-4:] if len(v) > 4 else "•" * 8


def is_enabled(pid: str, cfg: dict | None = None) -> bool:
    """Fonte ativa? Ligada por padrão; se exige chave e não tem, fica inativa."""
    prov = BY_ID.get(pid)
    if not prov:
        return False
    cfg = _read_config() if cfg is None else cfg
    if not bool(cfg.get(_enabled_field(pid), True)):
        return False
    return has_key(cfg, prov) if prov["needs_key"] else True


def list_providers() -> list[dict]:
    """Catálogo + estado atual (sem expor chave)."""
    cfg = _read_config()
    out = []
    for prov in CATALOG:
        keyed = has_key(cfg, prov)
        on = bool(cfg.get(_enabled_field(prov["id"]), True))
        out.append({
            "id": prov["id"], "label": prov["label"], "what": prov["what"],
            "used_by": prov["used_by"], "free": prov["free"], "signup": prov["signup"],
            "requires_key": bool(prov["key"]), "needs_key": prov["needs_key"],
            "has_key": keyed if prov["key"] else False,
            "key_hint": mask(cfg.get(prov["key"], "")) if prov["key"] else "",
            "enabled": on,
            "active": on and (keyed if prov["needs_key"] else True),
            "blocked_reason": ("chave não configurada" if (on and prov["needs_key"] and not keyed) else ""),
        })
    return out


def set_enabled(pid: str, enabled: bool) -> dict:
    if pid not in BY_ID:
        raise ProviderError(f"fonte desconhecida: {pid}")
    cfg = _read_config()
    cfg[_enabled_field(pid)] = bool(enabled)
    _write_config(cfg)
    return {"id": pid, "enabled": bool(enabled), "active": is_enabled(pid, cfg)}


def set_key(pid: str, key: str) -> dict:
    """Define (ou remove, com string vazia) a chave da fonte."""
    prov = BY_ID.get(pid)
    if not prov:
        raise ProviderError(f"fonte desconhecida: {pid}")
    if not prov["key"]:
        raise ProviderError(f"{prov['label']} não usa chave de API")
    value = str(key or "").strip()
    cfg = _read_config()
    if not value:                                   # remover a chave
        cfg[prov["key"]] = PLACEHOLDER
    else:
        if not _KEY_RE.match(value):
            raise ProviderError("chave inválida: use de 8 a 128 caracteres, sem espaços "
                                "(letras, números, ponto, hífen ou underscore)")
        cfg[prov["key"]] = value
    _write_config(cfg)
    return {"id": pid, "has_key": has_key(cfg, prov),
            "key_hint": mask(cfg.get(prov["key"], "")), "active": is_enabled(pid, cfg)}
