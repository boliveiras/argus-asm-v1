# Argus — monitoramento de superfície de ataque
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
crtsh.py — Provider de Certificate Transparency (crt.sh)
=========================================================

Consulta o crt.sh para descobrir subdomínios de um domínio através dos
certificados SSL/TLS já emitidos (Certificate Transparency logs).

Diferente da enumeração ativa por wordlist, esta é uma técnica PASSIVA:
revela subdomínios reais que já existiram, sem precisar adivinhar nomes.

Uso:
    from threatintel.providers.crtsh import get_subdomains
    subs = get_subdomains("empresa.com.br")
    # → {"api.empresa.com.br", "vpn.empresa.com.br", ...}

Características:
    - Sem chave de API (serviço público)
    - Cache local em JSON por domínio (evita reconsultas no mesmo dia)
    - Normaliza wildcards (*.x.com → x.com) e remove duplicatas
    - Tolerante a falhas: se o crt.sh estiver lento/fora, retorna vazio
      sem quebrar o scan (degradação graciosa)
"""

import json
import os
import time
import urllib.request
import urllib.error
from pathlib import Path

# ── Configuração ─────────────────────────────────────────────
CRTSH_URL          = "https://crt.sh/?q=%25.{domain}&output=json"
REQUEST_TIMEOUT    = 30          # crt.sh às vezes é lento
CACHE_TTL_SECONDS  = 6 * 3600    # 6 horas
CACHE_DIR_NAME     = "crtsh_cache"
USER_AGENT         = "argus-monitor/1.0 (+ct-discovery)"

# Diretório de cache: ao lado deste arquivo, em ../<CACHE_DIR_NAME>
_BASE_DIR  = Path(__file__).resolve().parent.parent
_CACHE_DIR = _BASE_DIR / CACHE_DIR_NAME


def _ensure_cache_dir() -> None:
    try:
        _CACHE_DIR.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass


def _cache_path(domain: str) -> Path:
    safe = domain.replace("/", "_").replace("\\", "_").replace("*", "_")
    return _CACHE_DIR / f"{safe}.json"


def _read_cache(domain: str) -> set[str] | None:
    """Retorna subdomínios do cache se válido, senão None."""
    path = _cache_path(domain)
    try:
        if not path.exists():
            return None
        age = time.time() - path.stat().st_mtime
        if age > CACHE_TTL_SECONDS:
            return None
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return set(data.get("subdomains", []))
    except Exception:
        return None


def _write_cache(domain: str, subs: set[str]) -> None:
    _ensure_cache_dir()
    path = _cache_path(domain)
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"domain": domain,
                       "fetched_at": int(time.time()),
                       "subdomains": sorted(subs)}, f, indent=2)
    except Exception:
        pass


def _normalize_name(name: str, base_domain: str) -> list[str]:
    """
    Normaliza um nome retornado pelo crt.sh.
    O campo name_value pode conter múltiplas linhas e wildcards.
    Retorna lista de hostnames limpos pertencentes ao domínio base.
    """
    out = []
    for raw in name.split("\n"):
        host = raw.strip().lower().rstrip(".")
        if not host:
            continue
        # Remove wildcard: *.empresa.com.br → empresa.com.br
        if host.startswith("*."):
            host = host[2:]
        # Ignora e-mails (alguns certs trazem SAN de e-mail)
        if "@" in host:
            continue
        # Só aceita hostnames realmente dentro do domínio base
        if host == base_domain or host.endswith("." + base_domain):
            out.append(host)
    return out


def get_subdomains(domain: str, use_cache: bool = True) -> set[str]:
    """
    Consulta o crt.sh e retorna o conjunto de subdomínios descobertos
    para o domínio informado (incluindo o próprio domínio se aparecer).

    Em caso de erro de rede/timeout, retorna conjunto vazio (não levanta).
    """
    domain = domain.strip().lower().rstrip(".")
    if not domain:
        return set()

    # 1. Tenta cache
    if use_cache:
        cached = _read_cache(domain)
        if cached is not None:
            return cached

    # 2. Consulta crt.sh
    url = CRTSH_URL.format(domain=domain)
    subs: set[str] = set()
    try:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:  # nosec B310 - scheme https:// fixo (base URL constante)
            raw = resp.read().decode("utf-8", errors="replace")
        # crt.sh retorna um array JSON de objetos
        entries = json.loads(raw)
        for entry in entries:
            name_value = entry.get("name_value", "")
            common_name = entry.get("common_name", "")
            for src in (name_value, common_name):
                if src:
                    subs.update(_normalize_name(src, domain))
    except (urllib.error.URLError, urllib.error.HTTPError,
            json.JSONDecodeError, TimeoutError, ValueError):
        # Degradação graciosa — retorna o que tiver (vazio)
        return set()
    except Exception:
        return set()

    # 3. Grava cache
    if subs:
        _write_cache(domain, subs)
    return subs


def get_subdomains_safe(domain: str) -> set[str]:
    """Wrapper que nunca levanta exceção. Uso conveniente no orquestrador."""
    try:
        return get_subdomains(domain)
    except Exception:
        return set()
