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
urlscan.py — Provider urlscan.io (Search API, PASSIVO)
=======================================================

Usa exclusivamente a **Search API** do urlscan.io (consulta de scans históricos).
NÃO submete URLs para varredura ao vivo — isso evita expor publicamente o
inventário de ativos do alvo (submissões são públicas por padrão no urlscan).

Capacidades:
  1. get_subdomains(domain)  → descoberta passiva de subdomínios já vistos pelo
     urlscan (complementa o crt.sh). Origem "urlscan" no submonitor.
  2. enrich_results(results) → para cada host ativo, anexa contexto do último
     scan conhecido: servidor, IP, ASN, país, título, UUID + URLs de
     screenshot/relatório. Chave "urlscan" em cada dict.

Infra (auto-contida, espelha o padrão dos outros providers):
  - API key, timeout, limite diário e TTL de cache lidos do config.json
  - Cache em arquivos JSON (urlscan_cache/) com TTL
  - Controle de cota diária próprio (não mistura com o contador do AbuseIPDB)
  - Degradação graciosa: qualquer falha de rede/cota retorna vazio sem quebrar

Uso:
    from threatintel.providers import urlscan
    subs  = urlscan.get_subdomains_safe("empresa.com.br")
    urlscan.enrich_results(scan_results)   # adiciona "urlscan" in-place
"""

import datetime
import json
import time
from pathlib import Path

import requests

from threatintel import CONFIG

# ── Configuração ─────────────────────────────────────────────
_API_KEY      = CONFIG.get("urlscan_api_key", "")
_TIMEOUT      = int(CONFIG.get("urlscan_request_timeout", 15))
_DAILY_LIMIT  = int(CONFIG.get("urlscan_daily_request_limit", 1000))
_CACHE_TTL    = int(CONFIG.get("urlscan_cache_ttl_hours", 336)) * 3600  # padrão 14 dias
_SEARCH_URL   = "https://urlscan.io/api/v1/search/"
_USER_AGENT   = "argus-monitor/1.0 (+urlscan-passive)"

# Diretórios de cache (ao lado dos outros caches do threatintel)
_BASE_DIR    = Path(__file__).resolve().parent.parent
_CACHE_DIR   = _BASE_DIR / "urlscan_cache"
_DISC_DIR    = _CACHE_DIR / "disc"   # descoberta por domínio
_HOST_DIR    = _CACHE_DIR / "host"   # intel por hostname
_QUOTA_FILE  = _CACHE_DIR / "_quota.json"

_EMPTY_HOST = {
    "seen": False, "last_scan": "", "ip": "", "asn": "", "asnname": "",
    "server": "", "country": "", "title": "", "scan_uuid": "",
    "report_url": "", "screenshot": "", "source": "N/A",
}


# ============================================================
# HELPERS
# ============================================================

def _has_key() -> bool:
    return bool(_API_KEY) and _API_KEY != "SUA_API_KEY_AQUI"


def _safe_name(s: str) -> str:
    return s.replace("/", "_").replace("\\", "_").replace("*", "_").replace(":", "_").strip(".") or "_"


def _ensure_dirs() -> None:
    for d in (_DISC_DIR, _HOST_DIR):
        try:
            d.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass


# ── Cache em arquivo (TTL por mtime) ─────────────────────────

def _cache_get(path: Path):
    try:
        if not path.exists():
            return None
        if time.time() - path.stat().st_mtime > _CACHE_TTL:
            return None
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def _cache_put(path: Path, data) -> None:
    _ensure_dirs()
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f)
    except Exception:
        pass


# ── Cota diária própria ──────────────────────────────────────

def _today() -> str:
    return datetime.date.today().isoformat()


def _quota_read() -> dict:
    try:
        with open(_QUOTA_FILE, encoding="utf-8") as f:
            d = json.load(f)
        if d.get("day") == _today():
            return d
    except Exception:
        pass
    return {"day": _today(), "count": 0}


def _can_request() -> bool:
    return _quota_read().get("count", 0) < _DAILY_LIMIT


def _increment() -> None:
    _ensure_dirs()
    d = _quota_read()
    d["count"] = int(d.get("count", 0)) + 1
    try:
        with open(_QUOTA_FILE, "w", encoding="utf-8") as f:
            json.dump(d, f)
    except Exception:
        pass


# ============================================================
# CHAMADA À API (Search)
# ============================================================

def _search(query: str, size: int = 100) -> dict | None:
    """GET na Search API. Retorna o JSON ou None. Nunca levanta."""
    if not _has_key():
        return None
    if not _can_request():
        print(f"[URLSCAN] ⚠️  Cota diária esgotada ({_DAILY_LIMIT}) — consulta pulada")
        return None
    headers = {
        "User-Agent": _USER_AGENT,
        "API-Key": _API_KEY,
        "Accept": "application/json",
    }
    try:
        resp = requests.get(_SEARCH_URL, headers=headers,
                            params={"q": query, "size": size}, timeout=_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
        _increment()
        return data
    except requests.exceptions.HTTPError as exc:
        code = exc.response.status_code if exc.response is not None else None
        if code == 429:
            print("[URLSCAN] ⚠️  Rate limit (HTTP 429)")
        elif code == 401:
            print("[URLSCAN] ❌ API key inválida (HTTP 401)")
        return None
    except (requests.exceptions.RequestException, json.JSONDecodeError, ValueError):
        return None
    except Exception:
        return None


# ============================================================
# PARSING (puro — testável offline)
# ============================================================

def _extract_subdomains(data: dict, base_domain: str) -> set[str]:
    """Extrai hostnames dentro do domínio base a partir de um JSON de busca."""
    base = base_domain.strip().lower().rstrip(".")
    out: set[str] = set()
    for hit in (data or {}).get("results", []) or []:
        for src in (hit.get("page", {}) or {}, hit.get("task", {}) or {}):
            host = str(src.get("domain", "")).strip().lower().rstrip(".")
            if not host:
                continue
            if host == base or host.endswith("." + base):
                out.add(host)
    return out


def _hit_to_intel(hit: dict) -> dict:
    """Converte um resultado de busca no dict de intel por host."""
    page = hit.get("page", {}) or {}
    task = hit.get("task", {}) or {}
    uuid = hit.get("_id") or task.get("uuid") or ""
    return {
        "seen":       True,
        "last_scan":  str(task.get("time", "") or ""),
        "ip":         str(page.get("ip", "") or ""),
        "asn":        str(page.get("asn", "") or ""),
        "asnname":    str(page.get("asnname", "") or ""),
        "server":     str(page.get("server", "") or ""),
        "country":    str(page.get("country", "") or ""),
        "title":      str(page.get("title", "") or "")[:120],
        "scan_uuid":  str(uuid),
        "report_url": f"https://urlscan.io/result/{uuid}/" if uuid else "",
        "screenshot": f"https://urlscan.io/screenshots/{uuid}.png" if uuid else "",
        "source":     "api",
    }


# ============================================================
# API PÚBLICA
# ============================================================

def get_subdomains(domain: str, use_cache: bool = True) -> set[str]:
    """Descoberta passiva de subdomínios via urlscan. Conjunto (pode ser vazio)."""
    domain = (domain or "").strip().lower().rstrip(".")
    if not domain or not _has_key():
        return set()

    cache_path = _DISC_DIR / f"{_safe_name(domain)}.json"
    if use_cache:
        cached = _cache_get(cache_path)
        if cached is not None:
            return set(cached.get("subdomains", []))

    data = _search(f"domain:{domain}", size=100)
    if data is None:
        return set()
    subs = _extract_subdomains(data, domain)
    _cache_put(cache_path, {"domain": domain, "fetched_at": int(time.time()),
                            "subdomains": sorted(subs)})
    return subs


def get_subdomains_safe(domain: str) -> set[str]:
    """Wrapper que nunca levanta exceção."""
    try:
        return get_subdomains(domain)
    except Exception:
        return set()


def get_host_intel(hostname: str, use_cache: bool = True) -> dict:
    """Contexto do último scan urlscan conhecido para um hostname."""
    hostname = (hostname or "").strip().lower().rstrip(".")
    if not hostname or not _has_key():
        return {**_EMPTY_HOST, "source": "no_api_key" if not _has_key() else "N/A"}

    cache_path = _HOST_DIR / f"{_safe_name(hostname)}.json"
    if use_cache:
        cached = _cache_get(cache_path)
        if cached is not None:
            return cached

    data = _search(f"page.domain:{hostname}", size=1)
    if data is None:
        return {**_EMPTY_HOST, "source": "error"}

    results = data.get("results", []) or []
    intel = _hit_to_intel(results[0]) if results else {**_EMPTY_HOST, "source": "not_found"}
    _cache_put(cache_path, intel)
    return intel


def enrich_results(results: list[dict]) -> None:
    """
    Adiciona a chave "urlscan" a cada resultado de subdomínio (in-place).
    Consulta uma vez por hostname único; nunca levanta exceção.
    """
    if not _has_key():
        for r in results:
            r["urlscan"] = {**_EMPTY_HOST, "source": "no_api_key"}
        print("[URLSCAN] API key não configurada — enriquecimento desativado")
        return

    unique_hosts = sorted({r.get("hostname", "") for r in results if r.get("hostname")})
    print(f"[URLSCAN] Enriquecendo {len(unique_hosts)} host(s) único(s) "
          f"(cache TTL {_CACHE_TTL // 3600}h)...")

    cache_local: dict[str, dict] = {}
    for host in unique_hosts:
        cache_local[host] = get_host_intel(host)
        if cache_local[host].get("source") == "api":
            time.sleep(0.3)  # cortesia com a API em lotes grandes

    seen = sum(1 for v in cache_local.values() if v.get("seen"))
    print(f"[URLSCAN] {seen}/{len(unique_hosts)} host(s) com histórico no urlscan")

    for r in results:
        r["urlscan"] = cache_local.get(r.get("hostname", ""), {**_EMPTY_HOST})
