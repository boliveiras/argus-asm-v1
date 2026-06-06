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
hudsonrock.py — Provider Hudson Rock (Cavalier OSINT, gratuito)
================================================================

Consulta a exposição de um domínio em **logs de infostealer** via a API pública
(gratuita, sem chave) do Hudson Rock Cavalier. Retorna AGREGADOS por domínio —
nunca credenciais em si — o que mantém o módulo "metadata-only".

Endpoint:
    GET /api/json/v2/osint-tools/search-by-domain?domain=<domínio>

Campos relevantes da resposta (domínio-específicos):
    total          — total de entidades comprometidas (employees+users+third_parties)
    employees      — máquinas de FUNCIONÁRIOS comprometidas (acesso interno)
    users          — credenciais de USUÁRIOS/clientes comprometidas (ATO)
    third_parties  — terceiros
    data.employees_urls / data.clients_urls / data.third_parties_urls
                   — [{occurrence, type, url}] = quais aplicações da org aparecem

(`totalStealers` é o tamanho GLOBAL da base do Hudson Rock — ignorado de propósito.)

Infra (auto-contida, espelha urlscan.py):
    - timeout / limite diário / TTL de cache lidos do config.json
    - cache em arquivo JSON (hudsonrock_cache/) + cota diária própria
    - degradação graciosa: qualquer falha retorna vazio sem quebrar

Uso:
    from threatintel.providers import hudsonrock
    intel = hudsonrock.get_domain_exposure_safe("empresa.com.br")
"""

import datetime
import json
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from threatintel import CONFIG

# ── Configuração ─────────────────────────────────────────────
_TIMEOUT     = int(CONFIG.get("hudsonrock_request_timeout", 25))
_DAILY_LIMIT = int(CONFIG.get("hudsonrock_daily_request_limit", 300))
_CACHE_TTL   = int(CONFIG.get("hudsonrock_cache_ttl_hours", 24)) * 3600
_TOP_URLS    = int(CONFIG.get("hudsonrock_top_urls", 12))
_API_URL     = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain"
_USER_AGENT  = "argus-monitor/1.0 (+infostealer-exposure)"

_BASE_DIR   = Path(__file__).resolve().parent.parent
_CACHE_DIR  = _BASE_DIR / "hudsonrock_cache"
_QUOTA_FILE = _CACHE_DIR / "_quota.json"

_EMPTY = {
    "domain": "", "total": 0, "employees": 0, "users": 0, "third_parties": 0,
    "employees_urls": [], "clients_urls": [], "third_parties_urls": [],
    "logo": "", "seen": False, "source": "N/A",
}


# ============================================================
# HELPERS (cache em arquivo + cota própria)
# ============================================================

def _safe_int(v, d: int = 0) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return d


def _safe_name(s: str) -> str:
    return s.replace("/", "_").replace("\\", "_").replace("*", "_").strip(".") or "_"


def _ensure_dir() -> None:
    try:
        _CACHE_DIR.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass


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
    _ensure_dir()
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f)
    except Exception:
        pass


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
    _ensure_dir()
    d = _quota_read()
    d["count"] = int(d.get("count", 0)) + 1
    try:
        with open(_QUOTA_FILE, "w", encoding="utf-8") as f:
            json.dump(d, f)
    except Exception:
        pass


# ============================================================
# CHAMADA À API
# ============================================================

def _fetch(domain: str) -> dict | None:
    if not _can_request():
        print(f"[HUDSONROCK] ⚠️  Cota diária esgotada ({_DAILY_LIMIT}) — consulta pulada")
        return None
    url = f"{_API_URL}?{urllib.parse.urlencode({'domain': domain})}"
    req = urllib.request.Request(url, headers={
        "User-Agent": _USER_AGENT, "Accept": "application/json",
    })
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
        _increment()
        return data
    except urllib.error.HTTPError as exc:
        if exc.code == 429:
            print("[HUDSONROCK] ⚠️  Rate limit (HTTP 429)")
        else:
            print(f"[HUDSONROCK] HTTP {exc.code} para {domain}")
        return None
    except (urllib.error.URLError, json.JSONDecodeError, TimeoutError, ValueError):
        return None
    except Exception:
        return None


# ============================================================
# PARSING (puro — testável offline)
# ============================================================

def _top_urls(arr) -> list[dict]:
    """Normaliza e ordena por ocorrência os URLs comprometidos (top N)."""
    out = []
    for item in (arr or []):
        if not isinstance(item, dict):
            continue
        out.append({
            "url": str(item.get("url", "") or "")[:300],
            "occurrence": _safe_int(item.get("occurrence"), 0),
            "type": str(item.get("type", "") or ""),
        })
    out.sort(key=lambda x: x["occurrence"], reverse=True)
    return out[:_TOP_URLS]


def _normalize(raw: dict, domain: str) -> dict:
    d = raw.get("data", {}) or {}
    employees     = _safe_int(raw.get("employees"))
    users         = _safe_int(raw.get("users"))
    third_parties = _safe_int(raw.get("third_parties"))
    total         = _safe_int(raw.get("total"), employees + users + third_parties)
    return {
        "domain": domain,
        "total": total,
        "employees": employees,
        "users": users,
        "third_parties": third_parties,
        "employees_urls":     _top_urls(d.get("employees_urls")),
        "clients_urls":       _top_urls(d.get("clients_urls")),
        "third_parties_urls": _top_urls(d.get("third_parties_urls")),
        "logo": str(raw.get("logo", "") or ""),
        "seen": total > 0,
        "source": "api",
    }


# ============================================================
# API PÚBLICA
# ============================================================

def get_domain_exposure(domain: str, use_cache: bool = True) -> dict:
    """Exposição do domínio em infostealer logs (agregado). Nunca levanta."""
    domain = (domain or "").strip().lower().rstrip(".")
    if not domain:
        return {**_EMPTY}

    cache_path = _CACHE_DIR / f"{_safe_name(domain)}.json"
    if use_cache:
        cached = _cache_get(cache_path)
        if cached is not None:
            return cached

    raw = _fetch(domain)
    if raw is None:
        return {**_EMPTY, "domain": domain, "source": "error"}

    intel = _normalize(raw, domain)
    _cache_put(cache_path, intel)
    return intel


def get_domain_exposure_safe(domain: str) -> dict:
    """Wrapper que nunca levanta exceção."""
    try:
        return get_domain_exposure(domain)
    except Exception:
        return {**_EMPTY, "domain": domain, "source": "error"}


def classify_risk(intel: dict) -> str:
    """
    Classifica o risco de credencial a partir da exposição em infostealer.
      - funcionário comprometido  → CRITICO (acesso interno direto)
      - usuário/cliente exposto    → ALTO    (account takeover)
      - apenas terceiros           → MEDIO
      - nada                       → BAIXO
    """
    if _safe_int(intel.get("employees")) > 0:
        return "CRITICO"
    if _safe_int(intel.get("users")) > 0:
        return "ALTO"
    if _safe_int(intel.get("third_parties")) > 0:
        return "MEDIO"
    return "BAIXO"
