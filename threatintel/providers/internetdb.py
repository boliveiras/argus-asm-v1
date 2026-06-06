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
internetdb.py — Provider Shodan InternetDB (gratuito, sem chave)
================================================================

Enriquece um IP com inteligência PASSIVA do Shodan (último crawl), via a API
pública InternetDB — **sem API key**:

Endpoint:
    GET https://internetdb.shodan.io/<ip>      (somente IP; 404 = sem dados)

Resposta (confirmada):
    { "cpes": [...], "hostnames": [...], "ip": "...",
      "ports": [int], "tags": [...], "vulns": ["CVE-...."] }

Papel: ENRIQUECIMENTO por IP (como o AbuseIPDB) — adiciona a dimensão de
**vulnerabilidades (CVE)** que o Argus não tinha. NÃO é descoberta de ativos.

Ressalvas (refletidas no uso):
    - Passivo/histórico: pode estar desatualizado ou não ver o que está atrás de
      firewall que bloqueia o Shodan.
    - vulns vêm de matching CPE/banner do Shodan → podem ter FALSO-POSITIVO;
      são *leads* a validar, por isso a elevação de risco é conservadora.
    - Rate-limit (sem key) → cache em arquivo + cota diária + pausa entre chamadas.
    - Só IP público (RFC1918 é ignorado).

Infra auto-contida (espelha hudsonrock.py / urlscan.py):
    cache em internetdb_cache/ (JSON por IP) + cota diária + degradação graciosa.

Uso:
    from threatintel.providers import internetdb
    intel = internetdb.get_host_intel_safe("1.2.3.4")
    internetdb.enrich_results(scan_results)   # adiciona chave "internetdb" in-place
    risk = internetdb.vuln_elevate(risk, intel)
"""

import datetime
import json
import time
import urllib.error
import urllib.request
from pathlib import Path

from threatintel import CONFIG
from threatintel.core.utils import is_public_ip

# ── Configuração ─────────────────────────────────────────────
_TIMEOUT     = int(CONFIG.get("internetdb_request_timeout", 12))
_DAILY_LIMIT = int(CONFIG.get("internetdb_daily_request_limit", 2000))
_CACHE_TTL   = int(CONFIG.get("internetdb_cache_ttl_hours", 24)) * 3600
_TOP_VULNS   = int(CONFIG.get("internetdb_top_vulns", 30))
_API_URL     = "https://internetdb.shodan.io"
_USER_AGENT  = "argus-monitor/1.0 (+internetdb-enrichment)"

_BASE_DIR   = Path(__file__).resolve().parent.parent
_CACHE_DIR  = _BASE_DIR / "internetdb_cache"
_QUOTA_FILE = _CACHE_DIR / "_quota.json"

_EMPTY = {
    "ip": "", "ports": [], "vulns": [], "vuln_count": 0,
    "cpes": [], "tags": [], "hostnames": [], "seen": False, "source": "N/A",
}

_RANK = {"CRITICO": 0, "ALTO": 1, "MEDIO": 2, "BAIXO": 3, "INFO": 4}


# ============================================================
# HELPERS (cache em arquivo + cota própria)
# ============================================================

def _safe_name(ip: str) -> str:
    return ip.replace("/", "_").replace("\\", "_").replace("*", "_").replace(":", "_").strip(".") or "_"


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

def _fetch(ip: str):
    """Retorna (dict|None, found). found=False quando 404 (sem dados — IP limpo)."""
    if not _can_request():
        print(f"[INTERNETDB] ⚠️  Cota diária esgotada ({_DAILY_LIMIT}) — consulta pulada")
        return None, None
    req = urllib.request.Request(f"{_API_URL}/{ip}", headers={
        "User-Agent": _USER_AGENT, "Accept": "application/json",
    })
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
        _increment()
        return data, True
    except urllib.error.HTTPError as exc:
        _increment()
        if exc.code == 404:
            return None, False        # IP sem dados no Shodan (limpo)
        if exc.code == 429:
            print("[INTERNETDB] ⚠️  Rate limit (HTTP 429)")
        else:
            print(f"[INTERNETDB] HTTP {exc.code} para {ip}")
        return None, None
    except (urllib.error.URLError, json.JSONDecodeError, TimeoutError, ValueError):
        return None, None
    except Exception:
        return None, None


# ============================================================
# PARSING (puro — testável offline)
# ============================================================

def _str_list(arr, cap: int = 0) -> list[str]:
    out = []
    for x in (arr or []):
        s = str(x).strip()
        if s:
            out.append(s[:120])
    if cap:
        out = out[:cap]
    return out


def _int_list(arr) -> list[int]:
    out = []
    for x in (arr or []):
        try:
            out.append(int(x))
        except (TypeError, ValueError):
            pass
    return sorted(set(out))


def _normalize(raw: dict, ip: str) -> dict:
    vulns = sorted(set(_str_list(raw.get("vulns"))))
    return {
        "ip": ip,
        "ports": _int_list(raw.get("ports")),
        "vulns": vulns[:_TOP_VULNS],
        "vuln_count": len(vulns),
        "cpes": _str_list(raw.get("cpes"), 20),
        "tags": _str_list(raw.get("tags"), 20),
        "hostnames": _str_list(raw.get("hostnames"), 10),
        "seen": True,
        "source": "api",
    }


# ============================================================
# API PÚBLICA
# ============================================================

def get_host_intel(ip: str, use_cache: bool = True) -> dict:
    """Intel passiva (ports/vulns/cpes/tags) de um IP. Nunca levanta exceção."""
    ip = (ip or "").strip()
    if not ip or not is_public_ip(ip):
        return {**_EMPTY, "ip": ip, "source": "private"}

    cache_path = _CACHE_DIR / f"{_safe_name(ip)}.json"
    if use_cache:
        cached = _cache_get(cache_path)
        if cached is not None:
            return cached

    raw, found = _fetch(ip)
    if found is False:                         # 404 confirmado: IP sem dados
        intel = {**_EMPTY, "ip": ip, "seen": False, "source": "empty"}
        _cache_put(cache_path, intel)
        return intel
    if raw is None:                            # erro/rate-limit/cota
        return {**_EMPTY, "ip": ip, "source": "error"}

    intel = _normalize(raw, ip)
    _cache_put(cache_path, intel)
    return intel


def get_host_intel_safe(ip: str) -> dict:
    try:
        return get_host_intel(ip)
    except Exception:
        return {**_EMPTY, "ip": ip, "source": "error"}


def enrich_results(results: list[dict]) -> None:
    """Adiciona a chave 'internetdb' a cada resultado (in-place), por IP público
    único. Nunca levanta exceção."""
    unique_public = {r.get("ip", "") for r in results if is_public_ip(r.get("ip", ""))}
    total = len(unique_public)
    if total == 0:
        print("[INTERNETDB] Nenhum IP público para enriquecer (Shodan InternetDB)")
        return
    api_count = sum(1 for ip in unique_public
                    if _cache_get(_CACHE_DIR / f"{_safe_name(ip)}.json") is None)
    print(f"[INTERNETDB] {total} IPs únicos — {api_count} novas consultas, "
          f"{total - api_count} do cache (Shodan InternetDB)")

    cache: dict[str, dict] = {}
    for ip in unique_public:
        cache[ip] = get_host_intel(ip)
        if cache[ip].get("source") == "api":
            time.sleep(0.25)        # cortesia com a API gratuita

    empty = {**_EMPTY, "source": "private"}
    vuln_ips = 0
    for r in results:
        intel = cache.get(r.get("ip", ""), empty)
        r["internetdb"] = intel
        if intel.get("vuln_count", 0):
            vuln_ips += 1
    if vuln_ips:
        print(f"[INTERNETDB] {vuln_ips} resultado(s) com CVE conhecida (Shodan)")


def vuln_elevate(risk: str, intel: dict | None) -> str:
    """Elevação CONSERVADORA por vulnerabilidade conhecida (InternetDB):
    IP com ≥1 CVE → risco no MÍNIMO ALTO. Não força CRÍTICO sozinho (o matching
    do Shodan é heurístico). Combinado a porta crítica/abuso, o risco já chega a
    CRÍTICO por outras camadas."""
    if intel and intel.get("vuln_count", 0) >= 1:
        if _RANK.get(risk, 3) > _RANK["ALTO"]:
            return "ALTO"
    return risk
