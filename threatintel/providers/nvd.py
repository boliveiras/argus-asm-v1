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
nvd.py — Provider NVD (National Vulnerability Database) — CVSS por CVE
=====================================================================

Enriquece as CVEs já DESCOBERTAS pelo InternetDB (r['internetdb']['vulns']) com a
informação OFICIAL da NVD/NIST: **CVSS base score + severidade + descrição**.

Diferente dos outros:
  - InternetDB diz QUAIS CVEs existem por IP (sem severidade).
  - CISA KEV diz QUAIS dessas estão sendo exploradas in-the-wild.
  - NVD diz O QUÃO GRAVE cada CVE é (CVSS), de forma autoritativa.

Endpoint (NVD API 2.0):
    GET https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-XXXX-YYYY
    Header opcional: apiKey: <key>  (eleva o rate-limit: 5→50 req/30s)

A API key NÃO é obrigatória, mas sem ela o rate-limit é baixo (5 req/30s) — por
isso há pausa entre chamadas + cache longo (CVE é praticamente imutável). A key
fica no config.json (igual AbuseIPDB/urlscan); placeholder = "SUA_API_KEY_AQUI".

Infra auto-contida (espelha internetdb.py): cache por CVE em nvd_cache/ + cota
diária + degradação graciosa (em qualquer falha, simplesmente não enriquece).

Uso:
    from threatintel.providers import nvd
    nvd.enrich_results(scan_results)            # anexa "nvd" a cada result
    risk = nvd.nvd_elevate(risk, r.get("nvd"))  # eleva por CVSS (configurável)
"""

import datetime
import json
import re
import time
import urllib.error
import urllib.request
from pathlib import Path

from threatintel import CONFIG

# ── Configuração ─────────────────────────────────────────────
_API_KEY      = str(CONFIG.get("nvd_api_key", "") or "").strip()
_HAS_KEY      = bool(_API_KEY) and _API_KEY != "SUA_API_KEY_AQUI"
_TIMEOUT      = int(CONFIG.get("nvd_request_timeout", 20))
_DAILY_LIMIT  = int(CONFIG.get("nvd_daily_request_limit", 1000))
_CACHE_TTL    = int(CONFIG.get("nvd_cache_ttl_hours", 168)) * 3600
_TOP_CVES     = int(CONFIG.get("nvd_top_cves", 30))
_CVSS_CRIT    = float(CONFIG.get("nvd_cvss_critico", 9.0))
_CVSS_ALTO    = float(CONFIG.get("nvd_cvss_alto", 7.0))
# Sem key o limite é 5 req/30s (~6s); com key 50 req/30s (~0.6s). Cortesia.
_DELAY        = 0.7 if _HAS_KEY else 6.0
_API_URL      = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_USER_AGENT   = "argus-monitor/1.0 (+nvd-enrichment)"

_BASE_DIR   = Path(__file__).resolve().parent.parent
_CACHE_DIR  = _BASE_DIR / "nvd_cache"
_QUOTA_FILE = _CACHE_DIR / "_quota.json"

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_RANK   = {"CRITICO": 0, "ALTO": 1, "MEDIO": 2, "BAIXO": 3, "INFO": 4}

_EMPTY_CVE = {"cve": "", "cvss": 0.0, "severity": "INFO", "vector": "",
              "description": "", "source": "N/A"}


# ============================================================
# HELPERS (cache em arquivo + cota própria — espelha internetdb.py)
# ============================================================

def _safe_name(cve: str) -> str:
    return re.sub(r"[^A-Za-z0-9_-]", "_", cve).strip("_") or "_"


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

def _fetch(cve: str):
    """Retorna o JSON cru da NVD para um CVE, ou None em qualquer falha."""
    if not _can_request():
        print(f"[NVD] ⚠️  Cota diária esgotada ({_DAILY_LIMIT}) — consulta pulada")
        return None
    headers = {"User-Agent": _USER_AGENT, "Accept": "application/json"}
    if _HAS_KEY:
        headers["apiKey"] = _API_KEY
    req = urllib.request.Request(f"{_API_URL}?cveId={cve}", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
        _increment()
        return data
    except urllib.error.HTTPError as exc:
        _increment()
        if exc.code == 404:
            return {"vulnerabilities": []}     # CVE não encontrada na NVD
        if exc.code in (403, 429):
            print(f"[NVD] ⚠️  Rate limit (HTTP {exc.code}) — considere a API key")
        else:
            print(f"[NVD] HTTP {exc.code} para {cve}")
        return None
    except (urllib.error.URLError, json.JSONDecodeError, TimeoutError, ValueError):
        return None
    except Exception:
        return None


# ============================================================
# PARSING (puro — testável offline)
# ============================================================

def _severity_from_score(score: float) -> str:
    """CVSS base score -> severidade no vocabulário do Argus."""
    if score >= _CVSS_CRIT:
        return "CRITICO"
    if score >= _CVSS_ALTO:
        return "ALTO"
    if score >= 4.0:
        return "MEDIO"
    if score > 0.0:
        return "BAIXO"
    return "INFO"


def parse_cve(data: dict, cve: str) -> dict:
    """JSON da NVD 2.0 -> {cve, cvss, severity, vector, description}.
    Preferência de métrica: CVSS v3.1 > v3.0 > v2."""
    vulns = (data or {}).get("vulnerabilities") or []
    if not vulns:
        return {**_EMPTY_CVE, "cve": cve, "source": "empty"}
    node = (vulns[0] or {}).get("cve") or {}
    metrics = node.get("metrics") or {}
    cvss, vector = 0.0, ""
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        arr = metrics.get(key) or []
        if arr:
            cd = (arr[0] or {}).get("cvssData") or {}
            try:
                cvss = float(cd.get("baseScore", 0) or 0)
            except (TypeError, ValueError):
                cvss = 0.0
            vector = str(cd.get("vectorString", "") or "")
            break
    desc = ""
    for d in node.get("descriptions") or []:
        if str(d.get("lang", "")).lower() == "en":
            desc = str(d.get("value", "") or "")[:300]
            break
    return {
        "cve": cve,
        "cvss": round(cvss, 1),
        "severity": _severity_from_score(cvss),
        "vector": vector,
        "description": desc,
        "source": "api",
    }


# ============================================================
# API PÚBLICA
# ============================================================

def get_cve_intel(cve: str, use_cache: bool = True) -> dict:
    """CVSS/severidade/descrição de um CVE. Nunca levanta exceção."""
    cve = (cve or "").strip().upper()
    if not _CVE_RE.match(cve):
        return {**_EMPTY_CVE, "cve": cve, "source": "invalid"}

    cache_path = _CACHE_DIR / f"{_safe_name(cve)}.json"
    if use_cache:
        cached = _cache_get(cache_path)
        if cached is not None:
            return cached

    data = _fetch(cve)
    if data is None:                            # erro/rate-limit/cota
        return {**_EMPTY_CVE, "cve": cve, "source": "error"}

    intel = parse_cve(data, cve)
    _cache_put(cache_path, intel)
    return intel


def get_cve_intel_safe(cve: str) -> dict:
    try:
        return get_cve_intel(cve)
    except Exception:
        return {**_EMPTY_CVE, "cve": cve, "source": "error"}


def _aggregate(cve_map: dict) -> dict:
    """De {cve: intel} -> resumo por ativo (maior CVSS + mapa compacto)."""
    scored = {c: i.get("cvss", 0.0) for c, i in cve_map.items() if i.get("cvss", 0.0) > 0}
    if not scored:
        return {"count": 0, "max_cvss": 0.0, "max_severity": "INFO", "worst_cve": "", "scores": {}}
    worst = max(scored, key=lambda c: scored[c])
    top = dict(sorted(scored.items(), key=lambda kv: -kv[1])[:_TOP_CVES])
    return {
        "count": len(scored),
        "max_cvss": round(scored[worst], 1),
        "max_severity": _severity_from_score(scored[worst]),
        "worst_cve": worst,
        "scores": {c: round(v, 1) for c, v in top.items()},
    }


def enrich_results(results: list[dict]) -> None:
    """Anexa a chave 'nvd' a cada resultado (in-place), pontuando (CVSS) as CVEs
    que o InternetDB já encontrou (r['internetdb']['vulns']). Nunca levanta."""
    # Conjunto único de CVEs em toda a varredura (evita consultas repetidas).
    all_cves: set[str] = set()
    for r in results:
        for c in (r.get("internetdb") or {}).get("vulns") or []:
            cu = str(c).strip().upper()
            if _CVE_RE.match(cu):
                all_cves.add(cu)
    if not all_cves:
        print("[NVD] Nenhuma CVE para pontuar (NVD)")
        return

    new = sum(1 for c in all_cves
              if _cache_get(_CACHE_DIR / f"{_safe_name(c)}.json") is None)
    print(f"[NVD] {len(all_cves)} CVE única(s) — {new} nova(s) consulta(s), "
          f"{len(all_cves) - new} do cache" + ("" if _HAS_KEY else " (sem API key: rate-limit baixo)"))

    intel: dict[str, dict] = {}
    for c in sorted(all_cves):
        intel[c] = get_cve_intel(c)
        if intel[c].get("source") == "api":
            time.sleep(_DELAY)

    crit_assets = 0
    for r in results:
        cves = [str(c).strip().upper() for c in (r.get("internetdb") or {}).get("vulns") or []]
        r["nvd"] = _aggregate({c: intel[c] for c in cves if c in intel})
        if r["nvd"].get("max_severity") == "CRITICO":
            crit_assets += 1
    if crit_assets:
        print(f"[NVD] {crit_assets} ativo(s) com CVE CRÍTICA (CVSS ≥ {_CVSS_CRIT}) pela NVD")


def nvd_elevate(risk: str, nvd: dict | None) -> str:
    """Eleva o risco pela severidade OFICIAL (CVSS/NVD) — alta confiança:
    CVSS ≥ nvd_cvss_critico → CRÍTICO; ≥ nvd_cvss_alto → no mínimo ALTO."""
    if not nvd:
        return risk
    score = float(nvd.get("max_cvss", 0.0) or 0.0)
    if score >= _CVSS_CRIT:
        return "CRITICO"
    if score >= _CVSS_ALTO and _RANK.get(risk, 3) > _RANK["ALTO"]:
        return "ALTO"
    return risk


# CLI rápido p/ inspeção: `python -m threatintel.providers.nvd CVE-2021-44228`
if __name__ == "__main__":
    import sys
    cve = sys.argv[1] if len(sys.argv) > 1 else "CVE-2021-44228"
    print(f"[nvd] key={'sim' if _HAS_KEY else 'não'} — consultando {cve}")
    print(json.dumps(get_cve_intel(cve), ensure_ascii=False, indent=2))
