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
cisa_kev.py — Provider CISA Known Exploited Vulnerabilities (KEV)
================================================================

Enriquecimento que diz QUAIS das CVEs já descobertas (pelo InternetDB) estão
sendo **exploradas in-the-wild** segundo o catálogo oficial da CISA (KEV).

Diferente do InternetDB (consulta por IP), a KEV é um **catálogo único**: baixamos
o JSON INTEIRO **1×/dia** (cache) e cruzamos **localmente** — barato, sem rate-limit
e sem chave (a CISA KEV é pública e gratuita). A URL é configurável em config.json
caso você queira usar um feed equivalente.

Papel: segundo passo de enriquecimento (roda DEPOIS do InternetDB, reusando os CVEs
que ele já encontrou). Sinal de altíssima confiança: KEV = exploração CONFIRMADA.

Fonte (padrão):
    https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
    Formato: {"vulnerabilities":[{"cveID":"CVE-...","dueDate":"...","vulnerabilityName":"..."}]}

Uso:
    from threatintel.providers import cisa_kev
    cisa_kev.enrich_results(scan_results)            # anexa "kev" a cada result
    risk = cisa_kev.kev_elevate(risk, r.get("kev"))  # eleva (KEV -> CRÍTICO)
"""

import datetime
import json
import time
import urllib.error
import urllib.request
from pathlib import Path

from threatintel import CONFIG

# ── Configuração ─────────────────────────────────────────────
_ENABLED      = bool(CONFIG.get("cisa_kev_enabled", True))
_URL          = CONFIG.get("cisa_kev_url",
                           "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
_TIMEOUT      = int(CONFIG.get("cisa_kev_request_timeout", 30))
_CACHE_TTL    = int(CONFIG.get("cisa_kev_cache_ttl_hours", 24)) * 3600
_FORCES_CRIT  = bool(CONFIG.get("cisa_kev_forces_critico", True))
_USER_AGENT   = "argus-monitor/1.0 (+cisa-kev-enrichment)"

_BASE_DIR    = Path(__file__).resolve().parent.parent
_CACHE_DIR   = _BASE_DIR / "cisa_kev_cache"
_CACHE_FILE  = _CACHE_DIR / "catalog.json"

_RANK = {"CRITICO": 0, "ALTO": 1, "MEDIO": 2, "BAIXO": 3, "INFO": 4}

# Cache em memória do catálogo (carregado uma vez por execução).
_CATALOG: dict | None = None


# ============================================================
# PARSING (puro — testável offline)
# ============================================================

def parse_kev_catalog(data: dict) -> dict:
    """Catálogo CISA -> {CVE_MAIUSCULO: {kev_due, name}}."""
    out = {}
    for item in (data or {}).get("vulnerabilities", []) or []:
        cve = str(item.get("cveID", "")).strip().upper()
        if not cve:
            continue
        out[cve] = {
            "kev_due": str(item.get("dueDate", "") or ""),
            "name": str(item.get("vulnerabilityName", "") or "")[:160],
        }
    return out


# ============================================================
# CACHE EM ARQUIVO (catálogo único, TTL 24h)
# ============================================================

def _ensure_dir() -> None:
    try:
        _CACHE_DIR.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass


def _load_cache() -> dict | None:
    try:
        if not _CACHE_FILE.exists():
            return None
        if time.time() - _CACHE_FILE.stat().st_mtime > _CACHE_TTL:
            return None
        with open(_CACHE_FILE, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def _save_cache(catalog: dict) -> None:
    _ensure_dir()
    try:
        with open(_CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(catalog, f)
    except Exception:
        pass


def _download() -> dict | None:
    req = urllib.request.Request(_URL, headers={
        "User-Agent": _USER_AGENT, "Accept": "application/json",
    })
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            return json.loads(resp.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as exc:
        print(f"[CISA-KEV] HTTP {exc.code} ao baixar o catálogo KEV")
        return None
    except (urllib.error.URLError, json.JSONDecodeError, TimeoutError, ValueError):
        return None
    except Exception:
        return None


# ============================================================
# API PÚBLICA
# ============================================================

def get_catalog() -> dict:
    """Catálogo {CVE: {...}} — memória > cache em arquivo (24h) > download.
    Nunca levanta; em falha total retorna {} (KEV simplesmente não enriquece)."""
    global _CATALOG
    if _CATALOG is not None:
        return _CATALOG
    cached = _load_cache()
    if cached is not None:
        _CATALOG = cached
        return _CATALOG
    data = _download()
    catalog = parse_kev_catalog(data) if data else {}
    if catalog:
        _save_cache(catalog)
        print(f"[CISA-KEV] catálogo KEV atualizado: {len(catalog)} CVE explorada(s)")
    _CATALOG = catalog
    return _CATALOG


def _hits_for(cves) -> list[str]:
    catalog = get_catalog()
    if not catalog:
        return []
    seen, out = set(), []
    for c in (cves or []):
        cu = str(c).strip().upper()
        if cu and cu in catalog and cu not in seen:
            seen.add(cu)
            out.append(str(c).strip())
    return out


def enrich_results(results: list[dict]) -> None:
    """Anexa a chave 'kev' a cada resultado (in-place), cruzando as CVEs já
    descobertas pelo InternetDB (r['internetdb']['vulns']) com o catálogo KEV.
    Nunca levanta exceção."""
    if not _ENABLED:
        return
    catalog = get_catalog()
    if not catalog:
        print("[CISA-KEV] catálogo indisponível — enriquecimento KEV ignorado")
        return
    hit_assets = 0
    for r in results:
        cves = (r.get("internetdb") or {}).get("vulns") or []
        hits = _hits_for(cves)
        dues = [catalog[c.upper()].get("kev_due", "") for c in hits]
        dues = [d for d in dues if d]
        r["kev"] = {
            "kev_count": len(hits),
            "kev_cves": hits[:50],
            "kev_due": min(dues) if dues else "",
        }
        if hits:
            hit_assets += 1
    if hit_assets:
        print(f"[CISA-KEV] {hit_assets} ativo(s) com CVE explorada in-the-wild (CISA KEV)")


def kev_elevate(risk: str, kev: dict | None) -> str:
    """Eleva o risco quando há CVE na KEV (exploração CONFIRMADA pela CISA).
    Diferente do InternetDB (heurístico → no máx. ALTO), a KEV é alta confiança:
    por padrão vai a CRÍTICO (configurável via `cisa_kev_forces_critico`)."""
    if kev and kev.get("kev_count", 0) >= 1:
        if _FORCES_CRIT:
            return "CRITICO"
        if _RANK.get(risk, 3) > _RANK["ALTO"]:
            return "ALTO"
    return risk


# CLI rápido p/ inspeção: `python -m threatintel.providers.cisa_kev`
if __name__ == "__main__":
    cat = get_catalog()
    print(f"[cisa_kev] catálogo com {len(cat)} CVE")
    demo = ["CVE-2017-0144", "CVE-2099-9999"]
    print("hits demo:", _hits_for(demo))
