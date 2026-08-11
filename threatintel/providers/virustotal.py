#!/usr/bin/env python3
#
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
threatintel.providers.virustotal — reputação de IP (VirusTotal API v3)
=======================================================================

Consulta o veredito agregado de dezenas de motores de antivírus/blocklist para um
IP e devolve um resumo estável para o Risk Engine.

Como se comporta:
  • Só consulta IP **público** — endereço privado não tem reputação externa.
  • Cache em arquivo com TTL próprio (o plano gratuito é apertado: ~500/dia, 4/min).
  • Cota diária própria: ao estourar, devolve vazio em vez de martelar a API.
  • Chave vem do `config.json` (configurável pela interface Web). Sem chave, o
    provider fica inerte — nunca levanta exceção nem quebra o scan.
  • Falha de rede/HTTP nunca interrompe a varredura: retorna resultado vazio com
    `source` indicando o motivo (mesmo contrato dos outros provedores).

Campos devolvidos:
    malicious / suspicious / harmless / undetected  — votos dos motores
    reputation                                      — placar da comunidade
    country, asn, as_owner                          — contexto do IP
    detected (bool), source (str)
"""

from __future__ import annotations

import datetime
import json
import time
from pathlib import Path

import requests

from threatintel import CONFIG
from threatintel.core.utils import is_public_ip

_API_URL     = "https://www.virustotal.com/api/v3/ip_addresses/"
_API_KEY     = str(CONFIG.get("virustotal_api_key", "") or "").strip()
_TIMEOUT     = int(CONFIG.get("virustotal_request_timeout", 15))
_DAILY_LIMIT = int(CONFIG.get("virustotal_daily_request_limit", 450))
_CACHE_TTL   = int(CONFIG.get("virustotal_cache_ttl_hours", 168)) * 3600
# Piso de detecções para considerar o IP "malicioso" (evita elevar por 1 motor ruidoso).
_MIN_MALICIOUS = int(CONFIG.get("virustotal_min_malicious", 2))
# Pausa entre chamadas: o plano gratuito limita a 4 por minuto.
_THROTTLE_S  = float(CONFIG.get("virustotal_throttle_seconds", 16))

_BASE_DIR   = Path(__file__).resolve().parent.parent
_CACHE_DIR  = _BASE_DIR / "virustotal_cache"
_QUOTA_FILE = _CACHE_DIR / "_quota.json"

_EMPTY = {
    "ip": "", "malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0,
    "reputation": 0, "country": "", "asn": "", "as_owner": "",
    "detected": False, "seen": False, "source": "N/A",
}

_last_call = 0.0


# ── helpers (cache em arquivo + cota própria) ────────────────────────────────

def _safe_name(ip: str) -> str:
    return ip.replace("/", "_").replace("\\", "_").replace(":", "_").strip(".") or "_"


def _ensure_dir() -> None:
    try:
        _CACHE_DIR.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass


def _cache_get(path: Path):
    try:
        if not path.exists() or time.time() - path.stat().st_mtime > _CACHE_TTL:
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


def has_api_key() -> bool:
    return bool(_API_KEY) and _API_KEY != "SUA_API_KEY_AQUI"


# ── consulta ─────────────────────────────────────────────────────────────────

def _normalize(raw: dict, ip: str) -> dict:
    attr = (raw.get("data") or {}).get("attributes") or {}
    stats = attr.get("last_analysis_stats") or {}
    mal = int(stats.get("malicious", 0) or 0)
    sus = int(stats.get("suspicious", 0) or 0)
    return {
        "ip": ip,
        "malicious": mal,
        "suspicious": sus,
        "harmless": int(stats.get("harmless", 0) or 0),
        "undetected": int(stats.get("undetected", 0) or 0),
        "reputation": int(attr.get("reputation", 0) or 0),
        "country": str(attr.get("country", "") or ""),
        "asn": str(attr.get("asn", "") or ""),
        "as_owner": str(attr.get("as_owner", "") or ""),
        "detected": mal >= _MIN_MALICIOUS,
        "seen": True,
        "source": "api",
    }


def get_ip_report(ip: str, use_cache: bool = True) -> dict:
    """Reputação do IP no VirusTotal. NUNCA levanta exceção."""
    ip = (ip or "").strip()
    if not ip:
        return {**_EMPTY}
    if not is_public_ip(ip):
        return {**_EMPTY, "ip": ip, "source": "private"}
    if not has_api_key():
        return {**_EMPTY, "ip": ip, "source": "no_api_key"}

    cache_path = _CACHE_DIR / f"{_safe_name(ip)}.json"
    if use_cache:
        cached = _cache_get(cache_path)
        if cached is not None:
            return cached
    if not _can_request():
        return {**_EMPTY, "ip": ip, "source": "no_quota"}

    global _last_call
    wait = _THROTTLE_S - (time.monotonic() - _last_call)
    if wait > 0:                       # respeita o limite por minuto do plano gratuito
        time.sleep(wait)
    _last_call = time.monotonic()

    try:
        resp = requests.get(_API_URL + ip, headers={"x-apikey": _API_KEY,
                                                    "Accept": "application/json"},
                            timeout=_TIMEOUT)
        _increment()
        if resp.status_code == 200:
            data = _normalize(resp.json(), ip)
            _cache_put(cache_path, data)
            return data
        if resp.status_code == 401:
            print("[VT] ❌ chave inválida (HTTP 401)")
            return {**_EMPTY, "ip": ip, "source": "auth_error"}
        if resp.status_code == 429:
            print("[VT] ⚠️  limite de requisições atingido (HTTP 429)")
            return {**_EMPTY, "ip": ip, "source": "rate_limited"}
        if resp.status_code == 404:
            data = {**_EMPTY, "ip": ip, "seen": False, "source": "not_found"}
            _cache_put(cache_path, data)
            return data
        return {**_EMPTY, "ip": ip, "source": f"http_{resp.status_code}"}
    except requests.Timeout:
        return {**_EMPTY, "ip": ip, "source": "timeout"}
    except requests.RequestException:
        return {**_EMPTY, "ip": ip, "source": "network_error"}
    except Exception:
        return {**_EMPTY, "ip": ip, "source": "error"}


def get_ip_report_safe(ip: str) -> dict:
    try:
        return get_ip_report(ip)
    except Exception:
        return {**_EMPTY, "ip": ip, "source": "error"}


# ── enriquecimento em lote + elevação de risco ───────────────────────────────

def enrich_results(results: list) -> None:
    """Anexa `vt` a cada item que tenha IP público. Idempotente e tolerante a falha."""
    if not has_api_key():
        return
    ips = {}
    for r in results:
        ip = (r.get("ip") or "").strip()
        if ip and is_public_ip(ip):
            ips.setdefault(ip, []).append(r)
    if not ips:
        return
    print(f"[VT] {len(ips)} IP(s) único(s) — VirusTotal (cache TTL {_CACHE_TTL // 3600}h)")
    detected = 0
    for ip, rows in ips.items():
        rep = get_ip_report_safe(ip)
        for r in rows:
            r["vt"] = rep
        if rep.get("detected"):
            detected += 1
    if detected:
        print(f"[VT] {detected} IP(s) com detecção maliciosa (>= {_MIN_MALICIOUS} motores)")


_RANK = {"CRITICO": 0, "ALTO": 1, "MEDIO": 2, "BAIXO": 3, "INFO": 4}
_ORDER = ["CRITICO", "ALTO", "MEDIO", "BAIXO", "INFO"]


def elevate(results: list) -> int:
    """Eleva o risco de quem o VirusTotal aponta como malicioso — evidência objetiva,
    no mesmo espírito das demais camadas (o risco nunca é rebaixado)."""
    n = 0
    for r in results:
        vt = r.get("vt") or {}
        if not vt.get("detected"):
            continue
        mal = int(vt.get("malicious", 0) or 0)
        alvo = "CRITICO" if mal >= 5 else "ALTO"
        atual = r.get("risk", "INFO")
        if _RANK.get(alvo, 4) < _RANK.get(atual, 4):
            r["risk"] = alvo
            n += 1
    return n
