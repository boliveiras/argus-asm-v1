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
threatintel.providers.abuseipdb
────────────────────────────────
Provider reutilizável para consultas à API AbuseIPDB v2.

Fluxo por IP:
  1. Valida se é IP público
  2. Verifica cache SQLite (TTL 48h)
  3. Se cache hit → retorna imediatamente
  4. Verifica cota diária
  5. Consulta API com retry/timeout
  6. Normaliza resposta
  7. Persiste no cache
  8. Incrementa contador de quota
  9. Retorna resultado normalizado

Uso:
    from threatintel.providers.abuseipdb import get_ip_reputation, enrich_results

    data = get_ip_reputation("8.8.8.8")
    # → {"abuse_confidence_score": 0, "country_code": "US", ...}

    enrich_results(scan_results)
    # → adiciona chave "abuse" a cada dict da lista in-place
"""

from __future__ import annotations

import time

import requests

from threatintel import CONFIG
from threatintel.core.cache import get_cached, set_cache
from threatintel.core.quota import can_request, get_remaining, increment
from threatintel.core.utils import is_public_ip, safe_int, safe_str

# ─── Configurações ────────────────────────────────────────────────────────────

_API_KEY     = CONFIG.get("abuseipdb_api_key", "")
_TIMEOUT     = int(CONFIG.get("request_timeout", 15))
_MAX_AGE     = int(CONFIG.get("max_age_in_days", 90))
_API_URL     = "https://api.abuseipdb.com/api/v2/check"

# Resultado vazio padrão para IPs não consultáveis
_EMPTY_RESULT: dict = {
    "abuse_confidence_score": 0,
    "country_code":           "",
    "usage_type":             "",
    "isp":                    "",
    "domain":                 "",
    "hostnames":              [],
    "is_public":              0,
    "is_tor":                 0,
    "total_reports":          0,
    "num_distinct_users":     0,
    "last_reported_at":       "",
    "source":                 "N/A",
}

# ─── Normalização ─────────────────────────────────────────────────────────────


def _normalize(raw: dict) -> dict:
    """Normaliza a resposta bruta da API para o formato interno."""
    d = raw.get("data", {})
    hostnames = d.get("hostnames", []) or []
    return {
        "abuse_confidence_score": safe_int(d.get("abuseConfidenceScore"), 0),
        "country_code":           safe_str(d.get("countryCode")),
        "usage_type":             safe_str(d.get("usageType")),
        "isp":                    safe_str(d.get("isp")),
        "domain":                 safe_str(d.get("domain")),
        "hostnames":              hostnames if isinstance(hostnames, list) else [],
        "is_public":              int(bool(d.get("isPublic", True))),
        "is_tor":                 int(bool(d.get("isTor", False))),
        "total_reports":          safe_int(d.get("totalReports"), 0),
        "num_distinct_users":     safe_int(d.get("numDistinctUsers"), 0),
        "last_reported_at":       safe_str(d.get("lastReportedAt")),
        "raw":                    raw,
        "source":                 "api",
    }


# ─── Consulta individual ──────────────────────────────────────────────────────


def get_ip_reputation(ip: str) -> dict:
    """
    Retorna dados de reputação para um IP.

    Ordem de resolução:
      1. Cache SQLite válido (dentro do TTL)
      2. API AbuseIPDB (se houver cota)
      3. Resultado vazio com source="no_quota" ou "private" ou "invalid"

    Nunca lança exceção — sempre retorna um dict.
    """
    # IPs não-públicos não têm reputação
    if not is_public_ip(ip):
        return {**_EMPTY_RESULT, "source": "private"}

    # Cache hit
    cached = get_cached(ip)
    if cached:
        cached["source"] = "cache"
        return cached

    # Sem cota disponível
    if not can_request():
        print(f"[ABUSE] ⚠️  Cota esgotada — IP {ip} sem consulta (restantes: 0)")
        return {**_EMPTY_RESULT, "source": "no_quota"}

    # API key não configurada
    if not _API_KEY or _API_KEY == "SUA_API_KEY_AQUI":
        return {**_EMPTY_RESULT, "source": "no_api_key"}

    # Consulta à API
    try:
        resp = requests.get(
            _API_URL,
            headers={"Accept": "application/json", "Key": _API_KEY},
            params={"ipAddress": ip, "maxAgeInDays": _MAX_AGE},
            timeout=_TIMEOUT,
        )

        if resp.status_code == 200:
            data = _normalize(resp.json())
            set_cache(ip, data)
            increment(1)
            return data

        if resp.status_code == 429:
            print("[ABUSE] ⚠️  Rate limit atingido (HTTP 429) — aguardando 5s")
            time.sleep(5)
            return {**_EMPTY_RESULT, "source": "rate_limited"}

        if resp.status_code == 401:
            print("[ABUSE] ❌ API key inválida (HTTP 401)")
            return {**_EMPTY_RESULT, "source": "auth_error"}

        print(f"[ABUSE] HTTP {resp.status_code} para IP {ip}")
        return {**_EMPTY_RESULT, "source": f"http_{resp.status_code}"}

    except requests.Timeout:
        print(f"[ABUSE] Timeout ao consultar {ip}")
        return {**_EMPTY_RESULT, "source": "timeout"}
    except requests.RequestException as exc:
        print(f"[ABUSE] Erro de rede para {ip}: {exc}")
        return {**_EMPTY_RESULT, "source": "network_error"}
    except Exception as exc:
        print(f"[ABUSE] Erro inesperado para {ip}: {exc}")
        return {**_EMPTY_RESULT, "source": "error"}


# ─── Enriquecimento em lote ───────────────────────────────────────────────────


def enrich_results(results: list[dict]) -> None:
    """
    Enriquece uma lista de resultados de scan com dados de reputação.

    Para cada IP público único:
      - consulta get_ip_reputation() (cache ou API)
      - adiciona chave "abuse" ao dict de cada resultado

    Modifica `results` in-place. Nunca lança exceção.
    """
    # Coleta IPs públicos únicos
    unique_public: set[str] = {
        r["ip"] for r in results if is_public_ip(r.get("ip", ""))
    }

    total     = len(unique_public)
    api_count = sum(1 for ip in unique_public if get_cached(ip) is None)
    remaining = get_remaining()

    if total == 0:
        print("[ABUSE] Nenhum IP público para consultar reputação")
        return

    print(
        f"[ABUSE] {total} IPs únicos — "
        f"{min(api_count, remaining)} novas consultas, "
        f"{total - api_count} do cache | "
        f"Cota restante: {remaining}/dia"
    )

    # Consulta e monta cache local para o lote
    reputation_cache: dict[str, dict] = {}
    for ip in unique_public:
        reputation_cache[ip] = get_ip_reputation(ip)
        # Pequena pausa para não estressar a API em lotes grandes
        if reputation_cache[ip].get("source") == "api":
            time.sleep(0.3)

    # Aplica aos resultados
    empty = {**_EMPTY_RESULT, "source": "private"}
    for r in results:
        r["abuse"] = reputation_cache.get(r.get("ip", ""), empty)

    # Exibe status final da cota
    from threatintel.core.quota import status_line
    print(status_line())
