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
whois_lookup.py — Provider de inteligência de domínio via RDAP
===============================================================

Consulta dados de registro de domínios (criação, expiração, idade, registrar)
usando **RDAP** (Registration Data Access Protocol) — o substituto moderno do
WHOIS, baseado em HTTP/JSON, mais confiável e padronizado.

O servidor RDAP de cada TLD é descoberto automaticamente pelo bootstrap oficial
da IANA (data.iana.org/rdap/dns.json), com cache local de 7 dias. Para o .br há
um override fixo (rdap.registro.br).

Se o RDAP falhar para um domínio (TLD sem RDAP, servidor fora do ar), há um
**fallback silencioso** para a biblioteca python-whois (porta 43), quando
instalada. O logger ruidoso da python-whois é suprimido.

Os resultados são persistidos numa base de Threat Intel (intel.db) com cache
longo (14 dias), pois dados de registro mudam raramente.

Uso:
    from threatintel.providers.whois_lookup import get_domain_intel
    intel = get_domain_intel("empresa.com.br")
    # → {"domain","creation_date","expiration_date","updated_date",
    #     "registrar","age_days","days_to_expiry","status"}

Insights de CTI:
    - age_days < 30           → domínio recém-criado (suspeito)
    - days_to_expiry < 30     → risco de lapso de renovação / sequestro
    - status:  NOVO / RECENTE / ESTABELECIDO / EXPIRANDO / EXPIRADO
"""

import datetime
import json
import logging
import sqlite3
import time
from pathlib import Path

import requests

# Fallback opcional: python-whois (porta 43). RDAP é o motor principal.
try:
    import whois as _whois
    _WHOIS_LIB_AVAILABLE = True
    # Silencia o logger interno da biblioteca — ela emite ERROR no stderr quando
    # não resolve o servidor WHOIS de um TLD. O erro já é tratado por try/except.
    logging.getLogger("whois.whois").setLevel(logging.CRITICAL)
except ImportError:
    _WHOIS_LIB_AVAILABLE = False
    _whois = None

# ── Configuração ─────────────────────────────────────────────
# Cache de 14 dias — dados de registro mudam raramente.
CACHE_TTL_DAYS    = 14
# Domínio considerado "recém-criado" (sinal de risco para phishing)
NEW_DOMAIN_DAYS   = 30
# Aviso de expiração próxima
EXPIRY_WARN_DAYS  = 30

# RDAP
RDAP_TIMEOUT          = 15          # timeout por requisição HTTP RDAP
RDAP_BOOTSTRAP_URL    = "https://data.iana.org/rdap/dns.json"
RDAP_BOOTSTRAP_TTL    = 7 * 24 * 3600   # 7 dias
USER_AGENT            = "argus-monitor/1.0 (+rdap-intel)"
# Override de servidores RDAP por TLD (tem precedência sobre o bootstrap da IANA).
# Garante o .br mesmo que o bootstrap esteja indisponível.
_RDAP_OVERRIDES = {
    "br": "https://rdap.registro.br/",
}

# intel.db e o cache do bootstrap ficam no diretório raiz do threatintel.
_BASE_DIR        = Path(__file__).resolve().parent.parent
_INTEL_DB        = _BASE_DIR / "intel.db"
_BOOTSTRAP_FILE  = _BASE_DIR / "rdap_bootstrap.json"

# Cache em memória do mapa TLD→servidor (carregado uma vez por execução)
_bootstrap_map_cache: dict | None = None


# ============================================================
# BASE DE DADOS (intel.db)
# ============================================================

def _init_intel_db() -> None:
    """Cria a tabela domain_whois se não existir."""
    try:
        conn = sqlite3.connect(str(_INTEL_DB))
        conn.execute("""
            CREATE TABLE IF NOT EXISTS domain_whois (
                domain          TEXT PRIMARY KEY,
                creation_date   TEXT,
                expiration_date TEXT,
                updated_date    TEXT,
                registrar       TEXT,
                age_days        INTEGER,
                days_to_expiry  INTEGER,
                status          TEXT,
                last_checked    TEXT
            )
        """)
        conn.commit()
        conn.close()
    except Exception:
        pass


def _read_cache(domain: str) -> dict | None:
    """Lê o registro do cache se ainda válido (dentro do TTL)."""
    try:
        conn = sqlite3.connect(str(_INTEL_DB))
        conn.row_factory = sqlite3.Row
        cur = conn.execute("SELECT * FROM domain_whois WHERE domain=?", (domain,))
        row = cur.fetchone()
        conn.close()
        if not row:
            return None
        last = row["last_checked"]
        if last:
            checked = datetime.datetime.fromisoformat(last)
            age = (datetime.datetime.now() - checked).days
            if age > CACHE_TTL_DAYS:
                return None  # cache expirado
        return dict(row)
    except Exception:
        return None


def _write_cache(intel: dict) -> None:
    try:
        _init_intel_db()
        conn = sqlite3.connect(str(_INTEL_DB))
        conn.execute("""
            INSERT INTO domain_whois
              (domain,creation_date,expiration_date,updated_date,registrar,
               age_days,days_to_expiry,status,last_checked)
            VALUES (?,?,?,?,?,?,?,?,?)
            ON CONFLICT(domain) DO UPDATE SET
              creation_date=excluded.creation_date,
              expiration_date=excluded.expiration_date,
              updated_date=excluded.updated_date,
              registrar=excluded.registrar,
              age_days=excluded.age_days,
              days_to_expiry=excluded.days_to_expiry,
              status=excluded.status,
              last_checked=excluded.last_checked
        """, (intel["domain"], intel["creation_date"], intel["expiration_date"],
              intel["updated_date"], intel["registrar"], intel["age_days"],
              intel["days_to_expiry"], intel["status"],
              datetime.datetime.now().isoformat()))
        conn.commit()
        conn.close()
    except Exception:
        pass


# ============================================================
# RDAP — bootstrap (descoberta de servidor por TLD)
# ============================================================

def _fetch_json(url: str, timeout: int) -> dict | None:
    """GET genérico que retorna JSON ou None (nunca levanta)."""
    try:
        resp = requests.get(url, headers={
            "User-Agent": USER_AGENT,
            "Accept": "application/rdap+json, application/json",
        }, timeout=timeout)
        resp.raise_for_status()
        return resp.json()
    except (requests.exceptions.RequestException,
            json.JSONDecodeError, ValueError):
        return None
    except Exception:
        return None


def _load_bootstrap() -> dict | None:
    """Carrega o dns.json do cache local (se fresco) ou da IANA."""
    # 1. Cache em disco
    try:
        if _BOOTSTRAP_FILE.exists():
            age = time.time() - _BOOTSTRAP_FILE.stat().st_mtime
            if age <= RDAP_BOOTSTRAP_TTL:
                with open(_BOOTSTRAP_FILE, encoding="utf-8") as f:
                    return json.load(f)
    except Exception:
        pass
    # 2. Busca na IANA
    data = _fetch_json(RDAP_BOOTSTRAP_URL, RDAP_TIMEOUT)
    if data:
        try:
            with open(_BOOTSTRAP_FILE, "w", encoding="utf-8") as f:
                json.dump(data, f)
        except Exception:
            pass
    return data


def _bootstrap_servers() -> dict:
    """Retorna o mapa {tld: url_base_rdap}, carregado uma vez por execução."""
    global _bootstrap_map_cache
    if _bootstrap_map_cache is not None:
        return _bootstrap_map_cache
    mapping: dict[str, str] = {}
    data = _load_bootstrap()
    if data:
        for service in data.get("services", []):
            try:
                tlds, urls = service[0], service[1]
            except (IndexError, TypeError):
                continue
            if not urls:
                continue
            base = urls[0]
            for tld in tlds:
                mapping[str(tld).lower()] = base
    _bootstrap_map_cache = mapping
    return mapping


def _rdap_server_for(domain: str) -> str | None:
    """Resolve o servidor RDAP para o TLD do domínio (override > bootstrap)."""
    tld = domain.rsplit(".", 1)[-1] if "." in domain else domain
    return _RDAP_OVERRIDES.get(tld) or _bootstrap_servers().get(tld)


# ============================================================
# RDAP — parsing
# ============================================================

def _parse_rdap_date(value: str | None) -> datetime.datetime | None:
    """Converte data RDAP (ISO 8601) para datetime naïve em UTC."""
    if not value:
        return None
    s = str(value).strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.datetime.fromisoformat(s)
        if dt.tzinfo is not None:
            dt = dt.astimezone(datetime.UTC).replace(tzinfo=None)
        return dt
    except ValueError:
        for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
            try:
                return datetime.datetime.strptime(s[:19], fmt)
            except ValueError:
                continue
    return None


def _rdap_registrar(data: dict) -> str:
    """Extrai o nome do registrar das entidades RDAP (vcard 'fn')."""
    for entity in data.get("entities", []) or []:
        roles = entity.get("roles", []) or []
        if "registrar" not in roles:
            continue
        vcard = entity.get("vcardArray")
        if isinstance(vcard, list) and len(vcard) >= 2:
            for item in vcard[1]:
                # item = ["fn", {}, "text", "Nome do Registrar"]
                if isinstance(item, list) and len(item) >= 4 and item[0] == "fn":
                    return str(item[3])
        # Sem vcard legível — usa o handle como último recurso
        if entity.get("handle"):
            return str(entity["handle"])
    return ""


def _lookup_rdap(domain: str) -> dict | None:
    """Consulta RDAP. Retorna intel ou None se não obteve dados úteis."""
    base = _rdap_server_for(domain)
    if not base:
        return None
    url = base.rstrip("/") + "/domain/" + domain
    data = _fetch_json(url, RDAP_TIMEOUT)
    if not data:
        return None

    creation = expiry = updated = None
    for ev in data.get("events", []) or []:
        action = str(ev.get("eventAction", "")).lower()
        when = _parse_rdap_date(ev.get("eventDate"))
        if when is None:
            continue
        if action == "registration":
            creation = creation or when
        elif action == "expiration":
            expiry = expiry or when
        elif action == "last changed":
            updated = updated or when

    # Sem datas úteis → deixa o fallback (python-whois) tentar
    if creation is None and expiry is None:
        return None

    return _build_intel(domain, creation, expiry, updated, _rdap_registrar(data))


# ============================================================
# FALLBACK — python-whois (porta 43)
# ============================================================

def _coerce_date(value):
    """python-whois retorna datetime, lista, string ou None — normaliza."""
    if value is None:
        return None
    if isinstance(value, list):
        dates = [_coerce_date(v) for v in value]
        dates = [d for d in dates if d is not None]
        return min(dates) if dates else None
    if isinstance(value, datetime.datetime):
        return value
    if isinstance(value, datetime.date):
        return datetime.datetime(value.year, value.month, value.day)
    if isinstance(value, str):
        for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S",
                    "%Y-%m-%d", "%d/%m/%Y", "%Y.%m.%d"):
            try:
                return datetime.datetime.strptime(value.strip()[:19], fmt)
            except (ValueError, TypeError):
                continue
    return None


def _coerce_str(value) -> str:
    if value is None:
        return ""
    if isinstance(value, list):
        for v in value:
            if v:
                return str(v)
        return ""
    return str(value)


def _lookup_whois(domain: str) -> dict | None:
    """Fallback via python-whois. Retorna intel ou None."""
    if not _WHOIS_LIB_AVAILABLE:
        return None
    try:
        w = _whois.whois(domain)
    except Exception:
        return None
    creation = _coerce_date(getattr(w, "creation_date", None))
    expiry   = _coerce_date(getattr(w, "expiration_date", None))
    updated  = _coerce_date(getattr(w, "updated_date", None))
    if creation is None and expiry is None:
        return None
    return _build_intel(domain, creation, expiry, updated,
                        _coerce_str(getattr(w, "registrar", "")))


# ============================================================
# CLASSIFICAÇÃO / MONTAGEM
# ============================================================

def _classify(age_days, days_to_expiry) -> str:
    """Classifica o domínio do ponto de vista de CTI."""
    if days_to_expiry is not None and days_to_expiry < 0:
        return "EXPIRADO"
    if days_to_expiry is not None and days_to_expiry < EXPIRY_WARN_DAYS:
        return "EXPIRANDO"
    if age_days is not None and age_days < NEW_DOMAIN_DAYS:
        return "NOVO"
    if age_days is not None and age_days < 365:
        return "RECENTE"
    return "ESTABELECIDO"


def _build_intel(domain, creation, expiry, updated, registrar) -> dict:
    """Monta o dict de intel a partir das datas e registrar já normalizados."""
    now = datetime.datetime.now()
    age_days       = (now - creation).days if creation else None
    days_to_expiry = (expiry - now).days   if expiry   else None
    return {
        "domain":          domain,
        "creation_date":   creation.strftime("%Y-%m-%d") if creation else "",
        "expiration_date": expiry.strftime("%Y-%m-%d")   if expiry   else "",
        "updated_date":    updated.strftime("%Y-%m-%d")  if updated  else "",
        "registrar":       (registrar or "")[:80],
        "age_days":        age_days,
        "days_to_expiry":  days_to_expiry,
        "status":          _classify(age_days, days_to_expiry),
    }


def _empty_intel(domain: str) -> dict:
    return {"domain": domain, "creation_date": "", "expiration_date": "",
            "updated_date": "", "registrar": "", "age_days": None,
            "days_to_expiry": None, "status": "DESCONHECIDO"}


# ============================================================
# API PÚBLICA
# ============================================================

def get_domain_intel(domain: str, use_cache: bool = True) -> dict:
    """
    Retorna inteligência de registro de um domínio (RDAP, com fallback WHOIS),
    usando cache persistente. Nunca levanta exceção — em caso de falha total
    retorna status DESCONHECIDO (sem gravar no cache, para reconsultar depois).
    """
    domain = (domain or "").strip().lower().rstrip(".")
    if not domain:
        return _empty_intel(domain)

    # 1. Cache
    if use_cache:
        _init_intel_db()
        cached = _read_cache(domain)
        if cached is not None:
            return cached

    # 2. RDAP (primário) → python-whois (fallback)
    intel = _lookup_rdap(domain) or _lookup_whois(domain)
    if not intel:
        return _empty_intel(domain)

    # 3. Persiste no cache
    _write_cache(intel)
    return intel


def get_domain_intel_safe(domain: str) -> dict:
    """Wrapper que nunca levanta exceção."""
    try:
        return get_domain_intel(domain)
    except Exception:
        return _empty_intel(domain)


def enrich_with_whois(results: list[dict]) -> None:
    """
    Enriquece uma lista de resultados de subdomínios com dados de registro do
    DOMÍNIO BASE de cada um. Adiciona a chave "whois" a cada resultado.

    O lookup é do domínio registrável (empresa.com.br), não do subdomínio, então
    consultamos uma vez por domínio base e reaproveitamos.
    """
    cache_local: dict[str, dict] = {}
    for r in results:
        hostname = r.get("hostname", "")
        base = _registrable_domain(hostname)
        if base not in cache_local:
            cache_local[base] = get_domain_intel_safe(base)
        r["whois"] = cache_local[base]


def _registrable_domain(hostname: str) -> str:
    """
    Extrai o domínio registrável de um hostname.
    Heurística: para .X.br (com.br, org.br, etc) usa 3 labels, senão usa 2.
    """
    parts = (hostname or "").strip().lower().rstrip(".").split(".")
    if len(parts) <= 2:
        return ".".join(parts)
    # TLDs de segundo nível comuns no Brasil
    second_level = {"com", "org", "net", "gov", "edu", "mil", "co"}
    if parts[-1] == "br" and parts[-2] in second_level:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])
