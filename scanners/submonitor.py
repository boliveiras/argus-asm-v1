#!/usr/bin/env python3
# -*- coding: utf-8 -*-
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
Subdomain Monitor — DNS + HTTP + AbuseIPDB

Lê campanhas de targets/ (um .txt por empresa), resolve subdomínios,
enriquece com AbuseIPDB e gera relatório HTML via reporter.py.

Uso:
    python3 submonitor.py
    python3 submonitor.py --install-cron

Estrutura:
    submonitor/
        submonitor.py
        subs.txt
        targets/
            EMPRESA1.txt
            EMPRESA2.txt
        submonitor.db        (gerado automaticamente)
        submonitor_report.html
"""

import asyncio
import aiodns
import aiohttp
import sqlite3
import datetime
import ipaddress
import json
import os
import re
import socket
import ssl
import sys
import time
import uuid
from pathlib import Path

try:
    from threatintel.providers.abuseipdb import enrich_results as _ti_enrich
    from threatintel.core.reputation      import compute_final_risk as _ti_risk
    from threatintel.core.database        import init_database as _ti_init_db
    _THREATINTEL_AVAILABLE = True
except ImportError:
    _THREATINTEL_AVAILABLE = False
    def _ti_enrich(r):      pass
    def _ti_risk(p,i,a):    return p
    def _ti_init_db():       pass

try:
    from threatintel.providers import internetdb as _internetdb
except ImportError:
    _internetdb = None  # enriquecimento de vulnerabilidades (Shodan InternetDB) opcional

try:
    from threatintel.providers import cisa_kev as _cisa_kev
except ImportError:
    _cisa_kev = None  # enriquecimento KEV (CVE explorada in-the-wild) opcional

# Provider crt.sh (Certificate Transparency) — descoberta passiva de subdomínios
try:
    from threatintel.providers import crtsh
    _CRTSH_AVAILABLE = True
except ImportError:
    _CRTSH_AVAILABLE = False
    crtsh = None

# Provider urlscan.io (Search API, passivo) — descoberta passiva + contexto web
try:
    from threatintel.providers import urlscan
    _URLSCAN_AVAILABLE = True
except ImportError:
    _URLSCAN_AVAILABLE = False
    urlscan = None

# Provider WHOIS — idade, criação e expiração do domínio (cache em intel.db)
try:
    from threatintel.providers import whois_lookup
    _WHOIS_AVAILABLE = True
except ImportError:
    _WHOIS_AVAILABLE = False
    whois_lookup = None

try:
    from reporter import generate_submonitor_report
except ImportError:
    print("[ERRO] reporter.py não encontrado no PYTHONPATH.")
    print("        Verifique a instalação em /etc/argus (PYTHONPATH).")
    sys.exit(1)

try:
    import ack
except ImportError:
    ack = None  # reconhecimento opcional; degrada sem quebrar o scan

try:
    import findings as _findings
except ImportError:
    _findings = None  # store central de achados (argus.db) opcional/aditivo

# ============================================================
# CONFIG
# ============================================================

TARGETS_DIR   = "targets"
SUBS_FILE     = "subs.txt"
DATABASE_FILE = "submonitor.db"
HTML_REPORT   = "submonitor_report.html"
APACHE_DOCROOT = "/var/www/argus"
# Carência (dias) antes de marcar um subdomínio como REMOVIDO — absorve "misses"
# transitórios (DNS/crt.sh/urlscan). Ajustável por env.
CLOSE_GRACE_DAYS = int(os.environ.get("ARGUS_CLOSE_GRACE_DAYS", "3"))

TIMEOUT     = 5
CONCURRENCY = 25
ASN_BATCH_SIZE = 100
PREFIXES = ["", "prod-", "hml-", "dev-", "aceite-"]

# ============================================================
# SYSLOG RFC 5424
# ============================================================

SYSLOG_FILE = "/var/log/argus/submonitor/submonitor.log"
SYSLOG_APP  = "submonitor"
APP_VERSION = "2.0"

_FAC      = 16
_SEV      = {"EMERG":0,"ALERT":1,"CRIT":2,"ERR":3,"WARN":4,"NOTICE":5,"INFO":6,"DEBUG":7}
_RISK_SEV = {"CRITICO":"CRIT","ALTO":"WARN","MEDIO":"NOTICE","BAIXO":"INFO","INFO":"INFO"}

_syslog_fd  = None
_run_id     = None
_scan_start = None
_pid        = os.getpid()
_hostname   = socket.gethostname()


def _syslog_open():
    global _syslog_fd
    Path(SYSLOG_FILE).parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(SYSLOG_FILE, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o640)
    _syslog_fd = os.fdopen(fd, "a", encoding="utf-8", errors="replace")

def _syslog_close():
    global _syslog_fd
    if _syslog_fd:
        _syslog_fd.flush(); _syslog_fd.close(); _syslog_fd = None

def _sd_escape(v: str) -> str:
    return str(v).replace("\\","\\\\").replace('"','\\"').replace("]","\\]")

def syslog_write(severity: str, msgid: str, msg: str, **sd):
    if _syslog_fd is None: return
    prival = _FAC * 8 + _SEV.get(severity, 6)
    ts     = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]+"Z"
    parts  = [f'run_id="{_sd_escape(_run_id)}"'] + [f'{k}="{_sd_escape(v)}"' for k,v in sd.items()]
    line   = f"<{prival}>1 {ts} {_hostname} {SYSLOG_APP} {_pid} {msgid} [origin@32473 {' '.join(parts)}] {str(msg).replace(chr(10),' ')}\n"
    try: _syslog_fd.write(line); _syslog_fd.flush()
    except OSError: pass

def syslog_init(campaigns: int, domains: int, subs: int, prefixes: int):
    global _run_id, _scan_start
    _run_id = str(uuid.uuid4())
    _scan_start = datetime.datetime.now(datetime.timezone.utc)
    _syslog_open()
    syslog_write("INFO","SCAN_START",
                 f"Iniciando scan: {campaigns} campanha(s), {domains} dominio(s), {subs} sub(s)",
                 module=SYSLOG_APP, version=APP_VERSION,
                 campaigns=str(campaigns), domains=str(domains),
                 subs=str(subs), prefixes=str(prefixes))

def syslog_host(result: dict):
    status = result.get("status","")
    risk   = result.get("risk","INFO")
    sev    = _RISK_SEV.get(risk,"INFO")
    abuse  = result.get("abuse") or {}
    if status == "CORRIGIDO":
        sev = "NOTICE"; msgid = "HOST_FIX"
        msg = f"Host corrigido: {result.get('hostname','')}"
    elif status == "RESSURGIDO":
        msgid = "HOST_RESURG"
        msg = f"Host ressurgido [{risk}]: {result.get('hostname','')}"
    elif status == "REINCIDENTE":
        msgid = "HOST_REIN"
        msg = f"Host reincidente [{risk}]: {result.get('hostname','')}"
    else:
        msgid = "HOST_NEW"
        msg = f"Novo host [{risk}]: {result.get('hostname','')}"
    syslog_write(sev, msgid, msg,
                 hostname    = str(result.get("hostname",    "")),
                 campanha    = str(result.get("campanha",    "")),
                 ip          = str(result.get("ip",          "")),
                 asn         = str(result.get("asn",         "")),
                 environment = str(result.get("environment", "")),
                 risk        = risk,
                 http_status = str(result.get("http_status", "")),
                 waf         = str(result.get("waf",         "NAO")),
                 dnssec      = str(result.get("dnssec",      "DESABILITADO")),
                 ssl_status  = str((result.get("ssl") or {}).get("status","SEM CERTIFICADO")),
                 origem      = str(result.get("origem",      "wordlist")),
                 whois_status= str((result.get("whois") or {}).get("status","DESCONHECIDO")),
                 whois_age   = str((result.get("whois") or {}).get("age_days","")),
                 status      = status,
                 abuse_score = str(abuse.get("abuse_confidence_score","N/A")),
                 tor         = str(bool(abuse.get("is_tor",0))),
                 reports     = str(abuse.get("total_reports","N/A")),
                 urlscan_seen   = str(bool((result.get("urlscan") or {}).get("seen", False))),
                 urlscan_server = str((result.get("urlscan") or {}).get("server","")),
                 urlscan_ip     = str((result.get("urlscan") or {}).get("ip","")),
                 urlscan_asn    = str((result.get("urlscan") or {}).get("asnname","")),
                 urlscan_country= str((result.get("urlscan") or {}).get("country","")),
                 urlscan_uuid   = str((result.get("urlscan") or {}).get("scan_uuid","")))

def syslog_error(context: str, exc: Exception):
    syslog_write("ERR","SCAN_ERR",f"{context}: {exc}",
                 module=SYSLOG_APP, context=context, error_type=type(exc).__name__)

def syslog_end(novos, reincidentes, removidos, duration_s: int, status: str = "success"):
    all_risk = novos + reincidentes
    criticos = sum(1 for r in all_risk if r.get("risk")=="CRITICO")
    altos    = sum(1 for r in all_risk if r.get("risk")=="ALTO")
    sev = "INFO" if status == "success" else "ERR"
    syslog_write(sev,"SCAN_END",
                 f"Scan {status} em {duration_s}s — novos={len(novos)} reincidentes={len(reincidentes)} removidos={len(removidos)} criticos={criticos}",
                 module=SYSLOG_APP, status=status,
                 novos=str(len(novos)), reincidentes=str(len(reincidentes)),
                 removidos=str(len(removidos)), criticos=str(criticos),
                 altos=str(altos), duration_s=str(duration_s))
    _syslog_close()

# ============================================================
# DATABASE
# ============================================================

def init_database():
    conn   = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS subdomains (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            campanha    TEXT,
            hostname    TEXT,
            ip          TEXT,
            cname       TEXT,
            asn         TEXT,
            ip_type     TEXT,
            environment TEXT,
            http_status TEXT,
            waf         TEXT,
            risk        TEXT,
            first_seen  TEXT,
            last_seen   TEXT,
            status      TEXT
        )
    """)
    for col, dfn in [("campanha","TEXT DEFAULT ''"),("waf","TEXT DEFAULT 'NAO'"),
                     ("dnssec","TEXT DEFAULT 'DESABILITADO'"),
                     ("ssl_status","TEXT DEFAULT 'SEM CERTIFICADO'"),
                     ("ssl_expiry","TEXT DEFAULT ''"),
                     ("origem","TEXT DEFAULT 'wordlist'"),
                     ("whois_creation","TEXT DEFAULT ''"),
                     ("whois_expiry","TEXT DEFAULT ''"),
                     ("whois_age_days","INTEGER DEFAULT -1"),
                     ("whois_status","TEXT DEFAULT 'DESCONHECIDO'"),
                     ("whois_registrar","TEXT DEFAULT ''")]:
        try: cursor.execute(f"ALTER TABLE subdomains ADD COLUMN {col} {dfn}")
        except sqlite3.OperationalError: pass
    for col in ("title",):
        try: cursor.execute(f"ALTER TABLE subdomains DROP COLUMN {col}")
        except sqlite3.OperationalError: pass
    conn.commit(); conn.close()

# Validação de entrada (segurança — OWASP A03): domínios/labels só podem conter
# caracteres válidos de hostname. Rejeita metacaracteres que poderiam alterar a
# URL/consulta DNS. Entradas legítimas não mudam; inválidas são ignoradas.
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9_-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9_-]{1,63}(?<!-))*$")
_LABEL_RE = re.compile(r"^(?!-)[A-Za-z0-9_-]{1,63}(?<!-)$")

def _valid_domain(s: str) -> bool:
    return bool(_HOSTNAME_RE.match(s))

def _valid_sub(s: str) -> bool:
    # entradas da wordlist são labels (ex.: "api", "dev-app"); aceita rótulo único
    return bool(_LABEL_RE.match(s))


def load_campaigns() -> list[tuple[str, list[str]]]:
    target_path = Path(TARGETS_DIR)
    if not target_path.exists():
        raise FileNotFoundError(
            f"Diretório de targets não encontrado: {target_path.absolute()}\n"
            f"Crie o diretório e adicione arquivos .txt com os domínios.")
    campaign_files = sorted(target_path.glob("*.txt"))
    if not campaign_files:
        raise FileNotFoundError(f"Nenhum arquivo .txt encontrado em {target_path.absolute()}")
    campaigns = []
    for f in campaign_files:
        domains, skipped = [], 0
        for raw in f.read_text(encoding="utf-8").splitlines():
            # Remove comentário inline: "exemplo.com  # nota" → "exemplo.com".
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            if not _valid_domain(line):
                print(f"  [AVISO] {f.stem}: domínio inválido ignorado: {line!r}")
                skipped += 1
                continue
            domains.append(line)
        if domains:
            campaigns.append((f.stem, domains))
            extra = f" ({skipped} inválido(s) ignorado(s))" if skipped else ""
            print(f"  [TARGETS] {f.stem}: {len(domains)} domínio(s){extra}")
    return campaigns

def load_subs() -> list[str]:
    p = Path(SUBS_FILE)
    if not p.exists():
        raise FileNotFoundError(f"Arquivo {SUBS_FILE} não encontrado.")
    subs = []
    for raw in p.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if line and _valid_sub(line):
            subs.append(line)
    return subs

# ============================================================
# IP TYPE / ASN
# ============================================================

def get_ip_type(ip: str) -> str:
    try: return "PRIVADO" if ipaddress.ip_address(ip).is_private else "PUBLICO"
    except Exception: return "DESCONHECIDO"

async def _batch_asn_ipapi(session: aiohttp.ClientSession, ips: list[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    try:
        async with session.post("http://ip-api.com/batch",
            json=[{"query":ip,"fields":"query,org,as,status"} for ip in ips],
            timeout=aiohttp.ClientTimeout(total=15)) as resp:
            if resp.status == 200:
                for entry in await resp.json(content_type=None):
                    ip_key = entry.get("query","")
                    result[ip_key] = (entry.get("org") or entry.get("as") or "ASN desconhecido") \
                        if entry.get("status")=="success" else "ASN desconhecido"
    except Exception: pass
    return result

async def _single_asn_ipinfo(session: aiohttp.ClientSession, ip: str) -> str:
    for url in (f"https://ipinfo.io/{ip}/org", f"http://ipinfo.io/{ip}/org"):
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=TIMEOUT)) as resp:
                if resp.status == 200:
                    text = (await resp.text()).strip()
                    if text: return text
        except Exception: continue
    return "ASN desconhecido"

async def resolve_asn_bulk(session: aiohttp.ClientSession, results: list[dict]) -> None:
    ip_indices: dict[str, list[int]] = {}
    for idx, r in enumerate(results):
        if r.get("ip_type") == "PUBLICO" and r.get("asn") == "ASN desconhecido":
            ip_indices.setdefault(r["ip"], []).append(idx)
    unique_ips = list(ip_indices.keys())
    if not unique_ips: return
    print(f"[ASN] Resolvendo {len(unique_ips)} IPs únicos...")
    asn_cache: dict[str, str] = {}
    for i in range(0, len(unique_ips), ASN_BATCH_SIZE):
        asn_cache.update(await _batch_asn_ipapi(session, unique_ips[i:i+ASN_BATCH_SIZE]))
    sem = asyncio.Semaphore(10)
    async def fallback(ip: str) -> None:
        async with sem: asn_cache[ip] = await _single_asn_ipinfo(session, ip)
    failed = [ip for ip in unique_ips if asn_cache.get(ip) == "ASN desconhecido"]
    if failed:
        print(f"[ASN] Fallback ipinfo.io para {len(failed)} IPs...")
        await asyncio.gather(*[fallback(ip) for ip in failed])
    for ip, indices in ip_indices.items():
        resolved = asn_cache.get(ip, "ASN desconhecido")
        for idx in indices: results[idx]["asn"] = resolved

# ============================================================
# ENVIRONMENT / WAF / RISK
# ============================================================

def detect_environment(hostname: str) -> str:
    h = hostname.lower()
    if "dev" in h: return "DEV"
    if any(x in h for x in ("hml","hom","homolog")): return "HML"
    return "PROD"

# Detecção passiva via headers e NOMES de cookies. Cada assinatura é:
#   (tipo, chave, agulha|None, rótulo)
#   tipo "h" = header (agulha = substring exigida no valor, ou None p/ só existir)
#   tipo "c" = nome de cookie (substring no conjunto de nomes de cookies)
#
# Assinaturas de WAF DEDICADO (produto de segurança de aplicação) — sinal forte
# de que há proteção de aplicação ativa. Têm precedência sobre CDN.
_WAF_SIGS = [
    ("h", "x-sucuri-id",             None,        "Sucuri"),
    ("h", "x-sucuri-cache",          None,        "Sucuri"),
    ("h", "x-iinfo",                 None,        "Imperva/Incapsula"),
    ("h", "x-cdn",                   "incapsula", "Imperva/Incapsula"),
    ("h", "x-cdn",                   "imperva",   "Imperva"),
    ("h", "x-protected-by",          "sucuri",    "Sucuri"),
    ("h", "x-protected-by",          "wordfence", "Wordfence"),
    ("h", "x-reblaze-protection",    None,        "Reblaze"),
    ("h", "x-barracuda-connect",     None,        "Barracuda"),
    ("h", "cf-mitigated",            None,        "Cloudflare WAF"),
    ("h", "x-wzws-requested-method", None,        "WangZhan WAF"),
    ("h", "server",                  "mod_security", "ModSecurity"),
    ("h", "server",                  "modsecurity",  "ModSecurity"),
    ("h", "server",                  "fortiweb",  "FortiWeb"),
    ("h", "server",                  "barracuda", "Barracuda"),
    ("h", "server",                  "airlock",   "Airlock"),
    ("c", "incap_ses",               None,        "Imperva/Incapsula"),
    ("c", "visid_incap",             None,        "Imperva/Incapsula"),
    ("c", "aws-waf-token",           None,        "AWS WAF"),
    ("c", "awswaf",                  None,        "AWS WAF"),
    ("c", "barra_counter_session",   None,        "Barracuda"),
    ("c", "sucuri",                  None,        "Sucuri"),
]

# Assinaturas de CDN / proxy reverso. ATENÇÃO: indicam proxy na frente do host,
# NÃO necessariamente um WAF ativo (o WAF pode estar desligado). Por isso o rótulo
# distingue "CDN" de "WAF". Confirmar WAF ativo exige sonda comportamental.
_CDN_SIGS = [
    ("h", "cf-ray",                  None,        "Cloudflare"),
    ("h", "cf-cache-status",         None,        "Cloudflare"),
    ("h", "server",                  "cloudflare", "Cloudflare"),
    ("c", "__cf_bm",                 None,        "Cloudflare"),
    ("c", "__cfduid",                None,        "Cloudflare"),
    ("h", "x-amz-cf-id",             None,        "Amazon CloudFront"),
    ("h", "x-amz-cf-pop",            None,        "Amazon CloudFront"),
    ("h", "server",                  "cloudfront", "Amazon CloudFront"),
    ("h", "x-amzn-requestid",        None,        "AWS"),
    ("h", "x-amzn-trace-id",         None,        "AWS"),
    ("h", "server",                  "awselb",    "AWS ELB"),
    ("c", "awsalb",                  None,        "AWS ELB"),
    ("c", "awsalbcors",              None,        "AWS ELB"),
    ("h", "x-akamai-transformed",    None,        "Akamai"),
    ("h", "akamai-cache-status",     None,        "Akamai"),
    ("h", "akamai-grn",              None,        "Akamai"),
    ("c", "ak_bmsc",                 None,        "Akamai"),
    ("h", "x-fastly-request-id",     None,        "Fastly"),
    ("h", "x-azure-ref",             None,        "Azure Front Door"),
    ("h", "x-msedge-ref",            None,        "Azure Front Door"),
    ("h", "server",                  "bigip",     "F5 BIG-IP"),
    ("c", "bigipserver",             None,        "F5 BIG-IP"),
]

def detect_waf(headers: dict) -> str:
    """
    Detecção PASSIVA de WAF/CDN a partir de headers e nomes de cookies.
    Retorna "WAF (<vendor>)", "CDN (<vendor>)" ou "NAO".

    Limitação: a presença de CDN (Cloudflare/CloudFront/Fastly/Akamai/...) indica
    proxy reverso, NÃO garante WAF ativo. Confirmar exige sonda comportamental
    (enviar payload suspeito e observar bloqueio) — não realizada aqui.
    """
    h = {k.lower(): str(v).lower() for k, v in headers.items()}
    # Nomes de cookies agregados por fetch_headers na chave sintética.
    cookies = h.get("set-cookie-names", "")

    def _match(sigs):
        for typ, key, needle, label in sigs:
            if typ == "h":
                if key in h and (needle is None or needle in h[key]):
                    return label
            elif key in cookies:   # tipo "c": nome de cookie
                return label
        return None

    waf = _match(_WAF_SIGS)
    if waf:
        return f"WAF ({waf})"
    cdn = _match(_CDN_SIGS)
    if cdn:
        return f"CDN ({cdn})"
    return "NAO"

_MGMT_KEYWORDS = [
    "grafana","prometheus","kibana","elasticsearch","zabbix","nagios","icinga","netdata",
    "influxdb","jenkins","gitlab","sonarqube","nexus","artifactory","jira","confluence",
    "bitbucket","portainer","rancher","k8s","kubernetes","traefik","airflow",
    "phpmyadmin","adminer","pgadmin","redisinsight","vault","consul","keycloak",
    "swagger","api-docs","ftp","sftp","vpn","rdp",
]

def calculate_base_risk(hostname: str, ip_type: str = "PUBLICO",
                        environment: str = "PROD", waf: str = "NAO") -> str:
    is_exposed = ip_type == "PUBLICO" and waf == "NAO"
    h = hostname.lower()
    if is_exposed and environment in ("DEV","HML"): return "CRITICO"
    if is_exposed: return "ALTO"
    if ip_type == "PUBLICO" and any(kw in h for kw in _MGMT_KEYWORDS): return "MEDIO"
    return "BAIXO"

# ============================================================
# DNS / HTTP
# ============================================================

async def resolve_hostname(resolver: aiodns.DNSResolver, hostname: str) -> str | None:
    try:
        result = await resolver.getaddrinfo(hostname, family=socket.AF_INET)
        return result.nodes[0].addr[0].decode()
    except Exception: return None

async def resolve_cname(resolver: aiodns.DNSResolver, hostname: str) -> str:
    try:
        result = await resolver.query_dns(hostname, "CNAME")
        return result.answer[0].data.cname
    except Exception: return "-"

_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
]
_ua_idx = 0
def _next_ua() -> str:
    global _ua_idx; ua = _USER_AGENTS[_ua_idx % len(_USER_AGENTS)]; _ua_idx += 1; return ua

def _headers_plus_cookies(resp) -> dict:
    """dict de headers + chave sintética 'set-cookie-names' com os NOMES dos
    cookies (em minúsculas). Usada só pelo detect_waf para assinaturas por cookie."""
    h = dict(resp.headers)
    try:
        names = " ".join(resp.cookies.keys()).lower()
        if names:
            h["set-cookie-names"] = names
    except Exception:
        pass
    return h

async def fetch_headers(session: aiohttp.ClientSession, hostname: str) -> tuple[str, dict]:
    _timeout = aiohttp.ClientTimeout(total=3)
    hdrs = {"User-Agent":_next_ua(),"Accept":"text/html,*/*;q=0.8","Accept-Language":"pt-BR,pt;q=0.9","Connection":"close"}
    for scheme in ("https","http"):
        url = f"{scheme}://{hostname}"
        try:
            async with session.head(url, ssl=False, headers=hdrs, allow_redirects=False, timeout=_timeout) as resp:
                if resp.status != 405: return str(resp.status), _headers_plus_cookies(resp)
        except Exception: pass
        try:
            async with session.get(url, ssl=False, headers={**hdrs,"Range":"bytes=0-0"},
                                   allow_redirects=False, timeout=_timeout) as resp:
                await resp.read(); return str(resp.status), _headers_plus_cookies(resp)
        except Exception: continue
    return "-", {}


# ============================================================
# DNSSEC CHECK
# ============================================================

# DNSSEC usa dnspython (aiodns/c-ares não suporta DNSKEY/DS).
# A consulta é síncrona, então roda em executor para não bloquear o loop.
try:
    import dns.resolver as _dns_resolver
    _DNSSEC_AVAILABLE = True
except ImportError:
    _DNSSEC_AVAILABLE = False

# Cache de DNSSEC por domínio base (evita reconsultar o mesmo domínio
# para cada subdomínio da mesma campanha)
_dnssec_cache: dict[str, str] = {}


def _check_dnssec_sync(hostname: str) -> str:
    """Consulta síncrona de DNSSEC. Verifica DNSKEY do domínio base."""
    if not _DNSSEC_AVAILABLE:
        return "DESCONHECIDO"

    parts = hostname.rstrip(".").split(".")
    # Verifica do domínio base (2 últimos labels para .com, 3 para .com.br)
    # Tenta do registrable domain para cima
    candidates = []
    if len(parts) >= 3:
        candidates.append(".".join(parts[-3:]))  # empresa.com.br
    if len(parts) >= 2:
        candidates.append(".".join(parts[-2:]))  # empresa.com

    for domain in candidates:
        if domain in _dnssec_cache:
            return _dnssec_cache[domain]
        try:
            resolver = _dns_resolver.Resolver()
            resolver.timeout  = 4
            resolver.lifetime = 5
            answer = resolver.resolve(domain, "DNSKEY")
            if answer and len(answer) > 0:
                _dnssec_cache[domain] = "HABILITADO"
                return "HABILITADO"
        except Exception:
            pass

    # Marca o último candidato como desabilitado no cache
    if candidates:
        _dnssec_cache[candidates[0]] = "DESABILITADO"
    return "DESABILITADO"


async def check_dnssec(resolver: aiodns.DNSResolver, hostname: str) -> str:
    """
    Verifica se o domínio tem DNSSEC habilitado (zona assinada com DNSKEY).
    Roda a consulta síncrona dnspython em executor para não bloquear o loop.
    Retorna: "HABILITADO", "DESABILITADO" ou "DESCONHECIDO"
    """
    if not _DNSSEC_AVAILABLE:
        return "DESCONHECIDO"
    try:
        loop = asyncio.get_event_loop()
        return await asyncio.wait_for(
            loop.run_in_executor(None, _check_dnssec_sync, hostname),
            timeout=8
        )
    except Exception:
        return "DESCONHECIDO"


# ============================================================
# SSL CERTIFICATE CHECK
# ============================================================

async def check_ssl_cert(hostname: str, port: int = 443) -> dict:
    """
    Verifica certificado SSL do hostname.
    Retorna dict com:
      - valid: bool
      - expiry_date: str (YYYY-MM-DD)
      - days_remaining: int
      - issuer: str
      - status: "VÁLIDO", "EXPIRADO", "EXPIRANDO (<30 dias)", "SEM CERTIFICADO"
    """
    empty = {
        "valid": False, "expiry_date": "", "days_remaining": -1,
        "issuer": "", "status": "SEM CERTIFICADO"
    }
    try:
        loop = asyncio.get_event_loop()

        def _get_cert():
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_OPTIONAL
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    return ssock.getpeercert()

        cert = await asyncio.wait_for(
            loop.run_in_executor(None, _get_cert), timeout=7
        )

        if not cert:
            return empty

        # Extrai data de expiração
        not_after_str = cert.get("notAfter", "")
        if not not_after_str:
            return empty

        expiry = datetime.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
        expiry = expiry.replace(tzinfo=datetime.timezone.utc)
        now    = datetime.datetime.now(datetime.timezone.utc)
        days   = (expiry - now).days

        # Extrai issuer legível
        issuer_raw = cert.get("issuer", ())
        issuer_map = {k: v for t in issuer_raw for k, v in t}
        issuer     = issuer_map.get("organizationName", issuer_map.get("commonName", "Desconhecido"))

        if days < 0:
            status = "EXPIRADO"
        elif days < 30:
            status = f"EXPIRANDO ({days}d)"
        else:
            status = "VÁLIDO"

        return {
            "valid":          days >= 0,
            "expiry_date":    expiry.strftime("%Y-%m-%d"),
            "days_remaining": days,
            "issuer":         issuer[:60],
            "status":         status,
        }

    except (socket.timeout, ConnectionRefusedError, OSError):
        return empty
    except Exception:
        return empty


# ============================================================
# ENUMERATION
# ============================================================

async def resolve_subdomain(resolver: aiodns.DNSResolver, hostname: str,
                            campanha: str, dns_sem: asyncio.Semaphore,
                            origem: str = "wordlist") -> dict | None:
    async with dns_sem:
        ip = await resolve_hostname(resolver, hostname)
        if not ip: return None
        cname   = await resolve_cname(resolver, hostname)
        ip_type = get_ip_type(ip)
        return {"campanha":campanha,"hostname":hostname,"ip":ip,"cname":cname,
                "ip_type":ip_type,"environment":detect_environment(hostname),
                "asn":"REDE PRIVADA" if ip_type=="PRIVADO" else "ASN desconhecido",
                "origem":origem,"abuse":None}

async def probe_subdomain(session: aiohttp.ClientSession, entry: dict,
                          http_sem: asyncio.Semaphore,
                          resolver: aiodns.DNSResolver) -> dict:
    async with http_sem:
        http_status, hdrs = await fetch_headers(session, entry["hostname"])
    waf  = detect_waf(hdrs)
    risk = calculate_base_risk(entry["hostname"], entry["ip_type"], entry["environment"], waf)

    # DNSSEC — verifica se a zona está assinada
    dnssec = await check_dnssec(resolver, entry["hostname"])

    # SSL — só verifica se o host respondeu HTTP (evita timeout em hosts mortos)
    ssl_info = {"valid": False, "expiry_date": "", "days_remaining": -1,
                "issuer": "", "status": "SEM CERTIFICADO"}
    if http_status not in ("-", ""):
        ssl_info = await check_ssl_cert(entry["hostname"])

    return {**entry, "http_status":http_status, "waf":waf, "risk":risk,
            "dnssec":dnssec, "ssl":ssl_info}

def _build_candidates(campaigns: list[tuple[str, list[str]]],
                      subs: list[str]) -> dict[tuple[str, str], str]:
    """
    Constrói o dicionário de candidatos a resolver.

    Chave:  (hostname, campanha)
    Valor:  origem ("wordlist" ou "crtsh")

    1. Gera candidatos da wordlist (subs × domínios × prefixos)
    2. Consulta crt.sh para cada domínio e injeta os subdomínios descobertos
    3. Se um hostname já existe pela wordlist, mantém origem "wordlist"
       (não sobrescreve — a wordlist tem precedência por ser determinística)
    """
    candidates: dict[tuple[str, str], str] = {}

    # 1. Candidatos da wordlist
    for campanha, domains in campaigns:
        for domain in domains:
            for sub in subs:
                for prefix in PREFIXES:
                    host = f"{prefix}{sub}.{domain}"
                    candidates[(host, campanha)] = "wordlist"

    # 2. Candidatos do crt.sh (Certificate Transparency)
    if _CRTSH_AVAILABLE:
        for campanha, domains in campaigns:
            for domain in domains:
                discovered = crtsh.get_subdomains_safe(domain)
                if discovered:
                    print(f"  [CRT.SH] {domain}: {len(discovered)} nome(s) em Certificate Transparency")
                for host in discovered:
                    key = (host, campanha)
                    # Só adiciona se ainda não veio da wordlist
                    if key not in candidates:
                        candidates[key] = "crtsh"
    else:
        print("  [CRT.SH] provider indisponível — pulando descoberta passiva")

    # 3. Candidatos do urlscan.io (Search API, passivo)
    if _URLSCAN_AVAILABLE:
        for campanha, domains in campaigns:
            for domain in domains:
                discovered = urlscan.get_subdomains_safe(domain)
                if discovered:
                    print(f"  [URLSCAN] {domain}: {len(discovered)} nome(s) em scans históricos")
                for host in discovered:
                    key = (host, campanha)
                    # Não sobrescreve origem da wordlist/crtsh (precedência por ordem)
                    if key not in candidates:
                        candidates[key] = "urlscan"
    else:
        print("  [URLSCAN] provider indisponível — pulando descoberta passiva")

    return candidates


async def run_scan(campaigns: list[tuple[str, list[str]]], subs: list[str]) -> list[dict]:
    resolver  = aiodns.DNSResolver(timeout=3)
    dns_sem   = asyncio.Semaphore(CONCURRENCY * 4)
    http_sem  = asyncio.Semaphore(CONCURRENCY)
    connector = aiohttp.TCPConnector(limit=CONCURRENCY, ssl=False)

    # Constrói candidatos (wordlist + Certificate Transparency + urlscan)
    print("[+] Coletando candidatos (wordlist + crt.sh + urlscan)...")
    candidates = _build_candidates(campaigns, subs)
    n_wordlist = sum(1 for o in candidates.values() if o == "wordlist")
    n_crtsh    = sum(1 for o in candidates.values() if o == "crtsh")
    n_urlscan  = sum(1 for o in candidates.values() if o == "urlscan")
    print(f"[+] Candidatos: {len(candidates)} total | {n_wordlist} wordlist | {n_crtsh} crt.sh | {n_urlscan} urlscan")

    async with aiohttp.ClientSession(connector=connector,
                                     timeout=aiohttp.ClientTimeout(total=30)) as session:
        tasks_dns = [
            resolve_subdomain(resolver, host, campanha, dns_sem, origem)
            for (host, campanha), origem in candidates.items()
        ]
        print(f"[+] Total de hostnames a verificar: {len(tasks_dns)}")

        dns_raw  = await asyncio.gather(*tasks_dns, return_exceptions=True)
        resolved = [r for r in dns_raw if r and not isinstance(r, BaseException)]
        for r in dns_raw:
            if isinstance(r, BaseException): syslog_error("dns_phase", r)
        n_res_crtsh = sum(1 for r in resolved if r.get("origem") == "crtsh")
        print(f"[+] Hosts resolvidos via DNS: {len(resolved)} (sendo {n_res_crtsh} via crt.sh)")

        http_raw = await asyncio.gather(
            *[probe_subdomain(session, entry, http_sem, resolver) for entry in resolved],
            return_exceptions=True)
        results = [r for r in http_raw if r and not isinstance(r, BaseException)]
        for r in http_raw:
            if isinstance(r, BaseException): syslog_error("http_phase", r)
        print(f"[+] Hosts ativos encontrados: {len(results)}")

        await resolve_asn_bulk(session, results)

    # Enriquecimento WHOIS (idade/criação/expiração do domínio base)
    # Feito fora da sessão HTTP pois python-whois é síncrono (porta 43).
    if _WHOIS_AVAILABLE and results:
        print(f"[WHOIS] Consultando dados de registro dos domínios...")
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, whois_lookup.enrich_with_whois, results)
        n_novos = sum(1 for r in results if (r.get("whois") or {}).get("status") == "NOVO")
        if n_novos:
            print(f"[WHOIS] ⚠ {n_novos} domínio(s) recém-criado(s) (<30 dias) — possível risco")

    # Enriquecimento urlscan.io (contexto do último scan conhecido por host).
    # Síncrono (urllib) e fora da sessão HTTP — roda em executor.
    if _URLSCAN_AVAILABLE and results:
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, urlscan.enrich_results, results)
    return results

# ============================================================
# DATABASE PROCESS
# ============================================================

def process_results(results: list[dict]):
    conn   = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    now    = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    novos, reincidentes, removidos = [], [], []
    current_hosts = set()

    for result in results:
        hostname = result["hostname"]
        current_hosts.add(hostname)
        cursor.execute("SELECT id, status FROM subdomains WHERE hostname=? ORDER BY id DESC LIMIT 1", (hostname,))
        existing = cursor.fetchone()
        if existing:
            new_status = "RESSURGIDO" if existing[1] == "CORRIGIDO" else "REINCIDENTE"
            result["status"] = new_status; reincidentes.append(result); syslog_host(result)
            cursor.execute(
                "UPDATE subdomains SET campanha=?,ip=?,cname=?,asn=?,ip_type=?,environment=?,http_status=?,waf=?,risk=?,dnssec=?,ssl_status=?,ssl_expiry=?,origem=?,whois_creation=?,whois_expiry=?,whois_age_days=?,whois_status=?,whois_registrar=?,last_seen=?,status=? WHERE id=?",
                (result["campanha"],result["ip"],result["cname"],result["asn"],result["ip_type"],
                 result["environment"],result["http_status"],result.get("waf","NAO"),result["risk"],
                 result.get("dnssec","DESABILITADO"),
                 (result.get("ssl") or {}).get("status","SEM CERTIFICADO"),
                 (result.get("ssl") or {}).get("expiry_date",""),
                 result.get("origem","wordlist"),
                 (result.get("whois") or {}).get("creation_date",""),
                 (result.get("whois") or {}).get("expiration_date",""),
                 (result.get("whois") or {}).get("age_days") if (result.get("whois") or {}).get("age_days") is not None else -1,
                 (result.get("whois") or {}).get("status","DESCONHECIDO"),
                 (result.get("whois") or {}).get("registrar",""),
                 now,new_status,existing[0]))
        else:
            result["status"] = "NOVO"; novos.append(result); syslog_host(result)
            cursor.execute(
                "INSERT INTO subdomains (campanha,hostname,ip,cname,asn,ip_type,environment,http_status,waf,risk,dnssec,ssl_status,ssl_expiry,origem,whois_creation,whois_expiry,whois_age_days,whois_status,whois_registrar,first_seen,last_seen,status) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (result["campanha"],result["hostname"],result["ip"],result["cname"],result["asn"],
                 result["ip_type"],result["environment"],result["http_status"],
                 result.get("waf","NAO"),result["risk"],
                 result.get("dnssec","DESABILITADO"),
                 (result.get("ssl") or {}).get("status","SEM CERTIFICADO"),
                 (result.get("ssl") or {}).get("expiry_date",""),
                 result.get("origem","wordlist"),
                 (result.get("whois") or {}).get("creation_date",""),
                 (result.get("whois") or {}).get("expiration_date",""),
                 (result.get("whois") or {}).get("age_days") if (result.get("whois") or {}).get("age_days") is not None else -1,
                 (result.get("whois") or {}).get("status","DESCONHECIDO"),
                 (result.get("whois") or {}).get("registrar",""),
                 now,now,"NOVO"))

    # Carência: só marca REMOVIDO se o host estiver sem ser visto há ≥ CLOSE_GRACE_DAYS
    # (absorve falhas transitórias de DNS / fontes passivas — não remove por 1 miss).
    grace_cutoff = (datetime.datetime.now() - datetime.timedelta(days=CLOSE_GRACE_DAYS)).strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("SELECT id,hostname,ip,campanha FROM subdomains WHERE status IN ('REINCIDENTE','RESSURGIDO') AND last_seen < ?", (grace_cutoff,))
    for row_id, old_hostname, old_ip, old_campanha in cursor.fetchall():
        if old_hostname not in current_hosts:
            entry = {"hostname":old_hostname,"ip":old_ip or "","campanha":old_campanha or "",
                     "risk":"INFO","status":"CORRIGIDO","asn":"","environment":"",
                     "http_status":"","waf":"NAO","abuse":None,
                     "dnssec":"DESABILITADO","origem":"wordlist",
                     "ssl":{"status":"SEM CERTIFICADO","expiry_date":""},
                     "whois":{"creation_date":"","expiration_date":"","age_days":None,
                              "status":"DESCONHECIDO","registrar":""}}
            removidos.append(entry); syslog_host(entry)
            cursor.execute("UPDATE subdomains SET status='CORRIGIDO', last_seen=? WHERE id=?", (now, row_id))
    conn.commit(); conn.close()
    return novos, reincidentes, removidos

# ============================================================
# CRON
# ============================================================

def setup_cron():
    import shutil
    script_path = Path(__file__).resolve()
    python_bin  = shutil.which("python3") or "/usr/bin/python3"
    log_stdout  = Path(SYSLOG_FILE).parent / "submonitor_stdout.log"
    cron_file   = Path("/etc/cron.d/argus-submonitor")
    # PYTHONPATH = raiz da instalação (pai do diretório submonitor/), derivada do
    # próprio caminho do script para não chumbar um diretório fixo.
    ti_path     = str(script_path.parent.parent)
    # umask 0002: arquivos auxiliares do SQLite (-wal/-shm) ficam graváveis pelo
    # grupo, permitindo escrita compartilhada nas bases de Threat Intel.
    cron_content = (
        "# submonitor — scan de subdominios diariamente as 12h00\n"
        "# Para remover: sudo rm /etc/cron.d/argus-submonitor\n"
        "SHELL=/bin/bash\n"
        "PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n"
        f"PYTHONPATH={ti_path}\n\n"
        f"0 12 * * * root umask 0002 && cd {script_path.parent} && {python_bin} {script_path} >> {log_stdout} 2>&1\n"
    )
    try:
        cron_file.write_text(cron_content, encoding="utf-8"); cron_file.chmod(0o644)
        print(f"[+] Cron instalado : {cron_file}")
        print( "    Agenda         : diariamente as 12h00 (0 12 * * *)")
        print(f"    Script         : {script_path}")
        print(f"    Stdout/stderr  : {log_stdout}")
        print(f"    PYTHONPATH     : {ti_path}")
        print(f"    Syslog RFC5424 : {SYSLOG_FILE}")
        print("\n    Para remover:  sudo rm /etc/cron.d/argus-submonitor")
    except PermissionError:
        print("[!] Permissão negada — execute como root:")
        print(f"    sudo python3 {script_path} --install-cron")

# ============================================================
# MAIN
# ============================================================

def _fmt_duration(seconds: int) -> str:
    if seconds < 60: return f"{seconds}s"
    m, s = divmod(seconds, 60)
    if m < 60: return f"{m}m {s:02d}s"
    h, m = divmod(m, 60); return f"{h}h {m:02d}m {s:02d}s"

def main():
    if "--install-cron" in sys.argv: setup_cron(); return

    # Garante que os caminhos relativos resolvam a partir do diretório do script.
    os.chdir(Path(__file__).resolve().parent)

    _start = time.monotonic()
    print("=" * 60)
    print("ARGUS — Subdomain Monitor  (DNS/HTTP + crt.sh/urlscan/RDAP)")
    print("=" * 60)

    if _THREATINTEL_AVAILABLE:
        print("[INFO] Módulo threatintel carregado — reputação AbuseIPDB ativa"); _ti_init_db()
    else:
        print("[AVISO] Módulo threatintel não encontrado — reputação desativada")
        print("         Configure PYTHONPATH=/etc/argus para ativar")

    init_database()
    print()
    print("[+] Carregando campanhas...")
    try:
        campaigns = load_campaigns()
        subs      = load_subs()
    except FileNotFoundError as exc:
        print(f"[ERRO] {exc}"); sys.exit(1)

    total_domains = sum(len(d) for _, d in campaigns)
    print(f"[+] {len(campaigns)} campanha(s) | {total_domains} domínio(s) | {len(subs)} sub(s) | {len(PREFIXES)} prefixo(s)")
    syslog_init(len(campaigns), total_domains, len(subs), len(PREFIXES))
    print()

    try:
        results = asyncio.run(run_scan(campaigns, subs))

        if _THREATINTEL_AVAILABLE:
            print()
            _ti_enrich(results)
            for r in results:
                base = calculate_base_risk(r["hostname"], r["ip_type"],
                                           r["environment"], r.get("waf","NAO"))
                r["risk"] = _ti_risk(base, r["ip_type"], r.get("abuse"))

            # Shodan InternetDB (vulnerabilidades/CVE) — enriquece e eleva (leve)
            if _internetdb is not None:
                try:
                    _internetdb.enrich_results(results)
                    for r in results:
                        r["risk"] = _internetdb.vuln_elevate(r["risk"], r.get("internetdb"))
                except Exception as _exc:
                    print(f"[INTERNETDB] enriquecimento ignorado: {_exc}")

            # CISA KEV — cruza as CVEs do InternetDB com o catálogo de explorados
            # in-the-wild e eleva (KEV = alta confiança → CRÍTICO por padrão).
            if _cisa_kev is not None:
                try:
                    _cisa_kev.enrich_results(results)
                    for r in results:
                        r["risk"] = _cisa_kev.kev_elevate(r["risk"], r.get("kev"))
                except Exception as _exc:
                    print(f"[CISA-KEV] enriquecimento ignorado: {_exc}")

        novos, reincidentes, removidos = process_results(results)

        # ── Store central de achados (argus.db) — ADITIVO ─────────
        # Cada subdomínio ativo é um ativo exposto rastreável (severidade real).
        if _findings is not None:
            try:
                obs, closed = _findings.sync_findings(
                    "submonitor", novos + reincidentes,
                    key_of=lambda r: r.get("hostname", ""),
                    severity_of=lambda r: r.get("risk", "INFO"),
                    title_of=lambda r: r.get("hostname", ""),
                    campanha_of=lambda r: r.get("campanha", ""),
                    details_of=lambda r: {"ip": r.get("ip",""), "environment": r.get("environment",""),
                                          "http_status": r.get("http_status",""), "waf": r.get("waf","")},
                    corrected=removidos,
                    resurged=[r for r in reincidentes if r.get("status") == "RESSURGIDO"],
                    run_id=str(_run_id or ""))
                print(f"[FINDINGS] argus.db: {obs} observado(s), {closed} fechado(s)")
                try:
                    from reporter import write_findings_page as _wfp
                    if _wfp(APACHE_DOCROOT): print("[FINDINGS] página de Gestão de Achados atualizada")
                except Exception: pass
            except Exception as _exc:
                print(f"[FINDINGS] sync ignorado (não crítico): {_exc}")

        # ── Reconhecimento (RECONHECIDO -> INFO) ──────────────────
        if ack is not None:
            _ack_n = ack.apply("submonitor", novos, reincidentes)
            if _ack_n:
                print(f"[ACK] {_ack_n} host(s) reconhecido(s) -> status RECONHECIDO / risco INFO")

        # ── Esconde do relatório os hosts cujo ACHADO foi tratado (Mitigado/FP) ──
        if _findings is not None:
            try:
                _hidden = _findings.hidden_keys("submonitor")
                if _hidden:
                    novos        = [r for r in novos        if r.get("hostname") not in _hidden]
                    reincidentes = [r for r in reincidentes if r.get("hostname") not in _hidden]
                    removidos    = [r for r in removidos    if r.get("hostname") not in _hidden]
            except Exception:
                pass

        from pathlib import Path as _Path
        import os as _os, shutil as _shutil
        _docroot      = _Path(APACHE_DOCROOT)
        _docroot_path = _docroot / HTML_REPORT
        _local_path   = HTML_REPORT

        if _docroot.exists() and _docroot_path.is_symlink():
            _docroot_path.unlink()
            print(f"[INFO] Symlink antigo removido: {_docroot_path}")

        _out = str(_docroot_path) if _docroot.exists() else _local_path

        generate_submonitor_report(novos, reincidentes, removidos,
                                   output_path=_out,
                                   threatintel_available=_THREATINTEL_AVAILABLE)
        _os.chmod(_out, 0o644)
        if _out != _local_path:
            _shutil.copy2(_out, _local_path)

        duration_s = int(time.monotonic() - _start)
        syslog_end(novos, reincidentes, removidos, duration_s)

    except Exception as exc:
        duration_s = int(time.monotonic() - _start)
        syslog_error("main", exc); syslog_end([], [], [], duration_s, status="error"); raise

    print()
    print(f"[+] Relatório        : {Path(HTML_REPORT).absolute()}")
    print(f"[+] Log RFC5424      : {SYSLOG_FILE}")
    print(f"[+] Novos            : {len(novos)}")
    print(f"[+] Reincidentes     : {len(reincidentes)}")
    print(f"[+] Corrigidos       : {len(removidos)}")
    print(f"[+] Tempo de execução: {_fmt_duration(duration_s)}")

if __name__ == "__main__":
    main()
