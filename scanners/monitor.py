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
Monitor de Superfície Exposta — Nmap + AbuseIPDB

Lê campanhas de targets/ (um .txt por empresa), escaneia portas,
enriquece com AbuseIPDB e gera relatório HTML via reporter.py.

Uso:
    sudo python3 monitor.py
    sudo python3 monitor.py --install-cron

Estrutura:
    monitor/
        monitor.py
        targets/
            EMPRESA1.txt
            EMPRESA2.txt
        monitor.db      (gerado automaticamente)
        monitor_report.html   (gerado a cada execução)
"""

import datetime
import ipaddress
import os
import re
import socket
import sqlite3
import sys
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import requests

# Filtro de campanha (ARGUS_CAMPANHA): permite rodar uma campanha por vez, sem
# reduzir a cobertura das demais. Import tolerante — sem o módulo, roda tudo.
try:
    from campaigns import filtrar_campanhas as _filtrar_campanhas
except Exception:                                   # pragma: no cover
    def _filtrar_campanhas(arquivos):
        return list(arquivos)

# Teto de paralelismo por campanha (ARGUS_PARALELISMO em campaigns.py): sem
# módulo, cai em 1 — mesmo comportamento em série de sempre.
try:
    from campaigns import paralelismo_da_campanha as _paralelismo_da_campanha
except Exception:                                   # pragma: no cover
    def _paralelismo_da_campanha(nome):
        return 1



try:
    import nmap
except ImportError:
    print("[ERRO] python-nmap não instalado. Execute: pip install python-nmap")
    sys.exit(1)

try:
    from threatintel.core.database import init_database as init_threatintel_db
    from threatintel.core.reputation import compute_final_risk
    from threatintel.providers.abuseipdb import enrich_results
    _THREATINTEL_AVAILABLE = True
except ImportError:
    _THREATINTEL_AVAILABLE = False
    def enrich_results(r):          pass
    def compute_final_risk(p,i,a):  return p
    def init_threatintel_db():      pass

try:
    from threatintel.providers import internetdb as _internetdb
except ImportError:
    _internetdb = None  # enriquecimento de vulnerabilidades (Shodan InternetDB) opcional

try:
    from threatintel.providers import cisa_kev as _cisa_kev
except ImportError:
    _cisa_kev = None  # enriquecimento KEV (CVE explorada in-the-wild) opcional

try:
    from threatintel.providers import virustotal as _virustotal
except ImportError:
    _virustotal = None  # reputação VirusTotal (opcional, exige chave)

try:
    from threatintel.providers import nvd as _nvd
except ImportError:
    _nvd = None  # enriquecimento NVD (CVSS oficial por CVE) opcional

try:
    from reporter import generate_monitor_report
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
DATABASE_FILE = "monitor.db"
HTML_REPORT   = "monitor_report.html"

# Docroot do Apache — relatório é gravado aqui para acesso web imediato.
# Se o diretório não existir, o relatório fica no diretório local.
APACHE_DOCROOT = "/var/www/argus"

TOP_PORTS = "1000"
# -Pn: pula o host discovery e escaneia TODOS os alvos como se estivessem online.
# Essencial para superfície de ataque — muitos hosts bloqueiam ICMP/probes mas
# publicam serviços; sem -Pn eles seriam pulados (scan rápido, porém incompleto).
# Custo: IPs realmente mortos também são varridos (scan mais demorado, ~1-2h).
NMAP_ARGS = f"-Pn -sV --top-ports {TOP_PORTS} -T4 --open"

# ── UDP (opt-in, --udp) ──────────────────────────────────────────────
# Lista CURADA por criticidade (não pela frequência do nmap): 100 portas UDP
# de alto valor para superfície de ataque (OOB/ICS/RCE, VPN, DNS/SIP, poisoning
# e refletores de amplificação). UDP é lento por natureza, então: lista fixa,
# --max-retries 1, --host-timeout e só state=='open' (descarta open|filtered).
UDP_PORTS = (
    "7,17,19,53,67,68,69,88,111,123,137,138,161,162,177,389,443,464,500,512,"
    "513,514,520,521,546,547,623,631,749,1194,1434,1604,1645,1646,1701,1718,"
    "1719,1812,1813,1900,1985,2049,2055,2123,2152,2222,2427,2727,3283,3386,"
    "3389,3478,3479,3480,3481,3702,3784,3785,4500,4569,4789,5004,5005,5009,"
    "5060,5061,5246,5247,5351,5353,5355,5632,5683,5684,6081,6343,6481,7547,"
    "8472,9987,9995,9996,10001,11211,17185,19132,20000,27015,27016,27960,"
    "28015,30718,32414,34964,37810,41794,44818,47808,51820,64738"
)
NMAP_ARGS_UDP = (f"-Pn -sU -sV --version-intensity 0 -p {UDP_PORTS} --open -T4 "
                 "--max-retries 1 --host-timeout 8m --defeat-icmp-ratelimit")

# Janela (dias) para manter portas FECHADAS visíveis no relatório lido do banco.
CLOSED_WINDOW_DAYS = 7
# Carência (dias) antes de marcar uma porta como FECHADA — absorve "misses"
# transitórios (host fora do ar, scan incompleto). Ajustável por env.
CLOSE_GRACE_DAYS = int(os.environ.get("ARGUS_CLOSE_GRACE_DAYS", "3"))

ASN_BATCH_SIZE = 100
# Resolução de ASN: quantas vezes repetir e quanto esperar. A cota do ip-api é por
# minuto, então vale a pena aguardar o reset em vez de desistir e gravar
# "ASN desconhecido" — valor que fica visível no relatório até um scan futuro acertar.
ASN_MAX_TENTATIVAS = 3
ASN_ESPERA_ERRO    = 3      # segundos entre tentativas em erro genérico
ASN_ESPERA_MAX     = 65     # teto de espera no HTTP 429 (janela do ip-api = 60s)

# ============================================================
# SYSLOG RFC 5424
# ============================================================

SYSLOG_FILE = "/var/log/argus/monitor/monitor.log"
SYSLOG_APP  = "monitor"
APP_VERSION = "2.0"

_FAC      = 16
_SEV      = {"EMERG":0,"ALERT":1,"CRIT":2,"ERR":3,"WARN":4,"NOTICE":5,"INFO":6,"DEBUG":7}
_RISK_SEV = {"CRITICO":"CRIT","ALTO":"WARN","MEDIO":"NOTICE","BAIXO":"INFO"}

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
    ts     = datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]+"Z"
    parts  = [f'run_id="{_sd_escape(_run_id)}"'] + [f'{k}="{_sd_escape(v)}"' for k,v in sd.items()]
    line   = f"<{prival}>1 {ts} {_hostname} {SYSLOG_APP} {_pid} {msgid} [origin@32473 {' '.join(parts)}] {str(msg).replace(chr(10),' ')}\n"
    try: _syslog_fd.write(line); _syslog_fd.flush()
    except OSError: pass

def syslog_init(campaigns: int, targets_count: int, transport: str = "tcp"):
    global _run_id, _scan_start
    _run_id = str(uuid.uuid4())
    _scan_start = datetime.datetime.now(datetime.UTC)
    _syslog_open()
    syslog_write("INFO","SCAN_START",f"Iniciando scan {transport}: {campaigns} campanha(s), {targets_count} alvo(s)",
                 module=SYSLOG_APP, version=APP_VERSION, transport=transport,
                 campaigns=str(campaigns), targets=str(targets_count))

def syslog_port(result: dict):
    risk   = result.get("risk","BAIXO")
    status = result.get("status","NOVO")
    sev    = _RISK_SEV.get(risk,"INFO")
    abuse  = result.get("abuse") or {}
    if status == "CORRIGIDO":
        sev = "NOTICE"; msgid = "PORT_FIXED"
        msg = f"Porta corrigida: {result.get('ip')}:{result.get('port')}/{result.get('protocol')}"
    elif status == "RESSURGIDO":
        msgid = "PORT_RESURGED"
        msg = f"Porta ressurgida [{risk}]: {result.get('ip')}:{result.get('port')}/{result.get('protocol')} ({result.get('service','')})"
    elif status == "REINCIDENTE":
        msgid = "PORT_REIN"
        msg = f"Porta reincidente [{risk}]: {result.get('ip')}:{result.get('port')}/{result.get('protocol')} ({result.get('service','')})"
    else:
        msgid = "PORT_NEW"
        msg = f"Nova porta [{risk}]: {result.get('ip')}:{result.get('port')}/{result.get('protocol')} ({result.get('service','')})"
    syslog_write(sev, msgid, msg,
                 campanha    = str(result.get("campanha",  "")),
                 target      = str(result.get("target",    "")),
                 ip          = str(result.get("ip",        "")),
                 port        = str(result.get("port",      "")),
                 protocol    = str(result.get("protocol",  "")),
                 service     = str(result.get("service",   "")),
                 ip_type     = str(result.get("ip_type",   "")),
                 asn         = str(result.get("asn",       "")),
                 risk        = risk, status = status,
                 abuse_score = str(abuse.get("abuse_confidence_score","N/A")),
                 country     = str(abuse.get("country_code","")),
                 tor         = str(bool(abuse.get("is_tor",0))),
                 reports     = str(abuse.get("total_reports","N/A")))

def syslog_error(context: str, exc: Exception):
    syslog_write("ERR","SCAN_ERR",f"{context}: {exc}",
                 module=SYSLOG_APP, context=context, error_type=type(exc).__name__)

def syslog_end(novos, reincidentes, corrigidos, duration_s: int, status: str = "success", transport: str = "tcp"):
    criticos = sum(1 for r in novos+reincidentes if r.get("risk")=="CRITICO")
    altos    = sum(1 for r in novos+reincidentes if r.get("risk")=="ALTO")
    sev = "INFO" if status == "success" else "ERR"
    syslog_write(sev,"SCAN_END",
                 f"Scan {transport} {status} em {duration_s}s — novos={len(novos)} reincidentes={len(reincidentes)} fechados={len(corrigidos)} criticos={criticos}",
                 module=SYSLOG_APP, status=status, transport=transport,
                 novos=str(len(novos)), reincidentes=str(len(reincidentes)),
                 fechados=str(len(corrigidos)), criticos=str(criticos),
                 altos=str(altos), duration_s=str(duration_s))
    _syslog_close()

# ============================================================
# DATABASE
# ============================================================

def init_database():
    conn   = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            campanha    TEXT,
            target      TEXT,
            resolved_ip TEXT,
            ip          TEXT,
            port        INTEGER,
            protocol    TEXT,
            service     TEXT,
            banner      TEXT,
            state       TEXT,
            ip_type     TEXT,
            asn         TEXT,
            risk        TEXT,
            first_seen  TEXT,
            last_seen   TEXT,
            status      TEXT,
            abuse_score   INTEGER DEFAULT -1,
            abuse_country TEXT DEFAULT '',
            abuse_isp     TEXT DEFAULT '',
            abuse_usage   TEXT DEFAULT '',
            abuse_tor     INTEGER DEFAULT 0,
            abuse_reports INTEGER DEFAULT 0,
            abuse_last    TEXT DEFAULT '',
            abuse_source  TEXT DEFAULT '',
            idb_vuln_count INTEGER DEFAULT 0,
            idb_vulns      TEXT DEFAULT '',
            idb_tags       TEXT DEFAULT '',
            idb_ports      TEXT DEFAULT '',
            kev_count      INTEGER DEFAULT 0,
            kev_cves       TEXT DEFAULT '',
            nvd_max_score  REAL DEFAULT 0,
            nvd_severity   TEXT DEFAULT '',
            nvd_scores     TEXT DEFAULT '',
            vt_malicious   INTEGER DEFAULT 0,
            vt_suspicious  INTEGER DEFAULT 0,
            vt_reputation  INTEGER DEFAULT 0,
            vt_owner       TEXT DEFAULT ''
        )
    """)
    # Migração idempotente: adiciona colunas que faltarem em bancos antigos.
    # Persistir a reputação (AbuseIPDB, por IP) permite o relatório unificado
    # TCP+UDP ler o estado completo do banco sem perder os dados de abuso.
    for col, dfn in [("resolved_ip","TEXT DEFAULT ''"),("campanha","TEXT DEFAULT ''"),
                     ("abuse_score","INTEGER DEFAULT -1"),("abuse_country","TEXT DEFAULT ''"),
                     ("abuse_isp","TEXT DEFAULT ''"),("abuse_usage","TEXT DEFAULT ''"),
                     ("abuse_tor","INTEGER DEFAULT 0"),("abuse_reports","INTEGER DEFAULT 0"),
                     ("abuse_last","TEXT DEFAULT ''"),("abuse_source","TEXT DEFAULT ''"),
                     ("idb_vuln_count","INTEGER DEFAULT 0"),("idb_vulns","TEXT DEFAULT ''"),
                     ("idb_tags","TEXT DEFAULT ''"),("idb_ports","TEXT DEFAULT ''"),
                     ("kev_count","INTEGER DEFAULT 0"),("kev_cves","TEXT DEFAULT ''"),
                     ("nvd_max_score","REAL DEFAULT 0"),("nvd_severity","TEXT DEFAULT ''"),
                     ("nvd_scores","TEXT DEFAULT ''"),
                     ("vt_malicious","INTEGER DEFAULT 0"),("vt_suspicious","INTEGER DEFAULT 0"),
                     ("vt_reputation","INTEGER DEFAULT 0"),("vt_owner","TEXT DEFAULT ''")]:
        try: cursor.execute(f"ALTER TABLE scans ADD COLUMN {col} {dfn}")
        except sqlite3.OperationalError: pass
    for col in ("waf",):
        try: cursor.execute(f"ALTER TABLE scans DROP COLUMN {col}")
        except sqlite3.OperationalError: pass
    conn.commit(); conn.close()

# ============================================================
# TARGETS
# ============================================================

# Validação de alvo (segurança — OWASP A03/Injeção): aceita apenas IP, CIDR ou
# hostname. Rejeita tokens que poderiam virar FLAG do nmap (ex.: "-oN /etc/x",
# "--script") ou conter metacaracteres de shell. Entradas legítimas não mudam;
# linhas inválidas são ignoradas com aviso (não interrompe o scan).
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9_-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9_-]{1,63}(?<!-))*$")
_DANGEROUS = set(" \t\r\n;|&$`<>()[]{}\\'\"!*?")

def _valid_target(s: str) -> bool:
    if not s or s[0] == "-" or any(c in _DANGEROUS for c in s):
        return False
    try:
        ipaddress.ip_network(s, strict=False)   # IP ou CIDR (v4/v6)
        return True
    except ValueError:
        return bool(_HOSTNAME_RE.match(s))


def load_campaigns() -> list[tuple[str, list[str]]]:
    target_path = Path(TARGETS_DIR)
    if not target_path.exists():
        raise FileNotFoundError(
            f"Diretório de targets não encontrado: {target_path.absolute()}\n"
            f"Crie o diretório e adicione arquivos .txt com os IPs/hosts."
        )
    campaign_files = _filtrar_campanhas(sorted(target_path.glob("*.txt")))
    if not campaign_files:
        raise FileNotFoundError(f"Nenhum arquivo .txt encontrado em {target_path.absolute()}")
    campaigns = []
    for f in campaign_files:
        targets, skipped = [], 0
        for raw in f.read_text(encoding="utf-8").splitlines():
            # Remove comentário inline: "1.2.3.4  # nota" → "1.2.3.4"
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            if not _valid_target(line):
                print(f"  [AVISO] {f.stem}: alvo inválido ignorado: {line!r}")
                skipped += 1
                continue
            targets.append(line)
        if targets:
            campaigns.append((f.stem, targets))
            extra = f" ({skipped} inválido(s) ignorado(s))" if skipped else ""
            print(f"  [TARGETS] {f.stem}: {len(targets)} alvo(s){extra}")
    return campaigns


# ── Fontes de inteligência: liga/desliga vindo da interface Web ──────────────
try:
    import providers as _prov  # /etc/argus/providers.py (mesmo PYTHONPATH)
except Exception:
    _prov = None

def _fonte_ligada(pid: str) -> bool:
    """A fonte está habilitada? Sem o módulo (instalação antiga), assume que sim —
    o comportamento anterior é preservado."""
    try:
        return _prov.is_enabled(pid) if _prov else True
    except Exception:
        return True

# ============================================================
# IP TYPE / ASN
# ============================================================

def get_ip_type(ip: str) -> str:
    try: return "PRIVADO" if ipaddress.ip_address(ip).is_private else "PUBLICO"
    except Exception: return "DESCONHECIDO"

def _load_known_asn() -> dict:
    """ASN já resolvido e persistido no banco. Enriquecimento estático (ASN/org NÃO muda):
    reusa p/ não re-buscar e, sobretudo, p/ não rebaixar a 'desconhecido' quando a API
    falha ou a rede cai no momento do scan."""
    known: dict[str, str] = {}
    try:
        conn = sqlite3.connect(DATABASE_FILE)
        for ip, asn in conn.execute(
                "SELECT ip, asn FROM scans WHERE asn NOT IN ('', 'ASN desconhecido', 'REDE PRIVADA')"):
            if ip and asn:
                known[ip] = asn
        conn.close()
    except Exception:
        pass
    return known

def resolve_asn_bulk(results: list[dict]) -> None:
    known = _load_known_asn()
    ip_indices: dict[str, list[int]] = {}
    for idx, r in enumerate(results):
        if r.get("ip_type") == "PUBLICO" and r.get("asn") == "ASN desconhecido":
            k = known.get(r["ip"])
            if k:                       # já no banco — reusa, não re-busca
                r["asn"] = k
            else:
                ip_indices.setdefault(r["ip"], []).append(idx)
    unique_ips = list(ip_indices.keys())
    if not unique_ips: return
    print(f"[ASN] Resolvendo {len(unique_ips)} IP(s) novo(s)...")
    cache: dict[str, str] = {}
    for i in range(0, len(unique_ips), ASN_BATCH_SIZE):
        batch = unique_ips[i:i+ASN_BATCH_SIZE]
        # Retry com espera: a cota do ip-api é por minuto (HTTP 429 devolve o tempo de
        # reset em X-Ttl). Sem repetir, um único soluço de rede/cota gravava
        # "ASN desconhecido" no banco — e o registro só melhorava se um scan futuro
        # desse sorte, porque _load_known_asn() ignora justamente esse valor.
        for tentativa in range(1, ASN_MAX_TENTATIVAS + 1):
            try:
                resp = requests.post("http://ip-api.com/batch",
                    json=[{"query":ip,"fields":"query,org,as,status"} for ip in batch], timeout=15)
                if resp.status_code == 200:
                    for entry in resp.json():
                        ip_key = entry.get("query","")
                        cache[ip_key] = (entry.get("org") or entry.get("as") or "ASN desconhecido") if entry.get("status")=="success" else "ASN desconhecido"
                    break
                if resp.status_code == 429:                      # cota da janela estourada
                    espera = min(int(resp.headers.get("X-Ttl", 5) or 5) + 1, ASN_ESPERA_MAX)
                    print(f"[ASN] cota do ip-api esgotada (HTTP 429) — aguardando {espera}s "
                          f"(tentativa {tentativa}/{ASN_MAX_TENTATIVAS})")
                    if tentativa < ASN_MAX_TENTATIVAS: time.sleep(espera)
                    continue
                print(f"[ASN] ip-api respondeu HTTP {resp.status_code} "
                      f"(tentativa {tentativa}/{ASN_MAX_TENTATIVAS})")
            except Exception as exc:                             # timeout, DNS, conexão
                print(f"[ASN] ip-api falhou: {type(exc).__name__}: {exc} "
                      f"(tentativa {tentativa}/{ASN_MAX_TENTATIVAS})")
            if tentativa < ASN_MAX_TENTATIVAS: time.sleep(ASN_ESPERA_ERRO)
    # Fallback por IP (ipinfo.io) para o que o batch não resolveu.
    for ip in unique_ips:
        if cache.get(ip,"ASN desconhecido") == "ASN desconhecido":
            try:
                r = requests.get(f"https://ipinfo.io/{ip}/org", timeout=8)
                if r.status_code == 200 and r.text.strip(): cache[ip] = r.text.strip()
                else: print(f"[ASN] ipinfo HTTP {r.status_code} para {ip}")
            except Exception as exc:
                print(f"[ASN] ipinfo falhou para {ip}: {type(exc).__name__}: {exc}")
    nao_resolvidos = []
    for ip, indices in ip_indices.items():
        resolved = cache.get(ip, "ASN desconhecido")
        if resolved == "ASN desconhecido":
            nao_resolvidos.append(ip)
            continue                    # falhou e é IP novo — mantém 'desconhecido', nunca rebaixa um bom
        for idx in indices: results[idx]["asn"] = resolved
    ok = len(unique_ips) - len(nao_resolvidos)
    print(f"[ASN] {ok}/{len(unique_ips)} resolvido(s)")
    if nao_resolvidos:
        # Visível de propósito: 'ASN desconhecido' na tela é consequência DISTO, e sem
        # esta linha a causa (cota, timeout, DNS) não ficava registrada em lugar nenhum.
        print(f"[ASN] sem resposta para: {', '.join(nao_resolvidos[:10])}"
              + (f" (+{len(nao_resolvidos)-10})" if len(nao_resolvidos) > 10 else ""))

# ============================================================
# RISK
# ============================================================

_PORT_RISK: dict[int, tuple[str, str, str]] = {
    21:("FTP","CRITICO","ALTO"), 22:("SSH","MEDIO","BAIXO"), 23:("Telnet","CRITICO","CRITICO"),
    512:("rexec","CRITICO","CRITICO"), 513:("rlogin","CRITICO","CRITICO"), 514:("rsh","CRITICO","CRITICO"),
    3389:("RDP","CRITICO","ALTO"), 5900:("VNC","CRITICO","ALTO"), 5985:("WinRM HTTP","CRITICO","ALTO"),
    5986:("WinRM HTTPS","ALTO","MEDIO"), 80:("HTTP","BAIXO","BAIXO"), 443:("HTTPS","BAIXO","BAIXO"),
    8080:("HTTP alt","BAIXO","BAIXO"), 8443:("HTTPS alt","BAIXO","BAIXO"), 8888:("HTTP alt","MEDIO","BAIXO"),
    25:("SMTP","ALTO","MEDIO"), 110:("POP3","ALTO","MEDIO"), 143:("IMAP","MEDIO","BAIXO"),
    465:("SMTPS","MEDIO","BAIXO"), 587:("SMTP sub","MEDIO","BAIXO"), 993:("IMAPS","BAIXO","BAIXO"),
    995:("POP3S","BAIXO","BAIXO"), 53:("DNS","MEDIO","BAIXO"), 135:("RPC/DCOM","CRITICO","ALTO"),
    137:("NetBIOS NS","CRITICO","ALTO"), 138:("NetBIOS DGM","CRITICO","ALTO"), 139:("NetBIOS","CRITICO","ALTO"),
    389:("LDAP","CRITICO","ALTO"), 445:("SMB","CRITICO","ALTO"), 636:("LDAPS","ALTO","MEDIO"),
    1433:("MSSQL","CRITICO","ALTO"), 1521:("Oracle DB","CRITICO","ALTO"), 3306:("MySQL","CRITICO","ALTO"),
    5432:("PostgreSQL","CRITICO","ALTO"), 5984:("CouchDB","CRITICO","ALTO"), 6379:("Redis","CRITICO","ALTO"),
    9200:("Elasticsearch","CRITICO","ALTO"), 9300:("ES cluster","CRITICO","ALTO"), 27017:("MongoDB","CRITICO","ALTO"),
    2375:("Docker API","CRITICO","CRITICO"), 2376:("Docker TLS","ALTO","MEDIO"), 2379:("etcd","CRITICO","CRITICO"),
    2380:("etcd peer","CRITICO","CRITICO"), 4243:("Docker daemon","CRITICO","CRITICO"),
    6443:("K8s API","CRITICO","ALTO"), 8500:("Consul","CRITICO","ALTO"), 8200:("Vault","CRITICO","ALTO"),
    9090:("Prometheus","ALTO","MEDIO"), 3000:("Grafana","ALTO","MEDIO"), 5601:("Kibana","ALTO","MEDIO"),
    8161:("ActiveMQ","ALTO","MEDIO"), 500:("IKE","MEDIO","BAIXO"), 1194:("OpenVPN","MEDIO","BAIXO"),
    1723:("PPTP","ALTO","MEDIO"), 4500:("IPSec","MEDIO","BAIXO"), 69:("TFTP","CRITICO","ALTO"),
    111:("rpcbind","ALTO","MEDIO"), 161:("SNMP","ALTO","MEDIO"), 162:("SNMP trap","MEDIO","BAIXO"),
    2049:("NFS","ALTO","MEDIO"),
}

# Criticidade UDP — tabela própria (o serviço/risco difere do TCP). Tupla:
# (nome, risco IP público, risco IP privado). Portas fora da tabela usam o padrão.
_UDP_PORT_RISK: dict[int, tuple[str, str, str]] = {
    # OOB / RCE / ICS / refletores de amplificação
    7:("echo","ALTO","BAIXO"), 17:("QOTD","ALTO","BAIXO"), 19:("chargen","CRITICO","BAIXO"),
    69:("TFTP","CRITICO","ALTO"), 111:("rpcbind","ALTO","MEDIO"), 123:("NTP","ALTO","BAIXO"),
    137:("NetBIOS NS","CRITICO","ALTO"), 138:("NetBIOS DGM","CRITICO","ALTO"),
    161:("SNMP","CRITICO","ALTO"), 162:("SNMP trap","MEDIO","BAIXO"), 177:("XDMCP","CRITICO","ALTO"),
    389:("CLDAP","CRITICO","ALTO"), 623:("IPMI/BMC","CRITICO","CRITICO"),
    1434:("MS-SQL Browser","ALTO","MEDIO"), 1900:("SSDP/UPnP","ALTO","MEDIO"),
    2049:("NFS","ALTO","MEDIO"), 3283:("Apple ARD","ALTO","BAIXO"), 3702:("WS-Discovery","ALTO","MEDIO"),
    5351:("NAT-PMP","ALTO","BAIXO"), 5355:("LLMNR","ALTO","MEDIO"), 5632:("pcAnywhere","CRITICO","ALTO"),
    6481:("Sun servicetags","MEDIO","BAIXO"), 10001:("Ubiquiti disc","ALTO","BAIXO"),
    11211:("memcached","CRITICO","ALTO"), 17185:("VxWorks WDB","CRITICO","CRITICO"),
    30718:("Lantronix","ALTO","MEDIO"), 32414:("Plex GDM","MEDIO","BAIXO"), 37810:("DVR Dahua","ALTO","MEDIO"),
    # ICS / OT
    20000:("DNP3","CRITICO","ALTO"), 2222:("EtherNet/IP","ALTO","MEDIO"), 34964:("PROFINET","CRITICO","ALTO"),
    41794:("Crestron","ALTO","MEDIO"), 44818:("EtherNet/IP","CRITICO","ALTO"), 47808:("BACnet","CRITICO","ALTO"),
    5683:("CoAP","ALTO","MEDIO"), 5684:("CoAPS","MEDIO","BAIXO"),
    # DNS / diretório / auth
    53:("DNS","ALTO","BAIXO"), 88:("Kerberos","MEDIO","BAIXO"), 464:("kpasswd","MEDIO","BAIXO"),
    749:("Kerberos-adm","ALTO","MEDIO"), 1645:("RADIUS","ALTO","MEDIO"), 1646:("RADIUS acct","ALTO","MEDIO"),
    1812:("RADIUS","ALTO","MEDIO"), 1813:("RADIUS acct","ALTO","MEDIO"), 5353:("mDNS","MEDIO","BAIXO"),
    # VPN / túnel / telecom
    500:("IKE/ISAKMP","MEDIO","BAIXO"), 4500:("IPsec NAT-T","MEDIO","BAIXO"), 1701:("L2TP","MEDIO","BAIXO"),
    1194:("OpenVPN","MEDIO","BAIXO"), 51820:("WireGuard","MEDIO","BAIXO"),
    2123:("GTP-C","ALTO","MEDIO"), 2152:("GTP-U","ALTO","MEDIO"), 3386:("GTP'","MEDIO","BAIXO"),
    4789:("VXLAN","MEDIO","BAIXO"), 8472:("VXLAN","MEDIO","BAIXO"), 6081:("GENEVE","MEDIO","BAIXO"),
    # acesso remoto / gestão
    3389:("RDP (UDP)","CRITICO","ALTO"), 7547:("TR-069/CWMP","ALTO","MEDIO"), 631:("IPP","MEDIO","BAIXO"),
    5009:("AirPort Admin","MEDIO","BAIXO"), 5678:("MikroTik MNDP","MEDIO","BAIXO"), 1604:("Citrix ICA","ALTO","MEDIO"),
    512:("biff","MEDIO","BAIXO"), 513:("who","MEDIO","BAIXO"), 514:("syslog","MEDIO","BAIXO"),
    # VoIP / mídia
    5060:("SIP","ALTO","MEDIO"), 5061:("SIP-TLS","MEDIO","BAIXO"), 2427:("MGCP gw","MEDIO","BAIXO"),
    2727:("MGCP ca","MEDIO","BAIXO"), 1718:("H.323 disc","MEDIO","BAIXO"), 1719:("H.323 RAS","MEDIO","BAIXO"),
    4569:("IAX2","MEDIO","BAIXO"), 3478:("STUN/TURN","BAIXO","BAIXO"), 3479:("TURN","BAIXO","BAIXO"),
    3480:("STUN","BAIXO","BAIXO"), 3481:("STUN","BAIXO","BAIXO"), 5004:("RTP","BAIXO","BAIXO"),
    5005:("RTCP","BAIXO","BAIXO"),
    # rede / infra / telemetria
    67:("DHCP srv","MEDIO","BAIXO"), 68:("DHCP cli","MEDIO","BAIXO"), 546:("DHCPv6 cli","MEDIO","BAIXO"),
    547:("DHCPv6 srv","MEDIO","BAIXO"), 520:("RIP","MEDIO","BAIXO"), 521:("RIPng","MEDIO","BAIXO"),
    1985:("HSRP","MEDIO","BAIXO"), 3784:("BFD","BAIXO","BAIXO"), 3785:("BFD echo","BAIXO","BAIXO"),
    5246:("CAPWAP ctrl","MEDIO","BAIXO"), 5247:("CAPWAP data","MEDIO","BAIXO"),
    2055:("NetFlow","MEDIO","BAIXO"), 9995:("NetFlow","MEDIO","BAIXO"), 9996:("NetFlow","MEDIO","BAIXO"),
    6343:("sFlow","MEDIO","BAIXO"),
    # web moderno + serviços de jogos (refletores quando expostos)
    443:("QUIC/HTTP-3","BAIXO","BAIXO"), 27015:("Source/Steam","MEDIO","BAIXO"), 27016:("Source","MEDIO","BAIXO"),
    27960:("Quake3","MEDIO","BAIXO"), 28015:("Rust","MEDIO","BAIXO"), 19132:("Minecraft BE","MEDIO","BAIXO"),
    9987:("TeamSpeak3","MEDIO","BAIXO"), 64738:("Mumble","MEDIO","BAIXO"),
}

def calculate_risk(port: int, ip_type: str = "PUBLICO", protocol: str = "tcp") -> str:
    table = _UDP_PORT_RISK if str(protocol).lower() == "udp" else _PORT_RISK
    entry = table.get(port)
    if not entry: return "MEDIO" if ip_type == "PUBLICO" else "BAIXO"
    _, rp, rv = entry
    return rp if ip_type == "PUBLICO" else rv

# ============================================================
# NMAP
# ============================================================

def _check_root() -> bool: return os.geteuid() == 0

def _expand_targets(targets: list[str]) -> list[str]:
    """Expande para escanear **um IP por invocação do nmap**:
      • CIDR (ex.: 192.0.2.0/24) -> cada IP individual da faixa;
      • IP único / hostname -> mantido (já é um único host).
    Deduplica preservando a ordem. Garante varredura IP a IP, sem lote."""
    out: list[str] = []
    seen: set[str] = set()
    for t in targets:
        expanded: list[str]
        net = None
        if "/" in t:
            try: net = ipaddress.ip_network(t, strict=False)
            except ValueError: net = None
        if net is not None:
            hosts = [str(h) for h in net.hosts()] or [str(net.network_address)]
            expanded = hosts
        else:
            expanded = [t]
        for ip in expanded:
            if ip not in seen:
                seen.add(ip); out.append(ip)
    return out


def run_scan(target: str, campanha: str, mode: str = "tcp") -> list[dict]:
    """Escaneia UM alvo por invocação do nmap (host-a-host) — progresso e logs
    incrementais por host. `mode` = 'tcp' (top-1000) ou 'udp' (100 portas curadas).
    Estrutura de resultado idêntica à do report/process (campo protocol distingue).

    scanner.scan() NÃO é engolido aqui de propósito: uma exceção ali (permissão
    negada, dispositivo de rede indisponível, PortScannerTimeout, nmap morto por
    OOM, argumento inválido...) significa "não consegui varrer" — diferente de
    "varri e não achei nada" (host inacessível / sem portas abertas, tratado mais
    abaixo SEM exceção, depois que scan() já rodou com sucesso). Confundir os dois
    já foi o bug: engolindo tudo aqui, um ambiente quebrado em 100% dos alvos
    devolvia [] silencioso indistinguível de "scan limpo, zero portas" — e depois
    de CLOSE_GRACE_DAYS cada porta real virava CORRIGIDO no banco. Deixando
    propagar, quem chama (_varrer_alvos, que já embrulha esta chamada em
    try/except nos dois ramos — série e paralelo) recebe a contagem exata de
    falhas para _falha_total() abortar antes de process_results."""
    scanner   = nmap.PortScanner()
    if mode == "udp":
        args = NMAP_ARGS_UDP            # -sU (exige root, garantido pelo wrapper sudo)
    else:
        scan_type = "-sS" if _check_root() else "-sT"
        args      = f"{scan_type} {NMAP_ARGS}"
    print(f"[NMAP] [{campanha}] Escaneando {target}  ({args})")
    try: resolved_ip = socket.gethostbyname(target)
    except Exception: resolved_ip = target
    scanner.scan(hosts=target, arguments=args)

    results = []
    for host in scanner.all_hosts():
        ip_type = get_ip_type(host)
        for proto in scanner[host].all_protocols():
            for port in sorted(scanner[host][proto].keys()):
                data = scanner[host][proto][port]
                if data.get("state") != "open": continue
                service = data.get("name", "unknown")
                banner  = " ".join(x for x in [data.get("product",""), data.get("version",""), data.get("extrainfo","")] if x).strip() or "No banner"
                results.append({
                    "campanha": campanha, "target": target, "resolved_ip": resolved_ip,
                    "ip": host, "port": port, "protocol": proto,
                    "service": service, "banner": banner, "state": "open",
                    "ip_type": ip_type,
                    "asn": "REDE PRIVADA" if ip_type == "PRIVADO" else "ASN desconhecido",
                    "risk": calculate_risk(port, ip_type, proto), "abuse": None,
                })

    all_hosts = scanner.all_hosts()
    _scope = "UDP" if mode == "udp" else f"top-{TOP_PORTS}"
    if not all_hosts:
        print(f"  → Host inacessível ou completamente filtrado ({target})")
    else:
        for host in all_hosts:
            n = len([r for r in results if r["ip"] == host])
            if not n: print(f"  → {host} ativo mas sem portas abertas ({_scope})")
            else:     print(f"  → {n} porta(s) abertas em {host}")
    return results

# ============================================================
# PROCESS RESULTS
# ============================================================

def _idb_cols(result: dict) -> tuple:
    """Resumo do Shodan InternetDB (por IP) para persistir: (qtd CVEs, CVEs,
    tags, portas vistas pelo Shodan) — permite o relatório unificado ler do banco."""
    d = result.get("internetdb") or {}
    return (
        int(d.get("vuln_count", 0) or 0),
        ",".join(d.get("vulns", [])[:50]),
        ",".join(d.get("tags", [])[:20]),
        ",".join(str(p) for p in d.get("ports", [])[:60]),
    )


def _kev_cols(result: dict) -> tuple:
    """Resumo do CISA KEV (CVEs exploradas in-the-wild) para persistir: (qtd, CVEs)."""
    k = result.get("kev") or {}
    return (int(k.get("kev_count", 0) or 0), ",".join(k.get("kev_cves", [])[:50]))


def _nvd_cols(result: dict) -> tuple:
    """Resumo do NVD (CVSS oficial) para persistir: (maior CVSS, severidade, mapa
    compacto 'CVE:score,...'). Permite o relatório reconstruir do banco."""
    n = result.get("nvd") or {}
    scores = ",".join(f"{c}:{s}" for c, s in list((n.get("scores") or {}).items())[:50])
    return (float(n.get("max_cvss", 0) or 0), str(n.get("max_severity", "") or ""), scores)


def _vt_cols(result: dict) -> tuple:
    """Resumo do VirusTotal para persistir: (motores maliciosos, suspeitos,
    reputação da comunidade, provedor do AS). Permite o relatório reconstruir do
    banco sem consultar a API de novo."""
    v = result.get("vt") or {}
    return (int(v.get("malicious", 0) or 0), int(v.get("suspicious", 0) or 0),
            int(v.get("reputation", 0) or 0), str(v.get("as_owner", "") or "")[:80])


def _abuse_cols(result: dict) -> tuple:
    """Extrai o resumo do AbuseIPDB (por IP) de um resultado para persistir no
    banco. Sem dados -> score -1 (= 'sem reputação')."""
    a = result.get("abuse") or {}
    if not a:
        return (-1, "", "", "", 0, 0, "", "")
    score = a.get("abuse_confidence_score")
    return (
        int(score) if score is not None else -1,
        str(a.get("country_code", "") or ""), str(a.get("isp", "") or ""),
        str(a.get("usage_type", "") or ""), int(bool(a.get("is_tor", False))),
        int(a.get("total_reports", 0) or 0), str(a.get("last_reported_at", "") or ""),
        str(a.get("source", "") or ""),
    )


def process_results(scan_results: list[dict], scanned_protocols=("tcp",)):
    """Faz o diff (NOVO/REINCIDENTE/FECHADO) e grava no banco. O fechamento é
    ESCOPADO aos protocolos efetivamente varridos (`scanned_protocols`) — assim
    um scan UDP nunca fecha portas TCP e vice-versa. Retorna os deltas do run
    (para syslog/console)."""
    protos = tuple(str(p).lower() for p in scanned_protocols) or ("tcp",)
    conn   = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    now    = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    novos, reincidentes, corrigidos = [], [], []
    current_keys = set()

    for result in scan_results:
        key = (result["ip"], result["port"], result["protocol"])
        current_keys.add(key)
        ab = _abuse_cols(result)
        idb = _idb_cols(result)
        kev = _kev_cols(result)
        vt  = _vt_cols(result)
        nvd = _nvd_cols(result)
        cursor.execute("SELECT id, status FROM scans WHERE ip=? AND port=? AND protocol=? ORDER BY id DESC LIMIT 1", key)
        existing = cursor.fetchone()
        if existing:
            # RESSURGIDO se estava CORRIGIDO e reapareceu; caso contrário REINCIDENTE.
            new_status = "RESSURGIDO" if existing[1] == "CORRIGIDO" else "REINCIDENTE"
            result["status"] = new_status; reincidentes.append(result); syslog_port(result)
            cursor.execute(
                "UPDATE scans SET last_seen=?,service=?,banner=?,state=?,risk=?,status=?,asn=?,campanha=?,"
                "abuse_score=?,abuse_country=?,abuse_isp=?,abuse_usage=?,abuse_tor=?,abuse_reports=?,abuse_last=?,abuse_source=?,"
                "idb_vuln_count=?,idb_vulns=?,idb_tags=?,idb_ports=?,kev_count=?,kev_cves=?,"
                "vt_malicious=?,vt_suspicious=?,vt_reputation=?,vt_owner=?,"
                "nvd_max_score=?,nvd_severity=?,nvd_scores=? WHERE id=?",
                (now, result["service"], result["banner"], result["state"],
                 result["risk"], new_status, result["asn"], result["campanha"], *ab, *idb, *kev, *vt, *nvd, existing[0]))
        else:
            result["status"] = "NOVO"; novos.append(result); syslog_port(result)
            cursor.execute(
                "INSERT INTO scans (campanha,target,resolved_ip,ip,port,protocol,service,banner,state,ip_type,asn,risk,first_seen,last_seen,status,"
                "abuse_score,abuse_country,abuse_isp,abuse_usage,abuse_tor,abuse_reports,abuse_last,abuse_source,"
                "idb_vuln_count,idb_vulns,idb_tags,idb_ports,kev_count,kev_cves,"
                "vt_malicious,vt_suspicious,vt_reputation,vt_owner,"
                "nvd_max_score,nvd_severity,nvd_scores) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (result["campanha"],result["target"],result["resolved_ip"],result["ip"],result["port"],
                 result["protocol"],result["service"],result["banner"],result["state"],result["ip_type"],
                 result["asn"],result["risk"],now,now,"NOVO", *ab, *idb, *kev, *vt, *nvd))

    # Fechar apenas portas do(s) protocolo(s) varrido(s) E sem serem vistas há
    # ≥ CLOSE_GRACE_DAYS (carência contra "misses" transitórios).
    grace_cutoff = (datetime.datetime.now() - datetime.timedelta(days=CLOSE_GRACE_DAYS)).strftime("%Y-%m-%d %H:%M:%S")
    ph = ",".join("?" * len(protos))
    # Só REINCIDENTE/RESSURGIDO podem ser CORRIGIDOS — NOVO nunca vai direto.
    cursor.execute(
        f"SELECT id,ip,port,protocol,service,banner,risk,target,asn,ip_type,resolved_ip,campanha "  # nosec B608 - colunas fixas, protocol via placeholders
        f"FROM scans WHERE status IN ('REINCIDENTE','RESSURGIDO') AND protocol IN ({ph}) AND last_seen < ?",
        (*protos, grace_cutoff))
    for row_id,ip,port,protocol,service,banner,risk,target,asn,ip_type,resolved_ip,campanha in cursor.fetchall():
        if (ip,port,protocol) not in current_keys:
            entry = {"ip":ip,"port":port,"protocol":protocol,"service":service or "","banner":banner or "",
                     "risk":risk or "BAIXO","status":"CORRIGIDO","campanha":campanha or "",
                     "target":target or "","asn":asn or "","ip_type":ip_type or "","resolved_ip":resolved_ip or "","abuse":None}
            corrigidos.append(entry); syslog_port(entry)
            cursor.execute("UPDATE scans SET status='CORRIGIDO', last_seen=? WHERE id=?", (now, row_id))
    conn.commit(); conn.close()
    return novos, reincidentes, corrigidos


_REPORT_COLS = ("campanha,target,resolved_ip,ip,port,protocol,service,banner,ip_type,asn,risk,status,"
                "abuse_score,abuse_country,abuse_isp,abuse_usage,abuse_tor,abuse_reports,abuse_last,abuse_source,"
                "idb_vuln_count,idb_vulns,idb_tags,idb_ports,kev_count,kev_cves,"
                "vt_malicious,vt_suspicious,vt_reputation,vt_owner,"
                "nvd_max_score,nvd_severity,nvd_scores")

def _row_to_result(row) -> dict:
    (campanha,target,resolved_ip,ip,port,protocol,service,banner,ip_type,asn,risk,status,
     ab_score,ab_country,ab_isp,ab_usage,ab_tor,ab_reports,ab_last,ab_source,
     idb_vc,idb_vulns,idb_tags,idb_ports,kev_count,kev_cves,
     vt_mal,vt_sus,vt_rep,vt_owner,
     nvd_max_score,nvd_severity,nvd_scores) = row
    abuse = None
    if ab_score is not None and ab_score >= 0:
        abuse = {"abuse_confidence_score":ab_score,"country_code":ab_country or "","isp":ab_isp or "",
                 "usage_type":ab_usage or "","is_tor":bool(ab_tor),"total_reports":ab_reports or 0,
                 "last_reported_at":ab_last or "","source":ab_source or ""}
    internetdb = None
    if (idb_vc or 0) > 0 or (idb_tags or "") or (idb_ports or ""):
        internetdb = {
            "ip": ip or "", "vuln_count": int(idb_vc or 0),
            "vulns": [v for v in (idb_vulns or "").split(",") if v],
            "tags":  [t for t in (idb_tags or "").split(",") if t],
            "ports": [int(p) for p in (idb_ports or "").split(",") if p.strip().isdigit()],
            "cpes": [], "hostnames": [], "seen": True, "source": "db",
        }
    kev = None
    if (kev_count or 0) > 0:
        kev = {"kev_count": int(kev_count or 0),
               "kev_cves": [c for c in (kev_cves or "").split(",") if c]}
    vt = None
    if (vt_mal or 0) or (vt_sus or 0) or (vt_rep or 0) or (vt_owner or ""):
        vt = {"malicious": int(vt_mal or 0), "suspicious": int(vt_sus or 0),
              "reputation": int(vt_rep or 0), "as_owner": vt_owner or "",
              "detected": int(vt_mal or 0) >= 2, "seen": True, "source": "db"}
    nvd = None
    if (nvd_max_score or 0) > 0:
        scores = {}
        for pair in (nvd_scores or "").split(","):
            if ":" in pair:
                _c, _s = pair.rsplit(":", 1)
                try: scores[_c] = float(_s)
                except ValueError: pass
        nvd = {"count": len(scores), "max_cvss": float(nvd_max_score or 0),
               "max_severity": nvd_severity or "", "scores": scores,
               "worst_cve": max(scores, key=scores.get) if scores else ""}
    return {"campanha":campanha or "","target":target or "","resolved_ip":resolved_ip or "",
            "ip":ip or "","port":port,"protocol":protocol or "","service":service or "",
            "banner":banner or "","state":"open","ip_type":ip_type or "","asn":asn or "",
            "risk":risk or "BAIXO","status":status or "","abuse":abuse,"internetdb":internetdb,"kev":kev,"vt":vt,"nvd":nvd}

def load_report_rows():
    """Monta a entrada do relatório a partir do estado COMPLETO do banco (TCP+UDP):
    ativos (NOVO/REINCIDENTE) + fechados recentes (janela CLOSED_WINDOW_DAYS).
    É isso que torna o relatório unificado: cada scan (TCP diário ou UDP semanal)
    regenera a visão inteira, sem apagar o outro protocolo."""
    conn = sqlite3.connect(DATABASE_FILE); cur = conn.cursor()
    cutoff = (datetime.datetime.now() - datetime.timedelta(days=CLOSED_WINDOW_DAYS)).strftime("%Y-%m-%d %H:%M:%S")
    novos = [_row_to_result(r) for r in cur.execute(
        f"SELECT {_REPORT_COLS} FROM scans WHERE status='NOVO'").fetchall()]  # nosec B608 - _REPORT_COLS constante, status literal
    reincidentes = [_row_to_result(r) for r in cur.execute(
        f"SELECT {_REPORT_COLS} FROM scans WHERE status IN ('REINCIDENTE','RESSURGIDO')").fetchall()]  # nosec B608 - _REPORT_COLS constante, status literais
    corrigidos = [_row_to_result(r) for r in cur.execute(
        f"SELECT {_REPORT_COLS} FROM scans WHERE status='CORRIGIDO' AND last_seen>=?", (cutoff,)).fetchall()]  # nosec B608 - _REPORT_COLS constante, status literal + placeholder
    conn.close()
    return novos, reincidentes, corrigidos

# ============================================================
# CRON
# ============================================================

def setup_cron(mode: str = "tcp"):
    import shutil
    script_path = Path(__file__).resolve()
    python_bin  = shutil.which("python3") or "/usr/bin/python3"
    # Stdout UNIFICADO: TCP e UDP no mesmo monitor_stdout.log (não se sobrepõem
    # no tempo — TCP diário 10h, UDP semanal domingo 03h).
    log_stdout  = Path(SYSLOG_FILE).parent / "monitor_stdout.log"
    ti_path     = str(script_path.parent.parent)
    if mode == "udp":
        cron_file = Path("/etc/cron.d/argus-monitor-udp")
        schedule  = "0 3 * * 0"      # domingo 03h00
        when      = "semanalmente aos domingos as 03h00 (0 3 * * 0)"
        flag      = "--udp"
        header    = "# monitor UDP — postura UDP (100 portas) semanalmente aos domingos as 03h00"
    else:
        cron_file = Path("/etc/cron.d/argus-monitor")
        schedule  = "0 10 * * *"     # diario 10h00
        when      = "diariamente as 10h00 (0 10 * * *)"
        flag      = "--tcp"
        header    = "# monitor — scan de superficie exposta (TCP) diariamente as 10h00"
    # umask 0002: arquivos auxiliares do SQLite (-wal/-shm) criados como root
    # ficam graváveis pelo grupo, permitindo escrita compartilhada com o app user.
    cron_content = (
        f"{header}\n"
        f"# Para remover: sudo rm {cron_file}\n"
        "SHELL=/bin/bash\n"
        "PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n"
        f"PYTHONPATH={ti_path}\n\n"
        f"{schedule} root umask 0002 && cd {script_path.parent} && {python_bin} {script_path} {flag} >> {log_stdout} 2>&1\n"
    )
    try:
        cron_file.write_text(cron_content, encoding="utf-8"); cron_file.chmod(0o644)
        print(f"[+] Cron instalado : {cron_file}")
        print(f"    Agenda         : {when}")
        print(f"    Modo           : {flag}")
        print(f"    Script         : {script_path}")
        print(f"    Stdout/stderr  : {log_stdout}")
        print(f"    Syslog RFC5424 : {SYSLOG_FILE}  (campo transport=tcp|udp)")
        print(f"\n    Para remover:  sudo rm {cron_file}")
    except PermissionError:
        print("[!] Permissão negada — execute como root:")
        print(f"    sudo python3 {script_path} {flag} --install-cron")

# ============================================================
# MAIN
# ============================================================

def _fmt_duration(seconds: int) -> str:
    if seconds < 60: return f"{seconds}s"
    m, s = divmod(seconds, 60)
    if m < 60: return f"{m}m {s:02d}s"
    h, m = divmod(m, 60); return f"{h}h {m:02d}m {s:02d}s"

def _parse_modes(argv: list[str]) -> list[str]:
    """Resolve o(s) protocolo(s) a varrer a partir das flags. Sem flag = TCP
    (back-compat). Ordem determinística: TCP antes de UDP."""
    modes = []
    if "--tcp" in argv: modes.append("tcp")
    if "--udp" in argv: modes.append("udp")
    return modes or ["tcp"]


def _falha_total(ips: list[str], falhas: int) -> bool:
    """True quando TODOS os alvos de uma chamada a _varrer_alvos falharam.

    Isto é o predicado que separa "0 portas abertas porque nada está aberto"
    de "0 portas porque o ambiente explodiu em todo mundo" (nmap ausente do
    PATH, permissão de root perdida etc.). Lista vazia não conta — campanha
    sem IPs nunca chegou a chamar run_scan, não é falha de nada.
    """
    return bool(ips) and falhas == len(ips)


# Queda além disto, com paralelismo ligado, vira aviso. Variação entre
# execuções é normal (host que cai, serviço reiniciado); 30% é a fronteira
# escolhida para separar ruído de sinal — ajuste se a prática mostrar outro.
QUEDA_COBERTURA_ALERTA = 0.30


def _portas_da_execucao_anterior(campanha: str) -> int:
    """Portas ativas registradas para a campanha antes desta execução.

    Lê do banco do monitor. Zero quando não há histórico (primeira execução),
    e zero também em qualquer erro: a verificação é conveniência e não pode
    impedir o scan de terminar.
    """
    try:
        conn = sqlite3.connect(DATABASE_FILE, timeout=5)
        try:
            cur = conn.execute(
                "SELECT COUNT(*) FROM scans WHERE campanha=? AND protocol='tcp' "
                "AND status IN ('NOVO','REINCIDENTE','RESSURGIDO')", (campanha,))
            return int(cur.fetchone()[0] or 0)
        finally:
            conn.close()
    except Exception:
        return 0


def _alertar_queda_cobertura(campanha: str, achadas: int,
                             paralelismo: int) -> str | None:
    """Mensagem de aviso quando a cobertura cai de forma suspeita, ou None.

    Só alerta com paralelismo acima de 1: em série, uma queda tem outras causas
    (o alvo realmente fechou portas) e o aviso seria ruído.
    """
    if paralelismo <= 1:
        return None
    anterior = _portas_da_execucao_anterior(campanha)
    if anterior <= 0:
        return None                     # sem histórico, nada a comparar
    if achadas >= anterior * (1 - QUEDA_COBERTURA_ALERTA):
        return None
    return (f"cobertura caiu de {anterior} para {achadas} porta(s) com "
            f"paralelismo {paralelismo} — sob concorrência o nmap pode "
            f"reportar porta aberta como filtrada. Se a queda não for esperada, "
            f"reduza o paralelismo da campanha e compare.")


def _varrer_alvos(ips: list[str], campanha: str, mode: str,
                  paralelismo: int) -> tuple[list[dict], int]:
    """Varre a lista de IPs e devolve (resultados, falhas).

    Thread pool basta porque o nmap é processo externo e o trabalho é espera de
    rede — não há disputa de CPU (3min32 de CPU para 3h23 de relógio na medição
    que motivou isto) nem estado compartilhado dentro de run_scan.

    Falha de um alvo NÃO derruba os demais: um nmap que morre custa aquele IP,
    não a varredura inteira. Mas o chamador precisa saber QUANTOS alvos
    falharam — daí o segundo elemento da tupla. Sem essa contagem, um scan
    onde TODO alvo falhou (ambiente quebrado, não alvo individual) fica
    indistinguível de um scan que rodou limpo e não achou nada aberto; ver
    _falha_total(), usado por main() para decidir se aborta a execução.
    """
    total = len(ips)
    if total == 0:
        return [], 0

    # UDP não tem handshake: sob concorrência a distinção entre "aberta" e
    # "filtrada" degrada, e UDP não é o gargalo que motivou o paralelismo (só
    # o TCP media 3min32 de CPU para 3h23 de relógio). A guarda vive AQUI,
    # dentro da função, e não só em main() — um chamador futuro que esqueça
    # de restringir mode=="tcp" antes de paralelizar não fura a regra.
    if mode != "tcp":
        paralelismo = 1

    if paralelismo <= 1:
        # Caminho de série idêntico ao histórico — inclusive na saída impressa.
        resultados: list[dict] = []
        falhas = 0
        for i, ip in enumerate(ips, 1):
            print(f"[{i}/{total}]", end=" ")
            try:
                resultados.extend(run_scan(ip, campanha, mode))
            except Exception as exc:
                falhas += 1
                print(f"  [ERRO] {ip}: {exc}", file=sys.stderr)
                # Fecha a linha do contador impresso acima: se a exceção vier
                # antes de qualquer print de run_scan, "[i/total]" fica sem
                # quebra de linha e cola no contador da próxima iteração.
                print()
                syslog_error(f"run_scan({ip})", exc)
        return resultados, falhas

    resultados = []
    falhas = 0
    concluidos = 0
    pool = ThreadPoolExecutor(max_workers=paralelismo)
    try:
        futuros = {pool.submit(run_scan, ip, campanha, mode): ip for ip in ips}
        for fut in as_completed(futuros):
            ip = futuros[fut]
            concluidos += 1
            # Imprime ao TERMINAR, não ao começar: com execuções concorrentes,
            # anunciar o início embaralha a saída e o progresso deixa de fazer
            # sentido para quem acompanha o log.
            try:
                parciais = fut.result()
                resultados.extend(parciais)
                print(f"[{concluidos}/{total}] {ip}: {len(parciais)} porta(s)")
            except Exception as exc:
                falhas += 1
                print(f"[{concluidos}/{total}] {ip}: ERRO — {exc}", file=sys.stderr)
                syslog_error(f"run_scan({ip})", exc)
        pool.shutdown(wait=True)
    except BaseException:
        # Ctrl+C (ou qualquer sinal) chegando durante as_completed: todos os
        # alvos já foram submetidos de uma vez, então tarefas ainda não
        # iniciadas nascem DEPOIS do sinal. O "with"/shutdown(wait=True)
        # padrão bloqueia até a fila inteira esvaziar — o operador aperta
        # Ctrl+C e o processo segue varrendo os alvos restantes por minutos,
        # sem saída visível. cancel_futures descarta o que não começou —
        # mas isto NÃO é interrupção imediata: os no máximo `paralelismo`
        # scans já em voo continuam até o nmap terminar, porque o
        # _python_exit do próprio concurrent.futures (registrado via atexit)
        # dá join nessas threads antes do processo morrer. O operador espera
        # esse punhado de scans em andamento, não a fila inteira (que pode
        # ser 84 alvos).
        pool.shutdown(wait=False, cancel_futures=True)
        raise
    return resultados, falhas


def main():
    modes = _parse_modes(sys.argv)
    if "--install-cron" in sys.argv:
        setup_cron("udp" if "udp" in modes and "tcp" not in modes else "tcp"); return

    # Garante que os caminhos relativos (targets/, *.db, *.html) resolvam
    # a partir do diretório do script, não do diretório atual do shell.
    os.chdir(Path(__file__).resolve().parent)

    transport = "+".join(modes)
    _start = time.monotonic()
    print("=" * 60)
    print(f"ARGUS — Monitor de Portas  (Nmap + AbuseIPDB)  [{transport.upper()}]")
    print("=" * 60)

    if not _check_root():
        print("[AVISO] Executando sem root — usando TCP connect scan (-sT)")
        if "udp" in modes:
            print("[AVISO] Scan UDP (-sU) exige root — modo UDP será ignorado.")
            modes = [m for m in modes if m != "udp"] or ["tcp"]
    if _THREATINTEL_AVAILABLE:
        print("[INFO] Módulo threatintel carregado — reputação AbuseIPDB ativa"); init_threatintel_db()
    else:
        print("[AVISO] Módulo threatintel não encontrado — reputação desativada")
        print("         Configure PYTHONPATH=/etc/argus para ativar")

    init_database()
    print()
    print("[+] Carregando campanhas...")
    try: campaigns = load_campaigns()
    except FileNotFoundError as exc: print(f"[ERRO] {exc}"); sys.exit(1)

    total_targets = sum(len(t) for _, t in campaigns)
    print(f"[+] {len(campaigns)} campanha(s) | {total_targets} alvo(s) total | modo(s): {', '.join(modes)}")
    syslog_init(len(campaigns), total_targets, transport=transport)
    print()

    try:
        all_results: list[dict] = []
        for mode in modes:
            print(f"\n========== Varredura {mode.upper()} ==========")
            for campanha, targets in campaigns:
                ips = _expand_targets(targets)
                # Paralelismo só no TCP: o UDP não tem handshake e a distinção
                # entre "aberta" e "filtrada" já é frágil — concorrência ali
                # multiplica o falso negativo num scan que também não é o gargalo.
                paralelo = _paralelismo_da_campanha(campanha) if mode == "tcp" else 1
                extra = f" — {paralelo} em paralelo" if paralelo > 1 else ""
                print(f"\n--- Campanha: {campanha} ({len(ips)} IP(s) — "
                      f"varredura individual {mode.upper()}{extra}) ---")
                resultados, falhas = _varrer_alvos(ips, campanha, mode, paralelo)
                if _falha_total(ips, falhas):
                    # TODO alvo desta campanha falhou — isto não é "0 portas
                    # abertas", é o scan não ter acontecido (nmap ausente do
                    # PATH, permissão de root perdida etc). Abortamos AQUI,
                    # antes de process_results, e propositalmente com uma
                    # exceção comum: o "except Exception" logo abaixo em
                    # main() já registra SCAN_ERR + SCAN_END status="error"
                    # e re-lança — reaproveitamos essa trilha em vez de
                    # duplicá-la. Deixar seguir faria all_results permanecer
                    # vazio, process_results leria "nada mudou", e passados
                    # os dias de CLOSE_GRACE_DAYS o achado real seria fechado
                    # como CORRIGIDO: um scan que não rodou não pode afirmar
                    # que a superfície foi remediada.
                    raise RuntimeError(
                        f"todos os {len(ips)} alvo(s) da campanha "
                        f"'{campanha}' ({mode}) falharam — provável falha de "
                        f"ambiente (nmap ausente/permissão), não de alvo")
                if falhas:
                    print(f"[AVISO] {falhas}/{len(ips)} alvo(s) falharam na "
                          f"campanha {campanha} ({mode}) — resultados "
                          f"parciais dos demais seguem")
                all_results.extend(resultados)
                if mode == "tcp":
                    aviso = _alertar_queda_cobertura(
                        campanha, len([r for r in all_results
                                       if r.get("campanha") == campanha
                                       and r.get("protocol") == "tcp"]),
                        paralelo)
                    if aviso:
                        print(f"  [COBERTURA] {campanha}: {aviso}", file=sys.stderr)
                        syslog_write("WARN", "COVERAGE_DROP", aviso,
                                     module=SYSLOG_APP, campanha=campanha,
                                     paralelismo=str(paralelo))

        print(f"\n[ASN] Total de portas abertas: {len(all_results)}")
        resolve_asn_bulk(all_results)

        if _THREATINTEL_AVAILABLE:
            print()
            if _fonte_ligada("abuseipdb"):
                enrich_results(all_results)
                for r in all_results:
                    r["risk"] = compute_final_risk(r["risk"], r["ip_type"], r.get("abuse"))

            # Shodan InternetDB (vulnerabilidades/CVE) — enriquece e eleva (leve)
            if _internetdb is not None and _fonte_ligada("internetdb"):
                try:
                    _internetdb.enrich_results(all_results)
                    for r in all_results:
                        r["risk"] = _internetdb.vuln_elevate(r["risk"], r.get("internetdb"))
                except Exception as _exc:
                    print(f"[INTERNETDB] enriquecimento ignorado: {_exc}")

            # CISA KEV — cruza as CVEs do InternetDB com o catálogo de explorados
            # in-the-wild e eleva (KEV = alta confiança → CRÍTICO por padrão).
            if _cisa_kev is not None and _fonte_ligada("cisa_kev"):
                try:
                    _cisa_kev.enrich_results(all_results)
                    for r in all_results:
                        r["risk"] = _cisa_kev.kev_elevate(r["risk"], r.get("kev"))
                except Exception as _exc:
                    print(f"[CISA-KEV] enriquecimento ignorado: {_exc}")

            # VirusTotal — veredito agregado de antivírus/blocklists para o IP.
            if _virustotal is not None and _fonte_ligada("virustotal"):
                try:
                    _virustotal.enrich_results(all_results)
                    _n_vt = _virustotal.elevate(all_results)
                    if _n_vt:
                        print(f"[VT] {_n_vt} achado(s) elevado(s) por reputação do VirusTotal")
                except Exception as _exc:
                    print(f"[VT] enriquecimento ignorado: {_exc}")

            # NVD — pontua (CVSS oficial) as CVEs do InternetDB e eleva por severidade.
            if _nvd is not None and _fonte_ligada("nvd"):
                try:
                    _nvd.enrich_results(all_results)
                    for r in all_results:
                        r["risk"] = _nvd.nvd_elevate(r["risk"], r.get("nvd"))
                except Exception as _exc:
                    print(f"[NVD] enriquecimento ignorado: {_exc}")

        # Diff escopado ao(s) protocolo(s) varrido(s) — não fecha o outro protocolo.
        novos, reincidentes, corrigidos = process_results(all_results, scanned_protocols=modes)

        # ── Store central de achados (argus.db) — ADITIVO ─────────
        # Alimenta o domínio de Findings sem alterar o fluxo/DB/relatório atual.
        # Usa a severidade REAL (antes do RECONHECIDO->INFO); o reconhecimento
        # vira status ACEITO no domínio, não rebaixa a severidade técnica.
        if _findings is not None:
            try:
                _proto_set = set(modes)
                obs, closed = _findings.sync_findings(
                    "monitor", novos + reincidentes,
                    key_of=lambda r: f"{r.get('ip')}:{r.get('port')}/{r.get('protocol')}",
                    severity_of=lambda r: r.get("risk", "BAIXO"),
                    title_of=lambda r: f"{r.get('ip')}:{r.get('port')}/{r.get('protocol')} ({r.get('service','?')})",
                    campanha_of=lambda r: r.get("campanha", ""),
                    details_of=lambda r: {"service": r.get("service",""), "banner": r.get("banner",""),
                                          "asn": r.get("asn",""), "ip_type": r.get("ip_type","")},
                    scope_predicate=lambda k: k.rsplit("/", 1)[-1] in _proto_set,
                    corrected=corrigidos,
                    resurged=[r for r in reincidentes if r.get("status") == "RESSURGIDO"],
                    run_id=str(_run_id or ""))
                print(f"[FINDINGS] argus.db: {obs} observado(s), {closed} fechado(s)")
                try:
                    from reporter import write_findings_page as _wfp
                    if _wfp(APACHE_DOCROOT): print("[FINDINGS] página de Gestão de Achados atualizada")
                except Exception: pass
            except Exception as _exc:
                print(f"[FINDINGS] sync ignorado (não crítico): {_exc}")

        # ── Relatório lido do BANCO (estado completo TCP+UDP) ─────
        rep_novos, rep_rein, rep_corr = load_report_rows()

        # ── Esconde do relatório os ativos cujo ACHADO foi tratado (Mitigado/FP) ──
        if _findings is not None:
            try:
                _hidden = _findings.hidden_keys("monitor")
                if _hidden:
                    def _kf(r):
                        return f"{r.get('ip')}:{r.get('port')}/{r.get('protocol')}"
                    rep_novos = [r for r in rep_novos if _kf(r) not in _hidden]
                    rep_rein  = [r for r in rep_rein  if _kf(r) not in _hidden]
                    rep_corr  = [r for r in rep_corr  if _kf(r) not in _hidden]
            except Exception:
                pass

        # ── Reconhecimento (RECONHECIDO -> INFO) sobre a visão do relatório ──
        if ack is not None:
            _ack_n = ack.apply("monitor", rep_novos, rep_rein)
            if _ack_n:
                print(f"[ACK] {_ack_n} achado(s) reconhecido(s) -> status RECONHECIDO / risco INFO")

        # ── Grava relatório HTML ──────────────────────────────────
        import os as _os
        import shutil as _shutil
        from pathlib import Path as _Path
        _docroot      = _Path(APACHE_DOCROOT)
        _docroot_path = _docroot / HTML_REPORT
        _local_path   = HTML_REPORT

        # Remove symlink quebrado se existir (instalação anterior)
        if _docroot.exists() and _docroot_path.is_symlink():
            _docroot_path.unlink()
            print(f"[INFO] Symlink antigo removido: {_docroot_path}")

        _out = str(_docroot_path) if _docroot.exists() else _local_path

        generate_monitor_report(rep_novos, rep_rein, rep_corr,
                                output_path=_out,
                                threatintel_available=_THREATINTEL_AVAILABLE)
        _os.chmod(_out, 0o644)
        if _out != _local_path:
            _shutil.copy2(_out, _local_path)

        duration_s = int(time.monotonic() - _start)
        syslog_end(novos, reincidentes, corrigidos, duration_s, transport=transport)

    except Exception as exc:
        duration_s = int(time.monotonic() - _start)
        syslog_error("main", exc); syslog_end([], [], [], duration_s, status="error", transport=transport); raise

    udp_tot = sum(1 for r in rep_novos + rep_rein if r.get("protocol") == "udp")
    print()
    print(f"[+] Relatório        : {Path(HTML_REPORT).absolute()}")
    print(f"[+] Log RFC5424      : {SYSLOG_FILE}")
    print(f"[+] Novos (run)      : {len(novos)}")
    print(f"[+] Reincidentes(run): {len(reincidentes)}")
    print(f"[+] Corrigidos (run) : {len(corrigidos)}")
    print(f"[+] Portas UDP (DB)  : {udp_tot}")
    print(f"[+] Tempo de execução: {_fmt_duration(duration_s)}")

if __name__ == "__main__":
    main()
