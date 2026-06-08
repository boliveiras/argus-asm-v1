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
import json
import os
import re
import socket
import sqlite3
import sys
import time
import uuid
from pathlib import Path

import requests

try:
    import nmap
except ImportError:
    print("[ERRO] python-nmap não instalado. Execute: pip install python-nmap")
    sys.exit(1)

try:
    from threatintel.providers.abuseipdb import enrich_results
    from threatintel.core.reputation      import compute_final_risk
    from threatintel.core.database        import init_database as init_threatintel_db
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
    ts     = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]+"Z"
    parts  = [f'run_id="{_sd_escape(_run_id)}"'] + [f'{k}="{_sd_escape(v)}"' for k,v in sd.items()]
    line   = f"<{prival}>1 {ts} {_hostname} {SYSLOG_APP} {_pid} {msgid} [origin@32473 {' '.join(parts)}] {str(msg).replace(chr(10),' ')}\n"
    try: _syslog_fd.write(line); _syslog_fd.flush()
    except OSError: pass

def syslog_init(campaigns: int, targets_count: int, transport: str = "tcp"):
    global _run_id, _scan_start
    _run_id = str(uuid.uuid4())
    _scan_start = datetime.datetime.now(datetime.timezone.utc)
    _syslog_open()
    syslog_write("INFO","SCAN_START",f"Iniciando scan {transport}: {campaigns} campanha(s), {targets_count} alvo(s)",
                 module=SYSLOG_APP, version=APP_VERSION, transport=transport,
                 campaigns=str(campaigns), targets=str(targets_count))

def syslog_port(result: dict):
    risk   = result.get("risk","BAIXO")
    status = result.get("status","NOVO")
    sev    = _RISK_SEV.get(risk,"INFO")
    abuse  = result.get("abuse") or {}
    if status == "FECHADO":
        sev = "NOTICE"; msgid = "PORT_CLOSED"
        msg = f"Porta fechada: {result.get('ip')}:{result.get('port')}/{result.get('protocol')}"
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
            idb_ports      TEXT DEFAULT ''
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
                     ("idb_tags","TEXT DEFAULT ''"),("idb_ports","TEXT DEFAULT ''")]:
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
    campaign_files = sorted(target_path.glob("*.txt"))
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

# ============================================================
# IP TYPE / ASN
# ============================================================

def get_ip_type(ip: str) -> str:
    try: return "PRIVADO" if ipaddress.ip_address(ip).is_private else "PUBLICO"
    except Exception: return "DESCONHECIDO"

def resolve_asn_bulk(results: list[dict]) -> None:
    ip_indices: dict[str, list[int]] = {}
    for idx, r in enumerate(results):
        if r.get("ip_type") == "PUBLICO" and r.get("asn") == "ASN desconhecido":
            ip_indices.setdefault(r["ip"], []).append(idx)
    unique_ips = list(ip_indices.keys())
    if not unique_ips: return
    print(f"[ASN] Resolvendo {len(unique_ips)} IPs únicos...")
    cache: dict[str, str] = {}
    for i in range(0, len(unique_ips), ASN_BATCH_SIZE):
        batch = unique_ips[i:i+ASN_BATCH_SIZE]
        try:
            resp = requests.post("http://ip-api.com/batch",
                json=[{"query":ip,"fields":"query,org,as,status"} for ip in batch], timeout=15)
            if resp.status_code == 200:
                for entry in resp.json():
                    ip_key = entry.get("query","")
                    cache[ip_key] = (entry.get("org") or entry.get("as") or "ASN desconhecido") if entry.get("status")=="success" else "ASN desconhecido"
        except Exception: pass
    for ip in unique_ips:
        if cache.get(ip,"ASN desconhecido") == "ASN desconhecido":
            try:
                r = requests.get(f"https://ipinfo.io/{ip}/org", timeout=5)
                if r.status_code == 200 and r.text.strip(): cache[ip] = r.text.strip()
            except Exception: pass
    for ip, indices in ip_indices.items():
        resolved = cache.get(ip, "ASN desconhecido")
        for idx in indices: results[idx]["asn"] = resolved

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
    Estrutura de resultado idêntica à do report/process (campo protocol distingue)."""
    scanner   = nmap.PortScanner()
    if mode == "udp":
        args = NMAP_ARGS_UDP            # -sU (exige root, garantido pelo wrapper sudo)
    else:
        scan_type = "-sS" if _check_root() else "-sT"
        args      = f"{scan_type} {NMAP_ARGS}"
    print(f"[NMAP] [{campanha}] Escaneando {target}  ({args})")
    try: resolved_ip = socket.gethostbyname(target)
    except Exception: resolved_ip = target
    try: scanner.scan(hosts=target, arguments=args)
    except Exception as exc:
        syslog_error(f"nmap.scan({target})", exc)
        print(f"  [ERRO] {target}: {exc}"); return []

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
        cursor.execute("SELECT id FROM scans WHERE ip=? AND port=? AND protocol=? ORDER BY id DESC LIMIT 1", key)
        existing = cursor.fetchone()
        if existing:
            result["status"] = "REINCIDENTE"; reincidentes.append(result); syslog_port(result)
            cursor.execute(
                "UPDATE scans SET last_seen=?,service=?,banner=?,state=?,risk=?,status=?,asn=?,campanha=?,"
                "abuse_score=?,abuse_country=?,abuse_isp=?,abuse_usage=?,abuse_tor=?,abuse_reports=?,abuse_last=?,abuse_source=?,"
                "idb_vuln_count=?,idb_vulns=?,idb_tags=?,idb_ports=? WHERE id=?",
                (now, result["service"], result["banner"], result["state"],
                 result["risk"], "REINCIDENTE", result["asn"], result["campanha"], *ab, *idb, existing[0]))
        else:
            result["status"] = "NOVO"; novos.append(result); syslog_port(result)
            cursor.execute(
                "INSERT INTO scans (campanha,target,resolved_ip,ip,port,protocol,service,banner,state,ip_type,asn,risk,first_seen,last_seen,status,"
                "abuse_score,abuse_country,abuse_isp,abuse_usage,abuse_tor,abuse_reports,abuse_last,abuse_source,"
                "idb_vuln_count,idb_vulns,idb_tags,idb_ports) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (result["campanha"],result["target"],result["resolved_ip"],result["ip"],result["port"],
                 result["protocol"],result["service"],result["banner"],result["state"],result["ip_type"],
                 result["asn"],result["risk"],now,now,"NOVO", *ab, *idb))

    # Fechar apenas portas do(s) protocolo(s) varrido(s) E sem serem vistas há
    # ≥ CLOSE_GRACE_DAYS (carência contra "misses" transitórios).
    grace_cutoff = (datetime.datetime.now() - datetime.timedelta(days=CLOSE_GRACE_DAYS)).strftime("%Y-%m-%d %H:%M:%S")
    ph = ",".join("?" * len(protos))
    cursor.execute(
        f"SELECT id,ip,port,protocol,service,banner,risk,target,asn,ip_type,resolved_ip,campanha "
        f"FROM scans WHERE status IN ('NOVO','REINCIDENTE') AND protocol IN ({ph}) AND last_seen < ?",
        (*protos, grace_cutoff))
    for row_id,ip,port,protocol,service,banner,risk,target,asn,ip_type,resolved_ip,campanha in cursor.fetchall():
        if (ip,port,protocol) not in current_keys:
            entry = {"ip":ip,"port":port,"protocol":protocol,"service":service or "","banner":banner or "",
                     "risk":risk or "BAIXO","status":"FECHADO","campanha":campanha or "",
                     "target":target or "","asn":asn or "","ip_type":ip_type or "","resolved_ip":resolved_ip or "","abuse":None}
            corrigidos.append(entry); syslog_port(entry)
            cursor.execute("UPDATE scans SET status='FECHADO', last_seen=? WHERE id=?", (now, row_id))
    conn.commit(); conn.close()
    return novos, reincidentes, corrigidos


_REPORT_COLS = ("campanha,target,resolved_ip,ip,port,protocol,service,banner,ip_type,asn,risk,status,"
                "abuse_score,abuse_country,abuse_isp,abuse_usage,abuse_tor,abuse_reports,abuse_last,abuse_source,"
                "idb_vuln_count,idb_vulns,idb_tags,idb_ports")

def _row_to_result(row) -> dict:
    (campanha,target,resolved_ip,ip,port,protocol,service,banner,ip_type,asn,risk,status,
     ab_score,ab_country,ab_isp,ab_usage,ab_tor,ab_reports,ab_last,ab_source,
     idb_vc,idb_vulns,idb_tags,idb_ports) = row
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
    return {"campanha":campanha or "","target":target or "","resolved_ip":resolved_ip or "",
            "ip":ip or "","port":port,"protocol":protocol or "","service":service or "",
            "banner":banner or "","state":"open","ip_type":ip_type or "","asn":asn or "",
            "risk":risk or "BAIXO","status":status or "","abuse":abuse,"internetdb":internetdb}

def load_report_rows():
    """Monta a entrada do relatório a partir do estado COMPLETO do banco (TCP+UDP):
    ativos (NOVO/REINCIDENTE) + fechados recentes (janela CLOSED_WINDOW_DAYS).
    É isso que torna o relatório unificado: cada scan (TCP diário ou UDP semanal)
    regenera a visão inteira, sem apagar o outro protocolo."""
    conn = sqlite3.connect(DATABASE_FILE); cur = conn.cursor()
    cutoff = (datetime.datetime.now() - datetime.timedelta(days=CLOSED_WINDOW_DAYS)).strftime("%Y-%m-%d %H:%M:%S")
    novos = [_row_to_result(r) for r in cur.execute(
        f"SELECT {_REPORT_COLS} FROM scans WHERE status='NOVO'").fetchall()]
    reincidentes = [_row_to_result(r) for r in cur.execute(
        f"SELECT {_REPORT_COLS} FROM scans WHERE status='REINCIDENTE'").fetchall()]
    corrigidos = [_row_to_result(r) for r in cur.execute(
        f"SELECT {_REPORT_COLS} FROM scans WHERE status='FECHADO' AND last_seen>=?", (cutoff,)).fetchall()]
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
                print(f"\n--- Campanha: {campanha} ({len(ips)} IP(s) — varredura individual {mode.upper()}) ---")
                for i, ip in enumerate(ips, 1):
                    print(f"[{i}/{len(ips)}]", end=" ")
                    all_results.extend(run_scan(ip, campanha, mode))

        print(f"\n[ASN] Total de portas abertas: {len(all_results)}")
        resolve_asn_bulk(all_results)

        if _THREATINTEL_AVAILABLE:
            print()
            enrich_results(all_results)
            for r in all_results:
                r["risk"] = compute_final_risk(r["risk"], r["ip_type"], r.get("abuse"))

            # Shodan InternetDB (vulnerabilidades/CVE) — enriquece e eleva (leve)
            if _internetdb is not None:
                try:
                    _internetdb.enrich_results(all_results)
                    for r in all_results:
                        r["risk"] = _internetdb.vuln_elevate(r["risk"], r.get("internetdb"))
                except Exception as _exc:
                    print(f"[INTERNETDB] enriquecimento ignorado: {_exc}")

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

        # ── Reconhecimento (RECONHECIDO -> INFO) sobre a visão do relatório ──
        if ack is not None:
            _ack_n = ack.apply("monitor", rep_novos, rep_rein)
            if _ack_n:
                print(f"[ACK] {_ack_n} achado(s) reconhecido(s) -> status RECONHECIDO / risco INFO")

        # ── Grava relatório HTML ──────────────────────────────────
        from pathlib import Path as _Path
        import os as _os, shutil as _shutil
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
    print(f"[+] Fechados (run)   : {len(corrigidos)}")
    print(f"[+] Portas UDP (DB)  : {udp_tot}")
    print(f"[+] Tempo de execução: {_fmt_duration(duration_s)}")

if __name__ == "__main__":
    main()
