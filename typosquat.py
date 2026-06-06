#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Argus ASM — monitoramento de superfície de ataque
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
Argus Typosquat — detecção de typosquatting / homoglyph (dnstwist)

Para cada domínio-base das campanhas (reaproveita os do submonitor), gera
permutações sósia (typos, homoglyphs, bitsquatting, troca de TLD, omissões…)
via **dnstwist** e reporta apenas as **registradas** — vetor direto de phishing
e abuso de marca. Cada sósia registrado é um achado, com ciclo de vida no store
central (argus.db, source="typosquat").

Risco:
    resolve (IP) + MX  -> CRÍTICO  (pode hospedar página E receber e-mail)
    resolve (IP)       -> ALTO     (pode hospedar página de phishing)
    apenas registrado  -> MÉDIO    (latente / estacionado)

Uso:
    argus-typosquat
    python3 typosquat.py --install-cron
"""

import datetime
import json
import os
import shutil
import socket
import sqlite3
import subprocess
import sys
import time
import uuid
from pathlib import Path

try:
    from reporter import generate_typosquat_report
except ImportError:
    print("[ERRO] reporter.py não encontrado no PYTHONPATH.")
    print("        Verifique a instalação em /etc/argus (PYTHONPATH).")
    sys.exit(1)

try:
    import ack
except ImportError:
    ack = None

try:
    import findings as _findings
except ImportError:
    _findings = None

# ============================================================
# CONFIG
# ============================================================

TARGETS_DIR            = "targets"
SUBMONITOR_TARGETS_DIR = "../submonitor/targets"
DATABASE_FILE  = "typosquat.db"
# Carência (dias) antes de marcar um sósia como REMOVIDO — absorve variação
# transitória do dnstwist/DNS. Ajustável por env.
CLOSE_GRACE_DAYS = int(os.environ.get("ARGUS_CLOSE_GRACE_DAYS", "3"))
HTML_REPORT    = "typosquat_report.html"
APACHE_DOCROOT = "/var/www/argus"

DNSTWIST_BIN    = shutil.which("dnstwist") or "dnstwist"
# Performance do dnstwist (ajustável por env). O custo é DNS: domínios longos geram
# muitas permutações e cada uma precisa ser resolvida. Defaults priorizam velocidade.
DNSTWIST_THREADS = int(os.environ.get("ARGUS_DNSTWIST_THREADS", "32"))
DNSTWIST_TIMEOUT = int(os.environ.get("ARGUS_DNSTWIST_TIMEOUT", "900"))   # por domínio-base (s)
# Resolvers rápidos/dedicados — MAIOR ganho (evita resolver local lento/rate-limited).
# Vazio ("") usa o resolver do sistema.
DNSTWIST_NAMESERVERS = os.environ.get("ARGUS_DNSTWIST_NAMESERVERS", "1.1.1.1,8.8.8.8,9.9.9.9")
# Opcional: restringir os fuzzers para cortar permutações em domínios longos
# (ex.: "addition,homoglyph,hyphenation,insertion,omission,repetition,replacement,"
#       "transposition,vowel-swap,tld-swap,bitsquatting,subdomain"). Vazio = todos.
DNSTWIST_FUZZERS = os.environ.get("ARGUS_DNSTWIST_FUZZERS", "")

# ============================================================
# SYSLOG RFC 5424
# ============================================================

SYSLOG_FILE = "/var/log/argus/typosquat/typosquat.log"
SYSLOG_APP  = "typosquat"
APP_VERSION = "2.0"

_FAC      = 16
_SEV      = {"EMERG":0,"ALERT":1,"CRIT":2,"ERR":3,"WARN":4,"NOTICE":5,"INFO":6,"DEBUG":7}
_RISK_SEV = {"CRITICO":"CRIT","ALTO":"WARN","MEDIO":"NOTICE","BAIXO":"INFO","INFO":"INFO"}

_syslog_fd = None
_run_id    = None
_pid       = os.getpid()
_hostname  = socket.gethostname()


def _syslog_open():
    global _syslog_fd
    Path(SYSLOG_FILE).parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(SYSLOG_FILE, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o640)
    _syslog_fd = os.fdopen(fd, "a", encoding="ascii", errors="replace")

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

def syslog_init(campaigns: int, domains: int):
    global _run_id
    _run_id = str(uuid.uuid4())
    _syslog_open()
    syslog_write("INFO","SCAN_START",
                 f"Iniciando typosquat: {campaigns} campanha(s), {domains} domínio(s)-base",
                 module=SYSLOG_APP, version=APP_VERSION,
                 campaigns=str(campaigns), domains=str(domains))

def syslog_look(result: dict):
    risk   = result.get("risk","MEDIO")
    status = result.get("status","NOVO")
    sev    = _RISK_SEV.get(risk,"INFO")
    if status == "REMOVIDO":
        sev = "NOTICE"; msgid = "TYPO_REM"
        msg = f"Sósia removido: {result.get('domain','')}"
    elif status == "REINCIDENTE":
        msgid = "TYPO_REIN"
        msg = f"Sósia reincidente [{risk}]: {result.get('domain','')} (de {result.get('base_domain','')})"
    else:
        msgid = "TYPO_NEW"
        msg = f"Sósia registrado [{risk}]: {result.get('domain','')} (de {result.get('base_domain','')})"
    syslog_write(sev, msgid, msg,
                 domain      = str(result.get("domain","")),
                 base_domain = str(result.get("base_domain","")),
                 campanha    = str(result.get("campanha","")),
                 fuzzer      = str(result.get("fuzzer","")),
                 ip          = str(result.get("ip","")),
                 mx          = str(result.get("mx", False)),
                 risk        = risk, status = status)

def syslog_error(context: str, exc: Exception):
    syslog_write("ERR","SCAN_ERR",f"{context}: {exc}",
                 module=SYSLOG_APP, context=context, error_type=type(exc).__name__)

def syslog_end(novos, reincidentes, removidos, duration_s: int, status: str = "success"):
    allr = novos + reincidentes
    criticos = sum(1 for r in allr if r.get("risk")=="CRITICO")
    altos    = sum(1 for r in allr if r.get("risk")=="ALTO")
    sev = "INFO" if status == "success" else "ERR"
    syslog_write(sev,"SCAN_END",
                 f"Typosquat {status} em {duration_s}s — novos={len(novos)} reincidentes={len(reincidentes)} removidos={len(removidos)} criticos={criticos}",
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
        CREATE TABLE IF NOT EXISTS lookalikes (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            campanha    TEXT,
            base_domain TEXT,
            domain      TEXT,
            fuzzer      TEXT,
            ip          TEXT,
            mx          INTEGER,
            risk        TEXT,
            first_seen  TEXT,
            last_seen   TEXT,
            status      TEXT
        )
    """)
    conn.commit(); conn.close()

# ============================================================
# TARGETS  (reaproveita os do submonitor — igual ao credentials/email)
# ============================================================

import re
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9_-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9_-]{1,63}(?<!-))*$")

def _valid_domain(s: str) -> bool:
    return bool(_HOSTNAME_RE.match(s))

def _resolve_targets_dir() -> Path:
    own = Path(TARGETS_DIR)
    if own.exists() and any(own.glob("*.txt")):
        print(f"  [TARGETS] Usando override próprio: {own.absolute()}")
        return own
    sub = Path(SUBMONITOR_TARGETS_DIR)
    if sub.exists() and any(sub.glob("*.txt")):
        print(f"  [TARGETS] Reaproveitando domínios do submonitor: {sub.resolve()}")
        return sub
    raise FileNotFoundError(
        f"Nenhum domínio encontrado.\n"
        f"  Adicione .txt em {sub.resolve() if sub.exists() else sub} (submonitor)\n"
        f"  ou em {own.absolute()} (override de typosquat).")

def load_campaigns() -> list[tuple[str, list[str]]]:
    target_path = _resolve_targets_dir()
    campaigns = []
    for f in sorted(target_path.glob("*.txt")):
        domains, seen = [], set()
        for raw in f.read_text(encoding="utf-8").splitlines():
            line = raw.split("#", 1)[0].strip().lower()
            if not line or line in seen:
                continue
            if not _valid_domain(line):
                print(f"  [AVISO] {f.stem}: domínio inválido ignorado: {line!r}")
                continue
            seen.add(line); domains.append(line)
        if domains:
            campaigns.append((f.stem, domains))
            print(f"  [TARGETS] {f.stem}: {len(domains)} domínio(s)-base")
    return campaigns

# ============================================================
# DNSTWIST
# ============================================================

def dnstwist_available() -> bool:
    return shutil.which(DNSTWIST_BIN) is not None or Path(DNSTWIST_BIN).exists()

def _risk_for(has_ip: bool, has_mx: bool) -> str:
    if has_ip and has_mx: return "CRITICO"
    if has_ip:            return "ALTO"
    return "MEDIO"

def run_dnstwist(base_domain: str, campanha: str) -> list[dict]:
    """Roda o dnstwist (somente sósia REGISTRADOS, saída JSON) para um domínio-base."""
    cmd = [DNSTWIST_BIN, "--registered", "--format", "json",
           "--threads", str(DNSTWIST_THREADS)]
    if DNSTWIST_NAMESERVERS:
        cmd += ["--nameservers", DNSTWIST_NAMESERVERS]
    if DNSTWIST_FUZZERS:
        cmd += ["--fuzzers", DNSTWIST_FUZZERS]
    cmd += [base_domain]
    print(f"[DNSTWIST] {base_domain} ({campanha})")
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=DNSTWIST_TIMEOUT)
    except subprocess.TimeoutExpired:
        print(f"  [TIMEOUT] {base_domain}"); syslog_error(f"dnstwist timeout({base_domain})", Exception("timeout"))
        return []
    except Exception as exc:
        syslog_error(f"dnstwist({base_domain})", exc); print(f"  [ERRO] {exc}")
        return []
    if not (proc.stdout or "").strip():
        return []
    try:
        data = json.loads(proc.stdout)
    except Exception:
        return []

    results = []
    for e in data:
        if not isinstance(e, dict):
            continue
        dom = str(e.get("domain", "")).strip().lower()
        fuzzer = str(e.get("fuzzer", "") or "")
        # ignora o próprio domínio original
        if not dom or dom == base_domain or fuzzer in ("*original", "original"):
            continue
        a_recs  = e.get("dns_a") or e.get("dns_aaaa") or []
        mx_recs = e.get("dns_mx") or []
        has_ip  = bool(a_recs)
        has_mx  = bool(mx_recs)
        ip = str(a_recs[0]) if a_recs else ""
        results.append({
            "campanha": campanha, "base_domain": base_domain, "domain": dom,
            "fuzzer": fuzzer, "ip": ip, "mx": has_mx,
            "risk": _risk_for(has_ip, has_mx),
        })
    print(f"  → {len(results)} sósia(s) registrado(s)")
    return results

# ============================================================
# PROCESS RESULTS
# ============================================================

def process_results(results: list[dict]):
    conn   = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    now    = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    novos, reincidentes, removidos = [], [], []
    current = set()

    for r in results:
        dom = r["domain"]; current.add(dom)
        cursor.execute("SELECT id FROM lookalikes WHERE domain=? ORDER BY id DESC LIMIT 1", (dom,))
        existing = cursor.fetchone()
        if existing:
            r["status"] = "REINCIDENTE"; reincidentes.append(r); syslog_look(r)
            cursor.execute(
                "UPDATE lookalikes SET campanha=?,base_domain=?,fuzzer=?,ip=?,mx=?,risk=?,last_seen=?,status=? WHERE id=?",
                (r["campanha"], r["base_domain"], r["fuzzer"], r["ip"], int(r["mx"]),
                 r["risk"], now, "REINCIDENTE", existing[0]))
        else:
            r["status"] = "NOVO"; novos.append(r); syslog_look(r)
            cursor.execute(
                "INSERT INTO lookalikes (campanha,base_domain,domain,fuzzer,ip,mx,risk,first_seen,last_seen,status) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (r["campanha"], r["base_domain"], dom, r["fuzzer"], r["ip"], int(r["mx"]),
                 r["risk"], now, now, "NOVO"))

    grace_cutoff = (datetime.datetime.now() - datetime.timedelta(days=CLOSE_GRACE_DAYS)).strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("SELECT id,domain,base_domain,campanha FROM lookalikes WHERE status IN ('NOVO','REINCIDENTE') AND last_seen < ?", (grace_cutoff,))
    for row_id, dom, base, camp in cursor.fetchall():
        if dom not in current:
            entry = {"domain": dom, "base_domain": base or "", "campanha": camp or "",
                     "fuzzer": "", "ip": "", "mx": False, "risk": "INFO", "status": "REMOVIDO"}
            removidos.append(entry); syslog_look(entry)
            cursor.execute("UPDATE lookalikes SET status='REMOVIDO', last_seen=? WHERE id=?", (now, row_id))
    conn.commit(); conn.close()
    return novos, reincidentes, removidos

# ============================================================
# CRON
# ============================================================

def setup_cron():
    script_path = Path(__file__).resolve()
    python_bin  = shutil.which("python3") or "/usr/bin/python3"
    log_stdout  = Path(SYSLOG_FILE).parent / "typosquat_stdout.log"
    cron_file   = Path("/etc/cron.d/argus-typosquat")
    ti_path     = str(script_path.parent.parent)
    cron_content = (
        "# typosquat — detecção de domínios sósia (dnstwist) semanalmente aos domingos as 05h00\n"
        "# Para remover: sudo rm /etc/cron.d/argus-typosquat\n"
        "SHELL=/bin/bash\n"
        "PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n"
        f"PYTHONPATH={ti_path}\n\n"
        f"0 5 * * 0 root umask 0002 && cd {script_path.parent} && {python_bin} {script_path} >> {log_stdout} 2>&1\n"
    )
    try:
        cron_file.write_text(cron_content, encoding="utf-8"); cron_file.chmod(0o644)
        print(f"[+] Cron instalado : {cron_file}")
        print( "    Agenda         : semanalmente aos domingos as 05h00 (0 5 * * 0)")
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

    os.chdir(Path(__file__).resolve().parent)
    _start = time.monotonic()
    print("=" * 60)
    print("ARGUS — Typosquat  (dnstwist / homoglyph)")
    print("=" * 60)

    if not dnstwist_available():
        print("[ERRO] dnstwist não encontrado — instale com: pip install dnstwist  (ou apt install dnstwist)")
        sys.exit(1)

    init_database()
    print()
    print("[+] Carregando campanhas...")
    try: campaigns = load_campaigns()
    except FileNotFoundError as exc: print(f"[ERRO] {exc}"); sys.exit(1)

    total_domains = sum(len(d) for _, d in campaigns)
    print(f"[+] {len(campaigns)} campanha(s) | {total_domains} domínio(s)-base")
    syslog_init(len(campaigns), total_domains)
    print()

    try:
        results: list[dict] = []
        for campanha, domains in campaigns:
            print(f"\n--- Campanha: {campanha} ({len(domains)} domínio(s)-base) ---")
            for d in domains:
                results.extend(run_dnstwist(d, campanha))

        novos, reincidentes, removidos = process_results(results)

        # ── Reconhecimento (RECONHECIDO -> INFO) ──────────────────
        if ack is not None:
            _ack_n = ack.apply("typosquat", novos, reincidentes)
            if _ack_n:
                print(f"[ACK] {_ack_n} sósia(s) reconhecido(s) -> status RECONHECIDO / risco INFO")

        # ── Store central de achados (argus.db) — ADITIVO ─────────
        if _findings is not None:
            try:
                obs, closed = _findings.sync_findings(
                    "typosquat", novos + reincidentes,
                    key_of=lambda r: r.get("domain", ""),
                    severity_of=lambda r: r.get("risk", "MEDIO"),
                    title_of=lambda r: f"{r.get('domain','')} (sósia de {r.get('base_domain','')})",
                    campanha_of=lambda r: r.get("campanha", ""),
                    details_of=lambda r: {"base_domain": r.get("base_domain",""), "fuzzer": r.get("fuzzer",""),
                                          "ip": r.get("ip",""), "mx": r.get("mx", False)},
                    run_id=str(_run_id or ""))
                print(f"[FINDINGS] argus.db: {obs} observado(s), {closed} fechado(s)")
                try:
                    from reporter import write_findings_page as _wfp
                    if _wfp(APACHE_DOCROOT): print("[FINDINGS] página de Gestão de Achados atualizada")
                except Exception: pass
            except Exception as _exc:
                print(f"[FINDINGS] sync ignorado (não crítico): {_exc}")

        from pathlib import Path as _Path
        import os as _os, shutil as _shutil
        _docroot = _Path(APACHE_DOCROOT)
        _out = str(_docroot / HTML_REPORT) if _docroot.exists() else HTML_REPORT

        generate_typosquat_report(novos, reincidentes, removidos, output_path=_out)
        _os.chmod(_out, 0o644)
        if _out != HTML_REPORT:
            _shutil.copy2(_out, HTML_REPORT)

        duration_s = int(time.monotonic() - _start)
        syslog_end(novos, reincidentes, removidos, duration_s)
    except Exception as exc:
        duration_s = int(time.monotonic() - _start)
        syslog_error("main", exc); syslog_end([], [], [], duration_s, status="error"); raise

    criticos = sum(1 for r in novos + reincidentes if r.get("risk") == "CRITICO")
    print()
    print(f"[+] Relatório        : {Path(HTML_REPORT).absolute()}")
    print(f"[+] Log RFC5424      : {SYSLOG_FILE}")
    print(f"[+] Sósia (crítico)  : {criticos}")
    print(f"[+] Novos            : {len(novos)}")
    print(f"[+] Reincidentes     : {len(reincidentes)}")
    print(f"[+] Removidos        : {len(removidos)}")
    print(f"[+] Tempo de execução: {_fmt_duration(duration_s)}")

if __name__ == "__main__":
    main()
