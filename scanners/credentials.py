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
Credential Argus — Hudson Rock (infostealer)

Lê campanhas de targets/ (um .txt por empresa, com domínios), consulta a
exposição de credenciais em logs de infostealer (Hudson Rock Cavalier, gratuito)
e gera relatório HTML via reporter.py. Metadata-only: agregados por domínio,
nunca credenciais em si.

Uso:
    argus-credentials
    python3 credentials.py --install-cron
"""

import datetime
import os
import re
import socket
import sqlite3
import sys
import time
import uuid
from pathlib import Path

try:
    from threatintel.providers import hudsonrock
    _HR_AVAILABLE = True
except ImportError:
    _HR_AVAILABLE = False
    hudsonrock = None

try:
    from reporter import generate_credentials_report
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

# Por padrão reusa os MESMOS domínios do submonitor (../submonitor/targets).
# Se você quiser um conjunto diferente só para credenciais, basta colocar .txt
# em credentials/targets/ — esse diretório tem precedência quando não está vazio.
TARGETS_DIR            = "targets"                  # override próprio (opcional)
SUBMONITOR_TARGETS_DIR = "../submonitor/targets"   # padrão (reaproveitado)
DATABASE_FILE  = "credentials.db"
# Carência (dias) antes de marcar um domínio como REMOVIDO — absorve variação
# transitória da fonte (Hudson Rock). Ajustável por env.
CLOSE_GRACE_DAYS = int(os.environ.get("ARGUS_CLOSE_GRACE_DAYS", "3"))
HTML_REPORT    = "credentials_report.html"
APACHE_DOCROOT = "/var/www/argus"

# ============================================================
# SYSLOG RFC 5424
# ============================================================

SYSLOG_FILE = "/var/log/argus/credentials/credentials.log"
SYSLOG_APP  = "credentials"
APP_VERSION = "2.0"

_FAC      = 16
_SEV      = {"EMERG":0,"ALERT":1,"CRIT":2,"ERR":3,"WARN":4,"NOTICE":5,"INFO":6,"DEBUG":7}
_RISK_SEV = {"CRITICO":"CRIT","ALTO":"WARN","MEDIO":"NOTICE","BAIXO":"INFO"}

_syslog_fd = None
_run_id    = None
_pid       = os.getpid()
_hostname  = socket.gethostname()


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

def syslog_init(campaigns: int, domains: int):
    global _run_id
    _run_id = str(uuid.uuid4())
    _syslog_open()
    syslog_write("INFO","SCAN_START",
                 f"Iniciando varredura de credenciais: {campaigns} campanha(s), {domains} domínio(s)",
                 module=SYSLOG_APP, version=APP_VERSION,
                 campaigns=str(campaigns), domains=str(domains))

def syslog_domain(result: dict):
    risk   = result.get("risk","BAIXO")
    status = result.get("status","NOVO")
    sev    = _RISK_SEV.get(risk,"INFO")
    if status == "CORRIGIDO":
        sev = "NOTICE"; msgid = "CRED_FIX"
        msg = f"Exposição corrigida: {result.get('domain','')}"
    elif status == "RESSURGIDO":
        msgid = "CRED_RESURG"
        msg = f"Exposição ressurgida [{risk}]: {result.get('domain','')} (total={result.get('total',0)})"
    elif status == "REINCIDENTE":
        msgid = "CRED_REIN"
        msg = f"Exposição reincidente [{risk}]: {result.get('domain','')} (total={result.get('total',0)})"
    else:
        msgid = "CRED_NEW"
        msg = f"Exposição [{risk}]: {result.get('domain','')} (total={result.get('total',0)})"
    syslog_write(sev, msgid, msg,
                 domain        = str(result.get("domain","")),
                 campanha      = str(result.get("campanha","")),
                 total         = str(result.get("total",0)),
                 employees     = str(result.get("employees",0)),
                 users         = str(result.get("users",0)),
                 third_parties = str(result.get("third_parties",0)),
                 risk          = risk, status = status,
                 top_url       = str(result.get("top_url","")),
                 source        = str(result.get("source","")))

def syslog_error(context: str, exc: Exception):
    syslog_write("ERR","SCAN_ERR",f"{context}: {exc}",
                 module=SYSLOG_APP, context=context, error_type=type(exc).__name__)

def syslog_end(novos, reincidentes, removidos, duration_s: int, status: str = "success"):
    allr = novos + reincidentes
    criticos = sum(1 for r in allr if r.get("risk")=="CRITICO")
    altos    = sum(1 for r in allr if r.get("risk")=="ALTO")
    sev = "INFO" if status == "success" else "ERR"
    syslog_write(sev,"SCAN_END",
                 f"Varredura {status} em {duration_s}s — novos={len(novos)} reincidentes={len(reincidentes)} removidos={len(removidos)} criticos={criticos}",
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
        CREATE TABLE IF NOT EXISTS domains (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            campanha      TEXT,
            domain        TEXT,
            total         INTEGER,
            employees     INTEGER,
            users         INTEGER,
            third_parties INTEGER,
            top_url       TEXT,
            risk          TEXT,
            first_seen    TEXT,
            last_seen     TEXT,
            status        TEXT
        )
    """)
    conn.commit(); conn.close()

# ============================================================
# TARGETS
# ============================================================

def _resolve_targets_dir() -> Path:
    """Usa credentials/targets/ se tiver .txt (override); senão reusa os do submonitor."""
    own = Path(TARGETS_DIR)
    if own.exists() and any(own.glob("*.txt")):
        print(f"  [TARGETS] Usando override próprio: {own.absolute()}")
        return own
    sub = Path(SUBMONITOR_TARGETS_DIR)
    if sub.exists() and any(sub.glob("*.txt")):
        print(f"  [TARGETS] Reaproveitando domínios do submonitor: {sub.resolve()}")
        return sub
    # nenhum dos dois tem .txt — erra apontando os dois caminhos
    raise FileNotFoundError(
        f"Nenhum domínio encontrado.\n"
        f"  Adicione .txt em {sub.resolve() if sub.exists() else sub} (submonitor)\n"
        f"  ou em {own.absolute()} (override só de credenciais).")


# Validação de domínio (segurança — OWASP A03): só hostname válido entra na
# consulta à API. Entradas legítimas não mudam; inválidas são ignoradas.
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9_-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9_-]{1,63}(?<!-))*$")

def _valid_domain(s: str) -> bool:
    return bool(_HOSTNAME_RE.match(s))


def load_campaigns() -> list[tuple[str, list[str]]]:
    target_path = _resolve_targets_dir()
    campaign_files = sorted(target_path.glob("*.txt"))
    campaigns = []
    for f in campaign_files:
        domains, skipped = [], 0
        for raw in f.read_text(encoding="utf-8").splitlines():
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

# ============================================================
# SCAN
# ============================================================

def _top_url(intel: dict) -> str:
    for key in ("employees_urls", "clients_urls", "third_parties_urls"):
        lst = intel.get(key) or []
        if lst:
            return str(lst[0].get("url", ""))
    return ""

def run_scan(campaigns: list[tuple[str, list[str]]]) -> list[dict]:
    results = []
    for campanha, domains in campaigns:
        print(f"\n--- Campanha: {campanha} ({len(domains)} domínio(s)) ---")
        for domain in domains:
            intel = hudsonrock.get_domain_exposure_safe(domain)
            intel["campanha"] = campanha
            intel["risk"]     = hudsonrock.classify_risk(intel)
            intel["top_url"]  = _top_url(intel)
            results.append(intel)
            print(f"  [HR] {domain}: total={intel.get('total',0)} "
                  f"(func={intel.get('employees',0)} users={intel.get('users',0)}) [{intel['risk']}]")
            # cortesia com a API gratuita (apenas em consulta real, não em cache hit)
            if intel.get("source") == "api":
                time.sleep(0.5)
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
        domain = r["domain"]; current.add(domain)
        cursor.execute("SELECT id,status FROM domains WHERE domain=? ORDER BY id DESC LIMIT 1", (domain,))
        existing = cursor.fetchone()
        if existing:
            new_status = "RESSURGIDO" if existing[1] == "CORRIGIDO" else "REINCIDENTE"
            r["status"] = new_status; reincidentes.append(r); syslog_domain(r)
            cursor.execute(
                "UPDATE domains SET campanha=?,total=?,employees=?,users=?,third_parties=?,top_url=?,risk=?,last_seen=?,status=? WHERE id=?",
                (r["campanha"], r.get("total",0), r.get("employees",0), r.get("users",0),
                 r.get("third_parties",0), r.get("top_url",""), r["risk"], now, new_status, existing[0]))
        else:
            r["status"] = "NOVO"; novos.append(r); syslog_domain(r)
            cursor.execute(
                "INSERT INTO domains (campanha,domain,total,employees,users,third_parties,top_url,risk,first_seen,last_seen,status) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (r["campanha"], domain, r.get("total",0), r.get("employees",0), r.get("users",0),
                 r.get("third_parties",0), r.get("top_url",""), r["risk"], now, now, "NOVO"))

    grace_cutoff = (datetime.datetime.now() - datetime.timedelta(days=CLOSE_GRACE_DAYS)).strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("SELECT id,domain,campanha FROM domains WHERE status IN ('REINCIDENTE','RESSURGIDO') AND last_seen < ?", (grace_cutoff,))
    for row_id, old_domain, old_campanha in cursor.fetchall():
        if old_domain not in current:
            entry = {"domain":old_domain,"campanha":old_campanha or "","risk":"BAIXO","status":"CORRIGIDO",
                     "total":0,"employees":0,"users":0,"third_parties":0,"top_url":"",
                     "employees_urls":[],"clients_urls":[],"third_parties_urls":[]}
            removidos.append(entry); syslog_domain(entry)
            cursor.execute("UPDATE domains SET status='CORRIGIDO', last_seen=? WHERE id=?", (now, row_id))
    conn.commit(); conn.close()
    return novos, reincidentes, removidos

# ============================================================
# CRON
# ============================================================

def setup_cron():
    import shutil
    script_path = Path(__file__).resolve()
    python_bin  = shutil.which("python3") or "/usr/bin/python3"
    log_stdout  = Path(SYSLOG_FILE).parent / "credentials_stdout.log"
    cron_file   = Path("/etc/cron.d/argus-credentials")
    ti_path     = str(script_path.parent.parent)
    cron_content = (
        "# credentials — exposição de credenciais (infostealer) diariamente as 14h00\n"
        "# Para remover: sudo rm /etc/cron.d/argus-credentials\n"
        "SHELL=/bin/bash\n"
        "PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n"
        f"PYTHONPATH={ti_path}\n\n"
        f"0 14 * * * root umask 0002 && cd {script_path.parent} && {python_bin} {script_path} >> {log_stdout} 2>&1\n"
    )
    try:
        cron_file.write_text(cron_content, encoding="utf-8"); cron_file.chmod(0o644)
        print(f"[+] Cron instalado : {cron_file}")
        print( "    Agenda         : diariamente as 14h00 (0 14 * * *)")
        print(f"    Script         : {script_path}")
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
    print("ARGUS — Credential Exposure  (Hudson Rock / infostealer)")
    print("=" * 60)

    if not _HR_AVAILABLE:
        print("[ERRO] Provider hudsonrock não encontrado — configure PYTHONPATH=/etc/argus")
        sys.exit(1)

    init_database()
    print()
    print("[+] Carregando campanhas...")
    try: campaigns = load_campaigns()
    except FileNotFoundError as exc: print(f"[ERRO] {exc}"); sys.exit(1)

    total_domains = sum(len(d) for _, d in campaigns)
    print(f"[+] {len(campaigns)} campanha(s) | {total_domains} domínio(s)")
    syslog_init(len(campaigns), total_domains)

    try:
        results = run_scan(campaigns)
        novos, reincidentes, removidos = process_results(results)

        # ── Store central de achados (argus.db) — ADITIVO ─────────
        # Achado = domínio com exposição real (total > 0); domínio limpo não é achado.
        if _findings is not None:
            try:
                _exposed = [r for r in (novos + reincidentes) if int(r.get("total") or 0) > 0]
                obs, closed = _findings.sync_findings(
                    "credentials", _exposed,
                    key_of=lambda r: r.get("domain", ""),
                    severity_of=lambda r: r.get("risk", "BAIXO"),
                    title_of=lambda r: f"{r.get('domain','')} ({r.get('total',0)} exposição(ões))",
                    campanha_of=lambda r: r.get("campanha", ""),
                    details_of=lambda r: {"total": r.get("total",0), "employees": r.get("employees",0),
                                          "users": r.get("users",0), "third_parties": r.get("third_parties",0)},
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
            _ack_n = ack.apply("credentials", novos, reincidentes)
            if _ack_n:
                print(f"[ACK] {_ack_n} domínio(s) reconhecido(s) -> status RECONHECIDO / risco INFO")

        # ── Esconde do relatório os domínios cujo ACHADO foi tratado (Mitigado/FP) ──
        if _findings is not None:
            try:
                _hidden = _findings.hidden_keys("credentials")
                if _hidden:
                    novos        = [r for r in novos        if r.get("domain") not in _hidden]
                    reincidentes = [r for r in reincidentes if r.get("domain") not in _hidden]
                    removidos    = [r for r in removidos    if r.get("domain") not in _hidden]
            except Exception:
                pass

        from pathlib import Path as _Path
        import os as _os, shutil as _shutil
        _docroot = _Path(APACHE_DOCROOT)
        _out = str(_docroot / HTML_REPORT) if _docroot.exists() else HTML_REPORT

        generate_credentials_report(novos, reincidentes, removidos, output_path=_out)
        _os.chmod(_out, 0o644)
        if _out != HTML_REPORT:
            _shutil.copy2(_out, HTML_REPORT)

        duration_s = int(time.monotonic() - _start)
        syslog_end(novos, reincidentes, removidos, duration_s)
    except Exception as exc:
        duration_s = int(time.monotonic() - _start)
        syslog_error("main", exc); syslog_end([], [], [], duration_s, status="error"); raise

    comprometidos = sum(1 for r in novos + reincidentes if int(r.get("total", 0) or 0) > 0)
    print()
    print(f"[+] Relatório        : {Path(HTML_REPORT).absolute()}")
    print(f"[+] Log RFC5424      : {SYSLOG_FILE}")
    print(f"[+] Domínios expostos: {comprometidos}")
    print(f"[+] Novos            : {len(novos)}")
    print(f"[+] Reincidentes     : {len(reincidentes)}")
    print(f"[+] Corrigidos       : {len(removidos)}")
    print(f"[+] Tempo de execução: {_fmt_duration(duration_s)}")

if __name__ == "__main__":
    main()
