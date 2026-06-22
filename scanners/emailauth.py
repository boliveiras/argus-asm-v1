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
Argus E-mail Posture — autenticação de e-mail (anti-spoofing) por domínio.

Lê campanhas de targets/ (um .txt por empresa, com domínios — reaproveita os do
submonitor por padrão) e avalia, por consultas DNS (grátis):
  • MX     — o domínio recebe e-mail?
  • SPF    — registro v=spf1; qualificador -all/~all/?all/+all; nº de lookups
  • DMARC  — registro _dmarc; política p=none/quarantine/reject; rua
  • DKIM   — best-effort: sonda seletores comuns (o seletor não é descobrível)

Atribui um risco por domínio (CRÍTICO..INFO) e gera relatório HTML via reporter.
Nota: domínios SEM MX também são avaliados — um domínio que não envia e-mail
ainda deve ter SPF -all + DMARC p=reject para impedir spoofing do *From*.

Uso:
    argus-email
    python3 emailauth.py --install-cron
"""

import datetime
import os
import re
import socket
import sqlite3
import sys
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

try:
    import dns.exception
    import dns.resolver
    _DNS_AVAILABLE = True
except ImportError:
    _DNS_AVAILABLE = False

try:
    from reporter import generate_email_report
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
# Coloque .txt em email/targets/ para um conjunto próprio (tem precedência).
TARGETS_DIR            = "targets"
SUBMONITOR_TARGETS_DIR = "../submonitor/targets"
DATABASE_FILE  = "email.db"
# Carência (dias) antes de marcar um domínio como REMOVIDO — absorve "misses"
# transitórios de DNS. Ajustável por env.
CLOSE_GRACE_DAYS = int(os.environ.get("ARGUS_CLOSE_GRACE_DAYS", "3"))
HTML_REPORT    = "email_report.html"
APACHE_DOCROOT = "/var/www/argus"

DNS_TIMEOUT  = 5.0   # por consulta
DNS_LIFETIME = 8.0   # total por nome
SCAN_WORKERS = 8     # domínios checados em paralelo

# Seletores DKIM comuns (best-effort — o seletor real não é descobrível por DNS).
DKIM_SELECTORS = [
    "default", "google", "selector1", "selector2", "s1", "s2", "k1", "k2",
    "mail", "dkim", "smtp", "mxvault", "amazonses", "sendgrid", "mandrill",
    "mailjet", "zoho", "protonmail", "fm1", "fm2", "fm3", "key1", "dkim1",
]

# ============================================================
# SYSLOG RFC 5424
# ============================================================

SYSLOG_FILE = "/var/log/argus/email/email.log"
SYSLOG_APP  = "email"
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

def syslog_init(campaigns: int, domains: int):
    global _run_id
    _run_id = str(uuid.uuid4())
    _syslog_open()
    syslog_write("INFO","SCAN_START",
                 f"Iniciando verificação de postura de e-mail: {campaigns} campanha(s), {domains} domínio(s)",
                 module=SYSLOG_APP, version=APP_VERSION,
                 campaigns=str(campaigns), domains=str(domains))

def syslog_domain(result: dict):
    risk   = result.get("risk","INFO")
    status = result.get("status","NOVO")
    sev    = _RISK_SEV.get(risk,"INFO")
    if status == "CORRIGIDO":
        sev = "NOTICE"; msgid = "MAIL_FIX"
        msg = f"Postura corrigida: {result.get('domain','')}"
    elif status == "RESSURGIDO":
        msgid = "MAIL_RESURG"
        msg = f"Postura ressurgida [{risk}]: {result.get('domain','')}"
    elif status == "REINCIDENTE":
        msgid = "MAIL_REIN"
        msg = f"Postura reincidente [{risk}]: {result.get('domain','')}"
    else:
        msgid = "MAIL_NEW"
        msg = f"Postura [{risk}]: {result.get('domain','')}"
    syslog_write(sev, msgid, msg,
                 domain   = str(result.get("domain","")),
                 campanha = str(result.get("campanha","")),
                 has_mx   = str(result.get("has_mx", False)),
                 spf      = str(result.get("spf_status","")),
                 dmarc    = str(result.get("dmarc_status","")),
                 dkim     = str(result.get("dkim_status","")),
                 risk     = risk, status = status,
                 issues   = "; ".join(result.get("issues", [])))

def syslog_error(context: str, exc: Exception):
    syslog_write("ERR","SCAN_ERR",f"{context}: {exc}",
                 module=SYSLOG_APP, context=context, error_type=type(exc).__name__)

def syslog_end(novos, reincidentes, removidos, duration_s: int, status: str = "success"):
    allr = novos + reincidentes
    criticos = sum(1 for r in allr if r.get("risk")=="CRITICO")
    altos    = sum(1 for r in allr if r.get("risk")=="ALTO")
    sev = "INFO" if status == "success" else "ERR"
    syslog_write(sev,"SCAN_END",
                 f"Verificação {status} em {duration_s}s — novos={len(novos)} reincidentes={len(reincidentes)} removidos={len(removidos)} criticos={criticos}",
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
            has_mx        INTEGER,
            mx            TEXT,
            spf_status    TEXT,
            dmarc_status  TEXT,
            dkim_status   TEXT,
            dkim_selector TEXT,
            risk          TEXT,
            issues        TEXT,
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
        f"  ou em {own.absolute()} (override só de e-mail).")


_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9_-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9_-]{1,63}(?<!-))*$")

def _valid_domain(s: str) -> bool:
    return bool(_HOSTNAME_RE.match(s))


def load_campaigns() -> list[tuple[str, list[str]]]:
    target_path = _resolve_targets_dir()
    campaign_files = sorted(target_path.glob("*.txt"))
    campaigns = []
    for f in campaign_files:
        domains, skipped, seen = [], 0, set()
        for raw in f.read_text(encoding="utf-8").splitlines():
            line = raw.split("#", 1)[0].strip().lower()
            if not line:
                continue
            if not _valid_domain(line):
                print(f"  [AVISO] {f.stem}: domínio inválido ignorado: {line!r}")
                skipped += 1
                continue
            if line in seen:
                continue
            seen.add(line)
            domains.append(line)
        if domains:
            campaigns.append((f.stem, domains))
            extra = f" ({skipped} inválido(s) ignorado(s))" if skipped else ""
            print(f"  [TARGETS] {f.stem}: {len(domains)} domínio(s){extra}")
    return campaigns

# ============================================================
# CHECAGENS DNS (SPF / DMARC / DKIM / MX)
# ============================================================

def _make_resolver() -> "dns.resolver.Resolver":
    r = dns.resolver.Resolver()
    r.timeout  = DNS_TIMEOUT
    r.lifetime = DNS_LIFETIME
    return r

def _txt(resolver, name: str) -> list[str]:
    try:
        ans = resolver.resolve(name, "TXT")
    except dns.exception.DNSException:
        return []
    out = []
    for rr in ans:
        try:
            out.append(b"".join(rr.strings).decode("utf-8", "replace"))
        except Exception:
            out.append(str(rr).strip('"'))
    return out

def _mx(resolver, domain: str) -> list[str]:
    try:
        ans = resolver.resolve(domain, "MX")
    except dns.exception.DNSException:
        return []
    return sorted({str(r.exchange).rstrip(".") for r in ans if str(r.exchange).rstrip(".")})


def _analyze_spf(records: list[str]) -> dict:
    spfs = [t for t in records if t.lower().startswith("v=spf1")]
    if not spfs:
        return {"status": "AUSENTE", "raw": "", "all": "", "lookups": 0}
    if len(spfs) > 1:
        return {"status": "INVALIDO", "raw": " || ".join(spfs), "all": "",
                "lookups": 0, "note": "múltiplos registros SPF"}
    raw = spfs[0]
    low = raw.lower()
    m = re.search(r'([-~?+])all\b', low)
    qual = m.group(1) if m else ""
    lookups = 0
    for tk in low.split():
        name = re.split(r'[:=]', tk.lstrip("+-~?"), maxsplit=1)[0]
        if name in ("include", "a", "mx", "ptr", "exists", "redirect"):
            lookups += 1
    if qual == "+":   status = "PERIGOSO"
    elif qual == "-": status = "FORTE"
    elif qual == "~": status = "SOFTFAIL"
    elif qual == "?": status = "NEUTRO"
    else:             status = "INVALIDO"   # sem mecanismo 'all'
    if lookups > 10:
        status = "INVALIDO"
    return {"status": status, "raw": raw, "all": (qual + "all") if qual else "", "lookups": lookups}


def _analyze_dmarc(records: list[str]) -> dict:
    recs = [t for t in records if t.lower().startswith("v=dmarc1")]
    if not recs:
        return {"status": "AUSENTE", "raw": "", "policy": "", "rua": False}
    if len(recs) > 1:
        return {"status": "INVALIDO", "raw": " || ".join(recs), "policy": "", "rua": False}
    raw = recs[0]
    low = raw.lower()
    m = re.search(r'\bp\s*=\s*(none|quarantine|reject)\b', low)
    policy = m.group(1) if m else ""
    rua = "rua=" in low
    if policy == "reject":       status = "REJECT"
    elif policy == "quarantine": status = "QUARANTINE"
    elif policy == "none":       status = "NONE"
    else:                        status = "INVALIDO"
    return {"status": status, "raw": raw, "policy": policy, "rua": rua}


def _probe_dkim(resolver, domain: str) -> dict:
    for sel in DKIM_SELECTORS:
        for t in _txt(resolver, f"{sel}._domainkey.{domain}"):
            tl = t.lower()
            if "v=dkim1" in tl or "k=rsa" in tl or "p=" in tl:
                return {"status": "ENCONTRADO", "selector": sel}
    return {"status": "NAO DETECTADO", "selector": ""}


_RANK = {"CRITICO": 0, "ALTO": 1, "MEDIO": 2, "BAIXO": 3, "INFO": 4}

def _score(has_mx: bool, spf: dict, dmarc: dict, dkim: dict) -> tuple[str, list[str]]:
    issues: list[str] = []
    risk = "BAIXO"
    def bump(r: str):
        nonlocal risk
        if _RANK[r] < _RANK[risk]:
            risk = r

    s = spf["status"]
    if s == "AUSENTE":     issues.append("SPF ausente"); bump("ALTO")
    elif s == "PERIGOSO":  issues.append("SPF +all (autoriza qualquer remetente)"); bump("CRITICO")
    elif s == "INVALIDO":  issues.append("SPF inválido (múltiplos registros ou >10 lookups)"); bump("ALTO")
    elif s == "SOFTFAIL":  issues.append("SPF softfail (~all) — prefira -all"); bump("MEDIO")
    elif s == "NEUTRO":    issues.append("SPF neutro (?all)"); bump("MEDIO")

    d = dmarc["status"]
    if d == "AUSENTE":       issues.append("DMARC ausente"); bump("ALTO")
    elif d == "NONE":        issues.append("DMARC p=none (apenas monitora, não bloqueia)"); bump("ALTO")
    elif d == "QUARANTINE":  issues.append("DMARC p=quarantine (não rejeita)"); bump("MEDIO")
    elif d == "INVALIDO":    issues.append("DMARC inválido"); bump("ALTO")
    elif d == "REJECT" and not dmarc.get("rua"):
        issues.append("DMARC sem rua (sem relatórios agregados)"); bump("BAIXO")

    # Totalmente spoofável: sem SPF e sem DMARC eficaz
    if s == "AUSENTE" and d in ("AUSENTE", "NONE"):
        issues.append("Domínio spoofável (sem SPF e sem DMARC eficaz)"); bump("CRITICO")

    # DKIM é best-effort (informativo) — só pontua levemente quando recebe e-mail
    if dkim["status"] == "NAO DETECTADO" and has_mx:
        issues.append("DKIM não detectado (seletores comuns)"); bump("BAIXO")

    if not issues:
        risk = "INFO"
    return risk, issues


def check_domain(campanha: str, domain: str) -> dict:
    resolver = _make_resolver()
    mx_hosts = _mx(resolver, domain)
    has_mx   = bool(mx_hosts)
    base_txt = _txt(resolver, domain)
    spf      = _analyze_spf(base_txt)
    dmarc    = _analyze_dmarc(_txt(resolver, "_dmarc." + domain))
    dkim     = _probe_dkim(resolver, domain)
    risk, issues = _score(has_mx, spf, dmarc, dkim)
    return {
        "campanha":      campanha,
        "domain":        domain,
        "has_mx":        has_mx,
        "mx":            ", ".join(mx_hosts[:3]),
        "spf_status":    spf["status"],
        "spf_raw":       spf["raw"],
        "dmarc_status":  dmarc["status"],
        "dmarc_raw":     dmarc["raw"],
        "dmarc_rua":     dmarc.get("rua", False),
        "dkim_status":   dkim["status"],
        "dkim_selector": dkim["selector"],
        "risk":          risk,
        "issues":        issues,
    }


def run_scan(campaigns: list[tuple[str, list[str]]]) -> list[dict]:
    jobs = [(c, d) for c, domains in campaigns for d in domains]
    results: list[dict] = []
    with ThreadPoolExecutor(max_workers=SCAN_WORKERS) as pool:
        futures = {pool.submit(check_domain, c, d): (c, d) for c, d in jobs}
        for fut in futures:
            c, d = futures[fut]
            try:
                r = fut.result()
            except Exception as exc:
                print(f"  [ERRO] {d}: {exc}")
                continue
            results.append(r)
            print(f"  [MAIL] {r['domain']}: MX={'sim' if r['has_mx'] else 'nao'} "
                  f"SPF={r['spf_status']} DMARC={r['dmarc_status']} DKIM={r['dkim_status']} [{r['risk']}]")
    results.sort(key=lambda r: (r.get("campanha", ""), r.get("domain", "")))
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
        issues_txt = " | ".join(r.get("issues", []))
        cursor.execute("SELECT id,status FROM domains WHERE domain=? ORDER BY id DESC LIMIT 1", (domain,))
        existing = cursor.fetchone()
        if existing:
            new_status = "RESSURGIDO" if existing[1] == "CORRIGIDO" else "REINCIDENTE"
            r["status"] = new_status; reincidentes.append(r); syslog_domain(r)
            cursor.execute(
                "UPDATE domains SET campanha=?,has_mx=?,mx=?,spf_status=?,dmarc_status=?,dkim_status=?,dkim_selector=?,risk=?,issues=?,last_seen=?,status=? WHERE id=?",
                (r["campanha"], int(r["has_mx"]), r["mx"], r["spf_status"], r["dmarc_status"],
                 r["dkim_status"], r["dkim_selector"], r["risk"], issues_txt, now, new_status, existing[0]))
        else:
            r["status"] = "NOVO"; novos.append(r); syslog_domain(r)
            cursor.execute(
                "INSERT INTO domains (campanha,domain,has_mx,mx,spf_status,dmarc_status,dkim_status,dkim_selector,risk,issues,first_seen,last_seen,status) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (r["campanha"], domain, int(r["has_mx"]), r["mx"], r["spf_status"], r["dmarc_status"],
                 r["dkim_status"], r["dkim_selector"], r["risk"], issues_txt, now, now, "NOVO"))

    grace_cutoff = (datetime.datetime.now() - datetime.timedelta(days=CLOSE_GRACE_DAYS)).strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("SELECT id,domain,campanha FROM domains WHERE status IN ('REINCIDENTE','RESSURGIDO') AND last_seen < ?", (grace_cutoff,))
    for row_id, old_domain, old_campanha in cursor.fetchall():
        if old_domain not in current:
            entry = {"domain": old_domain, "campanha": old_campanha or "", "risk": "INFO",
                     "status": "CORRIGIDO", "has_mx": False, "mx": "",
                     "spf_status": "", "spf_raw": "", "dmarc_status": "", "dmarc_raw": "",
                     "dkim_status": "", "dkim_selector": "", "issues": []}
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
    log_stdout  = Path(SYSLOG_FILE).parent / "email_stdout.log"
    cron_file   = Path("/etc/cron.d/argus-email")
    ti_path     = str(script_path.parent.parent)
    cron_content = (
        "# email — postura de e-mail (SPF/DMARC/DKIM) diariamente as 13h00\n"
        "# Para remover: sudo rm /etc/cron.d/argus-email\n"
        "SHELL=/bin/bash\n"
        "PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n"
        f"PYTHONPATH={ti_path}\n\n"
        f"0 13 * * * root umask 0002 && cd {script_path.parent} && {python_bin} {script_path} >> {log_stdout} 2>&1\n"
    )
    try:
        cron_file.write_text(cron_content, encoding="utf-8"); cron_file.chmod(0o644)
        print(f"[+] Cron instalado : {cron_file}")
        print( "    Agenda         : diariamente as 13h00 (0 13 * * *)")
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
    print("ARGUS — Postura de E-mail  (SPF / DMARC / DKIM)")
    print("=" * 60)

    if not _DNS_AVAILABLE:
        print("[ERRO] dnspython não encontrado — instale com: pip install dnspython")
        sys.exit(1)

    init_database()
    print()
    print("[+] Carregando campanhas...")
    try: campaigns = load_campaigns()
    except FileNotFoundError as exc: print(f"[ERRO] {exc}"); sys.exit(1)

    total_domains = sum(len(d) for _, d in campaigns)
    print(f"[+] {len(campaigns)} campanha(s) | {total_domains} domínio(s)")
    syslog_init(len(campaigns), total_domains)
    print()

    try:
        results = run_scan(campaigns)
        novos, reincidentes, removidos = process_results(results)

        # ── Store central de achados (argus.db) — ADITIVO ─────────
        # Achado = domínio com postura deficiente (risco != INFO); postura forte não é achado.
        if _findings is not None:
            try:
                _weak = [r for r in (novos + reincidentes) if r.get("risk") != "INFO"]
                obs, closed = _findings.sync_findings(
                    "email", _weak,
                    key_of=lambda r: r.get("domain", ""),
                    severity_of=lambda r: r.get("risk", "BAIXO"),
                    title_of=lambda r: f"{r.get('domain','')} — SPF/{r.get('spf_status','?')} DMARC/{r.get('dmarc_status','?')}",
                    campanha_of=lambda r: r.get("campanha", ""),
                    details_of=lambda r: {"spf": r.get("spf_status",""), "dmarc": r.get("dmarc_status",""),
                                          "dkim": r.get("dkim_status",""), "issues": r.get("issues", [])},
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
            _ack_n = ack.apply("email", novos, reincidentes)
            if _ack_n:
                print(f"[ACK] {_ack_n} domínio(s) reconhecido(s) -> status RECONHECIDO / risco INFO")

        # ── Esconde do relatório os domínios cujo ACHADO foi tratado (Mitigado/FP) ──
        if _findings is not None:
            try:
                _hidden = _findings.hidden_keys("email")
                if _hidden:
                    novos        = [r for r in novos        if r.get("domain") not in _hidden]
                    reincidentes = [r for r in reincidentes if r.get("domain") not in _hidden]
                    removidos    = [r for r in removidos    if r.get("domain") not in _hidden]
            except Exception:
                pass

        import os as _os
        import shutil as _shutil
        from pathlib import Path as _Path
        _docroot = _Path(APACHE_DOCROOT)
        _out = str(_docroot / HTML_REPORT) if _docroot.exists() else HTML_REPORT

        generate_email_report(novos, reincidentes, removidos, output_path=_out)
        _os.chmod(_out, 0o644)
        if _out != HTML_REPORT:
            _shutil.copy2(_out, HTML_REPORT)

        duration_s = int(time.monotonic() - _start)
        syslog_end(novos, reincidentes, removidos, duration_s)
    except Exception as exc:
        duration_s = int(time.monotonic() - _start)
        syslog_error("main", exc); syslog_end([], [], [], duration_s, status="error"); raise

    spoofaveis = sum(1 for r in novos + reincidentes if r.get("risk") in ("CRITICO", "ALTO"))
    print()
    print(f"[+] Relatório        : {Path(HTML_REPORT).absolute()}")
    print(f"[+] Log RFC5424      : {SYSLOG_FILE}")
    print(f"[+] Spoofáveis       : {spoofaveis}")
    print(f"[+] Novos            : {len(novos)}")
    print(f"[+] Reincidentes     : {len(reincidentes)}")
    print(f"[+] Corrigidos       : {len(removidos)}")
    print(f"[+] Tempo de execução: {_fmt_duration(duration_s)}")

if __name__ == "__main__":
    main()
