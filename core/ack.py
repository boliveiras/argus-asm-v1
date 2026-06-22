#!/usr/bin/env python3
"""
ack.py — Reconhecimento de achados (status RECONHECIDO) compartilhado pelos
módulos Argus (monitor / submonitor / credentials).

Quando um achado é reconhecido, o analista assume aquele risco como conhecido
e tratado/aceito. A partir daí, nas próximas execuções o achado passa a ser
exibido como status **RECONHECIDO** e risco **INFO** (sai de CRÍTICO/ALTO/
MÉDIO/BAIXO) em toda a interface — tabela, filtros, KPIs e gráfico.

O reconhecimento é apenas uma camada de triagem na apresentação: o banco de
dados de cada módulo continua registrando o risco e o status reais de detecção
(NOVO/REINCIDENTE), preservando a integridade do diff e a detecção de
FECHADO/REMOVIDO.

Uso (CLI):
    argus-ack add <chave> "<motivo>" [-m monitor|submonitor|credentials]
    argus-ack rm  <chave>            [-m monitor|submonitor|credentials]
    argus-ack list                   [-m monitor|submonitor|credentials]

Exemplos de chave:
    monitor      ->  IP:PORTA/PROTO     ex.: 1.2.3.4:179/tcp
    submonitor   ->  HOSTNAME           ex.: dev.acme.com
    credentials  ->  DOMINIO            ex.: acme.com   (use -m credentials)
    email        ->  DOMINIO            ex.: acme.com   (use -m email)

O módulo é autodetectado pela forma da chave: IP:porta/proto => monitor; caso
contrário => submonitor. Para domínios de credentials/email, informe -m.
"""
import datetime
import os
import re
import sqlite3
import sys
from pathlib import Path

MODULES = ("monitor", "submonitor", "credentials", "email", "typosquat")
_ALIASES = {"m": "monitor", "s": "submonitor", "c": "credentials", "e": "email", "t": "typosquat",
            "mon": "monitor", "sub": "submonitor", "cred": "credentials", "mail": "email", "typo": "typosquat"}

# IP:porta/proto  (ex.: 1.2.3.4:179/tcp  ou  [2001:db8::1]:443/tcp)
_MONITOR_RE = re.compile(r"^.+:\d{1,5}/(?:tcp|udp)$", re.IGNORECASE)


def _db_path() -> str:
    """Store único compartilhado. Prod: /etc/argus/acknowledged.db;
    dev/local: ao lado deste arquivo. Sobrescrevível via ARGUS_ACK_DB."""
    env = os.environ.get("ARGUS_ACK_DB")
    if env:
        return env
    base = Path("/etc/argus")
    if base.is_dir():
        return str(base / "acknowledged.db")
    return str(Path(__file__).resolve().parent / "acknowledged.db")


def _conn() -> sqlite3.Connection:
    conn = sqlite3.connect(_db_path())
    conn.execute(
        "CREATE TABLE IF NOT EXISTS ack ("
        "  module     TEXT NOT NULL,"
        "  key        TEXT NOT NULL,"
        "  reason     TEXT NOT NULL,"
        "  created_at TEXT NOT NULL,"
        "  PRIMARY KEY (module, key))"
    )
    return conn


def normalize_key(key: str) -> str:
    return (key or "").strip().lower()


def detect_module(key: str, override: str | None = None) -> str:
    if override:
        m = _ALIASES.get(override.lower(), override.lower())
        if m not in MODULES:
            raise ValueError(f"módulo inválido: {override} (use {', '.join(MODULES)})")
        return m
    return "monitor" if _MONITOR_RE.match(key.strip()) else "submonitor"


# ── chaves por módulo (a partir de um resultado) ─────────────────────────────
def monitor_key(r: dict) -> str:
    return f"{r.get('ip','')}:{r.get('port','')}/{r.get('protocol','')}".lower()


def submonitor_key(r: dict) -> str:
    return str(r.get("hostname") or "").strip().lower()


def credentials_key(r: dict) -> str:
    return str(r.get("domain") or "").strip().lower()


def email_key(r: dict) -> str:
    return str(r.get("domain") or "").strip().lower()


def typosquat_key(r: dict) -> str:
    return str(r.get("domain") or "").strip().lower()


_KEYFN = {"monitor": monitor_key, "submonitor": submonitor_key,
          "credentials": credentials_key, "email": email_key, "typosquat": typosquat_key}


# ── API consumida pelos scripts ──────────────────────────────────────────────
def load_acks(module: str) -> dict:
    """Retorna {chave_normalizada: motivo} do módulo. Degrada para {} em erro."""
    try:
        conn = _conn()
        rows = conn.execute(
            "SELECT key, reason FROM ack WHERE module=?", (module,)).fetchall()
        conn.close()
        return dict(rows)
    except Exception:
        return {}


def apply(module: str, *lists) -> int:
    """Aplica o reconhecimento sobre listas de resultados (in-place).
    Para cada resultado cuja chave esteja reconhecida: status='RECONHECIDO',
    risk='INFO' e ack_reason=<motivo>. Retorna quantos foram marcados.

    Importante: só altera os dicts em memória (camada de apresentação). Não
    toca no banco de cada módulo, preservando o diff NOVO/REINCIDENTE/FECHADO."""
    acks = load_acks(module)
    keyfn = _KEYFN.get(module)
    if not acks or keyfn is None:
        return 0
    n = 0
    for lst in lists:
        for r in lst:
            if keyfn(r) in acks:
                r["status"] = "RECONHECIDO"
                r["risk"] = "INFO"
                r["ack_reason"] = acks[keyfn(r)]
                n += 1
    return n


# ── CLI ──────────────────────────────────────────────────────────────────────
def _pop_module_flag(argv: list[str]) -> str | None:
    for flag in ("-m", "--module"):
        if flag in argv:
            i = argv.index(flag)
            if i + 1 < len(argv):
                val = argv[i + 1]
                del argv[i:i + 2]
                return val
            del argv[i]
    return None


def _cmd_add(argv: list[str]) -> int:
    override = _pop_module_flag(argv)
    if len(argv) < 2:
        print('uso: argus-ack add <chave> "<motivo>" [-m monitor|submonitor|credentials]')
        return 2
    key = normalize_key(argv[0])
    reason = " ".join(argv[1:]).strip()
    if not key or not reason:
        print("[ERRO] chave e motivo são obrigatórios."); return 2
    try:
        module = detect_module(key, override)
    except ValueError as exc:
        print(f"[ERRO] {exc}"); return 2
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = _conn()
    conn.execute(
        "INSERT INTO ack (module,key,reason,created_at) VALUES (?,?,?,?) "
        "ON CONFLICT(module,key) DO UPDATE SET reason=excluded.reason",
        (module, key, reason, now))
    conn.commit(); conn.close()
    print(f"  ✓ RECONHECIDO registrado ({module}): {key}")
    print(f"    motivo: {reason}")
    return 0


def _cmd_rm(argv: list[str]) -> int:
    override = _pop_module_flag(argv)
    if not argv:
        print("uso: argus-ack rm <chave> [-m monitor|submonitor|credentials]")
        return 2
    key = normalize_key(argv[0])
    conn = _conn()
    if override:
        try:
            module = detect_module(key, override)
        except ValueError as exc:
            print(f"[ERRO] {exc}"); return 2
        cur = conn.execute("DELETE FROM ack WHERE module=? AND key=?", (module, key))
    else:
        cur = conn.execute("DELETE FROM ack WHERE key=?", (key,))
    conn.commit(); n = cur.rowcount; conn.close()
    if n:
        print(f"  ✓ reconhecimento removido: {key} ({n})")
        return 0
    print(f"  (nada a remover para: {key})")
    return 1


def _cmd_list(argv: list[str]) -> int:
    override = _pop_module_flag(argv)
    conn = _conn()
    if override:
        try:
            module = detect_module("", override)
        except ValueError as exc:
            print(f"[ERRO] {exc}"); return 2
        rows = conn.execute(
            "SELECT module,key,reason,created_at FROM ack WHERE module=? "
            "ORDER BY module,key", (module,)).fetchall()
    else:
        rows = conn.execute(
            "SELECT module,key,reason,created_at FROM ack "
            "ORDER BY module,key").fetchall()
    conn.close()
    if not rows:
        print("  (nenhum achado reconhecido)")
        return 0
    print(f"  {'MÓDULO':<12} {'CHAVE':<34} MOTIVO")
    print(f"  {'-'*12} {'-'*34} {'-'*30}")
    for module, key, reason, _created in rows:
        print(f"  {module:<12} {key:<34} {reason}")
    print(f"\n  total: {len(rows)} | store: {_db_path()}")
    return 0


def main(argv: list[str] | None = None) -> int:
    # Console UTF-8 em qualquer plataforma (Windows cp1252 não tem ✓/acentos).
    for _stream in (sys.stdout, sys.stderr):
        try:
            _stream.reconfigure(encoding="utf-8")
        except Exception:
            pass
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help", "help"):
        print(__doc__)
        return 0
    cmd, rest = argv[0], argv[1:]
    if cmd == "add":
        return _cmd_add(rest)
    if cmd in ("rm", "remove", "del"):
        return _cmd_rm(rest)
    if cmd in ("list", "ls"):
        return _cmd_list(rest)
    print(f"[ERRO] comando desconhecido: {cmd}")
    print("comandos: add | rm | list   (use --help para detalhes)")
    return 2


if __name__ == "__main__":
    sys.exit(main())
