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
findings.py — Domínio de Achados (Findings) unificado do Argus ASM
==================================================================

Entidade de PRIMEIRA CLASSE para os achados de TODOS os módulos (monitor,
submonitor, credentials, email e, futuramente, typosquat). Resolve o requisito
prioritário: **um achado tratado não reaparece como "novo" a cada execução** —
o registro é reutilizado por um `id` determinístico, preservando status,
histórico, notas e evidências.

Conceitos (orthogonais, de propósito):
  • detecção  → `active` (1 = observado na última varredura; 0 = não observado)
                + `first_seen`/`last_seen`. É o ciclo de OBSERVAÇÃO.
  • triagem   → `status` (Novo → Em tratamento → Mitigado, ou Falso Positivo).
                É o ciclo OPERACIONAL/humano e PERSISTE mesmo quando o ativo é
                reobservado. O scanner marcar CORRIGIDO promove o achado a Mitigado.

Banco: `argus.db` (store central). Os bancos de scan atuais NÃO são apagados —
a migração faz backup e importa de forma idempotente e não-destrutiva.

Tabelas:
  findings(id, source, natural_key, title, category, severity, status, active,
           campanha, details(JSON), first_seen, last_seen, created_at, updated_at)
  finding_events(id, finding_id, ts, actor, action, from_status, to_status, note)
  finding_notes(id, finding_id, ts, actor, note)
  finding_evidence(id, finding_id, ts, actor, label, ref)

Rastreabilidade (ISO 27001/27002, CIS): toda mudança gera um evento auditável.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import os
import shutil
import sqlite3
from pathlib import Path

# ── Severidade (mantém a nomenclatura atual do Argus) ────────────────────────
SEVERITIES = ("CRITICO", "ALTO", "MEDIO", "BAIXO", "INFO")

# ── Ciclo de triagem (ESTADO operacional do achado) — 4 estados ──────────────
ST_NOVO            = "NOVO"
ST_EM_TRATAMENTO   = "EM_TRATAMENTO"
ST_MITIGADO        = "MITIGADO"
ST_FALSO_POSITIVO  = "FALSO_POSITIVO"

STATUSES = (ST_NOVO, ST_EM_TRATAMENTO, ST_MITIGADO, ST_FALSO_POSITIVO)

# Rótulos legíveis (UI/relatórios)
STATUS_LABEL = {
    ST_NOVO: "Novo", ST_EM_TRATAMENTO: "Em tratamento",
    ST_MITIGADO: "Mitigado", ST_FALSO_POSITIVO: "Falso Positivo",
}
# "Tratados" = saem do backlog e vão para a aba Tratado (tudo que não é Novo).
TREATED_STATUSES = (ST_EM_TRATAMENTO, ST_MITIGADO, ST_FALSO_POSITIVO)
# "Resolvidos" = somem dos relatórios de scan (Em tratamento NÃO some).
SCAN_HIDDEN_STATUSES = (ST_MITIGADO, ST_FALSO_POSITIVO)

# Aliases amigáveis (CLI/Web) -> estado canônico. Inclui compat com os antigos.
STATUS_ALIASES = {
    "novo": ST_NOVO, "new": ST_NOVO,
    "em-tratamento": ST_EM_TRATAMENTO, "em_tratamento": ST_EM_TRATAMENTO,
    "tratamento": ST_EM_TRATAMENTO, "wip": ST_EM_TRATAMENTO,
    "mitigado": ST_MITIGADO, "mitigated": ST_MITIGADO,
    "falso-positivo": ST_FALSO_POSITIVO, "falso_positivo": ST_FALSO_POSITIVO,
    "fp": ST_FALSO_POSITIVO, "false-positive": ST_FALSO_POSITIVO,
    # compatibilidade com os estados antigos (6 -> 4)
    "em-analise": ST_EM_TRATAMENTO, "em_analise": ST_EM_TRATAMENTO, "analise": ST_EM_TRATAMENTO,
    "confirmado": ST_EM_TRATAMENTO, "confirmed": ST_EM_TRATAMENTO,
    "aceito": ST_MITIGADO, "accepted": ST_MITIGADO,
}

# Remapeamento de estados ANTIGOS (no banco) -> novos (migração idempotente).
_STATUS_REMAP = {"EM_ANALISE": ST_EM_TRATAMENTO, "CONFIRMADO": ST_EM_TRATAMENTO, "ACEITO": ST_MITIGADO}

def normalize_status(s: str) -> str:
    """Aceita o canônico (NOVO...) ou um alias amigável (em-analise, fp...)."""
    if not s:
        return ""
    up = s.strip().upper()
    if up in STATUSES:
        return up
    return STATUS_ALIASES.get(s.strip().lower(), "")


def _cli_actor() -> str:
    """Quem executou a ação (rastreabilidade ISO/CIS). Respeita SUDO_USER."""
    import getpass
    return os.environ.get("SUDO_USER") or os.environ.get("USER") or getpass.getuser() or "cli"

# Categorias por origem (rótulo operacional; o mapeamento a controles
# ISO 27002/CIS fica para a Fase 3.2).
CATEGORY_BY_SOURCE = {
    "monitor":     "Exposição de Serviço (porta)",
    "submonitor":  "Ativo Web Exposto (subdomínio)",
    "credentials": "Vazamento de Credencial",
    "email":       "Higiene de E-mail / Anti-spoofing",
    "typosquat":   "Typosquatting / Abuso de Marca",
}

# Mapeamento de conformidade por tipo de achado — APENAS controles realmente
# pertinentes (sem "compliance de marketing"). Referências: ISO/IEC 27002:2022,
# CIS Controls v8, PCI-DSS v4.0.
CONTROLS_BY_SOURCE = {
    "monitor": {
        "iso": ["8.20 Segurança de redes", "8.21 Segurança dos serviços de rede",
                "8.8 Gestão de vulnerabilidades técnicas", "8.9 Gestão de configuração"],
        "cis": ["CIS 4 Configuração segura", "CIS 7 Gestão contínua de vulnerabilidades",
                "CIS 12 Gestão de infraestrutura de rede", "CIS 13 Monitoramento de rede"],
        "pci": ["Req 1 Controles de segurança de rede", "Req 2 Configurações seguras",
                "Req 6.3 Vulnerabilidades", "Req 11.3 Varredura de vulnerabilidades"],
    },
    "submonitor": {
        "iso": ["5.9 Inventário de ativos", "8.20 Segurança de redes", "8.9 Gestão de configuração"],
        "cis": ["CIS 1 Inventário de ativos corporativos", "CIS 4 Configuração segura",
                "CIS 13 Monitoramento de rede"],
        "pci": ["Req 2 Configurações seguras", "Req 11.3 Varredura de vulnerabilidades"],
    },
    "credentials": {
        "iso": ["5.16 Gestão de identidade", "5.17 Informação de autenticação",
                "8.5 Autenticação segura"],
        "cis": ["CIS 5 Gestão de contas", "CIS 6 Gestão de controle de acesso"],
        "pci": ["Req 8 Identificar e autenticar o acesso"],
    },
    "email": {
        "iso": ["5.14 Transferência de informações", "8.20 Segurança de redes"],
        "cis": ["CIS 9 Proteções de e-mail e navegador"],
        "pci": ["Req 5 Proteção contra software malicioso (phishing/BEC)"],
    },
    "typosquat": {
        "iso": ["5.7 Inteligência de ameaças"],
        "cis": ["CIS 7 Gestão contínua de vulnerabilidades"],
        "pci": [],
    },
}

def controls_for(source: str) -> dict:
    return CONTROLS_BY_SOURCE.get(source, {"iso": [], "cis": [], "pci": []})


# Carência (dias) antes de marcar um achado como NÃO observado. Absorve falhas
# transitórias de coleta (DNS/rate-limit/host fora do ar) — um "miss" isolado não
# fecha o achado; só após N dias sem ser visto. Ajustável por env.
CLOSE_GRACE_DAYS = int(os.environ.get("ARGUS_CLOSE_GRACE_DAYS", "3"))


def _now() -> str:
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def finding_id(source: str, natural_key: str) -> str:
    """ID estável e determinístico do achado (mesma chave natural → mesmo id)."""
    raw = f"{source}:{natural_key}".strip().lower()
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:16]


def default_db_path() -> str:
    """argus.db central. Sobrescrevível via ARGUS_DB.
    Prod: /etc/argus/store/argus.db (dir setgid 2775 root:app — escrita
    compartilhada root↔app, igual ao threatintel/); fallback /etc/argus/argus.db;
    dev: ao lado deste arquivo."""
    env = os.environ.get("ARGUS_DB")
    if env:
        return env
    base = Path("/etc/argus")
    if base.is_dir():
        store = base / "store"
        return str((store if store.is_dir() else base) / "argus.db")
    return str(Path(__file__).resolve().parent / "argus.db")


class FindingRepository:
    """Repositório do domínio de Findings (SQLite, store central)."""

    def __init__(self, db_path: str | None = None):
        self.db_path = db_path or default_db_path()
        self._conn = sqlite3.connect(self.db_path)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._init_schema()

    # ── infra ────────────────────────────────────────────────────────────
    def _init_schema(self) -> None:
        c = self._conn
        c.executescript("""
        CREATE TABLE IF NOT EXISTS findings (
            id           TEXT PRIMARY KEY,
            source       TEXT NOT NULL,
            natural_key  TEXT NOT NULL,
            title        TEXT,
            category     TEXT,
            severity     TEXT,
            status       TEXT NOT NULL DEFAULT 'NOVO',
            active       INTEGER NOT NULL DEFAULT 1,
            campanha     TEXT,
            details      TEXT,
            first_seen   TEXT,
            last_seen    TEXT,
            created_at   TEXT,
            updated_at   TEXT
        );
        CREATE TABLE IF NOT EXISTS finding_events (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            finding_id  TEXT NOT NULL,
            ts          TEXT,
            actor       TEXT,
            action      TEXT,
            from_status TEXT,
            to_status   TEXT,
            note        TEXT
        );
        CREATE TABLE IF NOT EXISTS finding_notes (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            finding_id  TEXT NOT NULL, ts TEXT, actor TEXT, note TEXT
        );
        CREATE TABLE IF NOT EXISTS finding_evidence (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            finding_id  TEXT NOT NULL, ts TEXT, actor TEXT, label TEXT, ref TEXT
        );
        CREATE INDEX IF NOT EXISTS ix_findings_source  ON findings(source);
        CREATE INDEX IF NOT EXISTS ix_findings_status  ON findings(status);
        CREATE INDEX IF NOT EXISTS ix_findings_active  ON findings(active);
        CREATE INDEX IF NOT EXISTS ix_events_finding   ON finding_events(finding_id);
        """)
        c.commit()
        # Migração de ESTADOS antigos (6) -> novos (4), idempotente e não-destrutiva.
        for _old, _new in _STATUS_REMAP.items():
            c.execute("UPDATE findings SET status=? WHERE status=?", (_new, _old))
        c.commit()

    def close(self) -> None:
        try: self._conn.commit(); self._conn.close()
        except Exception: pass

    def _event(self, fid: str, action: str, actor: str = "system",
               from_status: str | None = None, to_status: str | None = None,
               note: str | None = None, ts: str | None = None) -> None:
        self._conn.execute(
            "INSERT INTO finding_events (finding_id,ts,actor,action,from_status,to_status,note) "
            "VALUES (?,?,?,?,?,?,?)",
            (fid, ts or _now(), actor, action, from_status, to_status, note))

    # ── ingestão (chamada pelos scanners / migração) ─────────────────────
    def upsert(self, source: str, natural_key: str, *, severity: str,
               title: str = "", category: str | None = None, campanha: str = "",
               details: dict | None = None, run_id: str = "", ts: str | None = None,
               actor: str = "system") -> tuple[str, bool]:
        """Cria OU atualiza o achado (idempotente). Preserva status/histórico de
        achados já existentes. Reabre (active=1) e registra reobservação quando
        um achado inativo volta a ser visto. Retorna (finding_id, is_new)."""
        ts = ts or _now()
        category = category or CATEGORY_BY_SOURCE.get(source, "Achado")
        fid = finding_id(source, natural_key)
        det = json.dumps(details or {}, ensure_ascii=False)
        row = self._conn.execute(
            "SELECT status, active FROM findings WHERE id=?", (fid,)).fetchone()
        if row is None:
            self._conn.execute(
                "INSERT INTO findings (id,source,natural_key,title,category,severity,status,active,"
                "campanha,details,first_seen,last_seen,created_at,updated_at) "
                "VALUES (?,?,?,?,?,?,?,1,?,?,?,?,?,?)",
                (fid, source, natural_key, title, category, severity, ST_NOVO,
                 campanha, det, ts, ts, ts, ts))
            self._event(fid, "created", actor, None, ST_NOVO,
                        note=f"Detectado: {title or natural_key}", ts=ts)
            self._conn.commit()
            return fid, True
        # já existe → atualiza observação SEM mexer no status de triagem
        old_status, old_active = row
        self._conn.execute(
            "UPDATE findings SET severity=?, title=?, category=?, campanha=?, details=?, "
            "last_seen=?, active=1, updated_at=? WHERE id=?",
            (severity, title, category, campanha, det, ts, ts, fid))
        if not old_active:
            self._event(fid, "reopened", actor, note="Ativo voltou a ser observado", ts=ts)
        else:
            self._event(fid, "reobserved", actor, note="Reobservado na varredura", ts=ts)
        self._conn.commit()
        return fid, False

    def mark_absent(self, source: str, seen_keys, *, key_predicate=None,
                    grace_days: int | None = None, actor: str = "system",
                    ts: str | None = None) -> int:
        """Marca como NÃO observados (active=0) os achados de `source` que não
        apareceram nesta varredura. **Não** altera o status de triagem (um achado
        Mitigado/Aceito permanece com seu status). Retorna a quantidade fechada.

        `key_predicate(natural_key)->bool` limita QUAIS achados podem ser fechados
        (escopo). Ex.: no monitor TCP, só fecha chaves terminadas em '/tcp', para
        um scan UDP não fechar portas TCP (e vice-versa).

        `grace_days`: carência — só fecha se o achado estiver sem ser visto há
        ≥ N dias (absorve falhas transitórias de coleta). Default CLOSE_GRACE_DAYS."""
        ts = ts or _now()
        if grace_days is None:
            grace_days = CLOSE_GRACE_DAYS
        cutoff = (datetime.datetime.now() - datetime.timedelta(days=grace_days)).strftime("%Y-%m-%d %H:%M:%S")
        seen = {finding_id(source, k) for k in seen_keys}
        rows = self._conn.execute(
            "SELECT id, natural_key, last_seen FROM findings WHERE source=? AND active=1", (source,)).fetchall()
        n = 0
        for fid, nkey, last_seen in rows:
            if fid in seen:
                continue
            if key_predicate is not None and not key_predicate(nkey):
                continue   # fora do escopo desta varredura — não fecha
            if (last_seen or "") >= cutoff:
                continue   # carência: visto recentemente, não fecha ainda (miss transitório)
            self._conn.execute("UPDATE findings SET active=0, updated_at=? WHERE id=?", (ts, fid))
            self._event(fid, "closed", actor, note=f"Não observado há ≥{grace_days}d", ts=ts)
            n += 1
        self._conn.commit()
        return n

    # ── triagem (CLI / Web na Fase 2) ────────────────────────────────────
    def set_status(self, fid: str, to_status: str, *, actor: str = "system",
                   note: str | None = None) -> bool:
        if to_status not in STATUSES:
            raise ValueError(f"status inválido: {to_status}")
        row = self._conn.execute("SELECT status FROM findings WHERE id=?", (fid,)).fetchone()
        if row is None:
            return False
        from_status = row[0]
        ts = _now()
        self._conn.execute("UPDATE findings SET status=?, updated_at=? WHERE id=?",
                           (to_status, ts, fid))
        self._event(fid, "status_change", actor, from_status, to_status, note, ts=ts)
        self._conn.commit()
        return True

    def mark_corrected(self, source: str, keys, *, actor: str = "scan",
                       note: str | None = None) -> int:
        """ACOPLAMENTO scan→achado: quando o scanner marca um item como CORRIGIDO,
        o achado correspondente vira MITIGADO automaticamente. NÃO mexe em quem já
        é Falso Positivo ou Mitigado (decisão final do analista preservada).
        `keys` = chaves naturais corrigidas nesta varredura. Retorna quantos mudaram."""
        ts = _now()
        n = 0
        for k in keys:
            fid = finding_id(source, k)
            row = self._conn.execute("SELECT status FROM findings WHERE id=?", (fid,)).fetchone()
            if row is None or row[0] in (ST_MITIGADO, ST_FALSO_POSITIVO):
                continue
            self._conn.execute("UPDATE findings SET status=?, updated_at=? WHERE id=?",
                               (ST_MITIGADO, ts, fid))
            self._event(fid, "status_change", actor, row[0], ST_MITIGADO,
                        note or "Corrigido na varredura (auto-mitigado)", ts=ts)
            n += 1
        self._conn.commit()
        return n

    def mark_resurged(self, source: str, keys, *, actor: str = "scan") -> int:
        """Achado auto-mitigado que VOLTOU a ser detectado (scan Ressurgido) é
        reaberto para NOVO — senão ficaria 'escondido' do scan por estar Mitigado.
        NÃO mexe em Falso Positivo (decisão do analista). Retorna quantos reabriram."""
        ts = _now()
        n = 0
        for k in keys:
            fid = finding_id(source, k)
            row = self._conn.execute("SELECT status FROM findings WHERE id=?", (fid,)).fetchone()
            if row is None or row[0] != ST_MITIGADO:
                continue
            self._conn.execute("UPDATE findings SET status=?, updated_at=? WHERE id=?",
                               (ST_NOVO, ts, fid))
            self._event(fid, "status_change", actor, row[0], ST_NOVO,
                        "Ressurgido na varredura (reaberto)", ts=ts)
            n += 1
        self._conn.commit()
        return n

    def hidden_keys(self, source: str) -> set:
        """Chaves naturais cujo ESTADO faz o achado SUMIR do relatório de scan
        (Mitigado / Falso Positivo). 'Em tratamento' NÃO entra (continua no scan)."""
        ph = ",".join("?" * len(SCAN_HIDDEN_STATUSES))
        rows = self._conn.execute(
            f"SELECT natural_key FROM findings WHERE source=? AND status IN ({ph})",
            (source, *SCAN_HIDDEN_STATUSES)).fetchall()
        return {r[0] for r in rows}

    def add_note(self, fid: str, note: str, *, actor: str = "system") -> bool:
        if self._conn.execute("SELECT 1 FROM findings WHERE id=?", (fid,)).fetchone() is None:
            return False
        ts = _now()
        self._conn.execute("INSERT INTO finding_notes (finding_id,ts,actor,note) VALUES (?,?,?,?)",
                           (fid, ts, actor, note))
        self._event(fid, "note", actor, note=note, ts=ts)
        self._conn.commit()
        return True

    def add_evidence(self, fid: str, label: str, ref: str, *, actor: str = "system") -> bool:
        if self._conn.execute("SELECT 1 FROM findings WHERE id=?", (fid,)).fetchone() is None:
            return False
        ts = _now()
        self._conn.execute("INSERT INTO finding_evidence (finding_id,ts,actor,label,ref) VALUES (?,?,?,?,?)",
                           (fid, ts, actor, label, ref))
        self._event(fid, "evidence", actor, note=f"{label}: {ref}", ts=ts)
        self._conn.commit()
        return True

    # ── consulta ─────────────────────────────────────────────────────────
    def get(self, fid: str) -> dict | None:
        cols = [d[0] for d in self._conn.execute("SELECT * FROM findings WHERE id=?", (fid,)).description]
        row = self._conn.execute("SELECT * FROM findings WHERE id=?", (fid,)).fetchone()
        if not row:
            return None
        d = dict(zip(cols, row))
        try: d["details"] = json.loads(d.get("details") or "{}")
        except Exception: d["details"] = {}
        return d

    def history(self, fid: str) -> list[dict]:
        rows = self._conn.execute(
            "SELECT ts,actor,action,from_status,to_status,note FROM finding_events "
            "WHERE finding_id=? ORDER BY id", (fid,)).fetchall()
        return [dict(zip(("ts","actor","action","from_status","to_status","note"), r)) for r in rows]

    def counts(self) -> dict:
        out = {"total": 0, "active": 0, "by_status": {}, "by_severity": {}}
        out["total"] = self._conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
        out["active"] = self._conn.execute("SELECT COUNT(*) FROM findings WHERE active=1").fetchone()[0]
        for st, n in self._conn.execute("SELECT status,COUNT(*) FROM findings GROUP BY status"):
            out["by_status"][st] = n
        for sv, n in self._conn.execute("SELECT severity,COUNT(*) FROM findings GROUP BY severity"):
            out["by_severity"][sv] = n
        return out

    _SEV_RANK = {"CRITICO": 0, "ALTO": 1, "MEDIO": 2, "BAIXO": 3, "INFO": 4}

    def _where(self, source, status, severity, active):
        where, args = [], []
        if source:   where.append("source=?");   args.append(source)
        if status:   where.append("status=?");   args.append(status)
        if severity: where.append("severity=?"); args.append(severity)
        if active is not None: where.append("active=?"); args.append(1 if active else 0)
        return (" WHERE " + " AND ".join(where)) if where else "", args

    def count_findings(self, *, source=None, status=None, severity=None, active=None) -> int:
        w, args = self._where(source, status, severity, active)
        return self._conn.execute("SELECT COUNT(*) FROM findings" + w, args).fetchone()[0]

    def list_findings(self, *, source=None, status=None, severity=None,
                      active=None, limit: int = 200, offset: int = 0) -> list[dict]:
        w, args = self._where(source, status, severity, active)
        sql = ("SELECT id,source,natural_key,title,category,severity,status,active,"
               "campanha,first_seen,last_seen FROM findings") + w
        rows = self._conn.execute(sql, args).fetchall()
        cols = ("id","source","natural_key","title","category","severity","status",
                "active","campanha","first_seen","last_seen")
        out = [dict(zip(cols, r)) for r in rows]
        # ativos primeiro, depois por severidade, depois mais recentes
        out.sort(key=lambda d: (0 if d["active"] else 1,
                                self._SEV_RANK.get(d["severity"], 9),
                                d["last_seen"] or ""), )
        offset = max(0, offset)
        return out[offset:offset + limit] if limit else out[offset:]

    def resolve_id(self, id_or_prefix: str) -> str | None:
        """Resolve um id completo ou prefixo. Levanta ValueError se ambíguo."""
        s = (id_or_prefix or "").strip().lower()
        if not s:
            return None
        if self._conn.execute("SELECT 1 FROM findings WHERE id=?", (s,)).fetchone():
            return s
        rows = self._conn.execute("SELECT id FROM findings WHERE id LIKE ?", (s + "%",)).fetchall()
        if len(rows) == 1:
            return rows[0][0]
        if len(rows) > 1:
            raise ValueError(f"prefixo ambíguo ({len(rows)} achados): {id_or_prefix}")
        return None

    def notes(self, fid: str) -> list[dict]:
        rows = self._conn.execute(
            "SELECT ts,actor,note FROM finding_notes WHERE finding_id=? ORDER BY id", (fid,)).fetchall()
        return [dict(zip(("ts","actor","note"), r)) for r in rows]

    def evidence(self, fid: str) -> list[dict]:
        rows = self._conn.execute(
            "SELECT ts,actor,label,ref FROM finding_evidence WHERE finding_id=? ORDER BY id", (fid,)).fetchall()
        return [dict(zip(("ts","actor","label","ref"), r)) for r in rows]


def _parse_ts(s):
    try:
        return datetime.datetime.strptime((s or "")[:19], "%Y-%m-%d %H:%M:%S")
    except Exception:
        return None


def stats(db_path: str | None = None, weeks: int = 8) -> dict:
    """Estatísticas e tendências para o relatório executivo (Fase 3.1).
    Tudo derivado de `findings` + `finding_events` — sem nova persistência:
      • breakdown por status/severidade(ativos)/fonte/categoria
      • backlog, tratados, aging (faixas de idade do backlog), achado mais antigo
      • MTTT (tempo médio até o 1º tratamento, em dias)
      • tendência semanal: novos × tratados (últimas `weeks` semanas)
    """
    repo = FindingRepository(db_path)
    now = datetime.datetime.now()
    try:
        rows = repo._conn.execute(
            "SELECT id,source,category,severity,status,active,first_seen,created_at FROM findings").fetchall()
        evs = repo._conn.execute(
            "SELECT finding_id,ts,action,to_status FROM finding_events").fetchall()
    finally:
        repo.close()

    TREATED = set(TREATED_STATUSES)
    by_source, by_category, by_status, by_severity = {}, {}, {}, {}
    aging = {"<7d": 0, "7-30d": 0, "30-90d": 0, ">90d": 0}
    active = backlog = treated = 0
    oldest = 0
    created = {}
    for fid, src, cat, sev, st, act, fseen, cre in rows:
        by_source[src] = by_source.get(src, 0) + 1
        by_category[cat] = by_category.get(cat, 0) + 1
        by_status[st] = by_status.get(st, 0) + 1
        created[fid] = _parse_ts(cre)
        if act:
            active += 1
            by_severity[sev] = by_severity.get(sev, 0) + 1
        if st in TREATED:
            treated += 1
        if act and st not in TREATED:
            backlog += 1
            d = _parse_ts(fseen) or _parse_ts(cre)
            age = (now - d).days if d else 0
            oldest = max(oldest, age)
            if age < 7:    aging["<7d"] += 1
            elif age < 30: aging["7-30d"] += 1
            elif age < 90: aging["30-90d"] += 1
            else:          aging[">90d"] += 1

    # MTTT — created_at -> 1º status_change para um status tratado
    first_treat = {}
    for fid, ts, action, to in evs:
        if action == "status_change" and to in TREATED:
            t = _parse_ts(ts)
            if t and (fid not in first_treat or t < first_treat[fid]):
                first_treat[fid] = t
    durs = [(first_treat[f] - created[f]).total_seconds() / 86400
            for f in first_treat if created.get(f)]
    mttt = round(sum(durs) / len(durs), 1) if durs else None

    # Tendência semanal (segunda a segunda)
    monday = (now - datetime.timedelta(days=now.weekday())).replace(hour=0, minute=0, second=0, microsecond=0)
    trends = []
    for w in range(weeks - 1, -1, -1):
        ws = monday - datetime.timedelta(weeks=w)
        we = ws + datetime.timedelta(days=7)
        new = sum(1 for _f, ts, a, _t in evs
                  if a == "created" and (_parse_ts(ts) and ws <= _parse_ts(ts) < we))
        trt = sum(1 for _f, ts, a, to in evs
                  if a == "status_change" and to in TREATED and (_parse_ts(ts) and ws <= _parse_ts(ts) < we))
        trends.append({"label": ws.strftime("%d/%m"), "new": new, "treated": trt})

    return {
        "active": active, "backlog": backlog, "treated": treated,
        "oldest_days": oldest, "mttt_days": mttt,
        "by_source": by_source, "by_category": by_category,
        "by_status": by_status, "by_severity": by_severity,
        "aging": aging, "trends": trends,
    }


def snapshot(db_path: str | None = None, limit: int = 5000) -> dict:
    """Visão serializável do store para a página de Gestão de Achados (read-only).
    O domínio fornece os dados; o reporter apenas renderiza (sem acoplar a DB)."""
    repo = FindingRepository(db_path)
    try:
        counts = repo.counts()
        items = repo.list_findings(limit=limit)
        nc = dict(repo._conn.execute(
            "SELECT finding_id,COUNT(*) FROM finding_notes GROUP BY finding_id").fetchall())
        ec = dict(repo._conn.execute(
            "SELECT finding_id,COUNT(*) FROM finding_evidence GROUP BY finding_id").fetchall())
        for it in items:
            it["status_label"] = STATUS_LABEL.get(it["status"], it["status"])
            it["treated"] = it["status"] in TREATED_STATUSES
            it["notes"] = int(nc.get(it["id"], 0))
            it["evidence"] = int(ec.get(it["id"], 0))
        backlog = sum(1 for it in items if it["active"] and not it["treated"])
        return {
            "generated_at": _now(),
            "counts": counts,
            "backlog": backlog,
            "statuses": list(STATUSES),
            "status_label": dict(STATUS_LABEL),
            "controls": dict(CONTROLS_BY_SOURCE),
            "findings": items,
        }
    finally:
        repo.close()


# ============================================================
# SINCRONIZAÇÃO (chamada pelos scanners — entrada DRY)
# ============================================================

def sync_findings(source: str, observed: list, *, key_of, severity_of,
                  title_of=None, campanha_of=None, details_of=None,
                  scope_predicate=None, corrected=None, resurged=None,
                  db_path: str | None = None,
                  run_id: str = "", actor: str = "system") -> tuple[int, int]:
    """Sincroniza o resultado de UMA varredura com o store central, de forma
    ADITIVA (não interfere no fluxo/DB/relatório atual do módulo):
      • faz `upsert` de cada item observado (idempotente, preserva status);
      • `mark_absent` fecha os achados do `source` (no escopo) que sumiram.

    `observed` = itens vistos nesta execução (ex.: novos + reincidentes).
    `key_of(item)->str` = chave natural; demais *_of são extratores opcionais.
    `scope_predicate(natural_key)->bool` limita o fechamento (ver mark_absent).
    Retorna (observados, fechados). Nunca deve quebrar o scan — chame sob try."""
    repo = FindingRepository(db_path)
    try:
        seen = []
        for item in observed:
            k = key_of(item)
            if not k:
                continue
            seen.append(k)
            repo.upsert(
                source, k,
                severity=severity_of(item),
                title=(title_of(item) if title_of else k),
                campanha=(campanha_of(item) if campanha_of else ""),
                details=(details_of(item) if details_of else None),
                run_id=run_id, actor=actor)
        closed = repo.mark_absent(source, seen, key_predicate=scope_predicate, actor=actor)
        # ACOPLAMENTO scan→achado: CORRIGIDO vira MITIGADO; RESSURGIDO reabre p/ NOVO.
        if resurged:
            rk = [key_of(it) for it in resurged]
            repo.mark_resurged(source, [k for k in rk if k], actor=actor)
        if corrected:
            ck = [key_of(it) for it in corrected]
            repo.mark_corrected(source, [k for k in ck if k], actor=actor)
        return len(seen), closed
    finally:
        repo.close()


def hidden_keys(source: str, db_path: str | None = None) -> set:
    """Conveniência p/ os scanners: chaves cujo achado está Mitigado/Falso Positivo
    (devem sumir do relatório de scan). Nunca levanta — em erro retorna set()."""
    try:
        repo = FindingRepository(db_path)
        try:
            return repo.hidden_keys(source)
        finally:
            repo.close()
    except Exception:
        return set()


# ============================================================
# MIGRAÇÃO SEGURA (não-destrutiva, idempotente, com backup)
# ============================================================

def _backup_db(path: Path) -> str | None:
    if not path.exists():
        return None
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    dst = path.with_suffix(path.suffix + f".bak-{stamp}")
    try:
        shutil.copy2(path, dst)
        return str(dst)
    except Exception:
        return None


def _load_acks(base: Path) -> dict:
    """Lê o acknowledged.db (RECONHECIDO) -> {(module,key_lower): reason}."""
    db = base / "acknowledged.db"
    acks = {}
    if not db.exists():
        return acks
    try:
        c = sqlite3.connect(str(db))
        for module, key, reason in c.execute("SELECT module,key,reason FROM ack"):
            acks[(module, str(key).lower())] = reason
        c.close()
    except Exception:
        pass
    return acks


def migrate_legacy_dbs(base_dir: str, *, db_path: str | None = None) -> dict:
    """Importa os achados dos bancos de scan atuais para o `argus.db` central,
    de forma IDEMPOTENTE e NÃO-DESTRUTIVA (faz backup, não apaga os DBs antigos).
    Mapeia RECONHECIDO (acknowledged.db) -> status ACEITO + nota.

    Pode ser re-executada com segurança (upsert por finding_id). Retorna um
    resumo {fonte: importados}."""
    base = Path(base_dir)
    repo = FindingRepository(db_path)
    acks = _load_acks(base)
    summary = {"backups": [], "monitor": 0, "submonitor": 0, "credentials": 0, "email": 0}

    def _ack_status(module, key):
        reason = acks.get((module, str(key).lower()))
        return (ST_MITIGADO, reason) if reason is not None else (None, None)

    # ── monitor.db (scans) — ip:port/proto ──
    mon = base / "monitor" / "monitor.db"
    if not mon.exists(): mon = base / "monitor.db"
    if mon.exists():
        b = _backup_db(mon);  summary["backups"].append(b) if b else None
        try:
            c = sqlite3.connect(str(mon))
            cols = {r[1] for r in c.execute("PRAGMA table_info(scans)")}
            sel = "ip,port,protocol,service,risk,campanha,status"
            for ip,port,proto,svc,risk,camp,st in c.execute(
                    f"SELECT {sel} FROM scans WHERE status IN ('NOVO','REINCIDENTE','RESSURGIDO')"):
                key = f"{ip}:{port}/{proto}"
                fid, _ = repo.upsert("monitor", key, severity=risk or "BAIXO",
                                     title=f"{ip}:{port}/{proto} ({svc or '?'})",
                                     campanha=camp or "", details={"service": svc or ""})
                stt, reason = _ack_status("monitor", key)
                if stt: repo.set_status(fid, stt, note=f"Migrado do RECONHECIDO: {reason}")
                summary["monitor"] += 1
            c.close()
        except Exception as exc:
            summary["monitor_error"] = str(exc)

    # ── submonitor.db (subdomains) — hostname ──
    sub = base / "submonitor" / "submonitor.db"
    if not sub.exists(): sub = base / "submonitor.db"
    if sub.exists():
        b = _backup_db(sub);  summary["backups"].append(b) if b else None
        try:
            c = sqlite3.connect(str(sub))
            for host,risk,camp in c.execute(
                    "SELECT hostname,risk,campanha FROM subdomains WHERE status IN ('NOVO','REINCIDENTE','RESSURGIDO')"):
                fid, _ = repo.upsert("submonitor", host, severity=risk or "INFO",
                                     title=host, campanha=camp or "")
                stt, reason = _ack_status("submonitor", host)
                if stt: repo.set_status(fid, stt, note=f"Migrado do RECONHECIDO: {reason}")
                summary["submonitor"] += 1
            c.close()
        except Exception as exc:
            summary["submonitor_error"] = str(exc)

    # ── credentials.db / email.db (domains) — domínio ──
    for src, fname, table in (("credentials", "credentials", "domains"),
                              ("email", "email", "domains")):
        p = base / fname / f"{fname}.db"
        if not p.exists(): p = base / f"{fname}.db"
        if not p.exists(): continue
        b = _backup_db(p);  summary["backups"].append(b) if b else None
        try:
            c = sqlite3.connect(str(p))
            for dom,risk,camp in c.execute(
                    f"SELECT domain,risk,campanha FROM {table} WHERE status IN ('NOVO','REINCIDENTE','RESSURGIDO')"):
                fid, _ = repo.upsert(src, dom, severity=risk or "BAIXO", title=dom, campanha=camp or "")
                stt, reason = _ack_status(src, dom)
                if stt: repo.set_status(fid, stt, note=f"Migrado do RECONHECIDO: {reason}")
                summary[src] += 1
            c.close()
        except Exception as exc:
            summary[f"{src}_error"] = str(exc)

    repo.close()
    summary["backups"] = [b for b in summary["backups"] if b]
    return summary


# ============================================================
# CLI mínima (semente do futuro `argus-finding` — Fase 2/3)
# ============================================================

_USAGE = """argus-finding — gestão operacional de achados (Findings)

  argus-finding list [--source monitor|submonitor|credentials|email|typosquat]
                     [--status novo|em-tratamento|mitigado|fp]
                     [--severity CRITICO|ALTO|MEDIO|BAIXO|INFO] [--active]
                     [--limit N] [--page P]
                     (paginado: --limit = tamanho da pagina, padrao 50; --page = numero
                      da pagina; --limit 0 lista TODAS de uma vez, sem paginar)
  argus-finding show <id|prefixo>
  argus-finding set  <id|prefixo> <status> [--note "..."]
  argus-finding note <id|prefixo> "<texto>"
  argus-finding evidence <id|prefixo> "<rótulo>" "<ref: caminho/url/hash>"
  argus-finding counts
  argus-finding migrate [<base_dir>]      (importa DBs legados; idempotente)

estado: novo | em-tratamento | mitigado | falso-positivo (fp)
Toda ação é auditada (finding_events) com o usuário que executou."""


def _pop_opt(argv, name):
    if name in argv:
        i = argv.index(name)
        if i + 1 < len(argv):
            v = argv[i + 1]; del argv[i:i + 2]; return v
        del argv[i]
    return None


def _pop_flag(argv, name):
    if name in argv:
        argv.remove(name); return True
    return False


def _fmt_table(rows: list[dict]) -> str:
    if not rows:
        return "  (nenhum achado)"
    out = [f"  {'ID':<10} {'SEV':<8} {'STATUS':<14} {'A':<2} {'FONTE':<11} {'ÚLT.OBS':<19} ACHADO"]
    out.append("  " + "-" * 100)
    for d in rows:
        st = STATUS_LABEL.get(d["status"], d["status"])
        act = "•" if d["active"] else " "
        last = (d.get("last_seen") or "")[:19]
        title = (d.get("title") or d.get("natural_key") or "")[:46]
        out.append(f"  {d['id'][:10]:<10} {d['severity']:<8} {st:<14} {act:<2} "
                   f"{d['source']:<11} {last:<19} {title}")
    return "\n".join(out)


def _main(argv=None):
    import sys
    for s in (sys.stdout, sys.stderr):
        try: s.reconfigure(encoding="utf-8")
        except Exception: pass
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help", "help"):
        print(_USAGE); return 0
    cmd, rest = argv[0], argv[1:]

    if cmd == "migrate" or cmd == "--migrate":
        base = rest[0] if rest else os.environ.get("ARGUS_BASE", "/etc/argus")
        print("Migração concluída:", json.dumps(migrate_legacy_dbs(base), ensure_ascii=False, indent=2))
        return 0
    if cmd == "counts" or cmd == "--counts":
        print(json.dumps(FindingRepository().counts(), ensure_ascii=False, indent=2))
        return 0

    repo = FindingRepository()
    try:
        if cmd == "list":
            src = _pop_opt(rest, "--source")
            stt = normalize_status(_pop_opt(rest, "--status") or "") or None
            sev = (_pop_opt(rest, "--severity") or "").upper() or None
            lim = int(_pop_opt(rest, "--limit") or 50)        # tamanho da página
            page = max(1, int(_pop_opt(rest, "--page") or 1))
            active = True if _pop_flag(rest, "--active") else None
            total = repo.count_findings(source=src, status=stt, severity=sev, active=active)
            if lim <= 0:                                       # --limit 0 = tudo, sem paginar
                rows = repo.list_findings(source=src, status=stt, severity=sev, active=active, limit=0)
                print(_fmt_table(rows))
                print(f"\n  {len(rows)} achado(s) (todas) | store: {repo.db_path}")
                return 0
            pages = max(1, (total + lim - 1) // lim)
            page = min(page, pages)
            offset = (page - 1) * lim
            rows = repo.list_findings(source=src, status=stt, severity=sev,
                                      active=active, limit=lim, offset=offset)
            print(_fmt_table(rows))
            lo = offset + 1 if rows else 0
            hi = offset + len(rows)
            print(f"\n  pagina {page}/{pages}  ·  achados {lo}-{hi} de {total}  "
                  f"(ordenado por severidade: CRITICO->INFO)  ·  store: {repo.db_path}")
            nav = []
            if page < pages: nav.append(f"proxima: --page {page + 1}")
            if page > 1:     nav.append(f"anterior: --page {page - 1}")
            nav.append("tudo: --limit 0")
            print("  " + "   |   ".join(nav))
            return 0

        # comandos que exigem <id>
        if cmd in ("show", "set", "note", "evidence"):
            if not rest:
                print(f"[ERRO] informe o id do achado. Ex.: argus-finding {cmd} <id>"); return 2
            try:
                fid = repo.resolve_id(rest[0])
            except ValueError as exc:
                print(f"[ERRO] {exc}"); return 2
            if not fid:
                print(f"[ERRO] achado não encontrado: {rest[0]}"); return 2
            rest = rest[1:]
            actor = _pop_opt(rest, "--actor") or _cli_actor()

            if cmd == "show":
                f = repo.get(fid)
                print(f"  ID        : {f['id']}")
                print(f"  Fonte     : {f['source']}   Categoria: {f['category']}")
                print(f"  Achado    : {f['title'] or f['natural_key']}")
                print(f"  Severidade: {f['severity']}   Status: {STATUS_LABEL.get(f['status'], f['status'])}"
                      f"   {'(ATIVO)' if f['active'] else '(não observado)'}")
                print(f"  Campanha  : {f['campanha']}")
                print(f"  1ª obs.   : {f['first_seen']}   Últ. obs.: {f['last_seen']}")
                if f.get("details"):
                    print(f"  Detalhes  : {json.dumps(f['details'], ensure_ascii=False)}")
                nts = repo.notes(fid)
                if nts:
                    print("  Notas:")
                    for n in nts: print(f"    [{n['ts']}] {n['actor']}: {n['note']}")
                ev = repo.evidence(fid)
                if ev:
                    print("  Evidências:")
                    for e in ev: print(f"    [{e['ts']}] {e['actor']} — {e['label']}: {e['ref']}")
                print("  Histórico:")
                for h in repo.history(fid):
                    extra = (f"  {h['from_status']}→{h['to_status']}" if h['to_status'] else "")
                    note = f"  · {h['note']}" if h.get("note") else ""
                    print(f"    [{h['ts']}] {h['actor']} {h['action']}{extra}{note}")
                return 0

            if cmd == "set":
                if not rest:
                    print("[ERRO] informe o estado. Ex.: argus-finding set <id> mitigado --note \"...\""); return 2
                to = normalize_status(rest[0])
                if not to:
                    print(f"[ERRO] estado inválido: {rest[0]} (use novo|em-tratamento|mitigado|fp)"); return 2
                note = _pop_opt(rest, "--note")
                repo.set_status(fid, to, actor=actor, note=note)
                print(f"  ✓ {fid[:10]} → {STATUS_LABEL[to]} (por {actor})")
                return 0

            if cmd == "note":
                if not rest:
                    print("[ERRO] informe o texto da nota."); return 2
                repo.add_note(fid, " ".join(rest), actor=actor)
                print(f"  ✓ nota adicionada em {fid[:10]} (por {actor})")
                return 0

            if cmd == "evidence":
                if len(rest) < 2:
                    print("[ERRO] uso: argus-finding evidence <id> \"<rótulo>\" \"<ref>\""); return 2
                repo.add_evidence(fid, rest[0], rest[1], actor=actor)
                print(f"  ✓ evidência adicionada em {fid[:10]} (por {actor})")
                return 0

        print(f"[ERRO] comando desconhecido: {cmd}\n"); print(_USAGE)
        return 2
    finally:
        repo.close()


if __name__ == "__main__":
    raise SystemExit(_main())
