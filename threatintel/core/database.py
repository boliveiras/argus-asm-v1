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
threatintel.core.database
─────────────────────────
Gerencia a conexão e o schema do banco de dados compartilhado de threat intel.

Thread-safety: cada chamada a get_connection() abre uma conexão independente
com check_same_thread=False, adequado para uso em scripts single-thread.
Para uso multi-thread real, use um pool ou contextos por thread.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

from threatintel import CONFIG

DB_PATH = Path(CONFIG.get("db_path", "/home/kali/Scripts/threatintel/threatintel.db"))

# DDL ─────────────────────────────────────────────────────────────────────────

_DDL_ABUSEIPDB_CACHE = """
CREATE TABLE IF NOT EXISTS abuseipdb_cache (
    ip                   TEXT    PRIMARY KEY,
    abuse_confidence_score INTEGER,
    country_code         TEXT,
    usage_type           TEXT,
    isp                  TEXT,
    domain               TEXT,
    hostnames            TEXT,
    is_public            INTEGER,
    is_tor               INTEGER,
    total_reports        INTEGER,
    num_distinct_users   INTEGER,
    last_reported_at     TEXT,
    raw_json             TEXT,
    created_at           TEXT,
    updated_at           TEXT,
    last_accessed_at     TEXT
);
"""

_DDL_API_STATISTICS = """
CREATE TABLE IF NOT EXISTS api_statistics (
    day             TEXT    PRIMARY KEY,
    requests_count  INTEGER NOT NULL DEFAULT 0
);
"""

# ─────────────────────────────────────────────────────────────────────────────


def get_connection() -> sqlite3.Connection:
    """Retorna uma conexão SQLite com row_factory configurada."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn


def init_database() -> None:
    """Cria tabelas se não existirem. Idempotente."""
    conn = get_connection()
    try:
        conn.execute(_DDL_ABUSEIPDB_CACHE)
        conn.execute(_DDL_API_STATISTICS)
        conn.commit()
    finally:
        conn.close()
