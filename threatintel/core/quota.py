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
threatintel.core.quota
──────────────────────
Controla e persiste o consumo diário da API AbuseIPDB.

Limite configurável via config.json (daily_request_limit, padrão 1000).
Aviso automático ao atingir 80% e 95% da cota.
"""

from __future__ import annotations

import datetime

from threatintel import CONFIG
from threatintel.core.database import get_connection

_DAILY_LIMIT: int = int(CONFIG.get("daily_request_limit", 1000))


def _today() -> str:
    return datetime.date.today().isoformat()


def get_usage(day: str | None = None) -> int:
    """Retorna o número de requests feitos no dia informado (padrão: hoje)."""
    day = day or _today()
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT requests_count FROM api_statistics WHERE day = ?", (day,)
        ).fetchone()
        return int(row["requests_count"]) if row else 0
    finally:
        conn.close()


def get_remaining() -> int:
    """Retorna quantas consultas ainda podem ser feitas hoje."""
    return max(0, _DAILY_LIMIT - get_usage())


def can_request(n: int = 1) -> bool:
    """Retorna True se há cota disponível para `n` requisições."""
    return get_remaining() >= n


def increment(n: int = 1) -> int:
    """
    Registra `n` requests no dia de hoje.
    Retorna o total acumulado no dia após o incremento.
    Emite avisos de cota no stderr.
    """
    day  = _today()
    conn = get_connection()
    try:
        conn.execute(
            """
            INSERT INTO api_statistics (day, requests_count)
            VALUES (?, ?)
            ON CONFLICT(day) DO UPDATE SET
                requests_count = requests_count + excluded.requests_count
            """,
            (day, n),
        )
        conn.commit()
        total = get_usage(day)
    finally:
        conn.close()

    pct = total / _DAILY_LIMIT * 100
    if pct >= 95:
        print(f"[QUOTA] ⚠️  CRÍTICO: {total}/{_DAILY_LIMIT} consultas usadas hoje ({pct:.0f}%)")
    elif pct >= 80:
        print(f"[QUOTA] ⚠️  AVISO: {total}/{_DAILY_LIMIT} consultas usadas hoje ({pct:.0f}%)")

    return total


def status_line() -> str:
    """Retorna string formatada com status da cota para exibição no terminal."""
    used      = get_usage()
    remaining = get_remaining()
    pct       = used / _DAILY_LIMIT * 100
    return (
        f"[QUOTA] AbuseIPDB — {used}/{_DAILY_LIMIT} consultas hoje "
        f"({pct:.0f}% usado, {remaining} restantes)"
    )
