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
threatintel.core.cache
──────────────────────
Cache persistente de resultados AbuseIPDB em SQLite.

TTL configurável via config.json (cache_ttl_hours, padrão 48h).
"""

from __future__ import annotations

import datetime
import json
from typing import Optional

from threatintel import CONFIG
from threatintel.core.database import get_connection

_TTL_HOURS: int = int(CONFIG.get("cache_ttl_hours", 48))


def _now_utc() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _is_expired(updated_at: str) -> bool:
    """Retorna True se o registro está mais velho que o TTL."""
    try:
        ts = datetime.datetime.strptime(updated_at, "%Y-%m-%d %H:%M:%S").replace(
            tzinfo=datetime.timezone.utc
        )
        age = datetime.datetime.now(datetime.timezone.utc) - ts
        return age.total_seconds() > _TTL_HOURS * 3600
    except Exception:
        return True


def get_cached(ip: str) -> Optional[dict]:
    """
    Retorna o registro em cache se existir E não estiver expirado.
    Atualiza last_accessed_at transparentemente.
    Retorna None se ausente ou expirado.
    """
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT * FROM abuseipdb_cache WHERE ip = ?", (ip,)
        ).fetchone()

        if row is None:
            return None

        if _is_expired(row["updated_at"]):
            return None  # expirado — precisa re-consultar API

        # Atualiza timestamp de acesso
        conn.execute(
            "UPDATE abuseipdb_cache SET last_accessed_at = ? WHERE ip = ?",
            (_now_utc(), ip),
        )
        conn.commit()

        return dict(row)
    finally:
        conn.close()


def set_cache(ip: str, data: dict) -> None:
    """
    Insere ou atualiza o cache para um IP com os dados da API.
    `data` deve ser o dict normalizado retornado pelo provider.
    """
    now = _now_utc()
    conn = get_connection()
    try:
        conn.execute(
            """
            INSERT INTO abuseipdb_cache (
                ip, abuse_confidence_score, country_code, usage_type,
                isp, domain, hostnames, is_public, is_tor,
                total_reports, num_distinct_users, last_reported_at,
                raw_json, created_at, updated_at, last_accessed_at
            ) VALUES (
                :ip, :abuse_confidence_score, :country_code, :usage_type,
                :isp, :domain, :hostnames, :is_public, :is_tor,
                :total_reports, :num_distinct_users, :last_reported_at,
                :raw_json, :created_at, :updated_at, :last_accessed_at
            )
            ON CONFLICT(ip) DO UPDATE SET
                abuse_confidence_score = excluded.abuse_confidence_score,
                country_code           = excluded.country_code,
                usage_type             = excluded.usage_type,
                isp                    = excluded.isp,
                domain                 = excluded.domain,
                hostnames              = excluded.hostnames,
                is_public              = excluded.is_public,
                is_tor                 = excluded.is_tor,
                total_reports          = excluded.total_reports,
                num_distinct_users     = excluded.num_distinct_users,
                last_reported_at       = excluded.last_reported_at,
                raw_json               = excluded.raw_json,
                updated_at             = excluded.updated_at,
                last_accessed_at       = excluded.last_accessed_at
            """,
            {
                "ip":                    ip,
                "abuse_confidence_score": data.get("abuse_confidence_score", 0),
                "country_code":          data.get("country_code", ""),
                "usage_type":            data.get("usage_type", ""),
                "isp":                   data.get("isp", ""),
                "domain":                data.get("domain", ""),
                "hostnames":             json.dumps(data.get("hostnames", [])),
                "is_public":             int(data.get("is_public", 1)),
                "is_tor":                int(data.get("is_tor", 0)),
                "total_reports":         data.get("total_reports", 0),
                "num_distinct_users":    data.get("num_distinct_users", 0),
                "last_reported_at":      data.get("last_reported_at", ""),
                "raw_json":              json.dumps(data.get("raw", {})),
                "created_at":            now,
                "updated_at":            now,
                "last_accessed_at":      now,
            },
        )
        conn.commit()
    finally:
        conn.close()
