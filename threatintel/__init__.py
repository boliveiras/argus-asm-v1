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
threatintel — biblioteca compartilhada de Threat Intelligence

Uso:
    from threatintel.providers.abuseipdb import get_ip_reputation
    from threatintel.core.reputation import compute_final_risk

Estrutura:
    providers/   → integrações com APIs externas (AbuseIPDB, VirusTotal, etc.)
    core/        → lógica interna: cache, quota, banco, risco, utilitários
    logs/        → logs internos da biblioteca
"""

from __future__ import annotations

import json
import os
from pathlib import Path

# Localização canônica do config — permite override via env var
_DEFAULT_CONFIG = Path(__file__).parent / "config.json"
_CONFIG_PATH    = Path(os.environ.get("THREATINTEL_CONFIG", str(_DEFAULT_CONFIG)))


def load_config() -> dict:
    """Carrega config.json. Lança FileNotFoundError se ausente."""
    if not _CONFIG_PATH.exists():
        raise FileNotFoundError(
            f"[threatintel] config.json não encontrado em {_CONFIG_PATH}\n"
            f"Crie o arquivo ou defina a variável THREATINTEL_CONFIG."
        )
    with _CONFIG_PATH.open(encoding="utf-8") as f:
        cfg = json.load(f)

    # Substitui api_keys por variáveis de ambiente se definidas
    env_key = os.environ.get("ABUSEIPDB_KEY", "").strip()
    if env_key:
        cfg["abuseipdb_api_key"] = env_key
    env_urlscan = os.environ.get("URLSCAN_KEY", "").strip()
    if env_urlscan:
        cfg["urlscan_api_key"] = env_urlscan

    return cfg


# Config global — carregado uma vez na importação
try:
    CONFIG: dict = load_config()
except FileNotFoundError:
    CONFIG = {}

__all__ = ["CONFIG", "load_config"]
