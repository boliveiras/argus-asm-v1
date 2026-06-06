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
threatintel.core.utils
──────────────────────
Utilitários reutilizáveis por todos os módulos do pacote.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Optional


def is_public_ip(ip: str) -> bool:
    """
    Retorna True se o IP é público e elegível para consulta à API.
    Exclui: RFC1918, loopback, link-local, multicast, reserved.
    """
    try:
        addr = ipaddress.ip_address(ip)
        return (
            not addr.is_private
            and not addr.is_loopback
            and not addr.is_link_local
            and not addr.is_multicast
            and not addr.is_reserved
            and not addr.is_unspecified
        )
    except ValueError:
        return False


def normalize_ip(ip: str) -> Optional[str]:
    """
    Normaliza e valida um endereço IP.
    Retorna a forma canônica ou None se inválido.
    """
    try:
        return str(ipaddress.ip_address(ip.strip()))
    except ValueError:
        return None


def safe_int(value, default: int = 0) -> int:
    """Converte para int sem lançar exceção."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def safe_str(value, default: str = "") -> str:
    """Converte para str sem lançar exceção."""
    if value is None:
        return default
    return str(value).strip()


def score_color_class(score: int) -> str:
    """
    Retorna a classe CSS correspondente ao abuse score para o relatório HTML.
    0        → verde
    1–25     → amarelo
    26–50    → laranja
    51–75    → vermelho
    76–100   → vermelho crítico
    """
    if score == 0:
        return "score-clean"
    if score <= 25:
        return "score-low"
    if score <= 50:
        return "score-medium"
    if score <= 75:
        return "score-high"
    return "score-critical"


def score_label(score: int) -> str:
    """Rótulo textual para o abuse score."""
    if score == 0:
        return "Limpo"
    if score <= 25:
        return f"{score}% - Baixo"
    if score <= 50:
        return f"{score}% - Médio"
    if score <= 75:
        return f"{score}% - Alto"
    return f"{score}% - CRÍTICO"
