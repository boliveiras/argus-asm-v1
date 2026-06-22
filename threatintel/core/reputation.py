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
threatintel.core.reputation
────────────────────────────
Risk Engine — combina a criticidade da porta (Nmap) com a reputação do IP
(AbuseIPDB) para produzir um risco final consolidado.

Regras de elevação (nunca rebaixa o risco da porta):
  • abuse_score >= CRITICO_THRESHOLD (80) → CRITICO
  • abuse_score >= ALTO_THRESHOLD    (50) → mínimo ALTO
  • porta crítica + abuse_score > ELEVA_THRESHOLD (25) → CRITICO
  • IP TOR → eleva um nível (BAIXO→MEDIO, MEDIO→ALTO, ALTO→CRITICO)
  • usage_type "Data Center/Web Hosting/Transit" + score > 0 → +1 nível

Nota: o risco NUNCA é rebaixado — apenas elevado.
"""

from __future__ import annotations

from threatintel import CONFIG
from threatintel.core.utils import safe_int

# Thresholds lidos do config
_SCORE_CRITICO       = int(CONFIG.get("abuse_score_critico",              80))
_SCORE_ALTO          = int(CONFIG.get("abuse_score_alto",                 50))
_SCORE_ELEVA_CRITICA = int(CONFIG.get("abuse_score_eleva_porta_critica",  25))

# Ordem dos níveis de risco (crescente)
_LEVELS: list[str] = ["BAIXO", "MEDIO", "ALTO", "CRITICO"]
_LEVEL_IDX: dict[str, int] = {r: i for i, r in enumerate(_LEVELS)}

# Usage types de datacenter/hosting que aumentam suspeita
_DATACENTER_TYPES = {
    "data center/web hosting/transit",
    "hosting",
    "content delivery network",
}


def _elevate(risk: str, steps: int = 1) -> str:
    """Eleva o risco `steps` níveis, respeitando o máximo CRITICO."""
    idx = _LEVEL_IDX.get(risk, 0)
    return _LEVELS[min(idx + steps, len(_LEVELS) - 1)]


def compute_final_risk(
    port_risk: str,
    ip_type: str,
    abuse_data: dict | None,
) -> str:
    """
    Calcula o risco final combinando porta + reputação.

    Parâmetros:
        port_risk   — risco calculado pelo Nmap (ex: "MEDIO")
        ip_type     — "PUBLICO" ou "PRIVADO"
        abuse_data  — dict retornado pelo cache/provider, ou None

    Retorna o risco final como string: BAIXO / MEDIO / ALTO / CRITICO
    """
    risk = port_risk

    # IPs privados não têm dados de reputação — mantém risco da porta
    if ip_type != "PUBLICO" or not abuse_data:
        return risk

    score       = safe_int(abuse_data.get("abuse_confidence_score"), 0)
    is_tor      = bool(abuse_data.get("is_tor", 0))
    usage_type  = str(abuse_data.get("usage_type", "")).lower().strip()

    # Regra 1: score absoluto
    if score >= _SCORE_CRITICO:
        risk = "CRITICO"
    elif score >= _SCORE_ALTO:
        risk = _levels_max(risk, "ALTO")

    # Regra 2: porta crítica + score moderado
    if port_risk == "CRITICO" and score > _SCORE_ELEVA_CRITICA:
        risk = "CRITICO"

    # Regra 3: IP TOR sempre eleva um nível extra
    if is_tor:
        risk = _elevate(risk, 1)

    # Regra 4: datacenter suspeito com qualquer reporte
    if usage_type in _DATACENTER_TYPES and score > 0:
        risk = _elevate(risk, 1)

    return risk


def _levels_max(a: str, b: str) -> str:
    """Retorna o maior nível entre dois riscos."""
    return _LEVELS[max(_LEVEL_IDX.get(a, 0), _LEVEL_IDX.get(b, 0))]
