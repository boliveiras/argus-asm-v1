#!/usr/bin/env python3
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
logpush_dest.webhook — alerta legível em chat (Google Chat, Slack, Discord,
Teams, Telegram ou endpoint próprio).

Só as severidades marcadas saem: mandar tudo para um chat vira ruído em minutos
e a plataforma passa a descartar por limite de taxa.
"""

from __future__ import annotations

import requests
from logpush_config import severidades_ligadas, url_segura
from logpush_fmt import para_chat

from .base import LogDestination, LogPushError, Mensagem, registrar

_TIMEOUT = 15


@registrar("webhook")
class WebhookDestination(LogDestination):
    """Uma requisição por mensagem, já formatada para a plataforma."""

    def _post(self, url: str, payload: dict):
        """Isolado para o teste injetar sem tocar na rede."""
        return requests.post(url, json=payload, timeout=_TIMEOUT)

    def send(self, mensagens: list[Mensagem]) -> None:
        if not mensagens:
            return
        url = str(self.cfg.get("webhook_url") or "").strip()
        if not url_segura(url):
            # A URL NÃO entra no erro: quem a tem posta no canal, então ela é
            # segredo tanto quanto uma senha.
            raise LogPushError("URL de webhook inválida: exige https e host público")
        plataforma = str(self.cfg.get("webhook_plataforma") or "google_chat").strip()
        chat_id = str(self.cfg.get("webhook_chat_id") or "").strip()
        if plataforma == "telegram" and not chat_id:
            raise LogPushError("Telegram exige chat_id")
        permitidas = set(severidades_ligadas(self.cfg))
        for m in mensagens:
            if m.severidade not in permitidas:
                continue
            payload = para_chat(m, plataforma)
            if plataforma == "telegram":
                payload["chat_id"] = chat_id
            try:
                resp = self._post(url, payload)
            except Exception as exc:
                raise LogPushError(
                    f"falha de rede no webhook: {type(exc).__name__}") from exc
            if resp.status_code >= 300:
                corpo = (getattr(resp, "text", "") or "")[:120]
                raise LogPushError(f"webhook respondeu HTTP {resp.status_code}: {corpo}")
