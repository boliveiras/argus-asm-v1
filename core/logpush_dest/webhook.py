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

    def _preparar(self) -> tuple[str, str, str]:
        """Valida a configuração e devolve (url, plataforma, chat_id)."""
        url = str(self.cfg.get("webhook_url") or "").strip()
        if not url_segura(url):
            # A URL NÃO entra no erro: quem a tem posta no canal, então ela é
            # segredo tanto quanto uma senha.
            raise LogPushError("URL de webhook inválida: exige https e host público")
        plataforma = str(self.cfg.get("webhook_plataforma") or "google_chat").strip()
        chat_id = str(self.cfg.get("webhook_chat_id") or "").strip()
        if plataforma == "telegram" and not chat_id:
            raise LogPushError("Telegram exige chat_id")
        return url, plataforma, chat_id

    def _entregar(self, m: Mensagem, url: str, plataforma: str, chat_id: str) -> None:
        """Posta UMA mensagem. Não consulta o filtro de severidade."""
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

    def send(self, mensagens: list[Mensagem]) -> None:
        if not mensagens:
            return
        url, plataforma, chat_id = self._preparar()
        permitidas = set(severidades_ligadas(self.cfg))
        for m in mensagens:
            if m.severidade not in permitidas:
                continue
            self._entregar(m, url, plataforma, chat_id)

    def testar(self) -> str:
        """Prova de conexão — ignora o filtro de severidade de propósito.

        A mensagem de teste é INFO; passando pelo filtro (padrão CRÍTICO+ALTO)
        ela seria descartada e a tela diria "teste OK" sem nada ter saído. Um
        teste que aprova sem enviar é pior do que não ter teste.
        """
        import datetime
        url, plataforma, chat_id = self._preparar()
        self._entregar(Mensagem(
            origem="teste", texto="Argus — teste de conexão do logpush",
            quando=datetime.datetime.now(), severidade="INFO",
            msgid="LOGPUSH_TEST"), url, plataforma, chat_id)
        return f"mensagem de teste enviada para {plataforma}"
