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
logpush_dest.s3 — envio para bucket S3 (ou compatível).

Objetos são WRITE-ONCE: cada mensagem vira um objeto que nunca é reescrito. O
`pull-logs-s3` decide o que baixar por LastModified, então reescrever um objeto
faria aquele coletor rebaixar o arquivo inteiro e duplicar tudo no SIEM.
"""

from __future__ import annotations

from .base import LogDestination, LogPushError, Mensagem, registrar


@registrar("s3")
class S3Destination(LogDestination):
    """Um objeto por mensagem, nome com timestamp e sufixo anticolisão."""

    def __init__(self, cfg: dict) -> None:
        super().__init__(cfg)
        self._cliente = None            # injetável nos testes

    def _obter_cliente(self):
        if self._cliente is not None:
            return self._cliente
        try:
            import boto3
        except ImportError as exc:
            raise LogPushError("boto3 não instalado (apt install python3-boto3)") from exc
        extra = {}
        if self.cfg.get("s3_endpoint"):
            extra["endpoint_url"] = self.cfg["s3_endpoint"]
        try:
            sessao = boto3.session.Session(
                aws_access_key_id=self.cfg.get("s3_access_key") or None,
                aws_secret_access_key=self.cfg.get("s3_secret_key") or None,
                region_name=self.cfg.get("s3_regiao") or "us-east-1")
            self._cliente = sessao.client("s3", **extra)
        except Exception as exc:
            raise LogPushError(
                f"não consegui criar o cliente S3: {type(exc).__name__}") from exc
        return self._cliente

    def _chave(self, m: Mensagem, usados: set) -> str:
        prefixo = str(self.cfg.get("s3_prefixo") or "logs/argus").strip("/")
        carimbo = m.quando.strftime("%d-%m-%Y-%H-%M-%S")
        base = f"{prefixo}/{m.origem}/{carimbo}"
        chave = f"{base}.log"
        n = 1
        # O segundo NÃO é único: vários eventos caem no mesmo carimbo (o submonitor
        # registrou 9 hosts em menos de um segundo). Sem o sufixo o S3 sobrescreveria
        # em silêncio e o evento sumiria sem erro nenhum.
        while chave in usados:
            n += 1
            chave = f"{base}-{n:03d}.log"
        usados.add(chave)
        return chave

    def send(self, mensagens: list[Mensagem]) -> int:
        if not mensagens:
            return 0
        bucket = str(self.cfg.get("s3_bucket") or "").strip()
        if not bucket:
            raise LogPushError("bucket não configurado")
        cliente = self._obter_cliente()
        usados: set = set()
        for i, m in enumerate(mensagens):
            chave = self._chave(m, usados)
            corpo = (m.texto.rstrip("\n") + "\n").encode("utf-8", "replace")
            try:
                cliente.put_object(Bucket=bucket, Key=chave, Body=corpo)
            except Exception as exc:
                # Sem credencial no texto do erro. `processadas` preserva os
                # objetos já gravados: sem isso, o ciclo seguinte os regravaria
                # com carimbo novo e o bucket ficaria com cópias do mesmo evento.
                raise LogPushError(
                    f"falha ao gravar {chave}: {type(exc).__name__}",
                    processadas=i) from exc
        # O bucket não filtra: um objeto por mensagem, sempre.
        return len(mensagens)
