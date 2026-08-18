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
logpush_dest.base — contrato único dos destinos.

Mesma ideia do `LLMClient` do padrão de integração: a subclasse implementa APENAS
o transporte (`send`). Descobrir arquivos, controlar posição, lotear e repetir é
responsabilidade do coletor e vale igual para todos os destinos.
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass, field


class LogPushError(Exception):
    """Falha de envio. A mensagem NUNCA inclui credencial.

    `processadas` diz quantas mensagens do lote o destino já resolveu antes de
    falhar — entregues ou descartadas pelo filtro. Sem isso, uma falha na quinta
    de vinte faria as quatro primeiras, já entregues, voltarem no ciclo seguinte.
    """

    def __init__(self, *args, processadas: int = 0) -> None:
        super().__init__(*args)
        self.processadas = processadas


@dataclass
class Mensagem:
    """Uma unidade de envio já lida do arquivo."""

    origem: str
    texto: str                                  # linha original, sem alteração
    quando: datetime.datetime
    severidade: str = "INFO"
    msgid: str = ""
    campos: dict = field(default_factory=dict)
    # De onde veio e até que byte. É o que permite confirmar o progresso parcial
    # quando o lote falha no meio. Os destinos não usam nem enxergam.
    arquivo: str = ""
    ate: int = 0


class LogDestination:
    """Contrato. Subclasse implementa só `send`."""

    def __init__(self, cfg: dict) -> None:
        self.cfg = cfg or {}

    def lote_maximo(self) -> int:
        """Quantas mensagens este destino aceita por ciclo.

        Bucket não se importa com volume; chat se importa muito — passar do
        limite de taxa derruba o lote inteiro, e como o ponteiro só avança com
        entrega confirmada, o ciclo seguinte tentaria o mesmo lote outra vez.
        Um teto que caiba no limite da plataforma faz o acúmulo escoar aos
        poucos em vez de travar.
        """
        return 5000

    def send(self, mensagens: list[Mensagem]) -> int:
        """Entrega as mensagens e devolve QUANTAS saíram de fato.

        Retornar sem exceção significa ENTREGUE — é o que autoriza o coletor a
        avançar o ponteiro. O número devolvido pode ser menor que o lote quando
        o destino descarta parte (o filtro de severidade do chat, por exemplo):
        relatar o tamanho do lote faria o journal prometer entregas que não
        aconteceram.
        """
        raise NotImplementedError("destino deve implementar send()")

    def testar(self) -> str:
        """Envia uma prova de conexão. Devolve descrição curta do resultado."""
        # Hora local, como em toda Mensagem: é o que aparece no chat e no nome do
        # objeto, e precisa bater com o relógio de quem lê.
        agora = datetime.datetime.now()
        self.send([Mensagem(origem="teste",
                            texto="Argus — teste de conexão do logpush",
                            quando=agora, severidade="INFO", msgid="LOGPUSH_TEST")])
        return "envio de teste concluído"


_REGISTRY: dict = {}


def registrar(nome: str):
    def _wrap(cls):
        _REGISTRY[nome] = cls
        return cls
    return _wrap


def criar(cfg: dict) -> LogDestination:
    nome = str((cfg or {}).get("destino", "") or "").strip()
    cls = _REGISTRY.get(nome)
    if cls is None:
        raise LogPushError(f"destino desconhecido: {nome or '(vazio)'}")
    return cls(cfg)
