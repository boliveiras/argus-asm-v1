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
logpush — lê o que há de novo nos logs e entrega ao destino configurado.

O ponteiro guarda (inode, posição) por arquivo e só avança DEPOIS que o destino
confirma. Falha de rede vira atraso, nunca buraco: o ciclo seguinte retoma do
mesmo ponto.

Uso: python3 logpush.py
"""

from __future__ import annotations

import datetime
import json
import os
import sys
from pathlib import Path

import logpush_config as LC
from logpush_dest import s3 as _s3  # noqa: F401 - importar registra o destino
from logpush_dest import webhook as _wh  # noqa: F401 - importar registra o destino
from logpush_dest.base import LogPushError, Mensagem, criar
from logpush_fmt import parse_rfc5424

MAX_POR_CICLO = int(os.environ.get("ARGUS_LOGPUSH_MAX", "5000"))


def raiz_log() -> Path:
    return Path(os.environ.get("ARGUS_LOG_ROOT", "/var/log/argus"))


def estado_path() -> Path:
    return LC.base_dir() / "store" / "logpush_state.json"


def ler_estado() -> dict:
    try:
        return json.loads(estado_path().read_text(encoding="utf-8"))
    except Exception:
        return {}


def gravar_estado(estado: dict) -> None:
    caminho = estado_path()
    try:
        caminho.parent.mkdir(parents=True, exist_ok=True)
        with open(caminho, "w", encoding="utf-8", newline="") as fh:
            json.dump(estado, fh, ensure_ascii=False, indent=2)
            fh.flush()
            os.fsync(fh.fileno())
    except OSError as exc:
        print(f"[LOGPUSH] não consegui gravar o estado: {exc}", file=sys.stderr)


def _arquivos(cfg: dict, raiz: Path) -> list[tuple[str, Path, bool]]:
    """(origem, caminho, estruturado) de cada arquivo das origens ligadas."""
    saida = []
    for oid in LC.origens_ligadas(cfg):
        origem = LC.POR_ID[oid]
        padrao = origem["caminho"]
        pasta, _, nome = padrao.partition("/")
        if "*" in nome:
            achados = sorted((raiz / pasta).glob(nome))
        else:
            p = raiz / padrao
            achados = [p] if p.exists() else []
        for a in achados:
            saida.append((oid, a, origem["estruturado"]))
    return saida


def _ler_desde(caminho: Path, pos: int) -> str:
    with open(caminho, encoding="utf-8", errors="replace") as fh:
        fh.seek(pos)
        return fh.read()


def _pendente_rotacionado(caminho: Path, marca: dict) -> str:
    """Resto do arquivo anterior quando o logrotate criou um novo (inode mudou).

    O logrotate usa `create` + `delaycompress`: o anterior fica como `.log.1`
    ainda descomprimido, o que dá a janela para terminar de ler antes de seguir.
    """
    if not marca:
        return ""
    anterior = caminho.parent / (caminho.name + ".1")
    if not anterior.exists():
        return ""
    try:
        if anterior.stat().st_ino != int(marca.get("inode", 0)):
            return ""
        return _ler_desde(anterior, int(marca.get("pos", 0)))
    except OSError:
        return ""


def coletar(cfg: dict, raiz: Path | None = None) -> list[Mensagem]:
    """Mensagens novas desde o ponteiro. NÃO altera o estado."""
    raiz = raiz or raiz_log()
    estado = ler_estado()
    mensagens: list[Mensagem] = []
    for origem, caminho, estruturado in _arquivos(cfg, raiz):
        chave = caminho.relative_to(raiz).as_posix()
        marca = estado.get(chave, {})
        try:
            st = caminho.stat()
        except OSError:
            continue
        bruto = ""
        mesmo_arquivo = int(marca.get("inode", 0)) == st.st_ino
        if marca and not mesmo_arquivo:
            bruto += _pendente_rotacionado(caminho, marca)
        pos = int(marca.get("pos", 0)) if mesmo_arquivo else 0
        if pos > st.st_size:
            pos = 0        # truncado (scan/*.log é reescrito a cada execução)
        try:
            bruto += _ler_desde(caminho, pos)
        except OSError:
            continue
        if not bruto.strip():
            continue
        if estruturado:
            for linha in bruto.splitlines():
                if not linha.strip():
                    continue
                m = parse_rfc5424(linha, origem)
                if m is not None:
                    mensagens.append(m)
                if len(mensagens) >= MAX_POR_CICLO:
                    return mensagens
        else:
            # Saída de execução: o arquivo inteiro é uma mensagem só.
            mensagens.append(Mensagem(
                origem=origem, texto=bruto.rstrip("\n"),
                quando=datetime.datetime.now(), severidade="INFO",
                msgid="SCAN_OUTPUT", campos={"arquivo": caminho.name}))
    return mensagens


def _estado_apos(cfg: dict, raiz: Path | None = None) -> dict:
    """Estado que reflete tudo lido até agora."""
    raiz = raiz or raiz_log()
    estado = dict(ler_estado())
    agora = datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    for _origem, caminho, _e in _arquivos(cfg, raiz):
        try:
            st = caminho.stat()
        except OSError:
            continue
        estado[caminho.relative_to(raiz).as_posix()] = {
            "inode": st.st_ino, "pos": st.st_size, "enviado_em": agora}
    return estado


def executar(cfg: dict | None = None, raiz: Path | None = None) -> dict:
    """Um ciclo: coleta, envia e — só se o envio der certo — avança o ponteiro."""
    cfg = cfg if cfg is not None else LC.ler()
    raiz = raiz or raiz_log()
    mensagens = coletar(cfg, raiz)
    if not mensagens:
        return {"ok": True, "enviadas": 0, "detalhe": "nada novo"}
    try:
        criar(cfg).send(mensagens)
    except LogPushError as exc:
        # Ponteiro NÃO avança: o próximo ciclo reenvia o mesmo trecho.
        print(f"[LOGPUSH] envio falhou: {exc}", file=sys.stderr)
        return {"ok": False, "enviadas": 0, "detalhe": str(exc)}
    gravar_estado(_estado_apos(cfg, raiz))
    print(f"[LOGPUSH] {len(mensagens)} mensagem(ns) enviada(s)")
    return {"ok": True, "enviadas": len(mensagens), "detalhe": ""}


def main() -> int:
    cfg = LC.ler()
    if not cfg.get("logpush_ligado", False):
        print("[LOGPUSH] desligado na configuração — nada a fazer")
        return 0
    return 0 if executar(cfg)["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
