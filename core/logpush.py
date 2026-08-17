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


def gravar_estado(estado: dict) -> bool:
    caminho = estado_path()
    try:
        caminho.parent.mkdir(parents=True, exist_ok=True)
        with open(caminho, "w", encoding="utf-8", newline="") as fh:
            json.dump(estado, fh, ensure_ascii=False, indent=2)
            fh.flush()
            os.fsync(fh.fileno())
    except OSError as exc:
        print(f"[LOGPUSH] não consegui gravar o estado: {exc}", file=sys.stderr)
        return False
    return True


def gravar_marcas(marcas: dict) -> bool:
    """Avança o ponteiro SÓ dos arquivos lidos neste ciclo.

    Quem não aparece em `marcas` fica intocado: a origem que não pôde ser lida
    continua pendente do mesmo ponto no ciclo seguinte.
    """
    if not marcas:
        return True
    return gravar_estado({**ler_estado(), **marcas})


def _pular(chave: str, exc: Exception) -> None:
    """Toda origem pulada diz por quê — silêncio aqui vira perda invisível."""
    print(f"[LOGPUSH] {chave}: {type(exc).__name__} — origem pulada, "
          f"ponteiro mantido no lugar", file=sys.stderr)


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


def _ler_desde(caminho: Path, pos: int) -> bytes:
    """Bytes a partir de `pos`.

    Em bytes, não em texto: a posição gravada no ponteiro precisa ser o mesmo
    offset que o `seek` entende. Decodificando antes, um byte inválido vira um
    caractere de 3 bytes e a conta do offset passa a mentir.
    """
    with open(caminho, "rb") as fh:
        fh.seek(pos)
        return fh.read()


def _pendente_rotacionado(caminho: Path, marca: dict) -> bytes:
    """Resto do arquivo anterior quando o logrotate criou um novo (inode mudou).

    O logrotate usa `create` + `delaycompress`: o anterior fica como `.log.1`
    ainda descomprimido, o que dá a janela para terminar de ler antes de seguir.
    """
    if not marca:
        return b""
    anterior = caminho.parent / (caminho.name + ".1")
    if not anterior.exists():
        return b""
    try:
        if anterior.stat().st_ino != int(marca.get("inode", 0)):
            return b""
        return _ler_desde(anterior, int(marca.get("pos", 0)))
    except OSError as exc:
        _pular(anterior.name, exc)
        return b""


def _converter(bloco: bytes, origem: str, estruturado: bool, caminho: Path,
               limite: int) -> tuple[list[Mensagem], int]:
    """(mensagens, bytes consumidos) de um bloco lido.

    O consumo é contado byte a byte porque é ele que vira a posição do ponteiro:
    marcar mais do que se leu abre buraco, marcar menos duplica.
    """
    if limite <= 0:
        return [], 0
    if not estruturado:
        # Saída de execução: o arquivo inteiro é uma mensagem só.
        texto = bloco.decode("utf-8", "replace")
        if not texto.strip():
            return [], len(bloco)
        return [Mensagem(origem=origem, texto=texto.rstrip("\n"),
                         quando=datetime.datetime.now(), severidade="INFO",
                         msgid="SCAN_OUTPUT",
                         campos={"arquivo": caminho.name})], len(bloco)

    mensagens: list[Mensagem] = []
    consumido = 0
    partes = bloco.split(b"\n")
    # O último pedaço não termina em \n: ou é vazio (o bloco acabou redondo) ou
    # é uma linha que o scanner ainda está escrevendo. Nos dois casos ele fica
    # para o próximo ciclo — enviar meia linha e marcá-la como lida perderia o
    # evento inteiro quando o resto chegasse.
    for crua in partes[:-1]:
        if len(mensagens) >= limite:
            break
        consumido += len(crua) + 1
        linha = crua.decode("utf-8", "replace").strip()
        if not linha:
            continue
        m = parse_rfc5424(linha, origem)
        if m is not None:
            mensagens.append(m)
    return mensagens, consumido


def _varrer(cfg: dict, raiz: Path | None = None,
            limite: int | None = None) -> tuple[list[Mensagem], dict]:
    """Lê o que há de novo e devolve (mensagens, marcas).

    `marcas` traz SÓ os arquivos efetivamente lidos, com a posição exata do que
    saiu deles. Origem que não pôde ser aberta fica de fora, e o ponteiro dela
    não se mexe.

    `limite` é o teto do destino (um chat aceita bem menos que um bucket). O que
    passar dele fica para o ciclo seguinte, marcado no byte certo.
    """
    raiz = raiz or raiz_log()
    teto = MAX_POR_CICLO if limite is None else min(limite, MAX_POR_CICLO)
    estado = ler_estado()
    agora = datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    mensagens: list[Mensagem] = []
    marcas: dict = {}
    for origem, caminho, estruturado in _arquivos(cfg, raiz):
        restante = teto - len(mensagens)
        if restante <= 0:
            break
        chave = caminho.relative_to(raiz).as_posix()
        marca = estado.get(chave, {})
        try:
            st = caminho.stat()
        except OSError as exc:
            _pular(chave, exc)
            continue
        mesmo_arquivo = int(marca.get("inode", 0)) == st.st_ino
        if marca and not mesmo_arquivo:
            pendente = _pendente_rotacionado(caminho, marca)
            if pendente:
                msgs, _ = _converter(pendente, origem, estruturado, caminho, restante)
                mensagens.extend(msgs)
                restante -= len(msgs)
        pos = int(marca.get("pos", 0)) if mesmo_arquivo else 0
        if pos > st.st_size:
            pos = 0        # truncado (scan/*.log é reescrito a cada execução)
        try:
            bloco = _ler_desde(caminho, pos)
        except OSError as exc:
            # Sem marca: nada desta origem é dado como entregue. Foi exatamente
            # aqui que 3 KB de achados sumiram — o ponteiro ia ao fim de um
            # arquivo que o serviço nunca teve permissão de abrir.
            _pular(chave, exc)
            continue
        msgs, consumido = _converter(bloco, origem, estruturado, caminho, restante)
        mensagens.extend(msgs)
        marcas[chave] = {"inode": st.st_ino, "pos": pos + consumido,
                         "enviado_em": agora}
    return mensagens, marcas


def coletar(cfg: dict, raiz: Path | None = None) -> list[Mensagem]:
    """Mensagens novas desde o ponteiro. NÃO altera o estado."""
    return _varrer(cfg, raiz)[0]


def executar(cfg: dict | None = None, raiz: Path | None = None) -> dict:
    """Um ciclo: coleta, envia e — só se o envio der certo — avança o ponteiro."""
    cfg = cfg if cfg is not None else LC.ler()
    raiz = raiz or raiz_log()
    # Fail secure: sem conseguir guardar o ponteiro, o ciclo seguinte releria o
    # mesmo trecho e reenviaria tudo — a cada 5 minutos, para sempre. Não
    # entregar nada é o dano menor, e o serviço sai com erro para aparecer no
    # journal em vez de inundar o destino em silêncio.
    if not gravar_estado(ler_estado()):
        return {"ok": False, "enviadas": 0,
                "detalhe": "ponteiro não é gravável — nada enviado para não duplicar"}
    # O destino é montado antes da varredura só para saber quanto ele aceita por
    # ciclo. Se estiver mal configurado, o erro fica guardado: sem nada novo para
    # enviar, uma configuração incompleta não é falha do ciclo.
    destino, erro = None, None
    try:
        destino = criar(cfg)
    except LogPushError as exc:
        erro = exc
    mensagens, marcas = _varrer(cfg, raiz,
                                destino.lote_maximo() if destino else None)
    if not mensagens:
        # Nada a enviar, mas o que foi lido e descartado (linha em branco, lixo
        # fora do RFC) não precisa ser relido para sempre.
        gravar_marcas(marcas)
        return {"ok": True, "enviadas": 0, "detalhe": "nada novo"}
    if destino is None:
        print(f"[LOGPUSH] envio falhou: {erro}", file=sys.stderr)
        return {"ok": False, "enviadas": 0, "detalhe": str(erro)}
    try:
        destino.send(mensagens)
    except LogPushError as exc:
        # Ponteiro NÃO avança: o próximo ciclo reenvia o mesmo trecho.
        print(f"[LOGPUSH] envio falhou: {exc}", file=sys.stderr)
        return {"ok": False, "enviadas": 0, "detalhe": str(exc)}
    print(f"[LOGPUSH] {len(mensagens)} mensagem(ns) enviada(s)")
    if not gravar_marcas(marcas):
        # Entregue mas não anotado: o próximo ciclo vai repetir este lote. Sai
        # com erro para o operador ver, já que a duplicata é inevitável agora.
        return {"ok": False, "enviadas": len(mensagens),
                "detalhe": "enviado, mas o ponteiro não foi gravado — haverá repetição"}
    return {"ok": True, "enviadas": len(mensagens), "detalhe": ""}


def main() -> int:
    cfg = LC.ler()
    if not cfg.get("logpush_ligado", False):
        print("[LOGPUSH] desligado na configuração — nada a fazer")
        return 0
    return 0 if executar(cfg)["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
