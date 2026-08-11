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
runner.py — Executa a sequência completa de scans (worker ROOT)
================================================================

Roda "sob demanda" a partir da interface Web, de forma INDEPENDENTE do cron.

Fluxo (isolamento de privilégio — a Web nunca executa nada):
  1. A Web (usuário sem privilégio) apenas GRAVA o arquivo de pedido
     `store/scan_request` — não invoca processo algum.
  2. Uma unit `argus-scan.path` do systemd percebe o arquivo e dispara
     `argus-scan.service` (Type=oneshot, root), que executa ESTE script.
  3. Este script apaga o pedido, executa a sequência FIXA de scanners e vai
     escrevendo `store/scan_status.json` — que a Web lê para a barra de progresso.

Postura de segurança:
  • A sequência de comandos é uma CONSTANTE do código (`STEPS`). Nada vem da
    requisição HTTP: não há argumento, caminho ou flag controlável pelo usuário.
  • `subprocess.run` com LISTA de argumentos e `shell=False` — sem interpretação
    de shell, portanto sem injeção de comando.
  • Lock por diretório (`mkdir` atômico) impede duas execuções simultâneas.
  • Timeout por passo evita um scan travado segurar a fila para sempre.

Uso: `python3 runner.py`  (normalmente chamado pelo systemd; o cron NÃO usa este script)
"""

from __future__ import annotations

import datetime
import json
import os
import subprocess  # nosec B404 - sequência FIXA de comandos, sem shell e sem entrada do usuário
import sys
import time
from pathlib import Path

# O systemd costuma rodar com locale C/POSIX: sem isto, um print com acento levanta
# UnicodeEncodeError e derruba a execução inteira. `errors="replace"` nunca falha.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

BASE_DIR = Path(os.environ.get("ARGUS_BASE", "/etc/argus"))
STORE_DIR = BASE_DIR / "store"
STATUS_FILE = STORE_DIR / "scan_status.json"
REQUEST_FILE = STORE_DIR / "scan_request"
LOCK_DIR = STORE_DIR / "scan_run.lock"          # mkdir é atômico → serve de lock
BIN = Path(os.environ.get("ARGUS_BIN", "/usr/local/bin"))

# Timeout por passo (segundos). UDP e submonitor são naturalmente demorados.
STEP_TIMEOUT = int(os.environ.get("ARGUS_STEP_TIMEOUT", str(4 * 60 * 60)))
# Saída completa de cada etapa. O scan agendado grava stdout via cron; o disparado
# pela web não tinha destino nenhum, então a saída sumia quando o passo terminava
# bem — e diagnosticar depois virava impossível (foi o que aconteceu com o "[ASN]").
LOG_DIR = Path(os.environ.get("ARGUS_SCAN_LOG_DIR", "/var/log/argus/scan"))

# Sequência FIXA (constante de código — nunca vem da Web).
STEPS: list[dict] = [
    {"key": "submonitor",  "label": "Subdomínios",        "cmd": [str(BIN / "argus-submonitor")]},
    {"key": "monitor_tcp", "label": "Portas TCP",         "cmd": [str(BIN / "argus-monitor"), "--tcp"]},
    {"key": "monitor_udp", "label": "Portas UDP",         "cmd": [str(BIN / "argus-monitor"), "--udp"]},
    {"key": "email",       "label": "Postura de e-mail",  "cmd": [str(BIN / "argus-email")]},
    {"key": "credentials", "label": "Credenciais",        "cmd": [str(BIN / "argus-credentials")]},
    {"key": "typosquat",   "label": "Typosquat",          "cmd": [str(BIN / "argus-typosquat")]},
]


def _now() -> str:
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _gravar_saida(chave: str, cmd: list, rc: int, saida: str) -> None:
    """Grava a saída completa da etapa em /var/log/argus/scan/<chave>.log.

    Sobrescreve a cada execução: interessa o último run, não histórico infinito.
    Nunca deixa o log derrubar o scan — problema de disco/permissão só avisa.
    Modo 0640 root:adm segue o padrão dos demais logs do Argus (PCI 10.3).
    """
    try:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        destino = LOG_DIR / f"{chave}.log"
        cabecalho = (f"# {' '.join(cmd)}\n"
                     f"# fim: {time.strftime('%Y-%m-%d %H:%M:%S')} | rc={rc}\n\n")
        fd = os.open(destino, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o640)
        with os.fdopen(fd, "w", encoding="utf-8", errors="replace") as fh:
            fh.write(cabecalho); fh.write(saida)
    except Exception as exc:
        print(f"  [AVISO] não consegui gravar o log de {chave}: {exc}", file=sys.stderr)


def _write_status(state: dict) -> None:
    """Grava o status de forma atômica (a Web lê a qualquer momento)."""
    STORE_DIR.mkdir(parents=True, exist_ok=True)
    tmp = STATUS_FILE.with_suffix(".json.tmp")
    try:
        tmp.write_text(json.dumps(state, ensure_ascii=False, indent=1), encoding="utf-8")
        os.replace(tmp, STATUS_FILE)
        try:
            os.chmod(STATUS_FILE, 0o644)     # legível pela Web (app user)
        except OSError:
            pass
    except OSError as exc:
        print(f"[ERRO] não foi possível gravar o status: {exc}", file=sys.stderr)


def _initial_state(actor: str) -> dict:
    return {
        "running": True,
        "actor": actor,
        "started_at": _now(),
        "finished_at": "",
        "current": 0,
        "total": len(STEPS),
        "percent": 0,
        "current_label": STEPS[0]["label"],
        "steps": [{"key": s["key"], "label": s["label"],
                   "cmd": " ".join(Path(c).name if i == 0 else c for i, c in enumerate(s["cmd"])),
                   "status": "pending", "rc": None, "duration": 0, "detail": ""} for s in STEPS],
        # "succeeded" (e não "ok"): a API devolve o status com `ok=True` no envelope —
        # uma chave "ok" aqui colidiria com o campo de sucesso da própria resposta.
        "succeeded": 0, "failed": 0,
    }


def _read_request_actor() -> str:
    """Quem pediu (registrado pela Web no arquivo de pedido). Só para auditoria."""
    try:
        raw = REQUEST_FILE.read_text(encoding="utf-8").strip()
        data = json.loads(raw) if raw.startswith("{") else {}
        actor = str(data.get("actor", "") or "")
        # Sanitiza: o valor vem de fora, então só é usado como texto curto no status.
        return "".join(ch for ch in actor if ch.isalnum() or ch in "._-@ ")[:64] or "web"
    except Exception:
        return "web"


def run_all(actor: str = "web") -> int:
    state = _initial_state(actor)
    _write_status(state)
    print(f"[ARGUS] Execução sob demanda iniciada por '{actor}' — {len(STEPS)} etapa(s)")

    for idx, step in enumerate(STEPS):
        state["current"] = idx + 1
        state["current_label"] = step["label"]
        state["steps"][idx]["status"] = "running"
        # Progresso é medido por etapa concluída (a etapa em curso ainda não conta).
        state["percent"] = int(idx * 100 / len(STEPS))
        _write_status(state)

        print(f"[{idx + 1}/{len(STEPS)}] {step['label']} -> {' '.join(step['cmd'])}")
        t0 = time.monotonic()
        rc, status, detail = 1, "fail", ""
        try:
            # Captura a saída: quando um passo falha, a última linha útil vai para o status
            # e para o log — sem isso, a interface mostraria "falhou" sem dizer o porquê.
            proc = subprocess.run(  # nosec B603 - lista fixa de comandos, shell=False, sem entrada do usuário
                step["cmd"], shell=False, timeout=STEP_TIMEOUT,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False,
                text=True, errors="replace")
            rc = proc.returncode
            status = "ok" if rc == 0 else "fail"
            _gravar_saida(step["key"], step["cmd"], rc, proc.stdout or "")
            if rc != 0:
                lines = [ln.strip() for ln in (proc.stdout or "").splitlines() if ln.strip()]
                detail = " | ".join(lines[-3:])[:300]
                for ln in lines[-15:]:
                    print(f"    {ln}")
        except subprocess.TimeoutExpired:
            rc, status = -1, "timeout"
            detail = f"excedeu {STEP_TIMEOUT}s"
            print(f"  [TIMEOUT] {step['label']} passou de {STEP_TIMEOUT}s", file=sys.stderr)
        except FileNotFoundError:
            rc, status = -2, "missing"
            detail = f"comando não encontrado: {step['cmd'][0]}"
            print(f"  [ERRO] {detail}", file=sys.stderr)
        except Exception as exc:                       # nunca aborta a fila
            rc, status = -3, "fail"
            detail = str(exc)[:300]
            print(f"  [ERRO] {step['label']}: {exc}", file=sys.stderr)

        dur = int(time.monotonic() - t0)
        state["steps"][idx].update({"status": status, "rc": rc, "duration": dur, "detail": detail})
        # Falha NÃO interrompe a sequência: os scanners são independentes.
        if status == "ok":
            state["succeeded"] += 1
        else:
            state["failed"] += 1
        state["percent"] = int((idx + 1) * 100 / len(STEPS))
        _write_status(state)
        print(f"  → {status} (rc={rc}) em {dur}s")

    state["running"] = False
    state["finished_at"] = _now()
    state["current_label"] = ""
    state["percent"] = 100
    _write_status(state)
    print(f"[ARGUS] Concluído: {state['succeeded']} ok, {state['failed']} com falha")
    return 0 if state["failed"] == 0 else 1


def main() -> int:
    actor = _read_request_actor()
    # Consome o pedido ANTES de rodar: senão a unit .path redispararia em loop.
    try:
        REQUEST_FILE.unlink()
    except FileNotFoundError:
        pass
    except OSError as exc:
        print(f"[AVISO] não foi possível remover o pedido: {exc}", file=sys.stderr)

    # Lock: mkdir é atômico — se já existe, outra execução está em curso.
    try:
        LOCK_DIR.mkdir(parents=False, exist_ok=False)
    except FileExistsError:
        print("[ARGUS] já existe uma execução em andamento — pedido ignorado", file=sys.stderr)
        return 0
    except OSError as exc:
        print(f"[ERRO] não foi possível criar o lock: {exc}", file=sys.stderr)
        return 1

    try:
        return run_all(actor)
    finally:
        try:
            LOCK_DIR.rmdir()
        except OSError:
            pass


if __name__ == "__main__":
    sys.exit(main())
