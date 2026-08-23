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
import re
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

# Sequência FIXA (constante de código — nunca vem da Web). "scope" diz de qual
# arquivo de alvos a etapa depende (submonitor/targets → domínios, monitor/targets
# → IPs) — usado para decidir quais etapas rodam em cada campanha (ver
# `_etapas_da_campanha`), já que uma campanha pode existir só num dos dois.
STEPS: list[dict] = [
    {"key": "submonitor",  "label": "Subdomínios",        "scope": "submonitor",
     "cmd": [str(BIN / "argus-submonitor")]},
    {"key": "monitor_tcp", "label": "Portas TCP",         "scope": "monitor",
     "cmd": [str(BIN / "argus-monitor"), "--tcp"]},
    {"key": "monitor_udp", "label": "Portas UDP",         "scope": "monitor",
     "cmd": [str(BIN / "argus-monitor"), "--udp"]},
    {"key": "email",       "label": "Postura de e-mail",  "scope": "submonitor",
     "cmd": [str(BIN / "argus-email")]},
    {"key": "credentials", "label": "Credenciais",        "scope": "submonitor",
     "cmd": [str(BIN / "argus-credentials")]},
    {"key": "typosquat",   "label": "Typosquat",          "scope": "submonitor",
     "cmd": [str(BIN / "argus-typosquat")]},
]

# Lista de campanhas para o loop. Import tolerante: sem o módulo, o runner cai
# no modo antigo (uma execução cobrindo todas as campanhas de uma vez).
try:
    from campaigns import list_campaigns as _list_campaigns
    from campaigns import targets_dir as _targets_dir
    from campaigns import valid_name as _valid_name
except Exception:                                   # pragma: no cover
    _list_campaigns = None
    _targets_dir = None
    _valid_name = None


def _campanhas_a_rodar() -> list[str]:
    """Nomes das campanhas, em ordem — união dos dois escopos (submonitor ∪
    monitor), sem duplicatas. Uma campanha pode existir só num escopo: a
    interface permite criar campanha só com IPs (escopo "Monitor de Portas"),
    e olhar só para submonitor (como antes) a fazia sumir do loop. Vazio quando
    não há como listar."""
    if _list_campaigns is None:
        return []
    nomes: set[str] = set()
    for escopo in ("submonitor", "monitor"):
        try:
            nomes.update(c["name"] for c in _list_campaigns(escopo))
        except Exception as exc:
            print(f"[AVISO] não consegui listar as campanhas ({escopo}): {exc}",
                  file=sys.stderr)
    return sorted(nomes)


def _etapas_da_campanha(campanha: str) -> list[dict]:
    """Etapas de STEPS que se aplicam a esta campanha, na ordem original.

    Uma campanha só entra na execução de uma etapa quando o arquivo de alvos do
    escopo dela existe — senão as 4 etapas de domínio falhariam com "Campanha X
    não encontrada neste escopo" em toda campanha só-de-IP (e vice-versa), 4
    erros falsos por campanha só porque a lista tentou unir os dois escopos sem
    filtrar. Sem campanha (modo antigo) ou sem como checar o disco, roda tudo.
    """
    if not campanha or _targets_dir is None:
        return list(STEPS)
    escopos_disponiveis = set()
    for escopo in ("submonitor", "monitor"):
        try:
            if (_targets_dir(escopo) / f"{campanha}.txt").exists():
                escopos_disponiveis.add(escopo)
        except Exception:
            continue
    return [s for s in STEPS if s["scope"] in escopos_disponiveis]


def _steps_state(etapas: list[dict]) -> list[dict]:
    """Monta a lista `state["steps"]` para as etapas planejadas desta campanha."""
    return [{"key": s["key"], "label": s["label"],
             "cmd": " ".join(Path(c).name if i == 0 else c for i, c in enumerate(s["cmd"])),
             "status": "pending", "rc": None, "duration": 0, "detail": ""} for s in etapas]


def _nome_campanha_seguro(campanha: str) -> str:
    """Nome de campanha seguro para compor um caminho de log (defesa em
    profundidade): usa a mesma allowlist de `campaigns.valid_name` — e, se o
    import de campaigns falhar, uma allowlist local equivalente — para o nome
    nunca escapar do diretório de log. Devolve "" quando o nome é inválido."""
    if not campanha:
        return ""
    if _valid_name is not None:
        return campanha if _valid_name(campanha) else ""
    if campanha in (".", "..") or not re.match(r"^[A-Za-z0-9._-]{1,64}$", campanha):
        return ""
    return campanha


def _now() -> str:
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _gravar_saida(chave: str, cmd: list, rc: int, saida: str, campanha: str = "") -> None:
    """Grava a saída completa da etapa em /var/log/argus/scan/<chave>[.campanha].log.

    Um arquivo POR CAMPANHA quando há campanha: gravar sempre em <chave>.log
    (sem distinguir campanha) fazia o log da campanha 1 ser sobrescrito assim
    que a campanha 2 rodava a mesma etapa — sobrava só o log da última, e uma
    falha na campanha 1 não deixava rastro depois que a 3 rodava. É a própria
    razão de existir desta função (não perder o "porquê" de uma falha).
    Sobrescreve a cada execução da MESMA campanha: interessa o último run
    dela, não histórico infinito. Nunca deixa o log derrubar o scan —
    problema de disco/permissão só avisa. Modo 0640 root:adm segue o padrão
    dos demais logs do Argus (PCI 10.3).
    """
    try:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        nome_seguro = _nome_campanha_seguro(campanha)
        sufixo = f".{nome_seguro}" if nome_seguro else ""
        destino = LOG_DIR / f"{chave}{sufixo}.log"
        cabecalho = (f"# {' '.join(cmd)}\n"
                     f"# campanha: {campanha or '(todas)'}\n"
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
        "steps": _steps_state(STEPS),
        # "succeeded" (e não "ok"): a API devolve o status com `ok=True` no envelope —
        # uma chave "ok" aqui colidiria com o campo de sucesso da própria resposta.
        "succeeded": 0, "failed": 0,
    }


def _read_request() -> tuple[str, str]:
    """Quem pediu e para qual campanha, lidos do pedido gravado pela Web.

    Nada daqui vira comando: o autor é texto de auditoria e a campanha entra como
    variável de ambiente, que os scanners conferem contra os arquivos de alvo já
    existentes. A sanitização aqui é defesa em profundidade.
    """
    try:
        raw = REQUEST_FILE.read_text(encoding="utf-8").strip()
        data = json.loads(raw) if raw.startswith("{") else {}
        actor = str(data.get("actor", "") or "")
        actor = "".join(ch for ch in actor if ch.isalnum() or ch in "._-@ ")[:64] or "web"
        camp = str(data.get("campanha", "") or "")
        camp = "".join(ch for ch in camp if ch.isalnum() or ch in "._-")[:64]
        return actor, camp
    except Exception:
        return "web", ""


def _executar_etapas(state: dict, etapas: list[dict], campanha: str = "") -> tuple[int, int]:
    """Roda os módulos planejados para a campanha corrente. Devolve (ok, falhas)."""
    ok = falhas = 0
    total = len(etapas)
    for idx, step in enumerate(etapas):
        state["current"] = idx + 1
        state["current_label"] = step["label"]
        state["steps"][idx].update({"status": "running", "rc": None,
                                    "duration": 0, "detail": ""})
        _atualizar_percent(state, idx)
        _write_status(state)

        print(f"[{idx + 1}/{total}] {step['label']} -> {' '.join(step['cmd'])}")
        t0 = time.monotonic()
        rc, status, detail = 1, "fail", ""
        # Falha NÃO interrompe a sequência: os scanners são independentes.
        try:
            # Captura a saída: quando um passo falha, a última linha útil vai para o status
            # e para o log — sem isso, a interface mostraria "falhou" sem dizer o porquê.
            proc = subprocess.run(  # nosec B603 - lista fixa de comandos, shell=False, sem entrada do usuário
                step["cmd"], shell=False, timeout=STEP_TIMEOUT,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False,
                text=True, errors="replace")
            rc = proc.returncode
            status = "ok" if rc == 0 else "fail"
            _gravar_saida(step["key"], step["cmd"], rc, proc.stdout or "", campanha)
            if rc != 0:
                lines = [ln.strip() for ln in (proc.stdout or "").splitlines() if ln.strip()]
                detail = " | ".join(lines[-3:])[:300]
                for ln in lines[-15:]:
                    print(f"    {ln}")
        except subprocess.TimeoutExpired as exc:
            rc, status = -1, "timeout"
            # A saída parcial vem no próprio TimeoutExpired. Sem gravá-la aqui, o log
            # sumia justamente no caso em que ele mais importa: a etapa que estourou.
            parcial = exc.output or ""
            if isinstance(parcial, bytes):
                parcial = parcial.decode("utf-8", "replace")
            _gravar_saida(step["key"], step["cmd"], rc, parcial, campanha)
            ultimas = [ln.strip() for ln in parcial.splitlines() if ln.strip()][-3:]
            detail = (f"excedeu {STEP_TIMEOUT}s"
                      + (" · última saída: " + " | ".join(ultimas) if ultimas else ""))[:300]
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
        state["steps"][idx].update({"status": status, "rc": rc,
                                    "duration": dur, "detail": detail})
        if status == "ok":
            ok += 1
            state["succeeded"] += 1
        else:
            falhas += 1
            state["failed"] += 1
        _atualizar_percent(state, idx + 1)
        _write_status(state)
        print(f"  → {status} (rc={rc}) em {dur}s")
    return ok, falhas


def _atualizar_percent(state: dict, etapas_feitas: int) -> None:
    """Progresso global: soma as etapas já concluídas nas campanhas anteriores
    mais as desta. O total de etapas por campanha VARIA (nem toda campanha
    roda as 6 — uma só-de-IP roda só 2), então não dá mais para multiplicar
    campanhas × 6; o total vem da soma das etapas realmente planejadas para
    cada campanha (`etapas_total_geral`, calculado no início do loop)."""
    total_geral = max(1, state.get("etapas_total_geral", 1))
    feitas_anteriores = state.get("etapas_feitas_anteriores", 0)
    state["percent"] = int((feitas_anteriores + etapas_feitas) * 100 / total_geral)


def run_all(actor: str = "web", campanha: str = "") -> int:
    # Campanha específica: uma execução só, como sempre foi.
    # Sem campanha: cada uma roda do início ao fim antes da próxima, para que o
    # resultado de uma esteja salvo mesmo se a seguinte falhar.
    alvos = [campanha] if campanha else _campanhas_a_rodar()
    if not alvos:
        alvos = [""]          # sem lista de campanhas, mantém o modo antigo

    # Etapas planejadas por campanha (varia: uma só-de-IP roda só 2, não 6) —
    # calculado uma vez para o total do progresso global (`_atualizar_percent`).
    planos = [_etapas_da_campanha(a) for a in alvos]

    state = _initial_state(actor)
    state["campanha"] = alvos[0]
    state["campanhas_total"] = len(alvos)
    state["campanha_idx"] = 1
    state["campanhas"] = [{"nome": n, "status": "pending"} for n in alvos]
    state["etapas_total_geral"] = sum(len(p) for p in planos) or 1
    state["etapas_feitas_anteriores"] = 0
    _write_status(state)

    escopo = f"campanha {campanha}" if campanha else f"{len(alvos)} campanha(s)"
    print(f"[ARGUS] Execução sob demanda iniciada por '{actor}' ({escopo})")

    falhas_seguidas = 0
    for i, alvo in enumerate(alvos):
        state["campanha"] = alvo
        state["campanha_idx"] = i + 1
        etapas = planos[i]

        if alvo and not etapas:
            # Campanha sem arquivo de alvos em escopo nenhum — o arquivo foi
            # apagado entre listar as campanhas e chegar aqui. Não é falha do
            # scan (nada rodou, nada quebrou): é "nada para rodar".
            state["campanhas"][i]["status"] = "skipped"
            state["campanhas"][i]["detail"] = "nenhum alvo encontrado em escopo nenhum"
            state["etapas_feitas_anteriores"] += len(etapas)
            _write_status(state)
            print(f"[ARGUS] === campanha {i + 1}/{len(alvos)}: {alvo} — "
                  "sem alvo em escopo nenhum, pulada ===")
            continue

        state["campanhas"][i]["status"] = "running"
        state["current"] = 0
        state["total"] = len(etapas)
        # Cada campanha começa com as etapas DELA (não as 6 fixas): o painel
        # mostra o progresso real, sem exibir como pendente uma etapa que
        # nunca vai rodar (ex.: as de domínio numa campanha só-de-IP).
        state["steps"] = _steps_state(etapas)
        _write_status(state)

        if alvo:
            os.environ["ARGUS_CAMPANHA"] = alvo
        else:
            os.environ.pop("ARGUS_CAMPANHA", None)
        print(f"[ARGUS] === campanha {i + 1}/{len(alvos)}: {alvo or 'todas'} "
              f"({len(etapas)} etapa(s)) ===")

        ok, falhas = _executar_etapas(state, etapas, alvo)
        # Campanha só conta como falha quando NENHUMA etapa passou: um typosquat
        # que falha sozinho não invalida os subdomínios já encontrados.
        completou = ok > 0
        state["campanhas"][i]["status"] = "succeeded" if completou else "failed"
        # Detalhe da(s) etapa(s) que falharam: sem isto, o motivo da falha desta
        # campanha some do estado assim que a próxima reseta `state["steps"]`.
        detalhes = [f"{s['key']}: {s['detail']}" for s in state["steps"]
                   if s["status"] not in ("ok", "pending") and s["detail"]]
        if detalhes:
            state["campanhas"][i]["detail"] = " | ".join(detalhes)[:500]
        state["etapas_feitas_anteriores"] += len(etapas)
        falhas_seguidas = 0 if completou else falhas_seguidas + 1
        _write_status(state)

        if falhas_seguidas >= 2 and i + 1 < len(alvos):
            # Duas campanhas seguidas sem nenhuma etapa completa: o problema é do
            # ambiente (rede, disco, permissão), não desta campanha. Insistir só
            # gasta hora — o que já rodou continua salvo.
            for pendente in state["campanhas"][i + 1:]:
                pendente["status"] = "skipped"
            print("[ARGUS] duas campanhas seguidas falharam por completo — "
                  "execução interrompida", file=sys.stderr)
            break

    os.environ.pop("ARGUS_CAMPANHA", None)
    state["running"] = False
    state["finished_at"] = _now()
    state["current_label"] = ""
    state["percent"] = 100
    _write_status(state)
    print(f"[ARGUS] Concluído: {state['succeeded']} ok, {state['failed']} com falha")
    return 0 if state["failed"] == 0 else 1


def main() -> int:
    actor, campanha = _read_request()
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
        return run_all(actor, campanha)
    finally:
        try:
            LOCK_DIR.rmdir()
        except OSError:
            pass


if __name__ == "__main__":
    sys.exit(main())
