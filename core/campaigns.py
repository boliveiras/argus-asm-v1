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
campaigns.py — Gestão de campanhas (targets/*.txt) para a interface Web
=======================================================================

Uma "campanha" é um arquivo `targets/<NOME>.txt` lido pelos scanners:
  • monitor      → IPs / CIDRs  (/etc/argus/monitor/targets/NOME.txt)
  • submonitor   → domínios     (/etc/argus/submonitor/targets/NOME.txt)

Formato (compatível com o parser dos scanners): um alvo por linha, `#` inicia
comentário. Este módulo só ESCREVE entradas válidas — a validação é a mesma
regra dos scanners (IP/CIDR para monitor, hostname para submonitor).

Postura de segurança (a Web escreve em disco — superfície sensível):
  • Nome da campanha em ALLOWLIST estrita (`^[A-Za-z0-9._-]{1,64}$`) e recusa
    "." / ".." — sem separador de caminho, sem traversal possível.
  • Defesa em profundidade: o caminho final é resolvido e precisa estar DENTRO
    do diretório de targets (bloqueia symlink/escape mesmo se a regex mudasse).
  • Escrita ATÔMICA (tmp no mesmo dir + os.replace) — nunca deixa arquivo
    truncado se o processo morrer no meio; o scanner nunca lê estado parcial.
  • Excluir remove APENAS o alvo (.txt). Achados/histórico nos bancos ficam
    intactos (auditoria preservada).
  • Renomear migra o histórico (campo `campanha` nos bancos) — sem órfãos.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import sqlite3
import tempfile
from pathlib import Path

# Escopos suportados: nome → (subdiretório do módulo, tipo de alvo)
SCOPES = {
    "monitor":    {"dir": "monitor",    "kind": "ip",     "label": "Monitor de Portas"},
    "submonitor": {"dir": "submonitor", "kind": "domain", "label": "Monitor de Subdomínios"},
}

# Nome da campanha: allowlist estrita (vira nome de arquivo).
_NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
# Hostname (mesma regra do submonitor).
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$")
# Caracteres que nunca podem chegar a uma linha de comando (defesa em profundidade).
_DANGEROUS = set(";|&$`<>\n\r\t\\\"'")


class CampaignError(ValueError):
    """Erro de uso (nome/alvo inválido, campanha inexistente, já existe...)."""


# ── validação ────────────────────────────────────────────────────────────────

def valid_name(name: str) -> bool:
    name = (name or "").strip()
    if name in (".", ".."):
        return False
    return bool(_NAME_RE.match(name))


# ── Configuração por campanha (campaigns.json) ───────────────────────
# Prefixos de wordlist. O padrão replica o comportamento histórico: campanha sem
# configuração roda exatamente como antes.
PREFIXOS_PADRAO = ["", "prod-", "hml-", "dev-", "aceite-"]
# Allowlist do prefixo. Ele é CONCATENADO em hostname e depois resolvido — sem
# esta trava, a interface viraria caminho para injetar consulta a domínio de
# terceiro. Vazio é válido: significa "a palavra da wordlist, pura".
_PREFIXO_RE = re.compile(r"^[a-z0-9-]{0,20}$")


def config_path() -> Path:
    return Path(_base()) / "campaigns.json"


def ler_config() -> dict:
    """Todo o campaigns.json. Arquivo ausente ou corrompido devolve {} — a
    configuração é conveniência, e perdê-la não pode impedir o scan de rodar."""
    try:
        dados = json.loads(config_path().read_text(encoding="utf-8"))
        return dados if isinstance(dados, dict) else {}
    except Exception:
        return {}


def prefixos_da_campanha(nome: str) -> list[str]:
    """Prefixos da campanha; o padrão quando ela não tem configuração própria."""
    entrada = ler_config().get(str(nome or ""), {})
    if not isinstance(entrada, dict):
        return list(PREFIXOS_PADRAO)
    prefixos = entrada.get("prefixos")
    if not isinstance(prefixos, list):
        return list(PREFIXOS_PADRAO)
    # Revalida na LEITURA: o arquivo pode ter sido editado à mão no servidor.
    limpos = [p for p in prefixos if isinstance(p, str) and _PREFIXO_RE.match(p)]
    return limpos or [""]


def set_prefixos(nome: str, prefixos) -> list[str]:
    """Valida e grava os prefixos da campanha. Devolve a lista efetivamente salva.

    Grava IN-PLACE (mesmo inode): o serviço precisa de permissão apenas NESTE
    arquivo, nunca de criar arquivos no diretório de configuração.
    """
    if not valid_name(nome):
        raise CampaignError("nome de campanha inválido")
    if not isinstance(prefixos, list):
        raise CampaignError("prefixos deve ser uma lista")
    limpos: list[str] = []
    for p in prefixos:
        if not isinstance(p, str):
            raise CampaignError("prefixo inválido: precisa ser texto")
        if not _PREFIXO_RE.match(p):
            raise CampaignError(
                f"prefixo inválido: {p!r} — use apenas letras minúsculas, "
                f"números e hífen (até 20 caracteres)")
        if p not in limpos:
            limpos.append(p)
    if not limpos:
        limpos = [""]        # sem nenhum prefixo, ainda se testa a palavra pura
    cfg = ler_config()
    cfg[nome] = {**cfg.get(nome, {}), "prefixos": limpos}
    corpo = json.dumps(cfg, ensure_ascii=False, indent=2) + "\n"
    caminho = config_path()
    try:
        caminho.parent.mkdir(parents=True, exist_ok=True)
        with open(caminho, "w", encoding="utf-8", newline="") as fh:
            fh.write(corpo)
            fh.flush()
            os.fsync(fh.fileno())
    except OSError as exc:
        raise CampaignError(f"sem permissão para gravar a configuração: {exc}") from exc
    return limpos


def campanha_pedida() -> str:
    """Campanha escolhida para esta execução, via ARGUS_CAMPANHA. Vazio = todas.

    Existe porque o escopo cresce por multiplicação: cada domínio novo custa uma
    wordlist inteira de consultas. Poder rodar uma campanha por vez mantém cada
    execução dentro do tempo limite sem precisar reduzir a cobertura das outras.
    """
    return os.environ.get("ARGUS_CAMPANHA", "").strip()


def filtrar_campanhas(arquivos):
    """Filtra a lista de arquivos de campanha pela escolhida em ARGUS_CAMPANHA.

    Nome inválido nunca vira caminho: compara com o `stem` já existente, então
    não há como escapar do diretório de targets por aqui.
    """
    alvo = campanha_pedida()
    arquivos = list(arquivos)
    if not alvo:
        return arquivos
    escolhidos = [f for f in arquivos if f.stem == alvo]
    if not escolhidos:
        disponiveis = ", ".join(sorted(f.stem for f in arquivos)) or "(nenhuma)"
        raise FileNotFoundError(
            f"Campanha {alvo!r} não encontrada neste escopo. Disponíveis: {disponiveis}")
    print(f"  [CAMPANHA] execução restrita a {alvo}")
    return escolhidos


def valid_target(scope: str, value: str) -> bool:
    """Alvo válido para o escopo: IP/CIDR (monitor) ou hostname (submonitor)."""
    value = (value or "").strip()
    if not value or value[0] == "-" or any(c in _DANGEROUS for c in value):
        return False
    if SCOPES.get(scope, {}).get("kind") == "ip":
        try:
            ipaddress.ip_network(value, strict=False)   # IP ou CIDR (v4/v6)
            return True
        except ValueError:
            return False
    # Domínio: recusa IP puro (o regex de hostname casaria "1.2.3.4") — IP em campanha
    # de subdomínio é erro de escopo; o alvo certo é a campanha do monitor.
    try:
        ipaddress.ip_address(value)
        return False
    except ValueError:
        pass
    return bool(_HOSTNAME_RE.match(value))


def _split_entries(raw) -> list[str]:
    """Entradas cruas → itens limpos. O comentário é removido ANTES de separar por
    vírgula/espaço: senão uma vírgula dentro de um comentário viraria um "item"."""
    lines = raw.splitlines() if isinstance(raw, str) else [str(x) for x in (raw or [])]
    out: list[str] = []
    for raw_line in lines:
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        for part in line.replace(",", " ").replace(";", " ").split():
            part = part.strip()
            if part:
                out.append(part)
    return out


def parse_targets(scope: str, raw) -> tuple[list[str], list[str]]:
    """Normaliza a entrada do usuário (texto ou lista) → (válidos, inválidos).
    Deduplica preservando a ordem; ignora linhas vazias e comentários."""
    good: list[str] = []
    bad: list[str] = []
    seen: set[str] = set()
    for line in _split_entries(raw):
        key = line.lower()
        if key in seen:
            continue
        seen.add(key)
        (good if valid_target(scope, line) else bad).append(line)
    return good, bad


# ── caminhos ─────────────────────────────────────────────────────────────────

def _base() -> Path:
    """Diretório base do Argus (/etc/argus), igual ao usado pelo webapp."""
    db = os.environ.get("ARGUS_DB", "")
    if db:
        p = Path(db).resolve().parent
        return p.parent if p.name == "store" else p
    return Path(os.environ.get("ARGUS_BASE", "/etc/argus"))


def targets_dir(scope: str, base: str | None = None) -> Path:
    if scope not in SCOPES:
        raise CampaignError(f"escopo inválido: {scope}")
    return Path(base or _base()) / SCOPES[scope]["dir"] / "targets"


def _campaign_path(scope: str, name: str, base: str | None = None) -> Path:
    """Caminho do .txt da campanha — com checagem de contenção (anti-traversal)."""
    if not valid_name(name):
        raise CampaignError(
            "nome inválido: use apenas letras, números, ponto, hífen ou underscore (até 64)")
    d = targets_dir(scope, base)
    path = (d / f"{name}.txt")
    # Defesa em profundidade: o arquivo TEM de estar dentro do diretório de targets.
    try:
        d_res = d.resolve()
        p_res = path.resolve()
        if p_res.parent != d_res:
            raise CampaignError("caminho fora do diretório de targets")
    except CampaignError:
        raise
    except Exception:
        pass          # diretório ainda não existe: a criação valida de novo
    return path


# ── leitura ──────────────────────────────────────────────────────────────────

def _read_targets(path: Path) -> list[str]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return []
    out = []
    for raw in lines:
        line = raw.split("#", 1)[0].strip()
        if line:
            out.append(line)
    return out


def list_campaigns(scope: str, base: str | None = None) -> list[dict]:
    """Campanhas do escopo: nome, nº de alvos e os alvos. Nunca levanta por I/O."""
    d = targets_dir(scope, base)
    out: list[dict] = []
    try:
        files = sorted(d.glob("*.txt"))
    except Exception:
        return out
    for f in files:
        if not valid_name(f.stem):
            continue                      # ignora nomes fora da allowlist
        targets = _read_targets(f)
        try:
            mtime = int(f.stat().st_mtime)
        except Exception:
            mtime = 0
        out.append({"name": f.stem, "scope": scope, "count": len(targets),
                    "targets": targets, "updated": mtime})
    return out


def get_campaign(scope: str, name: str, base: str | None = None) -> dict:
    path = _campaign_path(scope, name, base)
    if not path.exists():
        raise CampaignError(f"campanha não encontrada: {name}")
    targets = _read_targets(path)
    return {"name": name, "scope": scope, "count": len(targets), "targets": targets}


# ── escrita ──────────────────────────────────────────────────────────────────

def _write_atomic(path: Path, content: str) -> None:
    """Grava de forma atômica: tmp no MESMO diretório + os.replace (rename atômico).
    Evita que um scanner leia um arquivo truncado durante a escrita."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.stem}.", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(content)
            fh.flush()
            os.fsync(fh.fileno())
        try:
            os.chmod(tmp, 0o644)          # legível pelos scanners (root) e pelo grupo
        except Exception:
            pass
        os.replace(tmp, path)
    except Exception:
        try: os.unlink(tmp)
        except Exception: pass
        raise


def _render(scope: str, name: str, targets: list[str]) -> str:
    kind = "IPs / CIDRs" if SCOPES[scope]["kind"] == "ip" else "domínios"
    head = (f"# Campanha: {name}\n"
            f"# Alvos ({kind}) — um por linha. '#' inicia comentário.\n"
            f"# Gerado pela interface web do Argus.\n")
    return head + "\n".join(targets) + ("\n" if targets else "")


def save_campaign(scope: str, name: str, targets, *, overwrite: bool,
                  base: str | None = None) -> dict:
    """Cria (overwrite=False) ou atualiza (True) a campanha. Recusa alvo inválido."""
    path = _campaign_path(scope, name, base)
    if path.exists() and not overwrite:
        raise CampaignError(f"campanha já existe: {name}")
    if not path.exists() and overwrite:
        raise CampaignError(f"campanha não encontrada: {name}")
    good, bad = parse_targets(scope, targets)
    if bad:
        kind = "IP/CIDR" if SCOPES[scope]["kind"] == "ip" else "domínio"
        raise CampaignError(f"{len(bad)} alvo(s) inválido(s) para {kind}: " + ", ".join(bad[:5]))
    if not good:
        raise CampaignError("informe ao menos um alvo válido")
    _write_atomic(path, _render(scope, name, good))
    return {"name": name, "scope": scope, "count": len(good), "targets": good}


def delete_campaign(scope: str, name: str, base: str | None = None) -> dict:
    """Remove APENAS o arquivo de alvos. Histórico/achados nos bancos são preservados."""
    path = _campaign_path(scope, name, base)
    if not path.exists():
        raise CampaignError(f"campanha não encontrada: {name}")
    os.unlink(path)
    return {"name": name, "scope": scope, "deleted": True}


# ── renomear (migra o histórico) ─────────────────────────────────────────────

def _dbs_for(scope: str, base: Path) -> list[tuple[Path, str]]:
    """Bancos onde o nome da campanha aparece: (caminho, tabela)."""
    out = [(base / "store" / "argus.db", "findings")]
    if scope == "monitor":
        out.append((base / "monitor" / "monitor.db", "scans"))
    else:
        out.append((base / "submonitor" / "submonitor.db", "subdomains"))
    return out


def _migrate_history(scope: str, old: str, new: str, base: Path) -> int:
    """Atualiza o campo `campanha` nos bancos. Nunca levanta — banco ausente/sem
    permissão apenas não migra (o rename do alvo já ocorreu)."""
    total = 0
    for db_path, table in _dbs_for(scope, base):
        if not db_path.exists():
            continue
        try:
            conn = sqlite3.connect(str(db_path), timeout=5)
            try:
                cur = conn.execute(
                    f"UPDATE {table} SET campanha=? WHERE campanha=?",   # nosec B608 - tabela de allowlist interna
                    (new, old))
                total += cur.rowcount or 0
                conn.commit()
            finally:
                conn.close()
        except Exception:
            continue
    return total


# ── wordlist de subdomínios (submonitor/subs.txt) ────────────────────────────
# Prefixo DNS: um rótulo ("api", "dev-app", "_domainkey") ou vários separados por
# ponto ("abt.cleverdata" → abt.cleverdata.empresa.com.br). Wordlists reais trazem
# muita entrada composta — recusá-las descartaria boa parte da lista.
_DNS_LABEL = r"(?!-)[A-Za-z0-9_-]{1,63}(?<!-)"
_LABEL_RE = re.compile(rf"^{_DNS_LABEL}(\.{_DNS_LABEL})*$")
_WORD_MAXLEN = 200          # o prefixo + o domínio precisam caber no limite DNS (253)
WORDLIST_MAX = 20000          # teto defensivo (a wordlist multiplica o custo do scan)


def wordlist_path(base: str | None = None) -> Path:
    return Path(base or _base()) / "submonitor" / "subs.txt"


def valid_word(value: str) -> bool:
    v = (value or "").strip()
    return len(v) <= _WORD_MAXLEN and bool(_LABEL_RE.match(v))


def parse_words(raw) -> tuple[list[str], list[str]]:
    """Normaliza a wordlist (texto ou lista) → (válidos, inválidos), deduplicado
    (case-insensitive) e preservando a ordem."""
    good: list[str] = []
    bad: list[str] = []
    seen: set[str] = set()
    for line in _split_entries(raw):
        key = line.lower()
        if key in seen:
            continue
        seen.add(key)
        (good if valid_word(line) else bad).append(line)
    return good, bad


def read_wordlist(base: str | None = None) -> dict:
    path = wordlist_path(base)
    words = []
    if path.exists():
        for raw in path.read_text(encoding="utf-8").splitlines():
            line = raw.split("#", 1)[0].strip()
            if line:
                words.append(line)
    return {"count": len(words), "words": words, "path": str(path), "exists": path.exists()}


def save_wordlist(raw, base: str | None = None) -> dict:
    """Grava a wordlist. NUNCA aceita lista vazia — sem prefixos o submonitor não
    descobre nada por força bruta (perda silenciosa de cobertura).

    Escrita IN-PLACE (trunca o arquivo existente) e não tmp+rename: mantém o mesmo
    inode, preservando a ACL do arquivo. Assim o app user precisa de escrita apenas
    NESTE arquivo — e não no diretório submonitor/ (que guarda o banco)."""
    words, bad = parse_words(raw)
    if bad:
        raise CampaignError(
            f"{len(bad)} item(ns) inválido(s) — use apenas o prefixo (ex.: 'api', 'dev-app'), "
            f"sem pontos nem domínio: " + ", ".join(bad[:5]))
    if not words:
        raise CampaignError("a wordlist não pode ficar vazia — informe ao menos um prefixo")
    if len(words) > WORDLIST_MAX:
        raise CampaignError(f"limite de {WORDLIST_MAX} prefixos excedido ({len(words)})")
    path = wordlist_path(base)
    path.parent.mkdir(parents=True, exist_ok=True)
    content = ("# Wordlist de subdomínios (prefixos) — um por linha, '#' inicia comentário.\n"
               "# Editada pela interface web do Argus.\n" + "\n".join(words) + "\n")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)
        fh.flush()
        os.fsync(fh.fileno())
    return {"count": len(words), "words": words}


def rename_campaign(scope: str, old: str, new: str, base: str | None = None) -> dict:
    """Renomeia a campanha e MIGRA o histórico (campo campanha nos bancos)."""
    src = _campaign_path(scope, old, base)
    dst = _campaign_path(scope, new, base)
    if not src.exists():
        raise CampaignError(f"campanha não encontrada: {old}")
    if old == new:
        return {"name": new, "scope": scope, "migrated": 0}
    if dst.exists():
        raise CampaignError(f"já existe uma campanha chamada {new}")
    os.replace(src, dst)
    migrated = _migrate_history(scope, old, new, Path(base or _base()))
    return {"name": new, "scope": scope, "renamed_from": old, "migrated": migrated}
