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
users.py — Contas de acesso e perfis (RBAC) da interface Web
=============================================================

Perfis:
  • admin  — o usuário criado na INSTALAÇÃO (padrão `monitor`). Faz tudo, inclusive
             gerenciar contas. Não é editável nem removível pela Web (evita que um
             comprometimento da interface derrube o acesso administrativo).
  • master — leitura + edição (campanhas, wordlist, execução sob demanda, triagem).
  • user   — SOMENTE LEITURA (nenhuma ação de escrita).

Onde ficam os dados:
  • Credencial → arquivo htpasswd do Apache (mesma base que autentica o login).
    A senha é gravada apenas como hash **bcrypt** — nunca em texto claro, nunca logada.
  • Perfil     → `store/users.json` ({"nome": {"role": "...", ...}}). Fica separado do
    htpasswd porque o formato do Apache não tem campo de papel.

Postura de segurança:
  • Nome de usuário em ALLOWLIST estrita: `:` ou quebra de linha corromperiam o
    htpasswd (uma linha = um usuário) e permitiriam forjar entradas.
  • Hash bcrypt (custo padrão da lib). O Apache valida bcrypt desde a versão 2.4.4.
  • O htpasswd é gravado IN-PLACE: o serviço tem permissão apenas NESTE arquivo, e
    nunca de criar/trocar arquivos em /etc/apache2 (onde vive a config do servidor).
  • A senha atual é exigida para o usuário trocar a própria senha.
  • Senha INICIAL é gerada pelo sistema (`secrets`, o CSPRNG do SO) e mostrada
    uma única vez — ninguém precisa inventar nem transmitir senha. Ela nasce com
    a marca `must_change_password`, e enquanto a marca existir a conta não faz
    nada além de trocar a senha (o guard da API barra o resto). É isso que torna
    a senha gerada aceitável: vazando antes da troca, não abre acesso a dado algum.
"""

from __future__ import annotations

import json
import os
import re
import secrets
from pathlib import Path

try:                                  # dependência opcional: erro claro se faltar
    import bcrypt
    _BCRYPT_OK = True
except ImportError:
    _BCRYPT_OK = False

ROLE_ADMIN = "admin"
ROLE_MASTER = "master"
ROLE_USER = "user"
ROLES = (ROLE_MASTER, ROLE_USER)          # papéis atribuíveis pela Web
ROLE_LABEL = {ROLE_ADMIN: "Administrador", ROLE_MASTER: "Master (leitura e edição)",
              ROLE_USER: "User (somente leitura)"}

# Nome de usuário: letras, números, ponto, hífen, underscore (1–32).
_NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,32}$")
MIN_PASSWORD = 8
MAX_PASSWORD = 72                          # bcrypt ignora bytes além de 72

# Chave que marca a conta como "ainda usa a senha inicial gerada pelo sistema".
MUST_CHANGE_KEY = "must_change_password"

# Alfabeto da senha gerada: sem 0/O e 1/l/I. A senha é LIDA DA TELA (saída do
# instalador ou o campo mostrado uma vez na Web) e digitada de novo — um par
# ambíguo vira suporte, não segurança.
PASSWORD_ALPHABET = ("ABCDEFGHJKLMNPQRSTUVWXYZ"
                     "abcdefghijkmnopqrstuvwxyz"
                     "23456789")
# 20 caracteres nesse alfabeto (57 símbolos) ≈ 116 bits de entropia: forte o
# bastante para não precisar de política de expiração, curto o bastante para
# alguém copiar da tela sem errar.
PASSWORD_LENGTH = 20


class UserError(ValueError):
    """Erro de uso (nome/senha inválidos, usuário inexistente, permissão)."""


# ── caminhos ─────────────────────────────────────────────────────────────────

def _base() -> Path:
    db = os.environ.get("ARGUS_DB", "")
    if db:
        p = Path(db).resolve().parent
        return p.parent if p.name == "store" else p
    return Path(os.environ.get("ARGUS_BASE", "/etc/argus"))


def htpasswd_path() -> Path:
    return Path(os.environ.get("ARGUS_HTPASSWD", "/etc/apache2/.htpasswd-monitor"))


def roles_path() -> Path:
    return _base() / "store" / "users.json"


def admin_user() -> str:
    """Usuário full-admin definido na instalação (não editável pela Web)."""
    return os.environ.get("ARGUS_ADMIN_USER", "monitor")


# ── validação ────────────────────────────────────────────────────────────────

def valid_name(name: str) -> bool:
    return bool(_NAME_RE.match((name or "").strip()))


def _check_password(password: str) -> str:
    pw = password or ""
    if len(pw) < MIN_PASSWORD:
        raise UserError(f"a senha precisa ter ao menos {MIN_PASSWORD} caracteres")
    if len(pw.encode("utf-8")) > MAX_PASSWORD:
        raise UserError(f"senha muito longa (máximo {MAX_PASSWORD} bytes)")
    return pw


def generate_password(length: int = PASSWORD_LENGTH) -> str:
    """Senha inicial aleatória.

    `secrets` usa o CSPRNG do sistema operacional. `random` NÃO serve aqui: é um
    Mersenne Twister semeado por relógio — quem observa algumas saídas prevê as
    próximas, e isso é uma credencial.
    """
    return "".join(secrets.choice(PASSWORD_ALPHABET) for _ in range(max(1, length)))


def _hash(password: str) -> str:
    if not _BCRYPT_OK:
        raise UserError("biblioteca bcrypt ausente no servidor — instale com: "
                        "apt install python3-bcrypt")
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("ascii")


def _verify(password: str, hashed: str) -> bool:
    if not _BCRYPT_OK or not hashed:
        return False
    if not hashed.startswith(("$2a$", "$2b$", "$2y$")):
        # Hash em formato antigo (ex.: md5-apr1 do htpasswd): não dá para conferir aqui.
        raise UserError("a senha atual não pôde ser verificada (formato antigo) — "
                        "peça ao administrador para redefini-la")
    try:
        return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False


# ── htpasswd ─────────────────────────────────────────────────────────────────

def _read_htpasswd() -> dict:
    """{usuário: hash} — ignora linhas vazias/comentadas e malformadas."""
    out: dict[str, str] = {}
    path = htpasswd_path()
    if not path.exists():
        return out
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        name, _, hashed = line.partition(":")
        if name:
            out[name] = hashed
    return out


def _write_htpasswd(entries: dict) -> None:
    """Grava a base de credenciais IN-PLACE (mesmo inode).

    Não usa arquivo temporário + rename de propósito: criar o temporário exigiria
    escrita no DIRETÓRIO (/etc/apache2), que guarda toda a configuração do servidor.
    Gravando no próprio arquivo, basta a permissão nele — o serviço nunca recebe
    poder de criar ou trocar arquivos na config do Apache. Isso também preserva a
    ACL e o dono (root:www-data 640).

    O conteúdo vai em UMA escrita seguida de fsync e, se algo falhar no meio, o
    conteúdo anterior é restaurado — um htpasswd truncado deixaria todos sem acesso.
    """
    path = htpasswd_path()
    body = "".join(f"{n}:{h}\n" for n, h in sorted(entries.items()))
    try:
        previous = path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""
    except OSError:
        previous = ""
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(body)
            fh.flush()
            os.fsync(fh.fileno())
    except Exception:
        if previous:                       # tenta devolver o conteúdo original
            try:
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write(previous)
                    fh.flush()
                    os.fsync(fh.fileno())
            except OSError:
                pass
        raise


# ── perfis ───────────────────────────────────────────────────────────────────

def _read_roles() -> dict:
    p = roles_path()
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _write_roles(roles: dict) -> None:
    p = roles_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(roles, ensure_ascii=False, indent=1), encoding="utf-8")
    os.replace(tmp, p)


def role_of(name: str) -> str:
    """Perfil efetivo. O admin da instalação é sempre admin; quem não estiver
    mapeado entra como `user` (somente leitura) — padrão restritivo."""
    name = (name or "").strip()
    if name and name == admin_user():
        return ROLE_ADMIN
    entry = _read_roles().get(name) or {}
    role = str(entry.get("role", "")).lower()
    return role if role in ROLES else ROLE_USER


def must_change_password(name: str) -> bool:
    """A conta ainda está com a senha inicial gerada pelo sistema?

    Enquanto isto for verdade a conta não faz NADA além de trocar a senha — quem
    aplica a regra é o guard da API (webapp._authorize). Vale para qualquer perfil,
    inclusive o administrador da instalação.
    """
    name = (name or "").strip()
    if not name:
        return False
    return bool((_read_roles().get(name) or {}).get(MUST_CHANGE_KEY, False))


def mark_must_change(name: str) -> None:
    """Marca a conta como "precisa trocar a senha" (usado pelo instalador).

    Cria a entrada em users.json se ela não existir — o administrador da instalação
    não tem perfil gravado (o papel dele é derivado do nome), mas a marca precisa
    de um lugar para morar.
    """
    name = (name or "").strip()
    if not name:
        raise UserError("nome vazio")
    roles = _read_roles()
    entry = roles.get(name) or {}
    entry[MUST_CHANGE_KEY] = True
    roles[name] = entry
    _write_roles(roles)


def _clear_must_change(name: str) -> None:
    """Tira a marca. Só grava se ela existia — evita reescrever users.json a cada
    troca de senha de quem já está em dia."""
    roles = _read_roles()
    entry = roles.get(name)
    if not entry or not entry.get(MUST_CHANGE_KEY):
        return
    entry.pop(MUST_CHANGE_KEY, None)
    roles[name] = entry
    _write_roles(roles)


def can_write(name: str) -> bool:
    return role_of(name) in (ROLE_ADMIN, ROLE_MASTER)


def is_admin(name: str) -> bool:
    return role_of(name) == ROLE_ADMIN


# ── operações ────────────────────────────────────────────────────────────────

def list_users() -> list[dict]:
    """Contas existentes com seu perfil (sem hash algum na saída)."""
    roles = _read_roles()
    adm = admin_user()
    out = []
    for name in sorted(_read_htpasswd()):
        role = ROLE_ADMIN if name == adm else (
            (roles.get(name) or {}).get("role", ROLE_USER))
        role = role if role in (ROLE_ADMIN, *ROLES) else ROLE_USER
        out.append({"name": name, "role": role, "role_label": ROLE_LABEL.get(role, role),
                    "is_admin": name == adm,
                    # Mostra ao administrador quem ainda não trocou a senha inicial
                    # (essa conta está travada até trocar).
                    "must_change_password": bool(
                        (roles.get(name) or {}).get(MUST_CHANGE_KEY, False)),
                    "created": (roles.get(name) or {}).get("created", "")})
    return out


def create_user(name: str, password: str, role: str, *, now: str = "",
                must_change: bool = False) -> dict:
    name = (name or "").strip()
    if not valid_name(name):
        raise UserError("nome inválido: use letras, números, ponto, hífen ou underscore (até 32)")
    if name == admin_user():
        raise UserError("esse nome é reservado ao administrador da instalação")
    if role not in ROLES:
        raise UserError(f"perfil inválido: use {ROLE_MASTER} ou {ROLE_USER}")
    _check_password(password)
    entries = _read_htpasswd()
    if name in entries:
        raise UserError(f"usuário já existe: {name}")
    entries[name] = _hash(password)
    _write_htpasswd(entries)
    roles = _read_roles()
    roles[name] = {"role": role, "created": now}
    if must_change:
        roles[name][MUST_CHANGE_KEY] = True
    _write_roles(roles)
    return {"name": name, "role": role, "role_label": ROLE_LABEL[role],
            "must_change_password": bool(must_change)}


def set_role(name: str, role: str) -> dict:
    name = (name or "").strip()
    if name == admin_user():
        raise UserError("o perfil do administrador da instalação não pode ser alterado")
    if role not in ROLES:
        raise UserError(f"perfil inválido: use {ROLE_MASTER} ou {ROLE_USER}")
    if name not in _read_htpasswd():
        raise UserError(f"usuário não encontrado: {name}")
    roles = _read_roles()
    entry = roles.get(name) or {}
    entry["role"] = role
    roles[name] = entry
    _write_roles(roles)
    return {"name": name, "role": role, "role_label": ROLE_LABEL[role]}


def set_password(name: str, password: str) -> dict:
    """Redefinição pelo administrador (não exige a senha atual)."""
    name = (name or "").strip()
    _check_password(password)
    entries = _read_htpasswd()
    if name not in entries:
        raise UserError(f"usuário não encontrado: {name}")
    entries[name] = _hash(password)
    _write_htpasswd(entries)
    return {"name": name, "updated": True}


def change_own_password(name: str, current: str, new: str) -> dict:
    """Troca da própria senha — exige a senha atual (defesa contra sessão sequestrada)."""
    name = (name or "").strip()
    entries = _read_htpasswd()
    if name not in entries:
        raise UserError("usuário não encontrado")
    if not _verify(current or "", entries[name]):
        raise UserError("senha atual incorreta")
    _check_password(new)
    if new == current:
        raise UserError("a nova senha precisa ser diferente da atual")
    entries[name] = _hash(new)
    _write_htpasswd(entries)
    # A senha inicial deixou de valer: some com a marca e a conta é liberada.
    # A ordem importa — limpar a marca ANTES de gravar o hash liberaria a conta
    # sem que a nova senha tivesse entrado.
    _clear_must_change(name)
    return {"name": name, "updated": True}


def delete_user(name: str) -> dict:
    name = (name or "").strip()
    if name == admin_user():
        raise UserError("o administrador da instalação não pode ser removido")
    entries = _read_htpasswd()
    if name not in entries:
        raise UserError(f"usuário não encontrado: {name}")
    del entries[name]
    _write_htpasswd(entries)
    roles = _read_roles()
    if name in roles:
        del roles[name]
        _write_roles(roles)
    return {"name": name, "deleted": True}


# ── CLI do instalador ────────────────────────────────────────────────────────
# O install.sh é shell, mas a senha gerada e a marca de troca são regra de
# domínio: repeti-las em shell (`$RANDOM`, JSON no sed) daria duas verdades e
# uma delas seria fraca. Duas operações só, e nenhuma delas ESCREVE senha em
# lugar nenhum — quem grava a credencial segue sendo o `htpasswd`.
if __name__ == "__main__":
    import sys

    _uso = ("uso: users.py --gerar-senha | --marcar-troca NOME")
    _args = sys.argv[1:]
    if _args[:1] == ["--gerar-senha"] and len(_args) == 1:
        # Só para stdout, para o instalador capturar. Nunca vai para log.
        print(generate_password())
    elif _args[:1] == ["--marcar-troca"] and len(_args) == 2:
        mark_must_change(_args[1])
        print(f"[users] {_args[1]}: troca de senha obrigatória no 1º acesso")
    else:
        print(_uso, file=sys.stderr)
        sys.exit(2)
