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
  • Escrita atômica do htpasswd: um arquivo truncado deixaria TODOS sem acesso.
  • A senha atual é exigida para o usuário trocar a própria senha.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
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
    """Grava de forma ATÔMICA — um htpasswd truncado tiraria o acesso de todos."""
    path = htpasswd_path()
    body = "".join(f"{n}:{h}\n" for n, h in sorted(entries.items()))
    fd, tmp = tempfile.mkstemp(prefix=".htpasswd.", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(body)
            fh.flush()
            os.fsync(fh.fileno())
        try:                                   # mantém o dono/modo originais (root:www-data 640)
            st = path.stat()
            os.chmod(tmp, st.st_mode & 0o7777)
            os.chown(tmp, st.st_uid, st.st_gid)
        except (OSError, AttributeError):
            os.chmod(tmp, 0o640)
        os.replace(tmp, path)
    except Exception:
        try: os.unlink(tmp)
        except OSError: pass
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
                    "created": (roles.get(name) or {}).get("created", "")})
    return out


def create_user(name: str, password: str, role: str, *, now: str = "") -> dict:
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
    _write_roles(roles)
    return {"name": name, "role": role, "role_label": ROLE_LABEL[role]}


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
