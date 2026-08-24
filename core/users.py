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
  • Liberação  → `store/argus.groups`, um *group file* do Apache com UMA linha
    (`liberados: nome1 nome2`) contendo só quem NÃO está marcado. É o que permite
    ao Apache negar os relatórios estáticos a quem ainda usa a senha inicial —
    ver "Contenção dos relatórios" abaixo.

Postura de segurança:
  • Nome de usuário em ALLOWLIST estrita: `:` ou quebra de linha corromperiam o
    htpasswd (uma linha = um usuário) e permitiriam forjar entradas.
  • Hash bcrypt (custo padrão da lib). O Apache valida bcrypt desde a versão 2.4.4.
    Hash md5-apr1 (`$apr1$`, o padrão histórico do `htpasswd`) é ACEITO na
    verificação e NUNCA gravado: instalações antigas migram sozinhas para bcrypt
    na primeira troca de senha. Recusá-lo trancava o portal de quem já tinha apr1.
  • O htpasswd é gravado IN-PLACE: o serviço tem permissão apenas NESTE arquivo, e
    nunca de criar/trocar arquivos em /etc/apache2 (onde vive a config do servidor).
  • A senha atual é exigida para o usuário trocar a própria senha.
  • Senha INICIAL é gerada pelo sistema (`secrets`, o CSPRNG do SO) e mostrada
    uma única vez — ninguém precisa inventar nem transmitir senha. Ela nasce com
    a marca `must_change_password`, e enquanto a marca existir a conta não faz
    nada além de trocar a senha.
  • users.json ilegível/corrompido é ANOMALIA, não ausência: `_read_roles` levanta
    `RolesUnavailable` e o guard traduz em 403 + evento de auditoria. Engolir o
    erro devolveria `{}` — e como o papel de `monitor` vem do NOME, a conta virava
    admin PLENO e sem marca, exatamente o que a marca existe para impedir.

Contenção dos relatórios (o que a marca REALMENTE garante):
  As páginas de relatório são HTML ESTÁTICO servido pelo Apache, com o dado
  embutido — o Flask nem as vê. Guard de API e desvio por JavaScript não seguram
  quem baixa a página com `curl`. Quem segura é o Apache: o `<Directory>` do
  docroot exige `Require group liberados`, e este módulo mantém o group file.
  Toda operação que muda o conjunto de marcados regenera o arquivo.
"""

from __future__ import annotations

import hashlib
import hmac
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

# Grupo do Apache com as contas LIBERADAS (as que já trocaram a senha inicial).
# O `<Directory>` do docroot exige `Require group liberados` — é o que impede que
# uma sessão travada baixe um relatório estático com curl.
GROUP_NAME = "liberados"

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


class RolesUnavailable(RuntimeError):
    """users.json EXISTE mas não pôde ser lido/interpretado.

    Não é o mesmo que "não existe": ausência é legítima (instalação sem conta Web
    ainda) e libera; anomalia é suspeita e NEGA. Quem chama traduz isto em 403 e
    registra na auditoria — devolver {} aqui derrubaria a marca de todo mundo.
    """


class PasswordChangedIncomplete(UserError):
    """A senha NOVA já está valendo, mas a liberação da conta não foi concluída.

    Acontece se a gravação de users.json falhar DEPOIS que o hash novo entrou no
    htpasswd. Sem uma exceção própria, o usuário recebia um erro genérico, tentava
    de novo com a senha ANTIGA e ouvia "senha atual incorreta" — sem jeito de
    descobrir que a senha já havia mudado.
    """


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


def groups_path() -> Path:
    """Group file do Apache com as contas liberadas. Fica ao lado do users.json
    (mesma verdade, mesmo dono) — o Apache só precisa LER."""
    env = os.environ.get("ARGUS_GROUPFILE", "")
    return Path(env) if env else _base() / "store" / "argus.groups"


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


# ── md5-apr1: o hash LEGADO do htpasswd ──────────────────────────────────────
# O `htpasswd` do Apache 2.4 grava `$apr1$` por padrão (só com -B sai bcrypt), e
# instalações reais do Argus estão assim. Verificar apr1 é o que permite a essas
# contas MIGRAREM sozinhas: o usuário entra com a senha antiga e a nova é gravada
# em bcrypt. Sem isto, atualizar tranca o portal — o reset do administrador está
# atrás do próprio bloqueio que a senha antiga não consegue vencer.
#
# Por que implementar em vez de usar biblioteca: `passlib` NÃO é dependência do
# projeto (ver requirements.txt) e o algoritmo cabe em 30 linhas de stdlib — a
# escada de construção do projeto manda parar antes de acrescentar dependência.
# Delegar ao binário `htpasswd -v` foi descartado: passar a senha para um processo
# externo a expõe no `ps`/argv e ainda amarra a verificação a um binário opcional.
_ITOA64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def _md5(data: bytes = b""):
    # usedforsecurity=False: o MD5 aqui NÃO é escolha de projeto — é o formato que
    # o Apache já gravou em disco, e só é lido para deixar a conta migrar para
    # bcrypt. Marcar assim mantém a leitura possível mesmo em modo FIPS.
    return hashlib.md5(data, usedforsecurity=False)


def _apr1(password: bytes, salt: bytes) -> str:
    """Parte do hash depois do último `$`, no formato md5-apr1 do Apache."""
    inicial = _md5(password + salt + password).digest()
    ctx = _md5(password + b"$apr1$" + salt)
    restante = len(password)
    while restante > 0:
        ctx.update(inicial[:min(restante, 16)])
        restante -= 16
    # O "algo realmente estranho" do algoritmo original: percorre os bits do
    # tamanho da senha misturando ora um NUL, ora o primeiro byte dela.
    bits = len(password)
    while bits:
        ctx.update(b"\0" if bits & 1 else password[:1])
        bits >>= 1
    digest = ctx.digest()
    # 1000 rodadas — o alongamento de chave que dá algum custo ao ataque offline.
    for i in range(1000):
        rodada = _md5(password if i & 1 else digest)
        if i % 3: rodada.update(salt)
        if i % 7: rodada.update(password)
        rodada.update(digest if i & 1 else password)
        digest = rodada.digest()
    saida = []
    for a, b, c in ((0, 6, 12), (1, 7, 13), (2, 8, 14), (3, 9, 15), (4, 10, 5)):
        valor = (digest[a] << 16) | (digest[b] << 8) | digest[c]
        for _ in range(4):
            saida.append(_ITOA64[valor & 0x3F]); valor >>= 6
    valor = digest[11]
    for _ in range(2):
        saida.append(_ITOA64[valor & 0x3F]); valor >>= 6
    return "".join(saida)


def _verify_apr1(password: str, hashed: str) -> bool:
    partes = hashed.split("$")           # ['', 'apr1', salt, hash]
    if len(partes) != 4 or not partes[2] or not partes[3]:
        return False                     # linha truncada/corrompida: não autentica
    esperado = _apr1(password.encode("utf-8"), partes[2].encode("utf-8"))
    return hmac.compare_digest(esperado, partes[3])


def _verify(password: str, hashed: str) -> bool:
    """Confere a senha contra o hash GRAVADO — bcrypt (o que escrevemos) ou
    md5-apr1 (o que o htpasswd escreveu antes). Gravar segue sendo só bcrypt."""
    if not hashed:
        return False
    if hashed.startswith("$apr1$"):
        return _verify_apr1(password, hashed)
    if not _BCRYPT_OK:
        return False
    if not hashed.startswith(("$2a$", "$2b$", "$2y$")):
        # Formato que não sabemos conferir (crypt DES, `{SHA}` do htpasswd -s…).
        # NEGA em vez de levantar: o instalador do Argus nunca gravou nada além de
        # apr1 e bcrypt, então isto só acontece com um htpasswd editado à mão. A
        # saída existe e está documentada: `users.py --limpar-marca` no console
        # destrava a conta e o administrador redefine a senha (que nasce bcrypt).
        return False
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
    """Perfis + marcas. AUSENTE é diferente de ILEGÍVEL — e essa diferença é a
    própria feature.

    • Arquivo ausente  → instalação que ainda não criou conta Web. Devolve {} e a
      vida segue: ninguém está marcado porque não há ninguém.
    • Existe e não abre / JSON inválido → ANOMALIA. Levanta `RolesUnavailable`.
      Devolver {} aqui (o que este código fazia) apagava a marca de TODA conta, e
      como `role_of` deriva o papel de `monitor` do NOME, um users.json corrompido
      entregava admin PLENO e destravado — com a senha impressa pelo instalador.
      Falhar ABERTO no controle que existe justamente para conter essa senha é o
      pior default possível; daqui em diante a anomalia NEGA e vai para a auditoria.
    """
    p = roles_path()
    try:
        bruto = p.read_text(encoding="utf-8")
    except FileNotFoundError:
        return {}
    except OSError as exc:
        raise RolesUnavailable(f"não consegui ler {p}: {exc}") from exc
    if not bruto.strip():
        return {}                          # arquivo zerado: mesmo caso de ausente
    try:
        data = json.loads(bruto)
    except ValueError as exc:
        raise RolesUnavailable(f"{p} não é JSON válido: {exc}") from exc
    if not isinstance(data, dict):
        raise RolesUnavailable(f"{p} não contém um objeto JSON")
    return data


def _write_preservando(p: Path, body: str, *, modo_novo: int) -> None:
    """Grava atomicamente (tmp + os.replace) PRESERVANDO dono/grupo/modo.

    tmp+replace troca o inode: sem restaurar os metadados, o arquivo passa a nascer
    com o umask do serviço e some com o `chown root:argus` / `chmod 660` que o
    instalador aplicou — users.json ficaria legível por qualquer conta local.
    O `chown` de volta ao dono ORIGINAL só é possível para o root; rodando como a
    conta de serviço, o dono muda mas o GRUPO (que é quem dá o acesso) volta.
    """
    p.parent.mkdir(parents=True, exist_ok=True)
    try:
        anterior = p.stat()
    except OSError:
        anterior = None
    tmp = p.with_name(p.name + ".tmp")
    tmp.write_text(body, encoding="utf-8")
    try:
        os.chmod(tmp, (anterior.st_mode & 0o777) if anterior else modo_novo)
        if anterior is not None and hasattr(os, "chown"):
            try:
                os.chown(tmp, anterior.st_uid, anterior.st_gid)
            except (PermissionError, OSError):
                try:                       # ao menos o grupo, que é o que libera
                    os.chown(tmp, -1, anterior.st_gid)
                except OSError:
                    pass
    except OSError:
        pass                               # metadado é higiene; o dado tem de entrar
    os.replace(tmp, p)


def _write_roles(roles: dict) -> None:
    # 0640: perfil e marca não são segredo, mas dizem quem existe e quem está
    # travado — não precisa ser legível por qualquer conta da máquina.
    _write_preservando(roles_path(), json.dumps(roles, ensure_ascii=False, indent=1),
                       modo_novo=0o640)


# ── group file do Apache (contenção dos relatórios estáticos) ────────────────

def liberados() -> list[str]:
    """Contas que JÁ trocaram a senha inicial (as que entram no group file)."""
    roles = _read_roles()
    return sorted(n for n in _read_htpasswd()
                  if not (roles.get(n) or {}).get(MUST_CHANGE_KEY, False))


def sync_group_file() -> Path:
    """Regenera `argus.groups` a partir do estado atual. Chamado por TODA operação
    que muda o conjunto de marcados (marcar, limpar, criar, remover).

    Formato do Apache: uma linha `grupo: membro membro`. Sem membros, a linha sai
    vazia e o Apache nega a todo mundo — que é o lado certo para errar.

    Modo 0644 de propósito: o Apache roda como www-data, que NÃO está no grupo do
    serviço. Depender de dono/grupo ou de ACL aqui é frágil (uma reescrita e o
    www-data perde a leitura → relatório negado a todos). O arquivo só contém
    NOMES de usuário, nenhum hash e nenhum segredo — o htpasswd, esse sim, segue
    640. Se um dia isto precisar fechar, o caminho é `chown :www-data` + 0640
    aplicado pelo instalador, e este módulo passa a gravar in-place.
    """
    p = groups_path()
    membros = " ".join(liberados())
    linha = f"{GROUP_NAME}: {membros}\n" if membros else f"{GROUP_NAME}:\n"
    _write_preservando(p, linha, modo_novo=0o644)
    try:
        os.chmod(p, 0o644)                 # garante a leitura do Apache a cada escrita
    except OSError:
        pass
    return p


def role_of(name: str) -> str:
    """Perfil efetivo. O admin da instalação é sempre admin; quem não estiver
    mapeado entra como `user` (somente leitura) — padrão restritivo.

    Propaga `RolesUnavailable`: com o users.json corrompido não há como AFIRMAR
    papel algum, e afirmar "admin" pelo nome é justamente o furo. Quem chama
    (o guard da API) transforma isso em 403.
    """
    name = (name or "").strip()
    # O arquivo é lido ANTES do atalho do admin de propósito: se ele estiver
    # corrompido, nem o `monitor` pode ser declarado admin (era assim que a
    # anomalia entregava admin pleno).
    roles = _read_roles()
    if name and name == admin_user():
        return ROLE_ADMIN
    entry = roles.get(name) or {}
    role = str(entry.get("role", "")).lower()
    return role if role in ROLES else ROLE_USER


def must_change_password(name: str) -> bool:
    """A conta ainda está com a senha inicial gerada pelo sistema?

    Enquanto isto for verdade a conta não faz NADA além de trocar a senha: o guard
    da API (webapp._authorize) barra as rotas e o Apache barra os relatórios
    estáticos (group file). Vale para qualquer perfil, inclusive o administrador
    da instalação.

    Propaga `RolesUnavailable` — não dá para afirmar "não precisa trocar" com o
    arquivo que guarda a marca ilegível.
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
    sync_group_file()                      # sai do grupo: perde os relatórios já


def clear_must_change(name: str) -> None:
    """Tira a marca e devolve a conta ao grupo liberado.

    Só reescreve users.json se a marca existia — mas o group file é regenerado
    sempre, porque ele pode estar defasado (instalação antiga, arquivo apagado).
    """
    roles = _read_roles()
    entry = roles.get(name)
    if entry and entry.get(MUST_CHANGE_KEY):
        entry.pop(MUST_CHANGE_KEY, None)
        roles[name] = entry
        _write_roles(roles)
    sync_group_file()


_clear_must_change = clear_must_change     # nome antigo, mantido por compatibilidade


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
    sync_group_file()                      # entra no grupo só se NÃO estiver marcado
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


def set_password(name: str) -> dict:
    """Redefinição pelo administrador (não exige a senha atual).

    Mesmo modelo da criação de conta: quem GERA a senha é o servidor, ela aparece
    uma única vez na resposta e a conta volta a nascer TRAVADA. O administrador
    inventar e transmitir senha era o buraco que a criação já tinha fechado — e
    uma conta redefinida sem marca voltava destravada com uma senha que passou
    pelas mãos (e pelo canal) de outra pessoa.
    """
    name = (name or "").strip()
    entries = _read_htpasswd()
    if name not in entries:
        raise UserError(f"usuário não encontrado: {name}")
    senha = generate_password()
    entries[name] = _hash(senha)
    _write_htpasswd(entries)
    mark_must_change(name)                 # já regenera o group file
    return {"name": name, "updated": True, "password": senha,
            MUST_CHANGE_KEY: True}


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
    # A partir daqui a senha NOVA é a que vale — o hash antigo já foi substituído.
    entries[name] = _hash(new)
    _write_htpasswd(entries)
    # A senha inicial deixou de valer: some com a marca e a conta é liberada.
    # A ordem importa — limpar a marca ANTES de gravar o hash liberaria a conta
    # sem que a nova senha tivesse entrado.
    try:
        clear_must_change(name)
    except Exception as exc:
        # Falhou DEPOIS da senha já trocada. Um erro genérico aqui fazia o usuário
        # tentar de novo com a senha antiga e ouvir "senha atual incorreta", sem
        # nenhuma pista de que a senha já havia mudado. A mensagem precisa dizer
        # as duas coisas: qual senha vale agora, e que a conta segue travada.
        raise PasswordChangedIncomplete(
            "sua NOVA senha já está valendo (entre com ela a partir de agora), mas "
            "não consegui liberar a conta: o registro de perfis não pôde ser gravado "
            f"({exc}). A conta continua travada na troca de senha — peça ao "
            "administrador para rodar, no servidor: "
            f"sudo python3 /etc/argus/users.py --limpar-marca {name}") from exc
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
    sync_group_file()                      # sai do group file junto com a credencial
    return {"name": name, "deleted": True}


# ── CLI do instalador ────────────────────────────────────────────────────────
# O install.sh é shell, mas a senha gerada e a marca de troca são regra de
# domínio: repeti-las em shell (`$RANDOM`, JSON no sed) daria duas verdades e
# uma delas seria fraca. Duas operações só, e nenhuma delas ESCREVE senha em
# lugar nenhum — quem grava a credencial segue sendo o `htpasswd`.
if __name__ == "__main__":
    import sys

    _uso = ("uso: users.py --gerar-senha | --marcar-troca NOME | "
            "--limpar-marca NOME | --sincronizar-grupos")
    _args = sys.argv[1:]
    if _args[:1] == ["--gerar-senha"] and len(_args) == 1:
        # Só para stdout, para o instalador capturar. Nunca vai para log.
        print(generate_password())
    elif _args[:1] == ["--marcar-troca"] and len(_args) == 2:
        mark_must_change(_args[1])
        print(f"[users] {_args[1]}: troca de senha obrigatória no 1º acesso")
    elif _args[:1] == ["--limpar-marca"] and len(_args) == 2:
        # RECUPERAÇÃO por console/SSH. O bloqueio da senha inicial roda em toda
        # requisição e tem UMA saída (o endpoint de troca): se ela falhar — hash
        # em formato que não sabemos conferir, senha perdida, users.json editado
        # à mão — não existiria caminho de volta sem esta linha.
        _alvo = _args[1].strip()
        if _alvo not in _read_htpasswd():
            print(f"[users] usuário não encontrado: {_alvo}", file=sys.stderr)
            sys.exit(1)
        clear_must_change(_alvo)
        print(f"[users] {_alvo}: marca removida — a conta está liberada. "
              "Troque a senha assim que entrar.")
    elif _args[:1] == ["--sincronizar-grupos"] and len(_args) == 1:
        # Idempotente: o instalador chama em toda execução para que uma instalação
        # ANTIGA (sem group file) ganhe o arquivo sem precisar marcar ninguém.
        print(f"[users] group file atualizado: {sync_group_file()}")
    else:
        print(_uso, file=sys.stderr)
        sys.exit(2)
