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
logpush_config — catálogo e configuração do envio de logs para fora.

Espelha a postura de `providers.py`: o segredo mora no arquivo de config (fora do
repositório), a interface só recebe um resumo mascarado, e a gravação é in-place
para o serviço precisar de permissão apenas NO ARQUIVO, nunca no diretório.
"""

from __future__ import annotations

import ipaddress
import json
import os
import socket
from pathlib import Path
from urllib.parse import urlparse

PLACEHOLDER = "SUA_CHAVE_AQUI"

# Origens de log que podem ser enviadas. `caminho` é relativo a /var/log/argus.
# `estruturado` diz se o conteúdo é RFC 5424 (uma linha = uma mensagem) ou texto
# cru de execução (o arquivo inteiro é uma mensagem).
ORIGENS: list[dict] = [
    {"id": "monitor",     "label": "Portas",            "caminho": "monitor/monitor.log", "estruturado": True},
    {"id": "submonitor",  "label": "Subdomínios",       "caminho": "submonitor/*.log",    "estruturado": True},
    {"id": "credentials", "label": "Credenciais",       "caminho": "credentials/*.log",   "estruturado": True},
    {"id": "email",       "label": "Postura de e-mail", "caminho": "email/*.log",         "estruturado": True},
    {"id": "typosquat",   "label": "Typosquat",         "caminho": "typosquat/*.log",     "estruturado": True},
    {"id": "audit",       "label": "Auditoria",         "caminho": "audit/audit.log",     "estruturado": True},
    {"id": "scan",        "label": "Saída de execução", "caminho": "scan/*.log",          "estruturado": False},
]
POR_ID = {o["id"]: o for o in ORIGENS}

# Destinos e seus campos. `segredo` marca o que nunca volta inteiro pela API.
DESTINOS: list[dict] = [
    {"id": "s3", "label": "Bucket S3 (ou compatível)",
     "campos": [
         {"nome": "s3_bucket",     "label": "Bucket",     "segredo": False},
         {"nome": "s3_prefixo",    "label": "Prefixo",    "segredo": False, "padrao": "logs/argus"},
         {"nome": "s3_regiao",     "label": "Região",     "segredo": False, "padrao": "us-east-1"},
         {"nome": "s3_endpoint",   "label": "Endpoint (MinIO/R2, opcional)", "segredo": False},
         {"nome": "s3_access_key", "label": "Access key", "segredo": True},
         {"nome": "s3_secret_key", "label": "Secret key", "segredo": True},
     ]},
    {"id": "webhook", "label": "Webhook (chat)",
     "campos": [
         {"nome": "webhook_url",        "label": "URL do webhook", "segredo": True},
         {"nome": "webhook_plataforma", "label": "Plataforma",     "segredo": False, "padrao": "google_chat"},
         # so_plataforma: campo que só faz sentido para uma plataforma. A interface
         # esconde nas demais — pedir "Chat ID (Telegram)" a quem escolheu Google
         # Chat só gera dúvida sobre o que preencher.
         {"nome": "webhook_chat_id",    "label": "Chat ID",        "segredo": False,
          "so_plataforma": "telegram",
          "ajuda": "Identificador do chat ou grupo no Telegram (ex.: -1001234567890)"},
     ]},
]
DEST_POR_ID = {d["id"]: d for d in DESTINOS}

PLATAFORMAS = ["google_chat", "slack", "discord", "teams", "telegram", "generico"]
SEVERIDADES = ["CRITICO", "ALTO", "MEDIO", "BAIXO", "INFO"]
SEV_PADRAO = ["CRITICO", "ALTO"]


def base_dir() -> Path:
    return Path(os.environ.get("ARGUS_BASE", "/etc/argus"))


def config_path() -> Path:
    return Path(os.environ.get("ARGUS_LOGPUSH_CONFIG", str(base_dir() / "logpush.json")))


def ler() -> dict:
    try:
        dados = json.loads(config_path().read_text(encoding="utf-8"))
        return dados if isinstance(dados, dict) else {}
    except Exception:
        return {}


def gravar(cfg: dict) -> None:
    """Grava IN-PLACE: o serviço precisa de permissão só no arquivo, nunca no
    diretório. Restaura o conteúdo anterior se a escrita falhar no meio."""
    caminho = config_path()
    corpo = json.dumps(cfg, ensure_ascii=False, indent=4) + "\n"
    try:
        anterior = caminho.read_text(encoding="utf-8") if caminho.exists() else ""
    except OSError:
        anterior = ""
    try:
        caminho.parent.mkdir(parents=True, exist_ok=True)
        with open(caminho, "w", encoding="utf-8", newline="") as fh:
            fh.write(corpo)
            fh.flush()
            os.fsync(fh.fileno())
    except Exception:
        if anterior:
            try:
                with open(caminho, "w", encoding="utf-8", newline="") as fh:
                    fh.write(anterior)
                    fh.flush()
                    os.fsync(fh.fileno())
            except OSError:
                pass
        raise


def mascarar(valor: str) -> str:
    """Resumo seguro — nunca devolve o valor real."""
    v = str(valor or "").strip()
    if not v or v == PLACEHOLDER:
        return ""
    return "••••" + v[-4:] if len(v) > 4 else "••••"


def checar_url(url: str) -> tuple[bool, str]:
    """(segura, motivo) — separa configuração errada de falha momentânea.

    Motivos: "" (segura), "config" (não é https, ou aponta para rede interna) e
    "dns" (não deu para resolver AGORA). A distinção importa: um DNS que falhou
    por um instante estava sendo relatado como "URL inválida", o que manda o
    operador conferir uma configuração que está certa. Nos dois casos o envio
    não acontece — na dúvida sobre para onde o nome resolve, não se envia.
    """
    try:
        p = urlparse(str(url or "").strip())
    except Exception:
        return False, "config"
    if p.scheme != "https" or not p.hostname:
        return False, "config"
    try:
        infos = socket.getaddrinfo(p.hostname, None)
    except Exception:
        return False, "dns"
    for info in infos:
        try:
            ip = ipaddress.ip_address(info[4][0])
        except ValueError:
            return False, "config"
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            return False, "config"
    return True, ""


def url_segura(url: str) -> bool:
    """Só HTTPS para host público.

    Recusa IP privado, loopback, link-local e nomes que resolvem para eles: sem
    isso o Argus viraria um pivô para varrer a rede interna de quem o hospeda
    (SSRF) — justamente o que a ferramenta existe para denunciar.
    """
    return checar_url(url)[0]


def owner_ref(cfg: dict) -> str:
    """Identidade do destino S3 para a prova de posse: endpoint + bucket.

    Inclui o endpoint porque em MinIO/R2 o nome do bucket só é único DENTRO de
    um endpoint — provar posse de `logs` num servidor não vale para `logs` de
    outro. Trocar bucket ou endpoint invalida a prova automaticamente.
    """
    endpoint = str(cfg.get("s3_endpoint") or "").strip()
    bucket = str(cfg.get("s3_bucket") or "").strip()
    return f"{endpoint}|{bucket}"


def dono_verificado(cfg: dict) -> bool:
    """True só se a posse foi provada PARA O bucket/endpoint atuais."""
    marca = str(cfg.get("s3_owner_verified") or "")
    return bool(marca) and marca == owner_ref(cfg)


def origens_ligadas(cfg: dict) -> list[str]:
    return [o["id"] for o in ORIGENS if bool(cfg.get(f"origem_{o['id']}", False))]


def severidades_ligadas(cfg: dict) -> list[str]:
    marcadas = [s for s in SEVERIDADES if bool(cfg.get(f"sev_{s}", False))]
    return marcadas or SEV_PADRAO
