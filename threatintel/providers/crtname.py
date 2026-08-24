# Argus — monitoramento de superfície de ataque
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
crtname.py — Provider de Certificate Transparency (crt.name)
=============================================================

Consulta o crt.name para descobrir subdomínios de um domínio a partir dos
certificados TLS já emitidos (mesma categoria do crt.sh, fonte independente —
uma cobre lacunas da outra).

Técnica PASSIVA: revela subdomínios reais que já existiram, sem adivinhar nomes.

Uso:
    from threatintel.providers.crtname import get_subdomains
    subs = get_subdomains("empresa.com.br")
    # → {"api.empresa.com.br", "vpn.empresa.com.br", ...}

Características:
    - Sem chave de API (serviço público)
    - Resposta é TEXTO PURO: um hostname por linha (não JSON, diferente do crt.sh)
    - Cache local em JSON por domínio (evita reconsultas no mesmo dia)
    - Teto de linhas: a resposta é entrada NÃO confiável; um servidor hostil
      poderia devolver corpo gigante e estourar a memória
    - Filtra ao domínio base e valida cada hostname (anti-injeção)
    - Tolerante a falhas: se o crt.name estiver lento/fora, retorna vazio sem
      quebrar o scan (degradação graciosa)
    - get_subdomains()/get_subdomains_safe() mantêm o contrato antigo (só o
      set) por compatibilidade. Quem precisa saber SE a fonte falhou — e não
      confundir "0 resultados reais" com "consulta não respondeu" — usa
      get_subdomains_ex()/get_subdomains_safe_ex(), que devolvem (subs, motivo).
"""

import json
import re
import time
from pathlib import Path

import requests

# ── Configuração ─────────────────────────────────────────────
CRTNAME_URL        = "https://crt.name/v1/search?apex={domain}"
REQUEST_TIMEOUT    = 30
CACHE_TTL_SECONDS  = 6 * 3600    # 6 horas
CACHE_DIR_NAME     = "crtname_cache"
USER_AGENT         = "argus-monitor/1.0 (+ct-discovery)"
# Teto de linhas lidas da resposta. Domínio real não passa de alguns milhares;
# o limite existe para conter resposta anômala/hostil sem carregar tudo na RAM.
MAX_LINES          = 50_000

# Rótulo de hostname válido: sem isso, lixo do provedor (ou uma injeção via
# resposta) entraria como "subdomínio" e seria resolvido/consultado adiante.
_HOST_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9_-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9_-]{1,63}(?<!-))*$")

_BASE_DIR  = Path(__file__).resolve().parent.parent
_CACHE_DIR = _BASE_DIR / CACHE_DIR_NAME


def _ensure_cache_dir() -> None:
    try:
        _CACHE_DIR.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass


def _cache_path(domain: str) -> Path:
    safe = domain.replace("/", "_").replace("\\", "_").replace("*", "_")
    return _CACHE_DIR / f"{safe}.json"


def _read_cache(domain: str) -> set[str] | None:
    path = _cache_path(domain)
    try:
        if not path.exists():
            return None
        age = time.time() - path.stat().st_mtime
        if age > CACHE_TTL_SECONDS:
            return None
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return set(data.get("subdomains", []))
    except Exception:
        return None


def _write_cache(domain: str, subs: set[str]) -> None:
    _ensure_cache_dir()
    path = _cache_path(domain)
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"domain": domain,
                       "fetched_at": int(time.time()),
                       "subdomains": sorted(subs)}, f, indent=2)
    except Exception:
        pass


def _normalize(raw: str, base_domain: str) -> str | None:
    """Um hostname da resposta → limpo e validado, ou None se não serve."""
    host = (raw or "").strip().lower().rstrip(".")
    if not host:
        return None
    if host.startswith("*."):           # wildcard: *.empresa.com.br → empresa.com.br
        host = host[2:]
    if "@" in host:                     # SAN de e-mail, não é host
        return None
    # Só dentro do domínio base — barra host de terceiro que apareça no cert.
    if host != base_domain and not host.endswith("." + base_domain):
        return None
    if not _HOST_RE.match(host):        # descarta lixo/injeção
        return None
    return host


def _fetch_remote(domain: str) -> tuple[set[str], str | None]:
    """Consulta o crt.name de fato e devolve (subdomínios, motivo do erro).

    motivo é None em sucesso — mesmo com conjunto vazio, pois o domínio pode
    realmente não ter certificado nenhum listado. Quando motivo não é None,
    a consulta FALHOU e o conjunto vazio não significa "nada encontrado" (a
    mesma confusão que escondia o crt.sh fora do ar em produção se aplica
    aqui — fonte independente, mesmo risco).
    """
    url = CRTNAME_URL.format(domain=domain)
    subs: set[str] = set()
    resp = None
    try:
        resp = requests.get(url, headers={"User-Agent": USER_AGENT},
                            timeout=REQUEST_TIMEOUT, stream=True)
        resp.raise_for_status()
        # iter_lines com teto: não materializa a resposta inteira na memória.
        for i, linha in enumerate(resp.iter_lines(decode_unicode=True)):
            if i >= MAX_LINES:
                break
            host = _normalize(linha, domain)
            if host:
                subs.add(host)
        return subs, None
    except requests.exceptions.Timeout:
        return set(), "timeout"
    except requests.exceptions.HTTPError as e:
        status = getattr(e.response, "status_code", None)
        return set(), f"HTTP {status}" if status else f"erro HTTP ({e})"
    except requests.exceptions.RequestException as e:
        return set(), f"erro de rede ({type(e).__name__})"
    except ValueError:
        # Corpo/encoding que não bate com o texto puro esperado — resposta
        # ilegível, não "vazia".
        return set(), "resposta ilegível"
    except Exception as e:
        return set(), f"erro inesperado ({type(e).__name__})"
    finally:
        try:
            if resp is not None:
                resp.close()
        except Exception:
            pass


def get_subdomains_ex(domain: str, use_cache: bool = True) -> tuple[set[str], str | None]:
    """Como get_subdomains(), mas devolve também o motivo quando a fonte falha.

    (subdomínios, None)  -> sucesso, mesmo que o conjunto venha vazio.
    (set(), motivo)      -> a fonte falhou (rede/timeout/HTTP/resposta
                             ilegível); NUNCA leia motivo != None como "0
                             subdomínios encontrados".
    """
    domain = domain.strip().lower().rstrip(".")
    if not domain:
        return set(), None

    if use_cache:
        cached = _read_cache(domain)
        if cached is not None:
            return cached, None

    subs, erro = _fetch_remote(domain)
    if erro is None and subs:
        _write_cache(domain, subs)
    return subs, erro


def get_subdomains(domain: str, use_cache: bool = True) -> set[str]:
    """Subdomínios de `domain` segundo o crt.name.

    Em erro de rede/timeout, retorna conjunto vazio (não levanta).
    Fachada de compatibilidade: mantém a assinatura antiga para quem só
    precisa do conjunto — o motivo do erro (quando houver) fica em
    get_subdomains_ex().
    """
    subs, _erro = get_subdomains_ex(domain, use_cache=use_cache)
    return subs


def get_subdomains_safe(domain: str) -> set[str]:
    """Wrapper que nunca levanta — uso conveniente no orquestrador."""
    try:
        return get_subdomains(domain)
    except Exception:
        return set()


def get_subdomains_safe_ex(domain: str) -> tuple[set[str], str | None]:
    """Como get_subdomains_safe(), mas preserva o motivo da falha para quem
    precisa logar/relatar cobertura parcial (ex.: scanners/submonitor.py)
    em vez de só engolir o erro."""
    try:
        return get_subdomains_ex(domain)
    except Exception as e:
        return set(), f"erro inesperado ({type(e).__name__})"
