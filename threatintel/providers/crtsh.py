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
crtsh.py — Provider de Certificate Transparency (crt.sh)
=========================================================

Consulta o crt.sh para descobrir subdomínios de um domínio através dos
certificados SSL/TLS já emitidos (Certificate Transparency logs).

Diferente da enumeração ativa por wordlist, esta é uma técnica PASSIVA:
revela subdomínios reais que já existiram, sem precisar adivinhar nomes.

Uso:
    from threatintel.providers.crtsh import get_subdomains
    subs = get_subdomains("empresa.com.br")
    # → {"api.empresa.com.br", "vpn.empresa.com.br", ...}

Características:
    - Sem chave de API (serviço público)
    - Cache local em JSON por domínio (evita reconsultas no mesmo dia)
    - Normaliza wildcards (*.x.com → x.com) e remove duplicatas
    - Tolerante a falhas: se o crt.sh estiver lento/fora, retorna vazio
      sem quebrar o scan (degradação graciosa)
    - get_subdomains()/get_subdomains_safe() mantêm o contrato antigo (só o
      set) por compatibilidade. Quem precisa saber SE a fonte falhou — e não
      confundir "0 resultados reais" com "consulta não respondeu" — usa
      get_subdomains_ex()/get_subdomains_safe_ex(), que devolvem (subs, motivo).
"""

import json
import time
from pathlib import Path

import requests

# ── Configuração ─────────────────────────────────────────────
CRTSH_URL          = "https://crt.sh/?q=%25.{domain}&output=json"
REQUEST_TIMEOUT    = 30          # crt.sh às vezes é lento
CACHE_TTL_SECONDS  = 6 * 3600    # 6 horas
CACHE_DIR_NAME     = "crtsh_cache"
USER_AGENT         = "argus-monitor/1.0 (+ct-discovery)"

# Diretório de cache: ao lado deste arquivo, em ../<CACHE_DIR_NAME>
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
    """Retorna subdomínios do cache se válido, senão None."""
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


def _normalize_name(name: str, base_domain: str) -> list[str]:
    """
    Normaliza um nome retornado pelo crt.sh.
    O campo name_value pode conter múltiplas linhas e wildcards.
    Retorna lista de hostnames limpos pertencentes ao domínio base.
    """
    out = []
    for raw in name.split("\n"):
        host = raw.strip().lower().rstrip(".")
        if not host:
            continue
        # Remove wildcard: *.empresa.com.br → empresa.com.br
        if host.startswith("*."):
            host = host[2:]
        # Ignora e-mails (alguns certs trazem SAN de e-mail)
        if "@" in host:
            continue
        # Só aceita hostnames realmente dentro do domínio base
        if host == base_domain or host.endswith("." + base_domain):
            out.append(host)
    return out


def _fetch_remote(domain: str) -> tuple[set[str], str | None]:
    """Consulta o crt.sh de fato e devolve (subdomínios, motivo do erro).

    motivo é None em sucesso — mesmo com conjunto vazio, pois o domínio pode
    realmente não ter certificado nenhum listado. Quando motivo não é None,
    a consulta FALHOU e o conjunto vazio não significa "nada encontrado";
    quem chama não pode tratar os dois casos como equivalentes (foi
    exatamente essa confusão que escondeu o crt.sh fora do ar em produção,
    virando um "0 crt.sh" indistinguível de "domínio sem certificado").
    """
    url = CRTSH_URL.format(domain=domain)
    subs: set[str] = set()
    try:
        resp = requests.get(url, headers={"User-Agent": USER_AGENT},
                            timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        # crt.sh retorna um array JSON de objetos
        entries = json.loads(resp.text)
        for entry in entries:
            name_value = entry.get("name_value", "")
            common_name = entry.get("common_name", "")
            for src in (name_value, common_name):
                if src:
                    subs.update(_normalize_name(src, domain))
        return subs, None
    except requests.exceptions.Timeout:
        return set(), "timeout"
    except requests.exceptions.HTTPError as e:
        status = getattr(e.response, "status_code", None)
        return set(), f"HTTP {status}" if status else f"erro HTTP ({e})"
    except requests.exceptions.RequestException as e:
        return set(), f"erro de rede ({type(e).__name__})"
    except (json.JSONDecodeError, ValueError, AttributeError, TypeError):
        # Corpo que não é o JSON esperado (ex.: página de erro em HTML) ou
        # estrutura inesperada dentro do array — resposta ilegível, não "vazia".
        return set(), "resposta ilegível"
    except Exception as e:
        return set(), f"erro inesperado ({type(e).__name__})"


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

    # 1. Tenta cache — um cache válido é sucesso (a consulta original já
    # confirmou a fonte disponível).
    if use_cache:
        cached = _read_cache(domain)
        if cached is not None:
            return cached, None

    # 2. Consulta crt.sh
    subs, erro = _fetch_remote(domain)

    # 3. Grava cache só em sucesso com achados
    if erro is None and subs:
        _write_cache(domain, subs)
    return subs, erro


def get_subdomains(domain: str, use_cache: bool = True) -> set[str]:
    """
    Consulta o crt.sh e retorna o conjunto de subdomínios descobertos
    para o domínio informado (incluindo o próprio domínio se aparecer).

    Em caso de erro de rede/timeout, retorna conjunto vazio (não levanta).
    Fachada de compatibilidade: mantém a assinatura antiga para quem só
    precisa do conjunto — o motivo do erro (quando houver) fica em
    get_subdomains_ex().
    """
    subs, _erro = get_subdomains_ex(domain, use_cache=use_cache)
    return subs


def get_subdomains_safe(domain: str) -> set[str]:
    """Wrapper que nunca levanta exceção. Uso conveniente no orquestrador."""
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
