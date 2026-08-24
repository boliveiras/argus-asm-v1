"""Testes do provider crt.sh (descoberta passiva de subdomínios via Certificate
Transparency).

Cobre o parsing normal e, principalmente, que uma falha da FONTE (HTTP 5xx,
timeout, resposta ilegível) é DISTINGUÍVEL de "consultei e não achei nada" —
ver get_subdomains_ex()/get_subdomains_safe_ex(). Bug em produção: crt.sh
devolvendo HTTP 502 virava silenciosamente "0 crt.sh" no log, indistinguível
de um domínio sem certificado nenhum.
"""

import json
import sys
import unittest

sys.path.insert(0, "core")
import requests  # noqa: E402

from threatintel.providers import crtsh  # noqa: E402


class FakeResp:
    """Dublê de requests.Response, como a API real (JSON) devolve."""

    def __init__(self, body, status=200):
        self.text = body
        self.status_code = status

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.exceptions.HTTPError(f"HTTP {self.status_code}", response=self)


def _entries(*names):
    return json.dumps([{"name_value": n, "common_name": ""} for n in names])


def _sem_cache(body, status=200):
    """Injeta uma resposta, desliga o cache e devolve só o set (compat antiga)."""
    orig_get = crtsh.requests.get
    orig_read = crtsh._read_cache
    orig_write = crtsh._write_cache
    crtsh.requests.get = lambda *a, **k: FakeResp(body, status)
    crtsh._read_cache = lambda d: None
    crtsh._write_cache = lambda d, s: None
    try:
        return crtsh.get_subdomains("empresa.com.br")
    finally:
        crtsh.requests.get = orig_get
        crtsh._read_cache = orig_read
        crtsh._write_cache = orig_write


def _sem_cache_ex(body=None, status=200, get_fn=None):
    """Mesma injeção, mas devolvendo (subs, erro) via get_subdomains_ex."""
    orig_get = crtsh.requests.get
    orig_read = crtsh._read_cache
    orig_write = crtsh._write_cache
    crtsh.requests.get = get_fn or (lambda *a, **k: FakeResp(body, status))
    crtsh._read_cache = lambda d: None
    crtsh._write_cache = lambda d, s: None
    try:
        return crtsh.get_subdomains_ex("empresa.com.br")
    finally:
        crtsh.requests.get = orig_get
        crtsh._read_cache = orig_read
        crtsh._write_cache = orig_write


class TestParse(unittest.TestCase):
    def test_extrai_hostnames_do_dominio(self):
        subs = _sem_cache(_entries("api.empresa.com.br", "vpn.empresa.com.br"))
        self.assertEqual(subs, {"api.empresa.com.br", "vpn.empresa.com.br"})

    def test_wildcard_vira_dominio_base(self):
        self.assertIn("empresa.com.br", _sem_cache(_entries("*.empresa.com.br")))

    def test_descarta_email_e_terceiro(self):
        subs = _sem_cache(_entries("admin@empresa.com.br", "algo.outrodominio.com",
                                   "ok.empresa.com.br"))
        self.assertEqual(subs, {"ok.empresa.com.br"})


class TestDegradacaoCompat(unittest.TestCase):
    """get_subdomains (assinatura antiga) precisa continuar devolvendo set() em
    qualquer falha — é o contrato que scanners/submonitor.py e outros
    consumidores já usam; não pode quebrar."""

    def test_erro_http_devolve_vazio(self):
        self.assertEqual(_sem_cache("", status=502), set())

    def test_json_invalido_devolve_vazio(self):
        self.assertEqual(_sem_cache("<html>não é json</html>"), set())

    def test_erro_de_rede_nao_levanta(self):
        def explode(*a, **k):
            raise requests.exceptions.ConnectionError("sem rede")
        orig_get = crtsh.requests.get
        orig_read = crtsh._read_cache
        crtsh.requests.get = explode
        crtsh._read_cache = lambda d: None
        try:
            self.assertEqual(crtsh.get_subdomains_safe("empresa.com.br"), set())
        finally:
            crtsh.requests.get = orig_get
            crtsh._read_cache = orig_read

    def test_dominio_vazio_nao_consulta(self):
        self.assertEqual(crtsh.get_subdomains(""), set())


class TestMotivoDaFalha(unittest.TestCase):
    """get_subdomains_ex/get_subdomains_safe_ex: a fonte precisa dizer POR QUÊ
    quando falha, para não ser lida como '0 subdomínios reais'."""

    def test_sucesso_com_zero_nomes_nao_e_erro(self):
        subs, erro = _sem_cache_ex(body="[]", status=200)
        self.assertEqual(subs, set())
        self.assertIsNone(erro)

    def test_http_502_reporta_indisponibilidade_nao_zero_resultado(self):
        subs, erro = _sem_cache_ex(body="", status=502)
        self.assertEqual(subs, set())
        self.assertIsNotNone(erro)
        self.assertIn("502", erro)

    def test_timeout_e_distinto_de_erro_de_servidor(self):
        def explode(*a, **k):
            raise requests.exceptions.Timeout("demorou demais")
        subs, erro = _sem_cache_ex(get_fn=explode)
        self.assertEqual(subs, set())
        self.assertEqual(erro, "timeout")
        self.assertNotIn("502", erro)

    def test_erro_de_rede_e_reportado(self):
        def explode(*a, **k):
            raise requests.exceptions.ConnectionError("sem rede")
        subs, erro = _sem_cache_ex(get_fn=explode)
        self.assertEqual(subs, set())
        self.assertIsNotNone(erro)

    def test_resposta_ilegivel_e_reportada(self):
        subs, erro = _sem_cache_ex(body="isso não é json", status=200)
        self.assertEqual(subs, set())
        self.assertIn("ilegível", erro)

    def test_cache_hit_e_sucesso_sem_erro(self):
        orig_read = crtsh._read_cache
        crtsh._read_cache = lambda d: {"cached.empresa.com.br"}
        try:
            subs, erro = crtsh.get_subdomains_ex("empresa.com.br")
            self.assertEqual(subs, {"cached.empresa.com.br"})
            self.assertIsNone(erro)
        finally:
            crtsh._read_cache = orig_read

    def test_get_subdomains_safe_ex_nunca_levanta(self):
        def explode(*a, **k):
            raise RuntimeError("catástrofe inesperada")
        orig_get = crtsh.requests.get
        orig_read = crtsh._read_cache
        crtsh.requests.get = explode
        crtsh._read_cache = lambda d: None
        try:
            subs, erro = crtsh.get_subdomains_safe_ex("empresa.com.br")
            self.assertEqual(subs, set())
            self.assertIsNotNone(erro)
        finally:
            crtsh.requests.get = orig_get
            crtsh._read_cache = orig_read


if __name__ == "__main__":
    unittest.main()
