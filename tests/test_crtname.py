"""Testes do provider crt.name (descoberta passiva de subdomínios).

A resposta do crt.name é entrada NÃO confiável: texto puro de um servidor
externo. Os testes fixam que só hostname válido dentro do domínio base entra,
que wildcard/e-mail/lixo são descartados, e que a rede fora não quebra o scan.
"""

import sys
import unittest

sys.path.insert(0, "core")
from threatintel.providers import crtname  # noqa: E402


class FakeResp:
    """Dublê de requests.Response com iter_lines, como a API real devolve."""

    def __init__(self, linhas, status=200):
        self._linhas = linhas
        self.status_code = status

    def raise_for_status(self):
        if self.status_code >= 400:
            import requests
            raise requests.exceptions.HTTPError(f"HTTP {self.status_code}")

    def iter_lines(self, decode_unicode=False):
        yield from self._linhas

    def close(self):
        pass


def _sem_cache(monkey_linhas, status=200):
    """Injeta uma resposta e desliga o cache, devolvendo o set descoberto."""
    orig_get = crtname.requests.get
    orig_read = crtname._read_cache
    orig_write = crtname._write_cache
    crtname.requests.get = lambda *a, **k: FakeResp(monkey_linhas, status)
    crtname._read_cache = lambda d: None
    crtname._write_cache = lambda d, s: None
    try:
        return crtname.get_subdomains("empresa.com.br")
    finally:
        crtname.requests.get = orig_get
        crtname._read_cache = orig_read
        crtname._write_cache = orig_write


def _sem_cache_ex(monkey_linhas=None, status=200, get_fn=None):
    """Mesma injeção, mas devolvendo (subs, erro) via get_subdomains_ex."""
    orig_get = crtname.requests.get
    orig_read = crtname._read_cache
    orig_write = crtname._write_cache
    crtname.requests.get = get_fn or (lambda *a, **k: FakeResp(monkey_linhas, status))
    crtname._read_cache = lambda d: None
    crtname._write_cache = lambda d, s: None
    try:
        return crtname.get_subdomains_ex("empresa.com.br")
    finally:
        crtname.requests.get = orig_get
        crtname._read_cache = orig_read
        crtname._write_cache = orig_write


class TestParse(unittest.TestCase):
    def test_extrai_hostnames_do_dominio(self):
        subs = _sem_cache([
            "empresa.com.br",
            "api.empresa.com.br",
            "vpn.empresa.com.br",
        ])
        self.assertEqual(subs, {"empresa.com.br", "api.empresa.com.br",
                                "vpn.empresa.com.br"})

    def test_wildcard_vira_dominio_base(self):
        self.assertIn("empresa.com.br", _sem_cache(["*.empresa.com.br"]))

    def test_normaliza_caixa_e_ponto_final(self):
        self.assertEqual(_sem_cache(["API.Empresa.Com.Br."]),
                         {"api.empresa.com.br"})

    def test_descarta_host_de_terceiro(self):
        # Um cert pode listar SAN de outro domínio — não é superfície desta empresa.
        subs = _sem_cache(["api.empresa.com.br", "algo.outrodominio.com"])
        self.assertEqual(subs, {"api.empresa.com.br"})

    def test_descarta_email_e_lixo(self):
        subs = _sem_cache([
            "admin@empresa.com.br",           # SAN de e-mail
            "  ",                             # linha vazia
            "-invalido-.empresa.com.br",      # rótulo começando com hífen
            "ok.empresa.com.br",
        ])
        self.assertEqual(subs, {"ok.empresa.com.br"})

    def test_injecao_nao_passa(self):
        # Resposta hostil: nada disso é hostname válido do domínio.
        subs = _sem_cache([
            "a.empresa.com.br;rm -rf /",
            "http://empresa.com.br/x",
            "empresa.com.br/../../etc",
        ])
        self.assertEqual(subs, set())


class TestTeto(unittest.TestCase):
    def test_respeita_o_teto_de_linhas(self):
        orig = crtname.MAX_LINES
        crtname.MAX_LINES = 10
        try:
            linhas = [f"h{i}.empresa.com.br" for i in range(100)]
            subs = _sem_cache(linhas)
            self.assertEqual(len(subs), 10)
        finally:
            crtname.MAX_LINES = orig


class TestDegradacao(unittest.TestCase):
    def test_erro_http_devolve_vazio(self):
        self.assertEqual(_sem_cache(["api.empresa.com.br"], status=500), set())

    def test_erro_de_rede_nao_levanta(self):
        orig_get = crtname.requests.get
        orig_read = crtname._read_cache

        def explode(*a, **k):
            import requests
            raise requests.exceptions.ConnectionError("sem rede")

        crtname.requests.get = explode
        crtname._read_cache = lambda d: None
        try:
            self.assertEqual(crtname.get_subdomains_safe("empresa.com.br"), set())
        finally:
            crtname.requests.get = orig_get
            crtname._read_cache = orig_read

    def test_dominio_vazio_nao_consulta(self):
        self.assertEqual(crtname.get_subdomains(""), set())


class TestMotivoDaFalha(unittest.TestCase):
    """get_subdomains_ex/get_subdomains_safe_ex: a fonte precisa dizer POR QUÊ
    quando falha — indistinguibilidade entre '0 achados reais' e 'fonte fora
    do ar' foi exatamente o bug observado em produção com o crt.sh irmão
    deste provider (mesmo padrão de degradação, mesma correção)."""

    def test_sucesso_com_zero_nomes_nao_e_erro(self):
        subs, erro = _sem_cache_ex([])
        self.assertEqual(subs, set())
        self.assertIsNone(erro)

    def test_http_502_reporta_indisponibilidade_nao_zero_resultado(self):
        subs, erro = _sem_cache_ex(["qualquer.empresa.com.br"], status=502)
        self.assertEqual(subs, set())
        self.assertIsNotNone(erro)
        self.assertIn("502", erro)

    def test_timeout_e_distinto_de_erro_de_servidor(self):
        def explode(*a, **k):
            import requests
            raise requests.exceptions.Timeout("demorou demais")
        subs, erro = _sem_cache_ex(get_fn=explode)
        self.assertEqual(subs, set())
        self.assertEqual(erro, "timeout")
        self.assertNotIn("502", erro)

    def test_erro_de_rede_e_reportado(self):
        def explode(*a, **k):
            import requests
            raise requests.exceptions.ConnectionError("sem rede")
        subs, erro = _sem_cache_ex(get_fn=explode)
        self.assertEqual(subs, set())
        self.assertIsNotNone(erro)

    def test_cache_hit_e_sucesso_sem_erro(self):
        orig_read = crtname._read_cache
        crtname._read_cache = lambda d: {"cached.empresa.com.br"}
        try:
            subs, erro = crtname.get_subdomains_ex("empresa.com.br")
            self.assertEqual(subs, {"cached.empresa.com.br"})
            self.assertIsNone(erro)
        finally:
            crtname._read_cache = orig_read

    def test_get_subdomains_continua_so_com_set_apos_falha(self):
        # Compat: get_subdomains (assinatura antiga) não pode passar a devolver
        # tupla — scanners/submonitor.py e outros consumidores dependem do set puro.
        self.assertEqual(_sem_cache(["x"], status=500), set())

    def test_get_subdomains_safe_ex_nunca_levanta(self):
        def explode(*a, **k):
            raise RuntimeError("catástrofe inesperada")
        orig_get = crtname.requests.get
        orig_read = crtname._read_cache
        crtname.requests.get = explode
        crtname._read_cache = lambda d: None
        try:
            subs, erro = crtname.get_subdomains_safe_ex("empresa.com.br")
            self.assertEqual(subs, set())
            self.assertIsNotNone(erro)
        finally:
            crtname.requests.get = orig_get
            crtname._read_cache = orig_read


if __name__ == "__main__":
    unittest.main()
