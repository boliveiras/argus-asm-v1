"""Testes do painel de documentação e do enxugamento da interface."""

import re
import sys
import types
import unittest

sys.modules.setdefault("nmap", types.ModuleType("nmap"))
sys.path.insert(0, "core")
import reporter  # noqa: E402

import docs as DOCS  # noqa: E402

PAGINAS = {
    "dashboard": reporter.build_dashboard,
    "logpush": reporter.build_logpush_page,
    "campanhas": reporter.build_campaigns_page,
    "provedores": reporter.build_providers_page,
    "usuarios": reporter.build_users_page,
    "correlacao": reporter.build_correlation_page,
    "risk": reporter.build_risk_guide,
}


class TestConteudo(unittest.TestCase):
    def test_toda_secao_tem_id_titulo_e_corpo(self):
        for sid, titulo, html in DOCS.SECOES:
            self.assertTrue(sid and titulo and html.strip(), sid)
            self.assertRegex(sid, r"^[a-z]+$")

    def test_ids_sao_unicos(self):
        ids = [s[0] for s in DOCS.SECOES]
        self.assertEqual(len(ids), len(set(ids)))

    def test_toda_pagina_mapeia_para_uma_secao_existente(self):
        existentes = {s[0] for s in DOCS.SECOES}
        for pagina, secao in DOCS.PAGINA_PARA_SECAO.items():
            self.assertIn(secao, existentes, f"{pagina} aponta para seção inexistente")

    def test_pagina_desconhecida_cai_no_inicio(self):
        self.assertEqual(DOCS.secao_da_pagina("nao_existe"), "inicio")


class TestPainelNasPaginas(unittest.TestCase):
    def test_todas_as_paginas_tem_o_painel(self):
        for nome, fn in PAGINAS.items():
            self.assertIn('id="doc-painel"', fn(), nome)

    def test_todas_tem_o_botao_no_topo(self):
        for nome, fn in PAGINAS.items():
            self.assertIn("argusAbrirDocs()", fn(), nome)

    def test_painel_abre_na_secao_da_pagina(self):
        html = reporter.build_logpush_page()
        self.assertIn('window.__DOC_INICIAL="doc-logpush"', html)
        html = reporter.build_campaigns_page()
        self.assertIn('window.__DOC_INICIAL="doc-campanhas"', html)

    def test_fecha_com_esc(self):
        self.assertIn("e.key==='Escape'", reporter.build_dashboard())


class TestInterfaceEnxuta(unittest.TestCase):
    """A explicação longa vive no painel; a tela traz instrução objetiva."""

    LIMITE = 130

    def test_nenhum_texto_de_pagina_passa_do_limite(self):
        for nome, fn in PAGINAS.items():
            html = fn()
            for m in re.finditer(r'class="page-sub"[^>]*>(.{0,500}?)</(?:p|div)>', html, re.S):
                texto = re.sub(r"<[^>]+>", "", m.group(1)).strip()
                self.assertLessEqual(
                    len(texto), self.LIMITE,
                    f"{nome}: texto com {len(texto)} caracteres deveria estar na "
                    f"documentação — {texto[:70]!r}")

    def test_paginas_ligam_para_a_documentacao(self):
        for nome in ("logpush", "campanhas", "provedores", "usuarios"):
            self.assertIn("data-doc", PAGINAS[nome](), nome)


if __name__ == "__main__":
    unittest.main()
