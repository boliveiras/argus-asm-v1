"""A página de campanhas precisa expor prefixos, recomendação e estimativa."""

import sys
import types
import unittest

sys.modules.setdefault("nmap", types.ModuleType("nmap"))
sys.path.insert(0, "core")
import reporter  # noqa: E402


class TestPagina(unittest.TestCase):
    def setUp(self):
        self.html = reporter.build_campaigns_page()

    def test_tem_bloco_de_prefixos(self):
        self.assertIn("cp-prefixos", self.html)

    def test_tem_estimativa_de_candidatos(self):
        self.assertIn("cp-estimativa", self.html)

    def test_recomenda_um_dominio_por_campanha(self):
        self.assertIn("um domínio por campanha", self.html)


class TestProgresso(unittest.TestCase):
    def test_painel_mostra_campanha_atual(self):
        # O progresso passa a ter duas dimensões: campanha X de Y, etapa N de 6.
        self.assertIn("campanhas_total", reporter._SCAN_SCRIPT)
        self.assertIn("Campanha ", reporter._SCAN_SCRIPT)


if __name__ == "__main__":
    unittest.main()
