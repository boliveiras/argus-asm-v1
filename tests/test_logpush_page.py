"""Testes da página de Logpush."""

import sys
import types
import unittest

sys.modules.setdefault("nmap", types.ModuleType("nmap"))
sys.path.insert(0, "core")
import reporter  # noqa: E402


class TestPagina(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.html = reporter.build_logpush_page()

    def test_titulo_segue_o_padrao(self):
        self.assertIn("<title>Logpush — Argus</title>", self.html)

    # Os checkboxes de origem e severidade são montados pelo JS a partir do
    # catálogo devolvido por /api/logpush — não existem no HTML estático. Aqui
    # verificamos o contêiner e o padrão de id; a marcação real é exercitada nos
    # testes da API, que é a fonte do catálogo.
    def contem(self, agulha, rotulo):
        """assertIn sem despejar a página inteira no relatório de falha."""
        self.assertTrue(agulha in self.html, f"não encontrei {rotulo}: {agulha!r}")

    def test_tem_container_de_origens(self):
        self.contem('id="lp-origens"', "contêiner de origens")
        self.contem('id="origem-', "id gerado por origem")

    def test_tem_container_de_severidades(self):
        self.contem('id="lp-sev"', "contêiner de severidades")
        self.contem('id="sev-', "id gerado por severidade")

    def test_severidade_padrao_e_critico_e_alto(self):
        self.contem("s==='CRITICO'||s==='ALTO'", "marcação padrão de severidade")

    def test_esconde_campo_de_outra_plataforma(self):
        # o Chat ID é do Telegram; aparecer no Google Chat só gera dúvida
        self.contem("data-so-plataforma", "atributo de campo por plataforma")
        self.contem("function aplicarPlataforma()", "função que aplica o filtro")

    def test_avisa_sobre_flood(self):
        self.assertIn("flood", self.html.lower())

    def test_tem_botao_testar_e_salvar(self):
        self.assertIn('id="lp-testar"', self.html)
        self.assertIn('id="lp-salvar"', self.html)

    def test_controles_marcados_para_rbac(self):
        # data-write="1" é o que o guard de RBAC usa para esconder de quem só lê
        self.assertIn('id="lp-ligado" data-write="1"', self.html)

    def test_nav_leva_para_logpush(self):
        self.assertIn("/logpush.html", reporter.build_dashboard())

    def test_grid_nao_estoura_em_tela_estreita(self):
        # min() evita coluna maior que a viewport (o erro que quebrou provedores)
        self.assertIn("minmax(min(190px,100%),1fr)", self.html)


if __name__ == "__main__":
    unittest.main()
