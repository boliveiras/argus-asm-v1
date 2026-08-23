"""Os relatórios de submonitor/credentials/email/typosquat são montados a
partir do resultado EM MEMÓRIA da execução corrente — com o runner rodando
campanha por campanha, cada campanha sobrescreve o mesmo arquivo HTML no
docroot, e só sobra no disco o da ÚLTIMA campanha. Até esses 4 relatórios
passarem a montar do banco (como o monitor já faz), a correção mínima é
DECLARAR o escopo: um aviso visível no topo quando ARGUS_CAMPANHA restringe a
execução a uma única campanha.
"""

import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, "core")
import reporter as REP  # noqa: E402


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        os.environ.pop("ARGUS_CAMPANHA", None)

    def tearDown(self):
        os.environ.pop("ARGUS_CAMPANHA", None)
        self.tmp.cleanup()

    def _out(self, nome):
        return str(Path(self.tmp.name) / nome)


class TestAvisoDeEscopo(Base):
    def test_submonitor_sem_restricao_nao_mostra_aviso(self):
        out = self._out("s.html")
        REP.generate_submonitor_report([], [], [], output_path=out)
        html = Path(out).read_text(encoding="utf-8")
        self.assertNotIn("As demais campanhas não estão neste relatório", html)

    def test_submonitor_com_restricao_mostra_aviso(self):
        os.environ["ARGUS_CAMPANHA"] = "RIOCARD"
        out = self._out("s.html")
        REP.generate_submonitor_report([], [], [], output_path=out)
        html = Path(out).read_text(encoding="utf-8")
        self.assertIn("As demais campanhas não estão neste relatório", html)
        self.assertIn("RIOCARD", html)

    def test_credentials_com_restricao_mostra_aviso(self):
        os.environ["ARGUS_CAMPANHA"] = "RIOCARD"
        out = self._out("c.html")
        REP.generate_credentials_report([], [], [], output_path=out)
        html = Path(out).read_text(encoding="utf-8")
        self.assertIn("As demais campanhas não estão neste relatório", html)
        self.assertIn("RIOCARD", html)

    def test_credentials_sem_restricao_nao_mostra_aviso(self):
        out = self._out("c.html")
        REP.generate_credentials_report([], [], [], output_path=out)
        html = Path(out).read_text(encoding="utf-8")
        self.assertNotIn("As demais campanhas não estão neste relatório", html)

    def test_email_com_restricao_mostra_aviso(self):
        os.environ["ARGUS_CAMPANHA"] = "RIOCARD"
        out = self._out("e.html")
        REP.generate_email_report([], [], [], output_path=out)
        html = Path(out).read_text(encoding="utf-8")
        self.assertIn("As demais campanhas não estão neste relatório", html)
        self.assertIn("RIOCARD", html)

    def test_email_sem_restricao_nao_mostra_aviso(self):
        out = self._out("e.html")
        REP.generate_email_report([], [], [], output_path=out)
        html = Path(out).read_text(encoding="utf-8")
        self.assertNotIn("As demais campanhas não estão neste relatório", html)

    def test_typosquat_com_restricao_mostra_aviso(self):
        os.environ["ARGUS_CAMPANHA"] = "RIOCARD"
        out = self._out("t.html")
        REP.generate_typosquat_report([], [], [], output_path=out)
        html = Path(out).read_text(encoding="utf-8")
        self.assertIn("As demais campanhas não estão neste relatório", html)
        self.assertIn("RIOCARD", html)

    def test_typosquat_sem_restricao_nao_mostra_aviso(self):
        out = self._out("t.html")
        REP.generate_typosquat_report([], [], [], output_path=out)
        html = Path(out).read_text(encoding="utf-8")
        self.assertNotIn("As demais campanhas não estão neste relatório", html)

    def test_nome_da_campanha_e_escapado_no_html(self):
        # Defesa em profundidade: o nome vem de env var (confiável, definida pelo
        # runner), mas o aviso escapa mesmo assim — sem depender de quem seta a env.
        os.environ["ARGUS_CAMPANHA"] = "<script>alert(1)</script>"
        out = self._out("s.html")
        REP.generate_submonitor_report([], [], [], output_path=out)
        html = Path(out).read_text(encoding="utf-8")
        self.assertNotIn("<script>alert(1)</script>", html)


if __name__ == "__main__":
    unittest.main()
