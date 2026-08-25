"""O aviso de escopo no topo dos relatórios de submonitor/credentials/email/
typosquat.

Ele existe porque o runner roda campanha por campanha (ARGUS_CAMPANHA). Antes,
esses relatórios eram montados do resultado EM MEMÓRIA e cada campanha
sobrescrevia o arquivo da anterior — o aviso dizia "as demais campanhas não
estão neste relatório". Depois que os quatro passaram a montar do BANCO
(load_report_rows), todas as campanhas voltaram a aparecer e essa frase virou
mentira; o aviso passou a declarar o que continua verdade: só UMA campanha foi
revarrida nesta execução, as outras estão na tela com o dado da varredura
anterior delas.

Cobre também o aviso de cobertura parcial (crt.sh/crt.name fora do ar).
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
        self.assertNotIn("revarreu apenas a campanha", html)

    def test_submonitor_com_restricao_mostra_aviso(self):
        os.environ["ARGUS_CAMPANHA"] = "RIOCARD"
        out = self._out("s.html")
        REP.generate_submonitor_report([], [], [], output_path=out)
        html = Path(out).read_text(encoding="utf-8")
        self.assertIn("revarreu apenas a campanha", html)
        self.assertIn("RIOCARD", html)

    def test_credentials_com_restricao_mostra_aviso(self):
        os.environ["ARGUS_CAMPANHA"] = "RIOCARD"
        out = self._out("c.html")
        REP.generate_credentials_report([], [], [], output_path=out)
        html = Path(out).read_text(encoding="utf-8")
        self.assertIn("revarreu apenas a campanha", html)
        self.assertIn("RIOCARD", html)

    def test_credentials_sem_restricao_nao_mostra_aviso(self):
        out = self._out("c.html")
        REP.generate_credentials_report([], [], [], output_path=out)
        html = Path(out).read_text(encoding="utf-8")
        self.assertNotIn("revarreu apenas a campanha", html)

    def test_email_com_restricao_mostra_aviso(self):
        os.environ["ARGUS_CAMPANHA"] = "RIOCARD"
        out = self._out("e.html")
        REP.generate_email_report([], [], [], output_path=out)
        html = Path(out).read_text(encoding="utf-8")
        self.assertIn("revarreu apenas a campanha", html)
        self.assertIn("RIOCARD", html)

    def test_email_sem_restricao_nao_mostra_aviso(self):
        out = self._out("e.html")
        REP.generate_email_report([], [], [], output_path=out)
        html = Path(out).read_text(encoding="utf-8")
        self.assertNotIn("revarreu apenas a campanha", html)

    def test_typosquat_com_restricao_mostra_aviso(self):
        os.environ["ARGUS_CAMPANHA"] = "RIOCARD"
        out = self._out("t.html")
        REP.generate_typosquat_report([], [], [], output_path=out)
        html = Path(out).read_text(encoding="utf-8")
        self.assertIn("revarreu apenas a campanha", html)
        self.assertIn("RIOCARD", html)

    def test_typosquat_sem_restricao_nao_mostra_aviso(self):
        out = self._out("t.html")
        REP.generate_typosquat_report([], [], [], output_path=out)
        html = Path(out).read_text(encoding="utf-8")
        self.assertNotIn("revarreu apenas a campanha", html)

    def test_nome_da_campanha_e_escapado_no_html(self):
        # Defesa em profundidade: o nome vem de env var (confiável, definida pelo
        # runner), mas o aviso escapa mesmo assim — sem depender de quem seta a env.
        os.environ["ARGUS_CAMPANHA"] = "<script>alert(1)</script>"
        out = self._out("s.html")
        REP.generate_submonitor_report([], [], [], output_path=out)
        html = Path(out).read_text(encoding="utf-8")
        self.assertNotIn("<script>alert(1)</script>", html)


class TestAvisoDeCoberturaParcial(Base):
    """Quando crt.sh/crt.name falham durante o scan, o relatório precisa dizer
    isso — sem o aviso, quem olha a tela vê menos subdomínios que o normal e
    conclui (errado) que a superfície diminuiu, em vez de "a fonte caiu"."""

    def test_sem_falha_nao_mostra_aviso_de_cobertura(self):
        out = self._out("s.html")
        REP.generate_submonitor_report([], [], [], output_path=out)
        html = Path(out).read_text(encoding="utf-8")
        self.assertNotIn("Cobertura parcial", html)

    def test_com_falha_mostra_aviso_de_cobertura_e_a_fonte(self):
        out = self._out("s.html")
        falhas = [{"fonte": "CRT.SH", "domain": "empresa.com.br", "motivo": "HTTP 502"}]
        REP.generate_submonitor_report([], [], [], output_path=out,
                                       partial_failures=falhas)
        html = Path(out).read_text(encoding="utf-8")
        self.assertIn("Cobertura parcial", html)
        self.assertIn("CRT.SH", html)
        self.assertIn("empresa.com.br", html)
        self.assertIn("HTTP 502", html)

    def test_falha_vazia_e_equivalente_a_sem_falha(self):
        out = self._out("s.html")
        REP.generate_submonitor_report([], [], [], output_path=out, partial_failures=[])
        html = Path(out).read_text(encoding="utf-8")
        self.assertNotIn("Cobertura parcial", html)

    def test_dominio_e_motivo_sao_escapados_no_html(self):
        out = self._out("s.html")
        falhas = [{"fonte": "CRT.SH", "domain": "<script>alert(1)</script>", "motivo": "x"}]
        REP.generate_submonitor_report([], [], [], output_path=out,
                                       partial_failures=falhas)
        html = Path(out).read_text(encoding="utf-8")
        self.assertNotIn("<script>alert(1)</script>", html)


if __name__ == "__main__":
    unittest.main()
