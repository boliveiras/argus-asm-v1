"""API de prefixos por campanha e dados da estimativa de custo."""

import os
import sys
import tempfile
import types
import unittest
from pathlib import Path

sys.modules.setdefault("nmap", types.ModuleType("nmap"))
sys.path.insert(0, "core")


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        os.environ["ARGUS_BASE"] = self.tmp.name
        os.environ["ARGUS_DB"] = os.path.join(self.tmp.name, "store", "argus.db")
        base = Path(self.tmp.name)
        (base / "store").mkdir(parents=True, exist_ok=True)
        alvos = base / "submonitor" / "targets"
        alvos.mkdir(parents=True, exist_ok=True)
        (alvos / "RIOCARD.txt").write_text("empresa.com\n", encoding="utf-8")
        (base / "submonitor" / "subs.txt").write_text(
            "www\napi\nmail\n", encoding="utf-8")
        import webapp
        self.app = webapp.create_app().test_client()
        self.H = {"X-Requested-With": "argus", "X-Remote-User": "monitor"}

    def tearDown(self):
        # ARGUS_DB tem prioridade sobre ARGUS_BASE em campaigns._base();
        # deixar a variável vazando quebra o isolamento dos testes seguintes.
        os.environ.pop("ARGUS_DB", None)
        self.tmp.cleanup()


class TestLeitura(Base):
    def test_get_traz_prefixos_padrao_e_tamanho_da_wordlist(self):
        j = self.app.get("/api/campaigns?scope=submonitor", headers=self.H).get_json()
        self.assertIn("", j["prefixos_padrao"])
        self.assertEqual(j["wordlist_size"], 3)

    def test_campanha_sem_config_traz_o_padrao(self):
        j = self.app.get("/api/campaigns?scope=submonitor", headers=self.H).get_json()
        camp = j["campaigns"]["submonitor"][0]
        self.assertEqual(camp["prefixos"], j["prefixos_padrao"])


class TestGravacao(Base):
    def test_grava_prefixos_e_devolve_na_leitura(self):
        r = self.app.post("/api/campaigns/submonitor/RIOCARD/prefixos",
                          headers=self.H, json={"prefixos": ["", "dev-"]})
        self.assertEqual(r.status_code, 200)
        j = self.app.get("/api/campaigns?scope=submonitor", headers=self.H).get_json()
        self.assertEqual(j["campaigns"]["submonitor"][0]["prefixos"], ["", "dev-"])

    def test_prefixo_invalido_recusado_com_400(self):
        r = self.app.post("/api/campaigns/submonitor/RIOCARD/prefixos",
                          headers=self.H, json={"prefixos": ["dev/"]})
        self.assertEqual(r.status_code, 400)

    def test_sem_csrf_recusado(self):
        r = self.app.post("/api/campaigns/submonitor/RIOCARD/prefixos",
                          headers={"X-Remote-User": "monitor"},
                          json={"prefixos": [""]})
        self.assertEqual(r.status_code, 403)

    def test_escopo_invalido_recusado(self):
        r = self.app.post("/api/campaigns/inexistente/RIOCARD/prefixos",
                          headers=self.H, json={"prefixos": [""]})
        self.assertEqual(r.status_code, 400)

    def test_escopo_monitor_recusado(self):
        # Prefixo de wordlist só existe p/ domínio (submonitor); monitor guarda
        # IP/CIDR — aceitar aqui gravaria configuração que nunca seria lida.
        r = self.app.post("/api/campaigns/monitor/RIOCARD/prefixos",
                          headers=self.H, json={"prefixos": [""]})
        self.assertEqual(r.status_code, 400)


if __name__ == "__main__":
    unittest.main()


class TestWordlistGrande(unittest.TestCase):
    """O teto de corpo da API não pode contradizer o teto de prefixos do domínio.

    campaigns.WORDLIST_MAX aceita 20.000 prefixos, mas o MAX_CONTENT_LENGTH do
    Flask cortava em 64 KB — na prática ~6.000 palavras curtas, e bem menos com
    nomes reais. O usuário recebia um 413 cru, gerado antes de a requisição
    chegar ao endpoint, sem mensagem que explicasse o que fazer.
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        os.environ["ARGUS_BASE"] = self.tmp.name
        os.environ["ARGUS_DB"] = os.path.join(self.tmp.name, "store", "argus.db")
        os.makedirs(os.path.join(self.tmp.name, "store"), exist_ok=True)
        os.makedirs(os.path.join(self.tmp.name, "submonitor"), exist_ok=True)
        import webapp
        self.app = webapp.create_app().test_client()
        self.H = {"X-Requested-With": "argus", "X-Remote-User": "monitor"}

    def tearDown(self):
        os.environ.pop("ARGUS_DB", None)
        self.tmp.cleanup()

    def test_wordlist_realista_de_5000_prefixos_e_aceita(self):
        # Nomes com o comprimento que aparece de verdade (abtbackoffice, wsgatewaypagamento).
        palavras = "\n".join(f"wsgatewaypagamento-{i:05d}" for i in range(5000))
        r = self.app.post("/api/wordlist", headers=self.H, json={"words": palavras})
        self.assertEqual(r.status_code, 200, "wordlist realista foi recusada pelo teto de corpo")
        self.assertEqual(r.get_json()["count"], 5000)

    def test_corpo_absurdo_e_recusado_com_mensagem_util(self):
        # O teto continua existindo — o que muda é ele caber no domínio e explicar-se.
        r = self.app.post("/api/wordlist", headers=self.H,
                          json={"words": "\n".join("x" * 60 for _ in range(60000))})
        self.assertEqual(r.status_code, 413)
        erro = (r.get_json() or {}).get("error", "")
        self.assertTrue(erro, "413 sem corpo JSON: o usuário não descobre o motivo")
        self.assertIn("grande", erro.lower())
