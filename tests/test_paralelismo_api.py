"""API do paralelismo TCP por campanha."""

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
        alvos = base / "monitor" / "targets"
        alvos.mkdir(parents=True, exist_ok=True)
        (alvos / "PRODATA.txt").write_text("10.0.0.1\n10.0.0.2\n", encoding="utf-8")
        import webapp
        self.app = webapp.create_app().test_client()
        self.H = {"X-Requested-With": "argus", "X-Remote-User": "monitor"}

    def tearDown(self):
        os.environ.pop("ARGUS_DB", None)
        self.tmp.cleanup()


class TestLeitura(Base):
    def test_get_traz_faixa_e_valor_atual(self):
        j = self.app.get("/api/campaigns?scope=monitor", headers=self.H).get_json()
        self.assertEqual(j["paralelismo_min"], 1)
        self.assertEqual(j["paralelismo_max"], 5)
        camp = j["campaigns"]["monitor"][0]
        self.assertEqual(camp["paralelismo_tcp"], 1)     # padrão: série


class TestGravacao(Base):
    def test_grava_e_devolve_na_leitura(self):
        r = self.app.post("/api/campaigns/monitor/PRODATA/paralelismo",
                          headers=self.H, json={"paralelismo": 3})
        self.assertEqual(r.status_code, 200)
        j = self.app.get("/api/campaigns?scope=monitor", headers=self.H).get_json()
        self.assertEqual(j["campaigns"]["monitor"][0]["paralelismo_tcp"], 3)

    def test_fora_da_faixa_recusado_com_400(self):
        r = self.app.post("/api/campaigns/monitor/PRODATA/paralelismo",
                          headers=self.H, json={"paralelismo": 20})
        self.assertEqual(r.status_code, 400)

    def test_sem_csrf_recusado(self):
        r = self.app.post("/api/campaigns/monitor/PRODATA/paralelismo",
                          headers={"X-Remote-User": "monitor"},
                          json={"paralelismo": 2})
        self.assertEqual(r.status_code, 403)

    def test_escopo_submonitor_recusado(self):
        # Paralelismo é da varredura de portas; em domínios não faz sentido.
        r = self.app.post("/api/campaigns/submonitor/PRODATA/paralelismo",
                          headers=self.H, json={"paralelismo": 2})
        self.assertEqual(r.status_code, 400)


if __name__ == "__main__":
    unittest.main()
