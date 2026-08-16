"""Testes da API de configuração do logpush."""

import os
import sys
import tempfile
import types
import unittest

sys.modules.setdefault("nmap", types.ModuleType("nmap"))
sys.path.insert(0, "core")


class TestAPI(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        os.environ["ARGUS_BASE"] = self.tmp.name
        os.environ["ARGUS_DB"] = os.path.join(self.tmp.name, "store", "argus.db")
        os.makedirs(os.path.join(self.tmp.name, "store"), exist_ok=True)
        import webapp
        self.app = webapp.create_app().test_client()
        self.H = {"X-Requested-With": "argus", "X-Remote-User": "monitor"}

    def tearDown(self):
        self.tmp.cleanup()

    def test_get_devolve_catalogo(self):
        j = self.app.get("/api/logpush", headers=self.H).get_json()
        self.assertEqual(len(j["origens"]), 7)
        self.assertEqual(len(j["destinos"]), 2)
        self.assertIn("google_chat", j["plataformas"])

    def test_post_grava_e_get_mascara_segredo(self):
        r = self.app.post("/api/logpush", headers=self.H, json={
            "destino": "s3", "s3_bucket": "meu-bucket",
            "s3_secret_key": "SEGREDOabcdefgh", "origem_monitor": True})
        self.assertEqual(r.status_code, 200)
        j = self.app.get("/api/logpush", headers=self.H).get_json()
        self.assertEqual(j["config"]["s3_bucket"], "meu-bucket")
        self.assertNotIn("SEGREDOabcdefgh", str(j))
        self.assertTrue(j["config"]["s3_secret_key"].startswith("••••"))
        self.assertTrue(j["config"]["origem_monitor"])

    def test_valor_mascarado_nao_sobrescreve_o_segredo(self):
        self.app.post("/api/logpush", headers=self.H,
                      json={"destino": "s3", "s3_secret_key": "SEGREDOabcdefgh"})
        # a interface devolve o mascarado; gravar isso destruiria a chave real
        self.app.post("/api/logpush", headers=self.H,
                      json={"destino": "s3", "s3_secret_key": "••••efgh"})
        import logpush_config as LPC
        self.assertEqual(LPC.ler()["s3_secret_key"], "SEGREDOabcdefgh")

    def test_post_sem_csrf_recusado(self):
        r = self.app.post("/api/logpush", json={"destino": "s3"},
                          headers={"X-Remote-User": "monitor"})
        self.assertEqual(r.status_code, 403)

    def test_url_insegura_recusada(self):
        r = self.app.post("/api/logpush", headers=self.H, json={
            "destino": "webhook", "webhook_url": "http://10.0.0.1/x"})
        self.assertEqual(r.status_code, 400)

    def test_teste_sem_destino_configurado_falha_limpo(self):
        r = self.app.post("/api/logpush/test", headers=self.H, json={})
        self.assertEqual(r.status_code, 400)
        self.assertIn("destino", (r.get_json() or {}).get("error", "").lower())


if __name__ == "__main__":
    unittest.main()
