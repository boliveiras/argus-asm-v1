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
        # ARGUS_DB tem prioridade sobre ARGUS_BASE em campaigns._base();
        # deixar a variavel vazando quebra o isolamento dos testes seguintes
        os.environ.pop("ARGUS_DB", None)
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


class TestPosseS3(unittest.TestCase):
    """Prova de posse do bucket: desafio, veredito e o token que não vaza."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        os.environ["ARGUS_BASE"] = self.tmp.name
        os.environ["ARGUS_DB"] = os.path.join(self.tmp.name, "store", "argus.db")
        os.makedirs(os.path.join(self.tmp.name, "store"), exist_ok=True)
        import webapp
        self.webapp = webapp
        self.app = webapp.create_app().test_client()
        self.H = {"X-Requested-With": "argus", "X-Remote-User": "monitor"}
        self.app.post("/api/logpush", headers=self.H,
                      json={"destino": "s3", "s3_bucket": "meu-bucket"})

    def tearDown(self):
        # ARGUS_DB tem prioridade sobre ARGUS_BASE em campaigns._base();
        # deixar a variavel vazando quebra o isolamento dos testes seguintes
        os.environ.pop("ARGUS_DB", None)
        self.tmp.cleanup()

    def _fake_s3(self):
        """Substitui o cliente boto3 por um dublê em memória."""
        from logpush_dest import s3 as S3

        objetos = {}

        class Fake:
            def put_object(self, Bucket, Key, Body, **kw):  # noqa: N803
                objetos[Key] = Body

        _orig = S3.S3Destination._obter_cliente
        S3.S3Destination._obter_cliente = lambda self: Fake()
        self.addCleanup(lambda: setattr(S3.S3Destination, "_obter_cliente", _orig))
        return objetos

    def test_desafio_grava_e_nao_devolve_o_token(self):
        objetos = self._fake_s3()
        r = self.app.post("/api/logpush/test", headers=self.H, json={})
        j = r.get_json()
        self.assertTrue(j["ok"])
        self.assertTrue(j["desafio"])
        # o token está no objeto do bucket, NUNCA na resposta HTTP
        chave = j["chave"]
        token = objetos[chave].decode()
        self.assertNotIn(token.strip().split()[-1], str(j))

    def test_get_nunca_expoe_o_token(self):
        self._fake_s3()
        self.app.post("/api/logpush/test", headers=self.H, json={})
        j = self.app.get("/api/logpush", headers=self.H).get_json()
        import logpush_config as LPC
        token = LPC.ler()["s3_owner_token"]
        self.assertNotIn(token, str(j))
        self.assertTrue(j["posse"]["pendente"])
        self.assertFalse(j["posse"]["verificado"])

    def test_token_certo_libera_posse(self):
        objetos = self._fake_s3()
        j = self.app.post("/api/logpush/test", headers=self.H, json={}).get_json()
        token = objetos[j["chave"]].decode().strip().split()[-1]
        r = self.app.post("/api/logpush/s3-posse", headers=self.H,
                          json={"token": token})
        self.assertEqual(r.status_code, 200)
        v = self.app.get("/api/logpush", headers=self.H).get_json()
        self.assertTrue(v["posse"]["verificado"])
        self.assertFalse(v["posse"]["pendente"])

    def test_token_errado_recusa(self):
        self._fake_s3()
        self.app.post("/api/logpush/test", headers=self.H, json={})
        r = self.app.post("/api/logpush/s3-posse", headers=self.H,
                          json={"token": "errado"})
        self.assertEqual(r.status_code, 400)
        v = self.app.get("/api/logpush", headers=self.H).get_json()
        self.assertFalse(v["posse"]["verificado"])

    def test_posse_sem_desafio_pendente_falha(self):
        r = self.app.post("/api/logpush/s3-posse", headers=self.H,
                          json={"token": "qualquer"})
        self.assertEqual(r.status_code, 400)

    def test_trocar_bucket_invalida_a_posse(self):
        objetos = self._fake_s3()
        j = self.app.post("/api/logpush/test", headers=self.H, json={}).get_json()
        token = objetos[j["chave"]].decode().strip().split()[-1]
        self.app.post("/api/logpush/s3-posse", headers=self.H, json={"token": token})
        # troca o bucket: a posse do anterior não vale mais
        self.app.post("/api/logpush", headers=self.H,
                      json={"destino": "s3", "s3_bucket": "outro-bucket"})
        v = self.app.get("/api/logpush", headers=self.H).get_json()
        self.assertFalse(v["posse"]["verificado"])


if __name__ == "__main__":
    unittest.main()
