"""Testes do catálogo/config do logpush. Rodar: python3 -m unittest discover -s tests"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, "core")
import logpush_config as LC  # noqa: E402


class TestMascarar(unittest.TestCase):
    def test_nunca_devolve_valor_inteiro(self):
        self.assertEqual(LC.mascarar("AKIAIOSFODNN7EXAMPLE"), "••••MPLE")

    def test_vazio_vira_vazio(self):
        self.assertEqual(LC.mascarar(""), "")
        self.assertEqual(LC.mascarar(LC.PLACEHOLDER), "")

    def test_valor_curto_nao_vaza(self):
        self.assertEqual(LC.mascarar("abc"), "••••")


class TestUrlSegura(unittest.TestCase):
    def test_https_publico_ok(self):
        self.assertTrue(LC.url_segura("https://chat.googleapis.com/v1/spaces/AAA"))

    def test_http_recusado(self):
        self.assertFalse(LC.url_segura("http://chat.googleapis.com/x"))

    def test_ip_privado_recusado(self):
        for u in ("https://127.0.0.1/x", "https://10.0.0.5/x",
                  "https://192.168.1.10/x", "https://172.16.0.1/x",
                  "https://localhost/x", "https://169.254.169.254/x"):
            self.assertFalse(LC.url_segura(u), u)

    def test_lixo_recusado(self):
        self.assertFalse(LC.url_segura(""))
        self.assertFalse(LC.url_segura("file:///etc/passwd"))


class TestOrigens(unittest.TestCase):
    def test_origens_ligadas_le_do_config(self):
        cfg = {"origem_monitor": True, "origem_audit": True, "origem_scan": False}
        self.assertEqual(sorted(LC.origens_ligadas(cfg)), ["audit", "monitor"])

    def test_catalogo_tem_as_sete_origens(self):
        ids = {o["id"] for o in LC.ORIGENS}
        self.assertEqual(ids, {"monitor", "submonitor", "credentials",
                               "email", "typosquat", "audit", "scan"})


class TestSeveridades(unittest.TestCase):
    def test_sem_marcacao_usa_padrao(self):
        self.assertEqual(LC.severidades_ligadas({}), ["CRITICO", "ALTO"])

    def test_respeita_o_que_foi_marcado(self):
        cfg = {"sev_CRITICO": True, "sev_INFO": True}
        self.assertEqual(LC.severidades_ligadas(cfg), ["CRITICO", "INFO"])


class TestGravarLer(unittest.TestCase):
    def test_roundtrip(self):
        with tempfile.TemporaryDirectory() as d:
            os.environ["ARGUS_BASE"] = d
            LC.gravar({"destino": "s3", "s3_bucket": "meu-bucket"})
            self.assertEqual(LC.ler()["s3_bucket"], "meu-bucket")

    def test_ler_sem_arquivo_devolve_vazio(self):
        with tempfile.TemporaryDirectory() as d:
            os.environ["ARGUS_BASE"] = d
            self.assertEqual(LC.ler(), {})


if __name__ == "__main__":
    unittest.main()
