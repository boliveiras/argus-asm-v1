"""Aviso de queda de cobertura após varredura paralela.

Sob concorrência o nmap não falha: ele reclassifica porta ABERTA como
'filtered', que não entra no relatório. O scan termina bem, mais rápido e com
menos achados — sem nada denunciar. Este aviso é o que torna esse risco
verificável, comparando com a execução anterior da mesma campanha.
"""

import os
import sys
import tempfile
import types
import unittest

sys.modules.setdefault("nmap", types.ModuleType("nmap"))
sys.path.insert(0, "core")
sys.path.insert(0, "scanners")


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        os.environ["ARGUS_BASE"] = self.tmp.name
        os.environ.pop("ARGUS_DB", None)
        import monitor as M
        self.M = M

    def tearDown(self):
        self.tmp.cleanup()

    def com_historico(self, anterior):
        """Finge que a execução anterior encontrou `anterior` portas."""
        self.M._portas_da_execucao_anterior = lambda campanha: anterior


class TestAviso(Base):
    def test_queda_grande_com_paralelismo_alerta(self):
        self.com_historico(214)
        aviso = self.M._alertar_queda_cobertura("PRODATA", 120, 5)
        self.assertIsNotNone(aviso)
        self.assertIn("214", aviso)
        self.assertIn("120", aviso)

    def test_queda_pequena_nao_alerta(self):
        # Variação normal entre execuções não pode virar alarme.
        self.com_historico(214)
        self.assertIsNone(self.M._alertar_queda_cobertura("PRODATA", 200, 5))

    def test_queda_em_serie_nao_alerta(self):
        # Com paralelismo 1 a causa não é concorrência: alertar aqui seria ruído.
        self.com_historico(214)
        self.assertIsNone(self.M._alertar_queda_cobertura("PRODATA", 50, 1))

    def test_aumento_nao_alerta(self):
        self.com_historico(100)
        self.assertIsNone(self.M._alertar_queda_cobertura("PRODATA", 214, 5))

    def test_sem_historico_nao_alerta(self):
        # Primeira execução da campanha: não há com o que comparar.
        self.com_historico(0)
        self.assertIsNone(self.M._alertar_queda_cobertura("PRODATA", 10, 5))

    def test_aviso_sugere_reduzir(self):
        self.com_historico(214)
        aviso = self.M._alertar_queda_cobertura("PRODATA", 100, 5)
        self.assertIn("paralelismo", aviso.lower())


if __name__ == "__main__":
    unittest.main()
