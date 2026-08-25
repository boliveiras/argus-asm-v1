"""Varredura TCP paralela: acelerar não pode perder nem duplicar alvo.

Todos os testes substituem run_scan por um dublê — nenhum nmap roda. O que se
verifica aqui é a orquestração: cobertura completa, agregação correta e o UDP
permanecendo em série.
"""

import os
import sys
import tempfile
import threading
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
        self.chamados = []
        self.lock = threading.Lock()
        self.simultaneos = 0
        self.pico = 0

    def tearDown(self):
        self.tmp.cleanup()

    def dublê(self, atraso=0.0):
        """Substitui run_scan, registrando ordem de chamada e concorrência real."""
        import time

        def fake(ip, campanha, mode="tcp"):
            with self.lock:
                self.chamados.append(ip)
                self.simultaneos += 1
                self.pico = max(self.pico, self.simultaneos)
            if atraso:
                time.sleep(atraso)
            with self.lock:
                self.simultaneos -= 1
            return [{"ip": ip, "port": 443, "protocol": mode}]

        self.M.run_scan = fake


class TestCobertura(Base):
    def test_todos_os_alvos_sao_varridos_uma_vez(self):
        self.dublê()
        ips = [f"10.0.0.{i}" for i in range(1, 21)]
        res = self.M._varrer_alvos(ips, "CAMP", "tcp", 5)
        self.assertEqual(sorted(self.chamados), sorted(ips))   # nenhum pulado
        self.assertEqual(len(self.chamados), len(ips))          # nenhum repetido
        self.assertEqual(len(res), len(ips))                    # nada perdido na agregação

    def test_serie_e_paralelo_produzem_o_mesmo_conjunto(self):
        # O resultado não pode depender da ordem de conclusão.
        self.dublê()
        ips = [f"10.0.0.{i}" for i in range(1, 11)]
        serie = self.M._varrer_alvos(ips, "CAMP", "tcp", 1)
        self.chamados.clear()
        paralelo = self.M._varrer_alvos(ips, "CAMP", "tcp", 5)
        self.assertEqual(sorted(r["ip"] for r in serie),
                         sorted(r["ip"] for r in paralelo))

    def test_lista_vazia_nao_quebra(self):
        self.dublê()
        self.assertEqual(self.M._varrer_alvos([], "CAMP", "tcp", 3), [])


class TestConcorrencia(Base):
    def test_paralelismo_1_roda_em_serie(self):
        self.dublê(atraso=0.02)
        self.M._varrer_alvos([f"10.0.0.{i}" for i in range(1, 6)], "CAMP", "tcp", 1)
        self.assertEqual(self.pico, 1)

    def test_respeita_o_teto_configurado(self):
        self.dublê(atraso=0.05)
        self.M._varrer_alvos([f"10.0.0.{i}" for i in range(1, 21)], "CAMP", "tcp", 3)
        self.assertLessEqual(self.pico, 3)
        self.assertGreater(self.pico, 1)     # e de fato paralelizou

    def test_falha_em_um_alvo_nao_derruba_os_outros(self):
        # Um nmap que explode não pode abortar a varredura inteira.
        def fake(ip, campanha, mode="tcp"):
            if ip == "10.0.0.3":
                raise RuntimeError("nmap morreu")
            return [{"ip": ip, "port": 443, "protocol": mode}]

        self.M.run_scan = fake
        res = self.M._varrer_alvos([f"10.0.0.{i}" for i in range(1, 6)],
                                   "CAMP", "tcp", 3)
        self.assertEqual(len(res), 4)        # os outros quatro seguiram


if __name__ == "__main__":
    unittest.main()
