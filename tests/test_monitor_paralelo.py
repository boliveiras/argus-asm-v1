"""Varredura TCP paralela: acelerar não pode perder nem duplicar alvo.

Todos os testes substituem run_scan por um dublê — nenhum nmap roda. O que se
verifica aqui é a orquestração: cobertura completa, agregação correta, o UDP
permanecendo em série e a contagem de falhas que o chamador (main) usa para
distinguir "0 portas abertas" de "o ambiente explodiu e o scan não aconteceu".
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
        self.addCleanup(self.tmp.cleanup)

        # Restaura ARGUS_BASE ao valor anterior — sem isto, o env var fica
        # apontando para um diretório temporário já apagado e os módulos de
        # teste seguintes (ordem alfabética) herdam o lixo.
        _base_antes = os.environ.get("ARGUS_BASE")

        def _restaurar_base():
            if _base_antes is None:
                os.environ.pop("ARGUS_BASE", None)
            else:
                os.environ["ARGUS_BASE"] = _base_antes

        self.addCleanup(_restaurar_base)
        os.environ["ARGUS_BASE"] = self.tmp.name
        os.environ.pop("ARGUS_DB", None)

        import monitor as M
        self.M = M
        # run_scan é substituído por dublê em quase todo teste — restaurar o
        # original evita que um teste vaze o dublê para o próximo.
        self.addCleanup(setattr, M, "run_scan", M.run_scan)

        self.chamados = []
        self.lock = threading.Lock()
        self.simultaneos = 0
        self.pico = 0

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
        res, falhas = self.M._varrer_alvos(ips, "CAMP", "tcp", 5)
        self.assertEqual(sorted(self.chamados), sorted(ips))   # nenhum pulado
        self.assertEqual(len(self.chamados), len(ips))          # nenhum repetido
        self.assertEqual(len(res), len(ips))                    # nada perdido na agregação
        self.assertEqual(falhas, 0)

    def test_serie_e_paralelo_produzem_o_mesmo_conjunto(self):
        # O resultado não pode depender da ordem de conclusão.
        self.dublê()
        ips = [f"10.0.0.{i}" for i in range(1, 11)]
        serie, _ = self.M._varrer_alvos(ips, "CAMP", "tcp", 1)
        self.chamados.clear()
        paralelo, _ = self.M._varrer_alvos(ips, "CAMP", "tcp", 5)
        self.assertEqual(sorted(r["ip"] for r in serie),
                         sorted(r["ip"] for r in paralelo))

    def test_lista_vazia_nao_quebra(self):
        self.dublê()
        self.assertEqual(self.M._varrer_alvos([], "CAMP", "tcp", 3), ([], 0))


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

    def test_udp_permanece_em_serie_mesmo_com_paralelismo_alto(self):
        # A guarda "UDP em série" vive DENTRO de _varrer_alvos (não só em
        # main()) — um chamador que passe paralelismo=5 com mode="udp" tem
        # de ser ignorado e forçado a 1.
        self.dublê(atraso=0.02)
        ips = [f"10.0.0.{i}" for i in range(1, 6)]
        self.M._varrer_alvos(ips, "CAMP", "udp", 5)
        self.assertEqual(self.pico, 1)

    def test_falha_em_um_alvo_nao_derruba_os_outros(self):
        # Um nmap que explode não pode abortar a varredura inteira.
        def fake(ip, campanha, mode="tcp"):
            if ip == "10.0.0.3":
                raise RuntimeError("nmap morreu")
            return [{"ip": ip, "port": 443, "protocol": mode}]

        self.M.run_scan = fake
        res, falhas = self.M._varrer_alvos([f"10.0.0.{i}" for i in range(1, 6)],
                                           "CAMP", "tcp", 3)
        self.assertEqual(len(res), 4)        # os outros quatro seguiram
        self.assertEqual(falhas, 1)

    def test_falha_em_um_alvo_nao_derruba_os_outros_serie(self):
        # Mesmo cenário acima, mas no ramo série (paralelismo=1) — é o ramo
        # que roda em praticamente toda instalação e onde o comportamento
        # mudou (try/except novo ao redor de run_scan).
        def fake(ip, campanha, mode="tcp"):
            if ip == "10.0.0.3":
                raise RuntimeError("nmap morreu")
            return [{"ip": ip, "port": 443, "protocol": mode}]

        self.M.run_scan = fake
        res, falhas = self.M._varrer_alvos([f"10.0.0.{i}" for i in range(1, 6)],
                                           "CAMP", "tcp", 1)
        self.assertEqual(len(res), 4)
        self.assertEqual(falhas, 1)


class TestFalhaTotal(Base):
    """CRÍTICO: falha de ambiente (nmap ausente etc.) não pode virar 'scan
    concluído com 0 portas'. _varrer_alvos precisa reportar QUANTOS alvos
    falharam, e _falha_total é o predicado que main() usa para decidir se a
    execução inteira deve abortar (em vez de deixar process_results tratar
    a lista vazia como 'nada mudou' e, dias depois, fechar achados reais).
    """

    def test_todos_os_alvos_falham_paralelo(self):
        def fake(ip, campanha, mode="tcp"):
            raise RuntimeError("nmap ausente do PATH")

        self.M.run_scan = fake
        ips = [f"10.0.0.{i}" for i in range(1, 4)]
        res, falhas = self.M._varrer_alvos(ips, "CAMP", "tcp", 3)
        self.assertEqual(res, [])
        self.assertEqual(falhas, len(ips))
        self.assertTrue(self.M._falha_total(ips, falhas))

    def test_todos_os_alvos_falham_serie(self):
        def fake(ip, campanha, mode="tcp"):
            raise RuntimeError("nmap ausente do PATH")

        self.M.run_scan = fake
        ips = [f"10.0.0.{i}" for i in range(1, 4)]
        res, falhas = self.M._varrer_alvos(ips, "CAMP", "tcp", 1)
        self.assertEqual(res, [])
        self.assertEqual(falhas, len(ips))
        self.assertTrue(self.M._falha_total(ips, falhas))

    def test_falha_parcial_nao_e_falha_total(self):
        # Cenário "alguns falharam" (já coberto acima em resultado) não deve
        # disparar o aborto da execução — é o caso que o paralelismo precisa
        # tolerar normalmente.
        self.assertFalse(self.M._falha_total(["10.0.0.1", "10.0.0.2"], 1))

    def test_lista_vazia_nao_e_falha_total(self):
        # 0 alvos não é "todos falharam" — é campanha sem IPs, caso já
        # tratado antes (sem chamar run_scan nenhuma vez).
        self.assertFalse(self.M._falha_total([], 0))


if __name__ == "__main__":
    unittest.main()
