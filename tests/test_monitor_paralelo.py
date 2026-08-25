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


class TestRunScanDistingueFalhaDeVazio(Base):
    """CRÍTICO residual: run_scan engolia QUALQUER exceção de scanner.scan()
    (permissão negada, dispositivo de rede indisponível, timeout, nmap morto
    por OOM...) e devolvia [] — indistinguível de "rodou e não achou nada".
    Com TODOS os alvos batendo nisso, _varrer_alvos nunca contava falhas e
    o scan "terminava com sucesso" sem ter varrido nada de verdade."""

    def setUp(self):
        super().setUp()
        # run_scan chama _check_root() -> os.geteuid(), inexistente no Windows
        # onde os testes rodam; substitui para não quebrar por motivo alheio
        # ao que está sendo testado aqui.
        check_root_original = self.M._check_root
        self.addCleanup(setattr, self.M, "_check_root", check_root_original)
        self.M._check_root = lambda: False
        # nmap.PortScanner é mutado no módulo nmap COMPARTILHADO entre
        # arquivos de teste (sys.modules — processo único); salva/restaura
        # para não vazar o dublê para outro teste.
        self._portscanner_original = getattr(self.M.nmap, "PortScanner", None)
        self.addCleanup(self._restaurar_portscanner)

    def _restaurar_portscanner(self):
        if self._portscanner_original is None:
            if hasattr(self.M.nmap, "PortScanner"):
                delattr(self.M.nmap, "PortScanner")
        else:
            self.M.nmap.PortScanner = self._portscanner_original

    def test_erro_de_permissao_no_scan_propaga_como_falha(self):
        # Caso mais provável na prática: nmap presente, mas sem privilégio
        # para o tipo de scan pedido.
        class FakeScanner:
            def scan(self, hosts, arguments):
                raise PermissionError(
                    "You requested a scan type which requires root privileges")

        self.M.nmap.PortScanner = FakeScanner
        with self.assertRaises(PermissionError):
            self.M.run_scan("10.0.0.1", "CAMP", "tcp")

    def test_host_inacessivel_sem_portas_continua_sendo_sucesso_vazio(self):
        # nmap RODOU (sem exceção) e não achou nada — não é falha de ambiente.
        class FakeScanner:
            def scan(self, hosts, arguments):
                pass

            def all_hosts(self):
                return []

        self.M.nmap.PortScanner = FakeScanner
        resultado = self.M.run_scan("10.0.0.1", "CAMP", "tcp")
        self.assertEqual(resultado, [])

    def test_falha_de_scan_em_todos_os_alvos_aborta_via_varrer_alvos(self):
        # Ponta a ponta com o dublê no nível de run_scan (não mais dentro de
        # nmap.PortScanner): confirma que _varrer_alvos conta a falha real
        # de scan, não só uma falha injetada diretamente no dublê de teste.
        class FakeScanner:
            def scan(self, hosts, arguments):
                raise PermissionError("permissão negada")

        self.M.nmap.PortScanner = FakeScanner
        ips = [f"10.0.0.{i}" for i in range(1, 4)]
        res, falhas = self.M._varrer_alvos(ips, "CAMP", "tcp", 1)
        self.assertEqual(res, [])
        self.assertEqual(falhas, len(ips))
        self.assertTrue(self.M._falha_total(ips, falhas))


class TestSyslogErrorPorAlvoFalho(Base):
    """Correção 3: cada alvo que falha precisa gerar EXATAMENTE uma chamada a
    syslog_error — nem zero (a trilha RFC5424 fica cega), nem duas (run_scan
    logando e _varrer_alvos logando de novo por cima)."""

    def setUp(self):
        super().setUp()
        original = self.M.syslog_error
        self.addCleanup(setattr, self.M, "syslog_error", original)
        self.chamadas = []
        self.M.syslog_error = lambda context, exc: self.chamadas.append((context, exc))

    def _fake_run_scan_que_sempre_falha(self):
        def fake(ip, campanha, mode="tcp"):
            raise RuntimeError("nmap ausente do PATH")
        return fake

    def test_uma_chamada_por_alvo_falho_serie(self):
        self.M.run_scan = self._fake_run_scan_que_sempre_falha()
        ips = [f"10.0.0.{i}" for i in range(1, 4)]
        self.M._varrer_alvos(ips, "CAMP", "tcp", 1)
        self.assertEqual(len(self.chamadas), len(ips))

    def test_uma_chamada_por_alvo_falho_paralelo(self):
        self.M.run_scan = self._fake_run_scan_que_sempre_falha()
        ips = [f"10.0.0.{i}" for i in range(1, 4)]
        self.M._varrer_alvos(ips, "CAMP", "tcp", 3)
        self.assertEqual(len(self.chamadas), len(ips))

    def test_falha_parcial_gera_chamada_so_para_o_alvo_que_falhou(self):
        def fake(ip, campanha, mode="tcp"):
            if ip == "10.0.0.2":
                raise RuntimeError("nmap morreu")
            return [{"ip": ip, "port": 443, "protocol": mode}]

        self.M.run_scan = fake
        ips = [f"10.0.0.{i}" for i in range(1, 4)]
        self.M._varrer_alvos(ips, "CAMP", "tcp", 1)
        self.assertEqual(len(self.chamadas), 1)


class TestMainAbortaEmFalhaTotal(Base):
    """Correção 2: a fiação em main() (não só o predicado _falha_total isolado)
    precisa de fato impedir process_results quando todos os alvos de uma
    campanha falham. Sem este teste, apagar o `if _falha_total(...): raise`
    de main() deixava a suíte inteira verde com o crítico de volta."""

    def setUp(self):
        super().setUp()
        # Restaura os nomes de módulo que este teste substitui.
        for nome in ("load_campaigns", "init_database", "process_results",
                     "run_scan", "_check_root", "_syslog_open"):
            original = getattr(self.M, nome)
            self.addCleanup(setattr, self.M, nome, original)
        # _THREATINTEL_AVAILABLE também é restaurado — força False para não
        # chamar init_threatintel_db() de verdade (caminho hardcoded /home/kali/...).
        self.addCleanup(setattr, self.M, "_THREATINTEL_AVAILABLE",
                         self.M._THREATINTEL_AVAILABLE)
        self.M._THREATINTEL_AVAILABLE = False

        # syslog não pode tocar disco em teste: _syslog_open no-op mantém
        # _syslog_fd None, e syslog_write/syslog_error/syslog_end já viram
        # no-op sozinhos com esse guard (mesmo em produção).
        self.M._syslog_open = lambda: None
        # run_scan chama _check_root() -> os.geteuid() (inexistente no
        # Windows); main() também chama _check_root() direto no início.
        self.M._check_root = lambda: False

        self._argv_original = sys.argv[:]
        self.addCleanup(setattr, sys, "argv", self._argv_original)
        sys.argv = ["monitor.py"]

        cwd_original = os.getcwd()
        self.addCleanup(os.chdir, cwd_original)

    def test_todos_os_alvos_falhando_impede_process_results_e_propaga_erro(self):
        chamadas_process_results = []
        self.M.process_results = lambda *a, **k: chamadas_process_results.append((a, k))
        self.M.load_campaigns = lambda: [("EMPRESA", ["10.0.0.1", "10.0.0.2"])]
        self.M.init_database = lambda: None

        def fake_run_scan(ip, campanha, mode="tcp"):
            raise RuntimeError("permissão negada")

        self.M.run_scan = fake_run_scan

        with self.assertRaises(RuntimeError):
            self.M.main()

        self.assertEqual(chamadas_process_results, [])


if __name__ == "__main__":
    unittest.main()
