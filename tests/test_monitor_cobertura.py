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
        self.addCleanup(setattr, M, "DATABASE_FILE", M.DATABASE_FILE)

    def tearDown(self):
        self.tmp.cleanup()

    def com_historico(self, anterior):
        """Finge que a execução anterior encontrou `anterior` portas.

        Restaura no fim do teste: o módulo é o mesmo objeto entre classes, e um
        dublê deixado para trás faz a classe seguinte testar o lambda em vez da
        função real — foi o que aconteceu antes de o addCleanup entrar aqui.
        """
        original = self.M._portas_da_execucao_anterior
        self.addCleanup(setattr, self.M, "_portas_da_execucao_anterior", original)
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


class TestLeituraDoHistorico(Base):
    """Exercita _portas_da_execucao_anterior de VERDADE — SQL e tratamento de erro.

    Os testes acima substituem essa função por um dublê, então o caminho real
    (consulta e o `except` que devolve zero) nunca rodava: uma coluna renomeada
    ou um caminho inválido passariam pela suíte inteira sem ninguém notar. E é
    justamente esse `except` que garante o requisito de que erro no banco não
    derruba o scan — a verificação de cobertura é conveniência, não função
    crítica.
    """

    def _banco(self, linhas):
        """Cria um monitor.db real com as linhas informadas."""
        import sqlite3
        caminho = os.path.join(self.tmp.name, "monitor.db")
        conn = sqlite3.connect(caminho)
        conn.execute("CREATE TABLE scans (campanha TEXT, protocol TEXT, status TEXT)")
        conn.executemany("INSERT INTO scans VALUES (?,?,?)", linhas)
        conn.commit()
        conn.close()
        self.M.DATABASE_FILE = caminho
        return caminho

    def test_conta_so_as_portas_ativas_da_campanha_em_tcp(self):
        self._banco([
            ("PRODATA", "tcp", "NOVO"),
            ("PRODATA", "tcp", "REINCIDENTE"),
            ("PRODATA", "tcp", "RESSURGIDO"),
            ("PRODATA", "tcp", "CORRIGIDO"),   # fechada: não conta
            ("PRODATA", "udp", "NOVO"),        # outro protocolo: não conta
            ("OUTRA",   "tcp", "NOVO"),        # outra campanha: não conta
        ])
        self.assertEqual(self.M._portas_da_execucao_anterior("PRODATA"), 3)

    def test_campanha_sem_historico_devolve_zero(self):
        self._banco([("OUTRA", "tcp", "NOVO")])
        self.assertEqual(self.M._portas_da_execucao_anterior("PRODATA"), 0)

    def test_banco_inexistente_devolve_zero_sem_levantar(self):
        self.M.DATABASE_FILE = os.path.join(self.tmp.name, "nao-existe", "x.db")
        self.assertEqual(self.M._portas_da_execucao_anterior("PRODATA"), 0)

    def test_schema_quebrado_devolve_zero_sem_levantar(self):
        # Coluna renomeada, tabela ausente: o scan não pode cair por causa disso.
        import sqlite3
        caminho = os.path.join(self.tmp.name, "quebrado.db")
        conn = sqlite3.connect(caminho)
        conn.execute("CREATE TABLE outra_coisa (x INTEGER)")
        conn.commit()
        conn.close()
        self.M.DATABASE_FILE = caminho
        self.assertEqual(self.M._portas_da_execucao_anterior("PRODATA"), 0)


class TestPisoDeAmostra(Base):
    """Histórico pequeno não pode alarmar: 3 portas caindo para 2 são 33%."""

    def test_historico_pequeno_nao_alerta(self):
        self.com_historico(3)
        self.assertIsNone(self.M._alertar_queda_cobertura("PRODATA", 2, 5))

    def test_historico_grande_continua_alertando(self):
        self.com_historico(214)
        self.assertIsNotNone(self.M._alertar_queda_cobertura("PRODATA", 100, 5))
