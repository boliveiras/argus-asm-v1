"""Testes do coletor: ponteiro, rotação, truncamento e falha do destino."""

import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, "core")
import logpush as LP  # noqa: E402
from logpush_dest import base as B  # noqa: E402

LINHA = ('<130>1 2026-08-15T13:35:47.812Z HOST monitor 1 PORT_NEW '
         '[origin@32473 ip="1.2.3.4" risk="CRITICO"] Nova porta')


@B.registrar("dublê_ok")
class DubleOk(B.LogDestination):
    recebidas: list = []

    def send(self, mensagens):
        DubleOk.recebidas = list(mensagens)


@B.registrar("dublê_falha")
class DubleFalha(B.LogDestination):
    def send(self, mensagens):
        raise B.LogPushError("destino fora do ar")


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.raiz = Path(self.tmp.name) / "log"
        (self.raiz / "monitor").mkdir(parents=True)
        (Path(self.tmp.name) / "store").mkdir(parents=True)
        os.environ["ARGUS_BASE"] = self.tmp.name
        self.arq = self.raiz / "monitor" / "monitor.log"
        self.cfg = {"origem_monitor": True}

    def tearDown(self):
        self.tmp.cleanup()

    def escrever(self, n=1, arquivo=None):
        with open(arquivo or self.arq, "a", encoding="utf-8", newline="") as fh:
            for _ in range(n):
                fh.write(LINHA + "\n")

    def avancar(self):
        """Confirma a entrega do que a varredura leu — como faz `executar`."""
        LP.gravar_marcas(LP._varrer(self.cfg, self.raiz)[1])


class TestPonteiro(Base):
    def test_le_so_o_que_e_novo(self):
        self.escrever(2)
        self.assertEqual(len(LP.coletar(self.cfg, self.raiz)), 2)
        self.avancar()
        self.assertEqual(len(LP.coletar(self.cfg, self.raiz)), 0)
        self.escrever(1)
        self.assertEqual(len(LP.coletar(self.cfg, self.raiz)), 1)

    def test_origem_desligada_nao_le(self):
        self.escrever(2)
        self.assertEqual(LP.coletar({"origem_monitor": False}, self.raiz), [])

    def test_arquivo_inexistente_nao_quebra(self):
        self.assertEqual(LP.coletar(self.cfg, self.raiz), [])


class TestRotacao(Base):
    def test_rotacao_nao_perde_nem_duplica(self):
        self.escrever(2)
        LP.coletar(self.cfg, self.raiz)
        self.avancar()
        # logrotate: renomeia o atual e cria um novo (inode diferente)
        self.arq.rename(self.raiz / "monitor" / "monitor.log.1")
        self.escrever(3)
        self.assertEqual(len(LP.coletar(self.cfg, self.raiz)), 3)

    def test_linhas_pendentes_do_rotacionado_sao_lidas(self):
        self.escrever(2)
        LP.coletar(self.cfg, self.raiz)
        self.avancar()
        # duas linhas escritas DEPOIS do ponteiro e antes da rotação
        self.escrever(2)
        self.arq.rename(self.raiz / "monitor" / "monitor.log.1")
        self.escrever(1)
        # 2 pendentes no .log.1 + 1 no arquivo novo
        self.assertEqual(len(LP.coletar(self.cfg, self.raiz)), 3)


class TestTruncamento(Base):
    def test_arquivo_menor_que_ponteiro_recomeca(self):
        self.escrever(5)
        LP.coletar(self.cfg, self.raiz)
        self.avancar()
        with open(self.arq, "w", encoding="utf-8", newline="") as fh:
            fh.write(LINHA + "\n")
        self.assertEqual(len(LP.coletar(self.cfg, self.raiz)), 1)


class TestExecutar(Base):
    def test_ponteiro_nao_avanca_se_destino_falha(self):
        self.escrever(2)
        antes = LP.ler_estado()
        resultado = LP.executar(dict(self.cfg, destino="dublê_falha"), raiz=self.raiz)
        self.assertFalse(resultado["ok"])
        self.assertEqual(LP.ler_estado(), antes)
        # e o mesmo trecho continua pendente para o próximo ciclo
        self.assertEqual(len(LP.coletar(self.cfg, self.raiz)), 2)

    def test_sucesso_avanca_e_nao_reenvia(self):
        self.escrever(2)
        r1 = LP.executar(dict(self.cfg, destino="dublê_ok"), raiz=self.raiz)
        self.assertTrue(r1["ok"])
        self.assertEqual(r1["enviadas"], 2)
        r2 = LP.executar(dict(self.cfg, destino="dublê_ok"), raiz=self.raiz)
        self.assertEqual(r2["enviadas"], 0)

    def test_nada_novo_nao_chama_destino(self):
        r = LP.executar(dict(self.cfg, destino="dublê_falha"), raiz=self.raiz)
        self.assertTrue(r["ok"])
        self.assertEqual(r["enviadas"], 0)


class TestSaidaDeExecucao(Base):
    def test_stdout_vira_uma_mensagem_por_arquivo(self):
        (self.raiz / "scan").mkdir()
        alvo = self.raiz / "scan" / "submonitor.log"
        with open(alvo, "w", encoding="utf-8", newline="") as fh:
            fh.write("# argus-submonitor\n# fim: 2026-08-15 09:37:07 | rc=0\n\n")
            for i in range(50):
                fh.write(f"[SUB] linha {i}\n")
        msgs = LP.coletar({"origem_scan": True}, self.raiz)
        self.assertEqual(len(msgs), 1)
        self.assertEqual(msgs[0].msgid, "SCAN_OUTPUT")
        self.assertIn("[SUB] linha 49", msgs[0].texto)


if __name__ == "__main__":
    unittest.main()
