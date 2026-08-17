"""O ponteiro só pode avançar sobre o que foi REALMENTE lido e entregue.

Todos os casos aqui nasceram de uma perda observada em produção: o coletor
marcava a posição final de arquivos que nunca conseguiu abrir, e aquele trecho
não voltava nunca mais.
"""

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


@B.registrar("dublê_ponteiro")
class DubleOk(B.LogDestination):
    recebidas: list = []

    def send(self, mensagens):
        DubleOk.recebidas = list(mensagens)


@B.registrar("dublê_durante")
class DubleDurante(B.LogDestination):
    """Simula o scanner escrevendo enquanto a entrega acontece."""

    ao_enviar = None

    def send(self, mensagens):
        if DubleDurante.ao_enviar is not None:
            DubleDurante.ao_enviar()


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

    def escrever(self, n=1, texto=None):
        with open(self.arq, "a", encoding="utf-8", newline="") as fh:
            for _ in range(n):
                fh.write((texto if texto is not None else LINHA) + "\n")

    def marca(self) -> dict:
        return LP.ler_estado().get("monitor/monitor.log", {})


class TestOrigemIlegivel(Base):
    """Permissão negada é atraso, nunca buraco."""

    def test_ponteiro_nao_avanca_quando_a_leitura_falha(self):
        self.escrever(3)

        def negar(caminho, pos):
            raise PermissionError(13, "Permission denied")

        original, LP._ler_desde = LP._ler_desde, negar
        try:
            r = LP.executar(dict(self.cfg, destino="dublê_ponteiro"), raiz=self.raiz)
        finally:
            LP._ler_desde = original

        self.assertEqual(r["enviadas"], 0)
        self.assertEqual(self.marca().get("pos", 0), 0)
        # corrigida a permissão, as três linhas continuam lá para enviar
        self.assertEqual(len(LP.coletar(self.cfg, self.raiz)), 3)

    def test_falha_de_leitura_e_registrada(self):
        """Silêncio aqui é o que fez o defeito passar despercebido por dias."""
        import contextlib
        import io

        self.escrever(1)

        def negar(caminho, pos):
            raise PermissionError(13, "Permission denied")

        buf = io.StringIO()
        original, LP._ler_desde = LP._ler_desde, negar
        try:
            with contextlib.redirect_stderr(buf):
                LP.executar(dict(self.cfg, destino="dublê_ponteiro"), raiz=self.raiz)
        finally:
            LP._ler_desde = original
        self.assertIn("monitor/monitor.log", buf.getvalue())
        self.assertIn("PermissionError", buf.getvalue())


class TestCrescimentoDuranteEnvio(Base):
    """O que o scanner escreve durante a entrega tem de sobrar para o ciclo seguinte."""

    def test_linhas_escritas_durante_o_envio_nao_somem(self):
        self.escrever(2)
        DubleDurante.ao_enviar = lambda: self.escrever(2)
        try:
            LP.executar(dict(self.cfg, destino="dublê_durante"), raiz=self.raiz)
        finally:
            DubleDurante.ao_enviar = None
        self.assertEqual(len(LP.coletar(self.cfg, self.raiz)), 2)


class TestLinhaIncompleta(Base):
    """Ler no meio de uma escrita não pode consumir a linha pela metade."""

    def test_linha_sem_quebra_espera_o_resto(self):
        self.escrever(1)
        with open(self.arq, "a", encoding="utf-8", newline="") as fh:
            fh.write(LINHA[:40])            # metade de uma linha, ainda sem \n
        self.assertEqual(len(LP.coletar(self.cfg, self.raiz)), 1)
        LP.gravar_marcas(LP._varrer(self.cfg, self.raiz)[1])
        with open(self.arq, "a", encoding="utf-8", newline="") as fh:
            fh.write(LINHA[40:] + "\n")     # o resto chega
        self.assertEqual(len(LP.coletar(self.cfg, self.raiz)), 1)


class TestLimitePorCiclo(Base):
    """O teto por ciclo atrasa o excedente; não o descarta."""

    def test_excedente_sai_nos_ciclos_seguintes(self):
        self.escrever(5)
        original, LP.MAX_POR_CICLO = LP.MAX_POR_CICLO, 2
        try:
            enviadas = [LP.executar(dict(self.cfg, destino="dublê_ponteiro"),
                                    raiz=self.raiz)["enviadas"] for _ in range(4)]
        finally:
            LP.MAX_POR_CICLO = original
        self.assertEqual(enviadas, [2, 2, 1, 0])


if __name__ == "__main__":
    unittest.main()
