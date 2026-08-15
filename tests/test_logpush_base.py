"""Testes do contrato dos destinos."""

import datetime
import sys
import unittest

sys.path.insert(0, "core")
from logpush_dest import base as B  # noqa: E402


class TestRegistry(unittest.TestCase):
    def test_criar_devolve_destino_registrado(self):
        @B.registrar("fake")
        class Fake(B.LogDestination):
            def send(self, mensagens):
                self.recebidas = mensagens

        d = B.criar({"destino": "fake"})
        self.assertIsInstance(d, Fake)

    def test_destino_desconhecido_levanta(self):
        with self.assertRaises(B.LogPushError):
            B.criar({"destino": "nao_existe"})

    def test_destino_vazio_levanta(self):
        with self.assertRaises(B.LogPushError):
            B.criar({})

    def test_base_nao_pode_ser_usada_direto(self):
        with self.assertRaises(NotImplementedError):
            B.LogDestination({}).send([])


class TestMensagem(unittest.TestCase):
    def test_campos_obrigatorios(self):
        m = B.Mensagem(origem="monitor", texto="linha crua",
                       quando=datetime.datetime(2026, 8, 15, 13, 35, 47),
                       severidade="CRITICO", msgid="PORT_NEW",
                       campos={"ip": "1.2.3.4"})
        self.assertEqual(m.origem, "monitor")
        self.assertEqual(m.campos["ip"], "1.2.3.4")

    def test_campos_tem_padrao_proprio_por_instancia(self):
        a = B.Mensagem(origem="x", texto="y", quando=datetime.datetime.now())
        b = B.Mensagem(origem="x", texto="y", quando=datetime.datetime.now())
        a.campos["so_em_a"] = 1
        self.assertEqual(b.campos, {})


if __name__ == "__main__":
    unittest.main()
