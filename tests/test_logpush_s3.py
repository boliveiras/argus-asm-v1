"""Testes do destino S3 (write-once e anticolisão)."""

import datetime
import sys
import unittest

sys.path.insert(0, "core")
from logpush_dest import base as B  # noqa: E402
from logpush_dest import s3 as S3  # noqa: E402


class FakeS3:
    """Dublê que ACUSA sobrescrita — é o que o pull-logs-s3 não perdoa."""

    def __init__(self):
        self.objetos = {}

    def put_object(self, Bucket, Key, Body, **kw):  # noqa: N803 - assinatura do boto3
        if Key in self.objetos:
            raise AssertionError(f"sobrescrita de {Key}")
        self.objetos[Key] = Body


def msg(seg=47, texto="linha", origem="monitor"):
    return B.Mensagem(origem=origem, texto=texto,
                      quando=datetime.datetime(2026, 8, 15, 13, 35, seg),
                      severidade="CRITICO", msgid="PORT_NEW", campos={})


class TestChave(unittest.TestCase):
    def setUp(self):
        self.d = S3.S3Destination({"destino": "s3", "s3_bucket": "b",
                                   "s3_prefixo": "logs/argus"})
        self.d._cliente = FakeS3()

    def test_layout_do_caminho(self):
        self.d.send([msg()])
        chave = next(iter(self.d._cliente.objetos))
        self.assertEqual(chave, "logs/argus/monitor/15-08-2026-13-35-47.log")

    def test_mesmo_segundo_nao_sobrescreve(self):
        # Três eventos no mesmo segundo têm de virar três objetos. A ORDEM das
        # chaves não importa (em ASCII "-002.log" ordena antes de ".log"); o que
        # não pode acontecer é o segundo evento apagar o primeiro.
        self.d.send([msg(), msg(), msg()])
        self.assertEqual(set(self.d._cliente.objetos), {
            "logs/argus/monitor/15-08-2026-13-35-47.log",
            "logs/argus/monitor/15-08-2026-13-35-47-002.log",
            "logs/argus/monitor/15-08-2026-13-35-47-003.log",
        })

    def test_separa_por_origem(self):
        self.d.send([msg(origem="monitor"), msg(origem="audit")])
        chaves = sorted(self.d._cliente.objetos)
        self.assertTrue(chaves[0].startswith("logs/argus/audit/"))
        self.assertTrue(chaves[1].startswith("logs/argus/monitor/"))

    def test_conteudo_e_a_linha_original(self):
        self.d.send([msg(texto="<130>1 linha crua")])
        corpo = next(iter(self.d._cliente.objetos.values()))
        self.assertEqual(corpo, b"<130>1 linha crua\n")

    def test_prefixo_padrao_quando_ausente(self):
        d = S3.S3Destination({"destino": "s3", "s3_bucket": "b"})
        d._cliente = FakeS3()
        d.send([msg()])
        self.assertTrue(next(iter(d._cliente.objetos)).startswith("logs/argus/"))


class TestFalha(unittest.TestCase):
    def test_erro_do_cliente_vira_logpusherror(self):
        class Quebrado:
            def put_object(self, **kw):
                raise RuntimeError("sem rede")

        d = S3.S3Destination({"destino": "s3", "s3_bucket": "b"})
        d._cliente = Quebrado()
        with self.assertRaises(B.LogPushError):
            d.send([msg()])

    def test_sem_bucket_levanta(self):
        d = S3.S3Destination({"destino": "s3"})
        with self.assertRaises(B.LogPushError):
            d.send([msg()])

    def test_lista_vazia_nao_faz_nada(self):
        d = S3.S3Destination({"destino": "s3", "s3_bucket": "b"})
        d._cliente = FakeS3()
        d.send([])
        self.assertEqual(d._cliente.objetos, {})


if __name__ == "__main__":
    unittest.main()
