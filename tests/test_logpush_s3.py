"""Testes do destino S3 (write-once, anticolisão e prova de posse)."""

import datetime
import sys
import unittest

sys.path.insert(0, "core")
import logpush_config as LPC  # noqa: E402
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


def cfg_ok(**extra):
    """Config de S3 com a posse já comprovada — para testar o envio em si."""
    base = {"destino": "s3", "s3_bucket": "b", "s3_prefixo": "logs/argus"}
    base.update(extra)
    base["s3_owner_verified"] = LPC.owner_ref(base)
    return base


def msg(seg=47, texto="linha", origem="monitor"):
    return B.Mensagem(origem=origem, texto=texto,
                      quando=datetime.datetime(2026, 8, 15, 13, 35, seg),
                      severidade="CRITICO", msgid="PORT_NEW", campos={})


class TestChave(unittest.TestCase):
    def setUp(self):
        self.d = S3.S3Destination(cfg_ok())
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
        c = cfg_ok()
        c.pop("s3_prefixo")
        c["s3_owner_verified"] = LPC.owner_ref(c)
        d = S3.S3Destination(c)
        d._cliente = FakeS3()
        d.send([msg()])
        self.assertTrue(next(iter(d._cliente.objetos)).startswith("logs/argus/"))


class TestFalha(unittest.TestCase):
    def test_erro_do_cliente_vira_logpusherror(self):
        class Quebrado:
            def put_object(self, **kw):
                raise RuntimeError("sem rede")

        d = S3.S3Destination(cfg_ok())
        d._cliente = Quebrado()
        with self.assertRaises(B.LogPushError):
            d.send([msg()])

    def test_sem_bucket_levanta(self):
        d = S3.S3Destination({"destino": "s3"})
        with self.assertRaises(B.LogPushError):
            d.send([msg()])

    def test_lista_vazia_nao_faz_nada(self):
        d = S3.S3Destination(cfg_ok())
        d._cliente = FakeS3()
        d.send([])
        self.assertEqual(d._cliente.objetos, {})


class TestProvaDePosse(unittest.TestCase):
    """Fail secure: sem posse comprovada, dado sensível não sai."""

    def test_send_bloqueado_sem_posse(self):
        d = S3.S3Destination({"destino": "s3", "s3_bucket": "b"})   # sem verified
        d._cliente = FakeS3()
        with self.assertRaises(B.LogPushError) as ctx:
            d.send([msg()])
        self.assertIn("posse", str(ctx.exception).lower())
        self.assertEqual(d._cliente.objetos, {})   # nada gravado

    def test_posse_de_outro_bucket_nao_libera(self):
        # verificado para "b", mas agora o bucket é "c": não vale.
        d = S3.S3Destination({"destino": "s3", "s3_bucket": "c",
                              "s3_owner_verified": "|b"})
        d._cliente = FakeS3()
        with self.assertRaises(B.LogPushError):
            d.send([msg()])

    def test_desafio_grava_token_fora_da_arvore_de_logs(self):
        d = S3.S3Destination({"destino": "s3", "s3_bucket": "b",
                              "s3_prefixo": "logs/argus"})
        d._cliente = FakeS3()
        token, chave = d.desafiar()
        # 32 hex, e a prova NÃO cai sob logs/argus (senão o pull-logs a coletaria)
        self.assertEqual(len(token), 32)
        self.assertEqual(chave, "logs/_argus/prova-de-posse.txt")
        self.assertFalse(chave.startswith("logs/argus/"))
        self.assertIn(token.encode(), d._cliente.objetos[chave])

    def test_desafio_sobrescreve_a_prova_anterior(self):
        # A prova tem nome fixo: rodar de novo troca o token, não acumula lixo.
        d = S3.S3Destination({"destino": "s3", "s3_bucket": "b"})

        class SobrescreveOk:
            def __init__(self): self.objetos = {}
            def put_object(self, Bucket, Key, Body, **kw):  # noqa: N803
                self.objetos[Key] = Body

        d._cliente = SobrescreveOk()
        t1, k1 = d.desafiar()
        t2, k2 = d.desafiar()
        self.assertEqual(k1, k2)
        self.assertNotEqual(t1, t2)

    def test_posse_confere_libera_o_envio(self):
        # Fluxo completo: desafia -> marca verified com o ref -> envia.
        c = {"destino": "s3", "s3_bucket": "b", "s3_prefixo": "logs/argus"}
        d = S3.S3Destination(c)
        d._cliente = FakeS3()
        _token, _chave = d.desafiar()
        c["s3_owner_verified"] = LPC.owner_ref(c)
        d2 = S3.S3Destination(c)
        d2._cliente = FakeS3()
        self.assertEqual(d2.send([msg()]), 1)


if __name__ == "__main__":
    unittest.main()
