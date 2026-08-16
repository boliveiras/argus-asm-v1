"""Testes do destino webhook (filtro de severidade, payload e segurança)."""

import datetime
import sys
import unittest

sys.path.insert(0, "core")
from logpush_dest import base as B  # noqa: E402
from logpush_dest import webhook as W  # noqa: E402


class FakeResp:
    def __init__(self, status=200, texto="ok"):
        self.status_code = status
        self.text = texto


def msg(sev="CRITICO"):
    return B.Mensagem(origem="monitor", texto="linha",
                      quando=datetime.datetime(2026, 8, 15, 13, 35, 47),
                      severidade=sev, msgid="PORT_NEW",
                      campos={"ip": "1.2.3.4", "campanha": "RIOCARD"})


def destino(**cfg):
    """Webhook com a rede substituída por um dublê que registra os envios."""
    base = {"destino": "webhook", "webhook_url": "https://exemplo.com/hook",
            "webhook_plataforma": "google_chat",
            "sev_CRITICO": True, "sev_ALTO": True}
    base.update(cfg)
    d = W.WebhookDestination(base)
    d.enviadas = []
    d._post = lambda url, payload: (d.enviadas.append(payload), FakeResp())[1]
    return d


class TestFiltroSeveridade(unittest.TestCase):
    def test_envia_severidade_marcada(self):
        d = destino()
        d.send([msg("CRITICO")])
        self.assertEqual(len(d.enviadas), 1)

    def test_descarta_severidade_nao_marcada(self):
        d = destino()
        d.send([msg("BAIXO")])
        self.assertEqual(d.enviadas, [])

    def test_todas_marcadas_envia_tudo(self):
        d = destino(sev_MEDIO=True, sev_BAIXO=True, sev_INFO=True)
        d.send([msg("CRITICO"), msg("BAIXO"), msg("INFO")])
        self.assertEqual(len(d.enviadas), 3)

    def test_sem_marcacao_usa_padrao_critico_e_alto(self):
        d = destino(sev_CRITICO=False, sev_ALTO=False)
        d.send([msg("CRITICO"), msg("ALTO"), msg("MEDIO")])
        self.assertEqual(len(d.enviadas), 2)


class TestPayload(unittest.TestCase):
    def test_usa_formato_da_plataforma(self):
        d = destino(webhook_plataforma="discord")
        d.send([msg()])
        self.assertIn("content", d.enviadas[0])

    def test_telegram_leva_chat_id(self):
        d = destino(webhook_plataforma="telegram", webhook_chat_id="-100123")
        d.send([msg()])
        self.assertEqual(d.enviadas[0]["chat_id"], "-100123")

    def test_telegram_sem_chat_id_levanta(self):
        d = destino(webhook_plataforma="telegram")
        with self.assertRaises(B.LogPushError):
            d.send([msg()])


class TestTesteDeConexao(unittest.TestCase):
    def test_teste_envia_mesmo_com_info_fora_do_filtro(self):
        # padrão é CRÍTICO+ALTO; a mensagem de teste é INFO. Se o filtro valesse
        # aqui, a tela diria "teste OK" sem nada ter saído.
        d = destino()
        detalhe = d.testar()
        self.assertEqual(len(d.enviadas), 1)
        self.assertIn("google_chat", detalhe)

    def test_teste_falha_quando_a_url_e_invalida(self):
        d = W.WebhookDestination({"destino": "webhook", "webhook_url": "http://10.0.0.1/h"})
        with self.assertRaises(B.LogPushError):
            d.testar()

    def test_teste_de_telegram_sem_chat_id_falha(self):
        d = destino(webhook_plataforma="telegram", webhook_chat_id="")
        with self.assertRaises(B.LogPushError):
            d.testar()


class TestSeguranca(unittest.TestCase):
    def test_url_insegura_levanta(self):
        d = W.WebhookDestination({"destino": "webhook",
                                  "webhook_url": "http://10.0.0.1/h",
                                  "sev_CRITICO": True})
        with self.assertRaises(B.LogPushError):
            d.send([msg()])

    def test_erro_http_vira_logpusherror(self):
        d = destino()
        d._post = lambda url, payload: FakeResp(500, "erro interno")
        with self.assertRaises(B.LogPushError):
            d.send([msg()])

    def test_erro_nao_vaza_url(self):
        d = destino(webhook_url="https://exemplo.com/hook/SEGREDO123")
        d._post = lambda url, payload: FakeResp(403, "proibido")
        with self.assertRaises(B.LogPushError) as ctx:
            d.send([msg()])
        self.assertNotIn("SEGREDO123", str(ctx.exception))

    def test_falha_de_rede_nao_vaza_url(self):
        d = destino(webhook_url="https://exemplo.com/hook/SEGREDO123")

        def explode(url, payload):
            raise ConnectionError("https://exemplo.com/hook/SEGREDO123 inacessível")

        d._post = explode
        with self.assertRaises(B.LogPushError) as ctx:
            d.send([msg()])
        self.assertNotIn("SEGREDO123", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
