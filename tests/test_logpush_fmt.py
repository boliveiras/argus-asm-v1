"""Testes do parser RFC 5424 e da formatação para chat."""

import sys
import unittest

sys.path.insert(0, "core")
import logpush_fmt as F  # noqa: E402

LINHA = ('<130>1 2026-08-15T13:35:47.812Z PROMETEUS monitor 4821 PORT_NEW '
         '[origin@32473 run_id="a3f2" campanha="RIOCARD" ip="104.18.9.141" port="443" '
         'service="https" risk="CRITICO" asn="Cloudflare, Inc."] Nova porta [CRITICO]: 104.18.9.141:443')

AUDIT = ('<109>1 2026-08-13T22:54:20.649Z PROMETEUS argus-audit 30880 AUTHZ_DENY '
         '[argus@32473 actor="monitor" src_ip="127.0.0.1" action="scan_start" outcome="deny"] '
         'acao negada: header CSRF ausente')


class TestParse(unittest.TestCase):
    def test_extrai_campos(self):
        m = F.parse_rfc5424(LINHA, "monitor")
        self.assertEqual(m.msgid, "PORT_NEW")
        self.assertEqual(m.campos["ip"], "104.18.9.141")
        self.assertEqual(m.campos["campanha"], "RIOCARD")

    def test_preserva_a_linha_original(self):
        self.assertEqual(F.parse_rfc5424(LINHA, "monitor").texto, LINHA)

    def test_severidade_vem_do_risco_declarado(self):
        self.assertEqual(F.parse_rfc5424(LINHA, "monitor").severidade, "CRITICO")

    def test_severidade_cai_no_prival_sem_risco(self):
        # 109 = 13*8 + 5 (NOTICE) -> MEDIO; o evento de auditoria não traz risk=
        self.assertEqual(F.parse_rfc5424(AUDIT, "audit").severidade, "MEDIO")

    def test_audit_tambem_parseia(self):
        m = F.parse_rfc5424(AUDIT, "audit")
        self.assertEqual(m.msgid, "AUTHZ_DENY")
        self.assertEqual(m.campos["actor"], "monitor")

    def test_linha_invalida_devolve_none(self):
        self.assertIsNone(F.parse_rfc5424("isso nao e syslog", "monitor"))
        self.assertIsNone(F.parse_rfc5424("", "monitor"))


class TestFormatoChat(unittest.TestCase):
    def setUp(self):
        self.m = F.parse_rfc5424(LINHA, "monitor")

    def test_google_chat_usa_text(self):
        p = F.para_chat(self.m, "google_chat")
        self.assertIn("text", p)
        self.assertIn("104.18.9.141", p["text"])
        self.assertIn("RIOCARD", p["text"])

    def test_discord_usa_content(self):
        self.assertIn("content", F.para_chat(self.m, "discord"))

    def test_teams_usa_card(self):
        self.assertEqual(F.para_chat(self.m, "teams")["@type"], "MessageCard")

    def test_telegram_usa_text(self):
        self.assertIn("text", F.para_chat(self.m, "telegram"))

    def test_nao_vaza_linha_crua(self):
        texto = F.para_chat(self.m, "google_chat")["text"]
        self.assertNotIn("<130>1", texto)
        self.assertNotIn("origin@32473", texto)

    def test_generico_leva_campos(self):
        p = F.para_chat(self.m, "generico")
        self.assertEqual(p["severidade"], "CRITICO")
        self.assertEqual(p["msgid"], "PORT_NEW")

    def test_titulo_legivel_para_msgid_conhecido(self):
        self.assertIn("Nova porta exposta", F.para_chat(self.m, "google_chat")["text"])


if __name__ == "__main__":
    unittest.main()
