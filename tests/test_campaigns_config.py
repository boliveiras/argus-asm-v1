"""Configuração por campanha: prefixos de wordlist.

O prefixo vem da interface e é CONCATENADO em hostname que depois é resolvido e
consultado. Por isso a allowlist é no servidor, e prefixo inválido é recusado —
nunca ignorado em silêncio.
"""

import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, "core")
import campaigns as CAMP  # noqa: E402


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        os.environ["ARGUS_BASE"] = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()


class TestPadrao(Base):
    def test_campanha_sem_config_usa_o_padrao(self):
        # Retrocompatibilidade: quem já tem campanha não vê mudança nenhuma.
        self.assertEqual(CAMP.prefixos_da_campanha("RIOCARD"), CAMP.PREFIXOS_PADRAO)

    def test_padrao_inclui_a_palavra_pura(self):
        # "" é o prefixo vazio: sem ele, a wordlist crua nunca seria testada.
        self.assertIn("", CAMP.PREFIXOS_PADRAO)

    def test_arquivo_corrompido_cai_no_padrao(self):
        CAMP.config_path().write_text("{ isso não é json", encoding="utf-8")
        self.assertEqual(CAMP.prefixos_da_campanha("RIOCARD"), CAMP.PREFIXOS_PADRAO)


class TestGravacao(Base):
    def test_grava_e_le_de_volta(self):
        CAMP.set_prefixos("RIOCARD", ["", "dev-"])
        self.assertEqual(CAMP.prefixos_da_campanha("RIOCARD"), ["", "dev-"])

    def test_uma_campanha_nao_afeta_outra(self):
        CAMP.set_prefixos("RIOCARD", ["", "dev-"])
        self.assertEqual(CAMP.prefixos_da_campanha("OUTRA"), CAMP.PREFIXOS_PADRAO)

    def test_lista_so_com_vazio_desliga_os_prefixos(self):
        # É o caso que corta 5x: apenas a palavra pura.
        CAMP.set_prefixos("RIOCARD", [""])
        self.assertEqual(CAMP.prefixos_da_campanha("RIOCARD"), [""])

    def test_lista_vazia_vira_so_a_palavra_pura(self):
        CAMP.set_prefixos("RIOCARD", [])
        self.assertEqual(CAMP.prefixos_da_campanha("RIOCARD"), [""])

    def test_remove_duplicatas_preservando_a_ordem(self):
        CAMP.set_prefixos("RIOCARD", ["", "dev-", "dev-", ""])
        self.assertEqual(CAMP.prefixos_da_campanha("RIOCARD"), ["", "dev-"])

    def test_falha_no_meio_da_gravacao_restaura_config_anterior(self):
        # campaigns.json é compartilhado por TODAS as campanhas: uma falha de
        # I/O ao salvar UMA delas não pode truncar a configuração das demais.
        CAMP.set_prefixos("RIOCARD", ["", "dev-"])
        with (
            mock.patch("campaigns.os.fsync", side_effect=OSError("disco cheio")),
            self.assertRaises(CAMP.CampaignError),
        ):
            CAMP.set_prefixos("RIOCARD", ["", "prod-"])
        self.assertEqual(CAMP.prefixos_da_campanha("RIOCARD"), ["", "dev-"])


class TestAllowlist(Base):
    def test_recusa_prefixo_com_caractere_invalido(self):
        for ruim in ["dev/", "dev;", "dev ", "DEV-", "dev.", "de v", "dev$"]:
            with self.subTest(prefixo=ruim), self.assertRaises(CAMP.CampaignError):
                CAMP.set_prefixos("RIOCARD", ["", ruim])

    def test_recusa_tentativa_de_injecao_em_hostname(self):
        with self.assertRaises(CAMP.CampaignError):
            CAMP.set_prefixos("RIOCARD", ["evil.attacker.com/"])

    def test_recusa_prefixo_longo_demais(self):
        with self.assertRaises(CAMP.CampaignError):
            CAMP.set_prefixos("RIOCARD", ["x" * 21])

    def test_recusa_nome_de_campanha_invalido(self):
        with self.assertRaises(CAMP.CampaignError):
            CAMP.set_prefixos("../escape", [""])

    def test_prefixo_invalido_nao_grava_nada(self):
        CAMP.set_prefixos("RIOCARD", ["", "dev-"])
        with self.assertRaises(CAMP.CampaignError):
            CAMP.set_prefixos("RIOCARD", ["", "ruim/"])
        # a configuração anterior permanece intacta
        self.assertEqual(CAMP.prefixos_da_campanha("RIOCARD"), ["", "dev-"])

    def test_recusa_prefixo_com_quebra_de_linha(self):
        # `$` casa antes de um \n final: sem fullmatch, "dev-\n" passaria pela
        # allowlist e viraria hostname.
        with self.assertRaises(CAMP.CampaignError):
            CAMP.set_prefixos("RIOCARD", ["dev-\n"])

    def test_leitura_descarta_prefixo_com_quebra_de_linha(self):
        # Arquivo editado à mão no servidor não pode contrabandear o mesmo valor.
        CAMP.config_path().write_text(
            '{"RIOCARD": {"prefixos": ["", "dev-\\n"]}}', encoding="utf-8")
        self.assertEqual(CAMP.prefixos_da_campanha("RIOCARD"), [""])


if __name__ == "__main__":
    unittest.main()
