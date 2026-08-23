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


class TestNomeDeCampanha(Base):
    """O nome da campanha vira nome de arquivo (targets/<NOME>.txt) e chave do
    campaigns.json. Validar uma string e usar OUTRA escancara justamente a porta
    que a allowlist existe para fechar."""

    def test_recusa_nome_com_quebra_de_linha(self):
        # `$` casa também antes de um \n final: com .match() — e com o strip()
        # que valid_name dava por dentro — "RIOCARD\n" era aprovado.
        self.assertFalse(CAMP.valid_name("RIOCARD\n"))
        self.assertTrue(CAMP.valid_name("RIOCARD"))

    def test_valid_name_nao_normaliza_por_conta_propria(self):
        # Quem valida não pode limpar em silêncio: o chamador seguia usando o
        # texto cru. Tolerância a espaço é trabalho de normalize_name().
        self.assertFalse(CAMP.valid_name(" RIOCARD "))
        self.assertEqual(CAMP.normalize_name(" RIOCARD \n"), "RIOCARD")

    def test_caminho_do_txt_nao_carrega_quebra_de_linha(self):
        # Antes: targets/RIOCARD\n.txt — arquivo distinto do da campanha real.
        caminho = CAMP._campaign_path("monitor", "RIOCARD\n", self.tmp.name)
        self.assertEqual(caminho.name, "RIOCARD.txt")

    def test_quebra_de_linha_no_meio_do_nome_continua_recusada(self):
        with self.assertRaises(CAMP.CampaignError):
            CAMP._campaign_path("monitor", "RIO\nCARD", self.tmp.name)

    def test_chave_do_campaigns_json_nao_carrega_quebra_de_linha(self):
        # Antes gravava sob "RIOCARD\n": uma segunda campanha, invisível na
        # interface, sombreando a configuração da verdadeira.
        CAMP.set_prefixos("RIOCARD\n", ["dev-"])
        self.assertEqual(list(CAMP.ler_config()), ["RIOCARD"])
        self.assertEqual(CAMP.prefixos_da_campanha("RIOCARD"), ["dev-"])


if __name__ == "__main__":
    unittest.main()
