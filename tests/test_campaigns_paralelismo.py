"""Paralelismo da varredura TCP, configurado por campanha.

O valor vira número de varreduras simultâneas contra alvos reais. Fora da faixa
não é só configuração errada: 20 nmaps concorrentes derrubam a medição (porta
aberta vira 'filtered' sob perda de pacote) e chamam atenção do alvo. Por isso a
faixa é validada no servidor, e o default é 1 — série, como sempre foi.
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, "core")
import campaigns as CAMP  # noqa: E402


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        os.environ["ARGUS_BASE"] = self.tmp.name
        os.environ.pop("ARGUS_DB", None)     # tem prioridade sobre ARGUS_BASE

    def tearDown(self):
        self.tmp.cleanup()


class TestPadrao(Base):
    def test_campanha_sem_config_roda_em_serie(self):
        # Retrocompatibilidade: quem não configurou nada não muda de comportamento.
        self.assertEqual(CAMP.paralelismo_da_campanha("PRODATA"), 1)

    def test_valor_invalido_no_arquivo_cai_para_serie(self):
        # Editado à mão no servidor: não pode virar 20 varreduras simultâneas.
        CAMP.config_path().write_text(
            '{"PRODATA": {"paralelismo_tcp": 20}}', encoding="utf-8")
        self.assertEqual(CAMP.paralelismo_da_campanha("PRODATA"), 1)

    def test_texto_no_lugar_do_numero_cai_para_serie(self):
        CAMP.config_path().write_text(
            '{"PRODATA": {"paralelismo_tcp": "cinco"}}', encoding="utf-8")
        self.assertEqual(CAMP.paralelismo_da_campanha("PRODATA"), 1)

    def test_arquivo_corrompido_cai_para_serie(self):
        CAMP.config_path().write_text("{ nao e json", encoding="utf-8")
        self.assertEqual(CAMP.paralelismo_da_campanha("PRODATA"), 1)


class TestGravacao(Base):
    def test_grava_e_le_de_volta(self):
        CAMP.set_paralelismo("PRODATA", 3)
        self.assertEqual(CAMP.paralelismo_da_campanha("PRODATA"), 3)

    def test_aceita_os_extremos_da_faixa(self):
        for v in (CAMP.PARALELISMO_TCP_MIN, CAMP.PARALELISMO_TCP_MAX):
            CAMP.set_paralelismo("PRODATA", v)
            self.assertEqual(CAMP.paralelismo_da_campanha("PRODATA"), v)

    def test_uma_campanha_nao_afeta_outra(self):
        CAMP.set_paralelismo("PRODATA", 4)
        self.assertEqual(CAMP.paralelismo_da_campanha("OUTRA"), 1)

    def test_convive_com_a_configuracao_de_prefixos(self):
        # As duas chaves moram no mesmo dict da campanha; uma não apaga a outra.
        CAMP.set_prefixos("PRODATA", ["", "dev-"])
        CAMP.set_paralelismo("PRODATA", 2)
        self.assertEqual(CAMP.prefixos_da_campanha("PRODATA"), ["", "dev-"])
        self.assertEqual(CAMP.paralelismo_da_campanha("PRODATA"), 2)

    def test_aceita_numero_em_texto(self):
        # A interface manda string; o servidor normaliza.
        CAMP.set_paralelismo("PRODATA", "3")
        self.assertEqual(CAMP.paralelismo_da_campanha("PRODATA"), 3)


class TestValidacao(Base):
    def test_recusa_acima_do_teto(self):
        with self.assertRaises(CAMP.CampaignError):
            CAMP.set_paralelismo("PRODATA", CAMP.PARALELISMO_TCP_MAX + 1)

    def test_recusa_zero_e_negativo(self):
        for v in (0, -1):
            with self.subTest(valor=v), self.assertRaises(CAMP.CampaignError):
                CAMP.set_paralelismo("PRODATA", v)

    def test_recusa_texto_nao_numerico(self):
        with self.assertRaises(CAMP.CampaignError):
            CAMP.set_paralelismo("PRODATA", "muito")

    def test_recusa_nome_de_campanha_invalido(self):
        with self.assertRaises(CAMP.CampaignError):
            CAMP.set_paralelismo("../escape", 2)

    def test_valor_invalido_nao_grava_nada(self):
        CAMP.set_paralelismo("PRODATA", 3)
        with self.assertRaises(CAMP.CampaignError):
            CAMP.set_paralelismo("PRODATA", 99)
        self.assertEqual(CAMP.paralelismo_da_campanha("PRODATA"), 3)


if __name__ == "__main__":
    unittest.main()
