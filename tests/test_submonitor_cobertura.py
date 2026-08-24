"""Cobertura parcial do submonitor: quando uma fonte de descoberta passiva
(crt.sh/crt.name) falha, o operador precisa SABER — não pode ler "0 crt.sh"
como "esse domínio não tem certificado" quando na verdade a fonte estava fora
do ar (bug observado em produção: crt.sh devolvendo HTTP 502).

Cobre:
  - _build_candidates propaga o motivo da falha por (fonte, domínio)
  - _build_candidates não reporta falha nenhuma quando tudo funciona
  - syslog_end registra a cobertura (completa/parcial) no evento SCAN_END
"""

import os
import sys
import tempfile
import types
import unittest

sys.modules.setdefault("nmap", types.ModuleType("nmap"))
sys.path.insert(0, "core")
sys.path.insert(0, "scanners")


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        os.environ.pop("ARGUS_DB", None)
        os.environ["ARGUS_BASE"] = self.tmp.name
        import submonitor as SUB
        self.SUB = SUB

    def tearDown(self):
        self.tmp.cleanup()


class TestBuildCandidatesFalhas(Base):
    def setUp(self):
        super().setUp()
        self.SUB._CRTSH_AVAILABLE = True
        self.SUB._CRTNAME_AVAILABLE = True
        self.SUB._URLSCAN_AVAILABLE = False
        self.SUB._fonte_ligada = lambda pid: True

    def test_falha_do_crtsh_e_reportada_sem_virar_zero_mudo(self):
        class FakeCrtsh:
            @staticmethod
            def get_subdomains_safe_ex(domain):
                return set(), "HTTP 502"
        self.SUB.crtsh = FakeCrtsh

        class FakeCrtname:
            @staticmethod
            def get_subdomains_safe_ex(domain):
                return set(), None
        self.SUB.crtname = FakeCrtname

        cands, falhas = self.SUB._build_candidates(
            [("RIOCARD", ["empresa.com"])], ["www"])

        self.assertEqual(len(falhas), 1)
        self.assertEqual(falhas[0]["fonte"], "CRT.SH")
        self.assertEqual(falhas[0]["domain"], "empresa.com")
        self.assertIn("502", falhas[0]["motivo"])

    def test_sucesso_com_zero_nomes_nao_gera_falha(self):
        class FakeSemFalha:
            @staticmethod
            def get_subdomains_safe_ex(domain):
                return set(), None
        self.SUB.crtsh = FakeSemFalha
        self.SUB.crtname = FakeSemFalha

        cands, falhas = self.SUB._build_candidates(
            [("RIOCARD", ["empresa.com"])], ["www"])

        self.assertEqual(falhas, [])

    def test_falha_de_duas_fontes_gera_duas_entradas(self):
        class FakeFalha:
            @staticmethod
            def get_subdomains_safe_ex(domain):
                return set(), "timeout"
        self.SUB.crtsh = FakeFalha
        self.SUB.crtname = FakeFalha

        cands, falhas = self.SUB._build_candidates(
            [("RIOCARD", ["empresa.com"])], ["www"])

        fontes = sorted(f["fonte"] for f in falhas)
        self.assertEqual(fontes, ["CRT.NAME", "CRT.SH"])

    def test_achados_reais_continuam_entrando_nos_candidatos(self):
        class FakeCrtsh:
            @staticmethod
            def get_subdomains_safe_ex(domain):
                return {"api.empresa.com"}, None
        self.SUB.crtsh = FakeCrtsh

        class FakeCrtname:
            @staticmethod
            def get_subdomains_safe_ex(domain):
                return set(), None
        self.SUB.crtname = FakeCrtname

        cands, falhas = self.SUB._build_candidates(
            [("RIOCARD", ["empresa.com"])], ["www"])

        self.assertIn(("api.empresa.com", "RIOCARD"), cands)
        self.assertEqual(cands[("api.empresa.com", "RIOCARD")], "crtsh")
        self.assertEqual(falhas, [])


class TestSyslogEndCobertura(Base):
    def setUp(self):
        super().setUp()
        self.chamadas = []
        self.SUB.syslog_write = lambda severity, msgid, msg, **sd: \
            self.chamadas.append((severity, msgid, msg, sd))
        self.SUB._syslog_fd = None  # _syslog_close() vira no-op

    def _scan_end_kwargs(self):
        for severity, msgid, msg, sd in self.chamadas:
            if msgid == "SCAN_END":
                return severity, msg, sd
        raise AssertionError("SCAN_END não foi emitido")

    def test_sem_falhas_marca_cobertura_completa(self):
        self.SUB.syslog_end([], [], [], 5, partial_failures=[])
        severity, msg, sd = self._scan_end_kwargs()
        self.assertEqual(sd.get("cobertura"), "COMPLETA")
        self.assertEqual(severity, "INFO")

    def test_com_falha_marca_cobertura_parcial_e_lista_fontes(self):
        falhas = [{"fonte": "CRT.SH", "domain": "empresa.com", "motivo": "HTTP 502"}]
        self.SUB.syslog_end([], [], [], 5, partial_failures=falhas)
        severity, msg, sd = self._scan_end_kwargs()
        self.assertEqual(sd.get("cobertura"), "PARCIAL")
        self.assertIn("CRT.SH", sd.get("fontes_falhas", ""))

    def test_falha_eleva_severidade_de_info_para_warn(self):
        # Sem isso, cobertura parcial fica enterrada em severidade INFO — quem
        # filtra o syslog por WARN+ (o caso comum) nunca veria o problema.
        falhas = [{"fonte": "CRT.SH", "domain": "empresa.com", "motivo": "HTTP 502"}]
        self.SUB.syslog_end([], [], [], 5, status="success", partial_failures=falhas)
        severity, _msg, _sd = self._scan_end_kwargs()
        self.assertEqual(severity, "WARN")

    def test_falha_nao_rebaixa_severidade_de_erro_real(self):
        falhas = [{"fonte": "CRT.SH", "domain": "empresa.com", "motivo": "HTTP 502"}]
        self.SUB.syslog_end([], [], [], 5, status="error", partial_failures=falhas)
        severity, _msg, _sd = self._scan_end_kwargs()
        self.assertEqual(severity, "ERR")

    def test_sem_partial_failures_nao_quebra_compat(self):
        # Chamada antiga (sem o novo parâmetro) precisa continuar funcionando —
        # ex.: o branch de exceção em main() ainda chama assim.
        self.SUB.syslog_end([], [], [], 5)
        severity, msg, sd = self._scan_end_kwargs()
        self.assertEqual(sd.get("cobertura"), "COMPLETA")


if __name__ == "__main__":
    unittest.main()
