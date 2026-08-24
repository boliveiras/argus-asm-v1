"""O submonitor precisa respeitar os prefixos configurados por campanha.

É o corte de volume que evita o scan arrastar até o timeout: com a wordlist
inteira multiplicada por 5, 2000 palavras viram 10.000 consultas por domínio.
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
        # campaigns._base() prioriza ARGUS_DB sobre ARGUS_BASE; test_logpush_api.py
        # seta ARGUS_DB e não limpa no tearDown. Sem isso, quando este arquivo roda
        # depois (ordem alfabética coloca "submonitor" por último), o valor deixado
        # para trás vaza e os testes deste arquivo passam a compartilhar estado
        # entre si em vez de cada um usar seu próprio diretório temporário.
        os.environ.pop("ARGUS_DB", None)
        os.environ["ARGUS_BASE"] = self.tmp.name
        import campaigns as CAMP
        import submonitor as SUB
        self.CAMP, self.SUB = CAMP, SUB
        # Sem provedores passivos: aqui interessa só a combinação da wordlist.
        SUB._CRTSH_AVAILABLE = False
        SUB._CRTNAME_AVAILABLE = False
        SUB._URLSCAN_AVAILABLE = False

    def tearDown(self):
        self.tmp.cleanup()

    def hosts(self, campanha="RIOCARD"):
        cands, _falhas = self.SUB._build_candidates([(campanha, ["empresa.com"])], ["www", "api"])
        return sorted(h for (h, _c) in cands)


class TestPrefixos(Base):
    def test_sem_config_usa_os_cinco_padroes(self):
        # 2 palavras x 5 prefixos = 10 candidatos
        self.assertEqual(len(self.hosts()), 10)
        self.assertIn("dev-www.empresa.com", self.hosts())

    def test_prefixos_desligados_geram_so_a_palavra_pura(self):
        self.CAMP.set_prefixos("RIOCARD", [""])
        hosts = self.hosts()
        self.assertEqual(hosts, ["api.empresa.com", "www.empresa.com"])

    def test_config_de_uma_campanha_nao_vaza_para_outra(self):
        self.CAMP.set_prefixos("RIOCARD", [""])
        self.assertEqual(len(self.hosts("RIOCARD")), 2)
        self.assertEqual(len(self.hosts("OUTRA")), 10)

    def test_prefixo_customizado_entra_na_combinacao(self):
        self.CAMP.set_prefixos("RIOCARD", ["", "qa-"])
        hosts = self.hosts()
        self.assertIn("qa-www.empresa.com", hosts)
        self.assertNotIn("dev-www.empresa.com", hosts)


if __name__ == "__main__":
    unittest.main()
