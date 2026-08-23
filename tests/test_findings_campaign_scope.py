"""Achados de OUTRAS campanhas não podem ser fechados quando a execução está
restrita a uma campanha (ARGUS_CAMPANHA).

Contexto: o runner passou a rodar campanha por campanha (core/runner.py define
ARGUS_CAMPANHA e chama os módulos uma campanha de cada vez). Os scanners
sincronizam o resultado com o store central via findings.sync_findings(), que
por baixo chama mark_absent() — e mark_absent() fecha (active=0) TODO achado
ativo da origem que não apareceu em `seen`. Com a execução restrita, `seen` só
tem os hosts/domínios DESSA campanha: sem proteção, achados ativos de outras
campanhas (que não rodaram nesta execução) seriam fechados como se tivessem
sido corrigidos — um falso "corrigido" que na verdade é só uma falha de
infraestrutura (ex.: runner abortou após 2 campanhas falhando seguidas).

Este arquivo cobre dois níveis:
  1. O mecanismo geral (findings.sync_findings/mark_absent com scope_predicate),
     usado pelos 4 scanners exatamente como o monitor.py já usa para não misturar
     TCP/UDP.
  2. O fechamento "local" que cada scanner faz na própria tabela (subdomains/
     domains/lookalikes) antes mesmo de chegar no store central — mesmo bug,
     mesma correção (ver process_results() em cada scanner).
"""

import datetime
import os
import sqlite3
import sys
import tempfile
import types
import unittest

sys.modules.setdefault("nmap", types.ModuleType("nmap"))
sys.path.insert(0, "core")
sys.path.insert(0, "scanners")

import findings as FIND  # noqa: E402


def _dias_atras(n: int) -> str:
    return (datetime.datetime.now() - datetime.timedelta(days=n)).strftime("%Y-%m-%d %H:%M:%S")


class TestSyncFindingsEscopoDeCampanha(unittest.TestCase):
    """Mecanismo geral — a peça que os 4 scanners usam (scope_predicate)."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tmp.name, "argus.db")

    def tearDown(self):
        self.tmp.cleanup()

    def _semear(self):
        repo = FIND.FindingRepository(self.db_path)
        try:
            # Dois achados antigos (fora da carência), um de cada campanha.
            repo.upsert("submonitor", "riocard.empresa.com", severity="BAIXO",
                       campanha="RIOCARD", ts=_dias_atras(10))
            repo.upsert("submonitor", "outra.empresa2.com", severity="BAIXO",
                       campanha="OUTRA", ts=_dias_atras(10))
        finally:
            repo.close()

    def test_com_predicado_bloqueado_nao_fecha_nenhuma_campanha(self):
        # É exatamente o que os scanners passam quando ARGUS_CAMPANHA está
        # definida: scope_predicate=lambda k: False.
        self._semear()
        obs, closed = FIND.sync_findings(
            "submonitor", [{"hostname": "riocard.empresa.com", "risk": "BAIXO",
                            "campanha": "RIOCARD"}],
            key_of=lambda r: r["hostname"], severity_of=lambda r: r["risk"],
            campanha_of=lambda r: r["campanha"],
            scope_predicate=lambda k: False,
            db_path=self.db_path)
        self.assertEqual(closed, 0)
        repo = FIND.FindingRepository(self.db_path)
        try:
            ativos = {row[0] for row in repo._conn.execute(
                "SELECT natural_key FROM findings WHERE active=1")}
        finally:
            repo.close()
        self.assertIn("outra.empresa2.com", ativos, "achado de outra campanha foi fechado")

    def test_sem_predicado_fecha_como_antes(self):
        # Sem restrição (scope_predicate=None), o comportamento é o de sempre:
        # quem sumiu da varredura completa é fechado.
        self._semear()
        obs, closed = FIND.sync_findings(
            "submonitor", [{"hostname": "riocard.empresa.com", "risk": "BAIXO",
                            "campanha": "RIOCARD"}],
            key_of=lambda r: r["hostname"], severity_of=lambda r: r["risk"],
            campanha_of=lambda r: r["campanha"],
            db_path=self.db_path)
        self.assertEqual(closed, 1)
        repo = FIND.FindingRepository(self.db_path)
        try:
            ativos = {row[0] for row in repo._conn.execute(
                "SELECT natural_key FROM findings WHERE active=1")}
        finally:
            repo.close()
        self.assertNotIn("outra.empresa2.com", ativos)


class _ScannerScopeBase(unittest.TestCase):
    """Base comum: isola DATABASE_FILE num tmpdir e limpa ARGUS_CAMPANHA."""

    MODNAME = ""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        os.environ.pop("ARGUS_CAMPANHA", None)
        import importlib
        self.mod = importlib.import_module(self.MODNAME)
        self._orig_db = self.mod.DATABASE_FILE
        self.mod.DATABASE_FILE = os.path.join(self.tmp.name, f"{self.MODNAME}.db")
        self.mod.init_database()

    def tearDown(self):
        os.environ.pop("ARGUS_CAMPANHA", None)
        self.mod.DATABASE_FILE = self._orig_db
        self.tmp.cleanup()

    def _conn(self):
        return sqlite3.connect(self.mod.DATABASE_FILE)

    def _query_one(self, sql):
        # Conexão fechada explicitamente: no Windows um handle de arquivo SQLite
        # aberto impede o TemporaryDirectory.cleanup() no tearDown (WinError 32).
        conn = self._conn()
        try:
            row = conn.execute(sql).fetchone()
            return row[0] if row else None
        finally:
            conn.close()


class TestSubmonitorProcessResultsEscopo(_ScannerScopeBase):
    MODNAME = "submonitor"

    def _seed_outra(self):
        conn = self._conn()
        conn.execute(
            "INSERT INTO subdomains (campanha,hostname,ip,cname,asn,ip_type,http_status,risk,"
            "first_seen,last_seen,status) VALUES ('OUTRA','outra.empresa2.com','','','','','',"
            "'BAIXO',?,?,'REINCIDENTE')", (_dias_atras(10), _dias_atras(10)))
        conn.commit(); conn.close()

    def _resultado_riocard(self):
        return [{"hostname": "riocard.empresa.com", "ip": "", "cname": "", "asn": "",
                 "ip_type": "", "http_status": "", "risk": "BAIXO", "campanha": "RIOCARD"}]

    def test_com_campanha_restrita_nao_fecha_host_de_outra_campanha(self):
        self._seed_outra()
        os.environ["ARGUS_CAMPANHA"] = "RIOCARD"
        novos, reincidentes, removidos = self.mod.process_results(self._resultado_riocard())
        self.assertEqual(removidos, [])
        status = self._query_one(
            "SELECT status FROM subdomains WHERE hostname='outra.empresa2.com'")
        self.assertEqual(status, "REINCIDENTE")

    def test_sem_restricao_fecha_como_antes(self):
        self._seed_outra()
        novos, reincidentes, removidos = self.mod.process_results(self._resultado_riocard())
        self.assertEqual(len(removidos), 1)
        status = self._query_one(
            "SELECT status FROM subdomains WHERE hostname='outra.empresa2.com'")
        self.assertEqual(status, "CORRIGIDO")


class TestCredentialsProcessResultsEscopo(_ScannerScopeBase):
    MODNAME = "credentials"

    def _seed_outra(self):
        conn = self._conn()
        conn.execute(
            "INSERT INTO domains (campanha,domain,total,employees,users,third_parties,top_url,"
            "risk,first_seen,last_seen,status) VALUES ('OUTRA','outra2.com',3,1,1,1,'',"
            "'MEDIO',?,?,'REINCIDENTE')", (_dias_atras(10), _dias_atras(10)))
        conn.commit(); conn.close()

    def _resultado_riocard(self):
        return [{"domain": "riocard.com", "campanha": "RIOCARD", "risk": "BAIXO",
                 "total": 0, "employees": 0, "users": 0, "third_parties": 0, "top_url": ""}]

    def test_com_campanha_restrita_nao_fecha_dominio_de_outra_campanha(self):
        self._seed_outra()
        os.environ["ARGUS_CAMPANHA"] = "RIOCARD"
        novos, reincidentes, removidos = self.mod.process_results(self._resultado_riocard())
        self.assertEqual(removidos, [])
        status = self._query_one(
            "SELECT status FROM domains WHERE domain='outra2.com'")
        self.assertEqual(status, "REINCIDENTE")

    def test_sem_restricao_fecha_como_antes(self):
        self._seed_outra()
        novos, reincidentes, removidos = self.mod.process_results(self._resultado_riocard())
        self.assertEqual(len(removidos), 1)
        status = self._query_one(
            "SELECT status FROM domains WHERE domain='outra2.com'")
        self.assertEqual(status, "CORRIGIDO")


class TestEmailauthProcessResultsEscopo(_ScannerScopeBase):
    MODNAME = "emailauth"

    def _seed_outra(self):
        conn = self._conn()
        conn.execute(
            "INSERT INTO domains (campanha,domain,has_mx,mx,spf_status,dmarc_status,dkim_status,"
            "dkim_selector,risk,issues,first_seen,last_seen,status) VALUES "
            "('OUTRA','outra2.com',1,'mx.outra2.com','OK','OK','OK','','INFO','',?,?,'REINCIDENTE')",
            (_dias_atras(10), _dias_atras(10)))
        conn.commit(); conn.close()

    def _resultado_riocard(self):
        return [{"domain": "riocard.com", "campanha": "RIOCARD", "has_mx": True,
                 "mx": "mx.riocard.com", "spf_status": "OK", "dmarc_status": "OK",
                 "dkim_status": "OK", "dkim_selector": "", "risk": "INFO", "issues": []}]

    def test_com_campanha_restrita_nao_fecha_dominio_de_outra_campanha(self):
        self._seed_outra()
        os.environ["ARGUS_CAMPANHA"] = "RIOCARD"
        novos, reincidentes, removidos = self.mod.process_results(self._resultado_riocard())
        self.assertEqual(removidos, [])
        status = self._query_one(
            "SELECT status FROM domains WHERE domain='outra2.com'")
        self.assertEqual(status, "REINCIDENTE")

    def test_sem_restricao_fecha_como_antes(self):
        self._seed_outra()
        novos, reincidentes, removidos = self.mod.process_results(self._resultado_riocard())
        self.assertEqual(len(removidos), 1)
        status = self._query_one(
            "SELECT status FROM domains WHERE domain='outra2.com'")
        self.assertEqual(status, "CORRIGIDO")


class TestTyposquatProcessResultsEscopo(_ScannerScopeBase):
    MODNAME = "typosquat"

    def _seed_outra(self):
        conn = self._conn()
        conn.execute(
            "INSERT INTO lookalikes (campanha,base_domain,domain,fuzzer,ip,mx,risk,first_seen,"
            "last_seen,status) VALUES ('OUTRA','outra2.com','0utra2.com','homoglyph','',0,"
            "'MEDIO',?,?,'REINCIDENTE')", (_dias_atras(10), _dias_atras(10)))
        conn.commit(); conn.close()

    def _resultado_riocard(self):
        return [{"domain": "r10card.com", "campanha": "RIOCARD", "base_domain": "riocard.com",
                 "fuzzer": "homoglyph", "ip": "", "mx": False, "risk": "MEDIO"}]

    def test_com_campanha_restrita_nao_fecha_dominio_de_outra_campanha(self):
        self._seed_outra()
        os.environ["ARGUS_CAMPANHA"] = "RIOCARD"
        novos, reincidentes, removidos = self.mod.process_results(self._resultado_riocard())
        self.assertEqual(removidos, [])
        status = self._query_one(
            "SELECT status FROM lookalikes WHERE domain='0utra2.com'")
        self.assertEqual(status, "REINCIDENTE")

    def test_sem_restricao_fecha_como_antes(self):
        self._seed_outra()
        novos, reincidentes, removidos = self.mod.process_results(self._resultado_riocard())
        self.assertEqual(len(removidos), 1)
        status = self._query_one(
            "SELECT status FROM lookalikes WHERE domain='0utra2.com'")
        self.assertEqual(status, "CORRIGIDO")


if __name__ == "__main__":
    unittest.main()
