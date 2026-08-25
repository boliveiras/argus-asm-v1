"""Relatório tem de mostrar TODAS as campanhas, mesmo rodando uma por vez.

Bug observado em produção: o runner passou a executar campanha por campanha
(define ARGUS_CAMPANHA e chama os módulos em sequência). Os relatórios de
submonitor/credentials/email/typosquat eram montados a partir do resultado EM
MEMÓRIA da execução corrente e gravados sempre no MESMO arquivo do docroot —
logo, cada campanha sobrescrevia o relatório da anterior e sobrava no disco só
o da ÚLTIMA. Quem abria a tela de subdomínios via a campanha B e concluía que
a campanha A tinha sumido.

A correção segue o modelo que o monitor.py já usa (load_report_rows): montar a
entrada do relatório a partir do estado COMPLETO do banco, não do que esta
execução viu. O que a execução corrente descobriu entra por cima (overlay),
porque só ela tem os campos que o banco não guarda (enriquecimento de threat
intel no submonitor, URLs de apps no credentials, TXT bruto de SPF/DMARC no
email).

Cada teste roda a campanha A, depois a campanha B — isoladas, como em produção
— e exige que o relatório final contenha AS DUAS.
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


def _dias_atras(n: int) -> str:
    return (datetime.datetime.now() - datetime.timedelta(days=n)).strftime("%Y-%m-%d %H:%M:%S")


class _RelatorioMixin:
    """Bateria comum aos 4 scanners. Mixin (não TestCase) de propósito: assim o
    unittest só coleta as subclasses concretas, que sabem qual módulo carregar."""

    MODNAME = ""
    CHAVE = ""          # campo que identifica a linha (hostname / domain)

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

    # ── helpers ────────────────────────────────────────────────────────────
    def _conn(self):
        # Conexão sempre fechada explicitamente: no Windows um handle SQLite
        # aberto impede o TemporaryDirectory.cleanup() (WinError 32).
        return sqlite3.connect(self.mod.DATABASE_FILE)

    def _rodar(self, campanha, resultados):
        """Executa uma campanha isolada, como o runner faz em produção."""
        os.environ["ARGUS_CAMPANHA"] = campanha
        try:
            return self.mod.process_results(resultados)
        finally:
            os.environ.pop("ARGUS_CAMPANHA", None)

    def _chaves(self, *listas):
        return {r.get(self.CHAVE) for lst in listas for r in lst}

    def _campanhas(self, *listas):
        return {r.get("campanha") for lst in listas for r in lst}

    # ── testes comuns aos 4 scanners ───────────────────────────────────────
    def test_campanha_anterior_continua_no_relatorio(self):
        """O caso relatado pelo usuário: A roda, depois B roda sozinha — o
        relatório final tem de mostrar as duas, não só a última."""
        self._rodar("CAMP_A", [self._resultado("CAMP_A", "alfa")])
        novos_b, rein_b, rem_b = self._rodar("CAMP_B", [self._resultado("CAMP_B", "bravo")])

        n, r, c = self.mod.load_report_rows(novos_b + rein_b + rem_b)
        self.assertEqual(self._campanhas(n, r, c), {"CAMP_A", "CAMP_B"})
        chaves = str(sorted(self._chaves(n, r, c)))
        self.assertIn("alfa", chaves)
        self.assertIn("bravo", chaves)

    def test_ordem_inversa_tambem_mostra_as_duas(self):
        """Simetria: quem roda por último não pode ser o único visível."""
        self._rodar("CAMP_B", [self._resultado("CAMP_B", "bravo")])
        novos_a, rein_a, rem_a = self._rodar("CAMP_A", [self._resultado("CAMP_A", "alfa")])

        n, r, c = self.mod.load_report_rows(novos_a + rein_a + rem_a)
        self.assertEqual(self._campanhas(n, r, c), {"CAMP_A", "CAMP_B"})

    def test_separacao_novo_reincidente_vem_do_status_do_banco(self):
        """Rodar A duas vezes torna A REINCIDENTE; B, recém-vista, é NOVO."""
        self._rodar("CAMP_A", [self._resultado("CAMP_A", "alfa")])
        self._rodar("CAMP_A", [self._resultado("CAMP_A", "alfa")])
        novos_b, rein_b, rem_b = self._rodar("CAMP_B", [self._resultado("CAMP_B", "bravo")])

        n, r, _c = self.mod.load_report_rows(novos_b + rein_b + rem_b)
        self.assertEqual(self._campanhas(n), {"CAMP_B"})
        self.assertEqual(self._campanhas(r), {"CAMP_A"})

    def test_corrigido_recente_aparece_e_antigo_some(self):
        """Corrigidos entram por janela de tempo (CLOSED_WINDOW_DAYS), como no
        monitor — senão sumiriam do relatório assim que outra campanha rodasse,
        já que com escopo restrito process_results não fecha nada."""
        self._semear_corrigido("CAMP_A", "recente", _dias_atras(1))
        self._semear_corrigido("CAMP_A", "antigo", _dias_atras(self.mod.CLOSED_WINDOW_DAYS + 5))

        _n, _r, c = self.mod.load_report_rows([])
        chaves = str(sorted(self._chaves(c)))
        self.assertIn("recente", chaves)
        self.assertNotIn("antigo", chaves)

    def test_sem_campanha_restrita_o_relatorio_continua_completo(self):
        """Modo cron diário (sem ARGUS_CAMPANHA): tudo numa execução só."""
        novos, rein, rem = self.mod.process_results([
            self._resultado("CAMP_A", "alfa"), self._resultado("CAMP_B", "bravo")])
        n, r, c = self.mod.load_report_rows(novos + rein + rem)
        self.assertEqual(self._campanhas(n, r, c), {"CAMP_A", "CAMP_B"})

    def test_execucao_corrente_entra_por_cima_do_banco(self):
        """O relatório continua refletindo o que a execução acabou de achar:
        campos que o banco não guarda vêm do dict em memória."""
        novos, rein, rem = self._rodar("CAMP_A", [self._resultado("CAMP_A", "alfa")])
        for r in novos:
            r["marca_da_execucao"] = "sim"
        n, _r, _c = self.mod.load_report_rows(novos + rein + rem)
        self.assertTrue(any(x.get("marca_da_execucao") == "sim" for x in n))

    def test_overlay_nao_muda_o_dict_da_execucao(self):
        """O relatório recebe cópias: aplicar reconhecimento (ack) sobre a visão
        do relatório não pode reescrever o resultado que vai para o syslog."""
        novos, rein, rem = self._rodar("CAMP_A", [self._resultado("CAMP_A", "alfa")])
        n, _r, _c = self.mod.load_report_rows(novos + rein + rem)
        for x in n:
            x["risk"] = "INFO"
            x["status"] = "RECONHECIDO"
        self.assertTrue(all(o.get("status") == "NOVO" for o in novos))


# ══════════════════════════════════════════════════════════════════════════
class TestSubmonitor(_RelatorioMixin, unittest.TestCase):
    MODNAME = "submonitor"
    CHAVE = "hostname"

    def _resultado(self, campanha, chave):
        return {"campanha": campanha, "hostname": f"{chave}.exemplo.test", "ip": "203.0.113.9",
                "cname": "", "asn": "AS64500", "ip_type": "PUBLICO", "http_status": "200",
                "risk": "BAIXO"}

    def _semear_corrigido(self, campanha, chave, quando):
        conn = self._conn()
        conn.execute(
            "INSERT INTO subdomains (campanha,hostname,ip,cname,asn,ip_type,http_status,risk,"
            "first_seen,last_seen,status) VALUES (?,?,'','','','','','BAIXO',?,?,'CORRIGIDO')",
            (campanha, f"{chave}.exemplo.test", quando, quando))
        conn.commit(); conn.close()

    def test_campos_do_banco_chegam_no_formato_do_relatorio(self):
        """_submonitor_rows_to_js lê ssl/whois como sub-dicts — a conversão
        linha->resultado tem de devolver nesse formato, não colunas cruas."""
        self._rodar("CAMP_A", [dict(self._resultado("CAMP_A", "alfa"),
                                    dnssec="HABILITADO", origem="crt.sh",
                                    ssl={"status": "VALIDO", "expiry_date": "2030-01-01"},
                                    whois={"creation_date": "2010-05-04",
                                           "expiration_date": "2031-05-04",
                                           "age_days": 4000, "status": "ANTIGO",
                                           "registrar": "Registro.br"})])
        n, _r, _c = self.mod.load_report_rows([])
        self.assertEqual(len(n), 1)
        linha = n[0]
        self.assertEqual(linha["ssl"]["status"], "VALIDO")
        self.assertEqual(linha["whois"]["registrar"], "Registro.br")
        self.assertEqual(linha["whois"]["age_days"], 4000)
        self.assertEqual(linha["dnssec"], "HABILITADO")
        self.assertEqual(linha["origem"], "crt.sh")


class TestCredentials(_RelatorioMixin, unittest.TestCase):
    MODNAME = "credentials"
    CHAVE = "domain"

    def _resultado(self, campanha, chave):
        return {"campanha": campanha, "domain": f"{chave}.exemplo.test", "total": 3,
                "employees": 1, "users": 2, "third_parties": 0, "top_url": "https://app.test",
                "risk": "ALTO", "employees_urls": [], "clients_urls": [], "third_parties_urls": []}

    def _semear_corrigido(self, campanha, chave, quando):
        conn = self._conn()
        conn.execute(
            "INSERT INTO domains (campanha,domain,total,employees,users,third_parties,top_url,"
            "risk,first_seen,last_seen,status) VALUES (?,?,0,0,0,0,'','BAIXO',?,?,'CORRIGIDO')",
            (campanha, f"{chave}.exemplo.test", quando, quando))
        conn.commit(); conn.close()

    def test_contadores_do_banco_sao_inteiros(self):
        self._rodar("CAMP_A", [self._resultado("CAMP_A", "alfa")])
        n, _r, _c = self.mod.load_report_rows([])
        self.assertEqual(n[0]["total"], 3)
        self.assertEqual(n[0]["employees"], 1)
        self.assertEqual(n[0]["users"], 2)
        # O banco não guarda as URLs das apps expostas — devolve lista vazia,
        # nunca None (o relatório itera sobre elas).
        self.assertEqual(n[0]["employees_urls"], [])


class TestEmailauth(_RelatorioMixin, unittest.TestCase):
    MODNAME = "emailauth"
    CHAVE = "domain"

    def _resultado(self, campanha, chave):
        return {"campanha": campanha, "domain": f"{chave}.exemplo.test", "has_mx": True,
                "mx": "mx.exemplo.test", "spf_status": "AUSENTE", "spf_raw": "",
                "dmarc_status": "NONE", "dmarc_raw": "v=DMARC1; p=none",
                "dkim_status": "AUSENTE", "dkim_selector": "", "risk": "ALTO",
                "issues": ["Sem SPF", "DMARC p=none"]}

    def _semear_corrigido(self, campanha, chave, quando):
        conn = self._conn()
        conn.execute(
            "INSERT INTO domains (campanha,domain,has_mx,mx,spf_status,dmarc_status,dkim_status,"
            "dkim_selector,risk,issues,first_seen,last_seen,status) "
            "VALUES (?,?,0,'','','','','','INFO','',?,?,'CORRIGIDO')",
            (campanha, f"{chave}.exemplo.test", quando, quando))
        conn.commit(); conn.close()

    def test_issues_voltam_como_lista(self):
        """process_results grava issues como texto 'a | b'; o relatório espera lista."""
        self._rodar("CAMP_A", [self._resultado("CAMP_A", "alfa")])
        n, _r, _c = self.mod.load_report_rows([])
        self.assertEqual(n[0]["issues"], ["Sem SPF", "DMARC p=none"])
        self.assertIs(n[0]["has_mx"], True)


class TestTyposquat(_RelatorioMixin, unittest.TestCase):
    MODNAME = "typosquat"
    CHAVE = "domain"

    def _resultado(self, campanha, chave):
        return {"campanha": campanha, "base_domain": "exemplo.test",
                "domain": f"{chave}-exemplo.test", "fuzzer": "omission",
                "ip": "203.0.113.7", "mx": True, "risk": "CRITICO",
                "whois_status": "NOVO", "whois_creation": "2026-01-02", "whois_age_days": 30}

    def _semear_corrigido(self, campanha, chave, quando):
        conn = self._conn()
        conn.execute(
            "INSERT INTO lookalikes (campanha,base_domain,domain,fuzzer,ip,mx,risk,"
            "first_seen,last_seen,status) VALUES (?,'exemplo.test',?,'','',0,'INFO',?,?,'CORRIGIDO')",
            (campanha, f"{chave}-exemplo.test", quando, quando))
        conn.commit(); conn.close()

    def test_mx_volta_booleano_e_whois_preservado(self):
        self._rodar("CAMP_A", [self._resultado("CAMP_A", "alfa")])
        n, _r, _c = self.mod.load_report_rows([])
        self.assertIs(n[0]["mx"], True)
        self.assertEqual(n[0]["whois_status"], "NOVO")
        self.assertEqual(n[0]["whois_age_days"], 30)
        self.assertEqual(n[0]["base_domain"], "exemplo.test")


if __name__ == "__main__":
    unittest.main()
