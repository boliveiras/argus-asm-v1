"""Loop por campanha: cada uma do início ao fim, persistindo antes da próxima.

O ponto do redesenho é não perder trabalho: se a terceira campanha falha, as
duas primeiras já estão salvas no banco.
"""

import importlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, "core")


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        # ARGUS_DB tem prioridade sobre ARGUS_BASE em campaigns._base(); sem
        # limpar, um ARGUS_DB deixado por outro arquivo de teste (rodando a
        # suíte inteira, não só este arquivo) faz list_campaigns() olhar para
        # um diretório errado (já apagado) e o loop cair no modo antigo.
        os.environ.pop("ARGUS_DB", None)
        os.environ["ARGUS_BASE"] = self.tmp.name
        base = Path(self.tmp.name)
        # Sem apontar para dentro do tmp dir, _gravar_saida tentaria escrever no
        # /var/log/argus/scan REAL a cada etapa simulada — inofensivo no Windows
        # (falha calada), mas em Linux como root a suíte escreveria no diretório
        # de log de produção.
        os.environ["ARGUS_SCAN_LOG_DIR"] = str(base / "scanlog")
        (base / "store").mkdir(parents=True, exist_ok=True)
        # Caso normal: a campanha existe nos DOIS escopos, porque a etapa de
        # subdomínios cria automaticamente o arquivo de IPs correspondente.
        alvos = base / "submonitor" / "targets"
        alvos.mkdir(parents=True, exist_ok=True)
        ips = base / "monitor" / "targets"
        ips.mkdir(parents=True, exist_ok=True)
        for nome in ("ALPHA", "BETA", "GAMA"):
            (alvos / f"{nome}.txt").write_text("empresa.com\n", encoding="utf-8")
            (ips / f"{nome}.txt").write_text("10.0.0.1\n", encoding="utf-8")
        import runner
        # BASE_DIR/STORE_DIR são constantes de módulo lidas de ARGUS_BASE na
        # importação. Sem recarregar, o segundo teste em diante herdaria o
        # caminho (já apagado) do primeiro, porque `import` não repete depois
        # que o módulo já está em sys.modules.
        importlib.reload(runner)
        self.runner = runner
        self.executadas = []

    def tearDown(self):
        self.tmp.cleanup()
        os.environ.pop("ARGUS_BASE", None)
        os.environ.pop("ARGUS_SCAN_LOG_DIR", None)
        os.environ.pop("ARGUS_CAMPANHA", None)

    def fingir_execucao(self, resultado_por_campanha):
        """Substitui a execução real do subprocess por um dublê.

        Devolve rc=0 ou rc=1 conforme o mapa {campanha: True/False}, registrando
        a ordem em que campanha e etapa foram chamadas. Usa patch.object (com
        addCleanup) em vez de atribuir direto em self.runner.subprocess.run: esse
        atributo é o objeto-módulo `subprocess`, COMPARTILHADO entre todos os
        arquivos de teste — atribuir sem restaurar vaza o dublê para a suíte
        inteira (mesma classe de vazamento já vista com ARGUS_DB).
        """
        registro = self.executadas

        class FakeProc:
            def __init__(self, rc):
                self.returncode = rc
                self.stdout = "saída de teste"

        def fake_run(cmd, **kw):
            campanha = os.environ.get("ARGUS_CAMPANHA", "")
            registro.append((campanha, Path(cmd[0]).name))
            ok = resultado_por_campanha.get(campanha, True)
            return FakeProc(0 if ok else 1)

        patcher = mock.patch.object(self.runner.subprocess, "run", fake_run)
        patcher.start()
        self.addCleanup(patcher.stop)

    def status(self):
        return json.loads((Path(self.tmp.name) / "store" / "scan_status.json")
                          .read_text(encoding="utf-8"))


class TestLoop(Base):
    def test_roda_cada_campanha_do_inicio_ao_fim(self):
        self.fingir_execucao({})
        self.runner.run_all("teste")
        # Cada campanha aparece com os 6 módulos ANTES da campanha seguinte começar
        campanhas_na_ordem = [c for c, _cmd in self.executadas]
        self.assertEqual(campanhas_na_ordem[:6], ["ALPHA"] * 6)
        self.assertEqual(campanhas_na_ordem[6:12], ["BETA"] * 6)
        self.assertEqual(campanhas_na_ordem[12:18], ["GAMA"] * 6)

    def test_estado_registra_progresso_por_campanha(self):
        self.fingir_execucao({})
        self.runner.run_all("teste")
        st = self.status()
        self.assertEqual(st["campanhas_total"], 3)
        self.assertEqual([c["status"] for c in st["campanhas"]],
                         ["succeeded"] * 3)
        self.assertEqual(st["percent"], 100)
        self.assertFalse(st["running"])

    def test_campanha_que_falha_nao_impede_as_seguintes(self):
        self.fingir_execucao({"BETA": False})
        self.runner.run_all("teste")
        st = self.status()
        self.assertEqual([c["status"] for c in st["campanhas"]],
                         ["succeeded", "failed", "succeeded"])
        # GAMA rodou mesmo com BETA falhando
        self.assertIn("GAMA", [c for c, _ in self.executadas])

    def test_campanha_especifica_nao_entra_no_loop(self):
        self.fingir_execucao({})
        self.runner.run_all("teste", campanha="BETA")
        self.assertEqual({c for c, _ in self.executadas}, {"BETA"})
        st = self.status()
        self.assertEqual(st["campanha"], "BETA")

    def test_argus_campanha_e_limpa_ao_final(self):
        # O tearDown faz pop() de ARGUS_CAMPANHA — sem esta asserção, uma
        # regressão que deixasse a variável vazando entre execuções passaria
        # despercebida (o pop no tearDown mascararia o vazamento).
        self.fingir_execucao({})
        self.runner.run_all("teste")
        self.assertNotIn("ARGUS_CAMPANHA", os.environ)


class TestAbort(Base):
    def test_duas_falhas_seguidas_abortam_o_restante(self):
        self.fingir_execucao({"ALPHA": False, "BETA": False})
        self.runner.run_all("teste")
        st = self.status()
        self.assertEqual([c["status"] for c in st["campanhas"]],
                         ["failed", "failed", "skipped"])
        # GAMA NÃO chegou a rodar
        self.assertNotIn("GAMA", [c for c, _ in self.executadas])

    def test_falhas_alternadas_nao_abortam(self):
        # falha, sucesso, falha — nunca duas seguidas
        self.fingir_execucao({"ALPHA": False, "GAMA": False})
        self.runner.run_all("teste")
        st = self.status()
        self.assertEqual([c["status"] for c in st["campanhas"]],
                         ["failed", "succeeded", "failed"])


class TestEscopoPorCampanha(Base):
    """Correção 1: uma campanha pode existir só em submonitor (domínio), só em
    monitor (IP) ou nos dois — a interface permite criar campanha só com IPs
    (escopo "Monitor de Portas"). Uma campanha só-de-IP (sem arquivo em
    submonitor) só deve rodar as 2 etapas de porta; senão as etapas de domínio
    falhariam com "Campanha X não encontrada neste escopo" (erro falso). Já uma
    campanha com domínio planeja SEMPRE as 6 — mesmo sem monitor/targets/X.txt
    ainda existir no disco —, porque é a própria etapa `submonitor` que cria
    esse arquivo (`feed_monitor_targets`) antes de as etapas de porta rodarem
    na mesma execução; olhar só o disco no planejamento perderia o scan de
    porta em silêncio na primeira execução de toda campanha nova."""

    def setUp(self):
        super().setUp()
        # Isola o teste: remove as campanhas padrão do Base (ALPHA/BETA/GAMA,
        # que existem nos dois escopos) para não interferir na união enumerada.
        base = Path(self.tmp.name)
        for nome in ("ALPHA", "BETA", "GAMA"):
            (base / "submonitor" / "targets" / f"{nome}.txt").unlink(missing_ok=True)
            (base / "monitor" / "targets" / f"{nome}.txt").unlink(missing_ok=True)

    def test_so_dominio_planeja_as_6_pois_submonitor_alimenta_monitor(self):
        # Campanha nova típica: só domínio (monitor/targets/SODOMINIO.txt
        # ainda NÃO existe). Antes da correção do Achado 1, isto planejava só
        # as 4 etapas de domínio e a campanha nunca escaneava porta.
        base = Path(self.tmp.name)
        (base / "submonitor" / "targets" / "SODOMINIO.txt").write_text(
            "empresa.com\n", encoding="utf-8")
        self.assertFalse((base / "monitor" / "targets" / "SODOMINIO.txt").exists())
        self.fingir_execucao({})
        self.runner.run_all("teste")
        st = self.status()
        self.assertEqual([c["nome"] for c in st["campanhas"]], ["SODOMINIO"])
        self.assertEqual({s["key"] for s in st["steps"]},
                         {"submonitor", "monitor_tcp", "monitor_udp",
                          "email", "credentials", "typosquat"})
        self.assertEqual(st["total"], 6)
        self.assertEqual(st["campanhas"][0]["status"], "succeeded")

    def test_so_ip_continua_so_com_as_2_etapas_de_porta(self):
        # Guarda de não-regressão do caso inverso: campanha só-de-IP (sem
        # domínio) não pode ganhar as etapas de domínio.
        base = Path(self.tmp.name)
        (base / "monitor" / "targets" / "SOIP.txt").write_text(
            "10.0.0.1\n", encoding="utf-8")
        self.fingir_execucao({})
        self.runner.run_all("teste")
        st = self.status()
        self.assertEqual([c["nome"] for c in st["campanhas"]], ["SOIP"])
        self.assertEqual({s["key"] for s in st["steps"]},
                         {"monitor_tcp", "monitor_udp"})
        self.assertEqual(st["total"], 2)
        self.assertEqual(st["campanhas"][0]["status"], "succeeded")

    def test_campanha_com_os_dois_roda_as_6_sem_regressao(self):
        base = Path(self.tmp.name)
        (base / "submonitor" / "targets" / "AMBOS.txt").write_text(
            "empresa.com\n", encoding="utf-8")
        (base / "monitor" / "targets" / "AMBOS.txt").write_text(
            "10.0.0.1\n", encoding="utf-8")
        self.fingir_execucao({})
        self.runner.run_all("teste")
        st = self.status()
        self.assertEqual(len(st["steps"]), 6)
        self.assertEqual(st["total"], 6)
        self.assertEqual(len([c for c, _ in self.executadas if c == "AMBOS"]), 6)

    def test_uniao_inclui_campanha_so_do_escopo_monitor(self):
        base = Path(self.tmp.name)
        (base / "submonitor" / "targets" / "COMDOMINIO.txt").write_text(
            "empresa.com\n", encoding="utf-8")
        (base / "monitor" / "targets" / "SOMONITOR.txt").write_text(
            "10.0.0.2\n", encoding="utf-8")
        self.fingir_execucao({})
        self.runner.run_all("teste")
        st = self.status()
        # Antes da correção, _campanhas_do_submonitor só olhava o escopo
        # submonitor — SOMONITOR (só-IP) sumiria da lista.
        self.assertEqual([c["nome"] for c in st["campanhas"]],
                         ["COMDOMINIO", "SOMONITOR"])
        self.assertEqual([c["status"] for c in st["campanhas"]],
                         ["succeeded", "succeeded"])

    def test_campanha_sem_alvo_em_escopo_nenhum_e_pulada_sem_contar_falha(self):
        base = Path(self.tmp.name)
        (base / "submonitor" / "targets" / "TEMALVO.txt").write_text(
            "empresa.com\n", encoding="utf-8")
        self.fingir_execucao({})
        # Simula o arquivo sumindo entre listar as campanhas e checar as
        # etapas dela (ex.: outra requisição apagou a campanha no meio do
        # caminho): força a união a incluir um nome sem arquivo em escopo
        # nenhum, sem depender de janela de corrida real no teste.
        with mock.patch.object(self.runner, "_campanhas_a_rodar",
                               return_value=["TEMALVO", "FANTASMA"]):
            self.runner.run_all("teste")
        st = self.status()
        self.assertEqual([c["nome"] for c in st["campanhas"]],
                         ["TEMALVO", "FANTASMA"])
        self.assertEqual([c["status"] for c in st["campanhas"]],
                         ["succeeded", "skipped"])
        # Campanha pulada não conta como falha nem entra na contagem de "duas
        # falhas seguidas" que aborta o restante.
        self.assertEqual(st["failed"], 0)
        self.assertNotIn("FANTASMA", [c for c, _ in self.executadas])
        # Achado 4: FANTASMA é a campanha corrente ao pular — o estado não pode
        # continuar mostrando as etapas de TEMALVO (a anterior) como se fossem
        # dela.
        self.assertEqual(st["steps"], [])
        self.assertEqual(st["total"], 0)
        self.assertEqual(st["current"], 0)


class TestLogPorCampanha(Base):
    """Achado 2: `_gravar_saida` grava <chave>.<campanha>.log para o log de
    uma campanha não apagar o da anterior. Sem este teste, remover o sufixo
    deixaria a suíte verde e reintroduziria o defeito (log da campanha 1
    sobrescrito assim que a campanha 2 roda a mesma etapa)."""

    def test_logs_de_campanhas_diferentes_coexistem(self):
        self.fingir_execucao({})
        self.runner.run_all("teste")
        log_dir = self.runner.LOG_DIR
        alpha = log_dir / "submonitor.ALPHA.log"
        beta = log_dir / "submonitor.BETA.log"
        self.assertTrue(alpha.exists(), f"faltou {alpha}")
        self.assertTrue(beta.exists(), f"faltou {beta}")
        # Conteúdo de cada um corresponde à sua campanha — não é só o nome do
        # arquivo que muda, o cabeçalho grava a campanha certa.
        self.assertIn("campanha: ALPHA", alpha.read_text(encoding="utf-8"))
        self.assertIn("campanha: BETA", beta.read_text(encoding="utf-8"))
        self.assertNotIn("campanha: BETA", alpha.read_text(encoding="utf-8"))


class TestNomeCampanhaSeguro(Base):
    """Achado 3: a allowlist do fallback local (só usada quando o import de
    `campaigns` falha) precisa da mesma defesa que `campaigns.valid_name` já
    tem (commit 150d4c8): `re.match` com "$" casa também antes de uma quebra
    de linha final, então "RIOCARD\\n" passaria por match() mas não deveria
    ser aceito como nome de campanha."""

    def test_fallback_rejeita_nome_com_quebra_de_linha_final(self):
        with mock.patch.object(self.runner, "_valid_name", None):
            self.assertEqual(self.runner._nome_campanha_seguro("RIOCARD\n"), "")

    def test_fallback_aceita_nome_valido(self):
        with mock.patch.object(self.runner, "_valid_name", None):
            self.assertEqual(self.runner._nome_campanha_seguro("RIOCARD"), "RIOCARD")


if __name__ == "__main__":
    unittest.main()
