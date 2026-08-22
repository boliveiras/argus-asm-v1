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
        (base / "store").mkdir(parents=True, exist_ok=True)
        alvos = base / "submonitor" / "targets"
        alvos.mkdir(parents=True, exist_ok=True)
        for nome in ("ALPHA", "BETA", "GAMA"):
            (alvos / f"{nome}.txt").write_text("empresa.com\n", encoding="utf-8")
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
        os.environ.pop("ARGUS_CAMPANHA", None)

    def fingir_execucao(self, resultado_por_campanha):
        """Substitui a execução real do subprocess por um dublê.

        Devolve rc=0 ou rc=1 conforme o mapa {campanha: True/False}, registrando
        a ordem em que campanha e etapa foram chamadas.
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

        self.runner.subprocess.run = fake_run

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


if __name__ == "__main__":
    unittest.main()
