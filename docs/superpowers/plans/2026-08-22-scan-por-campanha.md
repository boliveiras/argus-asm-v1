# Execução por campanha e prefixos configuráveis — Plano de Implementação

> **Para agentes:** SUB-SKILL OBRIGATÓRIA: use `superpowers:subagent-driven-development` (recomendado) ou `superpowers:executing-plans` para implementar tarefa a tarefa. Os passos usam checkbox (`- [ ]`) para acompanhamento.

**Objetivo:** Fazer o scan rodar campanha por campanha, cada uma do início ao fim, com os prefixos de wordlist configuráveis por campanha — cortando até 20× o volume de consultas DNS que hoje faz a execução arrastar até o timeout.

**Arquitetura:** O `runner` ganha um loop externo: quando nenhuma campanha é especificada, ele itera as campanhas do submonitor executando os 6 módulos para cada uma, persistindo antes de passar à próxima. Os prefixos saem da constante `PREFIXES` e passam a vir de um `campaigns.json` central por campanha, com fallback para o padrão atual. A interface mostra o progresso em duas dimensões e estima o custo antes de salvar.

**Stack:** Python 3.13 (stdlib + `unittest`), Flask (webapp), systemd (units), sem dependência nova.

## Restrições Globais

- **Testes com `unittest` da stdlib** — o projeto não tem pytest. Rodar com `python -m unittest tests.test_X` a partir da raiz do repositório.
- **Ruff limpo** — `python -m ruff check core/ scanners/ threatintel/` precisa passar; o hook de pre-commit bloqueia o commit se falhar.
- **Nunca commitar segredo** — repositório público.
- **Entrada da web que vira hostname exige allowlist no servidor**, nunca só no navegador.
- **Retrocompatibilidade obrigatória:** campanha sem configuração de prefixos usa exatamente o comportamento de hoje (`PREFIXES = ["", "prod-", "hml-", "dev-", "aceite-"]`).
- **Gravação de config é in-place** (mesmo inode), padrão do `logpush_config.gravar`.
- **Mensagens de interface em português**, sem jargão de implementação.

---

### Task 1: Configuração de prefixos por campanha

**Arquivos:**
- Modificar: `core/campaigns.py` (acrescentar ao final, antes de `valid_target`)
- Testar: `tests/test_campaigns_config.py` (criar)

**Interfaces:**
- Consome: `campaigns._base()` (já existe, devolve `Path` de `/etc/argus`)
- Produz:
  - `PREFIXOS_PADRAO: list[str]` — `["", "prod-", "hml-", "dev-", "aceite-"]`
  - `config_path() -> Path` — caminho do `campaigns.json`
  - `ler_config() -> dict` — todo o JSON; `{}` se ausente ou inválido
  - `prefixos_da_campanha(nome: str) -> list[str]` — lista da campanha, ou `PREFIXOS_PADRAO`
  - `set_prefixos(nome: str, prefixos: list[str]) -> list[str]` — valida, grava e devolve a lista salva; levanta `CampaignError` se inválida

- [ ] **Passo 1: Escrever os testes que falham**

Criar `tests/test_campaigns_config.py`:

```python
"""Configuração por campanha: prefixos de wordlist.

O prefixo vem da interface e é CONCATENADO em hostname que depois é resolvido e
consultado. Por isso a allowlist é no servidor, e prefixo inválido é recusado —
nunca ignorado em silêncio.
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


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Passo 2: Rodar e verificar que falha**

```bash
python -m unittest tests.test_campaigns_config -v
```

Esperado: FAIL com `AttributeError: module 'campaigns' has no attribute 'PREFIXOS_PADRAO'`.

- [ ] **Passo 3: Implementar**

Em `core/campaigns.py`, logo após a função `valid_name` (por volta da linha 78), acrescentar:

```python
# ── Configuração por campanha (campaigns.json) ───────────────────────
# Prefixos de wordlist. O padrão replica o comportamento histórico: campanha sem
# configuração roda exatamente como antes.
PREFIXOS_PADRAO = ["", "prod-", "hml-", "dev-", "aceite-"]
# Allowlist do prefixo. Ele é CONCATENADO em hostname e depois resolvido — sem
# esta trava, a interface viraria caminho para injetar consulta a domínio de
# terceiro. Vazio é válido: significa "a palavra da wordlist, pura".
_PREFIXO_RE = re.compile(r"^[a-z0-9-]{0,20}$")


def config_path() -> Path:
    return Path(_base()) / "campaigns.json"


def ler_config() -> dict:
    """Todo o campaigns.json. Arquivo ausente ou corrompido devolve {} — a
    configuração é conveniência, e perdê-la não pode impedir o scan de rodar."""
    try:
        dados = json.loads(config_path().read_text(encoding="utf-8"))
        return dados if isinstance(dados, dict) else {}
    except Exception:
        return {}


def prefixos_da_campanha(nome: str) -> list[str]:
    """Prefixos da campanha; o padrão quando ela não tem configuração própria."""
    entrada = ler_config().get(str(nome or ""), {})
    if not isinstance(entrada, dict):
        return list(PREFIXOS_PADRAO)
    prefixos = entrada.get("prefixos")
    if not isinstance(prefixos, list):
        return list(PREFIXOS_PADRAO)
    # Revalida na LEITURA: o arquivo pode ter sido editado à mão no servidor.
    limpos = [p for p in prefixos if isinstance(p, str) and _PREFIXO_RE.fullmatch(p)]
    return limpos or [""]


def set_prefixos(nome: str, prefixos) -> list[str]:
    """Valida e grava os prefixos da campanha. Devolve a lista efetivamente salva.

    Grava IN-PLACE (mesmo inode): o serviço precisa de permissão apenas NESTE
    arquivo, nunca de criar arquivos no diretório de configuração.
    """
    if not valid_name(nome):
        raise CampaignError("nome de campanha inválido")
    if not isinstance(prefixos, list):
        raise CampaignError("prefixos deve ser uma lista")
    limpos: list[str] = []
    for p in prefixos:
        if not isinstance(p, str):
            raise CampaignError("prefixo inválido: precisa ser texto")
        if not _PREFIXO_RE.fullmatch(p):
            raise CampaignError(
                f"prefixo inválido: {p!r} — use apenas letras minúsculas, "
                f"números e hífen (até 20 caracteres)")
        if p not in limpos:
            limpos.append(p)
    if not limpos:
        limpos = [""]        # sem nenhum prefixo, ainda se testa a palavra pura
    cfg = ler_config()
    cfg[nome] = {**cfg.get(nome, {}), "prefixos": limpos}
    corpo = json.dumps(cfg, ensure_ascii=False, indent=2) + "\n"
    caminho = config_path()
    try:
        caminho.parent.mkdir(parents=True, exist_ok=True)
        with open(caminho, "w", encoding="utf-8", newline="") as fh:
            fh.write(corpo)
            fh.flush()
            os.fsync(fh.fileno())
    except OSError as exc:
        raise CampaignError(f"sem permissão para gravar a configuração: {exc}") from exc
    return limpos
```

Conferir que `core/campaigns.py` já importa `json`, `os`, `re` e `Path` no topo; se `json` faltar, acrescentar `import json` junto dos demais.

- [ ] **Passo 4: Rodar e verificar que passa**

```bash
python -m unittest tests.test_campaigns_config -v
```

Esperado: PASS nos 13 testes.

- [ ] **Passo 5: Verificar o lint**

```bash
python -m ruff check core/campaigns.py tests/test_campaigns_config.py
```

Esperado: `All checks passed!`

- [ ] **Passo 6: Commit**

```bash
git add core/campaigns.py tests/test_campaigns_config.py
git commit -m "feat(campanhas): prefixos de wordlist configuráveis por campanha

Novo campaigns.json guarda os prefixos de cada campanha; ausência mantém o
padrão histórico, então nada muda para quem já tem campanha.

O prefixo é concatenado em hostname que depois é resolvido, então a allowlist
(minúsculas, números e hífen, até 20 caracteres) roda no servidor e recusa a
gravação inteira em vez de descartar o item inválido em silêncio. A leitura
revalida, porque o arquivo pode ser editado à mão no servidor."
```

---

### Task 2: Submonitor usa os prefixos da campanha

**Arquivos:**
- Modificar: `scanners/submonitor.py` (`_build_candidates`, por volta da linha 745)
- Testar: `tests/test_submonitor_prefixos.py` (criar)

**Interfaces:**
- Consome: `campaigns.prefixos_da_campanha(nome) -> list[str]` (Task 1)
- Produz: `_build_candidates(campaigns, subs)` passa a gerar candidatos com os prefixos de cada campanha

- [ ] **Passo 1: Escrever o teste que falha**

Criar `tests/test_submonitor_prefixos.py`:

```python
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
        cands = self.SUB._build_candidates([(campanha, ["empresa.com"])], ["www", "api"])
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
```

- [ ] **Passo 2: Rodar e verificar que falha**

```bash
python -m unittest tests.test_submonitor_prefixos -v
```

Esperado: FAIL em `test_prefixos_desligados_geram_so_a_palavra_pura` — hoje `_build_candidates` ignora a configuração e sempre gera 10.

- [ ] **Passo 3: Implementar**

Em `scanners/submonitor.py`, junto do import tolerante de `_filtrar_campanhas` (por volta da linha 57), acrescentar:

```python
try:
    from campaigns import prefixos_da_campanha as _prefixos_da_campanha
except Exception:                                   # pragma: no cover
    def _prefixos_da_campanha(nome):
        return PREFIXES
```

Em `_build_candidates`, trocar o bloco da wordlist (o `for` com `PREFIXES`) por:

```python
    # 1. Candidatos da wordlist
    for campanha, domains in campaigns:
        # Prefixos por campanha: a wordlist inteira multiplicada por 5 é o que
        # faz a execução arrastar. Sem configuração, mantém o padrão histórico.
        prefixos = _prefixos_da_campanha(campanha) or PREFIXES
        for domain in domains:
            for sub in subs:
                for prefix in prefixos:
                    host = f"{prefix}{sub}.{domain}"
                    candidates[(host, campanha)] = "wordlist"
```

- [ ] **Passo 4: Rodar e verificar que passa**

```bash
python -m unittest tests.test_submonitor_prefixos -v
```

Esperado: PASS nos 4 testes.

- [ ] **Passo 5: Rodar a suíte inteira (nada pode quebrar)**

```bash
python -m unittest discover -s tests -p "test_*.py" 2>&1 | tail -5
```

Esperado: `OK`.

- [ ] **Passo 6: Commit**

```bash
git add scanners/submonitor.py tests/test_submonitor_prefixos.py
git commit -m "feat(submonitor): usar os prefixos configurados na campanha

A wordlist inteira multiplicada por 5 é o que faz a execução arrastar até o
timeout: 2000 palavras viram 10.000 consultas por domínio. Cada campanha passa
a decidir seus prefixos; sem configuração, mantém os cinco padrões.

Import tolerante, como o de filtrar_campanhas: instalação sem o módulo continua
rodando com o comportamento anterior."
```

---

### Task 3: Loop por campanha no runner

**Arquivos:**
- Modificar: `core/runner.py` (`_initial_state` e `run_all`)
- Testar: `tests/test_runner_loop.py` (criar)

**Interfaces:**
- Consome: `campaigns.list_campaigns("submonitor")` (já existe; devolve `list[dict]` com chave `name`)
- Produz:
  - `_campanhas_do_submonitor() -> list[str]` — nomes das campanhas, ordenados
  - `_executar_etapas(state: dict) -> tuple[int, int]` — roda os 6 módulos da campanha corrente e devolve `(ok, falhas)`
  - `_atualizar_percent(state: dict, etapas_feitas: int) -> None` — recalcula o progresso global
  - `run_all(actor: str, campanha: str = "") -> int` — com campanha, comportamento atual; sem, itera

- [ ] **Passo 1: Escrever os testes que falham**

Criar `tests/test_runner_loop.py`:

```python
"""Loop por campanha: cada uma do início ao fim, persistindo antes da próxima.

O ponto do redesenho é não perder trabalho: se a terceira campanha falha, as
duas primeiras já estão salvas no banco.
"""

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
        os.environ["ARGUS_BASE"] = self.tmp.name
        base = Path(self.tmp.name)
        (base / "store").mkdir(parents=True, exist_ok=True)
        alvos = base / "submonitor" / "targets"
        alvos.mkdir(parents=True, exist_ok=True)
        for nome in ("ALPHA", "BETA", "GAMA"):
            (alvos / f"{nome}.txt").write_text("empresa.com\n", encoding="utf-8")
        import runner
        self.runner = runner
        self.executadas = []

    def tearDown(self):
        self.tmp.cleanup()

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
```

- [ ] **Passo 2: Rodar e verificar que falha**

```bash
python -m unittest tests.test_runner_loop -v
```

Esperado: FAIL — `run_all` hoje executa os 6 módulos uma única vez, sem iterar campanhas, e o status não tem `campanhas_total`.

- [ ] **Passo 3: Implementar**

Em `core/runner.py`, acrescentar o import tolerante logo após a definição de `STEPS`:

```python
# Lista de campanhas para o loop. Import tolerante: sem o módulo, o runner cai
# no modo antigo (uma execução cobrindo todas as campanhas de uma vez).
try:
    from campaigns import list_campaigns as _list_campaigns
except Exception:                                   # pragma: no cover
    _list_campaigns = None


def _campanhas_do_submonitor() -> list[str]:
    """Nomes das campanhas, em ordem. Vazio quando não há como listar."""
    if _list_campaigns is None:
        return []
    try:
        return sorted(c["name"] for c in _list_campaigns("submonitor"))
    except Exception as exc:
        print(f"[AVISO] não consegui listar as campanhas: {exc}", file=sys.stderr)
        return []
```

Substituir a função `run_all` inteira por:

```python
def _executar_etapas(state: dict) -> tuple[int, int]:
    """Roda os 6 módulos da campanha corrente. Devolve (ok, falhas)."""
    ok = falhas = 0
    for idx, step in enumerate(STEPS):
        state["current"] = idx + 1
        state["current_label"] = step["label"]
        state["steps"][idx].update({"status": "running", "rc": None,
                                    "duration": 0, "detail": ""})
        _atualizar_percent(state, idx)
        _write_status(state)

        print(f"[{idx + 1}/{len(STEPS)}] {step['label']} -> {' '.join(step['cmd'])}")
        t0 = time.monotonic()
        rc, status, detail = 1, "fail", ""
        try:
            proc = subprocess.run(  # nosec B603 - lista fixa de comandos, shell=False, sem entrada do usuário
                step["cmd"], shell=False, timeout=STEP_TIMEOUT,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False,
                text=True, errors="replace")
            rc = proc.returncode
            status = "ok" if rc == 0 else "fail"
            _gravar_saida(step["key"], step["cmd"], rc, proc.stdout or "")
            if rc != 0:
                lines = [ln.strip() for ln in (proc.stdout or "").splitlines() if ln.strip()]
                detail = " | ".join(lines[-3:])[:300]
                for ln in lines[-15:]:
                    print(f"    {ln}")
        except subprocess.TimeoutExpired as exc:
            rc, status = -1, "timeout"
            parcial = exc.output or ""
            if isinstance(parcial, bytes):
                parcial = parcial.decode("utf-8", "replace")
            _gravar_saida(step["key"], step["cmd"], rc, parcial)
            ultimas = [ln.strip() for ln in parcial.splitlines() if ln.strip()][-3:]
            detail = (f"excedeu {STEP_TIMEOUT}s"
                      + (" · última saída: " + " | ".join(ultimas) if ultimas else ""))[:300]
            print(f"  [TIMEOUT] {step['label']} passou de {STEP_TIMEOUT}s", file=sys.stderr)
        except FileNotFoundError:
            rc, status = -2, "missing"
            detail = f"comando não encontrado: {step['cmd'][0]}"
            print(f"  [ERRO] {detail}", file=sys.stderr)
        except Exception as exc:                       # nunca aborta a fila
            rc, status = -3, "fail"
            detail = str(exc)[:300]
            print(f"  [ERRO] {step['label']}: {exc}", file=sys.stderr)

        dur = int(time.monotonic() - t0)
        state["steps"][idx].update({"status": status, "rc": rc,
                                    "duration": dur, "detail": detail})
        if status == "ok":
            ok += 1
            state["succeeded"] += 1
        else:
            falhas += 1
            state["failed"] += 1
        _atualizar_percent(state, idx + 1)
        _write_status(state)
        print(f"  → {status} (rc={rc}) em {dur}s")
    return ok, falhas


def _atualizar_percent(state: dict, etapas_feitas: int) -> None:
    """Progresso global: conta as campanhas já concluídas mais as etapas da atual."""
    total_campanhas = max(1, state.get("campanhas_total", 1))
    feitas = state.get("campanha_idx", 1) - 1
    total_etapas = total_campanhas * len(STEPS)
    state["percent"] = int((feitas * len(STEPS) + etapas_feitas) * 100 / total_etapas)


def run_all(actor: str = "web", campanha: str = "") -> int:
    # Campanha específica: uma execução só, como sempre foi.
    # Sem campanha: cada uma roda do início ao fim antes da próxima, para que o
    # resultado de uma esteja salvo mesmo se a seguinte falhar.
    alvos = [campanha] if campanha else _campanhas_do_submonitor()
    if not alvos:
        alvos = [""]          # sem lista de campanhas, mantém o modo antigo

    state = _initial_state(actor)
    state["campanha"] = alvos[0]
    state["campanhas_total"] = len(alvos)
    state["campanha_idx"] = 1
    state["campanhas"] = [{"nome": n, "status": "pending"} for n in alvos]
    _write_status(state)

    escopo = f"campanha {campanha}" if campanha else f"{len(alvos)} campanha(s)"
    print(f"[ARGUS] Execução sob demanda iniciada por '{actor}' ({escopo}) "
          f"— {len(STEPS)} etapa(s) por campanha")

    falhas_seguidas = 0
    for i, alvo in enumerate(alvos):
        state["campanha"] = alvo
        state["campanha_idx"] = i + 1
        state["campanhas"][i]["status"] = "running"
        state["current"] = 0
        # Cada campanha começa com as etapas zeradas: o painel mostra o progresso
        # DELA, não o resíduo da anterior.
        for s in state["steps"]:
            s.update({"status": "pending", "rc": None, "duration": 0, "detail": ""})
        _write_status(state)

        if alvo:
            os.environ["ARGUS_CAMPANHA"] = alvo
        else:
            os.environ.pop("ARGUS_CAMPANHA", None)
        print(f"[ARGUS] === campanha {i + 1}/{len(alvos)}: {alvo or 'todas'} ===")

        ok, falhas = _executar_etapas(state)
        # Campanha só conta como falha quando NENHUMA etapa passou: um typosquat
        # que falha sozinho não invalida os subdomínios já encontrados.
        completou = ok > 0
        state["campanhas"][i]["status"] = "succeeded" if completou else "failed"
        falhas_seguidas = 0 if completou else falhas_seguidas + 1
        _write_status(state)

        if falhas_seguidas >= 2 and i + 1 < len(alvos):
            # Duas campanhas seguidas sem nenhuma etapa completa: o problema é do
            # ambiente (rede, disco, permissão), não desta campanha. Insistir só
            # gasta hora — o que já rodou continua salvo.
            for pendente in state["campanhas"][i + 1:]:
                pendente["status"] = "skipped"
            print("[ARGUS] duas campanhas seguidas falharam por completo — "
                  "execução interrompida", file=sys.stderr)
            break

    os.environ.pop("ARGUS_CAMPANHA", None)
    state["running"] = False
    state["finished_at"] = _now()
    state["current_label"] = ""
    state["percent"] = 100
    _write_status(state)
    print(f"[ARGUS] Concluído: {state['succeeded']} ok, {state['failed']} com falha")
    return 0 if state["failed"] == 0 else 1
```

- [ ] **Passo 4: Rodar e verificar que passa**

```bash
python -m unittest tests.test_runner_loop -v
```

Esperado: PASS nos 6 testes.

- [ ] **Passo 5: Rodar a suíte inteira**

```bash
python -m unittest discover -s tests -p "test_*.py" 2>&1 | tail -5
```

Esperado: `OK`.

- [ ] **Passo 6: Commit**

```bash
git add core/runner.py tests/test_runner_loop.py
git commit -m "feat(runner): executar campanha por campanha, do início ao fim

Rodar todas as campanhas processava tudo num lote só: com wordlist grande e
vários domínios, a execução arrastava até o timeout e nada era aproveitado.
Agora cada campanha passa pelos 6 módulos e persiste antes da próxima — se a
terceira falha, as duas primeiras já estão salvas.

Campanha só conta como falha quando nenhuma etapa passou; duas dessas seguidas
interrompem a execução, porque aí o problema é do ambiente e insistir só gasta
hora. As restantes ficam marcadas como puladas.

O progresso passa a ter duas dimensões (campanha X de Y, etapa N de 6) e o
percent é global. Campanha específica mantém o comportamento anterior."
```

---

### Task 4: API de prefixos e dados para a estimativa

**Arquivos:**
- Modificar: `core/webapp.py` (endpoint `/api/campaigns`, por volta da linha 742)
- Testar: `tests/test_campaigns_api.py` (criar)

**Interfaces:**
- Consome: `campaigns.prefixos_da_campanha`, `campaigns.set_prefixos`, `campaigns.PREFIXOS_PADRAO` (Task 1)
- Produz:
  - `GET /api/campaigns` passa a devolver `prefixos_padrao`, `wordlist_size` e, em cada campanha do escopo submonitor, a chave `prefixos`
  - `POST /api/campaigns/<scope>/<name>/prefixos` — grava; body `{"prefixos": ["", "dev-"]}`

- [ ] **Passo 1: Escrever os testes que falham**

Criar `tests/test_campaigns_api.py`:

```python
"""API de prefixos por campanha e dados da estimativa de custo."""

import os
import sys
import tempfile
import types
import unittest
from pathlib import Path

sys.modules.setdefault("nmap", types.ModuleType("nmap"))
sys.path.insert(0, "core")


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        os.environ["ARGUS_BASE"] = self.tmp.name
        os.environ["ARGUS_DB"] = os.path.join(self.tmp.name, "store", "argus.db")
        base = Path(self.tmp.name)
        (base / "store").mkdir(parents=True, exist_ok=True)
        alvos = base / "submonitor" / "targets"
        alvos.mkdir(parents=True, exist_ok=True)
        (alvos / "RIOCARD.txt").write_text("empresa.com\n", encoding="utf-8")
        (base / "submonitor" / "subs.txt").write_text(
            "www\napi\nmail\n", encoding="utf-8")
        import webapp
        self.app = webapp.create_app().test_client()
        self.H = {"X-Requested-With": "argus", "X-Remote-User": "monitor"}

    def tearDown(self):
        self.tmp.cleanup()


class TestLeitura(Base):
    def test_get_traz_prefixos_padrao_e_tamanho_da_wordlist(self):
        j = self.app.get("/api/campaigns?scope=submonitor", headers=self.H).get_json()
        self.assertIn("", j["prefixos_padrao"])
        self.assertEqual(j["wordlist_size"], 3)

    def test_campanha_sem_config_traz_o_padrao(self):
        j = self.app.get("/api/campaigns?scope=submonitor", headers=self.H).get_json()
        camp = j["campaigns"]["submonitor"][0]
        self.assertEqual(camp["prefixos"], j["prefixos_padrao"])


class TestGravacao(Base):
    def test_grava_prefixos_e_devolve_na_leitura(self):
        r = self.app.post("/api/campaigns/submonitor/RIOCARD/prefixos",
                          headers=self.H, json={"prefixos": ["", "dev-"]})
        self.assertEqual(r.status_code, 200)
        j = self.app.get("/api/campaigns?scope=submonitor", headers=self.H).get_json()
        self.assertEqual(j["campaigns"]["submonitor"][0]["prefixos"], ["", "dev-"])

    def test_prefixo_invalido_recusado_com_400(self):
        r = self.app.post("/api/campaigns/submonitor/RIOCARD/prefixos",
                          headers=self.H, json={"prefixos": ["dev/"]})
        self.assertEqual(r.status_code, 400)

    def test_sem_csrf_recusado(self):
        r = self.app.post("/api/campaigns/submonitor/RIOCARD/prefixos",
                          headers={"X-Remote-User": "monitor"},
                          json={"prefixos": [""]})
        self.assertEqual(r.status_code, 403)

    def test_escopo_invalido_recusado(self):
        r = self.app.post("/api/campaigns/inexistente/RIOCARD/prefixos",
                          headers=self.H, json={"prefixos": [""]})
        self.assertEqual(r.status_code, 400)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Passo 2: Rodar e verificar que falha**

```bash
python -m unittest tests.test_campaigns_api -v
```

Esperado: FAIL — a resposta não tem `prefixos_padrao` e a rota de prefixos devolve 404.

- [ ] **Passo 3: Implementar**

Em `core/webapp.py`, substituir o corpo de `list_campaigns` por:

```python
    @app.get("/api/campaigns")
    def list_campaigns():
        try:
            scope = str(request.args.get("scope", "")).strip()
            scopes = [scope] if scope in CAMP.SCOPES else list(CAMP.SCOPES)
            out = {}
            for s in scopes:
                campanhas = CAMP.list_campaigns(s)
                # Prefixos só fazem sentido para subdomínios (o monitor recebe IPs).
                if s == "submonitor":
                    for c in campanhas:
                        c["prefixos"] = CAMP.prefixos_da_campanha(c["name"])
                out[s] = campanhas
            # Tamanho da wordlist: a interface usa para estimar o custo da campanha
            # ANTES de rodar (domínios × palavras × prefixos).
            try:
                subs = Path(CAMP._base()) / "submonitor" / "subs.txt"
                wordlist_size = sum(
                    1 for ln in subs.read_text(encoding="utf-8").splitlines()
                    if ln.split("#", 1)[0].strip())
            except Exception:
                wordlist_size = 0
            return jsonify(ok=True, scopes={s: CAMP.SCOPES[s]["label"] for s in CAMP.SCOPES},
                           campaigns=out, prefixos_padrao=CAMP.PREFIXOS_PADRAO,
                           wordlist_size=wordlist_size)
        except Exception as exc:
            return jsonify(ok=False, error=str(exc)), 500

    @app.post("/api/campaigns/<scope>/<name>/prefixos")
    def set_campaign_prefixos(scope, name):
        if not _csrf_ok():
            _audit(request, "AUTHZ_DENY", "ação negada: header CSRF ausente",
                   outcome="deny", action="campaign_prefixos")
            return jsonify(ok=False, error="CSRF: header ausente"), 403
        if scope not in CAMP.SCOPES:
            return jsonify(ok=False, error="escopo inválido"), 400
        dados = request.get_json(silent=True) or {}
        try:
            salvos = CAMP.set_prefixos(name, dados.get("prefixos", []))
        except CAMP.CampaignError as exc:
            return jsonify(ok=False, error=str(exc)), 400
        _audit(request, "CAMPAIGN_UPDATE",
               f"prefixos da campanha {scope}/{name} alterados ({len(salvos)})",
               outcome="success", action="campaign_prefixos", obj=name,
               object_type="campaign")
        return jsonify(ok=True, prefixos=salvos)
```

Conferir que `Path` está importado em `core/webapp.py` (já está, linha 54).

- [ ] **Passo 4: Rodar e verificar que passa**

```bash
python -m unittest tests.test_campaigns_api -v
```

Esperado: PASS nos 6 testes.

- [ ] **Passo 5: Commit**

```bash
git add core/webapp.py tests/test_campaigns_api.py
git commit -m "feat(api): prefixos por campanha e dados da estimativa de custo

GET /api/campaigns passa a trazer os prefixos de cada campanha do submonitor,
o padrão e o tamanho da wordlist — é o que a tela usa para estimar o custo
(domínios × palavras × prefixos) antes de rodar, em vez de o operador descobrir
depois de duas horas de scan.

POST .../prefixos grava com a validação do servidor; prefixo inválido devolve
400 e não altera nada."
```

---

### Task 5: Interface — progresso, prefixos, recomendação e estimativa

**Arquivos:**
- Modificar: `core/reporter.py` — widget de progresso (`_SCAN_SCRIPT`, por volta da linha 4645) e página de campanhas (`build_campaigns_page`, linha 4749)
- Testar: `tests/test_campaigns_page.py` (criar)

**Interfaces:**
- Consome: `GET /api/campaigns` com `prefixos_padrao`, `wordlist_size`, `campaigns[].prefixos` (Task 4); `GET /api/scan/status` com `campanha_idx`, `campanhas_total`, `campanhas` (Task 3)
- Produz: página de campanhas com caixas de prefixos, aviso de recomendação e estimativa; painel de progresso com a dimensão de campanha

- [ ] **Passo 1: Escrever o teste que falha**

Criar `tests/test_campaigns_page.py`:

```python
"""A página de campanhas precisa expor prefixos, recomendação e estimativa."""

import sys
import types
import unittest

sys.modules.setdefault("nmap", types.ModuleType("nmap"))
sys.path.insert(0, "core")
import reporter  # noqa: E402


class TestPagina(unittest.TestCase):
    def setUp(self):
        self.html = reporter.build_campaigns_page()

    def test_tem_bloco_de_prefixos(self):
        self.assertIn("cp-prefixos", self.html)

    def test_tem_estimativa_de_candidatos(self):
        self.assertIn("cp-estimativa", self.html)

    def test_recomenda_um_dominio_por_campanha(self):
        self.assertIn("um domínio por campanha", self.html)


class TestProgresso(unittest.TestCase):
    def test_painel_mostra_campanha_atual(self):
        # O progresso passa a ter duas dimensões: campanha X de Y, etapa N de 6.
        self.assertIn("campanhas_total", reporter._SCAN_SCRIPT)
        self.assertIn("Campanha ", reporter._SCAN_SCRIPT)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Passo 2: Rodar e verificar que falha**

```bash
python -m unittest tests.test_campaigns_page -v
```

Esperado: FAIL — os identificadores ainda não existem.

- [ ] **Passo 3: Implementar o painel de progresso**

Em `core/reporter.py`, no script do painel de scan, trocar o trecho que monta o rótulo (por volta da linha 4648):

```javascript
      var doneLabel=running
        ? ('Etapa '+(st.current||0)+' de '+total+(st.current_label?(' — '+esc(st.current_label)):''))
```

por:

```javascript
      var campPrefixo='';
      if(st.campanhas_total>1){
        campPrefixo='Campanha '+(st.campanha_idx||1)+' de '+st.campanhas_total
          +(st.campanha?(' ('+esc(st.campanha)+')'):'')+' · ';
      }
      var doneLabel=running
        ? (campPrefixo+'Etapa '+(st.current||0)+' de '+total+(st.current_label?(' — '+esc(st.current_label)):''))
```

Logo depois do bloco que renderiza `st.steps`, acrescentar a lista de campanhas:

```javascript
      if(st.campanhas&&st.campanhas.length>1){
        h+='<div class="page-sub" style="margin-top:9px;font-size:11.5px">';
        st.campanhas.forEach(function(c){
          var cor=c.status==='succeeded'?'var(--green)'
                 :c.status==='failed'?'var(--red)'
                 :c.status==='running'?'var(--accent)':'var(--muted)';
          h+='<span style="color:'+cor+';margin-right:10px">'+esc(c.nome)+'</span>';
        });
        h+='</div>';
      }
```

- [ ] **Passo 4: Acrescentar o HTML no editor de campanha**

Em `build_campaigns_page` (linha ~4836), no bloco `<div id="camp-editor" ...>`, inserir **logo após** o `</div>` que fecha a `<div class="camp-split">` e **antes** da `<div style="display:flex;gap:8px;margin-top:14px">` dos botões:

```python
        '<div id="cp-prefixos-bloco" style="display:none;margin-top:14px">'
        '<label>Prefixos da wordlist</label>'
        '<div id="cp-prefixos" class="camp-grid" style="grid-template-columns:'
        'repeat(auto-fill,minmax(min(150px,100%),1fr));gap:8px"></div>'
        '<div id="cp-estimativa" class="page-sub" style="margin-top:9px;font-size:12px"></div>'
        '<div class="page-sub" style="margin-top:10px;border-left:3px solid var(--border-2);'
        'padding-left:10px;font-size:11.5px">'
        'Recomendamos <b>um domínio por campanha</b>: a execução roda campanha a campanha, '
        'então campanhas menores terminam antes e o resultado de cada uma fica salvo mesmo '
        'se a seguinte falhar.</div>'
        '</div>'
```

- [ ] **Passo 5: Acrescentar as funções no `_CAMP_SCRIPT`**

Em `core/reporter.py`, dentro de `_CAMP_SCRIPT`, inserir estas duas funções **antes** de `function openEditor(`:

```javascript
  function pintarPrefixos(cur){
    var bloco=document.getElementById('cp-prefixos-bloco');
    var host=document.getElementById('cp-prefixos');
    if(!bloco||!host) return;
    // Prefixos só existem para subdomínios: o monitor recebe IP, não nome.
    if(!editing||editing.scope!=='submonitor'){ bloco.style.display='none'; return; }
    bloco.style.display='block';
    host.innerHTML='';
    var padrao=DATA.prefixos_padrao||[];
    var atuais=(cur&&cur.prefixos)||padrao;
    padrao.forEach(function(p){
      var l=document.createElement('label');
      l.style.cssText='display:flex;gap:7px;align-items:center;font-size:13px;font-weight:400';
      var rotulo=(p==='')?'(sem prefixo)':p;
      l.innerHTML='<input type="checkbox" data-write="1" class="cp-pref" value="'+esc(p)+'"'
        +(atuais.indexOf(p)>=0?' checked':'')+'> '+esc(rotulo);
      host.appendChild(l);
      l.querySelector('input').addEventListener('change',estimar);
    });
    estimar();
  }
  function estimar(){
    var alvo=document.getElementById('cp-estimativa'); if(!alvo) return;
    if(!editing||editing.scope!=='submonitor'){ alvo.textContent=''; return; }
    var marcados=document.querySelectorAll('.cp-pref:checked').length||1;
    var dominios=(document.getElementById('camp-ed-targets').value||'')
      .split('\n').map(function(s){return s.split('#')[0].trim();})
      .filter(Boolean).length;
    var palavras=DATA.wordlist_size||0;
    var total=dominios*palavras*marcados;
    if(!total){ alvo.textContent=''; return; }
    var aviso=total>20000?' — volume alto, considere dividir em mais campanhas'
             :total>8000?' — volume considerável':'';
    alvo.innerHTML='Esta campanha vai gerar <b>'+total.toLocaleString('pt-BR')
      +'</b> consultas ('+dominios+' domínio(s) &times; '+palavras+' palavra(s) &times; '
      +marcados+' prefixo(s))'+esc(aviso);
  }
```

**Nota sobre `DATA`:** hoje `DATA` guarda as campanhas por escopo (`DATA[scope]`). O `carregar()` precisa guardar também os dois campos novos da API. Na função `carregar()` (linha ~5112), onde a resposta é atribuída, acrescentar:

```javascript
      DATA.prefixos_padrao = j.prefixos_padrao || [];
      DATA.wordlist_size = j.wordlist_size || 0;
```

- [ ] **Passo 6: Ligar aos eventos existentes**

Em `openEditor(scope,name)`, **logo antes** de `msg('');` (última linha da função), acrescentar:

```javascript
    pintarPrefixos(cur);
```

E, ainda em `openEditor`, ligar a estimativa à digitação dos alvos — acrescentar depois de `ta.placeholder=cfg.ph;`:

```javascript
    ta.oninput=estimar;
```

- [ ] **Passo 7: Enviar os prefixos ao salvar**

Na função `save()`, depois da chamada que grava a campanha ter dado certo (dentro do `.then` de sucesso, antes de `carregar()`), acrescentar:

```javascript
      if(editing && editing.scope==='submonitor'){
        var prefs=[].slice.call(document.querySelectorAll('.cp-pref:checked'))
          .map(function(i){return i.value;});
        // Grava em requisição separada: o endpoint de alvos não conhece prefixo,
        // e falhar aqui não pode desfazer a campanha que já foi salva.
        api('/api/campaigns/submonitor/'+encodeURIComponent(name)+'/prefixos',
            {method:'POST',body:JSON.stringify({prefixos:prefs})})
          .catch(function(e){ msg('Campanha salva, mas os prefixos não: '+e.message,'err'); });
      }
```

- [ ] **Passo 8: Rodar e verificar que passa**

```bash
python -m unittest tests.test_campaigns_page -v
```

Esperado: PASS nos 4 testes.

- [ ] **Passo 9: Rodar a suíte inteira e o lint**

```bash
python -m unittest discover -s tests -p "test_*.py" 2>&1 | tail -5
python -m ruff check core/ scanners/ threatintel/
```

Esperado: `OK` e `All checks passed!`.

- [ ] **Passo 10: Conferir a página renderizada localmente**

O teste garante que os identificadores existem, não que a tela funcione. Gerar a página e abrir no navegador:

```bash
python -c "
import sys, types; sys.modules.setdefault('nmap', types.ModuleType('nmap')); sys.path.insert(0,'core')
import reporter
open('/tmp/campanhas.html','w',encoding='utf-8').write(reporter.build_campaigns_page())
print('gerado: /tmp/campanhas.html')
"
```

Esperado: o arquivo abre sem erro de console. A verificação real das caixas e da estimativa acontece em produção (seção de validação), porque a página depende da API.

- [ ] **Passo 11: Commit**

```bash
git add core/reporter.py tests/test_campaigns_page.py
git commit -m "feat(ui): progresso por campanha, prefixos e estimativa de custo

O painel de execução passa a mostrar 'Campanha 2 de 4 · Etapa 3 de 6' e a lista
de campanhas com seus status, porque com o loop a etapa sozinha não diz mais
onde a execução está.

A tela de campanhas ganha as caixas de prefixos e a estimativa de consultas
(domínios × palavras × prefixos), que aparece enquanto se edita: o custo fica
visível antes de rodar, em vez de ser descoberto depois de duas horas. Junto,
a recomendação de um domínio por campanha."
```

---

### Task 6: Instalador — permissão do campaigns.json

**Arquivos:**
- Modificar: `install.sh` (bloco do store, por volta da linha 461; unit `argus-web`, por volta da linha 977)

**Interfaces:**
- Consome: `campaigns.config_path()` → `/etc/argus/campaigns.json` (Task 1)
- Produz: arquivo criado no bootstrap com dono e permissão corretos, e caminho liberado no systemd

- [ ] **Passo 1: Criar o arquivo no bootstrap**

Em `install.sh`, junto do bloco que trata o `logpush.json`, acrescentar:

```bash
# Configuração por campanha (prefixos de wordlist). Criado no bootstrap com o
# dono certo: o serviço argus-web GRAVA nele pela interface, e ProtectSystem=full
# deixa /etc somente-leitura para tudo que não estiver em ReadWritePaths.
if [ ! -f "$BASE_DIR/campaigns.json" ]; then
  printf '{}\n' > "$BASE_DIR/campaigns.json"
  ok "Configuração de campanhas criada: $BASE_DIR/campaigns.json"
fi
chown "root:$APP_USER" "$BASE_DIR/campaigns.json" 2>/dev/null || true
chmod 664 "$BASE_DIR/campaigns.json" 2>/dev/null || true
```

- [ ] **Passo 2: Liberar o caminho no systemd**

Na unit `argus-web`, acrescentar o arquivo ao `ReadWritePaths` existente (linha 977), ao final da lista:

```
ReadWritePaths=$BASE_DIR/store $APACHE_DOCROOT $LOG_DIR_AUDIT $MONITOR_DIR/targets $SUBMONITOR_DIR/targets $SUBMONITOR_DIR/subs.txt $HTPASSWD_FILE $THREATINTEL_DIR/config.json $BASE_DIR/logpush.json $BASE_DIR/campaigns.json
```

**Atenção:** o systemd recusa a unit inteira se um caminho de `ReadWritePaths` não existir. Por isso o Passo 1 (criar o arquivo) tem de vir **antes** da escrita da unit no script — confirmar a ordem no `install.sh`.

- [ ] **Passo 3: Verificar a sintaxe do script**

```bash
bash -n install.sh && python -m ruff check core/ scanners/
```

Esperado: sem saída do `bash -n` e `All checks passed!` do ruff.

- [ ] **Passo 4: Rodar o shellcheck (o hook exige)**

```bash
shellcheck install.sh 2>&1 | head -20
```

Esperado: sem erro novo introduzido por este bloco.

- [ ] **Passo 5: Subir a versão**

```bash
printf '1.7.0\n' > VERSION
```

Feature nova em MINOR, conforme o padrão do projeto.

- [ ] **Passo 6: Commit**

```bash
git add install.sh VERSION
git commit -m "chore(install): criar campaigns.json e liberá-lo no systemd

O serviço argus-web grava a configuração de campanha pela interface, e
ProtectSystem=full deixa /etc somente-leitura fora do ReadWritePaths — sem esta
entrada, salvar prefixos falharia com 'Read-only file system', como já ocorreu
com o logpush.json.

O arquivo é criado antes da unit porque o systemd recusa a unit inteira quando
um caminho de ReadWritePaths não existe."
```

---

## Validação em produção (após push e deploy)

O ciclo de entrega do projeto exige observar o comportamento rodando, não deduzir dos testes.

- [ ] `/version` mostra **1.7.0** e o commit da última tarefa
- [ ] Tela de Campanhas: as caixas de prefixos aparecem e a estimativa muda ao marcar/desmarcar
- [ ] Salvar com todos os prefixos desmarcados exceto "(sem prefixo)" e confirmar em `/etc/argus/campaigns.json`
- [ ] Disparar o scan e verificar no painel: "Campanha 1 de N · Etapa 1 de 6"
- [ ] No log do submonitor, confirmar a queda de candidatos: `[+] Candidatos: N total` deve cair ~5× com os prefixos desligados
- [ ] Uma campanha concluída deve ter achados no banco **antes** da campanha seguinte terminar
- [ ] `sudo journalctl -u argus-scan` (ou o log da execução) sem `Read-only file system`

**Preservar o `scan_status.json`** se houver falha — é a evidência que faltou no diagnóstico anterior:

```bash
sudo cp /etc/argus/store/scan_status.json ~/status-falha-$(date +%s).json
```

## Fora do escopo (registrado na spec)

- Cache negativo por rodízio dos candidatos que nunca resolveram — **é o próximo alvo**, vale ~7× de alívio
- Persistência em lotes dentro de uma campanha — descartada por medição (memória não é o gargalo)
- Loop por domínio em vez de campanha
- Limite rígido de candidatos (a estimativa avisa, não impede)
