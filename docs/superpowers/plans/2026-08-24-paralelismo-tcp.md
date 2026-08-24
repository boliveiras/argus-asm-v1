# Paralelismo TCP configurável — Plano de Implementação

> **Para agentes:** SUB-SKILL OBRIGATÓRIA: use `superpowers:subagent-driven-development` (recomendado) ou `superpowers:executing-plans` para implementar tarefa a tarefa. Os passos usam checkbox (`- [ ]`).

**Objetivo:** Permitir varrer de 2 a 5 IPs simultaneamente na etapa de portas TCP, configurável por campanha, cortando o gargalo que hoje consome 80% do tempo do scan — sem que a aceleração custe cobertura em silêncio.

**Arquitetura:** O `campaigns.json` (já existente) ganha `paralelismo_tcp` por campanha. O laço sequencial de `scanners/monitor.py` vira um pool de threads limitado por esse valor, **apenas no modo TCP**. Ao final da varredura, a contagem de portas é comparada com a execução anterior; queda anômala com paralelismo ligado gera aviso explícito.

**Stack:** Python 3.13 (stdlib: `concurrent.futures`, `threading`), Flask (API), sem dependência nova.

## Restrições Globais

- **Testes com `unittest` da stdlib** — não há pytest. Rodar da raiz: `python -m unittest tests.test_X`
- **Suíte inteira sem regressão**: `python -m unittest discover -s tests -p "test_*.py"` — hoje **314 testes** (1 skip esperado no Windows)
- **Ruff limpo**: `python -m ruff check core/ scanners/ threatintel/`
- **Nunca commitar segredo** — repositório público
- **Default é 1** (série): campanha sem configuração mantém exatamente o comportamento atual
- **Faixa 1 a 5**, validada **no servidor**
- **Somente TCP** — o UDP ignora a configuração e continua em série
- **Nada de rede nos testes** — nmap é substituído por dublê
- **Comentários e mensagens em português**, explicando o *porquê*
- Medidas de referência (duas execuções reais, campanha PRODATA): **1,94 min por IP**, 84 IPs, TCP em 163 min, **214 portas ativas**

---

### Task 1: Configuração de paralelismo por campanha

**Arquivos:**
- Modificar: `core/campaigns.py` (junto de `prefixos_da_campanha`/`set_prefixos`)
- Testar: `tests/test_campaigns_paralelismo.py` (criar)

**Interfaces:**
- Consome: `ler_config()`, `_write_preservando()`, `valid_name()`, `CampaignError` (já existem)
- Produz:
  - `PARALELISMO_TCP_MIN = 1`, `PARALELISMO_TCP_MAX = 5`
  - `paralelismo_da_campanha(nome: str) -> int` — 1 quando ausente ou inválido
  - `set_paralelismo(nome: str, valor) -> int` — valida, grava e devolve o salvo; `CampaignError` se fora da faixa

- [ ] **Passo 1: Escrever os testes que falham**

Criar `tests/test_campaigns_paralelismo.py`:

```python
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
```

- [ ] **Passo 2: Rodar e verificar que falha**

```bash
python -m unittest tests.test_campaigns_paralelismo -v
```
Esperado: `AttributeError: module 'campaigns' has no attribute 'PARALELISMO_TCP_MIN'`.

- [ ] **Passo 3: Implementar**

Em `core/campaigns.py`, logo após `set_prefixos`, acrescentar:

```python
# Paralelismo da varredura TCP. O valor vira o número de nmaps simultâneos
# contra alvos reais: acima do teto, a perda de pacote faz porta ABERTA ser
# reportada como "filtered" e sumir do relatório — o scan fica mais rápido e
# mais pobre, sem dizer. Por isso a faixa é estreita e o padrão é série.
PARALELISMO_TCP_MIN = 1
PARALELISMO_TCP_MAX = 5


def paralelismo_da_campanha(nome: str) -> int:
    """Varreduras TCP simultâneas da campanha. 1 (série) quando não configurado.

    Revalida na LEITURA porque o arquivo pode ser editado à mão no servidor:
    um 20 gravado direto no JSON não pode virar 20 nmaps concorrentes.
    """
    entrada = ler_config().get(normalize_name(nome), {})
    if not isinstance(entrada, dict):
        return PARALELISMO_TCP_MIN
    try:
        valor = int(entrada.get("paralelismo_tcp", PARALELISMO_TCP_MIN))
    except (TypeError, ValueError):
        return PARALELISMO_TCP_MIN
    if not PARALELISMO_TCP_MIN <= valor <= PARALELISMO_TCP_MAX:
        return PARALELISMO_TCP_MIN
    return valor


def set_paralelismo(nome: str, valor) -> int:
    """Valida e grava o paralelismo TCP da campanha. Devolve o valor salvo."""
    nome = normalize_name(nome)
    if not valid_name(nome):
        raise CampaignError("nome de campanha inválido")
    try:
        valor = int(valor)
    except (TypeError, ValueError) as exc:
        raise CampaignError(
            f"paralelismo inválido: informe um número entre "
            f"{PARALELISMO_TCP_MIN} e {PARALELISMO_TCP_MAX}") from exc
    if not PARALELISMO_TCP_MIN <= valor <= PARALELISMO_TCP_MAX:
        raise CampaignError(
            f"paralelismo fora da faixa: use de {PARALELISMO_TCP_MIN} a "
            f"{PARALELISMO_TCP_MAX} (acima disso a varredura perde pacote e "
            f"deixa de reportar porta aberta)")
    cfg = ler_config()
    cfg[nome] = {**cfg.get(nome, {}), "paralelismo_tcp": valor}
    _gravar_config(cfg)
    return valor
```

**Atenção:** `set_prefixos` já contém a lógica de gravação com backup/restauração. Se ela estiver embutida na função (e não numa auxiliar `_gravar_config`), **extraia-a** para uma auxiliar compartilhada e faça as duas usarem — duplicar aquele bloco significaria manter duas cópias da proteção contra perda do arquivo. Confira o código atual antes de decidir o nome.

- [ ] **Passo 4: Rodar e verificar que passa**

```bash
python -m unittest tests.test_campaigns_paralelismo -v
```
Esperado: PASS nos 14 testes.

- [ ] **Passo 5: Suíte inteira e lint**

```bash
python -m unittest discover -s tests -p "test_*.py" 2>&1 | tail -3
python -m ruff check core/
```
Esperado: `OK` e `All checks passed!`.

- [ ] **Passo 6: Commit**

```bash
git add core/campaigns.py tests/test_campaigns_paralelismo.py
git commit -m "feat(campanhas): paralelismo da varredura TCP por campanha

O valor vira nmaps simultâneos contra alvos reais, então a faixa (1 a 5) é
validada no servidor E revalidada na leitura — um 20 editado à mão no JSON não
pode virar 20 varreduras concorrentes.

Padrão 1 (série): campanha sem configuração mantém o comportamento atual."
```

---

### Task 2: Execução paralela no monitor

**Arquivos:**
- Modificar: `scanners/monitor.py` (import tolerante de `campaigns`, laço em `main()`)
- Testar: `tests/test_monitor_paralelo.py` (criar)

**Interfaces:**
- Consome: `campaigns.paralelismo_da_campanha(nome) -> int` (Task 1); `run_scan(ip, campanha, mode) -> list[dict]` (já existe)
- Produz: `_varrer_alvos(ips, campanha, mode, paralelismo) -> list[dict]` — varre a lista e devolve os resultados agregados

- [ ] **Passo 1: Escrever os testes que falham**

Criar `tests/test_monitor_paralelo.py`:

```python
"""Varredura TCP paralela: acelerar não pode perder nem duplicar alvo.

Todos os testes substituem run_scan por um dublê — nenhum nmap roda. O que se
verifica aqui é a orquestração: cobertura completa, agregação correta e o UDP
permanecendo em série.
"""

import os
import sys
import tempfile
import threading
import types
import unittest

sys.modules.setdefault("nmap", types.ModuleType("nmap"))
sys.path.insert(0, "core")
sys.path.insert(0, "scanners")


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        os.environ["ARGUS_BASE"] = self.tmp.name
        os.environ.pop("ARGUS_DB", None)
        import monitor as M
        self.M = M
        self.chamados = []
        self.lock = threading.Lock()
        self.simultaneos = 0
        self.pico = 0

    def tearDown(self):
        self.tmp.cleanup()

    def dublê(self, atraso=0.0):
        """Substitui run_scan, registrando ordem de chamada e concorrência real."""
        import time

        def fake(ip, campanha, mode="tcp"):
            with self.lock:
                self.chamados.append(ip)
                self.simultaneos += 1
                self.pico = max(self.pico, self.simultaneos)
            if atraso:
                time.sleep(atraso)
            with self.lock:
                self.simultaneos -= 1
            return [{"ip": ip, "port": 443, "protocol": mode}]

        self.M.run_scan = fake


class TestCobertura(Base):
    def test_todos_os_alvos_sao_varridos_uma_vez(self):
        self.dublê()
        ips = [f"10.0.0.{i}" for i in range(1, 21)]
        res = self.M._varrer_alvos(ips, "CAMP", "tcp", 5)
        self.assertEqual(sorted(self.chamados), sorted(ips))   # nenhum pulado
        self.assertEqual(len(self.chamados), len(ips))          # nenhum repetido
        self.assertEqual(len(res), len(ips))                    # nada perdido na agregação

    def test_serie_e_paralelo_produzem_o_mesmo_conjunto(self):
        # O resultado não pode depender da ordem de conclusão.
        self.dublê()
        ips = [f"10.0.0.{i}" for i in range(1, 11)]
        serie = self.M._varrer_alvos(ips, "CAMP", "tcp", 1)
        self.chamados.clear()
        paralelo = self.M._varrer_alvos(ips, "CAMP", "tcp", 5)
        self.assertEqual(sorted(r["ip"] for r in serie),
                         sorted(r["ip"] for r in paralelo))

    def test_lista_vazia_nao_quebra(self):
        self.dublê()
        self.assertEqual(self.M._varrer_alvos([], "CAMP", "tcp", 3), [])


class TestConcorrencia(Base):
    def test_paralelismo_1_roda_em_serie(self):
        self.dublê(atraso=0.02)
        self.M._varrer_alvos([f"10.0.0.{i}" for i in range(1, 6)], "CAMP", "tcp", 1)
        self.assertEqual(self.pico, 1)

    def test_respeita_o_teto_configurado(self):
        self.dublê(atraso=0.05)
        self.M._varrer_alvos([f"10.0.0.{i}" for i in range(1, 21)], "CAMP", "tcp", 3)
        self.assertLessEqual(self.pico, 3)
        self.assertGreater(self.pico, 1)     # e de fato paralelizou

    def test_falha_em_um_alvo_nao_derruba_os_outros(self):
        # Um nmap que explode não pode abortar a varredura inteira.
        def fake(ip, campanha, mode="tcp"):
            if ip == "10.0.0.3":
                raise RuntimeError("nmap morreu")
            return [{"ip": ip, "port": 443, "protocol": mode}]

        self.M.run_scan = fake
        res = self.M._varrer_alvos([f"10.0.0.{i}" for i in range(1, 6)],
                                   "CAMP", "tcp", 3)
        self.assertEqual(len(res), 4)        # os outros quatro seguiram


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Passo 2: Rodar e verificar que falha**

```bash
python -m unittest tests.test_monitor_paralelo -v
```
Esperado: `AttributeError: module 'monitor' has no attribute '_varrer_alvos'`.

- [ ] **Passo 3: Implementar**

Em `scanners/monitor.py`, junto do import tolerante de `filtrar_campanhas` (linha ~55), acrescentar:

```python
try:
    from campaigns import paralelismo_da_campanha as _paralelismo_da_campanha
except Exception:                                   # pragma: no cover
    def _paralelismo_da_campanha(nome):
        return 1
```

E no topo, junto dos demais imports da stdlib:

```python
from concurrent.futures import ThreadPoolExecutor, as_completed
```

Acrescentar a função de varredura (antes de `main`):

```python
def _varrer_alvos(ips: list[str], campanha: str, mode: str,
                  paralelismo: int) -> list[dict]:
    """Varre a lista de IPs e devolve os resultados agregados.

    Thread pool basta porque o nmap é processo externo e o trabalho é espera de
    rede — não há disputa de CPU (3min32 de CPU para 3h23 de relógio na medição
    que motivou isto) nem estado compartilhado dentro de run_scan.

    Falha de um alvo NÃO derruba os demais: um nmap que morre custa aquele IP,
    não a varredura inteira.
    """
    total = len(ips)
    if total == 0:
        return []
    if paralelismo <= 1:
        # Caminho de série idêntico ao histórico — inclusive na saída impressa.
        resultados: list[dict] = []
        for i, ip in enumerate(ips, 1):
            print(f"[{i}/{total}]", end=" ")
            try:
                resultados.extend(run_scan(ip, campanha, mode))
            except Exception as exc:
                print(f"  [ERRO] {ip}: {exc}", file=sys.stderr)
        return resultados

    resultados = []
    concluidos = 0
    with ThreadPoolExecutor(max_workers=paralelismo) as pool:
        futuros = {pool.submit(run_scan, ip, campanha, mode): ip for ip in ips}
        for fut in as_completed(futuros):
            ip = futuros[fut]
            concluidos += 1
            # Imprime ao TERMINAR, não ao começar: com execuções concorrentes,
            # anunciar o início embaralha a saída e o progresso deixa de fazer
            # sentido para quem acompanha o log.
            try:
                parciais = fut.result()
                resultados.extend(parciais)
                print(f"[{concluidos}/{total}] {ip}: {len(parciais)} porta(s)")
            except Exception as exc:
                print(f"[{concluidos}/{total}] {ip}: ERRO — {exc}", file=sys.stderr)
    return resultados
```

Em `main()`, substituir o laço interno (por volta da linha 950):

```python
            for campanha, targets in campaigns:
                ips = _expand_targets(targets)
                # Paralelismo só no TCP: o UDP não tem handshake e a distinção
                # entre "aberta" e "filtrada" já é frágil — concorrência ali
                # multiplica o falso negativo num scan que também não é o gargalo.
                paralelo = _paralelismo_da_campanha(campanha) if mode == "tcp" else 1
                extra = f" — {paralelo} em paralelo" if paralelo > 1 else ""
                print(f"\n--- Campanha: {campanha} ({len(ips)} IP(s) — "
                      f"varredura individual {mode.upper()}{extra}) ---")
                all_results.extend(_varrer_alvos(ips, campanha, mode, paralelo))
```

- [ ] **Passo 4: Rodar e verificar que passa**

```bash
python -m unittest tests.test_monitor_paralelo -v
```
Esperado: PASS nos 6 testes.

- [ ] **Passo 5: Suíte inteira e lint**

```bash
python -m unittest discover -s tests -p "test_*.py" 2>&1 | tail -3
python -m ruff check core/ scanners/ threatintel/
```

- [ ] **Passo 6: Commit**

```bash
git add scanners/monitor.py tests/test_monitor_paralelo.py
git commit -m "feat(monitor): varrer portas TCP em paralelo conforme a campanha

A varredura TCP consumia 80% do scan (163 min para 84 IPs) com a máquina
ociosa: 3min32 de CPU em 3h23 de relógio, esperando pacote. Um IP por
invocação do nmap, em série.

Thread pool limitado pelo valor da campanha, só no TCP. Falha de um alvo não
derruba os demais, e o progresso passa a ser impresso ao terminar cada IP —
anunciar o início embaralharia a saída com execuções concorrentes."
```

---

### Task 3: Verificação de cobertura

**Arquivos:**
- Modificar: `scanners/monitor.py` (após a varredura TCP, antes de `syslog_end`)
- Testar: `tests/test_monitor_cobertura.py` (criar)

**Interfaces:**
- Consome: contagem de portas do resultado atual; histórico do banco do monitor
- Produz: `_alertar_queda_cobertura(campanha, achadas, paralelismo) -> str | None` — devolve a mensagem de aviso, ou `None` quando não há o que alertar

- [ ] **Passo 1: Escrever os testes que falham**

Criar `tests/test_monitor_cobertura.py`:

```python
"""Aviso de queda de cobertura após varredura paralela.

Sob concorrência o nmap não falha: ele reclassifica porta ABERTA como
'filtered', que não entra no relatório. O scan termina bem, mais rápido e com
menos achados — sem nada denunciar. Este aviso é o que torna esse risco
verificável, comparando com a execução anterior da mesma campanha.
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
        os.environ.pop("ARGUS_DB", None)
        import monitor as M
        self.M = M

    def tearDown(self):
        self.tmp.cleanup()

    def com_historico(self, anterior):
        """Finge que a execução anterior encontrou `anterior` portas."""
        self.M._portas_da_execucao_anterior = lambda campanha: anterior


class TestAviso(Base):
    def test_queda_grande_com_paralelismo_alerta(self):
        self.com_historico(214)
        aviso = self.M._alertar_queda_cobertura("PRODATA", 120, 5)
        self.assertIsNotNone(aviso)
        self.assertIn("214", aviso)
        self.assertIn("120", aviso)

    def test_queda_pequena_nao_alerta(self):
        # Variação normal entre execuções não pode virar alarme.
        self.com_historico(214)
        self.assertIsNone(self.M._alertar_queda_cobertura("PRODATA", 200, 5))

    def test_queda_em_serie_nao_alerta(self):
        # Com paralelismo 1 a causa não é concorrência: alertar aqui seria ruído.
        self.com_historico(214)
        self.assertIsNone(self.M._alertar_queda_cobertura("PRODATA", 50, 1))

    def test_aumento_nao_alerta(self):
        self.com_historico(100)
        self.assertIsNone(self.M._alertar_queda_cobertura("PRODATA", 214, 5))

    def test_sem_historico_nao_alerta(self):
        # Primeira execução da campanha: não há com o que comparar.
        self.com_historico(0)
        self.assertIsNone(self.M._alertar_queda_cobertura("PRODATA", 10, 5))

    def test_aviso_sugere_reduzir(self):
        self.com_historico(214)
        aviso = self.M._alertar_queda_cobertura("PRODATA", 100, 5)
        self.assertIn("paralelismo", aviso.lower())


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Passo 2: Rodar e verificar que falha**

```bash
python -m unittest tests.test_monitor_cobertura -v
```

- [ ] **Passo 3: Implementar**

Em `scanners/monitor.py`:

```python
# Queda além disto, com paralelismo ligado, vira aviso. Variação entre
# execuções é normal (host que cai, serviço reiniciado); 30% é a fronteira
# escolhida para separar ruído de sinal — ajuste se a prática mostrar outro.
QUEDA_COBERTURA_ALERTA = 0.30


def _portas_da_execucao_anterior(campanha: str) -> int:
    """Portas ativas registradas para a campanha antes desta execução.

    Lê do banco do monitor. Zero quando não há histórico (primeira execução),
    e zero também em qualquer erro: a verificação é conveniência e não pode
    impedir o scan de terminar.
    """
    try:
        conn = sqlite3.connect(DATABASE_FILE, timeout=5)
        try:
            cur = conn.execute(
                "SELECT COUNT(*) FROM scans WHERE campanha=? AND protocol='tcp' "
                "AND status IN ('NOVO','REINCIDENTE','RESSURGIDO')", (campanha,))
            return int(cur.fetchone()[0] or 0)
        finally:
            conn.close()
    except Exception:
        return 0


def _alertar_queda_cobertura(campanha: str, achadas: int,
                             paralelismo: int) -> str | None:
    """Mensagem de aviso quando a cobertura cai de forma suspeita, ou None.

    Só alerta com paralelismo acima de 1: em série, uma queda tem outras causas
    (o alvo realmente fechou portas) e o aviso seria ruído.
    """
    if paralelismo <= 1:
        return None
    anterior = _portas_da_execucao_anterior(campanha)
    if anterior <= 0:
        return None                     # sem histórico, nada a comparar
    if achadas >= anterior * (1 - QUEDA_COBERTURA_ALERTA):
        return None
    return (f"cobertura caiu de {anterior} para {achadas} porta(s) com "
            f"paralelismo {paralelismo} — sob concorrência o nmap pode "
            f"reportar porta aberta como filtrada. Se a queda não for esperada, "
            f"reduza o paralelismo da campanha e compare.")
```

Chamar após a varredura TCP da campanha, em `main()`, registrando no log e no syslog:

```python
                if mode == "tcp":
                    aviso = _alertar_queda_cobertura(
                        campanha, len([r for r in all_results
                                       if r.get("campanha") == campanha
                                       and r.get("protocol") == "tcp"]),
                        paralelo)
                    if aviso:
                        print(f"  [COBERTURA] {campanha}: {aviso}", file=sys.stderr)
                        syslog_write("WARN", "COVERAGE_DROP", aviso,
                                     module=SYSLOG_APP, campanha=campanha,
                                     paralelismo=str(paralelo))
```

**Confira** o nome do campo de campanha no dicionário de resultado de `run_scan` antes de usar `r.get("campanha")` — se for outro, ajuste.

- [ ] **Passo 4: Rodar, suíte e lint**

```bash
python -m unittest tests.test_monitor_cobertura -v
python -m unittest discover -s tests -p "test_*.py" 2>&1 | tail -3
python -m ruff check core/ scanners/ threatintel/
```

- [ ] **Passo 5: Commit**

```bash
git add scanners/monitor.py tests/test_monitor_cobertura.py
git commit -m "feat(monitor): avisar quando a cobertura cai com paralelismo ligado

Dos riscos do paralelismo, bloqueio e consumo de recurso são visíveis. A perda
de pacote não é: o nmap reclassifica porta ABERTA como 'filtered', que não
entra no relatório — o scan fica mais rápido e mais pobre sem dizer nada.

A comparação com a execução anterior torna isso verificável. Só avisa: o
sistema não sabe distinguir 'o alvo fechou serviços' de 'perdi pacote', e
reduzir o paralelismo sozinho mexeria na configuração do operador por palpite."
```

---

### Task 4: API e interface

**Arquivos:**
- Modificar: `core/webapp.py` (GET `/api/campaigns` e nova rota), `core/reporter.py` (editor de campanha)
- Testar: `tests/test_paralelismo_api.py` (criar)

**Interfaces:**
- Consome: `campaigns.paralelismo_da_campanha`, `set_paralelismo`, `PARALELISMO_TCP_MIN/MAX` (Task 1)
- Produz:
  - `GET /api/campaigns` inclui `paralelismo_tcp` em cada campanha do escopo `monitor`, mais `paralelismo_min`/`paralelismo_max`
  - `POST /api/campaigns/<scope>/<name>/paralelismo` — body `{"paralelismo": 3}`

- [ ] **Passo 1: Escrever os testes que falham**

Criar `tests/test_paralelismo_api.py`:

```python
"""API do paralelismo TCP por campanha."""

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
        alvos = base / "monitor" / "targets"
        alvos.mkdir(parents=True, exist_ok=True)
        (alvos / "PRODATA.txt").write_text("10.0.0.1\n10.0.0.2\n", encoding="utf-8")
        import webapp
        self.app = webapp.create_app().test_client()
        self.H = {"X-Requested-With": "argus", "X-Remote-User": "monitor"}

    def tearDown(self):
        os.environ.pop("ARGUS_DB", None)
        self.tmp.cleanup()


class TestLeitura(Base):
    def test_get_traz_faixa_e_valor_atual(self):
        j = self.app.get("/api/campaigns?scope=monitor", headers=self.H).get_json()
        self.assertEqual(j["paralelismo_min"], 1)
        self.assertEqual(j["paralelismo_max"], 5)
        camp = j["campaigns"]["monitor"][0]
        self.assertEqual(camp["paralelismo_tcp"], 1)     # padrão: série


class TestGravacao(Base):
    def test_grava_e_devolve_na_leitura(self):
        r = self.app.post("/api/campaigns/monitor/PRODATA/paralelismo",
                          headers=self.H, json={"paralelismo": 3})
        self.assertEqual(r.status_code, 200)
        j = self.app.get("/api/campaigns?scope=monitor", headers=self.H).get_json()
        self.assertEqual(j["campaigns"]["monitor"][0]["paralelismo_tcp"], 3)

    def test_fora_da_faixa_recusado_com_400(self):
        r = self.app.post("/api/campaigns/monitor/PRODATA/paralelismo",
                          headers=self.H, json={"paralelismo": 20})
        self.assertEqual(r.status_code, 400)

    def test_sem_csrf_recusado(self):
        r = self.app.post("/api/campaigns/monitor/PRODATA/paralelismo",
                          headers={"X-Remote-User": "monitor"},
                          json={"paralelismo": 2})
        self.assertEqual(r.status_code, 403)

    def test_escopo_submonitor_recusado(self):
        # Paralelismo é da varredura de portas; em domínios não faz sentido.
        r = self.app.post("/api/campaigns/submonitor/PRODATA/paralelismo",
                          headers=self.H, json={"paralelismo": 2})
        self.assertEqual(r.status_code, 400)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Passo 2: Rodar e verificar que falha**

- [ ] **Passo 3: Implementar a API**

Em `core/webapp.py`, no `list_campaigns`, acrescentar ao laço de escopos (junto do que já faz para `submonitor`):

```python
                if s == "monitor":
                    for c in campanhas:
                        c["paralelismo_tcp"] = CAMP.paralelismo_da_campanha(c["name"])
```

E na resposta, acrescentar `paralelismo_min=CAMP.PARALELISMO_TCP_MIN, paralelismo_max=CAMP.PARALELISMO_TCP_MAX`.

Nova rota, no mesmo padrão da de prefixos:

```python
    @app.post("/api/campaigns/<scope>/<name>/paralelismo")
    def set_campaign_paralelismo(scope, name):
        if not _csrf_ok():
            _audit(request, "AUTHZ_DENY", "ação negada: header CSRF ausente",
                   outcome="deny", action="campaign_paralelismo")
            return jsonify(ok=False, error="CSRF: header ausente"), 403
        # Só faz sentido no escopo de IPs: a varredura paralela é de portas.
        if scope != "monitor":
            return jsonify(ok=False,
                           error="paralelismo se aplica apenas a campanhas de IPs"), 400
        dados = request.get_json(silent=True) or {}
        try:
            salvo = CAMP.set_paralelismo(name, dados.get("paralelismo", 1))
        except CAMP.CampaignError as exc:
            return jsonify(ok=False, error=str(exc)), 400
        _audit(request, "CAMPAIGN_UPDATE",
               f"paralelismo TCP da campanha {name} definido em {salvo}",
               outcome="success", action="campaign_paralelismo", obj=name,
               object_type="campaign")
        return jsonify(ok=True, paralelismo=salvo)
```

- [ ] **Passo 4: Implementar a interface**

Em `core/reporter.py`, no editor de campanha (`camp-editor`), acrescentar um bloco visível apenas no escopo `monitor`, no mesmo estilo do bloco de prefixos (`cp-prefixos-bloco`):

- `<select id="cp-paralelismo">` com as opções de 1 a 5 (rotular o 1 como "1 (série)")
- Um `<div id="cp-paralelismo-aviso">` com o texto de risco
- Estimativa de tempo, usando a medida real de **~2 min por IP**: mostrar o tempo previsto em série e com o valor escolhido

O aviso precisa citar os três riscos, e o invisível em destaque. Sugestão de texto:

> Varredura mais rápida, porém: pode chamar atenção do alvo (bloqueio), consumir mais rede da máquina e — o mais silencioso — **fazer porta aberta ser reportada como filtrada e sumir do relatório**. Se a contagem de portas cair sem explicação, reduza.

Ligar o `change` do select à mesma função de estimativa, e enviar o valor no `save()` da campanha, em requisição separada (como já é feito com os prefixos), tratando a falha sem desfazer a campanha já salva.

Consulte como o bloco de prefixos foi implementado e siga o mesmo padrão — inclusive `esc()` em tudo que vier da API.

- [ ] **Passo 5: Testar a página**

Acrescentar a `tests/test_campaigns_page.py`:

```python
    def test_tem_bloco_de_paralelismo(self):
        self.assertIn("cp-paralelismo", self.html)

    def test_avisa_sobre_porta_filtrada(self):
        # O risco invisível precisa estar escrito, não só o de bloqueio.
        self.assertIn("filtrada", self.html.lower())
```

- [ ] **Passo 6: Suíte, lint e conferência local**

```bash
python -m unittest discover -s tests -p "test_*.py" 2>&1 | tail -3
python -m ruff check core/ scanners/ threatintel/
python -c "
import sys, types; sys.modules.setdefault('nmap', types.ModuleType('nmap')); sys.path.insert(0,'core')
import reporter; open('/tmp/camp.html','w',encoding='utf-8').write(reporter.build_campaigns_page())
print('página gerada')
"
```

- [ ] **Passo 7: Subir a versão e commitar**

```bash
printf '1.10.0\n' > VERSION
git add core/webapp.py core/reporter.py tests/ VERSION
git commit -m "feat(ui): configurar o paralelismo TCP na campanha

Campo de 1 a 5 no editor de campanhas de IPs, com estimativa de tempo baseada
na medida real (~2 min por IP) e aviso dos três riscos — com destaque para o
que o operador não consegue perceber sozinho: porta aberta reportada como
filtrada, sumindo do relatório.

A gravação é requisição separada, como a de prefixos: falhar nela não desfaz a
campanha já salva."
```

---

## Validação em produção (após push e deploy)

O ciclo do projeto exige observar rodando, não deduzir dos testes.

- [ ] `/version` mostra **1.10.0** e o commit da última tarefa
- [ ] Editor de campanha de IPs mostra o campo, a estimativa muda ao trocar o valor, e o aviso está visível
- [ ] Definir **5** na campanha PRODATA e conferir em `/etc/argus/campaigns.json`
- [ ] Rodar o scan e cronometrar a etapa de Portas TCP

**Critério de sucesso, medido:**

| medida | referência | alvo |
|---|---|---|
| TCP | 163 min (84 IPs, série) | **< 70 min** |
| portas ativas | 214 | **≥ ~214** |

- [ ] Conferir a contagem depois:
```bash
sudo sqlite3 /etc/argus/store/argus.db "SELECT COUNT(*) FROM findings WHERE source='monitor' AND active=1;"
```
- [ ] Se o aviso de cobertura aparecer no log, **reduzir o paralelismo e repetir** — é o sinal de que 5 é demais neste ambiente
- [ ] Confirmar que o **UDP continuou em série** (o tempo dele não deve mudar: ~24 min)

## Fora do escopo

- Paralelismo no UDP
- Agrupar por rede/ASN para não concentrar carga no mesmo destino
- Reduzir `--top-ports` ou filtrar alvo morto — as outras saídas para o gargalo, com custo de cobertura
