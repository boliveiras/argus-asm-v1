# Paralelismo configurável na varredura de portas TCP

**Data:** 2026-08-24
**Estado:** aguardando aprovação

## Problema

A varredura de portas TCP consome **80% do tempo total do scan** e é o gargalo
seguinte depois que a etapa de subdomínios foi resolvida.

Medição de duas execuções reais na VM (campanha PRODATA):

| | rodada 1 | rodada 2 |
|---|---|---|
| IPs | 80 | 84 |
| TCP | 164 min | 163 min |
| **min/IP** | 2,05 | **1,94** |
| CPU do processo inteiro | 4min04 | 3min32 |
| memória (pico) | 254 MB | 184 MB |

O scan roda **um IP por invocação do nmap, em série** (`scanners/monitor.py`,
laço em `main()`). Com 3,5 minutos de CPU em 3h23 de relógio, a máquina passa
98% do tempo esperando pacote — o recurso está ocioso, não saturado.

Hoje não estoura o `STEP_TIMEOUT` de 4h, mas a margem é estreita: uma campanha
com dois domínios, ou alvos fora de CDN (onde cada nome vira um IP distinto em
vez de dezenas compartilharem o mesmo), dobra o tempo e a etapa é cortada.

## Decisões

| Questão | Decisão |
|---|---|
| Escopo | **Somente TCP**. UDP fica de fora |
| Configuração | **Por campanha**, no `campaigns.json` que já existe |
| Faixa | 1 a 5; **default 1** (comportamento atual) |
| Aviso | Deve citar o risco invisível, não só bloqueio |
| Verificação | Comparar cobertura com a execução anterior |

**Por que o UDP fica de fora:** ele não tem handshake, então distinguir "aberta"
de "filtrada" depende de resposta ou de ICMP — sob concorrência a ambiguidade
cresce muito mais rápido que no TCP. Já roda com `--max-retries 1` e
`--host-timeout 8m` justamente por ser caro, e são só 24 min contra 163 do TCP:
o ganho não paga o risco.

## O risco que o desenho precisa endereçar

Dos três riscos do paralelismo, dois são visíveis e um não é:

- **Bloqueio pelo alvo** (WAF, rate limit) — o scan falha ou o alvo responde
  erro. Perceptível.
- **Esgotar recurso local** (conntrack, banda) — o scan degrada de forma
  observável. Perceptível.
- **Perda de pacote reclassificando porta** — **invisível**. Sob concorrência, o
  nmap não reporta erro: uma porta **aberta** vira **`filtered`**, e `filtered`
  não entra no relatório. O scan termina "com sucesso", mais rápido, com menos
  achados, e nada indica que a diferença veio da configuração.

O terceiro é o que importa. Numa ferramenta cujo valor é dizer "isto está
exposto", um acelerador que faz achado sumir em silêncio é a pior troca
possível — e é o mesmo padrão que este projeto já corrigiu três vezes (ASN
sticky, crt.sh fora do ar, origem pulada no logpush): falha que se disfarça de
resultado legítimo.

## Componentes

### 1. Configuração por campanha

Reusa o `campaigns.json` (`core/campaigns.py`), no mesmo padrão dos prefixos:

```json
{ "PRODATA": { "prefixos": [""], "paralelismo_tcp": 3 } }
```

- Ausente ou inválido → **1** (série, comportamento atual)
- Faixa aceita: 1 a 5, validada **no servidor**
- Campanha sem entrada não muda de comportamento — retrocompatível

### 2. Execução paralela (`scanners/monitor.py`)

`run_scan(ip, campanha, mode)` já é independente por IP e devolve lista; o
enriquecimento e a persistência acontecem depois, sobre o conjunto completo.
A mudança é trocar o laço sequencial por um pool de threads com o limite da
campanha, **apenas quando `mode == "tcp"`**.

O nmap é processo externo e o trabalho é espera de rede, então thread pool
basta — não há disputa de CPU nem estado compartilhado dentro de `run_scan`.

A saída de progresso (`[i/N]`) precisa continuar legível com execuções
concorrentes: cada IP imprime ao **terminar**, não ao começar.

### 3. Verificação de cobertura

Ao final da varredura TCP de uma campanha, comparar o número de portas
encontradas com a execução anterior da mesma campanha (dado que o `argus.db` já
guarda).

Se a contagem cair além de um limiar (proposta: **30%**) e o paralelismo estiver
acima de 1, registrar aviso explícito no log e no evento de syslog dizendo que a
queda **pode ser perda de pacote por concorrência**, sugerindo reduzir o valor.

Isso transforma o risco invisível em verificável, usando dado que já existe.

**Decisão:** apenas **avisar**. O sistema não tem como distinguir "o alvo fechou
serviços" de "perdi pacote por concorrência" — as duas coisas produzem a mesma
queda. Reduzir o paralelismo sozinho mexeria na configuração que o operador
gravou, com base num palpite, e poderia baixar por engano justamente quando a
queda é real. O aviso entrega a informação; a decisão continua de quem conhece o
alvo.

### 4. Interface

Na tela de Campanhas, no escopo de IPs (monitor):

- Campo numérico 1 a 5, com o padrão 1
- Estimativa do tempo, usando a medida real (~2 min por IP): mostrar
  quanto a varredura deve levar em série e com o valor escolhido
- Aviso citando os três riscos, com destaque para o falso negativo:
  *"acima de 1, porta aberta pode ser classificada como filtrada e sumir do
  relatório"*

## Critério de sucesso

Com paralelismo 5 na campanha PRODATA (84 IPs):

- TCP **abaixo de 70 min** (hoje: 163)
- **Pelo menos ~214 portas** encontradas (a contagem atual: 65 crítico, 26 alto,
  59 médio, 64 baixo)

Se o tempo cair mas a contagem também, o paralelismo está custando cobertura e o
número honesto para este ambiente é menor que 5.

## Testes

**Configuração** — valor ausente/inválido vira 1; faixa 1-5 validada no
servidor; configuração de uma campanha não afeta outra.

**Execução** — com paralelismo 1 o comportamento é idêntico ao atual; com N>1
todos os IPs são varridos exatamente uma vez (nenhum pulado, nenhum repetido);
o resultado agregado independe da ordem de conclusão; UDP ignora a configuração
e roda em série.

**Cobertura** — queda além do limiar gera aviso; queda com paralelismo 1 **não**
gera (aí a causa não é concorrência); primeira execução, sem histórico, não
alarma.

## Fora do escopo

- Paralelismo no UDP
- Agrupar por rede/ASN para não concentrar carga no mesmo destino (paralelizar
  IPs de redes distintas e serializar os do mesmo /24). Mais preciso, bem mais
  código — reavaliar se a concentração se mostrar problema
- Reduzir `--top-ports` ou filtrar alvo morto: são as outras duas saídas para o
  gargalo, com custo de cobertura, e só fazem sentido se o paralelismo não
  bastar
