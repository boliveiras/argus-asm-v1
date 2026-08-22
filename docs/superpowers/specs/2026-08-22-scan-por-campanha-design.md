# Execução por campanha e prefixos configuráveis

**Data:** 2026-08-22
**Estado:** aprovado, aguardando plano de implementação

## Problema

Campanha com muitos domínios e wordlist grande (>2000 linhas) faz o scan falhar:
a etapa termina com erro e nada é aproveitado.

Três causas se somam:

1. **Multiplicador oculto.** `PREFIXES` (`scanners/submonitor.py:167`) aplica 5
   variações a cada palavra da wordlist. Wordlist de 2000 = 10.000 candidatos por
   domínio. Com 4 domínios, 40.000 resoluções DNS — mais o que crt.sh, crt.name e
   urlscan acrescentam.
2. **Nada persiste até o fim.** `run_scan` resolve tudo em memória, enriquece, e só
   então `process_results` grava. Falha no minuto 200 descarta 200 minutos de
   trabalho.
3. **Tudo num lote só.** Rodar "todas as campanhas" processa todos os domínios de
   uma vez; não há ponto de corte onde o resultado parcial fique salvo.

### O que a medição descartou

**Memória não é a causa.** A VM tem 15 GB com 13 GB livres e o kernel nunca matou
processo algum (`dmesg` sem OOM). Por isso a persistência em lotes fica fora do
escopo: ela resolveria um problema que não está acontecendo.

**A causa provável é saturação do resolver DNS.** Dezenas de milhares de consultas
simultâneas degradam o DNS da máquina; cada consulta passa a demorar e repetir, e o
scan não trava — arrasta, até bater nas 4h do `STEP_TIMEOUT`. Há evidência direta:
durante um scan, o logpush falhou quatro vezes seguidas com
`não consegui resolver o host do webhook agora (falha de DNS)`, competindo pelo
mesmo resolver.

O erro exato da execução que falhou se perdeu (`scan_status.json` foi removido na
reinstalação), então isto é a hipótese mais sustentada, não uma confirmação. Reduzir
o volume ataca a causa provável e é condição necessária em qualquer cenário.

## Decisões

| Questão | Decisão |
|---|---|
| Prefixos | Configuráveis **por campanha** |
| Execução com várias campanhas | **Loop automático**, cada campanha do início ao fim |
| Campanha falha no meio do loop | **Continua**; aborta se 2 seguidas falharem |
| Escopo desta entrega | Loop + prefixos; medir antes de construir mais |
| Granularidade | Loop por **campanha** + estimativa de custo ao salvar |

Persistência em lotes (gravar a cada N hosts) fica **fora do escopo**: a medição
descartou memória como causa, e o corte de volume abaixo é de até 20×. Se o scan
ainda falhar depois disso, o `scan_status.json` da execução dirá o que falta — e
desta vez ele precisa ser preservado antes de qualquer reinstalação.

## Impacto no volume

| cenário | candidatos |
|---|---|
| hoje: 4 domínios × 2000 × 5 prefixos | 40.000 |
| loop por campanha (1 domínio) | 10.000 |
| loop + prefixos desligados | 2.000 |

## Componentes

### 1. Loop por campanha (`core/runner.py`)

`run_all(actor, campanha)` ganha dois modos:

- **Campanha específica** (`campanha` preenchida): comportamento atual, inalterado.
- **Todas** (`campanha` vazia): itera as campanhas do submonitor, executando os 6
  módulos para cada uma antes de passar à próxima.

Cada campanha é uma unidade que persiste antes da seguinte. O `LOCK_DIR` existente
envolve o loop inteiro — segue valendo uma execução por vez. `STEP_TIMEOUT` (4h)
continua por etapa.

**Tratamento de falha:** campanha que falha é registrada e o loop segue. Duas
campanhas seguidas falhando por completo abortam a execução; as restantes ficam
marcadas como puladas. O que já concluiu permanece salvo.

**Estado** (`scan_status.json`) ganha a dimensão de campanha, preservando os campos
existentes para não quebrar a interface:

```json
{
  "running": true,
  "campanha": "RIOCARD-B",
  "campanha_idx": 2,
  "campanhas_total": 4,
  "campanhas": [
    {"nome": "RIOCARD-A", "status": "succeeded"},
    {"nome": "RIOCARD-B", "status": "running"},
    {"nome": "RIOCARD-C", "status": "pending"}
  ],
  "steps": [ "...os 6 módulos da campanha atual..." ],
  "percent": 29
}
```

`percent` passa a ser global: `(campanhas_feitas × 6 + etapas_ok) / (total × 6)`.

### 2. Prefixos por campanha

Campanha hoje é apenas `targets/<NOME>.txt`, sem metadados. A configuração vai para
um **`/etc/argus/campaigns.json`** central, no mesmo padrão do `logpush.json`
(gravação in-place, permissão só no arquivo):

```json
{ "RIOCARD": { "prefixos": ["", "hml-", "dev-"] } }
```

- **Campanha ausente do arquivo** → usa o padrão atual. Retrocompatível: quem já tem
  campanha não vê mudança.
- **`[""]`** → apenas a palavra pura, sem prefixo.

**Segurança.** O prefixo vem da interface e é concatenado em hostname que depois é
resolvido e consultado. Validação no servidor com allowlist estrita
(`^[a-z0-9-]{0,20}$`), nunca só no navegador. Prefixo inválido é rejeitado na
gravação, não silenciosamente ignorado.

O `submonitor` lê a configuração da campanha que está processando e usa aquela lista
em `_build_candidates`; sem entrada, mantém `PREFIXES`.

### 3. Interface

- **Progresso**: "Campanha 2 de 4 · Etapa 3 de 6 — Subdomínios", com a lista de
  campanhas e seus status.
- **Recomendação** na tela de Campanhas, sem bloquear: campanha com muitos domínios
  demora e tende a falhar; um domínio por campanha é o caminho seguro.
- **Estimativa ao salvar**: número de candidatos que a configuração vai gerar
  (`domínios × wordlist × prefixos`). O custo fica visível antes de rodar, em vez de
  ser descoberto duas horas depois.
- **Prefixos**: caixas marcáveis com os cinco valores atuais, na tela de Campanhas.

## Testes

**Loop** — ordem de execução; resultado de uma campanha persistido antes da próxima;
abort após duas falhas seguidas com as restantes marcadas como puladas; campanha
específica mantém o comportamento atual; cálculo do percent global.

**Prefixos** — ausência da campanha usa o padrão; lista vazia gera só a palavra pura;
allowlist rejeita prefixo com caractere inválido (incluindo tentativa de injeção em
hostname); configuração de uma campanha não afeta outra.

**Interface** — a estimativa reflete `domínios × wordlist × prefixos`.

## Fora do escopo

- Persistência em lotes dentro de uma campanha (decidir após medir)
- Loop por domínio (exigiria mudar como os scanners recebem escopo e afetaria o
  agrupamento de relatórios e achados por campanha)
- Limite rígido de candidatos por campanha (por ora avisa, não impede)
