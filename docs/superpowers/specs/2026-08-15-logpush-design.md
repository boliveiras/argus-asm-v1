# Logpush — envio dos logs do Argus para destinos externos

**Data:** 15/08/2026 · **Projeto:** argus-asm-v1 · **Status:** design aprovado, pronto para plano

---

## 1. Problema

O Argus vai rodar numa VPS (Contabo), fora dos ambientes que monitora — de propósito, para ter
apenas visão externa. Os logs ficam presos nessa instância: quem opera precisa entrar na VPS para
ler qualquer coisa, e nada chega ao SIEM.

Falta um caminho de saída dos logs para um destino externo, sem abrir a VPS para dentro da rede.

## 2. Objetivo

Enviar o que está em `/var/log/argus/**` para destinos externos configurados **pela interface web**,
sem perder mensagem e sem duplicar.

**Não faz parte deste escopo:** WhatsApp (exige Cloud API da Meta, número verificado e template
aprovado — não é webhook; fica como projeto à parte se virar requisito), rotação/retenção dos logs
(já resolvida pelo logrotate existente) e qualquer alteração no formato dos logs atuais.

## 3. Decisões e o porquê

| Decisão | Motivo |
|---|---|
| Serviço próprio em Python, padrão plugável | O padrão (base + subclasse por destino + registry) já está documentado em `.docs/llm-integration-standard.md` e em uso no `argus-cti-v1`. `boto3` já é dependência do `pull-logs-s3`. |
| **Não** usar rsyslog | Cobriria syslog/SIEM sem código, mas **não** cobre S3 (exigiria SigV4 na unha via `omhttp`) — e S3 é o destino principal. Também tiraria a configuração da web. |
| Objetos **write-once** no S3 | O `pull-logs-s3` decide o que baixar por `LastModified` (`pull_s3_logs.py:188`). Um "arquivo do dia" reescrito a cada ciclo ganharia `LastModified` novo toda vez, e o pull rebaixaria o arquivo inteiro — **duplicação em massa** no SIEM. |
| Ponteiro avança só após confirmação | Falha transitória não pode virar buraco permanente. Mesma postura já aplicada em ASN, e-mail e credenciais. |
| Ponteiro guarda `(inode, posição)` | O logrotate usa `create`: o arquivo novo tem inode diferente. Só a posição faria o push pular linhas a cada rotação. |
| Webhook com mensagem formatada | Linha RFC 5424 crua em chat é ilegível. O bucket recebe o original; o webhook recebe a visão humana. |

## 4. Arquitetura

```
/var/log/argus/**/*.log ──> logpush.py ──> LogDestination ──> S3 | Webhook | Syslog
                                │
                                └── logpush_state.json   (inode + posição por arquivo)
```

| Componente | Arquivo | Responsabilidade |
|---|---|---|
| Coletor | `core/logpush.py` | Descobre arquivos das origens ligadas, lê o que há de novo a partir do ponteiro, lida com rotação, agrupa e entrega ao destino, avança o ponteiro. **Não sabe o que é S3.** |
| Contrato | `core/logpush_dest/base.py` | `LogDestination.send(mensagens) -> None`. Levanta `LogPushError` em falha. Único ponto que muda ao trocar de destino. |
| Destinos | `core/logpush_dest/{s3,webhook,syslog}.py` | Só o transporte. |
| Config | `core/logpush_config.py` | Catálogo de destinos, campos, liga/desliga, segredos e origens selecionadas — espelha `providers.py`. |
| Formatação | `core/logpush_fmt.py` | RFC 5424 → texto legível por plataforma de chat. |
| Interface | página **Logpush** em `reporter.py` | Configuração, estado do último envio e teste de conexão. |
| Execução | `argus-logpush.timer` + `.service` | Oneshot a cada 5 min, no modelo do `argus-scan.path` existente. |

## 5. Origens selecionáveis

Cada origem liga/desliga independente na interface:

| Origem | Caminho | Formato |
|---|---|---|
| Portas | `/var/log/argus/monitor/monitor.log` | RFC 5424 |
| Subdomínios | `/var/log/argus/submonitor/*.log` | RFC 5424 |
| Credenciais | `/var/log/argus/credentials/*.log` | RFC 5424 |
| E-mail | `/var/log/argus/email/*.log` | RFC 5424 |
| Typosquat | `/var/log/argus/typosquat/*.log` | RFC 5424 |
| Auditoria | `/var/log/argus/audit/audit.log` | RFC 5424 (`argus@32473`) |
| Saída de execução | `/var/log/argus/scan/*.log`, `monitor_stdout.log` | texto cru |

Ao ligar uma origem pela primeira vez, o ponteiro começa **no fim do arquivo** (não reenvia
histórico), com opção explícita "enviar desde o início".

## 6. Destino S3

**Layout:**

```
logs/argus/<modulo>/DD-MM-AAAA-HH-mm-SS.log
logs/argus/<modulo>/DD-MM-AAAA-HH-mm-SS-002.log    ← sufixo apenas quando há disputa no mesmo segundo
```

- **Uma mensagem por objeto** para as origens RFC 5424.
- **Uma execução por objeto** para a saída de execução (stdout): um scan gera milhares de linhas de
  progresso; linha a linha viraria milhares de objetos de uma linha cada, caros de listar e baixar.
  O arquivo já tem cabeçalho (`# comando`, `# fim`, `rc=`) e se lê inteiro.
- **Sufixo anticolisão obrigatório**: o segundo não é único (o submonitor registrou 9 hosts em menos
  de um segundo). Sem sufixo, o S3 sobrescreve silenciosamente e a mensagem some sem erro.
- Objetos nunca são reescritos. Compatível com o watermark do `pull-logs-s3`.

**Config:** bucket, prefixo (padrão `logs/argus`), região, `endpoint_url` opcional (MinIO, Wasabi,
R2), access key e secret.

## 7. Destino Webhook

**Plataformas** (seletor): Google Chat, Slack, Discord, Microsoft Teams, Telegram, Genérico (JSON cru).

| Plataforma | Payload |
|---|---|
| Google Chat, Slack | `{"text": "..."}` |
| Discord | `{"content": "..."}` |
| Teams | card |
| Telegram | Bot API `sendMessage` (token + chat_id) |
| Genérico | JSON com os campos do evento |

**Filtro por severidade — checkboxes independentes:** CRÍTICO, ALTO, MÉDIO, BAIXO, INFO.
Padrão: CRÍTICO + ALTO.

Ao marcar todas, a interface avisa:

> ⚠️ Com todas as severidades ligadas, uma execução pode disparar centenas de mensagens. O último
> scan gerou 35 achados — a maioria dos serviços de chat aplica limite de taxa e passa a descartar.

**Formatação** (`logpush_fmt.py`): emoji e título derivam da severidade e do `MSGID`
(`PORT_NEW`, `HOST_NEW`, `CRED_LEAK`, `AUTHZ_DENY`…); os detalhes saem do structured data.

```
🔴 CRÍTICO · Nova porta exposta
104.18.9.141:443 (https) — campanha RIOCARD
ASN Cloudflare, Inc. · VirusTotal: 7 motores
15/08/2026 13:35
```

A saída de execução (texto cru) **não** vai para webhook — não tem severidade nem estrutura, e só
geraria ruído. Vai apenas para S3/syslog.

## 8. Estado e entrega

`/etc/argus/store/logpush_state.json`:

```json
{
  "monitor/monitor.log": {"inode": 1234567, "pos": 88213, "enviado_em": "2026-08-15T13:35:47Z"},
  "audit/audit.log":     {"inode": 1234891, "pos": 12044, "enviado_em": "2026-08-15T13:35:47Z"}
}
```

- Ponteiro avança **somente** após o destino confirmar. Falhou → o ciclo seguinte retoma do mesmo
  ponto: não perde e não duplica.
- Retry com backoff dentro do ciclo; esgotado, registra o motivo (status HTTP, exceção) e mantém o
  ponteiro. **Falha silenciosa é proibida** — sem o motivo registrado não há diagnóstico.
- **Rotação:** inode diferente do gravado → lê o que falta em `.log.1` (o `delaycompress` garante que
  ainda está descomprimido) e depois segue do início do arquivo novo.
- Teto por ciclo (`logpush_max_por_ciclo`, padrão 5000) para uma origem represada não travar o envio.

**Limitação conhecida — saída de execução:** `/var/log/argus/scan/*.log` é *sobrescrito* a cada
execução (não entra no logrotate, que cobre só `*.log` dos módulos). Se dois scans rodarem entre dois
ciclos de push, a saída do primeiro se perde. Com ciclo de 5 min e scans que levam minutos a horas,
isso é improvável; para eliminar de vez seria preciso o runner passar a versionar o arquivo por
execução — mudança no runner, fora deste escopo. As origens RFC 5424 não têm esse risco: são
append-only e protegidas pelo logrotate.

## 9. Segurança

- Credenciais (access key, secret, URL de webhook, token) no config com `640 root:argus` + ACL,
  como as chaves de API. **Nunca** devolvidas inteiras pela API — só sufixo mascarado.
- Envio sempre por HTTPS/TLS. Timeout em toda chamada.
- URL de webhook validada: apenas `https://`, sem IP privado nem `localhost` (evita usar o Argus
  como pivô para a rede interna).
- Erro nunca inclui credencial; corpo de resposta truncado.
- Escrita e alteração da config passam pelo RBAC existente (perfil `user` não altera).
- Toda mudança de configuração vai para a trilha de auditoria.

## 10. Interface (página Logpush)

- Liga/desliga geral e por destino.
- Seleção das origens (checkbox por módulo).
- Campos do destino escolhido, com segredo mascarado.
- Webhook: seletor de plataforma + checkboxes de severidade + aviso de flood.
- Estado: último envio, nº de mensagens, erro atual.
- **Testar conexão**: envia uma mensagem de prova e mostra o resultado.

## 11. Testes

| O que | Como |
|---|---|
| Rotação | Gravar, rotacionar (novo inode), gravar de novo → nada perdido, nada duplicado |
| Falha do destino | Destino que levanta → ponteiro não avança; próximo ciclo reenvia |
| Colisão de nome | Várias mensagens no mesmo segundo → objetos distintos |
| Formatação | Linha RFC 5424 real → texto esperado por plataforma |
| Filtro de severidade | Só as marcadas saem |
| Segredo | `GET` da config nunca devolve chave inteira |
| SSRF | URL com IP privado/`http://` é recusada |

Destinos testados com dublê (sem rede); o teste real de S3 e webhook é o botão "testar conexão".

## 12. Fora de escopo (YAGNI)

Compressão antes do envio, particionamento Hive (`year=/month=/day=`), múltiplos destinos
simultâneos do mesmo tipo, reprocessamento de histórico e fila persistente própria — o arquivo de
log local, mantido pelo logrotate, já é o buffer.
