# Argus — Attack Surface Monitor

> *O que tudo vê na sua superfície de ataque.* Nome inspirado em **Argos Panoptes**,
> o gigante de cem olhos da mitologia grega.

Plataforma de **monitoramento de superfície de ataque** para Linux (Debian/Ubuntu/Kali).
Faz varredura de portas, descoberta de subdomínios e checagem de **credenciais
vazadas** (infostealer), enriquece os achados com inteligência de ameaças (AbuseIPDB,
Certificate Transparency, urlscan.io, Hudson Rock e RDAP/WHOIS) e publica relatórios
HTML em um portal Apache com TLS e autenticação.

> **Nota:** o nome de produto é **Argus**. Por compatibilidade, os identificadores
> técnicos seguem como `argus-monitor` (comando, `/etc/argus`, etc.).

---

## Índice

- [Componentes](#componentes)
- [Arquitetura e fluxo](#arquitetura-e-fluxo)
- [Instalação](#instalação)
- [Configuração](#configuração)
- [Uso](#uso)
- [Modelo de risco](#modelo-de-risco)
- [Relatórios e portal web](#relatórios-e-portal-web)
- [Logs (RFC 5424)](#logs-rfc-5424)
- [Layout no sistema e permissões](#layout-no-sistema-e-permissões)
- [Segurança](#segurança)
- [Desinstalação](#desinstalação)
- [Solução de problemas](#solução-de-problemas)
- [Licença](#licença)

---

## Componentes

| Arquivo | Papel |
|---|---|
| `install.sh` | Instalador completo (14 etapas). Suporta `--no-apache` e `--uninstall`. |
| `monitor.py` | Scan de **portas TCP** com Nmap (top 1000), classificação de risco, resolução de ASN e geração de relatório. |
| `submonitor.py` | Scan de **subdomínios** (assíncrono) — wordlist + crt.sh + urlscan.io, detecção de ambiente/WAF/DNSSEC/SSL/RDAP. |
| `credentials.py` | **Exposição de credenciais** — consulta logs de infostealer por domínio (Hudson Rock, grátis), metadata-only. |
| `reporter.py` | Gerador de relatórios HTML **e do portal** (design system único; `write_portal()` cria index/dashboard/guia + `assets/app.css`). |
| `threatintel/` | Biblioteca reutilizável de Threat Intelligence. |

### Pacote `threatintel/`

```
threatintel/
├── config.json                  # API key + thresholds + caminhos
├── providers/
│   ├── abuseipdb.py             # reputação de IP (API AbuseIPDB v2)
│   ├── crtsh.py                 # Certificate Transparency (descoberta passiva)
│   ├── urlscan.py               # urlscan.io Search API (descoberta passiva + contexto web)
│   ├── hudsonrock.py            # Hudson Rock Cavalier (infostealer por domínio, grátis)
│   └── whois_lookup.py          # idade/expiração do domínio via RDAP (cache em intel.db)
└── core/
    ├── database.py              # conexão + schema SQLite (threatintel.db)
    ├── cache.py                 # cache de reputação (TTL 48h)
    ├── quota.py                 # controle de cota diária da API
    ├── reputation.py            # Risk Engine (combina porta + reputação)
    └── utils.py                 # validação de IP, helpers de score
```

---

## Arquitetura e fluxo

```
   targets (IPs) ──────▶┌─────────────────────────────────────┐
                        │  monitor.py  (Nmap -sV --top-ports) │
                        │  • risco por porta × tipo de IP     │
                        │  • ASN + AbuseIPDB → monitor.db     │
                        └─────────────────────────────────────┘
   targets (domínios) ─▶┌─────────────────────────────────────┐
   subs.txt ───────────▶│  submonitor.py  (DNS + HTTP async)  │   ┌──────────────────────┐
                        │  • wordlist + crt.sh + urlscan.io   │──▶│  Apache2 (:8443)     │
                        │  • WAF/CDN · DNSSEC · SSL · RDAP    │   │  TLS + Basic Auth    │
                        │  • AbuseIPDB → submonitor.db        │   │                      │
                        └─────────────────────────────────────┘   │  index · dashboard   │
   (reusa domínios) ───▶┌─────────────────────────────────────┐   │  risk-guide          │
                        │  credentials.py            │   │  monitor / submonitor│
                        │  • Hudson Rock (infostealer)        │──▶│  credentials reports │
                        │  • metadata-only → credentials.db   │   └──────────────────────┘
                        └─────────────────────────────────────┘
```

Os três scanners são **independentes** (campanhas por arquivo `.txt`) e publicam
seus relatórios no mesmo portal. O `argus-credentials` **reaproveita os domínios
do submonitor** por padrão.

---

## Instalação

Pré-requisitos: Debian/Ubuntu/Kali com `apt`, acesso root e Python 3.10+.

```bash
sudo bash install.sh                 # instalação completa (com Apache)
sudo bash install.sh --no-apache     # sem portal web (relatórios locais)
sudo bash install.sh --uninstall     # remove crons, comandos e Apache vhost
```

O instalador executa, em ordem:

1. Verifica privilégios (root) e sistema operacional.
2. Instala dependências de sistema: `nmap`, `python3`, `pip`, `openssl`,
   e (se aplicável) `apache2` + `apache2-utils`.
3. Instala dependências Python: `python-nmap`, `requests`, `aiodns`, `aiohttp`,
   `dnspython`, `python-whois`.
4. Cria a estrutura de diretórios em `/etc/argus`.
5. Copia os scripts e aplica permissões seguras.
6. Configura `PYTHONPATH` nos rcfiles de root e do app user.
7. Ajusta `config.json` (caminhos) e solicita a **API key do AbuseIPDB**.
8. Cria os comandos globais `argus-monitor` e `argus-submonitor`.
9. Configura `logrotate` (rotação semanal, 12 semanas).
10. Configura o Apache2 (TLS self-signed, Basic Auth, headers de segurança).
11. Instala os crons diários.
12. Valida a instalação (imports, binários, diretórios, serviços).

> **Variáveis editáveis** no topo do `install.sh`: `BASE_DIR`, `APACHE_PORT`
> (padrão `8443`), `APACHE_USER` (padrão `monitor`) e `APP_USER` (padrão `kali`).

---

## Configuração

### `threatintel/config.json`

```json
{
    "abuseipdb_api_key": "SUA_API_KEY_AQUI",
    "cache_ttl_hours": 48,
    "request_timeout": 15,
    "daily_request_limit": 1000,
    "abuse_score_alto": 50,
    "abuse_score_critico": 80,
    "abuse_score_eleva_porta_critica": 25,
    "max_age_in_days": 90,
    "urlscan_api_key": "SUA_API_KEY_AQUI",
    "urlscan_request_timeout": 15,
    "urlscan_daily_request_limit": 1000,
    "urlscan_cache_ttl_hours": 336,
    "db_path": "CONFIGURADO_PELO_INSTALADOR",
    "log_dir": "CONFIGURADO_PELO_INSTALADOR"
}
```

As API keys também podem ser fornecidas por variáveis de ambiente — `ABUSEIPDB_KEY`
e `URLSCAN_KEY` — que têm precedência sobre o arquivo. O caminho do config pode ser
sobrescrito com `THREATINTEL_CONFIG`. O instalador pergunta as duas chaves.

### Campanhas (targets)

Crie um arquivo `.txt` por empresa/campanha. O **nome do arquivo** é o nome da
campanha e é a chave de correspondência entre monitor e submonitor.

```bash
# IPs / hosts para o monitor de portas
sudo nano /etc/argus/monitor/targets/EMPRESA.txt

# Domínios para o submonitor
sudo nano /etc/argus/submonitor/targets/EMPRESA.txt

# Wordlist de subdomínios (usada pelo submonitor)
sudo nano /etc/argus/submonitor/subs.txt
```

Linhas iniciadas por `#` e linhas em branco são ignoradas.

---

## Uso

```bash
argus-monitor        # scan de portas TCP (padrão)
argus-monitor --tcp  # idem (explícito)
argus-monitor --udp  # scan de portas UDP (100 portas críticas, opt-in)
argus-submonitor     # executa o scan de subdomínios
argus-credentials    # exposição de credenciais (infostealer)
argus-email          # postura de e-mail (SPF/DMARC/DKIM)
argus-typosquat      # domínios sósia / typosquatting (dnstwist, semanal)
argus-finding        # gestão de achados: list/show/set/note/evidence (status, FP, evidências)
argus-ack            # reconhece um achado (RECONHECIDO → INFO) com motivo
```

Todos também rodam automaticamente por cron:

| Tarefa | Horário | Cron |
|---|---|---|
| `monitor` (TCP) | 10:00 diariamente | `/etc/cron.d/argus-monitor` |
| `monitor` (UDP) | **domingo 03:00** (semanal) | `/etc/cron.d/argus-monitor-udp` |
| `submonitor` | 12:00 diariamente | `/etc/cron.d/argus-submonitor` |
| `email` | 13:00 diariamente | `/etc/cron.d/argus-email` |
| `credentials` | 14:00 diariamente | `/etc/cron.d/argus-credentials` |
| `typosquat` | **domingo 05:00** (semanal) | `/etc/cron.d/argus-typosquat` |

Para (re)instalar apenas o cron de um script, manualmente:

```bash
sudo python3 /etc/argus/monitor/monitor.py --install-cron
sudo python3 /etc/argus/submonitor/submonitor.py --install-cron
```

### Reconhecimento de achados (`argus-ack`)

Quando o analista revisa um achado e decide que aquele risco é **conhecido e
aceito/tratado** (ex.: porta de firewall corporativo, ambiente interno
autorizado, exposição já tratada pelo SOC), ele pode **reconhecê-lo**. A partir
da próxima execução o achado passa a aparecer com status **`RECONHECIDO`** e
risco **`INFO`** — saindo de CRÍTICO/ALTO/MÉDIO/BAIXO em toda a interface
(tabela, filtros, KPIs e gráfico de distribuição) e do Resumo Executivo.

```bash
# chave do monitor = IP:PORTA/PROTO
argus-ack add 1.2.3.4:179/tcp "firewall corporativo, esperado"
# chave do submonitor = HOSTNAME
argus-ack add dev.acme.com "ambiente interno autorizado"
# chave de credenciais = DOMINIO (precisa de -m credentials)
argus-ack add acme.com "exposição já tratada pelo SOC" -m credentials

argus-ack list                  # lista todos os reconhecimentos
argus-ack rm 1.2.3.4:179/tcp    # remove (volta ao risco real)
```

O módulo é autodetectado pela forma da chave (`IP:porta/proto` → monitor; caso
contrário → submonitor; use `-m credentials` para domínios). O reconhecimento é
apenas uma **camada de triagem na apresentação**: o banco de cada scanner
continua registrando o risco e o status reais de detecção, preservando o diff
`NOVO`/`REINCIDENTE` e a detecção de `FECHADO`/`REMOVIDO`. O store fica em
`/etc/argus/acknowledged.db`.

---

## Modelo de risco

O risco final é calculado em duas camadas. **O risco nunca é rebaixado pela
inteligência de ameaças — apenas elevado.**

### Camada 1 — risco base

**Monitor (portas):** determinado pela porta aberta × tipo de IP (público/privado).
Apenas portas com estado `open` entram no relatório (`filtered` é descartado).
Ex.: `23/Telnet → CRÍTICO` sempre; `3306/MySQL → CRÍTICO` público / `ALTO` privado;
`22/SSH → MÉDIO` público / `BAIXO` privado.

**Submonitor (subdomínios):** baseado em hostname, ambiente, WAF e tipo de IP.

| Condição | Risco |
|---|---|
| IP público + sem WAF + ambiente DEV/HML | CRÍTICO |
| IP público + sem WAF + PROD | ALTO |
| IP público + keyword de gestão no hostname (grafana, jenkins, vault, …) | MÉDIO |
| IP público + com WAF | BAIXO |
| IP privado | BAIXO |

> **Detecção de WAF/CDN (passiva):** feita a partir dos headers HTTP **e nomes de
> cookies** já coletados na sondagem (sem requisição extra). O rótulo distingue
> `WAF (<vendor>)` de `CDN (<vendor>)` — pois a presença de um CDN
> (Cloudflare/CloudFront/Fastly/Akamai…) indica proxy reverso, mas **não garante**
> um WAF ativo. Confirmar WAF ativo exigiria sonda comportamental (envio de payload
> suspeito), não realizada por ser intrusiva.

### Camada 2 — elevação por AbuseIPDB (`core/reputation.py`)

| Condição | Efeito |
|---|---|
| score ≥ 80 (`abuse_score_critico`) | → CRÍTICO |
| score ≥ 50 (`abuse_score_alto`) | → mínimo ALTO |
| porta crítica + score > 25 (`abuse_score_eleva_porta_critica`) | → CRÍTICO |
| node TOR | +1 nível |
| datacenter/hosting + score > 0 | +1 nível |
| IP privado (RFC1918) | não consultado |

### Varredura UDP (`--udp`, opt-in)

Além do TCP (top-1000, diário), o monitor faz uma varredura **UDP opt-in** de
**100 portas curadas por criticidade** (não pela frequência do nmap): OOB/ICS/RCE
(IPMI, VxWorks, BACnet, DNP3, EtherNet/IP…), VPN/DNS/SIP/RADIUS, *poisoning*
(LLMNR/NetBIOS/mDNS) e refletores de amplificação (SNMP, CLDAP, memcached,
chargen, NTP…). Tem **tabela de criticidade própria** (`_UDP_PORT_RISK`), também
elevada por IP público × privado e por AbuseIPDB.

```bash
argus-monitor --udp            # varredura UDP agora
argus-monitor --tcp --udp      # os dois em sequência
```

Como UDP é lento/ambíguo, a varredura é **fixa em 100 portas**, com
`--max-retries 1`, `--host-timeout` e só reporta portas **confirmadas abertas**
(descarta `open|filtered`). Por isso roda em **cadência semanal** (domingo 03:00),
separada do TCP diário — sem atrapalhar o scan principal.

**Página unificada:** TCP e UDP convivem na **mesma** página "Portas"
(`monitor_report.html`), distinguidos pela coluna/filtro **Proto** e por um KPI
**Portas UDP**. O relatório é uma **projeção do banco** (`scans`, coluna
`protocol`): cada scan regenera a visão completa sem apagar o outro protocolo, e
o diff de fechamento é **escopado por protocolo** (um scan UDP nunca fecha portas
TCP). A reputação AbuseIPDB é **persistida** no banco (por IP) para o relatório
unificado. Os logs também são **únicos** — mesmo `monitor.log` RFC 5424, com o
campo `transport=tcp|udp` para o SIEM separar.

### Vulnerabilidades por IP (Shodan InternetDB)

Provider **gratuito e sem API key** (`threatintel/providers/internetdb.py`) que
enriquece **por IP** com inteligência **passiva** do Shodan:

```
GET https://internetdb.shodan.io/<ip>
→ { cpes, hostnames, ip, ports, tags, vulns:["CVE-..."] }
```

Adiciona a dimensão de **vulnerabilidades (CVE)** ao Argus — aplica tanto ao
**monitor** (por IP de cada porta) quanto ao **submonitor** (por IP de cada host):
coluna **CVEs** (contagem + lista no tooltip), **filtro** Com/Sem CVE e KPI
**IPs vulneráveis**. Cache próprio (`internetdb_cache/`, TTL 24h) + cota diária,
como os demais providers.

**Elevação de risco conservadora** (decisão de projeto): IP com **≥ 1 CVE
conhecida → no mínimo ALTO**; combinado a porta crítica/IP abusivo pode chegar a
CRÍTICO pelas outras camadas. **CVE sozinha não força CRÍTICO** — o matching do
Shodan é heurístico (banner/CPE) e pode ter **falso-positivo**, então os CVEs são
*leads a validar*. Dado **passivo/histórico**: pode não enxergar o que está atrás
de firewall que bloqueia o Shodan. No monitor, o resumo (CVEs/tags/portas) é
**persistido no banco** para alimentar o relatório unificado.

### Inteligência de domínio (RDAP / WHOIS)

Dados de registro consultados via **RDAP** (Registration Data Access Protocol —
o substituto moderno do WHOIS, em HTTP/JSON). O servidor de cada TLD é descoberto
pelo bootstrap da IANA (cache de 7 dias) com override fixo para `.br`. Se o RDAP
falhar, há fallback silencioso para `python-whois` (porta 43).

Classificação por idade/expiração, com cache de 14 dias em `intel.db`:
`NOVO` (<30d) · `RECENTE` (<1 ano) · `ESTABELECIDO` · `EXPIRANDO` (<30d) · `EXPIRADO`.

### Descoberta passiva e contexto web (urlscan.io)

O submonitor usa a **Search API do urlscan.io** (apenas consulta histórica — nunca
submete URLs, para não expor o inventário do alvo na base pública). Ela atua em
duas frentes:

- **Descoberta** — subdomínios já vistos em scans históricos viram candidatos
  (origem `urlscan`, ao lado de `wordlist` e `crtsh`).
- **Contexto por host** — para cada subdomínio ativo, anexa o último scan conhecido:
  servidor, IP, ASN, país, título e UUID (+ URLs de screenshot e relatório).

Requer API key gratuita (`urlscan_api_key`). Cache em arquivo (TTL 14 dias) e cota
diária própria. Os dados aparecem no **syslog** do submonitor nos campos
`urlscan_seen`, `urlscan_server`, `urlscan_ip`, `urlscan_asn`, `urlscan_country` e
`urlscan_uuid`.

### Exposição de credenciais (infostealer — Hudson Rock)

O `argus-credentials` consulta a **Cavalier API do Hudson Rock** (gratuita, sem
chave) para cada domínio das campanhas, retornando **agregados** de exposição em
logs de infostealer — **metadata-only**, nunca as credenciais em si. A unidade do
relatório é o **domínio**.

| Condição | Risco |
|---|---|
| Funcionário comprometido (máquina interna em stealer log) | CRÍTICO |
| Usuário/cliente comprometido (account takeover) | ALTO |
| Apenas terceiros | MÉDIO |
| Nenhum comprometimento | BAIXO |

Também lista as **aplicações da organização mais expostas** (URLs de login que
aparecem nos logs, com contagem de ocorrências). Cache próprio (TTL 24h) e cota
diária. Campos de syslog: `domain`, `total`, `employees`, `users`,
`third_parties`, `top_url`.

**Targets:** por padrão **reutiliza os domínios do submonitor**
(`submonitor/targets/*.txt`) — sem listas duplicadas. Para um conjunto diferente
só de credenciais, coloque `.txt` em `credentials/targets/` (tem precedência
quando não está vazio).

### Postura de e-mail / anti-spoofing (SPF · DMARC · DKIM)

O `argus-email` avalia, **só por DNS** (grátis, sem API), a autenticação de
e-mail de cada domínio — a falta dela é um dos maiores facilitadores de phishing
e fraude (BEC). A unidade do relatório é o **domínio**.

| Verificação | O que checa |
|---|---|
| **MX** | o domínio recebe e-mail? (contexto + relevância do DKIM) |
| **SPF** | registro `v=spf1`; qualificador `-all`/`~all`/`?all`/`+all`; nº de lookups (limite 10); duplicidade |
| **DMARC** | `_dmarc`; política `p=none`/`quarantine`/`reject`; presença de `rua` |
| **DKIM** | *best-effort*: sonda seletores comuns (`default`, `google`, `selector1/2`…) — o seletor não é descobrível por DNS |

**Score por domínio:** `+all` ou (sem SPF **e** sem DMARC eficaz) → **CRÍTICO**;
sem SPF · DMARC ausente/`p=none` · SPF inválido → **ALTO**; `p=quarantine` ·
`~all`/`?all` · sem DKIM → **MÉDIO**; `-all` + `p=reject` + DKIM → **BAIXO/INFO**.
A coluna **Problemas** detalha cada falha encontrada.

> **Importante:** domínios **sem MX também são avaliados** — um domínio que não
> envia e-mail ainda deve ter `-all` + `p=reject` para impedir spoofing do *From*.
> O DKIM é informativo (best-effort). Compatível com `argus-ack -m email`.

**Targets:** reutiliza os domínios do submonitor por padrão; override em
`email/targets/`. Verificação paralela (8 domínios por vez). Campos de syslog:
`domain`, `has_mx`, `spf`, `dmarc`, `dkim`, `issues`.

---

## Relatórios e portal web

Interface com **identidade visual de ferramenta ASM** (tema dark, navegação
persistente, KPIs de severidade, donut de risco, tabelas com acento por
severidade). Com Apache habilitado, o portal fica em `https://<IP>:8443/`
(Basic Auth):

- **index** — hub de navegação do produto.
- **dashboard.html** — KPIs consolidados, distribuição de risco, painéis por
  scanner, campanhas e agenda dos scans (lê os números dos relatórios em tempo real).
- **risk-guide.html** — guia de classificação de risco.
- **monitor_report.html** — superfície exposta (IPs e portas abertas).
- **submonitor_report.html** — subdomínios ativos e seus riscos.
- **credentials_report.html** — exposição de credenciais por domínio (infostealer).
- **email_report.html** — postura de e-mail por domínio (SPF/DMARC/DKIM).

**Design system de fonte única:** todo o CSS vive em `reporter.py`
(`_common_css`). Os relatórios o **inlinam** (ficam portáteis); o portal estático
é gerado por `reporter.write_portal()` durante a instalação, que também grava
`/var/www/argus/assets/app.css`. Tudo é offline/self-contained (sem
CDN; logo e donut em SVG inline).

Os relatórios são gravados diretamente no docroot (`/var/www/argus`)
a cada execução e também copiados ao lado do script. O vhost bloqueia o acesso
direto a arquivos `.db`, `.log`, `.json`, `.py` e `.sh` (o CSS/assets são servidos
normalmente).

### Resumo executivo

Cada relatório abre com um painel **"Resumo Executivo"** gerado automaticamente dos
dados (sem texto manual) — útil para técnico **e** gestão, e impresso no PDF:

- **Narrativa** — ex.: "N porta(s) aberta(s), X crítica(s) e Y de alto risco exigem atenção."
- **Principais riscos** — top 5 findings por severidade.
- **Recomendações** — acionáveis, disparadas pelo que foi encontrado (banco exposto →
  restringir; RDP → VPN/MFA; domínio recém-registrado → verificar phishing; credencial
  de funcionário → reset + MFA; …).
- **Evidências** — a tabela detalhada logo abaixo.

### Colunas configuráveis

Cada tabela tem um menu **"▦ Colunas"** que permite mostrar/ocultar colunas
individualmente. A escolha é **persistida por relatório** (localStorage) e
**respeitada na impressão/exportação em PDF** — útil para gerar um PDF enxuto
(ex.: só Campanha, IP, Porta, Serviço e Risco) sem a tabela estourar a página,
mesmo em paisagem.

### Exports para Red Team / Threat Intel

Cada relatório tem um seletor **"⬇ Export…"** que gera arquivos a partir do
conjunto **já filtrado** (client-side, respeita os filtros aplicados):

| Relatório | Export | Para |
|---|---|---|
| **Subdomínios** | `hosts.txt` · `urls_vivas.txt` · `ips_publicos.txt` | httpx · ffuf · gobuster · nuclei · katana · Nmap |
| **Portas** | `targets_ips.txt` (`-iL`) · `host_port.txt` · `urls_web.txt` | Nmap · Nessus · OpenVAS · Nuclei · httpx |
| **Credenciais** | `*.json` (estruturado) · `apps_expostas.txt` | Threat Intel / investigação |

Para produção, troque o certificado self-signed por Let's Encrypt:

```bash
sudo apt install certbot python3-certbot-apache
sudo certbot --apache -d seu.dominio.com
```

---

## Logs (RFC 5424)

Os três scanners emitem syslog estruturado (RFC 5424) com SD-PARAMS sob
`[origin@32473 ...]`, prontos para SIEM. Campos-chave:

- **`run_id`** — correlation ID único por execução (correlaciona todas as linhas)
- **`module`** + **APP-NAME** (`monitor`/`submonitor`/`credentials`) e **`version`**
- **`status`** (`success`/`error`) + **`duration_s`** no `SCAN_END`
- **estatísticas** (`novos`, `reincidentes`, `criticos`, …) e **erros detalhados**
  (`context`, `error_type`) no `SCAN_ERR`

```
/var/log/argus/monitor/monitor.log
/var/log/argus/submonitor/submonitor.log
/var/log/argus/credentials/credentials.log
```

Exemplo de `SCAN_END`:
```
<134>1 ...Z host credentials 25140 SCAN_END [origin@32473 run_id="cb5e..."
  module="credentials" status="success" novos="3" criticos="1" duration_s="42"] ...
```

`stdout`/`stderr` das execuções por cron ficam em `*_stdout.log` nos mesmos
diretórios. A rotação é semanal (12 semanas) via `logrotate`.

---

## Layout no sistema e permissões

```
/etc/argus/                 # BASE_DIR
├── reporter.py
├── monitor/        monitor.py · targets/ · monitor.db · monitor_report.html
├── submonitor/     submonitor.py · subs.txt · targets/ · submonitor.db · ...
└── threatintel/    (setgid, grupo do app user)
    ├── config.json          640 root:<app>   (API key — root rw, app ro)
    ├── threatintel.db        664 root:<app>   (cache AbuseIPDB — escrita compartilhada)
    ├── intel.db              664 root:<app>   (cache WHOIS)
    └── crtsh_cache/          2775 (cache crt.sh)

/var/log/argus/monitor      · /var/log/argus/submonitor       (750 root:adm)
/var/www/argus                         (docroot do Apache)
/etc/ssl/argus                         (certificado TLS)
```

**Modelo de execução:** o `monitor` roda como **root** (necessário para o SYN
scan `-sS` e via cron/sudo; sem root, cai para TCP connect `-sT`); o `submonitor`
pode rodar como **root** (cron) ou
como o **app user** (comando global). Como `threatintel.db` é escrito por ambos,
o diretório `threatintel/` usa o bit **setgid** com grupo do app user, os bancos
ficam `664`, e os processos rodam com **`umask 0002`** (configurado nos comandos
globais e nos crons) — assim os arquivos auxiliares do SQLite (`-wal`/`-shm`)
criados por root permanecem graváveis pelo app user.

---

## Segurança

Práticas aplicadas (referências: OWASP Top 10 / ASVS, CIS, NIST CSF):

- **Validação de entrada** — todo target/domínio passa por validação estrita
  (IP/CIDR/hostname). Linhas que poderiam injetar *flags* do nmap (ex.: `-oN`,
  `--script`) ou metacaracteres de shell são **ignoradas com aviso** (OWASP A03).
- **Gestão de segredos** — chaves de API em `config.json` (`640 root:app`),
  nunca em log/relatório; override por variável de ambiente.
- **Saída HTML** — escaping em `esc()` e dados embutidos com `<` → `<`
  (anti-XSS armazenado).
- **Apache** — TLS, Basic Auth, `Options -Indexes`, bloqueio de `.db/.log/.json/.py/.sh`,
  cabeçalhos de segurança (CSP, Permissions-Policy, X-Frame-Options, …). **HSTS**
  fica comentado por padrão (só habilitar com certificado válido / Let's Encrypt).
- **Degradação graciosa** — providers nunca derrubam o scan; erros vão para o syslog.

---

## Desinstalação

```bash
sudo bash install.sh --uninstall
```

Remove crons, comandos globais, o vhost do Apache e a config do logrotate.
**Os dados em `/etc/argus` são preservados.** Para removê-los:

```bash
sudo rm -rf /etc/argus
```

---

## Solução de problemas

| Sintoma | Causa provável / ação |
|---|---|
| `reporter.py não encontrado no PYTHONPATH` | `PYTHONPATH` não inclui `/etc/argus`. Reabra o shell ou rode pelo comando global. |
| `Módulo threatintel não encontrado` | idem acima — reputação fica desativada, o scan continua. |
| AbuseIPDB sem dados / `no_api_key` | API key não configurada em `threatintel/config.json`. |
| `Cota esgotada` | limite diário (`daily_request_limit`) atingido; reseta no dia seguinte. |
| Host "inacessível ou filtrado" no Nmap | firewall/filtragem ou host realmente offline. |
| Portal não abre | `apache2ctl configtest`; verifique se a porta 8443 está liberada. |
| Aviso de certificado no browser | certificado self-signed — aceite o aviso ou use Let's Encrypt. |

Validação rápida dos imports (como o instalador faz):

```bash
PYTHONPATH=/etc/argus python3 -c \
  "from reporter import generate_monitor_report; \
   from threatintel.providers.abuseipdb import get_ip_reputation; print('OK')"
```

---

## Licença

Copyright (C) 2026 Bruno Santos.

Este projeto é distribuído sob a **GNU Affero General Public License v3.0
(AGPL‑3.0)** — veja o arquivo [`LICENSE`](LICENSE) para o texto completo.

A AGPL é uma licença copyleft forte: você pode usar, estudar, modificar e
redistribuir o software, desde que os derivados permaneçam sob a mesma licença
e com o código-fonte disponível. Diferente da GPL comum, a AGPL também cobre o
**uso em rede**: se você disponibilizar uma versão modificada como serviço
(por exemplo, expondo o portal web a usuários remotos), deve oferecer a esses
usuários o código-fonte correspondente.

```
Argus — monitoramento de superfície de ataque
Copyright (C) 2026  Bruno Santos

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.
```
