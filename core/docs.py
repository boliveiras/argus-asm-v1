#!/usr/bin/env python3
#
# Argus ASM — monitoramento de superfície de ataque
# Copyright (C) 2026  Bruno Santos
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""
docs — conteúdo da documentação embutida no portal.

Vive fora do reporter porque é TEXTO, não layout: quem escreve documentação não
deveria precisar mexer no gerador de páginas. O painel lateral do portal lê daqui.

Cada seção tem um `id` que casa com a página correspondente, para o painel abrir
já no assunto certo: estando em Campanhas, abre em Campanhas.
"""

from __future__ import annotations

# (id, título, corpo HTML). O id casa com a chave de navegação da página.
SECOES: list[tuple[str, str, str]] = [
    ("inicio", "O que é o Argus", """
<p>O Argus olha para a sua empresa <b>de fora</b>, como um estranho olharia: quais
portas estão abertas na internet, quais subdomínios existem, se as senhas dos
funcionários vazaram, se alguém registrou um domínio parecido com o seu.</p>

<p>Ele roda sozinho, todos os dias, e guarda o histórico. O que importa não é a
foto de hoje — é perceber que <b>ontem essa porta não estava aberta</b>.</p>

<p class="doc-nota">Nada é apagado. Um achado que some continua registrado como
corrigido, porque saber que algo foi resolvido tem valor quando ele reaparece.</p>
"""),

    ("fluxo", "Como usar no dia a dia", """
<ol class="doc-passos">
  <li><b>Cadastre uma campanha</b> — o conjunto de IPs ou domínios de um cliente
      ou de uma unidade. É o escopo de tudo o que vem depois.</li>
  <li><b>Rode o scan</b> — pelo botão <b>▶ Rodar agora</b> ou esperando o
      agendamento diário.</li>
  <li><b>Trate os achados</b> — em Gestão de Achados, cada item recebe um estado:
      em tratamento, mitigado ou falso positivo, com nota e evidência.</li>
  <li><b>Acompanhe</b> — o Dashboard mostra o resumo; a Correlação mostra o que
      está ligado a quê.</li>
</ol>
"""),

    ("achados", "O ciclo de um achado", """
<p>Cada achado tem <b>duas informações independentes</b>, e confundir as duas é o
erro mais comum:</p>

<table class="doc-tabela">
  <tr><th>Estado</th><th>Quem define</th><th>O que significa</th></tr>
  <tr><td>Presença</td><td>o scanner</td>
      <td>o achado <b>ainda existe</b> lá fora, ou deixou de aparecer</td></tr>
  <tr><td>Tratativa</td><td>você</td>
      <td>o que a equipe <b>decidiu</b>: em tratamento, mitigado, falso positivo</td></tr>
</table>

<p>Um achado marcado como mitigado que volta a aparecer é sinalizado como
<b>ressurgido</b> — porque alguém achou que tinha resolvido e não resolveu.</p>

<p class="doc-nota">Um achado que some não é apagado na hora: ele espera três dias
antes de contar como corrigido. Serviço que cai e volta não é problema
resolvido.</p>

<p><b>Como tratar:</b> pelos controles da coluna <b>Ações</b>, onde dá para mudar o
estado, anexar nota e registrar evidência. Toda mudança fica na trilha de
auditoria, com autor e data.</p>

<p>Pelo terminal, o mesmo se faz com <code>argus-finding</code>:</p>
<table class="doc-tabela">
  <tr><th>Comando</th><th>O que faz</th></tr>
  <tr><td><code>set &lt;id&gt; em-tratamento|mitigado|fp</code></td><td>muda o estado</td></tr>
  <tr><td><code>note &lt;id&gt; "..."</code></td><td>anexa uma nota</td></tr>
  <tr><td><code>evidence &lt;id&gt; "rótulo" "ref"</code></td><td>registra evidência</td></tr>
</table>
"""),

    ("risco", "Como o risco é classificado", """
<p>O risco vem da <b>evidência</b>, não de suposição. Parte de uma base de
exposição e <b>sobe</b> conforme o enriquecimento traz agravante. O risco
<b>nunca é rebaixado</b> — só elevado.</p>

<table class="doc-tabela">
  <tr><th>Nível</th><th>Quando</th></tr>
  <tr><td><b class="doc-crit">Crítico</b></td>
      <td>exploração em uso (CISA KEV), CVSS 9+, credencial de funcionário
          vazada, domínio sósia com e-mail ativo</td></tr>
  <tr><td><b class="doc-alto">Alto</b></td>
      <td>CVE conhecida, reputação ruim, serviço sensível exposto</td></tr>
  <tr><td><b class="doc-med">Médio</b></td>
      <td>ativo público sem agravante conhecido</td></tr>
  <tr><td><b class="doc-baixo">Baixo</b></td>
      <td>ativo em rede privada — não alcançável de fora</td></tr>
</table>

<p class="doc-nota">O que é particular da sua empresa — se um host é de produção
ou de teste — fica para <b>você</b> validar. O Argus não adivinha contexto.</p>
"""),

    ("portas", "Risco por porta", """
<p>A base vem do serviço e de onde ele está exposto:</p>

<table class="doc-tabela">
  <tr><th>Porta</th><th>Público / Privado</th></tr>
  <tr><td>23 Telnet</td><td><b class="doc-crit">crítico</b> / <b class="doc-crit">crítico</b> — sem criptografia</td></tr>
  <tr><td>2375 Docker API</td><td><b class="doc-crit">crítico</b> / <b class="doc-crit">crítico</b> — root no host</td></tr>
  <tr><td>3389 RDP</td><td><b class="doc-crit">crítico</b> / <b class="doc-alto">alto</b> — alvo frequente</td></tr>
  <tr><td>445 SMB</td><td><b class="doc-crit">crítico</b> / <b class="doc-alto">alto</b> — ransomware</td></tr>
  <tr><td>3306 MySQL</td><td><b class="doc-crit">crítico</b> / <b class="doc-alto">alto</b> — banco exposto</td></tr>
  <tr><td>22 SSH</td><td><b class="doc-med">médio</b> / <b class="doc-baixo">baixo</b> — seguro, mas sofre brute force</td></tr>
  <tr><td>80/443 HTTP(S)</td><td><b class="doc-baixo">baixo</b> — serviço web padrão</td></tr>
</table>

<p><b>UDP</b> roda à parte, semanalmente, sobre 100 portas escolhidas por
criticidade: gestão fora de banda e automação industrial (IPMI, BACnet, DNP3),
vazamento e amplificação (SNMP, CLDAP, memcached, NetBIOS), acesso e VPN (IPsec,
OpenVPN, RADIUS). UDP é lento e ambíguo, então a lista é fixa e só reporta o que
confirma aberto.</p>
"""),

    ("elevacao", "O que eleva o risco", """
<p><b>Reputação do IP</b> (AbuseIPDB):</p>
<table class="doc-tabela">
  <tr><th>Condição</th><th>Efeito</th></tr>
  <tr><td>score ≥ 80</td><td>eleva a crítico</td></tr>
  <tr><td>score ≥ 50</td><td>no mínimo alto</td></tr>
  <tr><td>porta crítica + score &gt; 25</td><td>eleva a crítico</td></tr>
  <tr><td>saída TOR</td><td>+1 nível</td></tr>
</table>

<p><b>Vulnerabilidade</b> (Shodan InternetDB, CISA KEV, NVD):</p>
<table class="doc-tabela">
  <tr><th>Condição</th><th>Efeito</th></tr>
  <tr><td>IP com ao menos 1 CVE</td><td>no mínimo alto</td></tr>
  <tr><td>CVE no catálogo KEV</td><td>crítico — está sendo explorada agora</td></tr>
  <tr><td>CVSS 9+ (NVD)</td><td>crítico</td></tr>
</table>

<p class="doc-nota">O casamento de CVE do Shodan é heurístico (por banner e CPE) e
pode gerar falso positivo — por isso a elevação por CVE sozinha é conservadora, e
só o KEV leva direto a crítico.</p>
"""),

    ("emailrisco", "Risco da postura de e-mail", """
<table class="doc-tabela">
  <tr><th>Situação</th><th>Risco</th></tr>
  <tr><td>SPF <code>+all</code>, ou sem SPF e sem DMARC</td>
      <td><b class="doc-crit">crítico</b> — domínio totalmente falsificável</td></tr>
  <tr><td>DMARC ausente ou <code>p=none</code>, SPF inválido</td>
      <td><b class="doc-alto">alto</b> — não bloqueia falsificação</td></tr>
  <tr><td>DMARC <code>p=quarantine</code>, SPF <code>~all</code>, sem DKIM</td>
      <td><b class="doc-med">médio</b> — proteção parcial</td></tr>
  <tr><td>SPF <code>-all</code> + DMARC <code>p=reject</code> + DKIM</td>
      <td><b class="doc-baixo">baixo</b> — postura forte</td></tr>
</table>

<p class="doc-nota">Domínio sem MX também é verificado: um domínio que não envia
e-mail ainda pode ser usado para falsificar mensagens em nome dele.</p>
"""),

    ("conformidade", "Conformidade", """
<p>Cada tipo de achado é associado aos controles que realmente se aplicam —
<b>ISO/IEC 27002:2022</b>, <b>CIS Controls v8</b> e <b>PCI-DSS v4.0</b> — sem
conformidade de fachada.</p>

<p>O mapeamento aparece no detalhe de cada achado, em Gestão de Achados, e serve
tanto de evidência para auditoria quanto de critério de priorização.</p>
"""),

    ("campanhas", "Campanhas", """
<p>Uma campanha é o <b>escopo</b>: os IPs (para portas) ou domínios (para
subdomínios, e-mail, credenciais e typosquat) de um cliente ou unidade.</p>

<p>Renomear leva o histórico junto. Excluir tira do escopo mas <b>preserva os
achados</b> — você deixa de varrer, sem perder o que já foi encontrado.</p>

<p class="doc-nota">O escopo cresce por multiplicação: cada domínio novo custa uma
wordlist inteira de consultas. Muitos domínios com uma wordlist grande pode passar
do tempo limite de execução — nesse caso, rode uma campanha por vez pelo seletor
ao lado do botão.</p>
"""),

    ("scan", "Execução dos scans", """
<p>Os scanners rodam sozinhos, em horários diferentes para não competirem entre si.
O botão <b>▶ Rodar agora</b> executa a sequência completa na hora, sem esperar.</p>

<p>Enquanto roda, o botão fica travado — um scan por vez. Pode fechar a página: a
execução continua no servidor.</p>

<p>O seletor ao lado escolhe o escopo: todas as campanhas ou apenas uma.</p>
"""),

    ("provedores", "Fontes de inteligência", """
<p>São serviços externos que <b>enriquecem</b> o que os scanners encontram: dizem
se um IP tem denúncias de abuso, se a porta tem CVE conhecida, se aquela CVE está
sendo explorada agora.</p>

<p>Fonte desligada é simplesmente pulada — a varredura continua. Fonte que exige
chave só entra em ação depois que a credencial é informada.</p>

<p class="doc-nota">As chaves ficam no servidor, legíveis apenas pelo serviço, e
nunca são exibidas de volta: a tela mostra só os últimos dígitos.</p>
"""),

    ("logpush", "Envio de logs", """
<p>Manda o que o Argus registra para fora: um <b>bucket S3</b> (para o SIEM
consumir) ou um <b>chat</b> (Google Chat, Slack, Discord, Teams, Telegram).</p>

<p>Serve para quando a aplicação roda longe de quem acompanha — numa VPS, de
propósito, para enxergar a empresa como um estranho enxerga.</p>

<p>Os logs continuam na máquina; o que vai para fora é uma cópia. Se o destino
cair, nada se perde: o envio recomeça exatamente de onde parou.</p>

<p class="doc-nota">No chat, escolha quais severidades quer receber. Deixar todas
ligadas costuma virar ruído — uma execução pode disparar centenas de mensagens, e
os serviços de chat passam a descartar por limite de taxa.</p>

<p>Por isso o envio para chat sai em lotes de até 20 mensagens por ciclo, com um
respiro entre elas. Quando há atraso acumulado, ele escoa aos poucos em vez de
estourar a cota da plataforma — o bucket S3 não tem esse teto.</p>

<p class="doc-nota"><b>Bucket S3 — prova de posse.</b> Antes de enviar, o Argus
exige que você comprove ser dono do bucket. Em <b>Testar conexão</b> ele grava um
token num objeto do bucket; você abre esse objeto, copia o token e cola de volta.
Só então o envio é liberado. Isso impede que um bucket errado por engano — ou de
terceiro — receba dados sensíveis em silêncio. Trocar o bucket exige nova prova.</p>

<p><b>Permissão da chave S3.</b> A chave precisa apenas de <code>s3:PutObject</code>
no prefixo — o Argus só escreve, nunca lê nem apaga. Least privilege: se a chave
vazar, o dano se limita a gravar objeto no prefixo. O recurso é <code>logs/*</code>
(e não <code>logs/argus/*</code>) porque a prova de posse fica em
<code>logs/_argus/</code>, ao lado da pasta dos logs — precisa estar coberta.</p>
<pre class="doc-cod">{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "s3:PutObject",
    "Resource": "arn:aws:s3:::SEU-BUCKET/logs/*"
  }]
}</pre>
"""),

    ("usuarios", "Contas e perfis", """
<table class="doc-tabela">
  <tr><th>Perfil</th><th>Pode</th></tr>
  <tr><td><b>Administrador</b></td>
      <td>tudo, e é o único que gerencia contas. É o usuário criado na
          instalação.</td></tr>
  <tr><td><b>Master</b></td>
      <td>leitura e edição: campanhas, wordlist, executar scans, triagem</td></tr>
  <tr><td><b>User</b></td>
      <td>somente leitura — os botões de edição nem aparecem</td></tr>
</table>

<p>Cada um troca a própria senha informando a atual; o administrador redefine a de
qualquer um. As senhas são guardadas apenas como hash, e toda ação em contas fica
na trilha de auditoria.</p>
"""),

    ("correlacao", "Mapa de correlação", """
<p>Achado solto conta pouco. O que importa é como as coisas se ligam: um mesmo IP
servindo vários subdomínios é um <b>ponto único de falha</b>; uma CVE crítica nesse
IP vira o raio de explosão de tudo que depende dele.</p>

<p>Clique para expandir: campanha → domínios → subdomínios → IPs. A cor é a
criticidade. Clicar em qualquer item abre o que se sabe dele.</p>

<p><b>Como ler:</b></p>
<table class="doc-tabela">
  <tr><th>Ação</th><th>Resultado</th></tr>
  <tr><td>clicar num nó</td><td>expande e destaca só ele e os relacionados; o resto esmaece</td></tr>
  <tr><td>clicar no fundo</td><td>limpa o destaque</td></tr>
  <tr><td>clicar num subdomínio</td><td>acende o IP para onde ele resolve</td></tr>
  <tr><td>clicar num IP</td><td>lista todos os subdomínios que caem nele</td></tr>
  <tr><td>roda do mouse</td><td>zoom; arrastar o fundo move o mapa</td></tr>
</table>

<p><b>O que os símbolos dizem:</b> anel pontilhado significa que o nó ainda pode
expandir; IP com anel <b style="color:#fb923c">laranja</b> é servido por vários
subdomínios — é o raio de explosão daquele ponto.</p>

<p>A caixa <b>Por IP</b> inverte o mapa e mostra de cara quais IPs concentram mais
subdomínios. Os botões de criticidade filtram por nível.</p>

<p class="doc-nota">Com muitos hosts, o mapa vem agrupado pelo IP: cada IP aparece
uma vez, com quantos hosts concentra, e a lista completa abre ao clicar. Desligue o
agrupamento para ver tudo espalhado.</p>
"""),

    ("relatorios", "Os módulos de varredura", """
<table class="doc-tabela">
  <tr><th>Módulo</th><th>O que procura</th></tr>
  <tr><td><b>Portas</b></td>
      <td>o que responde na internet, com serviço, banner e CVEs conhecidas</td></tr>
  <tr><td><b>Subdomínios</b></td>
      <td>nomes que existem além do site principal — onde mora o que foi
          esquecido</td></tr>
  <tr><td><b>Credenciais</b></td>
      <td>senhas de funcionários e clientes em vazamentos de infostealer</td></tr>
  <tr><td><b>E-mail</b></td>
      <td>se dá para falsificar mensagens em nome do domínio (SPF, DKIM,
          DMARC)</td></tr>
  <tr><td><b>Typosquat</b></td>
      <td>domínios parecidos com o seu, já registrados — vetor direto de
          phishing</td></tr>
</table>

<p class="doc-nota">Cada relatório mostra primeiro as colunas que importam. O botão
de colunas revela o resto do enriquecimento.</p>
"""),
]

# Página → seção que o painel abre por padrão.
PAGINA_PARA_SECAO = {
    "dashboard": "inicio",
    "findings": "achados",
    "monitor": "relatorios",
    "submonitor": "relatorios",
    "credentials": "relatorios",
    "email": "relatorios",
    "typosquat": "relatorios",
    "correlacao": "correlacao",
    "campanhas": "campanhas",
    "provedores": "provedores",
    "logpush": "logpush",
    "usuarios": "usuarios",
}


def secao_da_pagina(pagina: str) -> str:
    return PAGINA_PARA_SECAO.get(pagina, "inicio")
