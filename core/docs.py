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
"""),

    ("risco", "Como o risco é classificado", """
<p>O risco vem da <b>evidência</b>, não de uma tabela fixa. A base é a exposição:</p>

<table class="doc-tabela">
  <tr><th>Nível</th><th>Quando</th></tr>
  <tr><td><b class="doc-crit">Crítico</b></td>
      <td>exploração conhecida em uso (CISA KEV), CVSS 9+, credenciais de
          funcionário vazadas, domínio sósia com e-mail configurado</td></tr>
  <tr><td><b class="doc-alto">Alto</b></td>
      <td>CVE relevante, IP com reputação ruim, serviço sensível exposto</td></tr>
  <tr><td><b class="doc-med">Médio</b></td>
      <td>ativo público sem agravante conhecido</td></tr>
  <tr><td><b class="doc-baixo">Baixo</b></td>
      <td>ativo em rede privada — não alcançável de fora</td></tr>
</table>

<p>Um mesmo ativo <b>sobe de nível</b> quando o enriquecimento traz agravante:
uma CVE explorada in-the-wild, denúncias de abuso, motores de antivírus apontando
o IP como malicioso.</p>

<p><a href="/risk-guide.html">Ver o guia completo, com o critério de cada
módulo →</a></p>
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
    "risk": "risco",
}


def secao_da_pagina(pagina: str) -> str:
    return PAGINA_PARA_SECAO.get(pagina, "inicio")
