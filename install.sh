#!/usr/bin/env bash
#
# Argus — monitoramento de superfície de ataque
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
#
# =============================================================
# install.sh — Instalador completo do Argus
#
# O que faz:
#   1.  Valida pré-requisitos (OS, root, dependências de sistema)
#   2.  Instala dependências Python
#   3.  Cria estrutura de diretórios com permissões seguras
#   4.  Copia scripts
#   5.  Aplica permissões seguras
#   6.  Configura PYTHONPATH
#   7.  Configura AbuseIPDB (db_path, log_dir, api_key)
#   8.  Cria comandos globais (argus-monitor / argus-submonitor)
#   9.  Configura logrotate
#   10. Configura Apache2 com TLS e autenticação
#   11. Instala crons
#   12. Valida instalação
#
# Uso:
#   sudo bash install.sh
#   sudo bash install.sh --no-apache
#   sudo bash install.sh --uninstall
# =============================================================

set -euo pipefail

# ── Cores ────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

ok()   { echo -e "  ${GREEN}✓${NC}  $*"; }
warn() { echo -e "  ${YELLOW}⚠${NC}  $*"; }
err()  { echo -e "  ${RED}✗${NC}  $*"; exit 1; }
info() { echo -e "  ${CYAN}→${NC}  $*"; }
step() { echo -e "\n${BOLD}$*${NC}"; }

# ── Configurações (edite aqui se necessário) ─────────────────
BASE_DIR="/etc/argus"
MONITOR_DIR="$BASE_DIR/monitor"
SUBMONITOR_DIR="$BASE_DIR/submonitor"
CREDENTIALS_DIR="$BASE_DIR/credentials"
EMAIL_DIR="$BASE_DIR/email"
TYPOSQUAT_DIR="$BASE_DIR/typosquat"
THREATINTEL_DIR="$BASE_DIR/threatintel"

LOG_DIR_MONITOR="/var/log/argus/monitor"
LOG_DIR_SUBMONITOR="/var/log/argus/submonitor"
LOG_DIR_CREDENTIALS="/var/log/argus/credentials"
LOG_DIR_EMAIL="/var/log/argus/email"
LOG_DIR_TYPOSQUAT="/var/log/argus/typosquat"
LOG_DIR_AUDIT="/var/log/argus/audit"

APACHE_DOCROOT="/var/www/argus"
APACHE_CONF="/etc/apache2/sites-available/argus-monitor.conf"
APACHE_PORT=8443
APACHE_USER="monitor"
APACHE_PASS=""

APP_USER="kali"
PYTHON_BIN=$(which python3 2>/dev/null || echo "/usr/bin/python3")
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

INSTALL_APACHE=true
UNINSTALL=false

# ── Parse de argumentos ──────────────────────────────────────
for arg in "$@"; do
  case "$arg" in
    --no-apache) INSTALL_APACHE=false ;;
    --uninstall) UNINSTALL=true ;;
  esac
done

# ── Desinstalação ─────────────────────────────────────────────
if [ "$UNINSTALL" = true ]; then
  echo -e "\n${RED}${BOLD}Desinstalando Argus...${NC}\n"
  rm -f /etc/cron.d/argus-monitor /etc/cron.d/argus-monitor-udp /etc/cron.d/argus-submonitor /etc/cron.d/argus-credentials /etc/cron.d/argus-email /etc/cron.d/argus-typosquat
  rm -f /usr/local/bin/argus-monitor /usr/local/bin/argus-submonitor /usr/local/bin/argus-credentials /usr/local/bin/argus-email /usr/local/bin/argus-typosquat /usr/local/bin/argus-ack /usr/local/bin/argus-finding /usr/local/bin/argus-reset
  systemctl disable --now argus-web 2>/dev/null || true
  rm -f /etc/systemd/system/argus-web.service
  systemctl daemon-reload 2>/dev/null || true
  a2dissite argus-monitor 2>/dev/null || true
  rm -f "$APACHE_CONF" /etc/apache2/sites-enabled/argus-monitor.conf
  rm -f /etc/apache2/argus-session.key
  systemctl reload apache2 2>/dev/null || true
  rm -f /etc/logrotate.d/argus-monitor
  echo -e "${GREEN}Desinstalação concluída.${NC}"
  echo -e "${YELLOW}Dados em $BASE_DIR preservados. Para remover: rm -rf $BASE_DIR${NC}"
  exit 0
fi

# ── Banner ────────────────────────────────────────────────────
echo -e "\n${BOLD}${CYAN}"
echo "  ╔══════════════════════════════════════════════╗"
echo "  ║         ARGUS — INSTALADOR  (◉)              ║"
echo "  ║     Attack Surface Monitor · portas ·        ║"
echo "  ║     subdomínios · credenciais · Apache2      ║"
echo "  ╚══════════════════════════════════════════════╝"
echo -e "${NC}"

# ── 1. ROOT ───────────────────────────────────────────────────
step "1. Verificando privilégios"
[ "$(id -u)" -eq 0 ] || err "Execute como root: sudo bash install.sh"
ok "Executando como root"

# ── 2. SO ─────────────────────────────────────────────────────
step "2. Verificando sistema operacional"
if [ -f /etc/os-release ]; then
  . /etc/os-release
  info "Sistema: $PRETTY_NAME"
  case "$ID" in
    debian|ubuntu|kali) ok "Debian/Ubuntu/Kali — compatível" ;;
    *) warn "Distribuição não testada ($ID) — continuando assim mesmo" ;;
  esac
fi

# ── 3. DEPENDÊNCIAS DE SISTEMA ────────────────────────────────
step "3. Instalando dependências de sistema"
apt-get update -qq
PKGS="nmap python3 python3-pip python3-venv openssl"
# 'acl' (setfacl) deixa o serviço argus-web (app user) regenerar a página de
# achados no docroot após cada ação — sem ele, a página só atualiza nos scans.
[ "$INSTALL_APACHE" = true ] && PKGS="$PKGS apache2 apache2-utils acl"
for pkg in $PKGS; do
  if dpkg -s "$pkg" &>/dev/null; then ok "$pkg já instalado"
  else
    info "Instalando $pkg..."
    apt-get install -y -qq "$pkg" && ok "$pkg instalado" || err "Falha ao instalar $pkg"
  fi
done

PY_VERSION=$($PYTHON_BIN -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>/dev/null)
PY_MAJOR=$(echo "$PY_VERSION" | cut -d. -f1)
PY_MINOR=$(echo "$PY_VERSION" | cut -d. -f2)
if [ "$PY_MAJOR" -lt 3 ] || { [ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -lt 10 ]; }; then
  err "Python 3.10+ necessário. Encontrado: $PY_VERSION"
fi
ok "Python $PY_VERSION"

# ── 4. DEPENDÊNCIAS PYTHON ────────────────────────────────────
step "4. Instalando dependências Python"
for dep in python-nmap requests aiodns aiohttp dnspython python-whois flask dnstwist; do
  info "Instalando $dep..."
  $PYTHON_BIN -m pip install --quiet --break-system-packages "$dep" \
    && ok "$dep" || warn "Falha ao instalar $dep"
done

# ── 5. ESTRUTURA DE DIRETÓRIOS ────────────────────────────────
step "5. Criando estrutura de diretórios"
dirs=(
  "$MONITOR_DIR/targets"
  "$SUBMONITOR_DIR/targets"
  "$CREDENTIALS_DIR/targets"
  "$EMAIL_DIR/targets"
  "$TYPOSQUAT_DIR/targets"
  "$THREATINTEL_DIR/providers"
  "$THREATINTEL_DIR/core"
  "$THREATINTEL_DIR/logs"
  "$LOG_DIR_MONITOR"
  "$LOG_DIR_SUBMONITOR"
  "$LOG_DIR_CREDENTIALS"
  "$LOG_DIR_EMAIL"
  "$LOG_DIR_TYPOSQUAT"
  "$LOG_DIR_AUDIT"
)
for d in "${dirs[@]}"; do mkdir -p "$d" && ok "$d"; done

# ── 6. COPIA ARQUIVOS ─────────────────────────────────────────
step "6. Copiando scripts"
copy_if_exists() {
  local src="$SCRIPT_DIR/$1" dst="$2"
  if [ -f "$src" ]; then cp "$src" "$dst" && ok "$1 → $dst"
  else warn "$1 não encontrado — pulando"; fi
}

# Os módulos vivem em pastas no REPO (core/ e scanners/), mas o layout de RUNTIME
# em /etc/argus continua o mesmo (plano) — por isso os imports não mudam.
copy_if_exists "core/reporter.py"                     "$BASE_DIR/reporter.py"
copy_if_exists "core/ack.py"                          "$BASE_DIR/ack.py"
copy_if_exists "core/findings.py"                     "$BASE_DIR/findings.py"
copy_if_exists "core/webapp.py"                       "$BASE_DIR/webapp.py"
copy_if_exists "core/logs.py"                         "$BASE_DIR/logs.py"
copy_if_exists "argus-reset.sh"                       "$BASE_DIR/argus-reset.sh"
copy_if_exists "scanners/monitor.py"                  "$MONITOR_DIR/monitor.py"
copy_if_exists "scanners/submonitor.py"               "$SUBMONITOR_DIR/submonitor.py"
copy_if_exists "scanners/credentials.py"     "$CREDENTIALS_DIR/credentials.py"
copy_if_exists "scanners/emailauth.py"       "$EMAIL_DIR/emailauth.py"
copy_if_exists "scanners/typosquat.py"       "$TYPOSQUAT_DIR/typosquat.py"
copy_if_exists "threatintel/__init__.py"              "$THREATINTEL_DIR/__init__.py"
copy_if_exists "threatintel/config.json"              "$THREATINTEL_DIR/config.json"
copy_if_exists "threatintel/providers/__init__.py"    "$THREATINTEL_DIR/providers/__init__.py"
copy_if_exists "threatintel/providers/abuseipdb.py"   "$THREATINTEL_DIR/providers/abuseipdb.py"
copy_if_exists "threatintel/providers/crtsh.py"       "$THREATINTEL_DIR/providers/crtsh.py"
copy_if_exists "threatintel/providers/whois_lookup.py" "$THREATINTEL_DIR/providers/whois_lookup.py"
copy_if_exists "threatintel/providers/urlscan.py"     "$THREATINTEL_DIR/providers/urlscan.py"
copy_if_exists "threatintel/providers/hudsonrock.py"  "$THREATINTEL_DIR/providers/hudsonrock.py"
copy_if_exists "threatintel/providers/internetdb.py"  "$THREATINTEL_DIR/providers/internetdb.py"
copy_if_exists "threatintel/providers/cisa_kev.py"    "$THREATINTEL_DIR/providers/cisa_kev.py"
copy_if_exists "threatintel/providers/nvd.py"         "$THREATINTEL_DIR/providers/nvd.py"
copy_if_exists "threatintel/core/__init__.py"         "$THREATINTEL_DIR/core/__init__.py"
copy_if_exists "threatintel/core/database.py"         "$THREATINTEL_DIR/core/database.py"
copy_if_exists "threatintel/core/cache.py"            "$THREATINTEL_DIR/core/cache.py"
copy_if_exists "threatintel/core/quota.py"            "$THREATINTEL_DIR/core/quota.py"
copy_if_exists "threatintel/core/reputation.py"       "$THREATINTEL_DIR/core/reputation.py"
copy_if_exists "threatintel/core/utils.py"            "$THREATINTEL_DIR/core/utils.py"

# ── 7. PERMISSÕES SEGURAS ─────────────────────────────────────
step "7. Aplicando permissões seguras"
chown -R root:root "$BASE_DIR"
find "$BASE_DIR" -type d                -exec chmod 755 {} \;
find "$BASE_DIR" -type f -name "*.py"  -exec chmod 644 {} \;
find "$BASE_DIR" -type f -name "*.json" -exec chmod 640 {} \;
find "$BASE_DIR" -type f -name "*.txt"  -exec chmod 640 {} \;
# www-data precisa ler os relatórios gerados
chown -R root:www-data "$MONITOR_DIR" "$SUBMONITOR_DIR" "$CREDENTIALS_DIR" "$EMAIL_DIR" "$TYPOSQUAT_DIR" 2>/dev/null || true
chmod 750 "$MONITOR_DIR" "$SUBMONITOR_DIR" "$CREDENTIALS_DIR" "$EMAIL_DIR" "$TYPOSQUAT_DIR"
ok "Scripts: 644, diretórios: 755"

# O serviço argus-web (usuário $APP_USER) precisa LER os bancos dos scanners para
# montar o mapa de Correlação. ACL concede leitura/travessia ao app user (rX) nos
# diretórios + default para os arquivos futuros (a .db de cada execução).
_acl_ok=true
# threatintel: cache de reputação (AbuseIPDB) lido pela Correlação p/ enriquecer TODOS os IPs.
for _sd in "$MONITOR_DIR" "$SUBMONITOR_DIR" "$CREDENTIALS_DIR" "$EMAIL_DIR" "$TYPOSQUAT_DIR" "$THREATINTEL_DIR"; do
  setfacl -Rm  "u:$APP_USER:rX" "$_sd" 2>/dev/null || _acl_ok=false
  setfacl -dm  "u:$APP_USER:rX" "$_sd" 2>/dev/null || _acl_ok=false
done
if $_acl_ok; then
  ok "ACL: $APP_USER pode ler os bancos dos scanners (mapa de Correlação)"
else
  warn "setfacl indisponível — o mapa de Correlação pode não ler os bancos (instale o pacote 'acl')"
fi
chown root:adm "$LOG_DIR_MONITOR" "$LOG_DIR_SUBMONITOR" "$LOG_DIR_CREDENTIALS" "$LOG_DIR_EMAIL" "$LOG_DIR_TYPOSQUAT"
chmod 750 "$LOG_DIR_MONITOR" "$LOG_DIR_SUBMONITOR" "$LOG_DIR_CREDENTIALS" "$LOG_DIR_EMAIL" "$LOG_DIR_TYPOSQUAT"
# Auditoria: o serviço argus-web (usuário $APP_USER) ESCREVE o audit.log; o grupo
# adm LÊ. setgid (2750) faz os logs herdarem o grupo adm — proteção do log (PCI 10.3).
chown "$APP_USER:adm" "$LOG_DIR_AUDIT" && chmod 2750 "$LOG_DIR_AUDIT"
ok "Diretório de auditoria: $LOG_DIR_AUDIT ($APP_USER:adm 2750)"
ok "Logs: 750, dono root:adm"
# config.json contém a API key (AbuseIPDB). O submonitor roda como $APP_USER
# pelo comando global, então precisa LER o config. 640 root:$APP_USER mantém o
# segredo fora do alcance de "outros", mas legível pelo app user. O monitor roda
# como root (cron/sudo) e lê normalmente.
chown "root:$APP_USER" "$THREATINTEL_DIR/config.json" 2>/dev/null || true
chmod 640 "$THREATINTEL_DIR/config.json" 2>/dev/null || true
ok "config.json: 640 root:$APP_USER (root rw, $APP_USER ro)"

# threatintel.db é gravado tanto pelo monitor (root, via cron/sudo) quanto pelo
# submonitor (como $APP_USER). Para permitir escrita compartilhada — inclusive os
# arquivos auxiliares -wal/-shm que o SQLite cria — o diretório recebe o bit setgid
# com grupo $APP_USER e os bancos ficam com escrita de grupo (664). Os processos
# rodam com umask 0002 (configurado nos comandos globais e nos crons) para que
# novos arquivos herdem 664.
chown "root:$APP_USER" "$THREATINTEL_DIR" 2>/dev/null || true
chmod 2775 "$THREATINTEL_DIR"

mkdir -p "$THREATINTEL_DIR/crtsh_cache"
chown "$APP_USER:$APP_USER" "$THREATINTEL_DIR/crtsh_cache" 2>/dev/null || true
chmod 2775 "$THREATINTEL_DIR/crtsh_cache"
mkdir -p "$THREATINTEL_DIR/urlscan_cache"
chown "$APP_USER:$APP_USER" "$THREATINTEL_DIR/urlscan_cache" 2>/dev/null || true
chmod 2775 "$THREATINTEL_DIR/urlscan_cache"
mkdir -p "$THREATINTEL_DIR/hudsonrock_cache"
chown "$APP_USER:$APP_USER" "$THREATINTEL_DIR/hudsonrock_cache" 2>/dev/null || true
chmod 2775 "$THREATINTEL_DIR/hudsonrock_cache"
mkdir -p "$THREATINTEL_DIR/internetdb_cache"
chown "$APP_USER:$APP_USER" "$THREATINTEL_DIR/internetdb_cache" 2>/dev/null || true
chmod 2775 "$THREATINTEL_DIR/internetdb_cache"
# intel.db e threatintel.db: cria vazios com escrita compartilhada se não existirem
for _db in "$THREATINTEL_DIR/intel.db" "$THREATINTEL_DIR/threatintel.db"; do
  if [ ! -f "$_db" ]; then
    touch "$_db" 2>/dev/null || true
  fi
  chown "root:$APP_USER" "$_db" 2>/dev/null || true
  chmod 664 "$_db" 2>/dev/null || true
done
ok "Bases de Threat Intel com escrita compartilhada (root + $APP_USER, setgid)"

# ── Store central de achados (argus.db) — domínio de Findings ────────────────
# Diretório setgid (igual ao threatintel/) para escrita compartilhada root↔app,
# incluindo os arquivos auxiliares do SQLite (-wal/-shm/-journal).
FINDINGS_STORE="$BASE_DIR/store"
mkdir -p "$FINDINGS_STORE"
chown "root:$APP_USER" "$FINDINGS_STORE" 2>/dev/null || true
chmod 2775 "$FINDINGS_STORE"
# Migração SEGURA e idempotente dos DBs de scan existentes -> argus.db (faz
# backup, não apaga os DBs antigos). Em instalação nova é um no-op.
if PYTHONPATH="$BASE_DIR" ARGUS_DB="$FINDINGS_STORE/argus.db" "$PYTHON_BIN" "$BASE_DIR/findings.py" --migrate "$BASE_DIR" >/dev/null 2>&1; then
  ok "Store de achados migrado/criado: $FINDINGS_STORE/argus.db"
else
  warn "Migração de achados pulada (será criada na 1ª execução de um scanner)"
fi
for _f in "$FINDINGS_STORE/argus.db" "$FINDINGS_STORE/argus.db-wal" "$FINDINGS_STORE/argus.db-shm"; do
  [ -f "$_f" ] && chown "root:$APP_USER" "$_f" 2>/dev/null && chmod 664 "$_f" 2>/dev/null || true
done

# ── 8. PYTHONPATH ─────────────────────────────────────────────
step "8. Configurando PYTHONPATH"
PYTHONPATH_LINE="export PYTHONPATH=\"$BASE_DIR:\$PYTHONPATH\""
for rcfile in /root/.zshrc /root/.bashrc "/home/$APP_USER/.zshrc" "/home/$APP_USER/.bashrc"; do
  [ -f "$rcfile" ] || continue
  if ! grep -q "PYTHONPATH.*$BASE_DIR" "$rcfile"; then
    { echo ""; echo "# Argus"; echo "$PYTHONPATH_LINE"; } >> "$rcfile"
    ok "PYTHONPATH adicionado em $rcfile"
  else
    ok "PYTHONPATH já configurado em $rcfile"
  fi
done

# ── 9. THREAT INTEL — API KEYS + CAMINHOS ────────────────────
step "9. Configurando Threat Intel (AbuseIPDB + urlscan.io)"
CONFIG_JSON="$THREATINTEL_DIR/config.json"
if [ -f "$CONFIG_JSON" ]; then
  # Atualiza db_path e log_dir para o BASE_DIR atual
  python3 - << PYEOF
import json
with open("$CONFIG_JSON") as f:
    d = json.load(f)
d["db_path"] = "$THREATINTEL_DIR/threatintel.db"
d["log_dir"] = "$THREATINTEL_DIR/logs"
with open("$CONFIG_JSON", "w") as f:
    json.dump(d, f, indent=4)
PYEOF
  ok "db_path e log_dir ajustados para $THREATINTEL_DIR"

  CURRENT_KEY=$(python3 -c "import json; d=json.load(open('$CONFIG_JSON')); print(d.get('abuseipdb_api_key',''))" 2>/dev/null || echo "")
  if [ "$CURRENT_KEY" = "SUA_API_KEY_AQUI" ] || [ -z "$CURRENT_KEY" ]; then
    echo -e "\n  ${YELLOW}Cole sua API key do AbuseIPDB (deixe em branco para configurar depois):${NC}"
    read -r -p "  API Key: " USER_API_KEY
    if [ -n "$USER_API_KEY" ]; then
      python3 - << PYEOF
import json
with open("$CONFIG_JSON") as f:
    d = json.load(f)
d["abuseipdb_api_key"] = "$USER_API_KEY"
with open("$CONFIG_JSON", "w") as f:
    json.dump(d, f, indent=4)
PYEOF
      chown "root:$APP_USER" "$CONFIG_JSON" 2>/dev/null || true
      chmod 640 "$CONFIG_JSON"
      ok "API key configurada"
    else
      warn "API key não configurada — edite $CONFIG_JSON depois"
    fi
  else
    ok "API key já configurada"
  fi

  # ── urlscan.io API key ──
  CURRENT_URLSCAN=$(python3 -c "import json; d=json.load(open('$CONFIG_JSON')); print(d.get('urlscan_api_key',''))" 2>/dev/null || echo "")
  if [ "$CURRENT_URLSCAN" = "SUA_API_KEY_AQUI" ] || [ -z "$CURRENT_URLSCAN" ]; then
    echo -e "\n  ${YELLOW}Cole sua API key do urlscan.io (deixe em branco para configurar depois):${NC}"
    read -r -p "  urlscan API Key: " USER_URLSCAN_KEY
    if [ -n "$USER_URLSCAN_KEY" ]; then
      python3 - << PYEOF
import json
with open("$CONFIG_JSON") as f:
    d = json.load(f)
d["urlscan_api_key"] = "$USER_URLSCAN_KEY"
with open("$CONFIG_JSON", "w") as f:
    json.dump(d, f, indent=4)
PYEOF
      chown "root:$APP_USER" "$CONFIG_JSON" 2>/dev/null || true
      chmod 640 "$CONFIG_JSON"
      ok "API key do urlscan configurada"
    else
      warn "API key do urlscan não configurada — edite $CONFIG_JSON depois"
    fi
  else
    ok "API key do urlscan já configurada"
  fi

  # ── NVD API key (opcional — eleva o rate-limit: 5→50 req/30s) ──
  CURRENT_NVD=$(python3 -c "import json; d=json.load(open('$CONFIG_JSON')); print(d.get('nvd_api_key',''))" 2>/dev/null || echo "")
  if [ "$CURRENT_NVD" = "SUA_API_KEY_AQUI" ] || [ -z "$CURRENT_NVD" ]; then
    echo -e "\n  ${YELLOW}Cole sua API key do NVD/NIST — opcional, só eleva o rate-limit (deixe em branco para usar sem key):${NC}"
    read -r -p "  NVD API Key: " USER_NVD_KEY
    if [ -n "$USER_NVD_KEY" ]; then
      python3 - << PYEOF
import json
with open("$CONFIG_JSON") as f:
    d = json.load(f)
d["nvd_api_key"] = "$USER_NVD_KEY"
with open("$CONFIG_JSON", "w") as f:
    json.dump(d, f, indent=4)
PYEOF
      chown "root:$APP_USER" "$CONFIG_JSON" 2>/dev/null || true
      chmod 640 "$CONFIG_JSON"
      ok "API key do NVD configurada"
    else
      warn "NVD sem key — funciona, mas com rate-limit baixo (edite $CONFIG_JSON depois)"
    fi
  else
    ok "API key do NVD já configurada"
  fi
fi

# ── 10. COMANDOS GLOBAIS ──────────────────────────────────────
step "10. Criando comandos globais"

cat > /usr/local/bin/argus-monitor << CMDEOF
#!/usr/bin/env bash
# Comando global: argus-monitor
# umask 0002: bancos do threatintel (root) ficam graváveis pelo grupo $APP_USER.
# Passa o PYTHONPATH através do sudo (env_reset descarta variáveis exportadas antes)
umask 0002
exec sudo PYTHONPATH="$BASE_DIR" "$PYTHON_BIN" "$MONITOR_DIR/monitor.py" "\$@"
CMDEOF
chmod 755 /usr/local/bin/argus-monitor
ok "argus-monitor → $MONITOR_DIR/monitor.py"

cat > /usr/local/bin/argus-submonitor << CMDEOF
#!/usr/bin/env bash
# Comando global: argus-submonitor
# umask 0002: bancos do threatintel ficam graváveis pelo grupo (escrita compartilhada).
umask 0002
export PYTHONPATH="$BASE_DIR:\$PYTHONPATH"
exec "$PYTHON_BIN" "$SUBMONITOR_DIR/submonitor.py" "\$@"
CMDEOF
chmod 755 /usr/local/bin/argus-submonitor
ok "argus-submonitor → $SUBMONITOR_DIR/submonitor.py"

cat > /usr/local/bin/argus-credentials << CMDEOF
#!/usr/bin/env bash
# Comando global: argus-credentials
# umask 0002: caches do threatintel ficam graváveis pelo grupo (escrita compartilhada).
umask 0002
export PYTHONPATH="$BASE_DIR:\$PYTHONPATH"
exec "$PYTHON_BIN" "$CREDENTIALS_DIR/credentials.py" "\$@"
CMDEOF
chmod 755 /usr/local/bin/argus-credentials
ok "argus-credentials → $CREDENTIALS_DIR/credentials.py"

cat > /usr/local/bin/argus-email << CMDEOF
#!/usr/bin/env bash
# Comando global: argus-email — postura de e-mail (SPF/DMARC/DKIM)
# umask 0002: o email.db fica gravável pelo grupo (escrita compartilhada).
umask 0002
export PYTHONPATH="$BASE_DIR:\$PYTHONPATH"
exec "$PYTHON_BIN" "$EMAIL_DIR/emailauth.py" "\$@"
CMDEOF
chmod 755 /usr/local/bin/argus-email
ok "argus-email → $EMAIL_DIR/emailauth.py"

cat > /usr/local/bin/argus-typosquat << CMDEOF
#!/usr/bin/env bash
# Comando global: argus-typosquat — detecção de domínios sósia (dnstwist)
umask 0002
export PYTHONPATH="$BASE_DIR:\$PYTHONPATH"
exec "$PYTHON_BIN" "$TYPOSQUAT_DIR/typosquat.py" "\$@"
CMDEOF
chmod 755 /usr/local/bin/argus-typosquat
ok "argus-typosquat → $TYPOSQUAT_DIR/typosquat.py"

cat > /usr/local/bin/argus-ack << CMDEOF
#!/usr/bin/env bash
# Comando global: argus-ack — reconhece achados (status RECONHECIDO -> INFO)
# sudo: o store fica em $BASE_DIR (root:root); umask 0002 deixa o .db legível/gravável pelo grupo.
umask 0002
exec sudo PYTHONPATH="$BASE_DIR" "$PYTHON_BIN" "$BASE_DIR/ack.py" "\$@"
CMDEOF
chmod 755 /usr/local/bin/argus-ack
ok "argus-ack → $BASE_DIR/ack.py"

cat > /usr/local/bin/argus-finding << CMDEOF
#!/usr/bin/env bash
# Comando global: argus-finding — gestão operacional de achados (status/nota/evidência/FP)
# sudo: escreve no store central $BASE_DIR/store/argus.db (auditoria registra o usuário via SUDO_USER).
umask 0002
exec sudo PYTHONPATH="$BASE_DIR" "$PYTHON_BIN" "$BASE_DIR/findings.py" "\$@"
CMDEOF
chmod 755 /usr/local/bin/argus-finding
ok "argus-finding → $BASE_DIR/findings.py"

cat > /usr/local/bin/argus-reset << CMDEOF
#!/usr/bin/env bash
# Comando global: argus-reset — zera os bancos de achados (recomeça do zero),
# preservando targets, config.json e (por padrão) o cache de Threat Intel.
exec sudo bash "$BASE_DIR/argus-reset.sh" "\$@"
CMDEOF
chmod 755 /usr/local/bin/argus-reset
ok "argus-reset → $BASE_DIR/argus-reset.sh"

# ── 11. LOGROTATE ─────────────────────────────────────────────
step "11. Configurando logrotate"
cat > /etc/logrotate.d/argus-monitor << LOGROTATE
$LOG_DIR_MONITOR/*.log
$LOG_DIR_SUBMONITOR/*.log
$LOG_DIR_CREDENTIALS/*.log
$LOG_DIR_EMAIL/*.log
$LOG_DIR_TYPOSQUAT/*.log {
    weekly
    rotate 12
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root adm
    sharedscripts
}
LOGROTATE
ok "Logrotate configurado (rotação semanal, 12 semanas)"

# Auditoria: retenção LONGA (~1 ano) e dono $APP_USER (quem escreve é o argus-web).
cat > /etc/logrotate.d/argus-audit << AUDITROTATE
$LOG_DIR_AUDIT/*.log {
    weekly
    rotate 53
    compress
    delaycompress
    missingok
    notifempty
    create 0640 $APP_USER adm
    su $APP_USER adm
}
AUDITROTATE
ok "Logrotate de auditoria (retenção ~12 meses — PCI 10.5.1)"

# Sincronização de tempo — timestamps de auditoria confiáveis (PCI 10.6 / NIST AU-8).
if timedatectl show -p NTPSynchronized --value 2>/dev/null | grep -qi yes; then
  ok "Relógio sincronizado por NTP"
else
  warn "NTP não sincronizado — habilite com: sudo timedatectl set-ntp true (auditoria exige hora correta)"
fi

# ── 12. APACHE2 ───────────────────────────────────────────────
if [ "$INSTALL_APACHE" = true ]; then
  step "12. Configurando Apache2"

  # auth_form/session/session_cookie/session_crypto/request → login form-based
  # (mod_auth_form) com sessão criptografada, no lugar do pop-up de Basic Auth.
  for mod in ssl rewrite headers auth_basic authn_file authn_core authz_core authz_user \
             proxy proxy_http auth_form session session_cookie session_crypto request; do
    a2enmod "$mod" -q 2>/dev/null && ok "mod_$mod habilitado" || warn "mod_$mod não pôde ser habilitado"
  done

  # Docroot — arquivos estáticos servidos diretamente
  mkdir -p "$APACHE_DOCROOT"
  chown www-data:www-data "$APACHE_DOCROOT"
  chmod 755 "$APACHE_DOCROOT"

  # Portal web (index, dashboard, guia de risco) + assets/app.css.
  # Gerado em Python pelo reporter.py — fonte ÚNICA de design (app.css = _common_css()).
  SERVER_IP=$(hostname -I | awk '{print $1}')
  if PYTHONPATH="$BASE_DIR" "$PYTHON_BIN" -c "import reporter; reporter.write_portal('$APACHE_DOCROOT')"; then
    ok "Portal gerado (index, dashboard, risk-guide, assets/app.css)"
  else
    warn "Falha ao gerar portal via reporter.py (PYTHONPATH=$BASE_DIR)"
  fi
  # Página de Gestão de Achados já preenchida com o argus.db migrado (se houver).
  PYTHONPATH="$BASE_DIR" ARGUS_DB="$FINDINGS_STORE/argus.db" "$PYTHON_BIN" -c \
    "import reporter; reporter.write_findings_page('$APACHE_DOCROOT')" 2>/dev/null \
    && ok "Página de Gestão de Achados gerada do store" || true

  chown -R www-data:www-data "$APACHE_DOCROOT"
  chmod -R 755 "$APACHE_DOCROOT"
  chmod g+s "$APACHE_DOCROOT"
  # ACL: permite o serviço web (rodando como $APP_USER) regenerar a página de
  # achados no docroot após uma ação. Best-effort (requer pacote 'acl').
  setfacl -m "u:$APP_USER:rwX" "$APACHE_DOCROOT" 2>/dev/null \
    && setfacl -d -m "u:$APP_USER:rwX" "$APACHE_DOCROOT" 2>/dev/null \
    && ok "ACL: $APP_USER pode regenerar a página no docroot" \
    || warn "setfacl indisponível — a página será regenerada pelos scans (cron)"
  ok "Docroot criado: $APACHE_DOCROOT"

  # Certificado TLS self-signed
  SSL_DIR="/etc/ssl/argus"
  mkdir -p "$SSL_DIR"
  if [ ! -f "$SSL_DIR/monitor.crt" ]; then
    info "Gerando certificado TLS self-signed..."
    openssl req -x509 -nodes -days 730 -newkey rsa:2048 \
      -keyout "$SSL_DIR/monitor.key" \
      -out    "$SSL_DIR/monitor.crt" \
      -subj "/C=BR/ST=SP/L=SaoPaulo/O=ExposureMonitor/CN=argus-monitor" \
      2>/dev/null
    chmod 600 "$SSL_DIR/monitor.key"
    chmod 644 "$SSL_DIR/monitor.crt"
    ok "Certificado TLS gerado em $SSL_DIR"
  else
    ok "Certificado TLS já existe"
  fi

  # Senha HTTP Basic Auth
  HTPASSWD_FILE="/etc/apache2/.htpasswd-monitor"
  if [ -z "$APACHE_PASS" ]; then
    echo -e "\n  ${YELLOW}Defina uma senha para acesso ao relatório web (usuário: $APACHE_USER):${NC}"
    read -r -s -p "  Senha: " APACHE_PASS_INPUT; echo
    read -r -s -p "  Confirme: " APACHE_PASS_CONFIRM; echo
    [ "$APACHE_PASS_INPUT" = "$APACHE_PASS_CONFIRM" ] || err "Senhas não conferem."
    APACHE_PASS="$APACHE_PASS_INPUT"
  fi
  htpasswd -cb "$HTPASSWD_FILE" "$APACHE_USER" "$APACHE_PASS" 2>/dev/null
  chmod 640 "$HTPASSWD_FILE"
  chown root:www-data "$HTPASSWD_FILE"
  ok "Autenticação HTTP configurada (usuário: $APACHE_USER)"

  # Passphrase para criptografar o cookie de sessão (mod_session_crypto).
  # Arquivo 640 root:www-data — fora do vhost (que é world-readable).
  SESSION_KEY_FILE="/etc/apache2/argus-session.key"
  if [ ! -f "$SESSION_KEY_FILE" ]; then
    openssl rand -base64 32 > "$SESSION_KEY_FILE"
    chmod 640 "$SESSION_KEY_FILE"
    chown root:www-data "$SESSION_KEY_FILE"
    ok "Passphrase de sessão gerada ($SESSION_KEY_FILE)"
  else
    ok "Passphrase de sessão já existe"
  fi

  # Virtual host — sem symlinks, Apache serve o APACHE_DOCROOT diretamente
  # Os scripts gravam os relatórios diretamente no APACHE_DOCROOT
  cat > "$APACHE_CONF" << APACHECONF
# Argus — Virtual Host
# Gerado pelo install.sh em $(date '+%Y-%m-%d %H:%M:%S')

<VirtualHost *:80>
    ServerName argus-monitor
    Redirect permanent / https://${SERVER_IP}:${APACHE_PORT}/
</VirtualHost>

<VirtualHost *:${APACHE_PORT}>
    ServerName argus-monitor
    DocumentRoot ${APACHE_DOCROOT}

    SSLEngine on
    SSLCertificateFile    ${SSL_DIR}/monitor.crt
    SSLCertificateKeyFile ${SSL_DIR}/monitor.key
    SSLProtocol           all -SSLv3 -TLSv1 -TLSv1.1
    SSLCipherSuite        HIGH:!aNULL:!MD5:!3DES
    SSLHonorCipherOrder   on

    Header always set X-Content-Type-Options "nosniff"
    Header always set X-Frame-Options "SAMEORIGIN"
    Header always set X-XSS-Protection "1; mode=block"
    Header always set Referrer-Policy "no-referrer"
    Header always set Cache-Control "no-store, no-cache, must-revalidate"
    # CSP — relatórios usam CSS/JS inline (precisam de 'unsafe-inline'); screenshots
    # do urlscan são imagens externas (img-src https:). Bloqueia scripts de origem
    # externa e enquadramento (frame-ancestors none).
    Header always set Content-Security-Policy "default-src 'self'; img-src 'self' data: https:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
    Header always set Permissions-Policy "geolocation=(), microphone=(), camera=()"
    # HSTS — habilite SOMENTE com certificado VÁLIDO (Let's Encrypt). Com cert
    # self-signed, o HSTS impede o click-through e bloqueia o acesso após o 1º
    # carregamento. Em produção com TLS confiável, descomente:
    # Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains"
    Header unset Server

    # ── Sessão (mod_session) para o login form-based (mod_auth_form) ──
    # O cookie de sessão é criptografado com a passphrase do arquivo 640.
    Session On
    SessionCookieName argus_session path=/;HttpOnly;Secure
    SessionCryptoPassphraseFile ${SESSION_KEY_FILE}
    SessionMaxAge 28800

    <Directory "${APACHE_DOCROOT}">
        Options -Indexes
        AllowOverride None
        AuthType form
        AuthName "Argus"
        AuthFormProvider file
        AuthUserFile ${HTPASSWD_FILE}
        AuthFormLoginRequiredLocation "/login.html"
        Require valid-user
    </Directory>

    # A página de login é PÚBLICA (precisa ser alcançável sem sessão).
    <Files "login.html">
        Require all granted
    </Files>

    <FilesMatch "\.(db|log|json|py|sh)$">
        Require all denied
    </FilesMatch>

    # Handler do formulário de login — valida a credencial NO APACHE (mod_auth_form);
    # a aplicação não recebe nem guarda a senha. Sucesso → portal; falha → erro.
    <Location "/dologin">
        SetHandler form-login-handler
        AuthType form
        AuthName "Argus"
        AuthFormProvider file
        AuthUserFile ${HTPASSWD_FILE}
        AuthFormLoginSuccessLocation "/index.html"
        AuthFormLoginRequiredLocation "/login.html?error=1"
        Session On
        Require all granted
    </Location>

    # Logout — encerra a sessão e volta para a tela de login.
    <Location "/logout">
        SetHandler form-logout-handler
        AuthFormLogoutLocation "/login.html?logout=1"
        Session On
        Require all granted
    </Location>

    # ── API de Gestão de Achados (Fase 2.1) — reverse-proxy aditivo ──
    # Só o caminho /api/ é proxied para o serviço Flask (127.0.0.1:8099);
    # o restante do site continua estático, inalterado. Mesma sessão/auth.
    # O usuário autenticado é repassado em X-Remote-User (vira o autor da
    # auditoria); o header é REESCRITO no servidor para o cliente não forjá-lo.
    ProxyPreserveHost On
    <Location "/api/">
        AuthType form
        AuthName "Argus"
        AuthFormProvider file
        AuthUserFile ${HTPASSWD_FILE}
        AuthFormLoginRequiredLocation "/login.html"
        Session On
        Require valid-user
        RequestHeader unset X-Remote-User
        RequestHeader set X-Remote-User "expr=%{REMOTE_USER}"
        ProxyPass        "http://127.0.0.1:8099/api/"
        ProxyPassReverse "http://127.0.0.1:8099/api/"
    </Location>

    ErrorLog  \${APACHE_LOG_DIR}/argus-monitor-error.log
    CustomLog \${APACHE_LOG_DIR}/argus-monitor-access.log combined

    # Trilha de AUTENTICAÇÃO (login/logout) — auditoria ISO A.8.15 / PCI 10.2.1.
    # status 302 + user=<nome> em /dologin = login OK; user=- = login falho.
    SetEnvIf Request_URI "^/(dologin|logout)" argus_auth
    LogFormat "%{%Y-%m-%dT%H:%M:%S%z}t src=%a user=%u %m %U%q -> %s" argusauth
    CustomLog \${APACHE_LOG_DIR}/argus-auth.log argusauth env=argus_auth
</VirtualHost>
APACHECONF

  if ! grep -q "^Listen ${APACHE_PORT}" /etc/apache2/ports.conf 2>/dev/null; then
    echo "Listen ${APACHE_PORT}" >> /etc/apache2/ports.conf
    ok "Porta $APACHE_PORT adicionada ao ports.conf"
  else
    ok "Porta $APACHE_PORT já configurada"
  fi

  a2ensite argus-monitor -q 2>/dev/null && ok "Site argus-monitor habilitado" || warn "Falha ao habilitar site"
  apache2ctl configtest 2>/dev/null && ok "Configuração Apache válida" || warn "Verifique: apache2ctl configtest"
  systemctl enable apache2 2>/dev/null
  systemctl restart apache2 2>/dev/null && ok "Apache2 reiniciado" || warn "Falha ao reiniciar Apache"

else
  step "12. Apache2 — PULADO (--no-apache)"
  warn "Relatórios acessíveis apenas localmente"
fi

# ── 12b. SERVIÇO WEB (API de gestão de achados) ───────────────
step "12b. Configurando serviço web (API de achados)"
cat > /etc/systemd/system/argus-web.service << UNITEOF
[Unit]
Description=Argus ASM — API de gestão de achados (Flask, atrás do Apache)
After=network.target

[Service]
Type=simple
User=$APP_USER
Group=$APP_USER
WorkingDirectory=$BASE_DIR
Environment=PYTHONPATH=$BASE_DIR
Environment=ARGUS_DOCROOT=$APACHE_DOCROOT
Environment=ARGUS_DB=$BASE_DIR/store/argus.db
Environment=ARGUS_WEB_HOST=127.0.0.1
Environment=ARGUS_WEB_PORT=8099
Environment=ARGUS_AUDIT_LOG=$LOG_DIR_AUDIT/audit.log
ExecStart=$PYTHON_BIN $BASE_DIR/webapp.py
Restart=on-failure
RestartSec=3
# Hardening (least privilege — CIS)
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
ReadWritePaths=$BASE_DIR/store $APACHE_DOCROOT $LOG_DIR_AUDIT

[Install]
WantedBy=multi-user.target
UNITEOF
systemctl daemon-reload 2>/dev/null
systemctl enable argus-web 2>/dev/null
if systemctl restart argus-web 2>/dev/null; then
  ok "Serviço argus-web ativo (127.0.0.1:8099, usuário $APP_USER)"
else
  warn "Falha ao iniciar argus-web — verifique: journalctl -u argus-web"
fi

# ── 13. CRONS ─────────────────────────────────────────────────
step "13. Instalando crons"

cat > /etc/cron.d/argus-monitor << CRONMONITOR
# monitor — scan de superficie exposta (TCP) diariamente as 10h00
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
PYTHONPATH=$BASE_DIR

0 10 * * * root umask 0002 && cd $MONITOR_DIR && $PYTHON_BIN $MONITOR_DIR/monitor.py --tcp >> $LOG_DIR_MONITOR/monitor_stdout.log 2>&1
CRONMONITOR
chmod 644 /etc/cron.d/argus-monitor
ok "Cron monitor (TCP): todos os dias às 10h00"

# UDP é mais lento, mas precisa rodar dentro da janela de carência (ARGUS_CLOSE_GRACE_DAYS=3):
# se a cadência for maior que a carência, os achados UDP "fecham" entre execuções e
# reaparecem como REINCIDENTE/RESSURGIDO (falsa reincidência). Por isso: a cada 2 dias,
# fora do horário. Log UNIFICADO (mesmo monitor.log RFC5424 com transport=udp).
cat > /etc/cron.d/argus-monitor-udp << CRONMONITORUDP
# monitor UDP — postura UDP (100 portas) a cada 2 dias as 03h00 (< carencia de 3 dias)
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
PYTHONPATH=$BASE_DIR

0 3 */2 * * root umask 0002 && cd $MONITOR_DIR && $PYTHON_BIN $MONITOR_DIR/monitor.py --udp >> $LOG_DIR_MONITOR/monitor_stdout.log 2>&1
CRONMONITORUDP
chmod 644 /etc/cron.d/argus-monitor-udp
ok "Cron monitor (UDP): a cada 2 dias às 03h00 (dentro da carência de 3 dias)"

cat > /etc/cron.d/argus-submonitor << CRONSUBMONITOR
# submonitor — scan de subdominios diariamente as 12h00
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
PYTHONPATH=$BASE_DIR

0 12 * * * root umask 0002 && cd $SUBMONITOR_DIR && $PYTHON_BIN $SUBMONITOR_DIR/submonitor.py >> $LOG_DIR_SUBMONITOR/submonitor_stdout.log 2>&1
CRONSUBMONITOR
chmod 644 /etc/cron.d/argus-submonitor
ok "Cron submonitor: todos os dias às 12h00"

cat > /etc/cron.d/argus-credentials << CRONCREDENTIALS
# credentials — exposicao de credenciais (infostealer) diariamente as 14h00
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
PYTHONPATH=$BASE_DIR

0 14 * * * root umask 0002 && cd $CREDENTIALS_DIR && $PYTHON_BIN $CREDENTIALS_DIR/credentials.py >> $LOG_DIR_CREDENTIALS/credentials_stdout.log 2>&1
CRONCREDENTIALS
chmod 644 /etc/cron.d/argus-credentials
ok "Cron credentials: todos os dias às 14h00"

cat > /etc/cron.d/argus-email << CRONEMAIL
# email — postura de e-mail (SPF/DMARC/DKIM) diariamente as 13h00
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
PYTHONPATH=$BASE_DIR

0 13 * * * root umask 0002 && cd $EMAIL_DIR && $PYTHON_BIN $EMAIL_DIR/emailauth.py >> $LOG_DIR_EMAIL/email_stdout.log 2>&1
CRONEMAIL
chmod 644 /etc/cron.d/argus-email
ok "Cron email: todos os dias às 13h00"

# typosquat (dnstwist) é semanal — domínios sósia mudam devagar e o scan é mais pesado.
cat > /etc/cron.d/argus-typosquat << CRONTYPO
# typosquat — domínios sósia (dnstwist) semanalmente aos domingos as 05h00
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
PYTHONPATH=$BASE_DIR

0 5 * * 0 root umask 0002 && cd $TYPOSQUAT_DIR && $PYTHON_BIN $TYPOSQUAT_DIR/typosquat.py >> $LOG_DIR_TYPOSQUAT/typosquat_stdout.log 2>&1
CRONTYPO
chmod 644 /etc/cron.d/argus-typosquat
ok "Cron typosquat: domingos às 05h00"

# ── 14. VALIDAÇÃO FINAL ───────────────────────────────────────
step "14. Validação final"

check() {
  local label="$1" cmd="$2"
  if eval "$cmd" &>/dev/null; then ok "$label"
  else warn "$label — FALHOU"; fi
}

check "Python acessível"             "$PYTHON_BIN --version"
check "nmap instalado"               "which nmap"
check "python-nmap importável"       "PYTHONPATH=$BASE_DIR $PYTHON_BIN -c 'import nmap'"
check "requests importável"          "PYTHONPATH=$BASE_DIR $PYTHON_BIN -c 'import requests'"
check "aiodns importável"            "PYTHONPATH=$BASE_DIR $PYTHON_BIN -c 'import aiodns'"
check "aiohttp importável"           "PYTHONPATH=$BASE_DIR $PYTHON_BIN -c 'import aiohttp'"
check "reporter.py importável"       "PYTHONPATH=$BASE_DIR $PYTHON_BIN -c 'from reporter import generate_monitor_report'"
check "threatintel importável"       "PYTHONPATH=$BASE_DIR $PYTHON_BIN -c 'from threatintel.providers.abuseipdb import get_ip_reputation'"
check "urlscan provider importável"  "PYTHONPATH=$BASE_DIR $PYTHON_BIN -c 'from threatintel.providers.urlscan import get_subdomains'"
check "hudsonrock importável"        "PYTHONPATH=$BASE_DIR $PYTHON_BIN -c 'from threatintel.providers.hudsonrock import get_domain_exposure'"
check "internetdb importável"        "PYTHONPATH=$BASE_DIR $PYTHON_BIN -c 'from threatintel.providers.internetdb import get_host_intel'"
check "credentials report importável" "PYTHONPATH=$BASE_DIR $PYTHON_BIN -c 'from reporter import generate_credentials_report'"
check "dnspython importável"         "PYTHONPATH=$BASE_DIR $PYTHON_BIN -c 'import dns.resolver'"
check "email report importável"      "PYTHONPATH=$BASE_DIR $PYTHON_BIN -c 'from reporter import generate_email_report'"
check "typosquat report importável"  "PYTHONPATH=$BASE_DIR $PYTHON_BIN -c 'from reporter import generate_typosquat_report'"
check "dnstwist instalado"           "command -v dnstwist"
check "emailauth.py importável"      "PYTHONPATH=$BASE_DIR $PYTHON_BIN -c 'import sys; sys.path.insert(0,\"$EMAIL_DIR\"); import emailauth'"
check "argus-monitor instalado"   "[ -x /usr/local/bin/argus-monitor ]"
check "argus-submonitor instalado" "[ -x /usr/local/bin/argus-submonitor ]"
check "argus-credentials instalado" "[ -x /usr/local/bin/argus-credentials ]"
check "argus-email instalado"        "[ -x /usr/local/bin/argus-email ]"
check "argus-typosquat instalado"    "[ -x /usr/local/bin/argus-typosquat ]"
check "argus-ack instalado"          "[ -x /usr/local/bin/argus-ack ]"
check "argus-finding instalado"      "[ -x /usr/local/bin/argus-finding ]"
check "argus-reset instalado"        "[ -x /usr/local/bin/argus-reset ]"
check "ack.py importável"            "PYTHONPATH=$BASE_DIR $PYTHON_BIN -c 'import ack'"
check "findings.py importável"       "PYTHONPATH=$BASE_DIR $PYTHON_BIN -c 'import findings'"
check "store de achados (argus.db)"  "[ -f $BASE_DIR/store/argus.db ]"
check "monitor/targets existe"       "[ -d $MONITOR_DIR/targets ]"
check "submonitor/targets existe"    "[ -d $SUBMONITOR_DIR/targets ]"
check "credentials/targets existe"   "[ -d $CREDENTIALS_DIR/targets ]"
check "email/targets existe"         "[ -d $EMAIL_DIR/targets ]"
check "Log monitor criado"           "[ -d $LOG_DIR_MONITOR ]"
check "Log submonitor criado"        "[ -d $LOG_DIR_SUBMONITOR ]"
check "Log credentials criado"       "[ -d $LOG_DIR_CREDENTIALS ]"
check "Log email criado"             "[ -d $LOG_DIR_EMAIL ]"
check "Cron monitor instalado"       "[ -f /etc/cron.d/argus-monitor ]"
check "Cron monitor-udp instalado"   "[ -f /etc/cron.d/argus-monitor-udp ]"
check "Cron submonitor instalado"    "[ -f /etc/cron.d/argus-submonitor ]"
check "Cron credentials instalado"   "[ -f /etc/cron.d/argus-credentials ]"
check "Cron email instalado"         "[ -f /etc/cron.d/argus-email ]"
check "Cron typosquat instalado"     "[ -f /etc/cron.d/argus-typosquat ]"
[ "$INSTALL_APACHE" = true ] && check "Apache2 rodando" "systemctl is-active apache2"
check "webapp.py importável"         "PYTHONPATH=$BASE_DIR $PYTHON_BIN -c 'import flask, webapp'"
check "serviço argus-web ativo"      "systemctl is-active argus-web"

# ── Resumo ────────────────────────────────────────────────────
SERVER_IP=$(hostname -I | awk '{print $1}')
echo -e "\n${BOLD}${GREEN}╔══════════════════════════════════════════════╗"
echo                 "║         INSTALAÇÃO CONCLUÍDA ✓               ║"
echo -e              "╚══════════════════════════════════════════════╝${NC}\n"

echo -e "${BOLD}Comandos disponíveis:${NC}"
echo -e "  ${CYAN}argus-monitor${NC}       — scan de portas TCP (--tcp, padrão) | UDP (--udp, semanal)"
echo -e "  ${CYAN}argus-submonitor${NC}    — executa o scan de subdomínios"
echo -e "  ${CYAN}argus-credentials${NC}   — exposição de credenciais (infostealer)"
echo -e "  ${CYAN}argus-email${NC}         — postura de e-mail (SPF/DMARC/DKIM)"
echo -e "  ${CYAN}argus-typosquat${NC}     — domínios sósia / typosquatting (dnstwist, semanal)"
echo -e "  ${CYAN}argus-ack${NC}           — reconhece achado (RECONHECIDO → INFO) com motivo"
echo -e "  ${CYAN}argus-reset${NC}         — zera os bancos de achados (preserva enriquecimento, targets e config)"
echo -e "  ${CYAN}argus-finding${NC}       — gestão de achados: list/show/set/note/evidence (status, FP, evidências)"
echo -e "                          ex.: ${CYAN}argus-ack add 1.2.3.4:179/tcp \"firewall, esperado\"${NC}"
echo ""
echo -e "${BOLD}Próximos passos:${NC}"
echo ""
echo -e "  1. Adicione targets do monitor (IPs):"
echo -e "     ${CYAN}nano $MONITOR_DIR/targets/EMPRESA.txt${NC}"
echo ""
echo -e "  2. Adicione targets do submonitor (domínios):"
echo -e "     ${CYAN}nano $SUBMONITOR_DIR/targets/EMPRESA.txt${NC}"
echo ""
echo -e "  3. Crie a wordlist de subdomínios:"
echo -e "     ${CYAN}nano $SUBMONITOR_DIR/subs.txt${NC}"
echo ""
echo -e "  4. Credenciais e E-mail: por padrão reusam os domínios do submonitor (passo 2)."
echo -e "     ${YELLOW}(opcional)${NC} para conjuntos diferentes:"
echo -e "     ${CYAN}nano $CREDENTIALS_DIR/targets/EMPRESA.txt${NC}  (credenciais)"
echo -e "     ${CYAN}nano $EMAIL_DIR/targets/EMPRESA.txt${NC}  (e-mail)"
echo ""
echo -e "  5. API keys do AbuseIPDB e urlscan.io (se não configurou):"
echo -e "     ${CYAN}nano $THREATINTEL_DIR/config.json${NC}"
echo -e "     ${YELLOW}(Hudson Rock é gratuito e não precisa de chave)${NC}"
echo ""
echo -e "  6. Teste a execução:"
echo -e "     ${CYAN}argus-monitor${NC}"
echo -e "     ${CYAN}argus-submonitor${NC}"
echo -e "     ${CYAN}argus-credentials${NC}"
echo ""

if [ "$INSTALL_APACHE" = true ]; then
  echo -e "  6. Acesse o portal:"
  echo -e "     ${CYAN}https://${SERVER_IP}:${APACHE_PORT}/${NC}"
  echo -e "     Usuário: ${BOLD}${APACHE_USER}${NC}"
  echo -e "     ${YELLOW}(certificado self-signed — aceite o aviso do browser)${NC}"
  echo ""
  echo -e "  Para Let's Encrypt em produção:"
  echo -e "     ${CYAN}sudo apt install certbot python3-certbot-apache${NC}"
  echo -e "     ${CYAN}sudo certbot --apache -d seu.dominio.com${NC}"
  echo ""
fi

echo -e "  Logs em tempo real:"
echo -e "     ${CYAN}tail -f $LOG_DIR_MONITOR/monitor.log${NC}"
echo -e "     ${CYAN}tail -f $LOG_DIR_SUBMONITOR/submonitor.log${NC}"
echo ""
