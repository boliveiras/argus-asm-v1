#!/usr/bin/env bash
#
# Argus ASM — monitoramento de superfície de ataque
# Copyright (C) 2026  Bruno Santos — AGPL-3.0
#
# uninstall.sh — remoção do Argus ASM.
#   (padrão)     remove comandos, cron, serviço web e o vhost do Apache,
#                PRESERVANDO os dados em /etc/argus.
#   --keep-db    idem ao padrão (explícito).
#   --purge      remove TUDO, inclusive /etc/argus, /var/log/argus e /var/www/argus.
#
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BOLD='\033[1m'; NC='\033[0m'
ok()   { echo -e "  ${GREEN}✓${NC} $*"; }
warn() { echo -e "  ${YELLOW}!${NC} $*"; }

[ "$(id -u)" -eq 0 ] || { echo -e "${RED}Execute como root:${NC} sudo bash uninstall.sh [--purge]"; exit 1; }

BASE_DIR="/etc/argus"
LOG_DIR="/var/log/argus"
DOCROOT="/var/www/argus"
APACHE_CONF="/etc/apache2/sites-available/argus-monitor.conf"
PURGE=false
for a in "$@"; do
  case "$a" in
    --purge)   PURGE=true ;;
    --keep-db) PURGE=false ;;
    *) warn "opção ignorada: $a" ;;
  esac
done

echo -e "\n${RED}${BOLD}Desinstalando Argus ASM...${NC}\n"

# Crons
rm -f /etc/cron.d/argus-monitor /etc/cron.d/argus-monitor-udp /etc/cron.d/argus-submonitor \
      /etc/cron.d/argus-credentials /etc/cron.d/argus-email /etc/cron.d/argus-typosquat
ok "crons removidos"

# Comandos globais
rm -f /usr/local/bin/argus-monitor /usr/local/bin/argus-submonitor /usr/local/bin/argus-credentials \
      /usr/local/bin/argus-email /usr/local/bin/argus-typosquat /usr/local/bin/argus-ack \
      /usr/local/bin/argus-finding /usr/local/bin/argus-reset
ok "comandos globais removidos"

# Serviço web
systemctl disable --now argus-web 2>/dev/null || true
rm -f /etc/systemd/system/argus-web.service
systemctl daemon-reload 2>/dev/null || true
ok "serviço argus-web removido"

# Apache (vhost + passphrase de sessão)
a2dissite argus-monitor 2>/dev/null || true
rm -f "$APACHE_CONF" /etc/apache2/sites-enabled/argus-monitor.conf /etc/apache2/argus-session.key
systemctl reload apache2 2>/dev/null || true
ok "vhost do Apache removido"

# Logrotate
rm -f /etc/logrotate.d/argus-monitor /etc/logrotate.d/argus-audit
ok "logrotate removido"

if $PURGE; then
  rm -rf "$BASE_DIR" "$LOG_DIR" "$DOCROOT"
  ok "PURGE: $BASE_DIR, $LOG_DIR e $DOCROOT removidos"
  echo -e "\n${GREEN}${BOLD}Remoção completa concluída.${NC}\n"
else
  warn "Dados PRESERVADOS em $BASE_DIR (use --purge para remover tudo, inclusive os bancos)."
  echo -e "\n${GREEN}${BOLD}Desinstalação concluída.${NC}\n"
fi
