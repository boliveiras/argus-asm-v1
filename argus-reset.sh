#!/usr/bin/env bash
#
# argus-reset.sh — zera os bancos de ACHADOS do Argus ASM (recomeça do zero),
# PRESERVANDO sempre os targets e o config.json (chaves de API), e — por
# PADRÃO — o cache de Threat Intel (enriquecimento). Cada scanner recria o seu
# banco na próxima execução; o argus.db é repovoado conforme os módulos rodam.
#
# Uso:
#   sudo bash argus-reset.sh            # pede confirmação; PRESERVA o enriquecimento
#   sudo argus-reset                    # (se instalado como comando)
#   sudo argus-reset -y                 # sem confirmação
#   sudo argus-reset --caches           # TAMBÉM limpa o cache de Threat Intel
#   sudo argus-reset --reports          # TAMBÉM remove os HTML de relatório do portal
#
set -uo pipefail

BASE_DIR="${ARGUS_BASE:-/etc/argus}"
DOCROOT="${ARGUS_DOCROOT:-/var/www/argus}"
PYTHON_BIN="$(command -v python3 || echo /usr/bin/python3)"
ASSUME_YES=0; WIPE_CACHES=0; WIPE_REPORTS=0

if [ -t 1 ]; then R=$'\e[31m'; G=$'\e[32m'; Y=$'\e[33m'; C=$'\e[36m'; B=$'\e[1m'; N=$'\e[0m'
else R=; G=; Y=; C=; B=; N=; fi

usage() {
  cat <<EOF
Uso: sudo bash argus-reset.sh [opções]
  -y, --yes        não pedir confirmação
      --caches     também limpar o cache de Threat Intel (PADRÃO: preserva)
      --reports    também remover os relatórios HTML do portal (recriados nos scans)
      --base DIR   diretório base do Argus (padrão: $BASE_DIR)
  -h, --help       esta ajuda
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    -y|--yes)   ASSUME_YES=1 ;;
    --caches)   WIPE_CACHES=1 ;;
    --reports)  WIPE_REPORTS=1 ;;
    --base)     BASE_DIR="${2:?--base requer um diretório}"; shift ;;
    -h|--help)  usage; exit 0 ;;
    *) echo "${R}Opção desconhecida: $1${N}"; usage; exit 2 ;;
  esac
  shift
done

[ "$(id -u)" -eq 0 ] || { echo "${R}Execute como root:${N} sudo bash argus-reset.sh"; exit 1; }
[ -d "$BASE_DIR" ]   || { echo "${R}Base não encontrada:${N} $BASE_DIR"; exit 1; }

# ── Bancos de achados (sempre removidos) ─────────────────────────────────────
DB_BASES=(
  "$BASE_DIR/store/argus.db"
  "$BASE_DIR/monitor/monitor.db"
  "$BASE_DIR/submonitor/submonitor.db"
  "$BASE_DIR/credentials/credentials.db"
  "$BASE_DIR/email/email.db"
  "$BASE_DIR/typosquat/typosquat.db"
  "$BASE_DIR/acknowledged.db"
)
shopt -s nullglob
to_remove=()
for base in "${DB_BASES[@]}"; do
  for f in "$base" "$base"-wal "$base"-shm "$base"-journal "$base".bak-*; do
    [ -e "$f" ] && to_remove+=("$f")
  done
done

# ── Cache de Threat Intel (somente com --caches) ─────────────────────────────
cache_remove=()
if [ "$WIPE_CACHES" -eq 1 ]; then
  for base in "$BASE_DIR/threatintel/threatintel.db" "$BASE_DIR/threatintel/intel.db"; do
    for f in "$base" "$base"-wal "$base"-shm "$base"-journal; do [ -e "$f" ] && cache_remove+=("$f"); done
  done
  for d in crtsh urlscan hudsonrock internetdb cisa_kev; do
    for f in "$BASE_DIR/threatintel/${d}_cache/"*; do [ -e "$f" ] && cache_remove+=("$f"); done
  done
fi

# ── Relatórios HTML (somente com --reports) ──────────────────────────────────
report_remove=()
if [ "$WIPE_REPORTS" -eq 1 ] && [ -d "$DOCROOT" ]; then
  for f in "$DOCROOT"/*_report.html; do [ -e "$f" ] && report_remove+=("$f"); done
fi

# ── Resumo + confirmação ─────────────────────────────────────────────────────
echo "${B}== Argus ASM — Reset de Achados ==${N}"
echo "Base: $BASE_DIR"
echo
echo "${Y}Será REMOVIDO (recomeça do zero):${N}"
if [ ${#to_remove[@]} -eq 0 ]; then echo "  (nenhum banco de achados encontrado)"
else printf '  %s\n' "${to_remove[@]}"; fi
if [ "$WIPE_CACHES" -eq 1 ]; then
  echo; echo "${Y}+ Cache de Threat Intel (${#cache_remove[@]} item[s]):${N}"
  echo "  threatintel.db · intel.db · {crtsh,urlscan,hudsonrock,internetdb,cisa_kev}_cache/*"
else
  echo; echo "${G}PRESERVADO:${N} enriquecimento (cache de Threat Intel intacto)."
fi
[ "$WIPE_REPORTS" -eq 1 ] && { echo "${Y}+ Relatórios HTML (${#report_remove[@]}):${N} $DOCROOT/*_report.html"; }
echo
echo "${G}PRESERVADO sempre:${N} targets/  e  threatintel/config.json (chaves de API)."
echo

if [ "$ASSUME_YES" -ne 1 ]; then
  read -r -p "Confirma? digite ${B}sim${N} para apagar: " ans
  [ "$ans" = "sim" ] || { echo "Cancelado."; exit 0; }
fi

# ── Execução ─────────────────────────────────────────────────────────────────
WEB=0
if systemctl list-unit-files 2>/dev/null | grep -q '^argus-web'; then
  systemctl stop argus-web 2>/dev/null && { WEB=1; echo "${C}argus-web parado.${N}"; }
fi

[ ${#to_remove[@]}    -gt 0 ] && rm -f  -- "${to_remove[@]}"
[ ${#cache_remove[@]} -gt 0 ] && rm -rf -- "${cache_remove[@]}"
[ ${#report_remove[@]} -gt 0 ] && rm -f  -- "${report_remove[@]}"
echo "${G}Bancos de achados removidos.${N}"
[ "$WIPE_CACHES" -eq 1 ] && echo "${G}Cache de Threat Intel limpo.${N}"

# Regenera os placeholders do portal (evita 404 até os scans rodarem)
if [ -d "$DOCROOT" ]; then
  if PYTHONPATH="$BASE_DIR" "$PYTHON_BIN" -c "import reporter; reporter.write_portal('$DOCROOT')" 2>/dev/null; then
    chown -R www-data:www-data "$DOCROOT" 2>/dev/null || true
    echo "${G}Portal regenerado (placeholders).${N}"
  fi
fi

[ "$WEB" -eq 1 ] && systemctl start argus-web 2>/dev/null && echo "${C}argus-web religado.${N}"

echo
echo "${B}Pronto — recomece rodando os módulos:${N}"
echo "  ${C}argus-submonitor && argus-credentials && argus-email && argus-typosquat && argus-monitor --tcp${N}"
echo "  (o enriquecimento foi preservado: o 1º scan reaproveita o cache de Threat Intel)"
