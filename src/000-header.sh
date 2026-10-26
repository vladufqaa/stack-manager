#!/usr/bin/env bash
STACK_MANAGER_VERSION="1.0.23"
# =====================================================================
# stack-manager.sh — управление SNI-стеком (3x-ui/LucX + AdGuard)
#   - Установка AdGuard Home (если не установлен)
#   - Установка панели LucX UI (если не установлена)
#   - Создание инбаундов через скрипт (автоопределение схемы БД)
#   - SNI-роутер на 443
#   - Decoy: панель (stub / AdGuard+DoH), Reality
#   - fail2ban, UFW, бэкапы, сертификаты, DNS Xray
# =====================================================================
set -o pipefail

G=$'\033[0;32m'; R=$'\033[0;31m'; Y=$'\033[1;33m'; B=$'\033[0;36m'; N=$'\033[0m'
log()  { echo -e "${G}[+]${N} $*"; }
warn() { echo -e "${Y}[!]${N} $*"; }
# Любая ошибка в интерактивном режиме должна быть замечена пользователем:
# печатаем короткую рекомендацию и ждём Enter. Это защищает от ситуации,
# когда важный отказ прокручивается следующими сообщениями.
ERROR_PAUSED=0
error_recommendation() {
  local __m="$*" __r="Проверьте причину выше; исправьте её и повторите этот пункт."
  case "$__m" in
    *сертификат*|*серт*|*certbot*|*CERT*)
      __r="Проверьте DNS A/AAAA, доступность порта 80 и лимиты Let's Encrypt; затем повторите выпуск сертификата." ;;
    *DNS*|*dns*|*резолв*|*разреш*)
      __r="Проверьте A/AAAA-запись домена: она должна указывать на этот сервер; после обновления DNS повторите операцию." ;;
    *порт*|*Port*|*listen*|*занят*)
      __r="Проверьте, какое приложение заняло порт (ss -lntup); выберите свободный порт или остановите конфликтующую службу." ;;
    *nginx*|*Nginx*)
      __r="Проверьте конфигурацию командой nginx -t и журнал systemctl status nginx; после исправления повторите." ;;
    *UFW*|*фаервол*|*firewall*)
      __r="Проверьте правила UFW и временно разрешите только необходимый порт; затем повторите операцию." ;;
    *x-ui*|*Xray*|*инбаунд*)
      __r="Проверьте состояние x-ui/Xray и журнал journalctl -u x-ui; исправьте причину и повторите настройку инбаунда." ;;
  esac
  echo -e "${Y}[>] Рекомендация: ${__r}${N}" >&2
}
err() {
  echo -e "${R}[x]${N} $*" >&2
  error_recommendation "$*"
  # В автоматическом/не-TTY запуске не блокируем пайплайн.
  if [[ -t 0 ]]; then
    ERROR_PAUSED=1
    pause
  fi
}
ok()   { echo -e "${G}[✓]${N} $*"; }
line() { echo -e "${B}────────────────────────────────────────────────────────${N}"; }

# Аудит действий: каждая операция, меняющая систему, — строка в журнал.
audit() {
  local f="${ACTION_LOG:-/root/stack-actions.log}"
  printf '%s root%s | %s\n' "$(date '+%F %T')" "${SUDO_USER:+ (sudo:$SUDO_USER)}" "$*" >> "$f" 2>/dev/null || true
}

# Сигнатура html-файлов каталога шаблонов — чтобы иниты печатали «готово»
# только когда реально что-то создали, а не при каждом запуске.
dir_sig() {
  find "$1" -maxdepth 1 -type f -name '*.html' -print0 2>/dev/null \
    | sort -z | xargs -0 -r md5sum 2>/dev/null | md5sum | awk '{print $1}'
}

[[ $EUID -eq 0 ]] || { err "Запустите от root (sudo $0)"; exit 1; }
export DEBIAN_FRONTEND=noninteractive
# Стабильный EN-вывод subprocess (ufw/systemctl/certbot): RU-локаль даёт
# «Статус: активен» и ломает парсинг. Собственные RU-сообщения скрипта не страдают.
# UTF-8 обязателен для корректного Backspace в Bash Readline.
export LC_ALL=C.UTF-8 LANG=C.UTF-8
read_safe() {
  local __prompt="$1" __var="$2"
  builtin read -e -r -p "$__prompt" "$__var"
}

BACKUP_DIR="/root/stack-backups"
# До явной настройки через меню скрипт работает только в режиме чтения.
# Этот маркер создаётся только после подтверждённой настройки пользователем.
STACK_CONFIGURED_FILE="/root/stack-backups/.stack-configured"
FW_STATE_DIR="/root/stack-backups/firewall-state"
ACTION_LOG="/root/stack-actions.log"

# Старые версии не всегда создавали .stack-configured. Если стек уже был
# установлен/поднят самим stack-manager, распознаём его по legacy-маркеру
# запуска и реально созданным артефактам. Это важно после обновления старой
# версии: существующую рабочую установку нельзя ошибочно считать «первым
# запуском» и закрывать пользователю разделы меню.
stack_legacy_installed() {
  [[ -f "$BACKUP_DIR/.stack-ever-ran" ]] || return 1
  [[ -n "${XUI_DB:-}" && -f "$XUI_DB" ]] || return 1
  [[ -f "$STACK_CONF" ]] || return 1
  [[ -f /etc/nginx/streams-available/sni-router.conf || -f "$SNI_CONF" ]] || return 1
  return 0
}
stack_is_configured() {
  [[ -f "$STACK_CONFIGURED_FILE" ]] && return 0
  # Миграция legacy-установки: маркер создаётся только при наличии всех
  # основных артефактов, а не просто из-за установленной панели.
  stack_legacy_installed || return 1
  stack_mark_configured
}
stack_mark_configured() {
  mkdir -p "$BACKUP_DIR" 2>/dev/null || return 1
  printf '%s\n' "configured=$(date '+%F %T')" > "$STACK_CONFIGURED_FILE" 2>/dev/null
}

# Wildcard-сертификат Cloudflare (один на все поддомены базового домена)
WILDCARD_DOMAIN=""
WILDCARD_STATE="/root/stack-backups/wildcard-domain"
CF_CREDS="/root/.secrets/cloudflare.ini"
CERT_DOMAINS_FILE="/etc/letsencrypt/stack-domains.txt"
# Режим выпуска сертификатов (A/B): файл + переменная (см. cert_mode_*)
CERT_MODE=""
CERT_MODE_FILE="/root/stack-backups/cert-mode"
# Файлы линий сертификатов (для режима B — несколько линий)
#   /root/stack-backups/cert-lines.txt              → список имён линий
#   /root/stack-backups/cert-line-<имя>.domains     → SAN этой линии (по строке)
CERT_LINES_FILE="/root/stack-backups/cert-lines.txt"
CERT_LINE_FILE_PREFIX="/root/stack-backups/cert-line-"
# Журнал отката: что скрипт поменял в панели — то и возвращает
PANEL_JOURNAL="/root/stack-backups/panel-journal.tsv"
LISTEN_JOURNAL="/root/stack-backups/inbound-listen.tsv"
ROWS_JOURNAL="/root/stack-backups/rows-journal.tsv"   # полные строки inbounds/hosts
JOURNAL_MARK="/root/stack-backups/.panel-journal-started"
DB_BIN="/usr/bin/sqlite3"
# =====================================================================
# CDN-режим XHTTP (см. xhttp_cdn_setup): инбаунд любого протокола с
# транспортом xhttp переводится в security=none (голый HTTP на loopback),
# TLS терминирует nginx. Единый локальный SSL-фронтенд + tsv-профили.
# =====================================================================
CDN_FE_PORT=47443                                        # локальный ssl-фронтенд nginx (http{})
CDN_PROFILES="/root/stack-backups/cdn-profiles.tsv"      # id|proto|origin|cdn|path|tpl|decoy_port
CDN_FORCE_IDS=""                                         # инбаунды, выбранные мастером как CDN
declare -a CERT_LINES=()
CERT_MULTI_NAME=""           # динамически = домен панели (cert_multi_name_resolve)
CERT_DEFER=0
CERT_BATCH_ENABLED=1
declare -a CERT_DOMAINS=()

# Сохранение email Let's Encrypt (переживает перезапуски скрипта)
LE_EMAIL_FILE="/root/stack-backups/le-email"


NGINX_STREAM_DIR="/etc/nginx/streams-enabled"
NGINX_SITES_DIR="/etc/nginx/sites-enabled"
NGINX_SITES_AVAIL="/etc/nginx/sites-available"
STACK_CONF="$NGINX_SITES_AVAIL/stack.conf"     # единый http-конфиг: ACME :80 + панель :4443 + все decoy
STACK_LINK="$NGINX_SITES_DIR/stack.conf"       # симлинк в sites-enabled
SNI_CONF="$NGINX_STREAM_DIR/sni-router.conf"
PANEL_DECOY_DIR="/var/www/panel-decoy"
DECOY_TPL_DIR="/var/www/decoy-templates"
DECOY_LOGIN_DIR="/var/www/decoy-login"
DECOY_LOG_ACCESS="/var/log/nginx/decoy-access.log"
# Внешние таргеты для Reality БЕЗ своего SNI: dest = <хост>:443, serverNames = [хост].
# Список — как «найти цели» в панели (крупные площадки со стабильным TLS 1.3 + h2).
REALITY_TARGETS=(
  "www.cloudflare.com"
  "dl.google.com"
  "www.amazon.com"
  "aws.amazon.com"
  "www.amd.com"
  "www.microsoft.com"
  "www.nvidia.com"
  "www.samsung.com"
  "www.intel.com"
  "www.sony.com"
)
# Печатает хост-таргет для инбаунда без своего SNI (сид = id инбаунда, детерминированно)
reality_pick_target() {
  local n=${#REALITY_TARGETS[@]}
  printf '%s' "${REALITY_TARGETS[$(( (${1:-0} + RANDOM) % n ))]}"
}

# Меню «найти цели» с живой проверкой (TLS 1.3 + h2) — как кнопка в панели.
#   $1 = переменная результата, $2 = имя инбаунда (для заголовка)
reality_target_menu() {
  local __v="$1" cname="${2:-reality}" _i=1 _c _st _out rt=""
  echo >&2
  echo -e "${B}Reality «найти цели» — кандидаты (нужен TLS 1.3 + h2):${N}" >&2
  for _c in "${REALITY_TARGETS[@]}"; do
    _out=$(timeout 4 openssl s_client -connect "$_c:443" -servername "$_c" -alpn h2 </dev/null 2>/dev/null || true)
    if grep -q "TLSv1.3" <<<"$_out" && grep -q "ALPN protocol: h2" <<<"$_out"; then
      _st="✓ TLS1.3+h2"
    else
      _st="✗ не отвечает"
    fi
    printf "  %2d) %-22s %s\n" "$_i" "$_c" "$_st" >&2; _i=$((_i+1))
  done
  if [[ ! -t 0 ]]; then
    printf -v "$__v" '%s' "$(reality_find_target 1)"
    return 0
  fi
  ask rt "Цель для «$cname» (1-${#REALITY_TARGETS[@]})" "1" '^[0-9]+$'
  if (( rt >= 1 && rt <= ${#REALITY_TARGETS[@]} )); then
    printf -v "$__v" '%s' "${REALITY_TARGETS[$((rt-1))]}"
  else
    printf -v "$__v" '%s' "$(reality_find_target 1)"
  fi
  return 0
}

# «Найти цели» как кнопка в панели: перебираем кандидатов и берём первый, кто
# отвечает TLS 1.3 + ALPN h2 (именно это Reality требует от внешнего таргета).
# Кеш — в файл: функция вызывается через $(…) и глобальные переменные не переживают subshell.
reality_find_target() {
  local cf="/tmp/.reality-found-target"
  [[ -s "$cf" ]] && { printf '%s' "$(cat "$cf" 2>/dev/null)"; return 0; }
  local c out
  for c in "${REALITY_TARGETS[@]}"; do
    out=$(timeout 6 openssl s_client -connect "$c:443" -servername "$c" -alpn h2 </dev/null 2>/dev/null || true)
    if grep -q "TLSv1.3" <<<"$out" && grep -q "ALPN protocol: h2" <<<"$out"; then
      printf '%s' "$c" > "$cf" 2>/dev/null || true
      printf '%s' "$c"
      return 0
    fi
  done
  # ни один не прошёл живую проверку — fallback на выбор из списка
  reality_pick_target "${1:-0}"
}
DECOY_MAX_FAILS=10
DECOY_BAN_SECONDS=7200

LUCX_INSTALL_URL="https://raw.githubusercontent.com/AlexeyLCP/lucx-ui/main/install.sh"
ADG_INSTALL_URL="https://raw.githubusercontent.com/AdguardTeam/AdGuardHome/master/scripts/install.sh"

# Бинарник Xray для генерации Reality-ключей (LucX использует xray-linux-amd64)
XRAY_BIN=""
find_xray_bin() {
  local cand
  for cand in \
    /usr/local/x-ui/bin/xray-linux-amd64 \
    /usr/local/x-ui/bin/xray-linux-arm64 \
    /usr/local/x-ui/bin/xray-linux-arm32 \
    /usr/local/x-ui/bin/xray-linux-386 \
    /usr/local/x-ui/xray \
    /usr/local/bin/xray; do
    [[ -x "$cand" ]] && { XRAY_BIN="$cand"; return 0; }
  done
  # поиск по имени
  local found
  found=$(find /usr/local /opt -maxdepth 4 -type f -name 'xray*' -perm -u+x 2>/dev/null | head -1 || true)
  [[ -n "$found" ]] && { XRAY_BIN="$found"; return 0; }
  return 1
}

ADG_WEB_PORT=3000
XUI_DB=""
PANEL_FLAVOR=""
ADG_PRESENT=false
ADG_SERVICE=""
ADG_CONFIG=""
EMAIL=""
SSH_PORT="22"

DECOY_TEMPLATES=(
  "default|Nginx default — стандартная заглушка"
  "blank|Пустая белая страница"
  "corporate|Корпоративный лендинг (варьируется)"
  "blog|Персональный блог (варьируется)"
  "docs|Документация / wiki"
  "cloudflare|Cloudflare-style"
  "maintenance|▶ Техработы — «вернёмся позже»"
  "hosting-panel|▶ Панель хостинга — login (интерактивный)"
  "portfolio|▶ Фото-портфолио"
  "shop|▶ Магазин «скоро открытие» (трап-подписка)"
  "redirect|▶ Редирект 302 на URL — контента нет вовсе"
  "locked|▶ Закрытый раздел 401 — только окно логина"
  "adguard|▶ AdGuard Home — login (интерактивный)"
  "portainer|▶ Portainer — login (интерактивный)"
  "pihole|▶ Pi-hole — login (интерактивный)"
  "omv|▶ OpenMediaVault — login (интерактивный)"
  "jellyfin|▶ Jellyfin — login (интерактивный)"
  "homeassistant|▶ Home Assistant — login (интерактивный)"
  "uptime-kuma|▶ Uptime Kuma — login (интерактивный)"
)

# name|proto|transport|security|flow|net
# Создавать из скрипта можно ТОЛЬКО то, что LucX умеет запускать сам по данным БД:
#   VLESS + hysteria/qwdtt/csqtt/tproxy (рецепты lucx-ui-pro) + naive/trusttunnel/anytls
#   (tunnel-инбаунды LucX: панель сама поднимает caddy-naive / trusttunnel / anytls,
#    логины-пароли клиентов генерирует HMAC от authSeed).
# mtproto из скрипта не создаём — в LucX его роль играет tproxy (TG WEB-PROXY).
RECOMMENDED_INBOUNDS=(
  "VLESS TCP REALITY|vless|tcp|reality|xtls-rprx-vision|tcp"
  "VLESS TCP TLS|vless|tcp|tls||tcp"
  "VLESS XHTTP (через CDN)|vless|xhttp|none||tcp"
  "VLESS XHTTP TLS|vless|xhttp|tls||tcp"
  "VLESS XHTTP REALITY|vless|xhttp|reality||tcp"
  "NAIVE (TLS, за 443)|naive|naive|tls|-|tcp"
  "TRUSTTUNNEL (TLS, за 443)|trusttunnel|trusttunnel|tls|-|tcp"
  "ANYTLS (TLS, за 443)|anytls|anytls|tls|-|tcp"
  "HYSTERIA2 (UDP)|hysteria|hysteria|tls|-|udp"
  "QWDTT (UDP 56000)|qwdtt|qwdtt|-|-|udp"
  "CSQTT (UDP 46000)|csqtt|csqtt|-|-|udp"
  "TG WEB-PROXY (443→11443)|tproxy|tproxy|-|-|tcp"
)

is_login_template() {
  case "$1" in
    adguard|portainer|pihole|omv|jellyfin|homeassistant|uptime-kuma|hosting-panel|shop) return 0 ;;
    *) return 1 ;;
  esac
}

# =====================================================================
