#!/usr/bin/env bash
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

G='\033[0;32m'; R='\033[0;31m'; Y='\033[1;33m'; B='\033[0;36m'; N='\033[0m'
log()  { echo -e "${G}[+]${N} $*"; }
warn() { echo -e "${Y}[!]${N} $*"; }
err()  { echo -e "${R}[x]${N} $*" >&2; }
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
export LC_ALL=C LANG=C

BACKUP_DIR="/root/stack-backups"
FW_STATE_DIR="/root/stack-backups/firewall-state"
ACTION_LOG="/root/stack-actions.log"

# Wildcard-сертификат Cloudflare (один на все поддомены базового домена)
WILDCARD_DOMAIN=""
WILDCARD_STATE="/root/stack-backups/wildcard-domain"
CF_CREDS="/root/.secrets/cloudflare.ini"
FROZEN_FILE="/root/stack-frozen.txt"   # заморозка самолечения: cert:<domain> / inbound:<id> / ALL-CERTS
MULTI_CERT_NAME="stack-multi"                    # имя SAN-линии мультисерта (live/stack-multi)
MULTI_CERT_FILE="/root/stack-multi-cert-domains.txt"   # список доменов мультисерта (по одному в строке)

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
# ВВОД
# =====================================================================
ask() {
  # внутренние имена с __: если целевая переменная тоже называется d/in/p/r,
  # printf -v попадал в локальную ask, а не в вызывающую функцию (потеря ввода)
  local __v="$1" __p="$2" __d="$3" __r="${4:-}" __in
  while :; do
    if [[ -n "$__d" ]]; then
      read -rp "$(echo -e "${B}?${N} ${__p} [${__d}]: ")" __in || __in=""
      __in="${__in:-$__d}"
    else
      read -rp "$(echo -e "${B}?${N} ${__p}: ")" __in || __in=""
    fi
    case "${__in,,}" in
      q|quit|exit|выход)
        warn "Прервано — возврат в меню"
        exit 42 ;;          # под-оболочка пункта меню ловит 42 → назад в меню
    esac
    [[ -z "$__r" || "$__in" =~ $__r ]] && { printf -v "$__v" '%s' "$__in"; return; }
    err "Некорректно."
  done
}

askyn() {
  local __v="$1" __p="$2" __d="$3" __in
  while :; do
    read -rp "$(echo -e "${B}?${N} ${__p} [${__d}]: ")" __in || __in=""
    __in="${__in:-$__d}"
    case "${__in,,}" in
      q|quit|exit|выход)
        warn "Прервано — возврат в меню"
        exit 42 ;;
      y|yes|д|да) printf -v "$__v" 'true'; return;;
      n|no|н|нет) printf -v "$__v" 'false'; return;;
    esac
    err "y/n"
  done
}

pause() { read -rp "$(echo -e "${B}Нажмите Enter${N}")" _ || true; }

# =====================================================================
# ПРОВЕРКА ОС
# =====================================================================
check_os() {
  if [[ -f /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    case "${ID:-}" in
      ubuntu) [[ "$VERSION_ID" == "24.04" || "$VERSION_ID" == "26.04" ]] && return 0 ;;
      debian) [[ "$VERSION_ID" == "12" || "$VERSION_ID" == "13" ]] && return 0 ;;
    esac
    warn "ОС ${PRETTY_NAME:-неизвестна} не в списке поддерживаемых"
    sleep 2
  fi
  return 0
}

# =====================================================================
# УТИЛИТЫ
# =====================================================================
ensure_deps() {
  local missing=() t
  for t in sqlite3 jq curl ss nginx certbot openssl dig ufw fail2ban-client nc xxd; do
    command -v "$t" >/dev/null 2>&1 && continue
    case "$t" in
      sqlite3) missing+=(sqlite3);;
      jq) missing+=(jq);;
      curl) missing+=(curl);;
      ss) missing+=(iproute2);;
      nginx) missing+=(nginx);;
      certbot) missing+=(certbot);;
      openssl) missing+=(openssl);;
      dig) missing+=(dnsutils);;
      ufw) missing+=(ufw);;
      fail2ban-client) missing+=(fail2ban);;
      nc) missing+=(netcat-openbsd);;
      xxd) missing+=(xxd);;
    esac
  done
  dpkg -s libnginx-mod-stream >/dev/null 2>&1 || missing+=(libnginx-mod-stream)
  if [[ ${#missing[@]} -gt 0 ]]; then
    log "Установка: ${missing[*]}"
    apt-get update -y >/dev/null 2>&1 || true
    apt-get install -y "${missing[@]}" >/dev/null 2>&1 || true
  fi
}

get_random_port() { echo $(( ((RANDOM<<15)|RANDOM) % 49152 + 10000 )); }
gen_random_string() { head -c 4096 /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c "$1"; }

port_in_use() {
  local p="$1"
  ss -Hltn "sport = :$p" 2>/dev/null | grep -q . && return 0
  ss -Huln "sport = :$p" 2>/dev/null | grep -q . && return 0
  command -v nc >/dev/null 2>&1 && { timeout 1 nc -w 1 -z 127.0.0.1 "$p" &>/dev/null; return $?; }
  return 1
}

is_port_reserved() {
  local p="$1"
  case "$p" in
    22|53|80|443|3000|4443|5432|6060|8080|8443) return 0 ;;
  esac
  (( p >= 4444 && p <= 4600 )) && return 0   # decoy-порты 4444+
  [[ "$p" == "$SSH_PORT" ]] && return 0
  [[ -n "${PANEL_PORT:-}" && "$p" == "$PANEL_PORT" ]] && return 0
  [[ -n "${SUB_PORT:-}"   && "$p" == "$SUB_PORT"   ]] && return 0
  return 1
}

make_port() {
  local p tries=0
  while (( tries < 200 )); do
    p=$(get_random_port)
    if ! port_in_use "$p" && ! is_port_reserved "$p"; then
      echo "$p"; return 0
    fi
    tries=$((tries+1))
  done
  echo "$p"
}

# =====================================================================
# УНИКАЛЬНОСТЬ SNI-ДОМЕНОВ
#   SNI_USED[домен] = backend — домены, занятые панелью/инбаундами
# =====================================================================
declare -A SNI_USED=()

sni_used_load() {
  SNI_USED=()
  [[ -f "$SNI_CONF" ]] || return 0
  local line dom be
  local _re='^[[:space:]]+([A-Za-z0-9.-]+)[[:space:]]+([A-Za-z0-9_-]+);'
  while IFS= read -r line; do
    [[ "$line" =~ $_re ]] || continue
    dom="${BASH_REMATCH[1]}"; be="${BASH_REMATCH[2]}"
    [[ "$dom" == "default" ]] && continue
    SNI_USED["$dom"]="$be"
  done < "$SNI_CONF"
  return 0
}

# Печатает backend, который уже занимает домен $1 (кроме инбаунда $2), иначе пусто
sni_domain_owner() {
  local dom="$1" self="${2:-}" be=""
  [[ -z "$dom" ]] && { echo ""; return; }
  be="${SNI_USED[$dom]:-}"
  if [[ -z "$be" && -f "$SNI_CONF" ]]; then
    be=$(grep -E "^[[:space:]]+${dom//./\\.}[[:space:]]+[A-Za-z0-9_-]+;" "$SNI_CONF" 2>/dev/null | head -1 | awk '{print $2}' | tr -d ';' || true)
    [[ -n "$be" ]] && SNI_USED["$dom"]="$be"
  fi
  [[ -n "$self" && "$be" == "inb_${self}_backend" ]] && be=""
  echo "$be"
}

sni_domain_taken() { [[ -n "$(sni_domain_owner "$@")" ]]; }

# Интерактивный запрос уникального SNI-домена:
#   $1 = имя переменной результата, $2 = id инбаунда, $3 = домен по умолчанию
# ВАЖНО: переменная результата НЕ должна называться d/p/r/in — это локали ask()
ask_sni_domain() {
  local __v="$1" __id="$2" __def="$3" d_val owner
  while :; do
    d_val=""
    ask d_val "SNI-домен для #${__id}" "$__def" '^[a-zA-Z0-9.-]+$'
    [[ -z "$d_val" ]] && { err "Пустой домен."; continue; }
    owner=$(sni_domain_owner "$d_val" "$__id")
    if [[ -n "$owner" ]]; then
      err "Домен $d_val уже занят ($owner). Укажите другой SNI-домен — у двух инбаундов не может быть один SNI."
      continue
    fi
    printf -v "$__v" '%s' "$d_val"
    SNI_USED["$d_val"]="inb_${__id}_backend"
    return 0
  done
}

check_domain_points_to_server() {
  local domain="$1" server_ip="${2:-}"
  [[ -z "$server_ip" ]] && server_ip=$(curl -s --max-time 5 ifconfig.me 2>/dev/null || true)
  [[ -z "$server_ip" ]] && return 0
  local resolved=""
  resolved=$(dig +short "$domain" @1.1.1.1 2>/dev/null | grep -E '^[0-9.]+$' | tail -1 || true)
  [[ -z "$resolved" ]] && resolved=$(dig +short "$domain" @8.8.8.8 2>/dev/null | grep -E '^[0-9.]+$' | tail -1 || true)
  [[ -z "$resolved" ]] && { warn "Домен $domain не резолвится"; return 1; }
  [[ "$resolved" != "$server_ip" ]] && { warn "DNS mismatch: $domain=$resolved, server=$server_ip"; return 1; }
  log "DNS OK: $domain -> $resolved"
  return 0
}

# Определяем вариант панели: LucX-форк vs оригинальный 3x-ui.
#   LucX имеет уникальные маркеры: триггеры lucx_shareonly_*, таблицу
#   client_inbounds, фикс-теги sidecar-инбаундов (inbound-qwdtt/csqtt/tproxy).
#   Если ни одного маркера нет — считаем оригинальным 3x-ui.
# Печатает: lucx | 3x-ui | none
detect_panel_flavor() {
  [[ -z "$XUI_DB" || ! -f "$XUI_DB" ]] && { echo "none"; return 0; }
  local v=""
  v=$(sqlite3 -cmd ".timeout 3000" "$XUI_DB" "SELECT name FROM sqlite_master WHERE type='trigger' AND name LIKE 'lucx_shareonly_%' LIMIT 1;" 2>/dev/null || true)
  [[ -n "$v" ]] && { echo "lucx"; return 0; }
  v=$(sqlite3 -cmd ".timeout 3000" "$XUI_DB" "SELECT name FROM sqlite_master WHERE type='table' AND name='client_inbounds' LIMIT 1;" 2>/dev/null || true)
  [[ -n "$v" ]] && { echo "lucx"; return 0; }
  v=$(sqlite3 -cmd ".timeout 3000" "$XUI_DB" "SELECT 1 FROM inbounds WHERE tag IN ('inbound-qwdtt','inbound-csqtt','inbound-tproxy') LIMIT 1;" 2>/dev/null || true)
  [[ "$v" == "1" ]] && { echo "lucx"; return 0; }
  echo "3x-ui"
}

detect_env() {
  XUI_DB=""
  local db
  for db in /etc/x-ui/x-ui.db /usr/local/x-ui/x-ui.db /opt/x-ui/x-ui.db; do
    [[ -f "$db" ]] && { XUI_DB="$db"; break; }
  done

  ADG_PRESENT=false; ADG_SERVICE=""; ADG_CONFIG=""
  local svc cfg
  for svc in AdGuardHome adguard-home adguardhome; do
    if [[ -f "/etc/systemd/system/${svc}.service" ]] || \
       systemctl list-unit-files "${svc}.service" 2>/dev/null | grep -qE "^${svc}\.service"; then
      ADG_SERVICE="$svc"; ADG_PRESENT=true; break
    fi
  done
  for cfg in /opt/AdGuardHome/AdGuardHome.yaml /root/AdGuardHome/AdGuardHome.yaml \
             /etc/AdGuardHome.yaml /etc/adguardhome/AdGuardHome.yaml; do
    [[ -f "$cfg" ]] && { ADG_CONFIG="$cfg"; ADG_PRESENT=true; break; }
  done
  if [[ "$ADG_PRESENT" == true && -z "$ADG_SERVICE" ]]; then
    local found
    found=$(systemctl list-unit-files 2>/dev/null | grep -iE 'adguard' | awk '{print $1}' | head -1 || true)
    [[ -n "$found" ]] && ADG_SERVICE="${found%.service}"
  fi

  SSH_PORT=""
  if [[ -f /etc/ssh/sshd_config ]]; then
    SSH_PORT=$(grep -E '^[[:space:]]*Port[[:space:]]+[0-9]+' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' | head -1 || true)
  fi
  SSH_PORT="${SSH_PORT:-22}"

  find_xray_bin || true
  PANEL_FLAVOR=$(detect_panel_flavor)
}

xui_get() {
  [[ -z "$XUI_DB" || ! -f "$XUI_DB" ]] && return 0
  sqlite3 "$XUI_DB" "SELECT value FROM settings WHERE key='$1' LIMIT 1;" 2>/dev/null | tr -d '"' || true
}

# UPSERT настройки панели (UPDATE, если ключ есть; INSERT — если нет)
xui_set_setting() {
  [[ -z "$XUI_DB" || ! -f "$XUI_DB" ]] && return 0
  local k="$1" v="$2"
  sqlite3 "$XUI_DB" "UPDATE settings SET value='$v' WHERE key='$k';" 2>/dev/null || true
  sqlite3 "$XUI_DB" "INSERT INTO settings (key, value) SELECT '$k','$v' WHERE NOT EXISTS (SELECT 1 FROM settings WHERE key='$k');" 2>/dev/null || true
}

# URL подписки (обратный прокси): https://<домен><subPath> — без ":443",
# 443 и так дефолтный для https; лишний порт в URL не нужен.
# subPath ОБЯЗАТЕЛЬНО с ведущим и хвостовым "/" — иначе LucX клеит токен
# вплотную к домену: https://domTOKEN вместо https://dom/путь/TOKEN
suburi_build() {
  local dom="$1" sp="${2:-}"
  [[ -z "$sp" ]] && sp=$(xui_get subPath 2>/dev/null || true)
  sp="/${sp#/}"; sp="${sp%/}/"
  [[ "$sp" == "/" ]] && sp=""
  printf 'https://%s%s' "$dom" "$sp"
}

is_udp_proto() {
  case "$1" in
    hysteria|hysteria2|wireguard|amnezia|amneziawg|awg|qwdtt|csqdtt|csqtt|kroute|krout|krw) return 0 ;;
    *) return 1 ;;
  esac
}

# Порты UDP-инбаундов из БД панели — ЕДИНСТВЕННЫЙ источник правды для файрвола.
# Сокет-сканирование UDP не годится: xray и резолверы плодят несвязанные
# sendto()-сокеты на ephemeral-портах, неотличимые по peer от слушателей.
udp_inbound_ports() {
  [[ -z "$XUI_DB" || ! -f "$XUI_DB" ]] && return 0
  sqlite3 "$XUI_DB" "SELECT id, protocol, port FROM inbounds WHERE enable=1 AND port>0;" 2>/dev/null |
  while IFS='|' read -r _id _pr _pt; do
    [[ -z "$_pt" ]] && continue
    is_udp_proto "$_pr" && echo "$_pt"
  done | sort -un
}

# Заморозка: строка вида «cert:<domain>», «inbound:<id>» или «ALL-CERTS»
# в FROZEN_FILE запрещает АВТОМАТИКЕ (heal-таймер, авто-выпуск сертов)
# трогать объект. Ручные действия через меню не блокируются.
frozen() {
  [[ -s "$FROZEN_FILE" ]] || return 1
  grep -qxF -- "$1" "$FROZEN_FILE" 2>/dev/null
}

proto_remark() {
  local proto="$1" stream="${2:-}"
  case "$proto" in
    vless) grep -q '"security": *"reality"' <<<"$stream" && echo "reality" || echo "vless" ;;
    trusttunnel|trust-tunnel) echo "trusttunnel" ;;
    naive|naiveproxy) echo "naive" ;;
    mtproto) echo "mtproto" ;;
    hysteria|hysteria2) echo "hysteria2" ;;
    qwdtt) echo "qwdtt" ;;
    csqtt|csqdtt) echo "csqtt" ;;
    tproxy) echo "webproxy" ;;
    awg|amneziawg|wireguard) echo "awg" ;;
    *) echo "$proto" ;;
  esac
}

# IP сервера (IPv4) — для subHost у tunnel-протоколов
server_ip4() {
  local ip=""
  ip=$(curl -4 -s --connect-timeout 4 --max-time 8 ifconfig.me 2>/dev/null | tr -d '[:space:]')
  [[ -z "$ip" ]] && ip=$(hostname -I 2>/dev/null | awk '{print $1}')
  echo "$ip"
}

# Триггеры синхронизации клиентов qwdtt/csqtt/tproxy (как в lucx-ui-pro):
# клиенты хранятся в clients+client_inbounds, а inbounds.settings[].clients зеркалится
ensure_shareonly_triggers() {
  [[ -z "$XUI_DB" || ! -f "$XUI_DB" ]] && return 0
  sqlite3 "$XUI_DB" <<'SQL' 2>/dev/null || true
UPDATE inbounds
SET settings = json_set(
  CASE WHEN json_valid(settings) THEN settings ELSE '{}' END,
  '$.clients',
  CASE WHEN json_type(json_extract(settings, '$.clients')) = 'array'
       THEN json_extract(settings, '$.clients')
       ELSE json('[]') END
)
WHERE protocol IN ('qwdtt','csqtt','tproxy');
DROP TRIGGER IF EXISTS lucx_shareonly_clients_ins;
DROP TRIGGER IF EXISTS lucx_shareonly_clients_del;
CREATE TRIGGER lucx_shareonly_clients_ins
AFTER INSERT ON client_inbounds
WHEN EXISTS (SELECT 1 FROM inbounds WHERE id = NEW.inbound_id AND protocol IN ('qwdtt','csqtt','tproxy'))
BEGIN
  UPDATE inbounds SET settings = json_insert(
    json_set(
      settings,
      '$.clients',
      CASE WHEN json_type(json_extract(settings, '$.clients')) = 'array'
           THEN json_extract(settings, '$.clients')
           ELSE json('[]') END
    ),
    '$.clients[#]',
    json_object(
      'email', COALESCE((SELECT email FROM clients WHERE id = NEW.client_id), ''),
      'enable', json('true')
    )
  )
  WHERE id = NEW.inbound_id
    AND COALESCE((SELECT email FROM clients WHERE id = NEW.client_id), '') != ''
    AND NOT EXISTS (
      SELECT 1 FROM json_each(
        CASE WHEN json_type(json_extract(inbounds.settings, '$.clients')) = 'array'
             THEN json_extract(inbounds.settings, '$.clients')
             ELSE json('[]') END
      )
      WHERE json_extract(value, '$.email') = (SELECT email FROM clients WHERE id = NEW.client_id)
    );
END;
CREATE TRIGGER lucx_shareonly_clients_del
AFTER DELETE ON client_inbounds
WHEN EXISTS (SELECT 1 FROM inbounds WHERE id = OLD.inbound_id AND protocol IN ('qwdtt','csqtt','tproxy'))
BEGIN
  UPDATE inbounds SET settings = json_set(
    settings,
    '$.clients',
    (
      SELECT json_group_array(json(value))
      FROM json_each(
        CASE WHEN json_type(json_extract(inbounds.settings, '$.clients')) = 'array'
             THEN json_extract(inbounds.settings, '$.clients')
             ELSE json('[]') END
      )
      WHERE json_extract(value, '$.email') != (SELECT email FROM clients WHERE id = OLD.client_id)
         OR (SELECT email FROM clients WHERE id = OLD.client_id) IS NULL
    )
  )
  WHERE id = OLD.inbound_id;
END;
SQL
}

# Камуфляж-сайт для tproxy: НЕЙТРАЛЬНАЯ заглушка (blog), НЕ связанная с Telegram —
# мимикрия под Telegram на tg-домене = прямая подсказка, что за ним tg-прокси.
ensure_tproxy_site() {
  mkdir -p /var/www/html 2>/dev/null || true
  rm -f /var/www/html/telegram.html 2>/dev/null || true   # след прошлой версии
  # перезаписываем ВСЕГДА: пустышка/старый index = белый лист для посторонних
  if [[ -n "$DECOY_TPL_DIR" && -f "$DECOY_TPL_DIR/blog.html" ]]; then
    cp -f "$DECOY_TPL_DIR/blog.html" /var/www/html/index.html 2>/dev/null || true
  elif [[ ! -s /var/www/html/index.html ]]; then
    printf '%s\n' \
      '<!DOCTYPE html><html><head><meta charset="utf-8"><title></title></head><body></body></html>' \
      > /var/www/html/index.html
  fi
  chmod 644 /var/www/html/index.html 2>/dev/null || true
}

# открыть UDP-порты в UFW, если он активен
ufwd_allow_udp() {
  command -v ufw >/dev/null 2>&1 || return 0
  ufw status 2>/dev/null | grep -q "Status: active" || return 0
  local p
  for p in "$@"; do ufw allow "$p/udp" >/dev/null 2>&1 || true; done
}

# =====================================================================
# ADGUARD HOME
# =====================================================================
# свободный порт для web-UI AdGuard: 3000, если занят — первый свободный из 3001..3099
adg_pick_port() {
  local p="$ADG_WEB_PORT" i
  if port_in_use "$p"; then
    for i in $(seq 3001 3099); do
      port_in_use "$i" || { p=$i; break; }
    done
  fi
  ADG_WEB_PORT="$p"
}

# bcrypt-хэш для AdGuard (Go bcrypt понимает $2a/$2b/$2y): python3 → htpasswd
adg_bcrypt() {
  local pw="$1" h=""
  if command -v python3 >/dev/null 2>&1; then
    # 1) pip-модуль bcrypt (основной; модуль crypt УДАЛЁН из Python 3.13+)
    h=$(python3 -c 'import sys
try:
    import bcrypt
    sys.stdout.write(bcrypt.hashpw(sys.argv[1].encode(), bcrypt.gensalt(10)).decode())
except Exception:
    sys.exit(1)' "$pw" 2>/dev/null || true)
    [[ "$h" == \$2* ]] && { echo "$h"; return 0; }
    # 2) stdlib crypt (Python < 3.13)
    h=$(python3 -c 'import sys
try:
    import crypt
    sys.stdout.write(crypt.crypt(sys.argv[1], crypt.mksalt(crypt.METHOD_BLOWFISH)))
except Exception:
    sys.exit(1)' "$pw" 2>/dev/null || true)
    [[ "$h" == \$2* ]] && { echo "$h"; return 0; }
  fi
  # 3) htpasswd (ставим apache2-utils при необходимости)
  command -v htpasswd >/dev/null 2>&1 || apt-get install -y apache2-utils >/dev/null 2>&1 || true
  if command -v htpasswd >/dev/null 2>&1; then
    h=$(htpasswd -bnBC 10 "" "$pw" 2>/dev/null | tr -d ':\n' || true)
    [[ "$h" == \$2* ]] && { echo "$h"; return 0; }
  fi
  return 1
}

# записать админа AdGuard (заменяет всех пользователей; пропускает визард первого запуска)
adg_set_admin() {
  local cfg="$ADG_CONFIG" user="$1" pass="$2"
  if [[ -z "$cfg" || ! -f "$cfg" ]]; then
    local c2
    for c2 in /opt/AdGuardHome/AdGuardHome.yaml /root/AdGuardHome/AdGuardHome.yaml \
              /etc/AdGuardHome.yaml /etc/adguardhome/AdGuardHome.yaml; do
      [[ -f "$c2" ]] && { cfg="$c2"; ADG_CONFIG="$c2"; break; }
    done
  fi
  [[ -z "$cfg" || ! -f "$cfg" ]] && { err "adg_set_admin: AdGuardHome.yaml не найден (ADG_CONFIG='$ADG_CONFIG')"; return 1; }
  local hash
  hash=$(adg_bcrypt "$pass") || { err "adg_set_admin: не удалось создать bcrypt-хэш (нет python3-bcrypt и htpasswd)"; return 1; }
  local svc="${ADG_SERVICE:-AdGuardHome}"
  systemctl stop "$svc" 2>/dev/null || true
  if grep -q '^users:' "$cfg"; then
    # заменяем ВЕСЬ блок users (до следующей строки верхнего уровня) — иначе
    # старый вложенный password: остаётся рядом с новым → yaml не парсится
    awk -v n="  - name: $user" -v p="    password: $hash" '
      /^users:/ { print; print n; print p; inu=1; next }
      inu && /^[^ #]/ { inu=0 }
      inu { next }
      { print }
    ' "$cfg" > "$cfg.new" && mv "$cfg.new" "$cfg"
  else
    printf 'users:\n  - name: %s\n    password: %s\n' "$user" "$hash" >> "$cfg"
  fi
  systemctl start "$svc" 2>/dev/null || true
  sleep 1
  return 0
}

# bootstrap конфига AdGuard при ЧИСТОЙ установке: без yaml сервис висит
# в режиме визарда на 0.0.0.0:3000. Конфиг НЕ пишем руками (схема меняется
# между версиями) — проходим официальный визард через его API: AdGuard сам
# генерирует родной AdGuardHome.yaml (web 127.0.0.1, DNS bind 127.0.0.1:53).
adg_bootstrap_config() {
  local admin_pass="$1"
  local cfg="${ADG_CONFIG:-/opt/AdGuardHome/AdGuardHome.yaml}"
  local dir; dir=$(dirname "$cfg")
  mkdir -p "$dir/data" "$dir/filters" 2>/dev/null || true
  systemctl start "$ADG_SERVICE" 2>/dev/null || true
  sleep 2
  local code=""
  code=$(curl -s -o /tmp/.agh-install.json -w '%{http_code}' --max-time 20 \
    -X POST http://127.0.0.1:3000/control/install/configure \
    -H 'Content-Type: application/json' \
    -d "{\"web\":{\"ip\":\"127.0.0.1\",\"port\":$ADG_WEB_PORT},\"dns\":{\"ip\":\"127.0.0.1\",\"port\":53},\"username\":\"admin\",\"password\":\"$admin_pass\"}" 2>/dev/null) || true
  if [[ "$code" != "200" ]]; then
    err "AdGuard wizard API не ответил 200 (got: $code)"
    head -c 300 /tmp/.agh-install.json 2>/dev/null; echo
    return 1
  fi
  # сервис перезапускается сам — ждём новый порт
  local i
  for i in 1 2 3 4 5 6; do
    ss -tlnH "sport = :$ADG_WEB_PORT" 2>/dev/null | grep -q . && break
    sleep 2
  done
  if ! ss -tlnH "sport = :$ADG_WEB_PORT" 2>/dev/null | grep -q .; then
    err "AdGuard не поднялся на 127.0.0.1:$ADG_WEB_PORT после визарда"
    return 1
  fi
  ADG_CONFIG="$cfg"
  # upstream'ы → Cloudflare/Google (дефолт визарда — quad9)
  curl -s -o /dev/null --max-time 10 -u "admin:$admin_pass" \
    -X POST "http://127.0.0.1:$ADG_WEB_PORT/control/dns_config" \
    -H 'Content-Type: application/json' \
    -d '{"upstream_dns":["https://dns.cloudflare.com/dns-query","8.8.8.8"],"bootstrap_dns":["1.1.1.1","8.8.8.8"]}' 2>/dev/null || true
  log "AdGuard: конфиг создан визард-API (web 127.0.0.1:$ADG_WEB_PORT · DNS 127.0.0.1:53 · admin/admin_pass)"
  return 0
}

# фактический web-порт AdGuard: при включённом TLS — tls.port_https (UI+DoH),
# иначе — порт из http.address
adg_config_port() {
  local cfg="$ADG_CONFIG"
  if [[ -z "$cfg" || ! -f "$cfg" ]]; then echo "$ADG_WEB_PORT"; return; fi
  local tls_en="" p=""
  tls_en=$(awk '/^tls:/{f=1;next} /^[^ ]/{f=0} f && /^  enabled:/{print $2; exit}' "$cfg" 2>/dev/null | tr -d '"')
  if [[ "$tls_en" == "true" ]]; then
    p=$(awk '/^tls:/{f=1;next} /^[^ ]/{f=0} f && /^  port_https:/{print $2; exit}' "$cfg" 2>/dev/null)
    if [[ -n "$p" && "$p" != "0" ]]; then echo "$p"; return; fi
  fi
  p=$(awk '/^http:/{f=1;next} /^[^ ]/{f=0} f && /^  address:/{n=split($2,a,":"); print a[n]; exit}' "$cfg" 2>/dev/null | tr -d '"')
  echo "${p:-$ADG_WEB_PORT}"
}

install_adguard_home() {
  line; echo -e "${B}   УСТАНОВКА ADGUARD HOME${N}"; line
  detect_env
  [[ "$ADG_PRESENT" == true ]] && { log "AdGuard Home уже установлен"; return 0; }
  warn "AdGuard Home не найден — устанавливаю (вопрос задаётся один раз, в начале скрипта)."

  log "Запуск установщика AdGuard Home..."
  if ! curl -s -S -L "$ADG_INSTALL_URL" | sh -s -- -v; then
    err "Ошибка установки AdGuard Home"; return 1
  fi
  sleep 3
  detect_env
  [[ "$ADG_PRESENT" != true ]] && { err "AdGuardHome.service не найден"; return 1; }

  log "AdGuard Home установлен: $ADG_SERVICE"
  adg_pick_port
  local adg_user="${U_ADG_USER:-admin}" adg_pass=""
  adg_pass=$(openssl rand -base64 18 2>/dev/null | tr -dc 'a-zA-Z0-9' | head -c 16)
  [[ -z "$adg_pass" ]] && adg_pass="AdG$(date +%s)"
  # чистая установка: конфига нет (режим визарда) → создаём через wizard-API
  if [[ -z "$ADG_CONFIG" || ! -f "$ADG_CONFIG" ]]; then
    adg_bootstrap_config "$adg_pass" || warn "Bootstrap AdGuardHome.yaml не удался — настройте вручную"
  fi
  configure_adguard_local || warn "Настройте bind вручную"

  # автоматические учётные данные админа — визард не нужен
  adg_user="${U_ADG_USER:-admin}" adg_pass=""
  adg_pass=$(openssl rand -base64 18 2>/dev/null | tr -dc 'a-zA-Z0-9' | head -c 16)
  [[ -z "$adg_pass" ]] && adg_pass="AdG$(date +%s)"
  if adg_set_admin "$adg_user" "$adg_pass"; then
    {
      echo "AdGuard Home — $(date '+%F %T')"
      echo "  URL:    https://<домен-панели>/          (после п.1, decoy=adguard)"
      echo "  DoH:    https://<домен-панели>/dns-query"
      echo "  Логин:  $adg_user"
      echo "  Пароль: $adg_pass"
    } > /root/adguard-credentials.txt 2>/dev/null || true
    chmod 600 /root/adguard-credentials.txt 2>/dev/null || true
  fi

  # СЕРТ для AdGuard: приоритет — серт, вписанный в x-ui (в т.ч. из меню x-ui),
  # затем subDomain/wildcard через cert_paths; без всего — самоподписанный fallback.
  local _adg_cert="" _adg_key="" _adg_cp="" _adg_dom="" _adg_pline=""
  _adg_pline=$(panel_cert_from_db) || true
  if [[ -n "$_adg_pline" ]]; then
    _adg_cert="${_adg_pline%% *}"; _adg_key=$(echo "$_adg_pline" | awk '{print $2}')
  else
    _adg_dom=$(xui_get subDomain 2>/dev/null || true)
    [[ -n "$_adg_dom" ]] && _adg_cp=$(cert_paths "$_adg_dom" 2>/dev/null || true)
    if [[ -z "$_adg_cp" && -f "$WILDCARD_STATE" ]]; then
      _adg_dom=$(head -n 1 "$WILDCARD_STATE" 2>/dev/null | tr -d '[:space:]')
      [[ -n "$_adg_dom" ]] && _adg_cp=$(cert_paths "adg.$_adg_dom" 2>/dev/null || true)
    fi
    [[ -n "$_adg_cp" ]] && { _adg_cert="${_adg_cp%% *}"; _adg_key="${_adg_cp##* }"; }
  fi

  configure_adguard_doh "" "$_adg_cert" "$_adg_key" || warn "DoH-настройка AdGuardHome.yaml не применена автоматически"

  echo
  line
  log "AdGuard Home установлен и настроен:"
  echo "   web:     127.0.0.1:$ADG_WEB_PORT (снаружи — только https://<домен-панели>/)"
  echo "   DoH:     https://<домен-панели>/dns-query"
  echo "   логин:   $adg_user"
  echo "   пароль:  $adg_pass"
  echo "   → сохранено в /root/adguard-credentials.txt"
  line

  # SNI-стек уже поднят? Сразу вешаем AdGuard за домен панели — иначе
  # nginx-правила появились бы только после перезапуска п.1 и сайт «не открывался».
  if grep -q "listen 127.0.0.1:4443" "$STACK_CONF" 2>/dev/null; then
    panel_decoy_apply adguard || warn "nginx-локация AdGuard не применилась — перезапусти п.1 «Первичная настройка»"
  fi
}
# AdGuard + DoH за nginx (v0.107.79+): plain DoH (allow_unencrypted_doh) больше
# не поддерживается — включаем в AdGuard РОДНОЙ HTTPS на 127.0.0.1:$ADG_WEB_PORT
# (web UI + /dns-query на одном порту) с wildcard/панельным сертификатом.
# nginx затем проксирует location / → https://127.0.0.1:$ADG_WEB_PORT.
#   dns.bind_hosts → 127.0.0.1 (plain DNS только для самого сервера)
# Аргументы: configure_adguard_doh [admin_pass] [cert] [key]
#   без серта — самоподписанный (nginx всё равно терминирует TLS с verify off)
configure_adguard_doh() {
  local adg_pass="${1:-}" cert="${2:-}" key="${3:-}"
  local cfg="$ADG_CONFIG"
  [[ -z "$cfg" || ! -f "$cfg" ]] && return 1

  # фактический порт из http.address конфига (дефолт ADG_WEB_PORT может врать)
  local cfg_port=""
  cfg_port=$(awk '/^http:/{f=1;next} /^[^ ]/{f=0} f && /^  address:/{n=split($2,a,":"); print a[n]; exit}' "$cfg" 2>/dev/null | tr -d '"')
  [[ -n "$cfg_port" && "$cfg_port" != "null" ]] && ADG_WEB_PORT="$cfg_port"

  # сертификат: панельный/wildcard или самоподписанный fallback
  if [[ -z "$cert" || ! -f "$cert" || -z "$key" || ! -f "$key" ]]; then
    local tdir="/etc/nginx/adguard-tls"
    mkdir -p "$tdir" 2>/dev/null || true
    if [[ ! -f "$tdir/adguard.crt" || ! -f "$tdir/adguard.key" ]]; then
      openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -keyout "$tdir/adguard.key" -out "$tdir/adguard.crt" -days 3650 -nodes \
        -subj "/CN=adguard.local" 2>/dev/null || true
    fi
    [[ -f "$tdir/adguard.crt" ]] && { cert="$tdir/adguard.crt"; key="$tdir/adguard.key"; }
  fi

  systemctl stop "$ADG_SERVICE" 2>/dev/null || true
  sleep 1
  cp "$cfg" "$cfg.bak.$(date +%s)" 2>/dev/null || true

  # dns.bind_hosts → 127.0.0.1
  awk '
    /^dns:/  { in_dns=1; print; next }
    /^[^ ]/ && !/^dns:/ { in_dns=0 }
    in_dns && /^  bind_hosts:/ {
      print "  bind_hosts:"
      print "    - 127.0.0.1"
      skip_list=1
      next
    }
    skip_list && /^    - / { next }
    skip_list && !/^    - / { skip_list=0 }
    { print }
  ' "$cfg" > "$cfg.new" && mv "$cfg.new" "$cfg"

  # plain-http (админка) уводим на соседний порт: дубликат порта с https запрещён
  local plain_port=""
  local cand=$((ADG_WEB_PORT + 1)) j
  for j in 1 2 3 4 5; do
    if ! port_in_use "$cand"; then plain_port=$cand; break; fi
    cand=$((cand + 1))
  done
  [[ -z "$plain_port" ]] && plain_port=$((ADG_WEB_PORT + 1))
  awk -v pp="$plain_port" '
    /^http:/ { f=1; print; next }
    /^[^ ]/ && !/^http:/ { f=0 }
    f && /^  address:/ { print "  address: 127.0.0.1:" pp; next }
    { print }
  ' "$cfg" > "$cfg.new" && mv "$cfg.new" "$cfg"

  # tls: → enabled + порт https = web порт (UI и DoH на одном порту, TLS на AdGuard)
  # ВАЖНО: в новых версиях (schema 34+) пути серта — certificate_path/private_key_path
  # (certificate_chain/private_key — это САМО PEM-содержимое).
  if grep -q "^tls:" "$cfg"; then
    awk -v ph="$ADG_WEB_PORT" -v sn="${ADG_SNI:-$PANEL_DOMAIN}" -v crt="$cert" -v key="$key" '
      /^tls:/ { in_tls=1; print; next }
      /^[^ ]/ && !/^tls:/ { in_tls=0 }
      in_tls && /^  enabled:/               { print "  enabled: true"; next }
      in_tls && /^  server_name:/           { print "  server_name: \"" sn "\""; next }
      in_tls && /^  force_https:/           { print "  force_https: false"; next }
      in_tls && /^  port_https:/            { print "  port_https: " ph; next }
      in_tls && /^  port_dns_over_tls:/     { print "  port_dns_over_tls: 0"; next }
      in_tls && /^  port_dns_over_quic:/    { print "  port_dns_over_quic: 0"; next }
      in_tls && /^  port_privileged_https:/ { print "  port_privileged_https: 0"; next }
      in_tls && /^  port_dnscrypt:/         { print "  port_dnscrypt: 0"; next }
      in_tls && /^  certificate_chain:/     { print "  certificate_chain: \"\""; next }
      in_tls && /^  private_key:/           { print "  private_key: \"\""; next }
      in_tls && /^  certificate_path:/      { print "  certificate_path: " crt; next }
      in_tls && /^  private_key_path:/      { print "  private_key_path: " key; next }
      { print }
    ' "$cfg" > "$cfg.new" && mv "$cfg.new" "$cfg"
    # отсутствующие ключи — вставляем после ^tls:
    local kv k
    for kv in "  enabled: true" "  port_https: $ADG_WEB_PORT" "  port_dns_over_tls: 0" "  port_dns_over_quic: 0" "  port_dnscrypt: 0" "  certificate_path: $cert" "  private_key_path: $key"; do
      k="${kv%%:*}"
      grep -q "^${k}:" "$cfg" || sed -i "s/^tls:/tls:\n${kv}/" "$cfg"
    done
  else
    {
      echo ""
      echo "tls:"
      echo "  enabled: true"
      echo "  server_name: \"${ADG_SNI:-$PANEL_DOMAIN}\""
      echo "  force_https: false"
      echo "  port_https: $ADG_WEB_PORT"
      echo "  port_dns_over_tls: 0"
      echo "  port_dns_over_quic: 0"
      echo "  port_dnscrypt: 0"
      echo "  certificate_path: $cert"
      echo "  private_key_path: $key"
    } >> "$cfg"
  fi

  systemctl start "$ADG_SERVICE" 2>/dev/null || true
  sleep 3
  if ! ss -tlnH "sport = :$ADG_WEB_PORT" 2>/dev/null | grep -q .; then
    warn "AdGuard не поднялся на 127.0.0.1:$ADG_WEB_PORT"
    return 1
  fi
  # DoH должен отвечать по https (403/200/4xx от хендлера, НЕ 404)
  local code=""
  code=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 8 \
    -H "accept: application/dns-message" \
    "https://127.0.0.1:$ADG_WEB_PORT/dns-query?dns=q80BAAABAAAAAAAAA3d3dwZnb29nbGUDY29tAAABAAE" 2>/dev/null) || true
  if [[ "$code" == "404" ]]; then
    warn "DoH /dns-query не отвечает (HTTP $code)"
    return 1
  fi
  log "AdGuard: https://127.0.0.1:$ADG_WEB_PORT (UI+DoH, TLS на AdGuard) · plain http 127.0.0.1:$plain_port · DNS=127.0.0.1:53 · DoH /dns-query: HTTP $code"
  return 0
}

# AdGuard на ОТДЕЛЬНОМ SNI-домене (adguard.<база панели>): серт (точный или
# wildcard), родной TLS AdGuard на 127.0.0.1:3002, маршрут SNI-роутера
# <домен> → agh_backend. UI + DoH живут на своём домене, панель — на своём корне.
adg_setup_sni_domain() {
  local dom="$1"
  [[ -z "$dom" ]] && return 1
  if [[ "$ADG_PRESENT" != true || -z "$ADG_SERVICE" ]]; then
    warn "AdGuard не установлен — отдельный домен $dom пропущен"
    return 1
  fi
  log "AdGuard → отдельный домен $dom: серт + TLS + SNI-маршрут…"
  cert_issue "$dom" || warn "серт $dom НЕ выпущен — проверь DNS; после выпуска перезапусти п.1 (или таймер самолечения доделает)"
  local cline cert="" key=""
  cline=$(cert_lineage_for "$dom")
  if [[ -n "$cline" ]]; then
    cert="${cline%% *}"; key="${cline##* }"
  else
    cert="/etc/letsencrypt/live/$dom/fullchain.pem"; key="/etc/letsencrypt/live/$dom/privkey.pem"
  fi
  ADG_WEB_PORT=3002
  port_in_use "$ADG_WEB_PORT" && ADG_WEB_PORT=13002
  ADG_SNI="$dom"
  configure_adguard_doh "" "$cert" "$key" || warn "TLS AdGuard для $dom не применился (смотри yaml)"
  sni_upstream_add agh_backend "$ADG_WEB_PORT"
  sni_map_add "$dom" "agh_backend"
  SNI_USED["$dom"]="agh_backend"
  nginx -t >/dev/null 2>&1 && nginx_reload || true
  log "AdGuard: https://$dom/ (UI + DoH /dns-query) — через SNI-роутер на 443"
  return 0
}

# Применить decoy/прокси КОРНЯ домена панели к УЖЕ существующему 4443-блоку
# (без перегенерации stack.conf): adguard | stub | tpl:ИМЯ.
# Нужна, чтобы AdGuard, установленный ПОСЛЕ первичной настройки, сразу
# открывался по домену панели — а не «после перезапуска п.1».
panel_decoy_apply() {
  local mode="$1" custom_path="${2:-}"
  [[ -f "$STACK_CONF" ]] || return 1
  grep -q "listen 127.0.0.1:4443" "$STACK_CONF" 2>/dev/null || return 1
  local adg_port=""
  adg_port=$(adg_config_port 2>/dev/null || true)
  [[ -z "$adg_port" ]] && adg_port="${ADG_WEB_PORT:-3000}"
  PD_MODE="$mode" PD_PORT="$adg_port" PD_DIR="$PANEL_DECOY_DIR" PD_CUSTOM="$custom_path" python3 - "$STACK_CONF" <<'PYPDA'
import sys, os
mode, adg_port, pdir = os.environ["PD_MODE"], os.environ["PD_PORT"], os.environ["PD_DIR"]
custom = os.environ.get("PD_CUSTOM", "")
path = sys.argv[1]
src = open(path).read()
if mode == "custom" and custom:
    block = (
        "    location / {\n"
        f"        root {custom};\n"
        "        try_files $uri $uri/ /index.html;\n"
        "    }"
    )
elif mode == "adguard":
    block = (
        "    location / {\n"
        f"        proxy_pass https://127.0.0.1:{adg_port};\n"
        "        proxy_ssl_verify off;\n"
        "        proxy_http_version 1.1;\n"
        "        proxy_set_header Host $host;\n"
        "        proxy_set_header X-Real-IP $remote_addr;\n"
        "        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n"
        "        proxy_set_header X-Forwarded-Proto https;\n"
        "        proxy_set_header Upgrade $http_upgrade;\n"
        '        proxy_set_header Connection "upgrade";\n'
        "        proxy_read_timeout 86400;\n"
        "    }"
    )
else:
    block = (
        "    location / {\n"
        f"        root {pdir};\n"
        "        try_files /index.html =404;\n"
        "    }"
    )
lines = src.split("\n")
out, i, done, in4443 = [], 0, False, False
while i < len(lines):
    l = lines[i]
    if "listen 127.0.0.1:4443" in l:
        in4443 = True
    if in4443 and l.strip().startswith("location / {"):
        j = i
        while j < len(lines) and lines[j].rstrip() != "    }":
            j += 1
        out.append(block)
        done = True
        i = j + 1
        continue
    out.append(l)
    i += 1
if not done:
    sys.exit(1)
open(path, "w").write("\n".join(out))
PYPDA
  local rc=$?
  if [[ $rc -eq 0 ]]; then
    if nginx -t >/dev/null 2>&1; then
      nginx_reload || true
      log "Корень домена панели → $mode (nginx перезагружен)"
    else
      err "nginx -t не прошёл после смены корня панели:"
      nginx -t 2>&1 | tail -4 | sed 's/^/    /'
    fi
  fi
  return $rc
}

configure_adguard_local() {
  local cfg="$ADG_CONFIG"
  [[ -z "$cfg" || ! -f "$cfg" ]] && return 1
  systemctl stop "$ADG_SERVICE" 2>/dev/null || true
  sleep 1
  cp "$cfg" "$cfg.bak.$(date +%s)" 2>/dev/null || true
  awk -v web="  address: 127.0.0.1:$ADG_WEB_PORT" '
    /^http:/ { in_http=1; print; next }
    /^[^ ]/ && !/^http:/ { in_http=0 }
    in_http && /^  address:/ { print web; next }
    { print }
  ' "$cfg" > "$cfg.new" && mv "$cfg.new" "$cfg"
  systemctl start "$ADG_SERVICE" 2>/dev/null || true
  sleep 2
  ss -tlnH "sport = :$ADG_WEB_PORT" 2>/dev/null | grep -q . && { log "AdGuard слушает 127.0.0.1:$ADG_WEB_PORT"; return 0; }
  warn "AdGuard не поднялся на $ADG_WEB_PORT"
  return 1
}

decoy_panel_choose() {
  local __result="$1"
  local no_adg="${2:-}"   # "1" = вариант adguard недоступен (пользователь отказался от настройки за панелью)
  echo
  echo -e "${B}Decoy для панели (что показывать по корню домена панели):${N}"
  echo "  1) stub     — стандартная заглушка nginx"
  if [[ "$no_adg" != "1" ]]; then
    echo "  2) adguard  — AdGuard Home web UI + DoH через домен панели"
  fi
  echo "  3) шаблон   — decoy-заглушка из каталога (corporate, blog, docs, cloudflare, login-страницы...)"
  if [[ "$no_adg" != "1" ]]; then
    echo "  4) adguard+ — AdGuard на ОТДЕЛЬНОМ SNI-домене (adguard.<база панели>)"
  fi
  echo
  if [[ "$no_adg" != "1" && "$ADG_PRESENT" != true ]]; then
    warn "AdGuard Home не установлен — варианты 2 и 4 потребуют установки."
  fi
  if [[ "$no_adg" == "1" ]]; then
    warn "Настройка AdGuard за панелью отклонена — доступен stub или шаблон."
  fi
  echo
  local choice=""
  if [[ "$no_adg" == "1" ]]; then
    ask choice "Выбор" "1" '^[13]$'
  else
    ask choice "Выбор" "1" '^[1234]$'
  fi
  if [[ "$choice" == "2" && "$ADG_PRESENT" != true ]]; then
    askyn do_install "AdGuard Home не установлен. Установить сейчас?" "y"
    if [[ "$do_install" == true ]]; then
      install_adguard_home || { warn "Не удалось — падаем на stub"; choice=1; }
    else
      choice=1
    fi
  fi
  if [[ "$choice" == "4" ]]; then
    if [[ "$ADG_PRESENT" != true ]]; then
      askyn do_install4 "AdGuard Home не установлен. Установить сейчас?" "y"
      if [[ "$do_install4" == true ]]; then
        install_adguard_home || { warn "Не удалось — падаем на stub"; choice=1; }
      else
        choice=1
      fi
    fi
    if [[ "$choice" == "4" ]]; then
      printf -v "$__result" '%s' "adguard-sni"
      return 0
    fi
  fi
  if [[ "$choice" == "3" ]]; then
    local tpl=""
    decoy_template_choose tpl "Decoy-шаблон для панели" "corporate"
    printf -v "$__result" '%s' "tpl:$tpl"
    return 0
  fi
  [[ "$choice" == "2" ]] && printf -v "$__result" '%s' "adguard" || printf -v "$__result" '%s' "stub"
}

panel_decoy_stub_init() {
  mkdir -p "$PANEL_DECOY_DIR" 2>/dev/null || true
  cat > "$PANEL_DECOY_DIR/index.html" <<'HTML'
<!doctype html><html><head><meta charset="utf-8"><title>Welcome to nginx!</title>
<style>body{font-family:sans-serif;background:#f4f4f4;text-align:center;padding-top:80px;color:#333}
h1{color:#2b6cb0}p{color:#666}</style></head>
<body><h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and working.</p></body></html>
HTML
  chown -R www-data:www-data "$PANEL_DECOY_DIR" 2>/dev/null || true
}

# =====================================================================
# УСТАНОВКА ПАНЕЛИ
# =====================================================================
# СЕРТ, ВПИСАННЫЙ В НАСТРОЙКИ x-ui (в т.ч. выпущенный через меню x-ui: x-ui setting
# -webCert/-webCertKey или acme-модулем панели). Скрипт СЧИТЫВАЕТ его и пользуется им,
# ничего не перевыпуская. Печатает "<cert> <key> [domain]"; код 1 — живого серта нет.
panel_cert_from_db() {
  [[ -z "$XUI_DB" || ! -f "$XUI_DB" ]] && return 1
  local c k d end
  c=$(xui_get webCertFile)
  k=$(xui_get webKeyFile)
  d=$(xui_get webDomain)
  [[ -z "$c" || ! -f "$c" ]] && return 1
  [[ -z "$k" || ! -f "$k" ]] && k=$(xui_get subKeyFile)
  [[ -z "$k" || ! -f "$k" ]] && return 1
  openssl x509 -noout -in "$c" >/dev/null 2>&1 || return 1
  end=$(openssl x509 -noout -enddate -in "$c" 2>/dev/null | cut -d= -f2)
  [[ -z "$end" ]] && return 1
  [[ $(date -d "$end" +%s 2>/dev/null || echo 0) -lt $(date +%s) ]] && return 1
  # домен: webDomain → subDomain → SAN/CN самого серта (x-ui меню могло не вписать домен)
  [[ -z "$d" ]] && d=$(xui_get subDomain)
  if [[ -z "$d" ]]; then
    d=$(openssl x509 -noout -ext subjectAltName -in "$c" 2>/dev/null \
        | grep -oE 'DNS:[^,]+' | head -1 | sed 's/DNS://; s/^\*\.//')
    [[ -z "$d" ]] && d=$(openssl x509 -noout -subject -in "$c" 2>/dev/null \
        | grep -oE 'CN ?= ?[^/,]+' | head -1 | sed 's/.*CN *= *//')
  fi
  echo "$c $k ${d}"
  return 0
}

# Автобэкап состояния стека при каждом старте: x-ui.db + nginx-конфиги.
# Держим последние 5 копий в /root/stack-backups/auto-*
auto_backup_stack() {
  local bd="/root/stack-backups/auto-$(date +%Y%m%d-%H%M%S)"
  local saved=false
  mkdir -p "$bd" 2>/dev/null || return 0
  [[ -f "$XUI_DB" ]] && { cp -a "$XUI_DB" "$bd/" 2>/dev/null && saved=true; }
  for f in /etc/nginx/sites-available/stack.conf /etc/nginx/sites-enabled/stack.conf \
           /etc/nginx/streams-enabled/sni-router.conf /etc/nginx/streams-available/sni-router.conf; do
    [[ -f "$f" ]] && cp -a "$f" "$bd/" 2>/dev/null && saved=true
  done
  [[ "$saved" == true ]] || { rmdir "$bd" 2>/dev/null; return 0; }
  echo "backup-ok" > "$bd/.ok"
  # ретеншен: последние 5
  ls -1dt /root/stack-backups/auto-* 2>/dev/null | tail -n +6 | xargs -r rm -rf 2>/dev/null || true
  return 0
}

# Хелпер выпуска серта ЧЕРЕЗ МЕНЮ x-ui: acme.sh панели работает standalone на :80,
# а :80 у нас занимает nginx. Временно освобождаем ТОЛЬКО 80 (443/SNI-роутер и
# туннели продолжают работать), открываем 80 в UFW, ждём, возвращаем всё обратно
# и подхватываем новый серт панели в nginx.
xui_cert_menu_helper() {
  line; echo -e "${B}   ВЫПУСК СЕРТА ЧЕРЕЗ МЕНЮ x-ui${N}"; line
  echo "  Меню x-ui выпускает серт standalone-режимом на :80, а там висит nginx."
  echo "  Этот пункт временно освобождает :80 (443 не трогается), открывает 80 в UFW,"
  echo "  затем ждёт, пока ты выпустишь серт в панели, и восстанавливает всё обратно."
  echo
  local bak="/root/stack-backups/pre-xuicert-$(date +%Y%m%d-%H%M%S)"
  mkdir -p "$bak" 2>/dev/null || true
  cp -a /etc/nginx/sites-available/stack.conf /etc/nginx/sites-enabled/stack.conf \
        /etc/nginx/streams-enabled/sni-router.conf "$bak/" 2>/dev/null || true
  [[ -f "$XUI_DB" ]] && cp -a "$XUI_DB" "$bak/" 2>/dev/null || true

  # 1) закомментировать listen :80 во всех наших конфигах (маркер ACME80)
  local touched=()
  local f
  for f in /etc/nginx/sites-enabled/*.conf /etc/nginx/streams-enabled/*.conf /etc/nginx/sites-enabled/default; do
    [[ -f "$f" ]] || continue
    if grep -qE '^[[:space:]]*listen[[:space:]]+([^[:space:]]+:)?80[[:space:]]*;' "$f"; then
      sed -i -E 's/^([[:space:]]*listen[[:space:]]+([^[:space:]]+:)?80[[:space:]]*;)/#ACME80 \1/' "$f"
      touched+=("$f")
    fi
  done
  if [[ ${#touched[@]} -gt 0 ]]; then
    if nginx -t >/dev/null 2>&1; then
      nginx_reload || true
      log ":80 освобождён: ${touched[*]}"
    else
      local rf2
      for rf2 in "${touched[@]}"; do
        cp -a "$bak/$(basename "$rf2")" "$rf2" 2>/dev/null || sed -i 's/^#ACME80 //' "$rf2"
      done
      nginx -t >/dev/null 2>&1 && nginx_reload || true
      err "nginx -t не прошёл после правки — откат выполнен"
      return 1
    fi
  else
    log ":80 в nginx-конфигах не найден — освобождать нечего"
  fi

  # 2) UFW: открыть 80 (ACME стучится извне)
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
    ufw allow 80/tcp comment "acme-temp" >/dev/null 2>&1 || true
    log "UFW: 80/tcp открыт"
  fi

  # 3) КТО выпускает: скрипт сам (acme.sh) или пользователь в панели x-ui
  local cert_mode="" cert_dom="" cert_ok=false
  ask cert_mode "Кто выпускает серт?  1) скрипт сам (acme.sh, авто)  2) я сам в панели x-ui" "1" '^[12]$'
  if [[ "$cert_mode" == "1" ]]; then
    local db_dom=""
    db_dom=$(xui_get webDomain 2>/dev/null || true)
    [[ -z "$db_dom" ]] && db_dom=$(xui_get subDomain 2>/dev/null || true)
    ask cert_dom "Домен для сертификата" "${db_dom:-panel.example.com}" '^[a-zA-Z0-9.-]+$'
    [[ -z "$cert_dom" ]] && { err "Домен не указан"; return 1; }
    # acme.sh установлен вместе с x-ui; если нет — ставим
    if [[ ! -x ~/.acme.sh/acme.sh ]]; then
      log "acme.sh не найден — устанавливаю…"
      curl -s https://get.acme.sh | sh >/dev/null 2>&1 || true
      [[ -x ~/.acme.sh/acme.sh ]] || { err "acme.sh не установился"; return 1; }
    fi
    log "Выпуск через acme.sh (standalone, :80): $cert_dom"
    ~/.acme.sh/acme.sh --set-default-ca --server letsencrypt --force >/dev/null 2>&1 || true
    if ~/.acme.sh/acme.sh --issue -d "$cert_dom" --standalone --httpport 80 --force; then
      local cdir="/etc/letsencrypt/live/$cert_dom"
      mkdir -p "$cdir"
      ~/.acme.sh/acme.sh --installcert --force -d "$cert_dom" \
        --key-file "$cdir/privkey.pem" \
        --fullchain-file "$cdir/fullchain.pem" \
        --reloadcmd "true" >/dev/null 2>&1 || true
      if [[ -f "$cdir/fullchain.pem" && -f "$cdir/privkey.pem" ]]; then
        # вписать серт в настройки панели (x-ui прочитает при рестарте)
        xui_set_setting webDomain   "$cert_dom"
        xui_set_setting webCertFile "$cdir/fullchain.pem"
        xui_set_setting webKeyFile  "$cdir/privkey.pem"
        xui_set_setting subCertFile "$cdir/fullchain.pem"
        xui_set_setting subKeyFile  "$cdir/privkey.pem"
        xui_set_setting subDomain   "$cert_dom"
        xui_set_setting subURI      "$(suburi_build "$cert_dom")"
        systemctl restart x-ui 2>/dev/null || true
        cert_ok=true
        log "Серт выпущен и вписан в панель: $cdir"
      else
        err "installcert не создал файлы в $cdir"
      fi
    else
      err "acme.sh не смог выпустить серт (домен резолвится на этот сервер? 80 открыт выше)"
    fi
  else
    warn "СЕЙЧАС: зайди в панель (или CLI x-ui) → SSL-сертификат → получить серт (порт 80)."
    warn "По завершении (успех или ошибка — неважно) вернись сюда и нажми Enter."
    read -rp "  Enter для восстановления :80 … " _r || _r=""
  fi

  # 3) вернуть listen :80
  local rf
  for rf in /etc/nginx/sites-enabled/*.conf /etc/nginx/streams-enabled/*.conf /etc/nginx/sites-enabled/default; do
    [[ -f "$rf" ]] || continue
    grep -q '^#ACME80 ' "$rf" && sed -i 's/^#ACME80 //' "$rf"
  done
  nginx -t >/dev/null 2>&1 && nginx_reload || warn "nginx -t: проверь конфиг вручную"
  # 4) UFW закрыть обратно
  command -v ufw >/dev/null 2>&1 && ufw delete allow 80/tcp >/dev/null 2>&1 || true
  log "UFW: 80/tcp закрыт обратно"
  nginx_reload >/dev/null 2>&1 || true

  # 5) подхватить новый серт панели в nginx (если панель его вписала)
  local pline="" pcert pkey
  pline=$(panel_cert_from_db) || true
  if [[ -n "$pline" && -f /etc/nginx/sites-available/stack.conf ]]; then
    pcert="${pline%% *}"; pkey=$(echo "$pline" | awk '{print $2}')
    local old_cert
    old_cert=$(awk '/# >>> panel/,/# <<< panel/ {if (/ssl_certificate /) print $2}' /etc/nginx/sites-available/stack.conf | head -1)
    if [[ -n "$old_cert" && "$old_cert" != "$pcert" ]]; then
      sed -i "s|$old_cert|$pcert|g; $(echo "$old_cert" | sed 's|fullchain|privkey|')|$pkey|g" /etc/nginx/sites-available/stack.conf
      nginx_reload >/dev/null 2>&1 || true
      log "Новый серт панели вписан в nginx: $pcert"
    else
      log "Серт панели уже актуален в nginx"
    fi
    log "Панель: ${pline##* } → $pcert (действует до: $(openssl x509 -noout -enddate -in "$pcert" 2>/dev/null | cut -d= -f2))"
  else
    warn "Панель не вписала серт в настройки — при следующем п.1 он будет подхвачен автоматически"
  fi
  log "Готово. Бэкап конфигов: $bak"
}

# =====================================================================
# ДОМЕН + СЕРТИФИКАТ ПАНЕЛИ СРАЗУ ПОСЛЕ ЧИСТОЙ УСТАНОВКИ
# =====================================================================
setup_panel_cert_domain() {
  [[ -z "$XUI_DB" || ! -f "$XUI_DB" ]] && { err "x-ui.db не найден"; return 1; }

  # уже настроено — не трогаем, но серт подписок приводим к панельному
  local cur_dom="" cur_cert="" cur_subcert="" cur_key="" cur_end=""
  cur_dom=$(xui_get webDomain); cur_cert=$(xui_get webCertFile); cur_subcert=$(xui_get subCertFile)
  if [[ -n "$cur_cert" && -f "$cur_cert" ]] && openssl x509 -noout -in "$cur_cert" >/dev/null 2>&1; then
    # СЕРТ УЖЕ ЕСТЬ (в т.ч. выпущенный через меню x-ui) — считываем и пользуемся им
    cur_end=$(openssl x509 -noout -enddate -in "$cur_cert" 2>/dev/null | cut -d= -f2)
    if [[ -z "$cur_dom" ]]; then
      # x-ui меню могло вписать серт без домена — восстанавливаем из SAN/CN
      cur_dom=$(openssl x509 -noout -ext subjectAltName -in "$cur_cert" 2>/dev/null \
          | grep -oE 'DNS:[^,]+' | head -1 | sed 's/DNS://; s/^\*\.//')
      [[ -z "$cur_dom" ]] && cur_dom=$(openssl x509 -noout -subject -in "$cur_cert" 2>/dev/null \
          | grep -oE 'CN ?= ?[^/,]+' | head -1 | sed 's/.*CN *= *//')
      if [[ -n "$cur_dom" ]]; then
        xui_set_setting webDomain "$cur_dom"
        xui_set_setting subDomain "$cur_dom"
        xui_set_setting subURI "$(suburi_build "$cur_dom")"
        log "Домен панели восстановлен из серта: $cur_dom (вписан в webDomain/subDomain)"
      fi
    fi
    log "Считан серт панели из настроек x-ui: ${cur_dom:-домен не определён} → $cur_cert"
    [[ -n "$cur_end" ]] && log "  действует до: $cur_end"
    cur_key=$(xui_get webKeyFile)
    # ПАНЕЛЬ: пути серта должны указывать в /etc/letsencrypt/live/ (единое место)
    if [[ "$cur_cert" != /etc/letsencrypt/live/* && -n "$cur_dom" ]]; then
      local mline=""
      mline=$(cert_mirror_to_certroot "$(dirname "$cur_cert")" "$cur_dom" 2>/dev/null || true)
      if [[ -n "$mline" ]]; then
        xui_set_setting webCertFile "${mline%% *}"
        xui_set_setting webKeyFile  "${mline##* }"
        xui_set_setting subCertFile "${mline%% *}"
        xui_set_setting subKeyFile  "${mline##* }"
        systemctl restart x-ui 2>/dev/null || true
        log "Серт панели перепривязан на ${mline%% *} (единое место live/)"
      fi
    fi
    if [[ -z "$cur_subcert" || "$cur_subcert" != "$cur_cert" || ! -f "$cur_subcert" ]]; then
      warn "subCertFile ($cur_subcert) ≠ панельному — заменяю на $cur_cert"
      xui_set_setting subCertFile "$cur_cert"
      xui_set_setting subKeyFile  "$cur_key"
      systemctl restart x-ui 2>/dev/null || true
      log "subCertFile/subKeyFile обновлены: $cur_cert"
    fi
    PANEL_DOMAIN="${PANEL_DOMAIN:-$cur_dom}"
    return 0
  fi

  echo; echo -e "${B}   ДОМЕН И СЕРТИФИКАТ ПАНЕЛИ${N}"
  local pdomain="${PANEL_DOMAIN:-}"
  if [[ -z "$pdomain" ]]; then
    ask pdomain "Домен панели (A-запись → этот сервер)" "panel.example.com" '^[a-zA-Z0-9.-]+$'
  fi
  [[ -z "$pdomain" ]] && { warn "Домен не указан — панель остаётся на самоподписанном сертификате"; return 1; }

  cert_issue "$pdomain" || { err "Сертификат $pdomain не выпущен"; return 1; }
  local cp_line="" pc="" pk=""
  cp_line=$(cert_paths "$pdomain") || true
  [[ -z "$cp_line" ]] && { err "cert_paths пуст для $pdomain"; return 1; }
  pc="${cp_line%% *}"; pk="${cp_line##* }"
  # пути панели — из /etc/letsencrypt/live/ (единое место)
  local mline=""
  mline=$(cert_mirror_to_certroot "$(dirname "$pc")" "$pdomain" 2>/dev/null || true)
  [[ -n "$mline" ]] && { pc="${mline%% *}"; pk="${mline##* }"; }

  xui_set_setting webDomain   "$pdomain"
  xui_set_setting webCertFile "$pc"
  xui_set_setting webKeyFile  "$pk"
  xui_set_setting subCertFile "$pc"
  xui_set_setting subKeyFile  "$pk"
  xui_set_setting subDomain   "$pdomain"
  # URL обратного прокси для подписок: иначе share-ссылки получают порт панели
  xui_set_setting subURI      "$(suburi_build "$pdomain")"

  systemctl restart x-ui 2>/dev/null || true
  sleep 2
  local chk=""
  chk=$(xui_get webCertFile)
  if [[ "$chk" == "$pc" ]]; then
    log "Панель: домен $pdomain + сертификат вписаны в настройки"
    PANEL_DOMAIN="$pdomain"
    SNI_USED["$pdomain"]="${SNI_USED[$pdomain]:-panel_backend}"
    return 0
  fi
  err "webCertFile не применился (chk='$chk')"
  return 1
}

install_lucx_panel() {
  line; echo -e "${B}   УСТАНОВКА ПАНЕЛИ LUCX UI${N}"; line
  detect_env
  [[ -n "$XUI_DB" && -f "$XUI_DB" ]] && { log "Панель уже установлена: $XUI_DB"; return 0; }
  warn "x-ui.db не найден — устанавливаю LucX UI (вопрос задаётся один раз, в начале скрипта)."

  local tmp_sh rc
  tmp_sh=$(mktemp /tmp/lucx-install.XXXXXX.sh 2>/dev/null) || { err "mktemp failed"; return 1; }
  log "Скачивание установщика LucX UI..."
  if ! curl -fSL --retry 3 "$LUCX_INSTALL_URL" -o "$tmp_sh" || [[ ! -s "$tmp_sh" ]]; then
    rm -f "$tmp_sh"
    err "Не удалось скачать установщик LucX UI ($LUCX_INSTALL_URL)"; return 1
  fi
  # ЖЁСТКИЙ SKIP SSL УСТАНОВЩИКА: панель ставится БЕЗ SSL (reverse proxy = наш nginx).
  # XUI_NONINTERACTIVE=1 обязателен: только в этом режиме установщик читает
  # XUI_SSL_MODE=none и НЕ показывает меню «1..4, default 2» (в интерактиве оно
  # показывается всегда и ведёт к конфликту «порт занят 80»).
  # Все параметры передаём через env — вопросов ноль. Серт панели вписывается
  # сразу после установки (setup_panel_cert_domain) или через СЕРТИФИКАТЫ → 5.
  # пароль панели: заданный при авто-установке (U_PANEL_PASS) → интерактивный
  # вопрос (Enter — случайный) → случайный; логин — U_PANEL_USER (Enter — admin)
  local lucx_user="${U_PANEL_USER:-admin}"
  local lucx_pass="${U_PANEL_PASS:-}"
  if [[ -z "$lucx_pass" ]]; then
    lucx_pass=$(openssl rand -base64 18 2>/dev/null | tr -dc 'a-zA-Z0-9' | head -c 16)
    [[ -z "$lucx_pass" ]] && lucx_pass="LucX$(date +%s)"
    if [[ -t 0 ]]; then
      ask lucx_pass "Пароль панели admin (Enter — случайный)" "$lucx_pass" '^.{6,}$'
    fi
  fi
  lucx_port=$(make_port)
  lucx_wbp=$(gen_random_string 12)
  log "Запуск установщика LucX UI (XUI_NONINTERACTIVE=1 + XUI_SSL_MODE=none — без вопросов и без SSL)..."
  XUI_NONINTERACTIVE=1 XUI_SSL_MODE=none XUI_DB_TYPE=sqlite \
    XUI_USERNAME="$lucx_user" XUI_PASSWORD="$lucx_pass" \
    XUI_PANEL_PORT="$lucx_port" XUI_WEB_BASE_PATH="$lucx_wbp" \
    bash "$tmp_sh"
  rc=$?
  rm -f "$tmp_sh"

  # креды панели — фиксируем (установщик в неинтерактиве берёт их из env)
  {
    echo "LucX UI панель — $(date '+%F %T')"
    echo "  Логин:  $lucx_user"
    echo "  Пароль: $lucx_pass"
  } > /root/panel-credentials.txt 2>/dev/null || true
  chmod 600 /root/panel-credentials.txt 2>/dev/null || true
  # запомнить финальные креды глобально — авто-поток не спрашивает второй раз
  U_PANEL_PASS="$lucx_pass"
  U_PANEL_USER="$lucx_user"

  if [[ $rc -ne 0 ]]; then
    err "Ошибка установки LucX UI"; return 1
  fi
  detect_env
  if [[ -n "$XUI_DB" && -f "$XUI_DB" ]]; then
    log "Панель установлена: $XUI_DB"
    # ЧИСТАЯ установка: старые SNI-записи панели/decoy/AdGuard недействительны
    # (новые порты/пути). Сносим sni-роутер и stack.conf — п.1 создаст заново.
    rm -f /etc/nginx/streams-enabled/sni-router.conf 2>/dev/null || true
    rm -f /etc/nginx/sites-enabled/stack.conf /etc/nginx/sites-available/stack.conf 2>/dev/null || true
    nginx -t >/dev/null 2>&1 && nginx_reload || true
    log "Старые SNI-записи панели/AdGuard очищены (п.1 создаст новые)"
    # nginx ставится зависимостью и может быть без автозапуска — стек обязан подниматься после ребра
    systemctl enable nginx >/dev/null 2>&1 || true
    # СРАЗУ после чистой установки: домен + настоящий сертификат панели
    setup_panel_cert_domain || warn "Домен/сертификат панели можно задать позже (п.1)"
    return 0
  fi
  err "Установка прошла, но x-ui.db не найден"; return 1
}

# =====================================================================
# ГЕНЕРАТОРЫ
# =====================================================================
gen_uuid() { cat /proc/sys/kernel/random/uuid 2>/dev/null || openssl rand -hex 16; }
gen_hex()  { openssl rand -hex "$1" 2>/dev/null || head -c "$1" /dev/urandom | xxd -p | head -c "$(( $1 * 2 ))"; }
gen_b64()  { openssl rand -base64 24 2>/dev/null | tr -d '/+=' | head -c 22; }
sql_escape() { echo "${1//\'/\'\'}"; }

gen_reality_keys() {
  local out="" priv="" pub=""
  if [[ -n "$XRAY_BIN" && -x "$XRAY_BIN" ]]; then
    out=$("$XRAY_BIN" x25519 2>/dev/null || true)
    priv=$(echo "$out" | grep -iE 'private' | awk '{print $NF}' | head -1)
    pub=$(echo "$out"  | grep -iE 'public'  | awk '{print $NF}' | head -1)
  fi
  if [[ -z "$priv" || -z "$pub" ]]; then
    priv=$(openssl rand -base64 32 | tr -d '/+=' | head -c 43)
    pub=$(openssl rand -base64 32 | tr -d '/+=' | head -c 43)
    warn "  xray не найден — Reality-ключи сгенерированы openssl и НЕВАЛИДНЫ! Установите панель (п.14), затем пересоздайте инбаунд."
  fi
  echo "$priv|$pub"
}

# =====================================================================
# СОЗДАНИЕ ИНБАУНДОВ
# =====================================================================
inbounds_columns() {
  sqlite3 "$XUI_DB" "PRAGMA table_info(inbounds);" 2>/dev/null \
    | awk -F'|' '{print $2}' | tr '\n' ' '
}

create_inbound_db() {
  local proto="$1" transport="$2" security="$3" flow="$4" port="$5" remark="$6"
  local net="$7"            # tcp / udp
  local sn="${8:-}"         # SNI-домен (подтягивается в serverNames/serverName)
  local vk="${9:-}"         # VK call hashes (только qwdtt/csqtt, через запятую)
  local cemail="${10:-}"    # имя клиента (email); пусто → безликий user
  local cert="" key=""
  if [[ -n "$sn" ]]; then
    local cp_line=""
    cp_line=$(cert_paths "$sn") || true     # wildcard- или персональный сертификат
    [[ -n "$cp_line" ]] && { cert="${cp_line%% *}"; key="${cp_line##* }"; }
  fi
  # xray-hysteria НЕ стартует без TLS ("tls config is nil"). Self-signed убран —
  # браузеры/клиенты его не принимают. Нет серта на домен и на панель → инбаунд
  # не создаётся (выпусти серт и добавь заново).
  if [[ "$proto" == "hysteria" && ( -z "$cert" || -z "$key" ) ]]; then
    local fdom="${PANEL_DOMAIN:-$(xui_get webDomain 2>/dev/null || true)}"
    local fline=""
    [[ -n "$fdom" ]] && fline=$(cert_paths "$fdom" 2>/dev/null || true)
    if [[ -n "$fline" ]]; then
      cert="${fline%% *}"; key="${fline##* }"
      warn "  hysteria: серт $sn не найден — использую серт $fdom (клиент: insecure=true)"
      [[ -z "$sn" ]] && sn="$fdom"
    else
      err "  hysteria: нет ни серта $sn, ни серта панели — инбаунд НЕ создан. Выпусти серт (Wildcard/Сертификаты) и добавь инбаунд заново."
      echo ""; return 1
    fi
  fi

  [[ -z "$XUI_DB" || ! -f "$XUI_DB" ]] && { err "x-ui.db не найден"; echo ""; return 1; }

  local cols
  cols=$(inbounds_columns)
  local missing=()
  local need
  for need in port protocol settings stream_settings remark enable listen sniffing; do
    grep -qw "$need" <<<"$cols" || missing+=("$need")
  done
  if [[ ${#missing[@]} -gt 0 ]]; then
    err "В таблице inbounds нет колонок: ${missing[*]}"
    echo ""; return 1
  fi

  local uuid sub_id
  uuid=$(gen_uuid)
  sub_id=$(gen_hex 8)
  local salamander="" secret32="" ip4=""
  salamander=$(gen_b64 | tr '[:upper:]' '[:lower:]')
  secret32=$(gen_hex 16)
  ip4=$(server_ip4)

  # --- settings ---
  local settings_json
  case "$proto" in
    vless)
      settings_json=$(cat <<EOF
{"clients":[],"decryption":"none","fallbacks":[]}
EOF
)
      ;;
    anytls)
      # tunnel-инбаунд LucX (internal/lucx/tunnel/anytls_inbound.go):
      # панель запускает anytls-server, пароль общий на порт
      settings_json=$(cat <<EOF
{"remark":"anytls-$port","enabled":true,"port":$port,"password":"$(gen_b64)","sni":"$sn","certFile":"$cert","keyFile":"$key"}
EOF
) ;;
    trusttunnel|trust-tunnel)
      # tunnel-инбаунд LucX (trusttunnel_inbound.go): hostname+cert обязательны,
      # клиенты → HMAC-креды из authSeed (панель покажет их и в share-ссылках)
      settings_json=$(cat <<EOF
{"remark":"trusttunnel-$port","hostname":"$sn","listen":"","ipv6":false,"certFile":"$cert","keyFile":"$key","clientDns":"1.1.1.1","upstreamProtocol":"http2","routeThroughXray":false,"routeXrayPort":0,"outboundTag":"","metricsPort":0,"listenPreset":"fast","clientRandomPrefix":"$(gen_hex 4)/ffffffff","authSeed":"$(gen_hex 32)","clients":[]}
EOF
) ;;
    naive|naiveproxy)
      # tunnel-инбаунд LucX (naive_inbound.go): caddy forward_proxy за nginx 443.
      # СЕРВИСНЫЙ логин/пароль генерируем сразу + authSeed для клиентских пар.
      settings_json=$(cat <<EOF
{"remark":"naive-$port","listen":"127.0.0.1","domain":"$sn","useAcme":false,"acmeEmail":"","certFile":"$cert","keyFile":"$key","authUser":"$(gen_hex 4)","authPass":"$(gen_b64)","enableH3":false,"probeResistance":false,"logLevel":"WARN","extraArgs":"","routeThroughXray":false,"routeXrayPort":0,"outboundTag":"","useRawConfig":false,"rawConfig":"","behindCover":false,"hideOn443":false,"authSeed":"$(gen_hex 32)","clients":[{"email":"user","enable":true}]}
EOF
) ;;
    hysteria)
      # рецепт lucx-ui-pro: hysteriaSettings v2 + salamander в finalmask
      settings_json='{"version":2,"clients":[]}' ;;
    qwdtt)
      # рецепт lucx-ui-pro: tunnel-протокол, клиенты добавляются в панели (share-only)
      settings_json=$(cat <<EOF
{"clients":[],"remark":"$remark","enabled":true,"listenAddr":"0.0.0.0:$port","wgPort":56001,"password":"$(gen_b64)","dns":"8.8.8.8","configDir":"","listenRaw":"0.0.0.0:56003","listenDirect":"","subHost":"$ip4:$port","vkHashes":"$vk","clientPort":9000,"workers":16,"routeThroughXray":true,"outboundTag":""}
EOF
) ;;
    csqtt)
      settings_json=$(cat <<EOF
{"clients":[],"remark":"$remark","enabled":true,"listenAddr":"0.0.0.0:$port","password":"$(gen_b64)","deviceId":"","webPass":"$(gen_b64)","subHost":"$ip4","vkHashes":"$vk","configDir":"","routeThroughXray":true,"outboundTag":""}
EOF
) ;;
    tproxy)
      # Telegram WEB-proxy LucX: слушает 127.0.0.1:11443, наружу через nginx 443
      settings_json=$(cat <<EOF
{"clients":[],"port":11443,"hostname":"$sn","secret":"$secret32","siteSource":"dir","siteDir":"/var/www/html","siteUpstream":"","carrierMode":"https","certFile":"$cert","keyFile":"$key","externalTLS":false,"behindCover":false,"routeThroughXray":false,"outboundTag":"","routeXrayPort":0}
EOF
) ;;
    awg|amneziawg|wireguard)
      settings_json="{\"secretKey\":\"$(openssl rand -base64 32 | tr -d '/+=' | head -c 43)\",\"address\":[\"10.8.1.1/24\"],\"peers\":[{\"publicKey\":\"$(openssl rand -base64 32 | tr -d '/+=' | head -c 43)\",\"allowedIPs\":[\"0.0.0.0/0\"]}],\"mtu\":1280}" ;;
    *)
      settings_json="{\"clients\":[{\"id\":\"$uuid\",\"email\":\"user@$port\",\"enable\":true}]}" ;;
  esac

  # --- stream_settings ---
  local stream_json
  case "$transport" in
    tcp)
      if [[ "$security" == "reality" ]]; then
        local keys priv pub short_id
        keys=$(gen_reality_keys); priv="${keys%%|*}"; pub="${keys##*|}"
        short_id=$(gen_hex 8)
        local sn_show=""
        if [[ -n "${REALITY_EXT_TARGET:-}" ]]; then
          sn_show="$REALITY_EXT_TARGET"   # выбранный пользователем/авто таргет
        else
          sn_show=$(reality_find_target "${id:-0}")
        fi
        [[ -n "$sn" ]] && sn_show="$sn"
        local dest_show="$sn_show:443"
        [[ -n "$sn" ]] && dest_show="127.0.0.1:4444"   # локальный decoy; точный порт проставит configure_sni_for_inbound
        stream_json=$(cat <<EOF
{"network":"tcp","security":"reality","realitySettings":{"show":false,"xver":0,"dest":"$dest_show","target":"$dest_show","serverNames":["$sn_show"],"privateKey":"$priv","shortIds":["$short_id"],"settings":{"publicKey":"$pub","fingerprint":"firefox","serverName":"","spiderX":"/"},"fingerprint":"firefox"},"tcpSettings":{"acceptProxyProtocol":false,"header":{"type":"none"}}}
EOF
)
      elif [[ "$security" == "tls" ]]; then
        if [[ -n "$cert" && -n "$key" ]]; then
          stream_json="{\"network\":\"tcp\",\"security\":\"tls\",\"tlsSettings\":{\"serverName\":\"$sn\",\"minVersion\":\"1.2\",\"certificates\":[{\"certificateFile\":\"$cert\",\"keyFile\":\"$key\"}]},\"tcpSettings\":{\"acceptProxyProtocol\":false,\"header\":{\"type\":\"none\"}}}"
        else
          stream_json="{\"network\":\"tcp\",\"security\":\"tls\",\"tlsSettings\":{\"serverName\":\"$sn\",\"minVersion\":\"1.2\"},\"tcpSettings\":{\"acceptProxyProtocol\":false,\"header\":{\"type\":\"none\"}}}"
        fi
      else
        stream_json='{"network":"tcp","security":"none","tcpSettings":{"acceptProxyProtocol":false,"header":{"type":"none"}}}'
      fi
      ;;
    xhttp)
      if [[ "$security" == "reality" ]]; then
        local keys priv pub short_id
        keys=$(gen_reality_keys); priv="${keys%%|*}"; pub="${keys##*|}"
        short_id=$(gen_hex 8)
        local sn_show=""
        if [[ -n "${REALITY_EXT_TARGET:-}" ]]; then
          sn_show="$REALITY_EXT_TARGET"   # выбранный пользователем/авто таргет
        else
          sn_show=$(reality_find_target "${id:-0}")
        fi
        [[ -n "$sn" ]] && sn_show="$sn"
        local dest_show="$sn_show:443"
        [[ -n "$sn" ]] && dest_show="127.0.0.1:4444"   # локальный decoy; точный порт проставит configure_sni_for_inbound
        stream_json=$(cat <<EOF
{"network":"xhttp","security":"reality","realitySettings":{"show":false,"xver":0,"dest":"$dest_show","target":"$dest_show","serverNames":["$sn_show"],"privateKey":"$priv","shortIds":["$short_id"],"settings":{"publicKey":"$pub","fingerprint":"firefox","serverName":"","spiderX":"/"},"fingerprint":"firefox"},"xhttpSettings":{"path":"/$(gen_hex 6)","host":"","mode":"auto"}}
EOF
)
      else
        stream_json="{\"network\":\"xhttp\",\"security\":\"none\",\"xhttpSettings\":{\"path\":\"/$(gen_hex 6)\",\"host\":\"\",\"mode\":\"auto\"}}"
      fi
      ;;
    hysteria)
      # рецепт lucx-ui-pro: TLS + hysteriaSettings + salamander в finalmask
      if [[ -n "$cert" && -n "$key" ]]; then
        stream_json=$(cat <<EOF
{"network":"hysteria","security":"tls","hysteriaSettings":{"version":2,"udpIdleTimeout":60},"tlsSettings":{"serverName":"$sn","minVersion":"1.2","maxVersion":"1.3","cipherSuites":"","rejectUnknownSni":false,"disableSystemRoot":false,"enableSessionResumption":false,"alpn":["h3"],"certificates":[{"useFile":true,"certificateFile":"$cert","keyFile":"$key","certificate":[],"key":[],"ocspStapling":0,"oneTimeLoading":false,"usage":"encipherment","buildChain":false}],"settings":{"fingerprint":"firefox","echConfigList":"","pinnedPeerCertSha256":[],"verifyPeerCertByName":""}},"finalmask":{"tcp":[],"udp":[{"type":"salamander","settings":{"password":"$salamander"}}]}}
EOF
)
      else
        stream_json='{"network":"hysteria","security":"none","hysteriaSettings":{"version":2,"udpIdleTimeout":60}}'
      fi
      ;;
    naive|anytls|trusttunnel|trust-tunnel)
      # tunnel-инбаунд LucX: stream не используется (конфиг живёт в settings)
      stream_json='{}'
      ;;
    qwdtt|csqtt|tproxy)
      # tunnel-протоколы LucX: БЕЗ network-блока (иначе xray падает "unknown transport")
      stream_json='{"security":"none"}'
      ;;
    udp)
      stream_json='{"network":"udp","security":"none","udpSettings":{}}'
      ;;
    *)
      stream_json='{"network":"tcp","security":"none","tcpSettings":{"acceptProxyProtocol":false,"header":{"type":"none"}}}'
      ;;
  esac

  local sniffing_json='{"enabled":true,"destOverride":["http","tls","quic"],"routeOnly":false}'
  case "$proto" in
    qwdtt|csqtt|tproxy|hysteria)
      sniffing_json='{"enabled":true,"destOverride":["http","tls","quic","fakedns"],"metadataOnly":false,"routeOnly":false}' ;;
  esac
  local listen
  case "$proto" in
    qwdtt|csqtt|hysteria) listen="" ;;          # порт живёт в settings.listenAddr
    tproxy)               listen="127.0.0.1" ;; # наружу только через nginx 443
    *) [[ "$net" == "udp" ]] && listen="0.0.0.0" || listen="127.0.0.1" ;;
  esac
  local tag_name="inbound-$port"
  case "$proto" in
    qwdtt) tag_name="inbound-qwdtt" ;;
    csqtt) tag_name="inbound-csqtt" ;;
    tproxy) tag_name="inbound-tproxy" ;;
  esac

  # --- экранируем одинарные кавычки ---
  settings_json=$(sql_escape "$settings_json")
  stream_json=$(sql_escape   "$stream_json")
  sniffing_json=$(sql_escape "$sniffing_json")
  remark=$(sql_escape "$remark")

  # --- собираем INSERT по фактической схеме ---
  local field_list="port,protocol,settings,stream_settings,remark,enable,listen,sniffing"
  local value_list="$port,'$proto','$settings_json','$stream_json','$remark',1,'$listen','$sniffing_json'"

  grep -qw user_id     <<<"$cols" && { field_list+=",user_id";     value_list+=",1"; }
  grep -qw up          <<<"$cols" && { field_list+=",up";          value_list+=",0"; }
  grep -qw down        <<<"$cols" && { field_list+=",down";        value_list+=",0"; }
  grep -qw total       <<<"$cols" && { field_list+=",total";       value_list+=",0"; }
  grep -qw expiry_time <<<"$cols" && { field_list+=",expiry_time"; value_list+=",0"; }
  grep -qw tag         <<<"$cols" && { field_list+=",tag";         value_list+=",'$tag_name'"; }
  grep -qw allocate    <<<"$cols" && { field_list+=",allocate";    value_list+=",'{}'"; }

  local err_out
  # понятная ошибка вместо SQL UNIQUE: LucX-sidecar теги (inbound-qwdtt/csqtt/tproxy)
  # фиксированы — один инбаунд такого протокола на сервер
  if sqlite3 "$XUI_DB" "SELECT 1 FROM inbounds WHERE tag='$tag_name' LIMIT 1;" 2>/dev/null | grep -q 1; then
    err "  Тег '$tag_name' уже занят (инбаунд id=$(sqlite3 "$XUI_DB" "SELECT id FROM inbounds WHERE tag='$tag_name';" 2>/dev/null)). Для sidecar-протоколов LucX допускается только один экземпляр."
    echo ""; return 1
  fi
  err_out=$(sqlite3 "$XUI_DB" "INSERT INTO inbounds ($field_list) VALUES ($value_list);" 2>&1) || {
    err "  SQL error: $err_out"
    echo ""; return 1
  }

  local new_id
  new_id=$(sqlite3 "$XUI_DB" "SELECT id FROM inbounds WHERE port=$port AND protocol='$proto' ORDER BY id DESC LIMIT 1;" 2>/dev/null || true)
  if [[ -z "$new_id" ]]; then
    err "  Инбаунд не найден после INSERT"
    echo ""; return 1
  fi

  # --- пост-действия по рецептам lucx-ui-pro ---
  # ВАЖНО: для hysteria HOSTS в панели НЕ создаются (UDP-инбаунд, подписка без hosts)
  if [[ "$proto" == "tproxy" ]]; then
    umask 077
    cat > /root/.lucx-tg-web-proxy-info <<EOF2
TG_WEB_PROXY_DOMAIN=$sn
TG_WEB_PROXY_SECRET=$secret32
EOF2
    chmod 600 /root/.lucx-tg-web-proxy-info 2>/dev/null || true
    umask 022
    ensure_tproxy_site
  fi
  if [[ "$proto" == "naive" || "$proto" == "anytls" || "$proto" == "trusttunnel" ]]; then
    # вытащить сгенерированные креды из settings — в файл пользователю
    local svc_user="" svc_pass="" anytls_pw="" seed=""
    svc_user=$(sqlite3 "$XUI_DB" "SELECT json_extract(settings,'\$.authUser') FROM inbounds WHERE id=$new_id;" 2>/dev/null || true)
    svc_pass=$(sqlite3 "$XUI_DB" "SELECT json_extract(settings,'\$.authPass') FROM inbounds WHERE id=$new_id;" 2>/dev/null || true)
    anytls_pw=$(sqlite3 "$XUI_DB" "SELECT json_extract(settings,'\$.password') FROM inbounds WHERE id=$new_id;" 2>/dev/null || true)
    seed=$(sqlite3 "$XUI_DB" "SELECT json_extract(settings,'\$.authSeed') FROM inbounds WHERE id=$new_id;" 2>/dev/null || true)
    umask 077
    {
      echo "=== $proto #$new_id (LucX tunnel) ==="
      echo "Домен (SNI): $sn"
      echo "Порт инбаунда: $port (панель слушает 127.0.0.1:$port, снаружи — https://$sn:443 через nginx)"
      if [[ "$proto" == "naive" ]]; then
        echo "Сервисный логин: $svc_user"
        echo "Сервисный пароль: $svc_pass"
        echo "URL: naive+https://$svc_user:$svc_pass@$sn:443"
        echo "Клиентские пары (HMAC от authSeed) — в панели: инбаунд naive → клиенты/share"
      elif [[ "$proto" == "anytls" ]]; then
        echo "Пароль: $anytls_pw"
        echo "URL: anytls://$anytls_pw@$sn:443/?sni=$sn (порт 443 через nginx)"
      else
        echo "Клиент: user — логин/пароль панель генерирует HMAC от authSeed,"
        echo "смотрите в панели (инбаунд trusttunnel → клиенты, tt:// ссылки)"
      fi
      echo "authSeed: $seed"
    } > "/root/.lucx-$proto-info"
    chmod 600 "/root/.lucx-$proto-info" 2>/dev/null || true
    umask 022
  fi
  case "$proto" in
    qwdtt|csqtt|tproxy) ensure_shareonly_triggers ;;
  esac

  echo "$new_id"
  return 0
}

create_inbounds_menu() {
  line; echo -e "${B}   СОЗДАНИЕ ИНБАУНДОВ${N}"; line

  [[ -z "$XUI_DB" || ! -f "$XUI_DB" ]] && { err "x-ui.db не найден"; return 1; }

  local existing=0
  existing=$(sqlite3 "$XUI_DB" "SELECT COUNT(*) FROM inbounds WHERE enable=1;" 2>/dev/null || echo 0)
  [[ "$existing" -gt 0 ]] && log "Активных инбаундов: $existing — выбирай тип нового."

  # быстрая проверка схемы
  local cols
  cols=$(inbounds_columns)
  [[ -z "$cols" ]] && { err "Не удалось получить схему inbounds"; return 1; }
  local miss=() n
  for n in port protocol settings stream_settings remark enable listen sniffing; do
    grep -qw "$n" <<<"$cols" || miss+=("$n")
  done
  [[ ${#miss[@]} -gt 0 ]] && { err "В таблице нет колонок: ${miss[*]}"; return 1; }

  echo
  echo -e "${B}Выберите инбаунды для создания:${N}"
  echo
  local i=1 entry
  local -a NAMES=()
  for entry in "${RECOMMENDED_INBOUNDS[@]}"; do
    local name="${entry%%|*}"
    printf "  %2d) %s\n" "$i" "$name"
    NAMES+=("$entry")
    i=$((i+1))
  done
  echo
  echo "  0) Отмена"
  echo
  echo "Пример: 1 2 5    (VLESS TCP Reality, VLESS XHTTP Reality, QWDTT)"
  echo "naive/anytls/trusttunnel/mtproto — создавайте в UI панели (sidecar-протоколы LucX)."
  echo

  local choices=""
  ask choices "Номера (через пробел)" "" '^[0-9 ]+$'
  [[ "$choices" == "0" || -z "$choices" ]] && return 0

  sni_used_load            # занятые SNI-домены: для проверки ДО создания инбаунда
  local panel_domain=""
  local -a used_ports=()
  local num
  for num in $choices; do
    (( num < 1 || num > ${#NAMES[@]} )) && { warn "Пропуск: $num"; continue; }
    local entry="${NAMES[$((num-1))]}"
    IFS='|' read -r name proto transport security flow net <<<"$entry"

    local port
    case "$proto" in
      tproxy) port=11443 ;;
      qwdtt)  port=56000; while port_in_use "$port"; do port=$((port+100)); done ;;
      csqtt)  port=46000; while port_in_use "$port"; do port=$((port+100)); done ;;
      *)      port=$(make_port) ;;
    esac
    local remark="${proto}-${transport}"

    # Домен панели для hosts-записи — резолвим ДО создания для ЛЮБОГО типа
    # (иначе reality/tproxy уходят с адресом-фолбэком, вплоть до IP сервера).
    if [[ -z "$panel_domain" ]]; then
      panel_domain="${PANEL_DOMAIN:-}"
      [[ -z "$panel_domain" ]] && panel_domain=$(xui_get subDomain 2>/dev/null || true)
      if [[ -z "$panel_domain" && -t 0 ]]; then
        ask panel_domain "Домен панели (адрес для hosts-записи инбаунда)" "panel.example.com" '^[a-zA-Z0-9.-]+$'
      fi
      [[ -n "$panel_domain" ]] && SNI_USED["$panel_domain"]="${SNI_USED[$panel_domain]:-panel_backend}"
    fi

    # --- Reality: свой/чужой — тот же вопрос, что и в авто-установке ---
    local rmode=""
    if [[ "$proto" == "vless" && "$security" == "reality" ]]; then
      echo
      echo "  $name:"
      echo "   1) Чужой реалити «найти цели» — за 443 по SNI цели, серт НЕ нужен"
      echo "   2) Свой SNI-домен — нужен серт + decoy"
      ask rmode "Выбор [1/2]" "1" '^[12]$'
    fi

    # --- SNI-домен/цель спрашиваем и проверяем на занятость ДО создания ---
    # Вопросы НЕ зависят от наличия SNI_CONF (создаётся/привязывается позже).
    local sni_domain="" rdtpl=""
    if [[ "$proto" == "qwdtt" || "$proto" == "csqtt" ]]; then
      sni_domain=""   # чистый UDP, SNI не нужен
    elif [[ "$proto" == "vless" && "$security" == "reality" && "$rmode" == "1" ]]; then
      # чужой реалити: живая проверка кандидатов + выбор цели (как в панели)
      local tgt=""
      reality_target_menu tgt "$name"
      REALITY_EXT_TARGET="$tgt"
      printf '%s' "$tgt" > /tmp/.reality-found-target 2>/dev/null || true
      log "  $name: цель → $tgt (dest+serverNames, за 443 по SNI цели)"
    elif [[ "$proto" == "hysteria" || "$proto" == "tproxy" || "$proto" == "naive" || "$proto" == "anytls" || "$proto" == "trusttunnel" || "$proto" == "trust-tunnel" || ( "$proto" == "vless" && "$security" == "reality" ) ]]; then
      echo
      if [[ -z "$panel_domain" ]]; then
        panel_domain="${PANEL_DOMAIN:-}"
        [[ -z "$panel_domain" ]] && panel_domain=$(xui_get subDomain)
        [[ -z "$panel_domain" ]] && ask panel_domain "Домен панели" "panel.example.com" '^[a-zA-Z0-9.-]+$'
        [[ -n "$panel_domain" ]] && SNI_USED["$panel_domain"]="${SNI_USED[$panel_domain]:-panel_backend}"
      fi
      local def2="h.example.com"
      case "$proto" in
        naive) def2="n.example.com";;
        anytls) def2="at.example.com";;
        trusttunnel|trust-tunnel) def2="tt.example.com";;
        tproxy) def2="tg.example.com";;
        vless) def2="r.example.com";;
      esac
      local d_new="" owner2=""
      while :; do
        d_new=""
        ask d_new "Домен для $name (нужен сертификат + decoy)" "$def2" '^[a-zA-Z0-9.-]+$'
        [[ -z "$d_new" ]] && continue
        if [[ "$d_new" == *.example.com ]]; then
          err "Это шаблон-плейсхолдер. Введи НАСТОЯЩИЙ домен (поддомен своего base-домена)"
          continue
        fi
        owner2=$(sni_domain_owner "$d_new" "")
        if [[ -n "$owner2" ]]; then
          err "Домен $d_new уже занят ($owner2). Укажите другой — инбаунд ещё не создан."
          continue
        fi
        break
      done
      sni_domain="$d_new"
      if [[ "$proto" == "vless" && "$security" == "reality" ]]; then
        # своя заглушка у каждого reality-инбаунда (как в авто-установке);
        # серт на decoy выпустит configure_sni_for_inbound после создания
        decoy_template_choose rdtpl "Decoy-заглушка для $name (страница на SNI-домене)" "corporate"
      elif ! cert_issue "$sni_domain"; then
        local keep=""
        askyn keep "Серт $sni_domain НЕ выпущен (DNS/ACME). Создать инбаунд всё равно? Серт можно дозапустить позже (Сертификаты → обновить)." "n"
        [[ "$keep" != true ]] && { warn "$name пропущен"; continue; }
        warn "$name создаётся БЕЗ сертификата — работать начнёт после выпуска серта"
      fi
    fi
    # (протоколы без SNI — например wireguard — создаются как есть)

    # --- Порт: запрет 443/80 + занятость (как в авто-установке) ---
    local port_ok=false
    while [[ "$port_ok" != true ]]; do
      ask port "Порт для $name (Enter — $port)" "$port" '^[0-9]{2,5}$'
      if [[ "$port" == "443" || "$port" == "80" ]]; then
        err "Порт $port занят nginx (SNI-роутер/ACME) — выбери другой"
        continue
      fi
      if [[ " ${used_ports[*]:-} " == *" $port "* ]]; then
        err "Порт $port уже назначен другому инбаунду в этой установке"
        continue
      fi
      if [[ -n "$XUI_DB" && -f "$XUI_DB" ]] && \
         [[ "$(sqlite3 "$XUI_DB" "SELECT COUNT(*) FROM inbounds WHERE port=$port;" 2>/dev/null || echo 0)" != "0" ]]; then
        err "Порт $port уже используется инбаундом в панели — выбери другой"
        continue
      fi
      port_ok=true
    done
    used_ports+=("$port")

    echo
    # Клиентов НЕ создаём (по решению пользователя) — добавляй сам в панели.
    # VK call hashes — только для qwdtt/csqtt; пусто → поле остаётся пустым
    local vk=""
    if [[ "$proto" == "qwdtt" || "$proto" == "csqtt" ]]; then
      ask vk "VK call hashes (через запятую, БЕЗ пробелов; Enter — пропустить)" "" '^[a-zA-Z0-9,_-]*$'
    fi
    log "Создаю: $name (proto=$proto, transport=$transport, sec=$security, port=$port, клиентов: 0)"
    local new_id
    new_id=$(create_inbound_db "$proto" "$transport" "$security" "$flow" "$port" "$remark" "$net" "$sni_domain" "$vk") || continue
    if [[ -n "$new_id" ]]; then
      case "$proto" in
        qwdtt|csqtt)
          log "  → id=$new_id (UDP $port). Клиенты добавляйте в панели: инбаунд → клиент (синк настроен)"
          ufwd_allow_udp 56000 56001 56003 46000
          ;;
        hysteria)
          log "  → id=$new_id (UDP $port, SNI $sni_domain)"
          SNI_USED["$sni_domain"]="hysteria_$port"
          ufwd_allow_udp "$port"
          ;;
        naive|anytls|trusttunnel|trust-tunnel)
          log "  → id=$new_id (панель запустит сервис на 127.0.0.1:$port; снаружи https://$sni_domain:443)"
          sni_upstream_add "inb_${new_id}_backend" "$port"
          sni_map_add "$sni_domain" "inb_${new_id}_backend"
          SNI_USED["$sni_domain"]="inb_${new_id}_backend"
          hosts_upsert "$new_id" "${panel_domain:-$sni_domain}" "$sni_domain"   # адрес=панель, SNI=свой домен
          nginx_reload || true
          log "  Логины/пароли: /root/.lucx-$proto-info (+ в панели у инбаунда)"
          systemctl restart x-ui >/dev/null 2>&1 || true
          ;;
        tproxy)
          log "  → id=$new_id (SNI $sni_domain → 127.0.0.1:11443)"
          sni_upstream_add "tproxy" 11443
          sni_map_add "$sni_domain" "tproxy"
          SNI_USED["$sni_domain"]="tproxy"
          hosts_upsert "$new_id" "${panel_domain:-$sni_domain}" "$sni_domain"   # адрес=панель, SNI=tg-домен
          nginx_reload || true
          log "  Секрет сохранён: /root/.lucx-tg-web-proxy-info"
          ;;
        *)
          log "  → id=$new_id, listen=$([[ "$net" == "udp" ]] && echo "0.0.0.0" || echo "127.0.0.1")"
          if [[ -n "$sni_domain" ]]; then
            SNI_USED["$sni_domain"]="inb_${new_id}_backend"
            configure_sni_for_inbound "$new_id" "$proto" "$port" "$panel_domain" "$sni_domain" "${rdtpl:-default}"
          elif [[ "$security" == "reality" ]]; then
            # доктрина «всё за 443»: чужой реалити прячем по SNI цели
            local ext_dom="${REALITY_EXT_TARGET:-$(reality_find_target "$new_id")}"
            reality_ext_hide "$new_id" "$ext_dom" "$port" || true
            systemctl restart x-ui >/dev/null 2>&1 || true
          fi
          ;;
      esac
    fi
  done

  # Перезапускаем x-ui, чтобы панель увидела новые инбаунды
  systemctl restart x-ui >/dev/null 2>&1 || true
  sleep 2


  local final
  final=$(sqlite3 "$XUI_DB" "SELECT COUNT(*) FROM inbounds WHERE enable=1;" 2>/dev/null || echo 0)
  log "Итого активных инбаундов: $final"
  return 0
}

# =====================================================================
# DECOY: СТАТИЧЕСКИЕ ШАБЛОНЫ
# =====================================================================
# записать шаблон, только если его ещё нет — повторные запуски ничего не перезаписывают
tpl_write() {
  [[ -s "$1" ]] && return 0
  cat > "$1"
}

decoy_templates_init() {
  mkdir -p "$DECOY_TPL_DIR" 2>/dev/null || true
  local sig_before; sig_before=$(dir_sig "$DECOY_TPL_DIR")

  # honeypot-ссылки: невидимы для человека, но их парсят боты → путь /admin,
  # /wp-login.php, /.env → nginx отдаёт 404 в лог decoy-access → fail2ban банит
  local honey='<a href="/admin" style="position:fixed;left:-9999px;top:-9999px" aria-hidden="true" tabindex="-1">admin</a>
<a href="/wp-login.php" style="position:fixed;left:-9999px;top:-9999px" aria-hidden="true" tabindex="-1">wp login</a>
<a href="/.env" style="position:fixed;left:-9999px;top:-9999px" aria-hidden="true" tabindex="-1">env</a>'

  tpl_write "$DECOY_TPL_DIR/default.html" <<HTML
<!doctype html><html><head><meta charset="utf-8"><title>Welcome to nginx!</title>
<style>body{font-family:sans-serif;background:#f4f4f4;text-align:center;padding-top:80px;color:#333}
h1{color:#2b6cb0}p{color:#666}</style></head>
<body><h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and working.</p>
$honey</body></html>
HTML

  tpl_write "$DECOY_TPL_DIR/blank.html" <<'HTML'
<!doctype html><html><head><meta charset="utf-8"><title> </title></head><body></body></html>
HTML

  # corporate: случайные год основания и слоган — домены не выглядят близнецами
  local cy=$(( 1998 + RANDOM % 20 ))
  local ctg; case $(( RANDOM % 3 )) in
    0) ctg="Building the future of infrastructure." ;;
    1) ctg="Reliable software for ambitious teams." ;;
    2) ctg="Engineering clarity into complex systems." ;;
  esac
  tpl_write "$DECOY_TPL_DIR/corporate.html" <<HTML
<!doctype html><html><head><meta charset="utf-8"><title>Corp — Solutions</title>
<style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:-apple-system,sans-serif;color:#111;line-height:1.6}
nav{padding:20px 40px;border-bottom:1px solid #eee;display:flex;justify-content:space-between}nav a{color:#111;text-decoration:none;margin-left:24px;font-size:14px}
.logo{font-weight:600;font-size:18px}.hero{padding:100px 40px;max-width:1100px;margin:auto}
h1{font-size:52px;font-weight:600;letter-spacing:-1px;margin-bottom:24px}p.lead{font-size:20px;color:#555;max-width:600px}
.btn{display:inline-block;margin-top:32px;padding:14px 28px;background:#111;color:#fff;text-decoration:none;border-radius:6px}
footer{padding:40px;border-top:1px solid #eee;color:#888;font-size:13px;text-align:center}</style></head><body>
<nav><div class="logo">Corp</div><div><a href="#">Product</a><a href="#">Solutions</a><a href="#">Contact</a></div></nav>
<div class="hero"><h1>$ctg</h1>
<p class="lead">We help enterprises scale with confidence.</p><a href="#" class="btn">Learn more</a></div>
<footer>© $cy Corp Inc. All rights reserved.</footer>
$honey</body></html>
HTML

  # blog: случайные даты постов — каждая генерация чуть другая
  local bd1 bd2
  bd1=$(date -d "-$(( RANDOM % 18 + 2 )) days" '+%B %-d, %Y' 2>/dev/null || date '+%B %d, %Y')
  bd2=$(date -d "-$(( RANDOM % 55 + 25 )) days" '+%B %-d, %Y' 2>/dev/null || date -d '-30 days' '+%B %d, %Y')
  tpl_write "$DECOY_TPL_DIR/blog.html" <<HTML
<!doctype html><html><head><meta charset="utf-8"><title>Notes</title>
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:Georgia,serif;max-width:720px;margin:auto;padding:60px 24px;color:#222;line-height:1.7}
h1{font-size:32px;margin-bottom:8px}.sub{color:#888;font-size:14px;margin-bottom:48px}article{margin-bottom:48px}
article h2{font-size:22px;margin-bottom:8px}article .meta{color:#888;font-size:13px;margin-bottom:12px}article p{color:#444}</style></head><body>
<h1>Notes</h1><p class="sub">Thoughts on software, systems, and craft.</p>
<article><h2>On simple systems</h2><div class="meta">$bd1</div>
<p>The best systems are the ones you can hold in your head.</p></article>
<article><h2>The quiet majority</h2><div class="meta">$bd2</div>
<p>Most software does its job silently.</p></article>
$honey</body></html>
HTML

  tpl_write "$DECOY_TPL_DIR/docs.html" <<HTML
<!doctype html><html><head><meta charset="utf-8"><title>Documentation</title>
<style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:-apple-system,sans-serif;display:flex;color:#222}
aside{width:260px;background:#fafafa;border-right:1px solid #eee;padding:24px;min-height:100vh}
aside h2{font-size:14px;text-transform:uppercase;color:#888;margin-bottom:16px;letter-spacing:1px}
aside a{display:block;padding:6px 0;color:#444;text-decoration:none;font-size:14px}
main{padding:60px 80px;max-width:900px}h1{font-size:36px;margin-bottom:24px}
p{margin-bottom:16px;color:#444;line-height:1.7}code{background:#f4f4f4;padding:2px 6px;border-radius:3px;font-size:13px}
pre{background:#1e1e1e;color:#f8f8f8;padding:20px;border-radius:8px;overflow-x:auto;margin:20px 0}</style></head><body>
<aside><h2>Getting Started</h2><a href="#">Introduction</a><a href="#">Installation</a><a href="#">Configuration</a></aside>
<main><h1>Introduction</h1><p>Welcome to the documentation.</p>
<pre>npm install @example/sdk</pre><p>Then call <code>client.connect()</code>.</p></main>
$honey</body></html>
HTML

  tpl_write "$DECOY_TPL_DIR/cloudflare.html" <<HTML
<!doctype html><html><head><meta charset="utf-8"><title>Attention Required! | Cloudflare</title>
<style>body{font-family:sans-serif;background:#f5f5f5;color:#333;margin:0;padding:60px 20px}
.container{max-width:800px;margin:auto;background:#fff;border-radius:6px;padding:60px;box-shadow:0 2px 12px rgba(0,0,0,.06)}
h1{font-size:26px;margin-bottom:24px;color:#111}p{line-height:1.7;color:#555;margin-bottom:16px}
.footer{border-top:1px solid #eee;margin-top:40px;padding-top:20px;color:#888;font-size:13px}</style></head><body>
<div class="container"><h1>Attention Required!</h1>
<p>You are unable to access this site.</p><p>Please enable cookies and JavaScript.</p>
<div class="footer">Cloudflare Ray ID: 8a3f... &nbsp;•&nbsp; Performance &amp; security by Cloudflare</div>
</div>$honey</body></html>
HTML

  # maintenance: правдоподобное «почему не работает» — отбивает желание копать
  local mh
  mh=$(date -d "+$(( RANDOM % 3 + 2 )) hours" '+%H:%M' 2>/dev/null || echo "12:00")
  tpl_write "$DECOY_TPL_DIR/maintenance.html" <<HTML
<!doctype html><html><head><meta charset="utf-8"><title>Scheduled maintenance</title>
<style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:-apple-system,sans-serif;background:#fffde7;color:#333;display:flex;align-items:center;justify-content:center;min-height:100vh}
.card{max-width:520px;text-align:center;padding:40px}
.ic{font-size:44px;margin-bottom:12px}h1{font-size:24px;margin-bottom:14px}p{color:#666;line-height:1.7;margin-bottom:8px}
.t{font-weight:600;color:#a05a00}</style></head><body><div class="card">
<div class="ic">&#128736;</div><h1>Scheduled maintenance</h1>
<p>We are performing planned maintenance on our systems.</p>
<p>Expected back online by <span class="t">$mh</span>. Thank you for your patience.</p></div>
$honey</body></html>
HTML

  # portfolio: тихая фото-визитка, без логина — совсем не палево
  tpl_write "$DECOY_TPL_DIR/portfolio.html" <<HTML
<!doctype html><html><head><meta charset="utf-8"><title>Selected Works — A. Raven</title>
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:Georgia,serif;background:#111;color:#ddd}
header{padding:80px 40px 40px;max-width:900px;margin:auto}h1{font-size:40px;font-weight:400;letter-spacing:1px}
header p{color:#888;margin-top:10px;font-style:italic}
.grid{max-width:900px;margin:auto;padding:0 40px 80px;display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:18px}
.ph{aspect-ratio:4/3;border-radius:4px;position:relative;overflow:hidden}
.ph:nth-child(1){background:linear-gradient(140deg,#23303d,#3d5266)}.ph:nth-child(2){background:linear-gradient(140deg,#3d2f33,#66424a)}
.ph:nth-child(3){background:linear-gradient(140deg,#2d3d33,#48664f)}.ph:nth-child(4){background:linear-gradient(140deg,#38332d,#5f5744)}
.ph span{position:absolute;bottom:10px;left:12px;font-size:13px;color:#cfcfcf;opacity:.75}
footer{padding:30px;text-align:center;color:#666;font-size:13px}</style></head><body>
<header><h1>Anna Raven</h1><p>photographer &mdash; selected works, 2019&ndash;2026</p></header>
<div class="grid">
<div class="ph"><span>Nordkapp, series IV</span></div><div class="ph"><span>Harbor study 12</span></div>
<div class="ph"><span>Forest interval</span></div><div class="ph"><span>Concrete noon</span></div></div>
<footer>contact: studio@raven.example &middot; prints on request</footer>
$honey</body></html>
HTML

  # hosting-panel и shop — интерактивные (трап через $js) → живут в
  # decoy_login_templates_init, где определены $css/$js.

  # tg-домену НЕ даём отдельного шаблона в меню: мимикрия под Telegram — палево
  # (сразу видно, что за доменом tg-прокси). Сайт tproxy получает нейтральный
  # blog (ensure_tproxy_site) — не совпадающий с corporate у reality-декоев.

  [[ "$sig_before" == "$(dir_sig "$DECOY_TPL_DIR")" ]] || log "Статические decoy-шаблоны готовы"
}

# =====================================================================
# DECOY: LOGIN-ШАБЛОНЫ
# =====================================================================
decoy_login_templates_init() {
  mkdir -p "$DECOY_LOGIN_DIR" 2>/dev/null || true
  local sig_before; sig_before=$(dir_sig "$DECOY_LOGIN_DIR")
  # реплики 1:1 (окт 2026): по умолчанию НЕ сносим — шаблоны пишутся один раз
  # (рандомная версия в футере фиксируется при установке; перегенерация при
  # каждом старте только меняла блобы и шумела в логе). Принудительно
  # обновить реплики из скрипта: SMG_FORCE_TPL=1 bash stack-manager.sh
  if [[ "${SMG_FORCE_TPL:-0}" == "1" ]]; then
    rm -f "$DECOY_LOGIN_DIR/adguard.html" "$DECOY_LOGIN_DIR/portainer.html" \
          "$DECOY_LOGIN_DIR/pihole.html" "$DECOY_LOGIN_DIR/omv.html" \
          "$DECOY_LOGIN_DIR/jellyfin.html" "$DECOY_LOGIN_DIR/homeassistant.html" \
          "$DECOY_LOGIN_DIR/uptime-kuma.html" "$DECOY_LOGIN_DIR/hosting-panel.html" \
          "$DECOY_LOGIN_DIR/shop.html" 2>/dev/null || true
  fi

  local agv="0.107.$(( RANDOM % 25 + 40 ))"   # версия в футере — правдоподобная рандомизация

  local css='<style>
*{box-sizing:border-box;margin:0;padding:0}
.msg{padding:12px;border-radius:4px;margin-bottom:16px;text-align:center;font-size:14px;display:none}
.msg.err{display:block;background:#fdecea;color:#b71c1c;border:1px solid #f5c6cb}
.msg.ban{display:block;background:#fff4e5;color:#a05a00;border:1px solid #ffd8a8}
label{display:block;font-size:13px;color:#555;margin-bottom:6px}
input{width:100%;padding:11px;border:1px solid #dcdcdc;border-radius:4px;font-size:14px;margin-bottom:16px}
button{width:100%;padding:12px;border:none;border-radius:4px;font-size:15px;cursor:pointer}
</style>'

  local js='<script>
document.getElementById("form").addEventListener("submit", async e=>{
  e.preventDefault();
  try{
    await fetch("/login",{method:"POST",body:new FormData(e.target)});
    showErr("Invalid credentials");
  }catch(err){showBan();}
});
function showErr(t){const el=document.getElementById("msg");el.className="msg err";el.textContent=t;}
function showBan(){
  const el=document.getElementById("msg");el.className="msg ban";
  el.textContent="Too many failed attempts. Access blocked for 2 hours.";
  document.getElementById("form").style.display="none";
}
</script>'

  tpl_write "$DECOY_LOGIN_DIR/adguard.html" <<HTML
<!doctype html><html><head><meta charset="utf-8"><title>AdGuard Home</title><link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Cpath fill='%2368b279' d='M12 2 4 5v6c0 5 3.4 9.7 8 11 4.6-1.3 8-6 8-11V5z'/%3E%3C/svg%3E">
$css<style>
body{font-family:Roboto,-apple-system,'Segoe UI',sans-serif;background:#fff;color:#3c4043;display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:100vh}
.logo{display:flex;align-items:center;gap:10px;margin-bottom:26px}
.logo svg{width:46px;height:46px}
.logo b{font-size:27px;font-weight:500;color:#3c4043}
.card{width:360px;padding:32px;background:#fff;border:1px solid #e0e0e0;border-radius:8px;box-shadow:0 1px 3px rgba(0,0,0,.08)}
input{border:1px solid #c6c6c6;border-radius:4px;padding:12px}
input:focus{border-color:#68b279;outline:none}
button{background:#68b279;color:#fff;font-weight:500;border-radius:4px}
button:hover{background:#5aa36c}
.foot{margin-top:20px;font-size:12px;color:#9aa0a6;text-align:center}
.foot span{color:#68b279;cursor:pointer}
</style></head><body>
<div class="logo"><svg viewBox="0 0 24 24"><path fill="#68b279" d="M12 2 4 5v6c0 5 3.4 9.7 8 11 4.6-1.3 8-6 8-11V5l-8-3z"/><path fill="#fff" d="M10.6 14.9l-2.9-2.9 1.2-1.2 1.7 1.7 4.5-4.5 1.2 1.2-5.7 5.7z"/></svg><b>AdGuard Home</b></div>
<div class="card">
<div id="msg" class="msg"></div>
<form id="form" method="POST" action="/login">
<label>Username</label><input name="u" required autocomplete="off">
<label>Password</label><input name="p" type="password" required>
<button>Sign in</button>
</form></div>
<div class="foot">AdGuard Home v$agv · <span>Homepage</span> · <span>Report issue</span></div>
$js</body></html>
HTML

  tpl_write "$DECOY_LOGIN_DIR/portainer.html" <<HTML
<!doctype html><html><head><meta charset="utf-8"><title>Portainer</title><link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Crect width='24' height='24' rx='5' fill='%2313bef9'/%3E%3Cpath fill='%23fff' d='M5 8h9v3.5H5V8zm0 5.5h9V17H5v-3.5zm11-5.5h3v3.5h-3V8zm0 5.5h3V17h-3v-3.5z'/%3E%3C/svg%3E">
$css<style>
body{font-family:'Segoe UI',Roboto,-apple-system,sans-serif;background:#eceff1;color:#333;display:flex;align-items:center;justify-content:center;min-height:100vh}
.card{background:#fff;padding:40px 36px;width:400px;border-radius:4px;box-shadow:0 1px 4px rgba(0,0,0,.14)}
.logo{width:56px;height:56px;background:#13bef9;border-radius:12px;display:flex;align-items:center;justify-content:center;margin:0 auto 18px}
.logo svg{width:32px;height:32px}
h1{font-size:24px;font-weight:400;color:#333;text-align:center;margin-bottom:26px}
button{background:#2b7fd4;color:#fff;font-weight:500}
button:hover{background:#246cb4}
</style></head><body><div class="card">
<div class="logo"><svg viewBox="0 0 24 24"><path fill="#fff" d="M4 7h10v4H4V7zm0 6h10v4H4v-4zm12-6h4v4h-4V7zm0 6h4v4h-4v-4z"/></svg></div>
<h1>Portainer</h1>
<div id="msg" class="msg"></div>
<form id="form" method="POST" action="/login">
<label>Username</label><input name="u" required autocomplete="off">
<label>Password</label><input name="p" type="password" required>
<button>Log in</button>
</form></div>$js</body></html>
HTML

  tpl_write "$DECOY_LOGIN_DIR/pihole.html" <<HTML
<!doctype html><html><head><meta charset="utf-8"><title>Pi-hole - Admin Console</title><link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Ccircle cx='12' cy='12' r='10' fill='%23c0392b'/%3E%3Ccircle cx='12' cy='12' r='5' fill='%23fff'/%3E%3Ccircle cx='12' cy='12' r='2' fill='%23c0392b'/%3E%3C/svg%3E">
$css<style>
body{font-family:'Helvetica Neue',Arial,sans-serif;background:#f5f6f7;color:#333;display:flex;align-items:center;justify-content:center;min-height:100vh}
.card{background:#fff;padding:36px 40px;width:400px;border-radius:6px;border:1px solid #e2e4e6;box-shadow:0 1px 4px rgba(0,0,0,.06)}
.logo{display:flex;align-items:center;gap:12px;margin-bottom:24px;justify-content:center}
.logo svg{width:44px;height:44px}
.logo b{font-size:28px;font-weight:600;color:#2b3033}
.logo b i{font-style:normal;color:#c0392b}
input{border:1px solid #ccc;border-radius:3px;padding:10px}
button{background:#3c8dbc;color:#fff;border-radius:3px}
button:hover{background:#3579a8}
</style></head><body><div class="card">
<div class="logo"><svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10" fill="#c0392b"/><circle cx="12" cy="12" r="6" fill="#fff"/><circle cx="12" cy="12" r="2.5" fill="#c0392b"/></svg><b>Pi-<i>hole</i></b></div>
<div id="msg" class="msg"></div>
<form id="form" method="POST" action="/login">
<label>Password</label><input name="p" type="password" required>
<button>Log in</button>
</form></div>$js</body></html>
HTML

  tpl_write "$DECOY_LOGIN_DIR/omv.html" <<HTML
<!doctype html><html><head><meta charset="utf-8"><title>openmediavault - Login</title><link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Crect width='24' height='24' rx='5' fill='%235d7789'/%3E%3Cpath fill='%23fff' d='M7 14a5 5 0 1 1 10 0h-2a3 3 0 1 0-6 0H7z'/%3E%3C/svg%3E">
$css<style>
body{font-family:'Segoe UI',Roboto,sans-serif;background:#262c31;color:#e8eaed;display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:100vh}
.brand{font-size:30px;font-weight:300;color:#fff;margin-bottom:6px;letter-spacing:.5px}
.brand i{font-style:normal;color:#5d9cec}
.sub{font-size:13px;color:#8a939b;margin-bottom:28px}
.card{background:#31373d;width:400px;padding:36px 32px;border-radius:6px;box-shadow:0 4px 18px rgba(0,0,0,.35)}
label{color:#b8bfc6}
input{background:#262c31;border:1px solid #454d54;color:#e8eaed;border-radius:4px}
input:focus{border-color:#5d9cec;outline:none}
button{background:#5d7789;color:#fff;border-radius:4px}
button:hover{background:#4d6575}
</style></head><body>
<div class="brand">openmediavault<i>.</i></div>
<div class="sub">Network Attached Storage Solution</div>
<div class="card">
<div id="msg" class="msg"></div>
<form id="form" method="POST" action="/login">
<label>Username</label><input name="u" required autocomplete="off">
<label>Password</label><input name="p" type="password" required>
<button>Sign in</button>
</form></div>$js</body></html>
HTML

  tpl_write "$DECOY_LOGIN_DIR/jellyfin.html" <<HTML
<!doctype html><html><head><meta charset="utf-8"><title>Jellyfin</title><link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Ccircle cx='12' cy='12' r='10' fill='%23aa5cc3'/%3E%3Ccircle cx='12' cy='12' r='4.5' fill='none' stroke='%23fff' stroke-width='1.5'/%3E%3Ccircle cx='12' cy='12' r='1.5' fill='%23fff'/%3E%3C/svg%3E">
$css<style>
body{font-family:'Segoe UI',Roboto,-apple-system,sans-serif;background:linear-gradient(160deg,#141e2c,#0b1017);color:#fff;display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:100vh}
.logo svg{width:72px;height:72px;margin-bottom:12px}
h1{font-size:30px;font-weight:400;text-align:center;margin-bottom:24px;letter-spacing:.5px}
.card{width:340px}
label{color:#aebac9}
input{background:#1a2431;border:1px solid #2f3d4f;color:#fff;border-radius:4px}
input:focus{border-color:#52b54b;outline:none}
button{background:#52b54b;color:#fff;font-weight:500;border-radius:4px}
button:hover{background:#46a03f}
</style></head><body>
<div class="logo"><svg viewBox="0 0 24 24"><defs><linearGradient id="jg" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#aa5cc3"/><stop offset="1" stop-color="#00a4dc"/></linearGradient></defs><circle cx="12" cy="12" r="11" fill="url(#jg)"/><circle cx="12" cy="12" r="5.5" fill="none" stroke="#fff" stroke-width="1.6"/><circle cx="12" cy="12" r="1.6" fill="#fff"/></svg></div>
<h1>Jellyfin</h1>
<div class="card">
<div id="msg" class="msg"></div>
<form id="form" method="POST" action="/login">
<label>Username</label><input name="u" required autocomplete="off">
<label>Password</label><input name="p" type="password" required>
<button>Sign In</button>
</form></div>$js</body></html>
HTML

  tpl_write "$DECOY_LOGIN_DIR/homeassistant.html" <<HTML
<!doctype html><html><head><meta charset="utf-8"><title>Home Assistant</title><link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Cpath fill='%2341bdf2' d='M12 3 2 12h3v8h5v-5h4v5h5v-8h3L12 3z'/%3E%3C/svg%3E">
$css<style>
body{font-family:Roboto,'Segoe UI',sans-serif;background:#fafafa;color:#212121;display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:100vh}
.logo svg{width:64px;height:64px;margin-bottom:10px}
h1{font-size:28px;font-weight:400;text-align:center;margin-bottom:26px;color:#424242}
.card{width:360px;padding:28px;background:#fff;border:1px solid #e0e0e0;border-radius:8px}
input{border:1px solid #c6c6c6;border-radius:4px;padding:12px}
input:focus{border-color:#41bdf2;outline:none}
button{background:#41bdf2;color:#fff;font-weight:500;border-radius:4px}
button:hover{background:#2cabdf}
</style></head><body>
<div class="logo"><svg viewBox="0 0 24 24"><path fill="#41bdf2" d="M12 3 2 12h3v8h5v-5h4v5h5v-8h3L12 3z"/></svg></div>
<h1>Home Assistant</h1>
<div class="card">
<div id="msg" class="msg"></div>
<form id="form" method="POST" action="/login">
<label>Username</label><input name="u" required autocomplete="off">
<label>Password</label><input name="p" type="password" required>
<button>Connect</button>
</form></div>$js</body></html>
HTML

  tpl_write "$DECOY_LOGIN_DIR/uptime-kuma.html" <<HTML
<!doctype html><html><head><meta charset="utf-8"><title>Uptime Kuma</title><link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Ccircle cx='12' cy='12' r='10' fill='none' stroke='%235cdd8b' stroke-width='2.5'/%3E%3Cpath fill='none' stroke='%235cdd8b' stroke-width='2' d='M6 12h3l2-4 2 8 2-4h3'/%3E%3C/svg%3E">
$css<style>
body{font-family:Roboto,'Segoe UI',sans-serif;background:#1b2637;color:#fff;display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:100vh}
.logo{display:flex;align-items:center;gap:10px;margin-bottom:30px}
.logo svg{width:40px;height:40px}
.logo b{font-size:24px;font-weight:600;color:#fff}
.logo b i{font-style:normal;color:#5cdd8b}
.card{width:360px;padding:32px;background:#243447;border:1px solid #2e4157;border-radius:10px}
label{color:#9fb0c0}
input{background:#1b2637;border:1px solid #33475e;color:#fff;border-radius:6px}
input:focus{border-color:#5cdd8b;outline:none}
button{background:#5cdd8b;color:#1b2637;font-weight:700;border-radius:6px}
button:hover{background:#4bcf7b}
</style></head><body>
<div class="logo"><svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10" fill="none" stroke="#5cdd8b" stroke-width="2"/><path fill="none" stroke="#5cdd8b" stroke-width="2" d="M6 12h3l2-4 2 8 2-4h3"/></svg><b>Uptime <i>Kuma</i></b></div>
<div class="card">
<div id="msg" class="msg"></div>
<form id="form" method="POST" action="/login">
<label>Username</label><input name="u" required autocomplete="off">
<label>Password</label><input name="p" type="password" required>
<button>Login</button>
</form></div>$js</body></html>
HTML

  # hosting-panel: cPanel-стиль, ловит POST /login как остальные реплики
  tpl_write "$DECOY_LOGIN_DIR/hosting-panel.html" <<HTML
<!doctype html><html><head><meta charset="utf-8"><title>Hosting Control Panel — Login</title>
$css<style>
body{font-family:Arial,Helvetica,sans-serif;background:linear-gradient(180deg,#0b2d4d,#123c66);display:flex;align-items:center;justify-content:center;min-height:100vh}
.card{background:#fff;width:400px;border-radius:8px;overflow:hidden;box-shadow:0 10px 30px rgba(0,0,0,.3)}
.head{background:#f5f7f9;padding:26px;text-align:center;border-bottom:1px solid #e3e8ec}
.logo{font-size:22px;font-weight:700;color:#0b5c8c}.logo i{font-style:normal;color:#ff6c2c}
.head small{display:block;color:#8a97a0;font-size:12px;margin-top:4px}
.body{padding:28px}
button{background:#ff6c2c;color:#fff;border-radius:4px;font-weight:600}
button:hover{background:#e85a1c}
label{color:#5a6a75;text-transform:uppercase;font-size:11px;letter-spacing:.5px}
.foot{padding:14px;text-align:center;color:#9aa7b0;font-size:12px;border-top:1px solid #e3e8ec}
</style></head><body><div class="card">
<div class="head"><div class="logo">Hosting<i>Panel</i></div><small>Client Area &middot; cPanel 110.4</small></div>
<div class="body">
<div id="msg" class="msg"></div>
<form id="form" method="POST" action="/login">
<label>Username</label><input name="u" required autocomplete="off">
<label>Password</label><input name="p" type="password" required>
<button>Log in</button>
</form></div>
<div class="foot">&copy; 2019 Hosting Solutions &middot; License v3</div></div>$js</body></html>
HTML

  # shop: «скоро открытие» — форма подписки постит в тот же трап /login
  tpl_write "$DECOY_LOGIN_DIR/shop.html" <<HTML
<!doctype html><html><head><meta charset="utf-8"><title>Ember Goods — coming soon</title>
$css<style>
body{font-family:-apple-system,sans-serif;background:#faf7f4;color:#2b2b2b;display:flex;align-items:center;justify-content:center;min-height:100vh}
.card{max-width:480px;text-align:center;padding:40px}
.logo{font-size:28px;font-weight:700;letter-spacing:3px;color:#b3541e;margin-bottom:8px}
h1{font-size:22px;font-weight:400;margin-bottom:14px}p{color:#777;line-height:1.7;margin-bottom:22px}
input{border:1px solid #ddd;border-radius:4px;padding:12px}
button{background:#b3541e;color:#fff;border-radius:4px}
.small{font-size:12px;color:#aaa;margin-top:16px}
</style></head><body><div class="card">
<div class="logo">EMBER GOODS</div>
<h1>Something warm is coming.</h1>
<p>We are putting the finishing touches on our store.<br>Leave your email to get 15% off at launch.</p>
<div id="msg" class="msg"></div>
<form id="form" method="POST" action="/login">
<input name="u" placeholder="you@example.com" required autocomplete="off">
<button>Notify me</button>
</form>
<p class="small">No spam. Unsubscribe anytime.</p></div>$js</body></html>
HTML

  chown -R www-data:www-data "$DECOY_LOGIN_DIR" 2>/dev/null || true
  [[ "$sig_before" == "$(dir_sig "$DECOY_LOGIN_DIR")" ]] || log "9 login-шаблонов установлены"
}

# =====================================================================
# FAIL2BAN
# =====================================================================
decoy_fail2ban_init() {
  command -v fail2ban-client >/dev/null 2>&1 || {
    apt-get update -y >/dev/null 2>&1 || true
    apt-get install -y fail2ban >/dev/null 2>&1 || true
  }
  touch "$DECOY_LOG_ACCESS" 2>/dev/null || true
  chown www-data:adm "$DECOY_LOG_ACCESS" 2>/dev/null || true
  chmod 640 "$DECOY_LOG_ACCESS" 2>/dev/null || true
  mkdir -p /etc/fail2ban/filter.d /etc/fail2ban/jail.d 2>/dev/null || true

  cat > /etc/fail2ban/filter.d/decoy-login.conf <<'F2B'
[Definition]
# формат decoy_ext: IP [time] "REQUEST" STATUS "UA" host=dom
failregex = ^<HOST> \[[^\]]+\] "POST /login HTTP/[0-9.]+" 401
            ^<HOST> \[[^\]]+\] "(?:GET|POST|HEAD) /(?:admin|wp-admin|wp-login\.php|\.env|\.git|api/debug|phpmyadmin|configuration\.php|actuator)(?:/|\?| )[^\"]*" \d+
ignoreregex =
F2B

  cat > /etc/fail2ban/jail.d/decoy-login.local <<EOF
[decoy-login]
enabled  = true
filter   = decoy-login
logpath  = $DECOY_LOG_ACCESS
maxretry = $DECOY_MAX_FAILS
findtime = 600
bantime  = $DECOY_BAN_SECONDS
action   = iptables-multiport[name=decoy, port="80,443"]
EOF

  systemctl enable fail2ban >/dev/null 2>&1 || true
  systemctl restart fail2ban >/dev/null 2>&1 || true
  sleep 2
  fail2ban-client status decoy-login >/dev/null 2>&1 && log "fail2ban активен" || warn "fail2ban jail не поднялся"
}

decoy_full_init() {
  decoy_templates_init || true
  decoy_login_templates_init || true
  decoy_fail2ban_init || true
}

# =====================================================================
# СЕРТИФИКАТЫ
# =====================================================================
# =====================================================================
# СЕРТЫ ЖИВУТ ТОЛЬКО В /etc/letsencrypt/live/ — дубликатов больше нет
# =====================================================================
# Раньше каждый серт зеркалировался в /root/cert/<домен>/ (папка панели) —
# дублирование. Теперь функция возвращает пути исходной live-линии, все
# вызывающие (панель, decoy, AdGuard) автоматически получают live-пути,
# а cert_dedup_migrate() разово перепривязывает старые ссылки и сносит /root/cert.
cert_mirror_to_certroot() {   # <live-dir> <domain> → echo "<fullchain> <privkey>"
  local src="$1"
  [[ -f "$src/fullchain.pem" && -f "$src/privkey.pem" ]] || return 1
  echo "$src/fullchain.pem $src/privkey.pem"
  return 0
}

cert_install_to_certroot() {  # <domain> — по одноимённой линии certbot (live)
  local d="$1"
  cert_mirror_to_certroot "/etc/letsencrypt/live/$d" "$d"
}

cert_sync_all() {             # зеркало упразднено — оставлено для совместимости
  return 0
}

# deploy-hook: после каждого certbot renew — рестарт панели/nginx/AdGuard
# (серты живут в live/, зеркало упразднено). Хук перезаписывается при каждом
# запуске скрипта — старая версия с зеркалом не должна выжить.
cert_hook_install() {
  local hook="/etc/letsencrypt/renewal-hooks/deploy/stack-cert-mirror.sh"
  mkdir -p "$(dirname "$hook")" 2>/dev/null || return 0
  cat > "$hook" <<'EOS'
#!/usr/bin/env bash
# stack-manager: после renew рестартуем потребителей сертов (серты в live/)
systemctl restart x-ui 2>/dev/null || true
nginx -t >/dev/null 2>&1 && systemctl reload nginx 2>/dev/null || true
if [ -f /opt/AdGuardHome/AdGuardHome.yaml ] && grep -q "certificate_path: /etc/letsencrypt/live/" /opt/AdGuardHome/AdGuardHome.yaml 2>/dev/null; then
  systemctl restart AdGuardHome 2>/dev/null || systemctl restart adguardhome 2>/dev/null || true
fi
EOS
  chmod +x "$hook" 2>/dev/null || true
  return 0
}

# Вписывает пути сертификатов в settings инбаундов:
#   naive/anytls/trusttunnel/tproxy → settings.certFile/keyFile
#   hysteria → stream tlsSettings.certificates[0]
# Lineage для домена: точный, иначе wildcard базового домена (если уже выпущен) —
# чтобы в wildcard-режиме не плодить персональные серты на каждый субдомен
cert_lineage_for() {
  local d="$1" wb="${1#*.}" c
  c=$(cert_paths "$d" 2>/dev/null || true)
  [[ -z "$c" && "$wb" == *.* ]] && c=$(cert_paths "$wb" 2>/dev/null || true)
  printf '%s' "$c"
}

# --- tg web proxy (tproxy): hostname + серт + сайт-заглушка + маршрут 443 -----
# Панель создаёт tproxy-инбаунд пустым — без hostname он отключается
# ("tproxy: hostname is required"), без index.html в siteDir не стартует caddy.
# Здесь доводим до рабочего вида: домен tg.<база панели>, серт (точный или
# wildcard базы), enable=1, маршрут SNI-роутера на 11443.
setup_tproxy_web() {
  [[ -z "$XUI_DB" || ! -f "$XUI_DB" ]] && return 0
  local tid
  tid=$(sqlite3 "$XUI_DB" "SELECT id FROM inbounds WHERE protocol='tproxy' ORDER BY id LIMIT 1;" 2>/dev/null || true)
  [[ -z "$tid" ]] && return 0   # tproxy не выбран при установке — нечего настраивать
  local tdom="${T_PROXY_DOMAIN:-}"
  if [[ -z "$tdom" ]]; then
    # реальный домен — из настроек инбаунда (если не плейсхолдер *.example.com)
    tdom=$(sqlite3 -cmd ".timeout 3000" "$XUI_DB" \
           "SELECT COALESCE(json_extract(settings,'\$.hostname'),'') FROM inbounds WHERE id=$tid;" 2>/dev/null | tr -d '[:space:]')
    [[ "$tdom" =~ \.example\.com$ ]] && tdom=""
  fi
  if [[ -z "$tdom" ]]; then
    local base="${PANEL_DOMAIN#*.}"
    [[ "$base" != *.* ]] && base="$PANEL_DOMAIN"
    tdom="tg.${base:-example.com}"
  fi
  # сайт-заглушка обязательна: без index.html в siteDir caddy tproxy не поднимается
  mkdir -p /var/www/html
  ensure_tproxy_site   # нейтральная blog-заглушка (перезаписывает пустышку/старое)
  # серт: точный → wildcard базового домена → выпуск
  local cline c_cert="" c_key=""
  cline=$(cert_lineage_for "$tdom")
  if [[ -z "$cline" ]]; then
    cert_issue "$tdom" || warn "  tg web proxy: серт $tdom НЕ выпущен (проверь DNS) — запусти скрипт повторно после добавления записи"
    cline=$(cert_lineage_for "$tdom")
  fi
  [[ -n "$cline" ]] && { c_cert="${cline%% *}"; c_key="${cline##* }"; }
  # БД: hostname + пути серта + enable=1 (строго при остановленном x-ui)
  systemctl stop x-ui 2>/dev/null || true
  T_PROXY_ID="$tid" T_PROXY_DOM="$tdom" T_PROXY_CERT="$c_cert" T_PROXY_KEY="$c_key" python3 - "$XUI_DB" <<'PYTP'
import sqlite3, json, os, sys
con = sqlite3.connect(sys.argv[1])
iid, dom = int(os.environ["T_PROXY_ID"]), os.environ["T_PROXY_DOM"]
s = json.loads(con.execute("SELECT settings FROM inbounds WHERE id=?", (iid,)).fetchone()[0] or "{}")
s["hostname"] = dom
if os.environ.get("T_PROXY_CERT"):
    s["certFile"] = os.environ["T_PROXY_CERT"]; s["keyFile"] = os.environ["T_PROXY_KEY"]
s["externalTLS"] = False
con.execute("UPDATE inbounds SET settings=?, enable=1 WHERE id=?", (json.dumps(s), iid))
con.commit()
print(f"  tproxy #{iid}: hostname={dom}, серт {'вписан' if os.environ.get('T_PROXY_CERT') else 'НЕ найден'}, enable=1")
PYTP
  systemctl start x-ui 2>/dev/null || true
  sleep 4
  # маршрут 443 → tproxy (idempotent UPSERT: upstream есть всегда,
  # строка домена — всегда АКТУАЛЬНЫЙ tdom; старый домен заменяется)
  if [[ -f "$SNI_CONF" ]]; then
    if ! grep -q "upstream tg_backend" "$SNI_CONF"; then
      sed -i "1i upstream tg_backend { server 127.0.0.1:11443; }" "$SNI_CONF" 2>/dev/null || true
    fi
    if ! grep -qE "^[[:space:]]*${tdom}[[:space:]]+tg_backend;" "$SNI_CONF"; then
      if grep -qE "^[[:space:]]*[A-Za-z0-9.-]+[[:space:]]+tg_backend;" "$SNI_CONF"; then
        sed -i -E "s|^([[:space:]]*)[A-Za-z0-9.-]+([[:space:]]+tg_backend;)|\1${tdom}\2|" "$SNI_CONF" 2>/dev/null || true
      else
        sed -i "s|^\(    default\)|    ${tdom}              tg_backend;\n\1|" "$SNI_CONF" 2>/dev/null || true
      fi
      log "tg web proxy: мап обновлён → $tdom → tg_backend"
    fi
  fi
  # доктрина «всё за 443»: 11443 наружу не открываем (и закрываем, если было);
  # UDP-порт здесь — HTTP/3 caddy, наружу не нужен и палится сканерами
  ufw delete allow 11443/tcp >/dev/null 2>&1 || true
  ufw delete allow 11443/udp >/dev/null 2>&1 || true
  nginx -t >/dev/null 2>&1 && nginx_reload || true
  log "tg web proxy: https://$tdom/ — сайт-заглушка + веб-интерфейс прокси (ключи/ссылки в панели)"
}

# --- Смена паролей admin (панель и/или AdGuard) ------------------------------
change_admin_passwords() {
  line; echo -e "${B}   СМЕНИТЬ ПАРОЛИ ADMIN${N}"; line
  detect_env >/dev/null 2>&1 || true
  local what=""
  if [[ "$ADG_PRESENT" == true && -n "$ADG_SERVICE" ]]; then
    ask what "Что меняем? [1] панель, [2] AdGuard, [3] обе" "3" '^[123]$'
  else
    log "AdGuard Home не установлен — меняем только пароль панели."
    what="1"
  fi
  if [[ "$what" == "1" || "$what" == "3" ]]; then
    [[ -z "$XUI_DB" || ! -f "$XUI_DB" ]] && { err "x-ui.db не найден"; return 1; }
    local ppass=""
    ask ppass "Новый пароль ПАНЕЛИ (admin; Enter — случайный)" "" '^$|.{6,}'
    [[ -z "$ppass" ]] && ppass=$(openssl rand -base64 18 2>/dev/null | tr -dc 'a-zA-Z0-9' | head -c 16)
    systemctl stop x-ui 2>/dev/null || true
    PPASS="$ppass" python3 - "$XUI_DB" <<'PYPASS'
import sqlite3, sys, os
try:
    import bcrypt
except Exception:
    print("  нет python3-bcrypt: apt install python3-bcrypt"); sys.exit(1)
h = bcrypt.hashpw(os.environ["PPASS"].encode(), bcrypt.gensalt()).decode()
con = sqlite3.connect(sys.argv[1])
tabs = [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")]
if "users" in tabs:
    cols = [r[1] for r in con.execute("PRAGMA table_info(users)")]
    if "username" in cols and "password" in cols:
        n = con.execute("UPDATE users SET password=? WHERE username='admin'", (h,)).rowcount
        if n == 0:
            con.execute("INSERT INTO users (username, password) VALUES ('admin', ?)", (h,))
        con.commit(); print("  панель: users.password обновлён (bcrypt)")
elif "pass" in [r[0] for r in con.execute("SELECT key FROM settings")]:
    con.execute("UPDATE settings SET value=? WHERE key='pass'", (h,))
    con.commit(); print("  панель: settings.pass обновлён (bcrypt)")
else:
    print("  панель: не нашёл, где хранится пароль — напиши разработчику"); sys.exit(1)
PYPASS
    local rc=$?
    systemctl start x-ui 2>/dev/null || true
    if [[ $rc -eq 0 ]]; then
      {
        echo "LucX UI панель — $(date '+%F %T')"
        echo "  Логин:  admin"
        echo "  Пароль: $ppass"
      } > /root/panel-credentials.txt
      chmod 600 /root/panel-credentials.txt
      log "Пароль панели обновлён ✓ — логин admin, сохранено в /root/panel-credentials.txt"
    else
      err "Пароль панели НЕ изменён"
    fi
  fi
  if [[ "$what" == "2" || "$what" == "3" ]]; then
    local auser="" apass=""
    auser=$(grep -i "логин" /root/adguard-credentials.txt 2>/dev/null | awk '{print $NF}' | head -1)
    [[ -z "$auser" ]] && auser="${U_ADG_USER:-admin}"
    ask auser "Логин ADGUARD (Enter — $auser)" "$auser" '^[a-zA-Z0-9._-]{3,32}$'
    ask apass "Новый пароль ADGUARD (Enter — случайный)" "" '^$|.{6,}'
    [[ -z "$apass" ]] && apass=$(openssl rand -base64 18 2>/dev/null | tr -dc 'a-zA-Z0-9' | head -c 16)
    if adg_set_admin "$auser" "$apass"; then
      {
        echo "AdGuard Home — $(date '+%F %T')"
        echo "  URL:    https://${PANEL_DOMAIN:-<домен панели>}/"
        echo "  DoH:    https://${PANEL_DOMAIN:-<домен панели>}/dns-query"
        echo "  Логин:  $auser"
        echo "  Пароль: $apass"
      } > /root/adguard-credentials.txt
      chmod 600 /root/adguard-credentials.txt
      log "Пароль AdGuard обновлён ✓ — сохранено в /root/adguard-credentials.txt"
    else
      err "Пароль AdGuard НЕ изменён"
    fi
  fi
  return 0
}

# Read-only проверка: есть ли вообще, что чинить. Пустой вывод = все серты
# на месте — тогда sync_inbound_certs не останавливает панель и молчит.
sync_inbound_needs() {
  python3 - "$XUI_DB" "${REALITY_TARGETS[@]}" <<'PYNEED' 2>/dev/null
import sqlite3, json, sys, subprocess, re
db = sys.argv[1]
targets = set(a.lower() for a in sys.argv[2:])
SKIP = {"qwdtt","csqdtt","csqtt","wireguard","amnezia","amneziawg","awg","mtproto","tun"}
FROZEN_INB = set()
try:
    FROZEN_INB = {l.strip().split(":",1)[1] for l in open("/root/stack-frozen.txt") if l.strip().startswith("inbound:")}
except Exception:
    pass
def listening(port):
    try:
        out = subprocess.run(["ss","-tln"],capture_output=True,text=True,timeout=5).stdout
    except Exception:
        return False
    return bool(re.search(rf":{port}(\s|$)", out))
try:
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=5)
    rows = con.execute("SELECT id,protocol,settings,stream_settings FROM inbounds WHERE enable=1 AND port>0").fetchall()
except Exception:
    sys.exit(0)
for iid, proto, s1, s2 in rows:
    p = (proto or "").lower()
    if p in SKIP: continue
    if f"inbound:{iid}" in FROZEN_INB: continue
    try: se = json.loads(s1 or "{}")
    except Exception: se = {}
    try: st = json.loads(s2 or "{}")
    except Exception: st = {}
    rs = st.get("realitySettings") or {}
    dom = se.get("domain") or se.get("hostname") or se.get("sni") \
       or (st.get("tlsSettings") or {}).get("serverName") \
       or (rs.get("serverNames") or [None])[0] or ""
    dom = str(dom).strip()
    if not dom: continue
    if (st.get("security") or "").lower() == "reality":
        dest = str(rs.get("dest") or rs.get("target") or "")
        if dest and dest.split(":")[0] != "127.0.0.1": continue   # чужой reality
        if dom.lower() in targets: continue                        # домен = цель
        port = 4444 + iid
        if re.search(r'"(?:dest|target)":\s*"127\.0\.0\.1:%d"' % port, s2 or "") and listening(port):
            continue                                               # decoy жив
    else:
        cert = se.get("certFile") or ""
        if not cert:
            c = (st.get("tlsSettings") or {}).get("certificates") or []
            if c: cert = c[0].get("certificateFile","")
        if cert.startswith("/etc/letsencrypt/live/"): continue
    print(f"{iid}\x1f{proto}\x1f{dom}\x1f{json.dumps(st, ensure_ascii=False)}")
PYNEED
}

sync_inbound_certs() {
  [[ -z "$XUI_DB" || ! -f "$XUI_DB" ]] && return 1
  # Тихий проход: если самолечению нечего чинить — панель НЕ останавливаем
  # и ничего не печатаем (раньше каждый запуск бил x-ui и сыпал «cert вписан»).
  [[ -z "$(sync_inbound_needs)" ]] && return 0
  local cnt=0 id proto dom stream line cert key
  # x-ui держит inbounds в памяти и при рестарте сбрасывает её поверх БД —
  # поэтому ВСЕ правки inbounds делаем только при ОСТАНОВЛЕННОМ x-ui
  systemctl stop x-ui 2>/dev/null || true
  # tproxy (caddy) отказывается стартовать без index.html в siteDir — нейтральный blog
  if [[ -d /var/www/html && -n "$DECOY_TPL_DIR" && -f "$DECOY_TPL_DIR/blog.html" ]]; then
    cp -f "$DECOY_TPL_DIR/blog.html" /var/www/html/index.html 2>/dev/null || true
  fi
  # Читаем через python: панель хранит stream/settings pretty-JSON (многострочно),
  # sqlite3|while-read обрезал бы значение на первом переносе — reality-инбаунды
  # молча выпадали из самолечения и не получали серты/decoy.
  while IFS=$'\x1f' read -r id proto dom stream; do
    [[ -z "$id" || -z "$dom" || "$dom" == "null" ]] && continue
    dom="$(printf '%s' "$dom" | tr -d '[:space:]')"   # хвост-пробел/CR ломает пути live/<домен>
    frozen "inbound:$id" && continue   # заморожено (п.25) — самолечение не трогает
    # qwdtt/csqtt/wireguard/т.п. — серты и decoy не нужны никогда
    case "$proto" in
      qwdtt|csqdtt|csqtt|wireguard|amnezia|amneziawg|awg|mtproto|tun) continue ;;
    esac

    # --- Reality: серт нужен DECOY-бекенду (dest). Если decoy нет/мёртв — создаём.
    if grep -qi '"security": *"reality"' <<<"$stream" 2>/dev/null; then
      # ЧУЖОЙ реалити (dest = внешняя цель, НЕ 127.0.0.1): серт и decoy НЕ НУЖНЫ —
      # инбаунд спрятан за 443 через SNI-маршрут на имя цели. dom здесь — это
      # serverNames (цель), выпускать на неё серт нельзя и не нужно.
      local rdest="" rt2
      rdest=$(sqlite3 "$XUI_DB" "SELECT COALESCE(json_extract(stream_settings,'\$.realitySettings.dest'),'') FROM inbounds WHERE id=$id;" 2>/dev/null || true)
      rdest="${rdest%%:*}"
      if [[ -n "$rdest" && "$rdest" != "127.0.0.1" ]]; then
        continue   # чужой реалити — самолечению серт/decoy не требуются
      fi
      for rt2 in "${REALITY_TARGETS[@]}"; do
        [[ "$dom" == "$rt2" ]] && continue 2   # домен = цель из списка → пропускаем
      done
      local cline2 c_cert c_key want_port droot
      cline2=$(cert_lineage_for "$dom")
      if [[ -z "$cline2" ]]; then
        cert_issue "$dom" >/dev/null 2>&1 || warn "  #$id (reality): серт $dom НЕ выпущен. Причина:"
        cline2=$(cert_lineage_for "$dom")
      fi
      if [[ -z "$cline2" ]]; then
        warn "  #$id (reality): без серта decoy не создать — пробивы увидят отказ соединения"
        continue
      fi
      c_cert="${cline2%% *}"; c_key="${cline2##* }"
      want_port=$(( 4444 + id ))
      # dest уже указывает на живой decoy с этим портом? тогда не трогаем
      if grep -Eq "\"(dest|target)\": ?\"127\.0\.0\.1:$want_port\"" <<<"$stream" && ss -tln 2>/dev/null | grep -q ":$want_port "; then
        continue
      fi
      droot="/var/www/decoy-$id"
      mkdir -p "$droot"
      [[ -f "$droot/index.html" ]] || { cp "$DECOY_TPL_DIR/corporate.html" "$droot/index.html" 2>/dev/null || echo '<html><body><h1>Welcome</h1></body></html>' > "$droot/index.html"; }
      if mk_decoy "$want_port" "$dom" "$c_cert" "$c_key" "$droot" "default" && reality_set_dest "$id" "$want_port" "$dom"; then
        log "  #$id (reality): decoy на $want_port + dest восстановлены (серт $dom)"
        cnt=$((cnt+1))
      else
        warn "  #$id (reality): не удалось создать decoy/dest"
      fi
      continue
    fi

    # --- TLS-инбаунды (naive/anytls/trusttunnel/hysteria и vless+tls) ---
    line=$(cert_lineage_for "$dom")
    if [[ -z "$line" ]]; then
      local ci_out=""
      if ! ci_out=$(cert_issue "$dom" 2>&1); then
        warn "  #$id ($proto): серт $dom НЕ выпущен. Причина:"
        echo "$ci_out" | tail -10 | sed 's/^/    /'
      fi
      line=$(cert_lineage_for "$dom")
    fi
    [[ -z "$line" ]] && { warn "  #$id ($proto): останется БЕЗ серта — порт подниматься не будет"; continue; }
    cert="${line%% *}"; key="${line##* }"
    # ВАЖНО: sidecar-инбаунды (naive) берут серт из settings.certFile,
    # xray-инбаунды (trusttunnel/anytls/hysteria) — из stream_settings.
    # Пишем ОБА места, иначе x-ui пропускает инбаунд и он не слушает порт.
    python3 - "$XUI_DB" "$id" "$proto" "$dom" "$cert" "$key" "$SNI_CONF" <<'PY' && cnt=$((cnt+1))
import sqlite3, json, sys, re
db, i, proto, dom, cert, key, sni_conf = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6], sys.argv[7]
con = sqlite3.connect(db)
def one(sql, *a):
    return con.execute(sql, a).fetchone()
changed = False
if proto == "hysteria":
    st = json.loads((one("SELECT stream_settings FROM inbounds WHERE id=?", i)[0] or "{}"))
    st["network"] = st.get("network") or "udp"
    st["security"] = "tls"
    tls = st.get("tlsSettings") or {}
    tls["serverName"] = dom
    tls["certificates"] = [{"certificateFile": cert, "keyFile": key}]
    st["tlsSettings"] = tls
    con.execute("UPDATE inbounds SET stream_settings=? WHERE id=?", (json.dumps(st), i))
    changed = True
else:
    try:
        s = json.loads((one("SELECT settings FROM inbounds WHERE id=?", i)[0] or "{}"))
    except Exception:
        s = {}
    # БЕЗУСЛОВНО: ключа certFile может не быть (панель перегенерила settings) —
    # создаём. Иначе самолечение зацикливается: sync «вписал», проверка не видит.
    s["certFile"] = cert; s["keyFile"] = key
    con.execute("UPDATE inbounds SET settings=? WHERE id=?", (json.dumps(s), i))
    changed = True
    # Tunnel-класс LucX читает порт из settings.port; если панель его потеряла —
    # сервис не биндится. Восстанавливаем из SNI-маршрута (upstream inb_<id>_backend).
    if proto in ("naive", "naiveproxy", "anytls", "trusttunnel", "trust-tunnel", "tproxy") and not s.get("port"):
        try:
            m = re.search(r"inb_%d_backend\s*\{[^}]*?server[^\d]*127\.0\.0\.1:(\d+)" % i,
                          open(sni_conf, encoding="utf-8", errors="ignore").read(), re.S)
            if m:
                s["port"] = int(m.group(1))
                con.execute("UPDATE inbounds SET settings=? WHERE id=?", (json.dumps(s), i))
                print(f"  #{i} ({proto}): порт восстановлен из SNI-маршрута → {s['port']}")
        except Exception:
            pass
    if proto in ("anytls", "trusttunnel", "trust-tunnel", "vless"):
        st2 = json.loads((one("SELECT stream_settings FROM inbounds WHERE id=?", i)[0] or "{}"))
        if st2.get("security") not in (None, "", "tls"):
            pass   # reality и прочие — stream не трогаем
        else:
            st2["network"] = "tcp"; st2["security"] = "tls"
            st2["tlsSettings"] = {"serverName": dom, "certificates": [{"certificateFile": cert, "keyFile": key}]}
            con.execute("UPDATE inbounds SET stream_settings=? WHERE id=?", (json.dumps(st2), i))
con.commit()
if changed:
    print(f"  #{i} ({proto}): cert вписан ({dom} → {cert})")
    sys.exit(0)
print(f"  #{i} ({proto}): ПРЕДУПРЕЖДЕНИЕ: серт никуда не вписан — структура не распознана")
sys.exit(4)
PY
  done < <(python3 - "$XUI_DB" <<'PYROWS' 2>/dev/null
import sqlite3, json, sys
try:
    con = sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True, timeout=5)
    rows = con.execute("SELECT id, protocol, settings, stream_settings FROM inbounds WHERE enable=1 AND port>0").fetchall()
except Exception:
    sys.exit(0)
for iid, proto, setts_s, stream_s in rows:
    try:    se = json.loads(setts_s or "{}")
    except Exception: se = {}
    try:    st = json.loads(stream_s or "{}")
    except Exception: st = {}
    rs = st.get("realitySettings") or {}
    dom = se.get("domain") or se.get("hostname") or se.get("sni") \
          or (st.get("tlsSettings") or {}).get("serverName") \
          or (rs.get("serverNames") or [None])[0]
    dom = str(dom or "")   # None → пустая строка (bash-фильтр её отбросит)
    # json.dumps — гарантированно ОДНА строка, какими бы кривыми ни были данные в БД
    print(f"{iid}\x1f{proto}\x1f{dom}\x1f{json.dumps(st, ensure_ascii=False)}")
PYROWS
  )
  if [[ $cnt -gt 0 ]]; then
    systemctl start x-ui 2>/dev/null || true
    sleep 3
    log "Серты вписаны в $cnt инбаунд(ов), x-ui запущен"
  else
    systemctl start x-ui 2>/dev/null || true
  fi
  # дедупликация: серты только в /etc/letsencrypt/live/, зеркала /root/cert нет
  cert_dedup_migrate
  return 0
}

# --- Дедупликация сертификатов: live/ — единственное место -------------------
# Разово перепривязывает ВСЕ ссылки на зеркало /root/cert/ на
# /etc/letsencrypt/live/ (БД панели — строго при остановленном x-ui, конфиги
# nginx, yaml AdGuard) и удаляет саму папку-дубль. Идемпотентно: без ссылок
# и папки ничего не делает — безопасно звать из таймера самолечения.
cert_dedup_migrate() {
  [[ -z "$XUI_DB" || ! -f "$XUI_DB" ]] && return 0
  local refs=0
  refs=$(sqlite3 "$XUI_DB" "SELECT (SELECT COUNT(*) FROM settings WHERE value LIKE '/root/cert/%') + (SELECT COUNT(*) FROM inbounds WHERE settings LIKE '%/root/cert/%' OR stream_settings LIKE '%/root/cert/%');" 2>/dev/null || echo 0)
  if [[ "${refs:-0}" -gt 0 ]]; then
    systemctl stop x-ui 2>/dev/null || true
    python3 - "$XUI_DB" <<'PYDEDUP'
import sqlite3, sys
con = sqlite3.connect(sys.argv[1])
cur = con.cursor()
n = 0
for k, v in cur.execute("SELECT key, value FROM settings WHERE value LIKE '/root/cert/%'").fetchall():
    cur.execute("UPDATE settings SET value=? WHERE key=?", (v.replace('/root/cert/', '/etc/letsencrypt/live/'), k)); n += 1
for iid, s, st in cur.execute("SELECT id, settings, stream_settings FROM inbounds WHERE settings LIKE '%/root/cert/%' OR stream_settings LIKE '%/root/cert/%'").fetchall():
    cur.execute("UPDATE inbounds SET settings=?, stream_settings=? WHERE id=?",
                ((s or '').replace('/root/cert/', '/etc/letsencrypt/live/'),
                 (st or '').replace('/root/cert/', '/etc/letsencrypt/live/'), iid)); n += 1
con.commit()
print(f"  дедуп: в БД панели перепривязано ссылок: {n}")
PYDEDUP
    systemctl start x-ui 2>/dev/null || true
  fi
  local nf
  nf=$(grep -rl '/root/cert/' /etc/nginx/ 2>/dev/null | head -5)
  if [[ -n "$nf" ]]; then
    grep -rl '/root/cert/' /etc/nginx/ 2>/dev/null | while read -r f; do
      sed -i 's|/root/cert/|/etc/letsencrypt/live/|g' "$f" 2>/dev/null || true
      log "  дедуп: nginx-конфиг переведён на live: $(basename "$f")"
    done
    nginx -t >/dev/null 2>&1 && nginx_reload || true
  fi
  if [[ -f /opt/AdGuardHome/AdGuardHome.yaml ]] && grep -q '/root/cert/' /opt/AdGuardHome/AdGuardHome.yaml 2>/dev/null; then
    sed -i 's|/root/cert/|/etc/letsencrypt/live/|g' /opt/AdGuardHome/AdGuardHome.yaml 2>/dev/null || true
    systemctl restart AdGuardHome 2>/dev/null || systemctl restart adguardhome 2>/dev/null || true
    log "  дедуп: AdGuard переведён на live и перезапущен"
  fi
  if [[ -d /root/cert ]]; then
    rm -rf /root/cert 2>/dev/null || true
    [[ -d /root/cert ]] || log "  дедуп: зеркало /root/cert удалено — серты только в /etc/letsencrypt/live/"
  fi
  return 0
}

# --- Автопочинка после правок инбаундов в панели -----------------------------
# Панель при сохранении инбаунда (даже «просто добавил клиента») сбрасывает
# dest/пути сертов из своей памяти. Таймер stack-heal.timer (2 мин) гоняет
# лёгкую read-only проверку; самолечение запускается ТОЛЬКО при находке.

inbounds_need_heal() {
  [[ -z "$XUI_DB" || ! -f "$XUI_DB" ]] && return 1
  # python3 + read-only sqlite: не спотыкается о многострочный JSON в БД
  # и о блокировку записи (статистика панели), в отличие от sqlite3|while-read
  python3 - "$XUI_DB" <<'PYNEEDHEAL' 2>/dev/null
import sqlite3, json, socket, sys

def port_listens(p):
    s = socket.socket(); s.settimeout(1.5)
    try:
        s.connect(("127.0.0.1", p)); return True
    except Exception:
        return False
    finally:
        s.close()

try:
    con = sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True, timeout=5)
    rows = con.execute("SELECT id, protocol, settings, stream_settings FROM inbounds WHERE enable=1 AND port>0").fetchall()
except Exception:
    sys.exit(1)   # БД недоступна — не считаем поломкой

SKIP = {"qwdtt", "csqdtt", "csqtt", "wireguard", "amnezia", "amneziawg", "awg", "mtproto", "tun"}
FROZEN_INB = set()
try:
    FROZEN_INB = {l.strip().split(":",1)[1] for l in open("/root/stack-frozen.txt") if l.strip().startswith("inbound:")}
except Exception:
    pass
for iid, proto, setts_s, stream_s in rows:
    if proto in SKIP:
        continue
    if f"inbound:{iid}" in FROZEN_INB:
        continue
    try:    st = json.loads(stream_s or "{}")
    except Exception: st = {}
    try:    se = json.loads(setts_s or "{}")
    except Exception: se = {}
    rs = st.get("realitySettings") or {}
    dom = se.get("domain") or se.get("hostname") or se.get("sni") \
          or (st.get("tlsSettings") or {}).get("serverName") \
          or (rs.get("serverNames") or [None])[0]
    if not dom:
        continue
    if (st.get("security") or "").lower() == "reality":
        want = 4444 + iid
        dest = str(rs.get("dest") or rs.get("target") or "")
        if f"127.0.0.1:{want}" in dest and port_listens(want):
            continue                      # dest на живом decoy — ок
        sys.exit(0)                       # dest сбит панелью или decoy мёртв
    if (st.get("tlsSettings") or {}).get("certificates"):
        continue                          # серт вписан в stream (xray-класс)
    if se.get("certFile"):
        continue                          # серт вписан в settings (caddy-класс)
    # сервис жив и слушает свой порт → серт фактически работает; панель-менеджер
    # туннелей мог перегенерить settings — не считаем это поломкой (иначе цикл)
    try:
        _p = int(se.get("port") or 0)
    except Exception:
        _p = 0
    if _p and port_listens(_p):
        continue
    sys.exit(0)                           # серт не вписан
sys.exit(1)
PYNEEDHEAL
}

heal_once() {
  local hlog="/root/stack-heal.log"
  inbounds_need_heal || return 0
  {
    echo "[$(date '+%F %T')] обнаружены правки панели — автопочинка:"
    sync_inbound_certs
  } >> "$hlog" 2>&1
}

install_heal_timer() {
  [[ "${HEAL_TIMER_DONE:-}" == 1 ]] && return 0
  cat > /etc/systemd/system/stack-heal.service <<EOF
[Unit]
Description=Stack auto-heal after panel edits (stack-manager)
[Service]
Type=oneshot
ExecStart=/bin/bash -c 'source /root/stack-manager.sh </dev/null; detect_env; heal_once'
EOF
  cat > /etc/systemd/system/stack-heal.timer <<EOF
[Unit]
Description=Periodic stack auto-heal check
[Timer]
OnBootSec=2min
OnUnitActiveSec=2min
Unit=stack-heal.service
[Install]
WantedBy=timers.target
EOF
  systemctl daemon-reload 2>/dev/null || true
  systemctl enable --now stack-heal.timer 2>/dev/null || true
  HEAL_TIMER_DONE=1
  log "Автопочинка правок панели: stack-heal.timer (каждые 2 мин, лог /root/stack-heal.log)"
}

uninstall_heal_timer() {
  systemctl disable --now stack-heal.timer 2>/dev/null || true
  rm -f /etc/systemd/system/stack-heal.service /etc/systemd/system/stack-heal.timer
  systemctl daemon-reload 2>/dev/null || true
}

# =====================================================================
# МУЛЬТИСЕРТ (единый серт на все домены стека) + сохранение email LE
# =====================================================================
le_email_load() {
  [[ -n "$EMAIL" ]] && return 0
  [[ -s "$LE_EMAIL_FILE" ]] && EMAIL=$(head -n1 "$LE_EMAIL_FILE" 2>/dev/null | tr -d '[:space:]')
  [[ -n "$EMAIL" ]] && return 0
  return 1
}
le_email_save() {
  local e="${1:-$EMAIL}"
  [[ -z "$e" ]] && return 1
  mkdir -p "$(dirname "$LE_EMAIL_FILE")" 2>/dev/null || true
  printf '%s\n' "$e" > "$LE_EMAIL_FILE" 2>/dev/null || return 1
  chmod 600 "$LE_EMAIL_FILE" 2>/dev/null || true
  EMAIL="$e"
  return 0
}
le_email_forget() {
  rm -f "$LE_EMAIL_FILE" 2>/dev/null || true
  EMAIL=""
}

certs_view() {
  echo
  echo -e "${B}▸ Все сертификаты в /etc/letsencrypt/live/:${N}"
  certbot certificates 2>/dev/null | sed 's/^/  /' || true
  echo
  echo -e "${B}▸ Email Let's Encrypt:${N} ${EMAIL:-<не задан>}   (файл: $LE_EMAIL_FILE)"
  pause
}

cert_issue() {
  local d="$1"
  # невидимый хвост (пробел/CR из БД или ans-файла) ломает пути live/<домен> —
  # certbot нормализует имя, скрипт ищет файлы по «грязному» пути и не находит
  d="$(printf '%s' "$d" | tr -d '[:space:]')"
  frozen "ALL-CERTS" && { warn "cert_issue: сертификаты заморожены (ALL-CERTS) — «$d» пропущен"; return 1; }
  frozen "cert:$d" && { warn "cert_issue: «$d» в заморозке — пропуск"; return 1; }
  # ЖЁСТКИЙ ЗАПРЕТ: цели чужого reality — НЕ наши домены. Let's Encrypt серт
  # на них не выдаст (HTTP-01/DNS-01 недоступны), а спрашивать пользователя
  # «какой сертификат для www.samsung.com» — баг, какими бы путями домен
  # сюда ни приехал (утёкший serverNames из старой БД и т.п.).
  local _rt_x
  for _rt_x in "${REALITY_TARGETS[@]}"; do
    if [[ "$d" == "$_rt_x" ]]; then
      warn "cert_issue: «$d» — цель чужого reality, серт не нужен и невозможен (пропускаю)"
      return 1
    fi
  done

  local dir="/etc/letsencrypt/live/$d" arch="/etc/letsencrypt/archive/$d"

  # self-heal: флаг wildcard мог не загрузиться (source без точки входа)
  if [[ -z "$WILDCARD_DOMAIN" && -f "$WILDCARD_STATE" ]]; then
    WILDCARD_DOMAIN=$(head -n 1 "$WILDCARD_STATE" 2>/dev/null | tr -d '[:space:]' || true)
  fi

  local in_wc_zone=false
  [[ -n "$WILDCARD_DOMAIN" && ( "$d" == "$WILDCARD_DOMAIN" || "$d" == *."$WILDCARD_DOMAIN" ) ]] && in_wc_zone=true

  # email обязателен: пустой --email меняет параметры аккаунта — certbot не
  # переиспользует существующую линию и плодит дубли (-0001, -0002…)
  # ВАЖНО: базу отрезаем только если остаётся ещё точка — иначе для домена
  # вида zone.ru (две метки) получаем admin@ru и отказ ACME-сервера.
  if [[ -z "$EMAIL" ]]; then
    local eb="${d#*.}"
    [[ "$eb" != *.* ]] && eb="$d"
    EMAIL="admin@$eb"
    [[ "$EMAIL" =~ ^[^@]+@[^@]+\.[^@]+$ ]] || { err "  cert $d: EMAIL='$EMAIL' не похож на адрес — задай EMAIL и перезапусти"; return 1; }
  fi

  # --- проверка: сертификат уже установлен → переустанавливать не нужно ---
  if [[ "$in_wc_zone" == true ]]; then
    local wdir="/etc/letsencrypt/live/$WILDCARD_DOMAIN"
    if [[ -f "$wdir/fullchain.pem" && -f "$wdir/privkey.pem" ]]; then
      log "  cert $d: уже есть wildcard *.$WILDCARD_DOMAIN — используется он"
      return 0
    fi
  fi
  if [[ -f "$dir/fullchain.pem" && -f "$dir/privkey.pem" ]]; then
    log "  cert $d уже установлен — переустановка не нужна"
    return 0
  fi

  # --- авто-поиск установленного сертификата по SAN (работает даже без флага wildcard) ---
  local hit wcdir wcbase
  hit=$(find_covering_cert "$d") || hit=""
  if [[ -n "$hit" ]]; then
    wcdir="${hit%%|*}"; wcbase="${hit#*|}"
    log "  cert $d: найден установленный сертификат «$(basename "$wcdir")» — переустановка не нужна"
    # панель берёт пути из cert_mirror_to_certroot → live/
    cert_mirror_to_certroot "$wcdir" "$d" >/dev/null 2>&1 || true
    if [[ -n "$wcbase" ]]; then
      echo "$wcbase" > "$WILDCARD_STATE" 2>/dev/null || true
      WILDCARD_DOMAIN="$wcbase"
      log "  флаг wildcard восстановлен: *.$wcbase"
    fi
    return 0
  fi

  # --- восстановление из archive/ (если live-ссылки потеряны) ---
  if [[ -d "$arch" ]]; then
    log "  cert $d: восстановление из archive/"
    mkdir -p "$dir" 2>/dev/null || true
    local n=""
    n=$(ls -1 "$arch"/fullchain*.pem 2>/dev/null | sed -E 's/.*fullchain([0-9]+)\.pem/\1/' | sort -n | tail -1 || true)
    if [[ -n "$n" ]]; then
      local f
      for f in cert chain fullchain privkey; do
        [[ -f "$arch/$f$n.pem" ]] && ln -sf "../../archive/$d/$f$n.pem" "$dir/$f.pem"
      done
      chmod 700 "$dir" 2>/dev/null || true
      if [[ -f "$dir/fullchain.pem" && -f "$dir/privkey.pem" ]]; then
        log "  восстановлен (v$n)"
        # пути — live/ (единое место)
        cert_mirror_to_certroot "$dir" "$d" >/dev/null 2>&1 || true
        return 0
      fi
    fi
  fi

  # --- выпуск: выбор типа сертификата ---
  # CERT_MODE_CHOICE — выбор запоминается на сессию (1 вопрос на установку,
  # а не на каждый инбаунд). В ans-автоустановках (stdin не TTY) вопрос
  # не задаётся — режим уже выбран вопросом 2b.
  local mode="personal"
  local wbase="${d#*.}"
  [[ "$wbase" != *.* ]] && wbase="$d"   # d — сам базовый домен
  if [[ -n "${CERT_MODE_CHOICE:-}" ]]; then
    mode="$CERT_MODE_CHOICE"
  elif [[ -t 0 ]]; then
    echo "  Какой сертификат выпустить для $d?"
    echo "   1) Wildcard *.$wbase — Cloudflare DNS-01, покроет $wbase и все поддомены"
    echo "   2) Обычный персональный — только $d (HTTP-01)"
    local cm=""
    ask cm "Выбор [1/2]" "2" '^[12]$'
    if [[ "$cm" == "1" ]]; then
      mode="wildcard"
      CERT_MODE_CHOICE="wildcard"
    else
      CERT_MODE_CHOICE="personal"
    fi
  fi

  if [[ "$mode" == "wildcard" ]]; then
    if cert_wildcard_issue "${WILDCARD_DOMAIN:-$wbase}"; then
      log "  cert $d: используется wildcard *.${WILDCARD_DOMAIN:-$wbase}"
      return 0
    fi
    warn "  wildcard не выпущен — выпускаю персональный cert для $d"
    CERT_MODE_CHOICE="personal"
  fi

  # DNS-проверка (dual-stack): A-запись сверяется с IPv4 сервера, AAAA — с IPv6.
  # Совпадение ЛЮБОЙ пары = OK (ложный mismatch раньше был из-за IPv6-ответа ifconfig.me).
  local nA nAAAA
  nA=$(dig +short A "$d" @8.8.8.8 2>/dev/null | grep -cE '^[0-9]+(\.[0-9]+){3}$' || true)
  nAAAA=$(dig +short AAAA "$d" @8.8.8.8 2>/dev/null | grep -c ':' || true)
  [[ "${nA:-0}" -eq 0 && "${nAAAA:-0}" -eq 0 ]] && { err "  $d не резолвится"; return 1; }

  local ip4_server="" ip6_server="" dns_ok=false
  ip4_server=$(curl -4 -s --max-time 5 ifconfig.me 2>/dev/null | tr -d '[:space:]' || true)
  ip6_server=$(curl -6 -s --max-time 5 ifconfig.me 2>/dev/null | tr -d '[:space:]' || true)
  if [[ -z "$ip4_server" && -z "$ip6_server" ]]; then
    warn "  не удалось определить IP сервера — DNS-проверка пропущена"
  else
    if [[ -n "$ip4_server" ]] && dig +short A "$d" @8.8.8.8 2>/dev/null | grep -Fqx -- "$ip4_server"; then
      dns_ok=true
    fi
    if [[ "$dns_ok" != true && -n "$ip6_server" ]] && dig +short AAAA "$d" @8.8.8.8 2>/dev/null | grep -Fxi -- "$ip6_server"; then
      dns_ok=true
    fi
    if [[ "$dns_ok" != true ]]; then
      warn "  DNS mismatch: $d"
      warn "    A ($nA):    $(dig +short A "$d" @8.8.8.8 2>/dev/null | tr '\n' ' ')"
      warn "    AAAA:      $(dig +short AAAA "$d" @8.8.8.8 2>/dev/null | tr '\n' ' ')"
      warn "    сервер v4: $ip4_server"
      warn "    сервер v6: $ip6_server"
      local continue_anyway
      askyn continue_anyway "Продолжить выпуск несмотря на DNS?" "n"
      [[ "$continue_anyway" == true ]] || return 1
    fi
  fi

  log "  выпуск cert для $d..."
  local out="" nginx_was_active=false
  systemctl is-active --quiet nginx 2>/dev/null && nginx_was_active=true
  # 80 закрыт UFW (наш принцип) — но ACME-сервер стучится снаружи. Открываем
  # временно и закрываем после выпуска (standalone И webroot оба требуют :80 извне).
  local ufw_80_temp=false
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
    if ! ufw status 2>/dev/null | grep -qE "^80/tcp[[:space:]]+ALLOW"; then
      ufw allow 80/tcp comment "acme-temp" >/dev/null 2>&1 || true
      ufw_80_temp=true
      log "  UFW: 80/tcp временно открыт для ACME"
    fi
  fi
  mkdir -p /var/www/html 2>/dev/null || true

  if [[ "$nginx_was_active" == true ]]; then
    # nginx держит :80 — используем webroot (ACME-сервер :80 в stack.conf отдаёт /.well-known/acme-challenge/)
    # --keep-until-expiring: если валидный серт с этими доменами уже есть —
    # certbot обязан переиспользовать линию, а не создавать копию -0001
    out=$(certbot certonly --webroot -w /var/www/html --non-interactive --agree-tos --keep-until-expiring --email "$EMAIL" --cert-name "$d" -d "$d" 2>&1 || true)
    if [[ ! -f "$dir/fullchain.pem" || ! -f "$dir/privkey.pem" ]]; then
      warn "  webroot не сработал, пробуем standalone (nginx кратко остановим)"
      systemctl stop nginx 2>/dev/null || true
      out="$out
$(certbot certonly --standalone --non-interactive --agree-tos --keep-until-expiring --email "$EMAIL" --cert-name "$d" -d "$d" 2>&1 || true)"
      systemctl start nginx 2>/dev/null || true
    fi
  else
    out=$(certbot certonly --standalone --non-interactive --agree-tos --keep-until-expiring --email "$EMAIL" --cert-name "$d" -d "$d" 2>&1 || true)
  fi
  if [[ "$ufw_80_temp" == true ]]; then
    ufw delete allow 80/tcp >/dev/null 2>&1 || true
    log "  UFW: 80/tcp закрыт обратно"
  fi
  # certbot мог создать линию с суффиксом (-0001…) — подхватываем фактическую
  if [[ ! -f "$dir/fullchain.pem" || ! -f "$dir/privkey.pem" ]]; then
    local alt=""
    alt=$(ls -d /etc/letsencrypt/live/"$d"-* 2>/dev/null | sort | tail -1 || true)
    if [[ -n "$alt" && -f "$alt/fullchain.pem" && -f "$alt/privkey.pem" ]]; then
      dir="$alt"
      warn "  certbot создал линию с суффиксом: $(basename "$alt") — использую её"
    fi
  fi
  # «not yet due for renewal» = серт УЖЕ существует и валиден (certbot сам
  # проверил) — это УСПЕХ, а не отказ: берём фактическую линию и зеркалим.
  if grep -q "not yet due for renewal" <<<"$out"; then
    if [[ ! -f "$dir/fullchain.pem" ]]; then
      local alt2
      alt2=$(ls -d /etc/letsencrypt/live/"$d"-* 2>/dev/null | sort | tail -1 || true)
      [[ -n "$alt2" ]] && dir="$alt2"
    fi
    if [[ -f "$dir/fullchain.pem" && -f "$dir/privkey.pem" ]]; then
      log "  cert $d: уже действует (certbot: not yet due for renewal) — переустановка не нужна"
      local mline0=""
      mline0=$(cert_mirror_to_certroot "$dir" "$d" 2>/dev/null || true)
      [[ -n "$mline0" ]] && log "  OK (live: /etc/letsencrypt/live/$d/)" || log "  OK"
      return 0
    fi
  fi
  [[ -f "$dir/fullchain.pem" && -f "$dir/privkey.pem" ]] || {
    err "  certbot отказал для $d:"
    echo "$out" | tail -8 | sed 's/^/    /'
    local rl
    rl=$(echo "$out" | grep -oE "retry after [0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} UTC" | head -1 || true)
    [[ -n "$rl" ]] && err "  ЛИМИТ LET'S ENCRYPT (5 сертов/168ч): повторить после $rl — это НЕ баг скрипта"
    err "  ИТОГ: серт $d НЕ выпущен — инбаунд с этим доменом не поднимется"
    return 1
  }

  # пути — live/ (единое место)
  local mline=""
  mline=$(cert_mirror_to_certroot "$dir" "$d" 2>/dev/null || true)
  [[ -n "$mline" ]] && log "  OK (live: /etc/letsencrypt/live/$d/)" || log "  OK"
  return 0
}

# =====================================================================
# WILDCART СЕРТИФИКАТ CLOUDFLARE (DNS-01, один на все поддомены)
# =====================================================================
# Поиск УСТАНОВЛЕННОГО сертификата, покрывающего домен, по SAN всех live-сертификатов.
# Не зависит от флага WILDCARD_STATE. Печатает: "<live-dir>|<wcbase>" (wcbase пуст, если совпадение точное).
find_covering_cert() {
  local d="$1" ldir san entry base wcbase
  for ldir in /etc/letsencrypt/live/*/; do
    [[ -f "${ldir}fullchain.pem" && -f "${ldir}privkey.pem" ]] || continue
    san=$(openssl x509 -noout -ext subjectAltName -in "${ldir}cert.pem" 2>/dev/null | tail -n +2 | tr -d ' ' || true)
    [[ "$san" != *DNS:* ]] && continue
    wcbase=""
    while IFS= read -r entry; do
      entry="${entry#DNS:}"
      [[ -z "$entry" ]] && continue
      if [[ "$entry" == "$d" ]]; then
        echo "${ldir%/}|$wcbase"; return 0
      fi
      if [[ "$entry" == \** ]]; then
        base="${entry#\*.}"
        if [[ "$d" == "*.$base" || "$d" == "$base" ]]; then
          wcbase="$base"
          echo "${ldir%/}|$wcbase"; return 0
        fi
      fi
    done < <(tr ',\n' '\n\n' <<<"$san")
  done
  return 1
}

# Печатает "fullchain privkey" для домена: wildcard (если покрывает) → персональный
cert_paths() {
  local d="$1"
  # self-heal: флаг wildcard мог не загрузиться (например, при source без точки входа)
  if [[ -z "$WILDCARD_DOMAIN" && -f "$WILDCARD_STATE" ]]; then
    WILDCARD_DOMAIN=$(head -n 1 "$WILDCARD_STATE" 2>/dev/null | tr -d '[:space:]' || true)
  fi
  if [[ -n "$WILDCARD_DOMAIN" && ( "$d" == "$WILDCARD_DOMAIN" || "$d" == *."$WILDCARD_DOMAIN" ) ]]; then
    local wd="/etc/letsencrypt/live/$WILDCARD_DOMAIN"
    [[ -f "$wd/fullchain.pem" && -f "$wd/privkey.pem" ]] && { echo "$wd/fullchain.pem $wd/privkey.pem"; return 0; }
  fi
  local pd="/etc/letsencrypt/live/$d"
  [[ -f "$pd/fullchain.pem" && -f "$pd/privkey.pem" ]] && { echo "$pd/fullchain.pem $pd/privkey.pem"; return 0; }
  # флаг потерян — ищем покрывающий сертификат по SAN
  local hit wcdir
  hit=$(find_covering_cert "$d") || return 1
  wcdir="${hit%%|*}"
  echo "$wcdir/fullchain.pem $wcdir/privkey.pem"
  return 0
}

# --- МУЛЬТИСЕРТ (SAN): один серт на несколько доменов (в т.ч. РАЗНЫХ зон) ---
# Сосуществует с wildcard: cert_paths/find_covering_cert сами выберут wildcard
# для его зоны, а для остальных доменов найдут SAN в линии stack-multi.
# cert_issue при виде домена из списка тоже переиспользует SAN (find_covering_cert).
multi_cert_list() {
  [[ -f "$MULTI_CERT_FILE" ]] && grep -vE '^\s*(#|$)' "$MULTI_CERT_FILE" 2>/dev/null || true
}

multi_cert_rebuild() {
  frozen "ALL-CERTS" && { warn "мультисерт: серты заморожены (ALL-CERTS) — п.25"; return 1; }
  le_email_load || true
  if [[ -z "$EMAIL" ]]; then
    ask EMAIL "Email для Let's Encrypt" "" '^[^@]+@[^@]+\.[^@]+$'
    le_email_save "$EMAIL"
  fi
  local -a doms=()
  local d
  while IFS= read -r d; do
    d="$(printf '%s' "$d" | tr -d '[:space:]')"
    [[ -z "$d" ]] && continue
    frozen "cert:$d" && { warn "мультисерт: «$d» в заморозке — пропущен"; continue; }
    doms+=("-d" "$d")
  done < <(multi_cert_list)
  [[ ${#doms[@]} -gt 0 ]] || { err "список доменов пуст ($MULTI_CERT_FILE)"; return 1; }

  local dir="/etc/letsencrypt/live/$MULTI_CERT_NAME"
  log "  выпуск SAN-серта «$MULTI_CERT_NAME»: $(multi_cert_list | tr '\n' ' ')"
  local out="" nginx_was_active=false
  systemctl is-active --quiet nginx 2>/dev/null && nginx_was_active=true
  # 80 закрыт UFW — для HTTP-01 открываем временно (как в cert_issue)
  local ufw_80_temp=false
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
    if ! ufw status 2>/dev/null | grep -qE "^80/tcp[[:space:]]+ALLOW"; then
      ufw allow 80/tcp comment "acme-temp" >/dev/null 2>&1 || true
      ufw_80_temp=true
      log "  UFW: 80/tcp временно открыт для ACME"
    fi
  fi
  mkdir -p /var/www/html 2>/dev/null || true
  if [[ "$nginx_was_active" == true ]]; then
    out=$(certbot certonly --webroot -w /var/www/html --non-interactive --agree-tos --keep-until-expiring --email "$EMAIL" --cert-name "$MULTI_CERT_NAME" "${doms[@]}" 2>&1 || true)
    if [[ ! -f "$dir/fullchain.pem" || ! -f "$dir/privkey.pem" ]]; then
      warn "  webroot не сработал, пробуем standalone (nginx кратко остановим)"
      systemctl stop nginx 2>/dev/null || true
      out="$out
$(certbot certonly --standalone --non-interactive --agree-tos --keep-until-expiring --email "$EMAIL" --cert-name "$MULTI_CERT_NAME" "${doms[@]}" 2>&1 || true)"
      systemctl start nginx 2>/dev/null || true
    fi
  else
    out=$(certbot certonly --standalone --non-interactive --agree-tos --keep-until-expiring --email "$EMAIL" --cert-name "$MULTI_CERT_NAME" "${doms[@]}" 2>&1 || true)
  fi
  if [[ "$ufw_80_temp" == true ]]; then
    ufw delete allow 80/tcp >/dev/null 2>&1 || true
    log "  UFW: 80/tcp закрыт обратно"
  fi
  if [[ -f "$dir/fullchain.pem" && -f "$dir/privkey.pem" ]]; then
    log "  OK: SAN-серт «$MULTI_CERT_NAME» покрывает: $(multi_cert_list | tr '\n' ' ')"
    openssl x509 -noout -enddate -in "$dir/cert.pem" 2>/dev/null | sed 's/^/    /'
    return 0
  fi
  err "  certbot отказал:"
  echo "$out" | tail -8 | sed 's/^/    /'
  return 1
}

multi_cert_menu() {
  line; echo -e "${B}   МУЛЬТИСЕРТ (SAN) — один серт на несколько доменов${N}"; line
  echo "  Wildcard покрывает СВОЮ зону сам; SAN нужен для доменов ДРУГИХ зон."
  echo "  Резолвер сам выбирает серт: точный → wildcard → SAN (stack-multi)."
  echo
  echo "  Домены в списке:"
  if [[ -n "$(multi_cert_list)" ]]; then multi_cert_list | sed 's/^/    • /'; else echo "    (пусто)"; fi
  echo
  echo "   1) Показать серт (SAN + срок)"
  echo "   2) Добавить домен в список"
  echo "   3) Убрать домен из списка"
  echo "   4) Пересобрать серт по списку"
  echo "   5) Удалить серт stack-multi целиком"
  echo "   0) Назад"
  local a=""; ask a "Выбор" "0" '^[0-9]+$'
  local d=""
  case "$a" in
    1)
      local mdir="/etc/letsencrypt/live/$MULTI_CERT_NAME"
      if [[ -f "$mdir/cert.pem" ]]; then
        openssl x509 -noout -subject -enddate -ext subjectAltName -in "$mdir/cert.pem" 2>/dev/null | sed 's/^/  /'
      else warn "серт stack-multi ещё не выпущен — добавь домены и пересобери (п.4)"; fi
      ;;
    2)
      ask d "Домен (напр. vpn.other-zone.ru)" "" '^[a-zA-Z0-9.-]+$'
      [[ -z "$d" ]] && return 0
      grep -qxF "$d" "$MULTI_CERT_FILE" 2>/dev/null || printf '%s\n' "$d" >> "$MULTI_CERT_FILE"
      log "в списке: $d (не забудь пересобрать — п.4)"
      ;;
    3)
      [[ -f "$MULTI_CERT_FILE" ]] || { warn "списка нет"; pause; return 0; }
      multi_cert_list | nl -ba | sed 's/^/  /'
      ask d "Домен для удаления" "" '^[a-zA-Z0-9.-]+$'
      [[ -z "$d" ]] && return 0
      sed -i "/^${d//./\\.}$/d" "$MULTI_CERT_FILE"
      log "убран: $d (пересобери — п.4)"
      ;;
    4) multi_cert_rebuild ;;
    5)
      if [[ -f "/etc/letsencrypt/live/$MULTI_CERT_NAME/cert.pem" ]]; then
        local dl=""; askyn dl "Удалить серт stack-multi и список доменов?" "n"
        if [[ "$dl" == true ]]; then
          certbot delete --cert-name "$MULTI_CERT_NAME" -n >/dev/null 2>&1
          rm -f "$MULTI_CERT_FILE"
          log "мультисерт удалён"
        fi
      else warn "серта нет"; fi
      ;;
    *) return 0 ;;
  esac
  pause
}

# Выпуск wildcard: base + *.base через Cloudflare DNS-01
# base можно передать аргументом; если wildcard уже выпущен и свеж — переустановки не будет
cert_wildcard_issue() {
  le_email_load || true
  if [[ -z "$EMAIL" ]]; then
    ask EMAIL "Email для Let's Encrypt" "" '^[^@]+@[^@]+\.[^@]+$'
    le_email_save "$EMAIL"
  fi
  local base="${1:-}"
  if [[ -z "$base" ]]; then
    ask base "Базовый домен wildcard (напр. example.com)" "${WILDCARD_DOMAIN:-}" '^[a-zA-Z0-9.-]+$'
  fi
  [[ -z "$base" ]] && return 1

  # --- проверка: wildcard уже установлен → переустанавливать не нужно ---
  local wdir="/etc/letsencrypt/live/$base"
  if [[ -f "$wdir/fullchain.pem" && -f "$wdir/privkey.pem" ]]; then
    local exp="" days_left=-1
    exp=$(openssl x509 -enddate -noout -in "$wdir/fullchain.pem" 2>/dev/null | cut -d= -f2 || true)
    [[ -n "$exp" ]] && days_left=$(( ( $(date -d "$exp" +%s 2>/dev/null || echo 0) - $(date +%s) ) / 86400 ))
    if [[ "$days_left" -gt 30 ]]; then
      echo "$base" > "$WILDCARD_STATE" 2>/dev/null || true
      WILDCARD_DOMAIN="$base"
      log "Wildcard *.$base уже выпущен (истекает через $days_left дн.) — переустановка не нужна"
      return 0
    fi
    warn "Wildcard *.$base истекает через $days_left дн. — обновляю"
  fi

  # плагин DNS-01 для Cloudflare
  if ! certbot plugins 2>/dev/null | grep -q dns-cloudflare; then
    log "Установка плагина python3-certbot-dns-cloudflare..."
    apt-get update -y >/dev/null 2>&1 || true
    apt-get install -y python3-certbot-dns-cloudflare >/dev/null 2>&1 \
      || { err "Не удалось установить python3-certbot-dns-cloudflare"; return 1; }
  fi

  # API Token (сохраняется один раз)
  local need_token=true
  if [[ -f "$CF_CREDS" ]] && grep -q 'dns_cloudflare_api_token' "$CF_CREDS" 2>/dev/null; then
    askyn reuse "Использовать сохранённый Cloudflare API Token ($CF_CREDS)?" "y"
    [[ "$reuse" == true ]] && need_token=false
  fi
  if [[ "$need_token" == true ]]; then
    echo "Создайте токен: Cloudflare → My Profile → API Tokens → 'Edit zone DNS'"
    echo "Права: Zone / DNS / Edit для зоны $base"
    local token=""
    ask token "Cloudflare API Token" "" '.+'
    mkdir -p "$(dirname "$CF_CREDS")" 2>/dev/null || true
    cat > "$CF_CREDS" <<EOF
# Cloudflare API Token (Zone:DNS:Edit) — для wildcard-сертификатов
dns_cloudflare_api_token = $token
EOF
    chmod 600 "$CF_CREDS" 2>/dev/null || true
  fi

  log "Выпуск wildcard: $base + *.$base (DNS-01 Cloudflare)..."
  local out=""
  out=$(certbot certonly \
    --dns-cloudflare \
    --dns-cloudflare-credentials "$CF_CREDS" \
    --dns-cloudflare-propagation-seconds 30 \
    --non-interactive --agree-tos --email "$EMAIL" \
    --cert-name "$base" \
    -d "$base" -d "*.$base" 2>&1 || true)

  local wdir="/etc/letsencrypt/live/$base"
  if [[ -f "$wdir/fullchain.pem" && -f "$wdir/privkey.pem" ]]; then
    # хук перезагрузки nginx после автопродления
    mkdir -p /etc/letsencrypt/renewal-hooks-deploy 2>/dev/null || true
    cat > /etc/letsencrypt/renewal-hooks-deploy/reload-nginx.sh <<'HOOK'
#!/bin/sh
systemctl reload nginx 2>/dev/null || true
HOOK
    chmod +x /etc/letsencrypt/renewal-hooks-deploy/reload-nginx.sh 2>/dev/null || true
    echo "$base" > "$WILDCARD_STATE" 2>/dev/null || true
    WILDCARD_DOMAIN="$base"
    log "Wildcard cert готов: $wdir"
    log "  покрывает: $base и *.$base — персональные сертификаты больше не нужны"
    return 0
  fi
  err "  certbot отказал:"; echo "$out" | tail -8 | sed 's/^/    /'
  return 1
}

wildcard_toggle() {
  echo
  echo "▸ Wildcard Cloudflare: ${WILDCARD_DOMAIN:-выключен}"
  if [[ -n "$WILDCARD_DOMAIN" ]]; then
    echo "  1) отключить (вернуть приоритет персональным сертификатам)"
    echo "  2) сменить базовый домен / перевыпустить"
    echo "  0) Назад"
    local c=""
    ask c "Выбор" "0" '^[0-9]$'
    case "$c" in
      1) rm -f "$WILDCARD_STATE" 2>/dev/null || true; WILDCARD_DOMAIN=""; log "Wildcard отключён" ;;
      2) cert_wildcard_issue ;;
    esac
  else
    local on=false
    askyn on "Включить wildcard — один cert Cloudflare на все поддомены?" "y"
    [[ "$on" == true ]] && cert_wildcard_issue
  fi
}

# =====================================================================
# NGINX ХЕЛПЕРЫ
# =====================================================================
sni_upstream_add() {
  local name="$1" port="$2"
  grep -q "upstream $name " "$SNI_CONF" 2>/dev/null && return 0
  if grep -q "^upstream panel_backend" "$SNI_CONF" 2>/dev/null; then
    sed -i "/^upstream panel_backend/i upstream $name { server 127.0.0.1:$port; }" "$SNI_CONF"
  else
    # нет якоря panel_backend — вставляем в начало файла
    sed -i "1i upstream $name { server 127.0.0.1:$port; }" "$SNI_CONF"
  fi
}
sni_upstream_remove() { sed -i "/^upstream $1 /d" "$SNI_CONF" 2>/dev/null || true; }

sni_map_add() {
  local domain="$1" backend="$2"
  if grep -qE "^\s+$domain\s+" "$SNI_CONF" 2>/dev/null; then
    sed -i "s|^\s*$domain\s\+.*|    $domain    $backend;|" "$SNI_CONF"; return 0
  fi
  awk -v dom="$domain" -v be="$backend" '
    /^map / { inmap=1 }
    inmap && /^}/ && !done { print "    " dom "    " be ";"; done=1 }
    { print }
  ' "$SNI_CONF" > "$SNI_CONF.tmp" && mv "$SNI_CONF.tmp" "$SNI_CONF"
}
sni_map_remove() { sed -i "/^\s*$1\s\+/d" "$SNI_CONF" 2>/dev/null || true; }

nginx_reload() {
  if ! nginx -t 2>/dev/null; then
    err "Nginx test failed"; nginx -t 2>&1 | tail -5 | sed 's/^/  /'
    return 1
  fi
  if systemctl is-active --quiet nginx 2>/dev/null; then
    systemctl reload nginx 2>/dev/null && { log "Nginx перезагружен"; return 0; }
  fi
  systemctl start nginx 2>/dev/null && { log "Nginx запущен"; return 0; }
  return 1
}

ensure_stream_include() {
  grep -q "streams-enabled" /etc/nginx/nginx.conf 2>/dev/null && return 0
  if ! grep -qE '^\s*stream\s*\{' /etc/nginx/nginx.conf 2>/dev/null; then
    sed -i '/^\s*http\s*{/i stream {\n    include /etc/nginx/streams-enabled/*.conf;\n}\n' /etc/nginx/nginx.conf
  else
    sed -i '/^\s*stream\s*{/a \    include /etc/nginx/streams-enabled/*.conf;' /etc/nginx/nginx.conf
  fi
}

# =====================================================================
# ФАЕРВОЛ
# =====================================================================
save_firewall_state() {
  mkdir -p "$FW_STATE_DIR" 2>/dev/null || true
  [[ -f "$FW_STATE_DIR/saved" ]] && { log "Снимок уже есть"; return 0; }
  {
    if command -v ufw >/dev/null 2>&1; then
      echo 'UFW_WAS_INSTALLED=1'
      ufw status 2>/dev/null | grep -q '^Status: active' && echo 'UFW_WAS_ACTIVE=1' || echo 'UFW_WAS_ACTIVE=0'
    else
      echo 'UFW_WAS_INSTALLED=0'; echo 'UFW_WAS_ACTIVE=0'
    fi
  } > "$FW_STATE_DIR/state"
  tar -cpf "$FW_STATE_DIR/ufw-config.tar" /etc/ufw /etc/default/ufw 2>/dev/null || true
  iptables-save  > "$FW_STATE_DIR/iptables.v4" 2>/dev/null || true
  ip6tables-save > "$FW_STATE_DIR/iptables.v6" 2>/dev/null || true
  touch "$FW_STATE_DIR/saved"
  log "Снимок: $FW_STATE_DIR"
}

restore_firewall_state() {
  line; echo -e "${B}   ВОССТАНОВЛЕНИЕ ФАЕРВОЛА${N}"; line
  [[ ! -f "$FW_STATE_DIR/saved" ]] && { warn "Снимок не найден"; pause; return 1; }
  askyn confirm "Восстановить?" "n"
  [[ "$confirm" == true ]] || return 0
  audit "firewall: восстановление состояния из снимка"
  # shellcheck disable=SC1090
  . "$FW_STATE_DIR/state" 2>/dev/null || true
  [[ -f "$FW_STATE_DIR/iptables.v4" ]] && iptables-restore  < "$FW_STATE_DIR/iptables.v4"  2>/dev/null || true
  [[ -f "$FW_STATE_DIR/iptables.v6" ]] && ip6tables-restore < "$FW_STATE_DIR/iptables.v6"  2>/dev/null || true
  if [[ "${UFW_WAS_INSTALLED:-0}" == "1" && -f "$FW_STATE_DIR/ufw-config.tar" ]]; then
    tar -xpf "$FW_STATE_DIR/ufw-config.tar" -C / 2>/dev/null || true
    [[ "${UFW_WAS_ACTIVE:-0}" == "1" ]] && ufw --force enable >/dev/null 2>&1 || ufw --force disable >/dev/null 2>&1
  fi
  rm -f "$FW_STATE_DIR/saved"
  log "Восстановлено"; pause
}

# =====================================================================
# DECOY ВЫБОР
# =====================================================================
decoy_template_choose() {
  local __result="$1" prompt="${2:-Выберите decoy-шаблон}" default="${3:-default}"
  echo >&2; echo -e "${B}Доступные decoy-шаблоны — страница-ЗАГЛУШКА:${N}" >&2
  echo -e "   (её увидит посторонний, открыв домен в браузере; на работу протокола не влияет)" >&2
  local i=1
  local -a NAMES=()
  local __t
  for __t in "${DECOY_TEMPLATES[@]}"; do
    local __n="${__t%%|*}" __dsc="${__t##*|}"
    printf "  %2d) %-15s %s\n" "$i" "$__n" "$__dsc" >&2
    NAMES+=("$__n"); i=$((i+1))
  done
  local __custom_num=$i
  printf "  %2d) %-15s %s\n" "$__custom_num" "custom" "▶ Свой сайт — папка со статикой (index.html и т.д.)" >&2
  echo >&2
  local __c=""
  ask __c "$prompt" "$default" '^[0-9]+$|^[a-z:_/.-]+$' 2>/dev/null || { printf -v "$__result" '%s' "$default"; return 0; }
  if [[ "$__c" == "custom" || "$__c" == "$__custom_num" || "$__c" == custom:* ]]; then
    local __path=""
    [[ "$__c" == custom:* ]] && __path="${__c#custom:}"
    if [[ -z "$__path" ]]; then
      while :; do
        __path=""
        ask __path "Путь к папке сайта (index.html обязателен)" "/var/www/mysite" '^/.+'
        [[ -d "$__path" ]] || { err "Папка $__path не существует"; continue; }
        if [[ ! -f "$__path/index.html" ]]; then
          warn "В $__path нет index.html — nginx отдаст 404"
          local __go=""
          askyn __go "Продолжить всё равно?" "n"
          [[ "$__go" == true ]] || continue
        fi
        break
      done
    fi
    if command -v sudo >/dev/null 2>&1 && ! sudo -u www-data test -r "$__path/index.html" 2>/dev/null; then
      warn "www-data не может читать $__path/index.html — nginx отдаст 403"
      local __fix=""
      askyn __fix "Исправить права (chmod -R o+rX)?" "y"
      if [[ "$__fix" == true ]]; then
        chmod -R o+rX "$__path" 2>/dev/null || true
        log "Права исправлены: $__path"
      fi
    fi
    printf -v "$__result" '%s' "custom:$__path"
    return 0
  fi
  if [[ "$__c" =~ ^[0-9]+$ ]]; then
    if (( __c >= 1 && __c <= ${#NAMES[@]} )); then
      printf -v "$__result" '%s' "${NAMES[$((__c-1))]}"
    else
      printf -v "$__result" '%s' "$default"
    fi
  else
    printf -v "$__result" '%s' "$__c"
  fi
}

# =====================================================================
# ЕДИНЫЙ HTTP-КОНФИГ (sites-available/stack.conf)
#   ACME :80 + панель :4443 + все decoy-блоки — в одном файле.
#   Stream-часть (SNI-роутер) обязана жить в streams-enabled/sni-router.conf:
#   в sites-available можно класть только http-контекст.
# =====================================================================
stack_ensure() {
  mkdir -p "$NGINX_SITES_AVAIL" "$NGINX_SITES_DIR" 2>/dev/null || true
  [[ -f "$STACK_CONF" ]] || printf '# stack-manager: единый конфиг (ACME :80, панель :4443, decoy)\n' > "$STACK_CONF"
  # формат лога декоёв: с доменом (host=) — нужен для статистики и бана смотревших
  if ! grep -q "log_format decoy_ext" "$STACK_CONF" 2>/dev/null; then
    sed -i "1i log_format decoy_ext '\$remote_addr [\$time_local] \"\$request\" \$status \"\$http_user_agent\" host=\$host';" "$STACK_CONF"
  fi
  [[ -e "$STACK_LINK" || -L "$STACK_LINK" ]] || ln -sf "$STACK_CONF" "$STACK_LINK"
  return 0
}

# удалить decoy-блок по домену (маркеры # >>> decoy ... domain=X)
stack_del_decoy() {
  local dom="$1"
  [[ -f "$STACK_CONF" ]] || return 0
  local tmp
  tmp=$(mktemp)
  awk -v dom="$dom" '
    !skip && index($0, "# >>> decoy ") == 1 {
      tail = $0
      sub(/^.* domain=/, "", tail)
      if (tail == dom) { skip = 1; next }
    }
    skip && index($0, "# <<< decoy ") == 1 { skip = 0; next }
    !skip { print }
  ' "$STACK_CONF" > "$tmp" 2>/dev/null && mv "$tmp" "$STACK_CONF"
}

# удалить ВСЕ decoy-блоки
stack_del_all_decoy() {
  [[ -f "$STACK_CONF" ]] || return 0
  local tmp
  tmp=$(mktemp)
  awk '
    index($0, "# >>> decoy ") == 1 { skip = 1; next }
    skip && index($0, "# <<< decoy ") == 1 { skip = 0; next }
    !skip { print }
  ' "$STACK_CONF" > "$tmp" 2>/dev/null && mv "$tmp" "$STACK_CONF"
}

# метаданные decoy по домену:  port root cert key
stack_decoy_meta() {
  local dom="$1" line=""
  [[ -f "$STACK_CONF" ]] || return 1
  local esc="${dom//./\\.}"
  line=$(grep -m1 -E "# >>> decoy .*domain=${esc}([[:space:]]|\$)" "$STACK_CONF" 2>/dev/null || true)
  [[ -z "$line" ]] && return 1
  local port root cert key
  port=$(grep -oE 'port=[0-9]+'   <<<"$line" | head -1 | cut -d= -f2)
  root=$(grep -oE 'root=[^ ]+'    <<<"$line" | head -1 | cut -d= -f2-)
  cert=$(grep -oE 'cert=[^ ]+'    <<<"$line" | head -1 | cut -d= -f2-)
  key=$(grep -oE 'key=[^ ]+'      <<<"$line" | head -1 | cut -d= -f2-)
  echo "$port $root $cert $key"
}

mk_decoy() {
  # $1..$6 как раньше; $7 (необязательно) — opts: "ua404=1 redir=https://..."
  local port="$1" dom="$2" cert="$3" key="$4" root="$5"
  local tpl="${6:-default}" opts="${7:-}"
  local opt_ua404=1 opt_redir=""
  local _o _k _v
  for _o in $opts; do
    _k="${_o%%=*}"; _v="${_o#*=}"
    case "$_k" in
      ua404) opt_ua404="$_v" ;;
      redir) opt_redir="$_v" ;;
    esac
  done
  # custom:<path> — nginx будет служить прямо из указанной папки
  if [[ "$tpl" == custom:* ]]; then
    root="${tpl#custom:}"
    tpl="custom"
  fi
  mkdir -p "$root" 2>/dev/null || true

  # security-заголовки decoy: сниппет должен существовать до nginx -t
  mkdir -p /etc/nginx/snippets 2>/dev/null || true
  [[ -f /etc/nginx/snippets/decoy-headers.conf ]] || cat > /etc/nginx/snippets/decoy-headers.conf <<'EOF'
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "SAMEORIGIN" always;
add_header Referrer-Policy "no-referrer-when-downgrade" always;
EOF

  # index.html: login-реплики из DECOY_LOGIN_DIR, статика из DECOY_TPL_DIR
  if [[ "$tpl" != "custom" ]]; then
    local tpl_src="$DECOY_TPL_DIR/$tpl.html"
    is_login_template "$tpl" && tpl_src="$DECOY_LOGIN_DIR/$tpl.html"
    if [[ -f "$tpl_src" ]]; then
      cp -f "$tpl_src" "$root/index.html" 2>/dev/null || true
    elif [[ "$tpl" != redirect && "$tpl" != locked ]]; then
      cp -f "$DECOY_TPL_DIR/default.html" "$root/index.html" 2>/dev/null || true
    fi
    chown www-data:www-data "$root/index.html" 2>/dev/null || true
  fi

  # redirect/locked: ответ формирует сам nginx, index не нужен
  local extra=""
  case "$tpl" in
    redirect)
      [[ -z "$opt_redir" ]] && opt_redir="https://www.google.com/"
      extra="    return 302 $opt_redir;"
      ;;
    locked)
      extra='    add_header WWW-Authenticate "Basic realm=Restricted" always;
    return 401;'
      ;;
  esac

  # UA-свитч: сканерам/ботам — пустая 404 (в лог попадает → банов не миновать)
  local ua_block=""
  if [[ "$opt_ua404" == "1" && "$tpl" != "redirect" && "$tpl" != "locked" ]]; then
    ua_block='    if ($http_user_agent ~* (curl|wget|python|scrapy|httpclient|okhttp|go-http|libwww|zgrab|nikto|dirbuster|gobuster|wfuzz|nuclei|masscan|headless|bot|spider|crawler|scanner)) { return 404; }'
  fi

  local body
  body=$(cat <<EOF
server {
    listen 127.0.0.1:$port ssl;
    server_name $dom;
    ssl_certificate     $cert;
    ssl_certificate_key $key;
    include /etc/nginx/snippets/decoy-headers.conf;
    root $root;
    index index.html;
    access_log $DECOY_LOG_ACCESS decoy_ext;
    error_log  /var/log/nginx/decoy-error.log;
$extra
$ua_block
    location = /robots.txt { return 200 "User-agent: *\nDisallow: /\n"; }
    location ~ ^/(admin|wp-admin|wp-login\.php|\.env|\.git|api/debug|phpmyadmin|configuration\.php|actuator)(/|\$|\?) { return 404; }
    location / { try_files \$uri \$uri/ /index.html; }
    location = /login { limit_except POST { deny all; } return 401; }
}
EOF
)

  stack_ensure
  stack_del_decoy "$dom"   # замена блока того же домена (upsert)
  {
    # ВАЖНО: domain= держим ПОСЛЕДНИМ ключом — парсеры маркера на это рассчитаны
    echo "# >>> decoy port=$port root=$root cert=$cert key=$key tpl=$tpl ua404=$opt_ua404 domain=$dom"
    echo "$body"
    echo "# <<< decoy port=$port domain=$dom"
  } >> "$STACK_CONF"
}

# =====================================================================
# SNI ДЛЯ ИНБАУНДА
# =====================================================================
# Reality dest → локальный decoy nginx (внутренний IP:порт decoy-конфа)
# + синхронизация serverNames с выбранным SNI-доменом.
# Если домен пустой или www.microsoft.com — ничего не меняем (остаётся microsoft).
reality_set_dest() {
  local id="$1" decoy_port="$2" dom="${3:-}" stream=""
  stream=$(sqlite3 "$XUI_DB" "SELECT COALESCE(stream_settings,'') FROM inbounds WHERE id=$id;" 2>/dev/null || true)
  grep -qi reality <<<"$stream" || return 0
  local new_stream
  # новые панели (xray 25+) читают «Цель» из target, старые — из dest: пишем ОБА ключа
  new_stream=$(sqlite3 "$XUI_DB" "SELECT json_set(stream_settings,'$.realitySettings.dest','127.0.0.1:$decoy_port','$.realitySettings.target','127.0.0.1:$decoy_port') FROM inbounds WHERE id=$id;" 2>/dev/null || true)
  # проверяем, что dest/target действительно заменены; иначе fallback на sed
  if [[ -z "$new_stream" || "$new_stream" == "null" ]] || ! grep -Eq "\"(dest|target)\": ?\"127\.0\.0\.1:$decoy_port\"" <<<"$new_stream"; then
    new_stream=$(sed -E "s/\"(dest|target)\"([[:space:]]*:[[:space:]]*)\"[^\"]*\"/\"\1\"\2\"127.0.0.1:$decoy_port\"/g" <<<"$stream")
  fi
  # если какого-то из ключей вообще не было — вставляем внутрь realitySettings
  grep -Eq "\"dest\": ?\"127\.0\.0\.1:$decoy_port\"" <<<"$new_stream" \
    || new_stream=$(sed -E "s/\"realitySettings\": ?\{/\"realitySettings\":{\"dest\":\"127.0.0.1:$decoy_port\",/" <<<"$new_stream")
  grep -Eq "\"target\": ?\"127\.0\.0\.1:$decoy_port\"" <<<"$new_stream" \
    || new_stream=$(sed -E "s/\"realitySettings\": ?\{/\"realitySettings\":{\"target\":\"127.0.0.1:$decoy_port\",/" <<<"$new_stream")
  grep -Eq "\"(dest|target)\": ?\"127\.0\.0\.1:$decoy_port\"" <<<"$new_stream" || { warn "  не удалось обновить reality dest (инбаунд #$id)"; return 1; }
  # serverNames → выбранный SNI-домен (если он задан и ещё не в списке)
  if [[ -n "$dom" && "$dom" != "www.microsoft.com" ]] && ! grep -q "\"$dom\"" <<<"$new_stream"; then
    new_stream=$(sed -E "s/\"serverNames\"[[:space:]]*:[[:space:]]*\[[^]]*\]/\"serverNames\":[\"$dom\"]/" <<<"$new_stream")
  fi
  sqlite3 "$XUI_DB" "UPDATE inbounds SET stream_settings='$new_stream' WHERE id=$id;" 2>/dev/null || true
  log "  Reality dest → 127.0.0.1:$decoy_port (decoy nginx)"
  return 0
}

# Вставить/обновить запись hosts в панели для TCP-инбаунда (адрес=домен, порт 443).
# Нужна ВСЕМ TCP-инбаундам (vless, naive, anytls, trusttunnel, tproxy…) — иначе
# в подписках панели нет ссылок через 443. Таблицы может не быть — пропускаем.
#   $1 = inbound_id, $2 = адрес (домен панели/IP), $3 = SNI (СТАРЫЙ смысл).
# ПОЛЕ SNI («безопасность» в hosts) БОЛЬШЕ НЕ ЗАПОЛНЯЕМ — панель на него ругается.
# Исключение: чужой reality (dest = внешняя цель ≠ 127.0.0.1) — там SNI=цель
# обязателен, иначе подписочная ссылка теряет нужный serverName.
hosts_upsert() {   # <inbound_id> <address> [sni]
  [[ -z "$XUI_DB" || ! -f "$XUI_DB" ]] && return 0
  local id="$1" dom="$2" sni="${3:-}"
  [[ -z "$id" || -z "$dom" || "$dom" == "null" ]] && return 0
  if [[ -n "$sni" ]]; then
    local _dest=""
    _dest=$(sqlite3 -cmd ".timeout 3000" "$XUI_DB" \
            "SELECT COALESCE(json_extract(stream_settings,'\$.realitySettings.dest'),'') FROM inbounds WHERE id=$id;" 2>/dev/null | tr -d '[:space:]') || true
    if [[ -z "$_dest" || "$_dest" == 127.0.0.1:* ]]; then
      sni=""   # своё reality (decoy) или не-reality — поле SNI оставляем пустым
    fi
    # чужой reality: sni = переданная цель — оставляем как есть
  fi
  local has_hosts
  has_hosts=$(sqlite3 -cmd ".timeout 3000" "$XUI_DB" "SELECT name FROM sqlite_master WHERE type='table' AND name='hosts';" 2>/dev/null || true)
  [[ -z "$has_hosts" ]] && return 0
  local cols
  cols=$(sqlite3 -cmd ".timeout 3000" "$XUI_DB" "PRAGMA table_info(hosts);" 2>/dev/null | awk -F'|' '{print $2}' | tr '\n' ' ')
  local remark
  remark=$(sqlite3 -cmd ".timeout 3000" "$XUI_DB" "SELECT remark FROM inbounds WHERE id=$id;" 2>/dev/null || true)
  sqlite3 -cmd ".timeout 3000" "$XUI_DB" "DELETE FROM hosts WHERE inbound_id=$id AND port=443;" 2>/dev/null || true
  local fields="inbound_id,address,port" vals="$id,'$dom',443"
  grep -qw remark       <<<"$cols" && { fields+=",remark";       vals+=",'$(printf '%s' "$remark" | sed "s/'/''/g")'"; }
  grep -qw sni          <<<"$cols" && { fields+=",sni";          vals+=",'$sni'"; }
  grep -qw fingerprint  <<<"$cols" && { fields+=",fingerprint";  vals+=",'firefox'"; }
  grep -qw is_disabled  <<<"$cols" && { fields+=",is_disabled";  vals+=",0"; }
  grep -qw enable       <<<"$cols" && { fields+=",enable";       vals+=",1"; }
  if sqlite3 -cmd ".timeout 3000" "$XUI_DB" "INSERT INTO hosts ($fields) VALUES ($vals);" 2>/dev/null; then
    log "  hosts: #$id → $dom:443 ✓"
  else
    warn "  hosts: вставка для #$id не прошла — проверь схему таблицы hosts"
  fi
  return 0
}

# ЧУЖОЙ реалити за 443 (доктрина «всё за 443»): dest/serverNames = цель,
# SNI-роутер отдаёт имя цели инбаунду, слушаем 127.0.0.1 — tcp-порт
# инбаунда наружу НЕ открываем. Аргументы: <inbound_id> <target> [port]
reality_ext_hide() {
  local id="$1" tdom="$2" port="${3:-}"
  [[ -z "$id" || -z "$tdom" ]] && return 1
  # ВАЖНО: x-ui хранит состояние in-memory — правки БД только при ОСТАНОВЛЕННОЙ
  # панели, иначе при рестарте panel state перетирает dest/serverNames/listen
  local xui_was=""
  if systemctl is-active --quiet x-ui 2>/dev/null; then
    xui_was=1
    systemctl stop x-ui >/dev/null 2>&1 || true
    sleep 1
  fi
  local stream="" new_stream=""
  stream=$(sqlite3 "$XUI_DB" "SELECT COALESCE(stream_settings,'') FROM inbounds WHERE id=$id;" 2>/dev/null || true)
  if [[ -n "$stream" ]]; then
    new_stream=$(sed -E "s/\"(dest|target)\": ?\"[^\"]*\"/\"\\1\":\"$tdom:443\"/g; s/\"serverNames\"[[:space:]]*:[[:space:]]*\[[^]]*\]/\"serverNames\":[\"$tdom\"]/" <<<"$stream")
    sqlite3 "$XUI_DB" "UPDATE inbounds SET stream_settings='$new_stream' WHERE id=$id;" 2>/dev/null || true
  fi
  [[ -n "$port" ]] && sni_upstream_add "inb_${id}_backend" "$port"
  sni_map_add "$tdom" "inb_${id}_backend"
  SNI_USED["$tdom"]="inb_${id}_backend"
  # кеш цели = фактическая цель: будущие сборки stream возьмут тот же домен,
  # что и в nginx (иначе клиент получит другой serverNames → таймаут)
  printf '%s' "$tdom" > /tmp/.reality-found-target 2>/dev/null || true
  sqlite3 "$XUI_DB" "UPDATE inbounds SET listen='127.0.0.1' WHERE id=$id;" 2>/dev/null || true
  # подписки: адрес = домен панели (валидный серт), SNI = serverNames ЦЕЛИ
  # (иначе в hosts прописывается SNI панели → подключение не стартует).
  # Домен панели: глобал → subDomain панели → вопрос; IP — последний рубеж.
  local _hp="${PANEL_DOMAIN:-}"
  [[ -z "$_hp" ]] && _hp=$(xui_get subDomain 2>/dev/null || true)
  if [[ -z "$_hp" && -t 0 ]]; then
    ask _hp "Домен панели (адрес для hosts-записи #$id)" "" '^[a-zA-Z0-9.-]+$'
  fi
  [[ -z "$_hp" ]] && _hp=$(curl -4 -s --max-time 6 ifconfig.me 2>/dev/null || true)
  [[ -z "$_hp" ]] && _hp="$tdom"
  hosts_upsert "$id" "$_hp" "$tdom"
  if [[ -n "$xui_was" ]]; then
    systemctl start x-ui >/dev/null 2>&1 || true
    sleep 2
  fi
  nginx_reload || true
  log "#$id: чужой реалити «$tdom» спрятан за 443 — SNI → inb_${id}_backend, слушает 127.0.0.1${port:+:$port} (tcp-порт НЕ открыт)"
  return 0
}

configure_sni_for_inbound() {
  local id="$1" proto="$2" port="$3" panel_domain="$4" pre_domain="${5:-}" pre_tpl="${6:-default}"
  is_udp_proto "$proto" && { warn "UDP ($proto) не маршрутизируется через SNI."; return 0; }
  [[ ! -f "$SNI_CONF" ]] && { err "$SNI_CONF не найден — сначала выполните 'Первичную настройку SNI-роутера' (пункт 1)."; return 1; }
  sni_used_load
  [[ -n "$panel_domain" ]] && SNI_USED["$panel_domain"]="${SNI_USED[$panel_domain]:-panel_backend}"

  local existing_domain=""
  existing_domain=$(grep -E "^\s+\S+\s+inb_${id}_backend" "$SNI_CONF" 2>/dev/null | awk '{print $1}' || true)
  if [[ -n "$existing_domain" ]]; then
    log "Инбаунд #$id уже в SNI: $existing_domain"
    grep -qE "^upstream inb_${id}_backend" "$SNI_CONF" 2>/dev/null || { sni_upstream_add "inb_${id}_backend" "$port"; nginx_reload || true; }

    # если это Reality с чужим/пустым dest (не 127.0.0.1:*) — чиним автоматически:
    # создаём decoy и проставляем dest = 127.0.0.1:<порт decoy>
    local stream_chk=""
    stream_chk=$(sqlite3 "$XUI_DB" "SELECT COALESCE(stream_settings,'') FROM inbounds WHERE id=$id;" 2>/dev/null || true)
    if grep -qi reality <<<"$stream_chk" && ! grep -Eq "\"dest\": ?\"127\.0\.0\.1:" <<<"$stream_chk"; then
      # Чужой реалити (dest = внешняя цель из списка) — это НЕ поломка:
      # инбаунд спрятан за 443 по SNI цели, decoy/серт ему не нужны
      local _t_hit=false _t
      for _t in "${REALITY_TARGETS[@]}"; do
        [[ "$existing_domain" == "$_t" ]] && { _t_hit=true; break; }
      done
      if [[ "$_t_hit" == true ]]; then
        log "  Reality (#$id) спрятан за 443 по цели «$existing_domain» — не трогаю"
        return 0
      fi
      warn "  Reality dest не локальный — чиню (decoy + dest)"
      local tls_port=$(( 4444 + id ))
      while ss -tlnH "sport = :$tls_port" 2>/dev/null | grep -q .; do tls_port=$((tls_port+1)); done
      local cp_line="" c="" k=""
      cp_line=$(cert_paths "$existing_domain") || true
      if [[ -z "$cp_line" ]]; then
        cert_issue "$existing_domain" || true
        cp_line=$(cert_paths "$existing_domain") || true
      fi
      if [[ -n "$cp_line" ]]; then
        c="${cp_line%% *}"; k="${cp_line##* }"
        mk_decoy "$tls_port" "$existing_domain" "$c" "$k" "/var/www/decoy-$id" "default"
        reality_set_dest "$id" "$tls_port" "$existing_domain"
        nginx_reload || true
        systemctl restart x-ui >/dev/null 2>&1 || true
        log "  Reality dest (#$id) исправлен → 127.0.0.1:$tls_port"
      else
        warn "  cert для $existing_domain недоступен — Reality dest не обновлён"
      fi
    fi
    return 0
  fi

  local def="svc-$id.example.com"
  case "$proto" in
    vless) def="r.example.com";;
    anytls) def="at.example.com";;
    mtproto) def="tg.example.com";;
  esac
  local domain="" HIDE_EXT_443=false
  if [[ -n "$pre_domain" ]]; then
    # домен выбран до создания инбаунда — проверяем и используем без повторного вопроса
    local pre_owner=""
    pre_owner=$(sni_domain_owner "$pre_domain" "$id")
    if [[ -n "$pre_owner" ]]; then
      err "Домен $pre_domain уже занят ($pre_owner) — SNI для #$id не настроен."
      return 1
    fi
    domain="$pre_domain"
    SNI_USED["$domain"]="inb_${id}_backend"
  else
    # Reality: «найти цели» (как кнопка в панели) или свой SNI-домен
    local stream_pre=""
    stream_pre=$(sqlite3 "$XUI_DB" "SELECT COALESCE(stream_settings,'') FROM inbounds WHERE id=$id;" 2>/dev/null || true)
    if grep -qi '"security": *"reality"' <<<"$stream_pre" || grep -qi '"security":"reality"' <<<"$stream_pre"; then
      echo
      echo -e "${B}Reality «найти цели» — кандидаты (нужен TLS 1.3 + h2):${N}"
      local _i=1 _c
      for _c in "${REALITY_TARGETS[@]}"; do
        printf "  %2d) %s\n" "$_i" "$_c"; _i=$((_i+1))
      done
      printf "  %2d) Свой SNI-домен (нужен сертификат + decoy)\n" "$_i"
      local rt=""
      ask rt "Выбор таргета (1-$_i)" "1" '^[0-9]+$'
      if (( rt >= 1 && rt <= ${#REALITY_TARGETS[@]} )); then
        REALITY_EXT_TARGET="${REALITY_TARGETS[$((rt-1))]}"
        printf '%s' "$REALITY_EXT_TARGET" > /tmp/.reality-found-target 2>/dev/null || true
        log "  #$id: внешний таргет → $REALITY_EXT_TARGET (спрячу за 443 по SNI цели, tcp-порт не открываю)"
      else
        ask_sni_domain domain "$id" "$def"
      fi
    else
      ask_sni_domain domain "$id" "$def"
    fi
  fi

  # Мусор из старой установки: «свой» домен оказался целью чужого reality —
  # SNI-маршрут/серт/decoy на чужой домен строить нельзя
  local _rt_y
  for _rt_y in "${REALITY_TARGETS[@]}"; do
    if [[ "$domain" == "$_rt_y" ]]; then
      warn "  «$domain» — цель чужого reality, а не твой домен (артефакт старой установки)."
      warn "  Инбаунд #$id пересоздай: панель → удалить → создать заново с нормальным доменом."
      return 1
    fi
  done

  # Внешний таргет «найти цели» — доктрина «всё за 443»: чужой реалити прячем
  # по SNI цели, слушаем 127.0.0.1, tcp-порт инбаунда НЕ открываем.
  if [[ -z "$domain" ]]; then
    local ext_dom="${REALITY_EXT_TARGET:-$(reality_find_target "$id")}"
    reality_ext_hide "$id" "$ext_dom" "$port" || warn "  не удалось спрятать #$id за 443"
    systemctl restart x-ui >/dev/null 2>&1 || true
    return 0
  fi

  sni_upstream_add "inb_${id}_backend" "$port"
  sni_map_add "$domain" "inb_${id}_backend"

  hosts_upsert "$id" "${panel_domain:-$domain}" "$domain"   # адрес=панель, SNI=свой домен
  systemctl restart x-ui >/dev/null 2>&1 || true

  local is_reality=false stream=""
  stream=$(sqlite3 "$XUI_DB" "SELECT COALESCE(stream_settings,'') FROM inbounds WHERE id=$id;" 2>/dev/null || true)
  [[ "$proto" == "vless" ]] && grep -q '"security": *"reality"' <<<"$stream" && is_reality=true

  if [[ "$is_reality" == true ]]; then
    cert_issue "$domain" || return 1
    local cp_line="" cert="" key=""
    cp_line=$(cert_paths "$domain") || true
    if [[ -n "$cp_line" ]]; then
      cert="${cp_line%% *}"; key="${cp_line##* }"
    else
      cert="/etc/letsencrypt/live/$domain/fullchain.pem"
      key="/etc/letsencrypt/live/$domain/privkey.pem"
    fi
    local tls_port=$(( 4444 + id ))
    while ss -tlnH "sport = :$tls_port" 2>/dev/null | grep -q .; do tls_port=$((tls_port+1)); done
    mk_decoy "$tls_port" "$domain" "$cert" "$key" "/var/www/decoy-$id" "$pre_tpl"
    reality_set_dest "$id" "$tls_port" "$domain"   # dest = внутренний IP decoy nginx + serverNames = домен
    systemctl restart x-ui >/dev/null 2>&1 || true   # панель сразу подхватит новый dest
    log "  + decoy (Reality) на порту $tls_port${pre_tpl:+ ($pre_tpl)}"
  fi

  # vless/trojan + TLS (не reality): заглушка для пробоев — не-протокольный
  # трафик (браузер по https://<домен>) уходит fallback'ом в nginx :80,
  # где лежит статичный сайт (ACME webroot), вместо молчаливого reset.
  if [[ "$proto" == "vless" || "$proto" == "trojan" ]] && grep -qE '"security": ?"tls"' <<<"$stream"; then
    local has_fb=""
    has_fb=$(sqlite3 "$XUI_DB" "SELECT COALESCE(json_extract(settings,'\$.fallbacks'),'[]') FROM inbounds WHERE id=$id;" 2>/dev/null || true)
    if [[ -z "$has_fb" || "$has_fb" == "[]" || "$has_fb" == "null" ]]; then
      systemctl stop x-ui >/dev/null 2>&1 || true
      if sqlite3 "$XUI_DB" "UPDATE inbounds SET settings=json_set(settings,'\$.fallbacks','[{\"dest\":80}]') WHERE id=$id;" 2>/dev/null; then
        log "  + заглушка vless/tls: fallback → 127.0.0.1:80 (пробой браузером увидит сайт)"
      fi
      systemctl start x-ui >/dev/null 2>&1 || true
    fi
  fi

  nginx_reload || true
  log "SNI настроен: $domain -> inb_${id}_backend"
}

# =====================================================================
# ПЕРВИЧНАЯ НАСТРОЙКА
# =====================================================================
initial_setup() {
  line; echo -e "${B}   ПЕРВИЧНАЯ НАСТРОЙКА SNI-РОУТЕРА${N}"; line
  # Предохранитель: стек уже собран? Повторный прогон может перезаписать
  # работающие настройки — по умолчанию отказываемся.
  if [[ -f "$STACK_CONF" ]] && { [[ -f /etc/nginx/streams-available/sni-router.conf ]] || [[ -n "$XUI_DB" && -f "$XUI_DB" ]]; }; then
    warn "Похоже, первичная настройка уже выполнена:"
    echo "    ✓ $STACK_CONF"
    echo "    ✓ SNI-роутер (:443, streams-available/sni-router.conf)"
    [[ -n "$XUI_DB" && -f "$XUI_DB" ]] && echo "    ✓ панель установлена (x-ui.db)"
    echo "  Точечные изменения — через п.2/п.4 (инбаунды, decoy), п.11 (файрвол), п.21 (гигиена)."
    local rerun=""
    askyn rerun "Всё равно запустить первичную настройку заново?" "n"
    [[ "$rerun" == true ]] || { log "Отменено — конфигурация не тронута."; return 0; }
    warn "Повторная настройка: ответы на вопросы нужно будет дать заново."
  fi
  # ПЕРЕУСТАНОВКА (п.17 → сюда): таймер самолечения лезет в x-ui каждые 2 мин
  # и рушит схему «стоп → правка БД → старт». Гасим до начала, вернём в конце.
  # === ФАЗА А: анкета и план — НИКАКИХ изменений до подтверждения ===
  local PLAN_INSTALL=true PLAN_CREATE=true PLAN_FW=true
  local PLAN_EMAIL_DONE=0 PLAN_CREDS_DONE=0 PLAN_ADG_DONE=0
  if [[ -z "$XUI_DB" || ! -f "$XUI_DB" ]]; then
    if [[ -z "$PANEL_DOMAIN" || "$PANEL_DOMAIN" == "panel.example.com" ]]; then
      local pd0=""
      ask pd0 "Домен панели (A-запись → этот сервер)" "${PANEL_DOMAIN:-panel.example.com}" '^[a-zA-Z0-9.-]+$'
      PANEL_DOMAIN="$pd0"
    fi
    askyn PLAN_INSTALL "Ставить панель LucX UI сейчас?" "y"
    if [[ "$PLAN_INSTALL" != true ]]; then
      err "Без панели стек не собирается — отмена."
      return 1
    fi
  fi
  le_email_load || true
  if [[ -z "$EMAIL" ]]; then
    ask EMAIL "Email для Let's Encrypt" "" '^[^@]+@[^@]+\.[^@]+$'
    le_email_save "$EMAIL"
  fi
  PLAN_EMAIL_DONE=1
  if [[ -t 0 ]]; then
    ask_panel_creds || return 1
    PLAN_CREDS_DONE=1
  fi
  ask_adguard_and_decoy               # AdGuard да/нет → пароль → где → заглушка
  PLAN_ADG_DONE=1
  askyn PLAN_CREATE "В конце создать инбаунды (мастер создания)?" "y"
  askyn PLAN_FW "В конце настроить файрвол (только нужные порты)?" "y"
  echo
  line
  echo -e "${B}   ПЛАН НАСТРОЙКИ${N}"; line
  local _pan_state="уже установлена"
  [[ -z "$XUI_DB" || ! -f "$XUI_DB" ]] && _pan_state="будет установлена (LucX UI)"
  echo "  • панель: $PANEL_DOMAIN — $_pan_state"
  echo "  • email LE: ${EMAIL:-<не задан>}"
  echo "  • AdGuard: ${ADG_PRESENT:-false} · размещение: ${ADG_PLACEMENT:--} · decoy панели: ${PDECOY:--}"
  echo "  • инбаунды в конце: $([[ "$PLAN_CREATE" == true ]] && echo да || echo нет)"
  echo "  • файрвол в конце: $([[ "$PLAN_FW" == true ]] && echo да || echo нет)"
  line
  local go_apply=""
  askyn go_apply "План верный — применять?" "y"
  [[ "$go_apply" == true ]] || { warn "Отменено — ничего не изменено"; return 0; }
  # === ФАЗА Б: применение (вопросы выше пропускаются по PLAN_*-флагам) ===
  systemctl stop stack-heal.timer 2>/dev/null || true
  systemctl disable stack-heal.timer 2>/dev/null || true
  # Панели нет? НЕ валимся — ставим прямо здесь (первоначальная установка
  # должна работать и после удаления панели через п.17).
  if [[ -z "$XUI_DB" || ! -f "$XUI_DB" ]]; then
    warn "Панель LucX UI не установлена (x-ui.db не найден)."
    if [[ -z "$PANEL_DOMAIN" || "$PANEL_DOMAIN" == "panel.example.com" ]]; then
      local pd_ask=""
      ask pd_ask "Домен панели (A-запись → этот сервер)" "${PANEL_DOMAIN:-panel.example.com}" '^[a-zA-Z0-9.-]+$'
      PANEL_DOMAIN="$pd_ask"
    fi
    local install_now=false
    [[ "$PLAN_INSTALL" == true ]] && install_now=true
    if [[ "$install_now" != true ]]; then
      err "Без панели работа невозможна."
      return 1
    fi
    install_lucx_panel || { err "Не удалось установить панель LucX UI."; return 1; }
  fi

  local inb_count=0
  inb_count=$(sqlite3 "$XUI_DB" "SELECT COUNT(*) FROM inbounds WHERE enable=1;" 2>/dev/null || echo 0)
  if [[ "$inb_count" -eq 0 ]]; then
    warn "Нет активных инбаундов — создадим их в КОНЦЕ п.1, когда SNI-стек уже собран (иначе нет ни SNI_CONF, ни сертов, ни домена)."
  fi

  local panel_port panel_path sub_port sub_path
  local PANEL_PORT PANEL_PATH SUB_PORT SUB_PATH
  panel_port=$(xui_get webPort); panel_port="${panel_port:-2053}"
  panel_path=$(xui_get webBasePath); panel_path="/${panel_path#/}"; panel_path="${panel_path%/}/"
  sub_port=$(xui_get subPort); sub_port="${sub_port:-2096}"
  sub_path=$(xui_get subPath); sub_path="/${sub_path#/}"; sub_path="${sub_path%/}/"

  if [[ "${PLAN_EMAIL_DONE:-0}" == 1 ]]; then
    log "Email для Let's Encrypt: $EMAIL (из анкеты)"
  else
  le_email_load || true
  if [[ -n "$EMAIL" ]]; then
    log "Email для Let's Encrypt: $EMAIL (сохранён)"
    if [[ -t 0 ]]; then
      local _keep_email=""
      askyn _keep_email "Оставить этот email? (n — указать новый)" "y"
      if [[ "$_keep_email" != true ]]; then
        ask EMAIL "Новый Email для Let's Encrypt" "$EMAIL" '^[^@]+@[^@]+\.[^@]+$'
        le_email_save "$EMAIL"
      fi
    fi
  else
    ask EMAIL "Email для Let's Encrypt" "" '^[^@]+@[^@]+\.[^@]+$'
    le_email_save "$EMAIL"
  fi
  fi
  if [[ -z "$PANEL_DOMAIN" ]]; then
    ask PANEL_DOMAIN "Домен панели" "panel.example.com" '^[a-zA-Z0-9.-]+$'
  else
    log "Домен панели: $PANEL_DOMAIN (задан ранее)"
  fi
  sni_used_load
  SNI_USED["$PANEL_DOMAIN"]="panel_backend"   # домен панели тоже занят — инбаунды не могут его использовать

  # ЕДИНЫЙ ПУТЬ (тот же, что в авто-подъёме):
  # пароль+порты — только в TTY; в ans-режиме всё уже в глобальных (U_*)
  if [[ "${PLAN_CREDS_DONE:-0}" != 1 ]]; then
    if [[ -t 0 ]]; then
      ask_panel_creds || return 1
    fi
  fi
  if [[ "${PLAN_ADG_DONE:-0}" != 1 ]]; then
    ask_adguard_and_decoy               # AdGuard да/нет → пароль → где → заглушка
  fi
  local panel_decoy="$PDECOY"
  if [[ "$ADG_PRESENT" == true && "$ADG_PLACEMENT" == "panel" ]]; then
    panel_decoy="adguard"
    log "AdGuard будет настроен за панелью: TLS+серт панели, порт, nginx-локация"
    # сторонний AdGuard мог слушать :80/:443 — nginx не сможет забиндиться
    local p80_owner=""
    p80_owner=$(ss -tlnpH "sport = :80" 2>/dev/null | grep -oE '\("[^"]+"' | head -1 | tr -d '("')
    if [[ -n "$p80_owner" && "$p80_owner" != "nginx" ]]; then
      warn ":80 занят процессом '$p80_owner' — nginx не сможет слушать 80 (нужен для ACME webroot)."
      warn "Освободи порт или переведи тот сервис (AdGuard) на другой порт перед п.1."
    fi
  fi
  if [[ "$ADG_PLACEMENT" == "sni" ]]; then
    local abase="${PANEL_DOMAIN#*.}"
    [[ "$abase" != *.* ]] && abase="$PANEL_DOMAIN"
    ADG_MODE_SNI_DOM="adguard.${abase:-example.com}"
    panel_decoy="stub"
    log "AdGuard: отдельный домен $ADG_MODE_SNI_DOM (настрою сразу после SNI-роутера)"
  fi
  log "Decoy панели: $panel_decoy"

  if [[ -n "$U_PANEL_PORT$U_SUB_PORT$U_PANEL_PATH$U_SUB_PATH" ]]; then
    PANEL_PORT="$U_PANEL_PORT"; PANEL_PATH="$U_PANEL_PATH"
    SUB_PORT="$U_SUB_PORT";     SUB_PATH="$U_SUB_PATH"
    log "Порты/пути: панель $PANEL_PORT $PANEL_PATH · подписки $SUB_PORT $SUB_PATH"
  else
    PANEL_PORT=$(make_port); PANEL_PATH="/$(gen_random_string 12)/"
    SUB_PORT=$(make_port);   SUB_PATH="/$(gen_random_string 10)/"
    log "Автогенерация: панель $PANEL_PORT $PANEL_PATH · подписки $SUB_PORT $SUB_PATH"
  fi

  if [[ "$PANEL_PORT" == "$SUB_PORT" ]]; then
    err "Порт панели и порт подписок совпадают ($PANEL_PORT) — укажите разные."
    return 1
  fi

  declare -A INB_PROTO INB_PORT INB_STREAM
  local -a INB_IDS=()
  local id proto port stream
  while IFS='|' read -r id proto port stream; do
    [[ -z "$id" ]] && continue
    INB_IDS+=("$id")
    INB_PROTO[$id]="$proto"; INB_PORT[$id]="$port"; INB_STREAM[$id]="$stream"
  done < <(sqlite3 "$XUI_DB" "SELECT id, protocol, port, COALESCE(stream_settings,'') FROM inbounds WHERE enable=1 AND port>0;" 2>/dev/null || true)

  declare -A DOMAIN HIDE TLS_PORT DECOY_TPL
  local tls_cur=4444
  for id in "${INB_IDS[@]}"; do
    proto="${INB_PROTO[$id]}"; port="${INB_PORT[$id]}"
    if is_udp_proto "$proto"; then
      warn "#$id $proto (UDP/$port) — пропускаем"
      HIDE[$id]=false; continue
    fi
    if [[ "$proto" == "tproxy" ]]; then
      # tg web proxy прячется СВОИМ механизмом (hosts: address=панель, sni=tg-домен;
      # маршрут в SNI_CONF ведёт setup_tproxy_web с бэкендом tg_backend) —
      # вопросы «Скрыть/SNI-домен» к нему не относятся
      log "#$id tproxy ($port) — прячется своим механизмом (tg web proxy за 443), повторно не спрашиваю"
      HIDE[$id]=false; continue
    fi

    # уже привязан к SNI (создан в п.2/п.16 или ранее) — НЕ спрашиваем второй раз
    local existing_dom=""
    existing_dom=$(grep -E "^\s+\S+\s+inb_${id}_backend" "$SNI_CONF" 2>/dev/null | awk '{print $1}' | head -1 || true)
    if [[ -n "$existing_dom" ]]; then
      log "#$id ($proto/$port) уже в SNI: $existing_dom — повторно не спрашиваю"
      HIDE[$id]=true
      DOMAIN[$id]="$existing_dom"
      local meta=""
      meta=$(stack_decoy_meta "$existing_dom") || true
      if [[ -n "$meta" ]]; then
        TLS_PORT[$id]="${meta%% *}"   # reuse существующий decoy-порт
      else
        TLS_PORT[$id]=$tls_cur; tls_cur=$((tls_cur+1))
      fi
      local is_reality=false
      [[ "$proto" == "vless" ]] && grep -qi reality <<<"${INB_STREAM[$id]}" && is_reality=true
      [[ "$is_reality" == true ]] && DECOY_TPL[$id]="default" || DECOY_TPL[$id]=""
      continue
    fi

    echo; echo -e "${Y}── #$id $proto на $port ──${N}"
    local h_hide=""
    askyn h_hide "Скрыть за 443?" "y"
    HIDE[$id]="$h_hide"
    [[ "${HIDE[$id]}" == true ]] || continue

    local def="svc-$id.example.com"
    case "$proto" in
      anytls) def="at.example.com";;
      trusttunnel|trust-tunnel) def="tt.example.com";;
      naive|naiveproxy) def="n.example.com";;
      mtproto) def="tg.example.com";;
      vless) def="r.example.com";;
    esac
    local d_new=""
    ask_sni_domain d_new "$id" "$def"
    DOMAIN[$id]="$d_new"

    local is_reality=false
    [[ "$proto" == "vless" ]] && grep -q '"security": *"reality"' <<<"${INB_STREAM[$id]}" && is_reality=true
    # decoy-порт нужен ТОЛЬКО Reality (dest для рукопожатия); шаблон заглушки — выбор пользователя
    if [[ "$is_reality" == true ]]; then
      local dtpl=""
      decoy_template_choose dtpl "Decoy-заглушка для #$id (страница на его SNI-домене)" "corporate"
      DECOY_TPL[$id]="${dtpl:-default}"
      TLS_PORT[$id]=$tls_cur; tls_cur=$((tls_cur+1))
    else
      DECOY_TPL[$id]=""
      TLS_PORT[$id]=""
    fi
  done


  local nginx_was_running=false xui_was_running=false adg_was_running=false
  systemctl is-active --quiet nginx 2>/dev/null && { nginx_was_running=true; systemctl stop nginx 2>/dev/null || true; }
  systemctl is-active --quiet x-ui  2>/dev/null && { xui_was_running=true;   systemctl stop x-ui  2>/dev/null || true; }
  if [[ "$ADG_PRESENT" == true && -n "$ADG_SERVICE" ]] && systemctl is-active --quiet "$ADG_SERVICE" 2>/dev/null; then
    adg_was_running=true; systemctl stop "$ADG_SERVICE" 2>/dev/null || true
  fi
  sleep 2

  restore_running_services() {
    [[ "$xui_was_running" == true ]] && systemctl start x-ui 2>/dev/null || true
    [[ "$adg_was_running" == true && -n "$ADG_SERVICE" ]] && systemctl start "$ADG_SERVICE" 2>/dev/null || true
    [[ "$nginx_was_running" == true ]] && systemctl start nginx 2>/dev/null || true
  }

  local pc="" pk="" cp_line="" db_line=""
  # ПРИОРИТЕТ №1: серт, ВПИСАННЫЙ в настройки x-ui (в т.ч. выпущенный через меню x-ui)
  db_line=$(panel_cert_from_db) || true
  if [[ -n "$db_line" ]]; then
    pc="${db_line%% *}"; pk=$(echo "$db_line" | awk '{print $2}')
    log "Панель: используется вписанный серт x-ui → $pc"
  fi
  # Приоритет №2: cert_paths (wildcard/персональный по домену)
  if [[ -z "$pc" ]]; then
    cp_line=$(cert_paths "$PANEL_DOMAIN") || true
    [[ -n "$cp_line" ]] && { pc="${cp_line%% *}"; pk="${cp_line##* }"; }
  fi
  if [[ -z "$pc" ]]; then
    log "Выпуск сертификата панели: $PANEL_DOMAIN"
    if ! cert_issue "$PANEL_DOMAIN"; then
      err "Не удалось выпустить cert"; restore_running_services; return 1
    fi
    cp_line=$(cert_paths "$PANEL_DOMAIN") || true
    if [[ -n "$cp_line" ]]; then pc="${cp_line%% *}"; pk="${cp_line##* }"; fi
  fi
  if [[ -z "$pc" || ! -f "$pc" || ! -f "$pk" ]]; then
    err "Сертификат панели не найден"; restore_running_services; return 1
  fi

  # СЕРТ ПАНЕЛИ ОБЯЗАН БЫТЬ ВПИСАН В НАСТРОЙКИ x-ui: без него панель слушает
  # HTTP, а nginx проксирует по https → 502 Bad Gateway. Вписываем всегда,
  # независимо от того, откуда пришёл серт (x-ui меню / cert_paths / выпуск).
  # ПУТИ — из /etc/letsencrypt/live/<домен>/ (единое место, без зеркала).
  local cr_line=""
  cr_line=$(cert_mirror_to_certroot "$(dirname "$pc")" "$PANEL_DOMAIN" 2>/dev/null || true)
  [[ -n "$cr_line" ]] && { pc="${cr_line%% *}"; pk="${cr_line##* }"; }
  xui_set_setting webDomain   "$PANEL_DOMAIN"
  xui_set_setting webCertFile "$pc"
  xui_set_setting webKeyFile  "$pk"
  xui_set_setting subCertFile "$pc"
  xui_set_setting subKeyFile  "$pk"
  xui_set_setting subDomain   "$PANEL_DOMAIN"
  xui_set_setting subURI      "$(suburi_build "$PANEL_DOMAIN")"
  log "Серт панели вписан в настройки x-ui (HTTPS-режим): $pc"

  for id in "${INB_IDS[@]}"; do
    [[ "${HIDE[$id]}" == true ]] || continue
    [[ -z "${DECOY_TPL[$id]}" ]] && continue
    cert_issue "${DOMAIN[$id]}" || warn "  ИТОГ: серт ${DOMAIN[$id]} НЕ выпущен — #$id ($proto) не поднимется (причина выше)"
  done
  # пути сертификатов → в settings инбаундов (naive/anytls/trusttunnel/tproxy/hysteria)
  sync_inbound_certs

  mkdir -p "$NGINX_STREAM_DIR" 2>/dev/null || true
  {
    echo "map \$ssl_preread_server_name \$backend {"
    echo "    default                       panel_backend;"
    echo "    $PANEL_DOMAIN                 panel_backend;"
    for id in "${INB_IDS[@]}"; do
      [[ "${HIDE[$id]}" == true ]] && echo "    ${DOMAIN[$id]}    inb_${id}_backend;"
    done
    echo "}"
    echo
    echo "upstream panel_backend { server 127.0.0.1:4443; }"
    for id in "${INB_IDS[@]}"; do
      [[ "${HIDE[$id]}" == true ]] && echo "upstream inb_${id}_backend { server 127.0.0.1:${INB_PORT[$id]}; }"
    done
    echo
    echo "server {"
    echo "    listen 443;"
    echo "    proxy_pass \$backend;"
    echo "    ssl_preread on;"
    echo "    proxy_connect_timeout 5s;"
    echo "    proxy_timeout 10m;"
    echo "}"
  } > "$SNI_CONF"

  # ПРОВЕРКА: SNI-запись домена панели в nginx — без неё decoy панели (4443)
  # недостижим по домену (сработает только default). Самолечение при наличии.
  if grep -qE "^[[:space:]]*${PANEL_DOMAIN//./\\.}[[:space:]]+panel_backend;" "$SNI_CONF" 2>/dev/null; then
    log "SNI-запись панели в nginx: $PANEL_DOMAIN → panel_backend ✓"
  else
    sed -i "0,/^[[:space:]]*default[[:space:]]\+panel_backend;/s||    $PANEL_DOMAIN                 panel_backend;\n&|" "$SNI_CONF" 2>/dev/null || true
    if grep -qE "^[[:space:]]*${PANEL_DOMAIN//./\\.}[[:space:]]+panel_backend;" "$SNI_CONF"; then
      warn "SNI-запись панели отсутствовала — добавлена: $PANEL_DOMAIN → panel_backend"
    else
      err "Не удалось добавить SNI-запись панели в $SNI_CONF — проверь вручную"
    fi
  fi

  # AdGuard на ОТДЕЛЬНОМ SNI-домене (режим 2): серт + TLS 3002 + маршрут.
  # nginx сейчас остановлен — карта подхватится финальным стартом nginx.
  if [[ -n "${ADG_MODE_SNI_DOM:-}" ]]; then
    adg_setup_sni_domain "$ADG_MODE_SNI_DOM" || warn "AdGuard SNI-домен не настроился — перезапусти п.1"
  fi

  mkdir -p "$NGINX_SITES_DIR" 2>/dev/null || true
  rm -f "$NGINX_SITES_DIR"/default 2>/dev/null || true
  # миграция: старые отдельные конфиги больше не нужны — всё будет в stack.conf
  rm -f "$NGINX_SITES_DIR"/decoy-*.conf 2>/dev/null || true
  rm -f "$NGINX_SITES_DIR"/panel.conf "$NGINX_SITES_DIR"/http80.conf 2>/dev/null || true
  stack_ensure
  stack_del_all_decoy
  printf '# stack-manager: единый конфиг (ACME :80, панель :4443, decoy)\n' > "$STACK_CONF"

  local decoy_block=""
  if [[ "$panel_decoy" == "adguard" ]]; then
    [[ "$ADG_PRESENT" == true && -n "$ADG_SERVICE" ]] && { systemctl start "$ADG_SERVICE" 2>/dev/null || true; sleep 1; }
    # фактический порт AdGuard (после configure может измениться — скорректируем ниже)
    local adg_port_build=""
    adg_port_build=$(adg_config_port)
    ADG_WEB_PORT="$adg_port_build"
    decoy_block=$(cat <<EOF
    location / {
        proxy_pass https://127.0.0.1:$ADG_WEB_PORT;
        proxy_ssl_verify off;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 86400;
    }
EOF
)
  else
    local panel_try='try_files /index.html =404;'
    if [[ "$panel_decoy" == tpl:custom:* ]]; then
      local custom_path="${panel_decoy#tpl:custom:}"
      if [[ -d "$custom_path" ]]; then
        PANEL_DECOY_DIR="$custom_path"
        panel_try='try_files $uri $uri/ /index.html;'
        log "Decoy панели: свой сайт из $custom_path"
      else
        warn "Папка $custom_path не найдена — стандартная заглушка"
        panel_decoy_stub_init
      fi
    else
      panel_decoy_stub_init
      # decoy-шаблон из каталога (tpl:ИМЯ) — кладём его как index.html панели
      if [[ "$panel_decoy" == tpl:* ]]; then
        local tpl_name="${panel_decoy#tpl:}"
        local tpl_src="$DECOY_TPL_DIR/$tpl_name.html"
        is_login_template "$tpl_name" && tpl_src="$DECOY_LOGIN_DIR/$tpl_name.html"
        if [[ -f "$tpl_src" ]]; then
          cp -f "$tpl_src" "$PANEL_DECOY_DIR/index.html" 2>/dev/null || true
          chown www-data:www-data "$PANEL_DECOY_DIR/index.html" 2>/dev/null || true
          log "Decoy панели: шаблон «$tpl_name»"
        else
          warn "Шаблон «$tpl_name» не найден — остаётся стандартная заглушка"
        fi
      fi
    fi
    decoy_block=$(cat <<EOF
    location / {
        root $PANEL_DECOY_DIR;
        $panel_try
    }
EOF
)
  fi

  { cat >> "$STACK_CONF" <<EOF
server {
    listen 127.0.0.1:4443 ssl;
    server_name $PANEL_DOMAIN;
    ssl_certificate     $pc;
    ssl_certificate_key $pk;
    set_real_ip_from 127.0.0.1;

    location $PANEL_PATH {
        proxy_pass https://127.0.0.1:$PANEL_PORT;
        proxy_ssl_verify off;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 86400;
    }

    location $SUB_PATH {
        proxy_pass https://127.0.0.1:$SUB_PORT;
        proxy_ssl_verify off;
        proxy_ssl_server_name on;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 86400;
    }

$decoy_block
}
EOF
  }

  { cat >> "$STACK_CONF" <<'EOF'
server {
    listen 80 default_server;
    server_name _;
    location /.well-known/acme-challenge/ { root /var/www/html; }
    location / { return 302 https://$host$request_uri; }
}
EOF
  }

  for id in "${INB_IDS[@]}"; do
    [[ "${HIDE[$id]}" == true ]] || continue
    [[ -z "${DECOY_TPL[$id]}" ]] && continue
    local dom="${DOMAIN[$id]}" cp_line="" c="" k=""
    cp_line=$(cert_paths "$dom") || true
    if [[ -n "$cp_line" ]]; then
      c="${cp_line%% *}"; k="${cp_line##* }"
      mk_decoy "${TLS_PORT[$id]}" "$dom" "$c" "$k" "/var/www/decoy-$id" "${DECOY_TPL[$id]:-default}"
      reality_set_dest "$id" "${TLS_PORT[$id]}" "$dom"   # dest = внутренний IP decoy nginx + serverNames = домен
    else
      warn "  cert для $dom не найден — decoy пропущен"
    fi
  done

  cp -n "$XUI_DB" "${XUI_DB}.bak.$(date +%s)" 2>/dev/null || true

  xui_set_setting webListen   '127.0.0.1'
  xui_set_setting webPort     "$PANEL_PORT"
  xui_set_setting webBasePath "$PANEL_PATH"
  xui_set_setting subListen   '127.0.0.1'
  xui_set_setting subPort     "$SUB_PORT"
  xui_set_setting subPath     "$SUB_PATH"
  xui_set_setting subDomain   "$PANEL_DOMAIN"
  # URL обратного прокси для подписок: иначе share-ссылки получают порт панели
  xui_set_setting subURI      "$(suburi_build "$PANEL_DOMAIN" "$SUB_PATH")"

  # самопроверка: указанные порты обязаны лечь в 3x-ui (панель остановлена —
  # запись пройдёт; снаружи всё закрывается nginx'ом на 443)
  local _chk_p _chk_s
  _chk_p=$(xui_get webPort); _chk_s=$(xui_get subPort)
  if [[ "$_chk_p" == "$PANEL_PORT" && "$_chk_s" == "$SUB_PORT" ]]; then
    log "Порты применены в 3x-ui: панель $PANEL_PORT, подписки $SUB_PORT (слушают 127.0.0.1, наружу — только 443 через nginx)"
  else
    err "Порты НЕ применились в 3x-ui (в базе panel=$_chk_p sub=$_chk_s, ожидалось $PANEL_PORT/$SUB_PORT)"
  fi

  local _id _proto _sec _dest
  while IFS='|' read -r _id _proto _sec _dest; do
    [[ -z "$_id" || -z "$_proto" ]] && continue
    # tproxy — прямой туннель без SNI-скрытия: всегда 0.0.0.0
    if is_udp_proto "$_proto" || [[ "$_proto" == "tproxy" ]]; then
      sqlite3 "$XUI_DB" "UPDATE inbounds SET listen='0.0.0.0' WHERE id=$_id;" 2>/dev/null || true
    elif [[ "$_proto" == "vless" && "$_sec" == "reality" && "$_dest" != 127.0.0.1:* ]]; then
      # Reality с внешним таргетом («найти цели»): доктрина «всё за 443» —
      # маршрут по SNI цели + hosts, слушаем 127.0.0.1, tcp-порт НЕ открываем
      local _dt="${_dest%%:*}"
      if [[ -n "$_dt" && "$_dt" != "127.0.0.1" ]]; then
        local _p_rt=""
        _p_rt=$(sqlite3 "$XUI_DB" "SELECT port FROM inbounds WHERE id=$_id;" 2>/dev/null || true)
        reality_ext_hide "$_id" "$_dt" "$_p_rt" || warn "  #$_id: не удалось спрятать за 443"
      else
        sqlite3 "$XUI_DB" "UPDATE inbounds SET listen='127.0.0.1' WHERE id=$_id;" 2>/dev/null || true
      fi
    else
      sqlite3 "$XUI_DB" "UPDATE inbounds SET listen='127.0.0.1' WHERE id=$_id;" 2>/dev/null || true
    fi
  done < <(sqlite3 "$XUI_DB" "SELECT id, protocol, COALESCE(json_extract(stream_settings,'\$.security'),''), COALESCE(json_extract(stream_settings,'\$.realitySettings.dest'),'') FROM inbounds WHERE enable=1 AND port>0;" 2>/dev/null || true)

  local has_hosts=""
  has_hosts=$(sqlite3 "$XUI_DB" "SELECT name FROM sqlite_master WHERE type='table' AND name='hosts';" 2>/dev/null || true)
  if [[ -n "$has_hosts" ]]; then
    local cols=""
    cols=$(sqlite3 "$XUI_DB" "PRAGMA table_info(hosts);" 2>/dev/null | awk -F'|' '{print $2}' | tr '\n' ' ' || true)
    # SNI не занят инбаундом (не скрываем за 443) — hosts-запись («SNI включён») не нужна
    for id in "${INB_IDS[@]}"; do
      [[ "${HIDE[$id]}" == true ]] && continue
      [[ "${INB_PROTO[$id]}" == "tproxy" ]] && continue   # tg web proxy: hosts ведёт setup_tproxy_web
      # спрятан за 443 (свой домен ИЛИ чужой реалити по SNI цели) — hosts не трогаем
      grep -qE "^upstream inb_${id}_backend" "$SNI_CONF" 2>/dev/null && continue
      sqlite3 "$XUI_DB" "DELETE FROM hosts WHERE inbound_id=$id AND port=443;" 2>/dev/null || true
    done
    for id in "${INB_IDS[@]}"; do
      [[ "${HIDE[$id]}" == true ]] || continue
      local dom="${DOMAIN[$id]}"
      local remark
      remark=$(proto_remark "${INB_PROTO[$id]}" "${INB_STREAM[$id]}")
      sqlite3 "$XUI_DB" "DELETE FROM hosts WHERE inbound_id=$id AND port=443;" 2>/dev/null || true
      local fields="inbound_id,address,port" vals="$id,'$PANEL_DOMAIN',443"
      grep -qw remark      <<<"$cols" && { fields+=",remark";      vals+=",'$remark'"; }
      # SNI («безопасность») не заполняем — панель на заполненное поле ругается
      grep -qw sni         <<<"$cols" && { fields+=",sni";         vals+=",''"; }
      grep -qw fingerprint <<<"$cols" && { fields+=",fingerprint"; vals+=",'firefox'"; }
      grep -qw is_disabled <<<"$cols" && { fields+=",is_disabled"; vals+=",0"; }
      grep -qw enable      <<<"$cols" && { fields+=",enable";      vals+=",1"; }
      sqlite3 "$XUI_DB" "INSERT INTO hosts ($fields) VALUES ($vals);" 2>/dev/null || true
    done
  fi

  ensure_stream_include
  if ! nginx -t 2>/dev/null; then
    err "nginx -t упал:"; nginx -t 2>&1 | tail -5 | sed 's/^/  /'
    restore_running_services; return 1
  fi

  if [[ "$panel_decoy" == "adguard" && -n "$ADG_SERVICE" ]]; then
    local adg_cred_pass=""
    adg_cred_pass=$(grep "Пароль" /root/adguard-credentials.txt 2>/dev/null | awk '{print $2}' | head -1 || true)
    if configure_adguard_doh "$adg_cred_pass" "$pc" "$pk"; then
      log "AdGuard Home добавлен в SNI-маршрут: https://$PANEL_DOMAIN/ (UI без пути) + /dns-query (DoH)"
    else
      warn "Не удалось настроить AdGuardHome.yaml для DoH"
    fi
    # configure мог сменить порт AdGuard — корректируем proxy_pass в stack.conf
    local adg_port_now=""
    adg_port_now=$(adg_config_port)
    if [[ -n "$adg_port_now" && "$adg_port_now" != "$adg_port_build" ]]; then
      sed -i "s|proxy_pass https://127.0.0.1:$adg_port_build;|proxy_pass https://127.0.0.1:$adg_port_now;|" "$STACK_CONF" 2>/dev/null || true
      nginx_reload || true
      log "AdGuard порт скорректирован в nginx: $adg_port_build → $adg_port_now"
    fi
    # визард не пройден (users пуст) — создаём админа автоматически и показываем пароль
    if grep -qE '^users: ?\[\]?' "$ADG_CONFIG" 2>/dev/null; then
      local adg_user="${U_ADG_USER:-admin}" adg_pass=""
      if [[ -n "${U_ADG_PASS:-}" ]]; then
        adg_pass="$U_ADG_PASS"   # пароль задан при установке
      else
        adg_pass=$(openssl rand -base64 18 2>/dev/null | tr -dc 'a-zA-Z0-9' | head -c 16)
        [[ -z "$adg_pass" ]] && adg_pass="AdG$(date +%s)"
      fi
      if adg_set_admin "$adg_user" "$adg_pass"; then
        {
          echo "AdGuard Home — $(date '+%F %T')"
          echo "  URL:    https://$PANEL_DOMAIN/"
          echo "  DoH:    https://$PANEL_DOMAIN/dns-query"
          echo "  Логин:  $adg_user"
          echo "  Пароль: $adg_pass"
        } > /root/adguard-credentials.txt 2>/dev/null || true
        chmod 600 /root/adguard-credentials.txt 2>/dev/null || true
        echo
        log "AdGuard UI:    https://$PANEL_DOMAIN/"
        log "AdGuard логин: $adg_user   пароль: $adg_pass  (сохранено в /root/adguard-credentials.txt)"
      fi
    fi
  fi

  systemctl start x-ui 2>/dev/null || true
  systemctl start nginx 2>/dev/null || true
  [[ "$adg_was_running" == true && -n "$ADG_SERVICE" ]] && systemctl start "$ADG_SERVICE" 2>/dev/null || true

  # tg web proxy: доводим tproxy-инбаунд до рабочего (hostname+серт+сайт+маршрут)
  setup_tproxy_web

  # --- Инбаунды на чистой установке: создаём ПОСЛЕ сборки стека.
  #     SNI_CONF готов, домен панели/email известны — вопросы в том же виде,
  #     что и в авто-подъёме (reality: свой/чужой → цель/домен → порт).
  inb_count=$(sqlite3 "$XUI_DB" "SELECT COUNT(*) FROM inbounds WHERE enable=1;" 2>/dev/null || echo 0)
  if [[ "$inb_count" -eq 0 ]]; then
    local do_create=false
    [[ "$PLAN_CREATE" == true ]] && do_create=true
    [[ "$do_create" == true ]] && create_inbounds_menu
  fi

  log "Первичная настройка завершена."
  if [[ "$panel_decoy" == "adguard" ]]; then
    echo
    log "DoH доступен:  https://$PANEL_DOMAIN/dns-query"
    log "AdGuard UI:    https://$PANEL_DOMAIN/"
  fi
  echo
  # Переустановка: сброс старых правил прошлой установки (лишние TCP-порты)
  local fw_now=false
  [[ "$PLAN_FW" == true ]] && fw_now=true
  [[ "$fw_now" == true ]] && firewall_apply
  install_heal_timer
}

# =====================================================================
# ЗАПОЛНЕНИЕ tunnel-инбаунда (naive/anytls/trusttunnel): домен + ключи + креды
# =====================================================================
tunnel_inbound_fill() {
  local id="$1" proto="$2" port="$3"
  [[ -z "$XUI_DB" || ! -f "$XUI_DB" ]] && { err "x-ui.db не найден"; return 1; }

  # снупет-поле настроек под протокол
  local sn_col="domain"
  [[ "$proto" == "anytls" ]] && sn_col="sni"
  [[ "$proto" == "trusttunnel" || "$proto" == "trust-tunnel" ]] && sn_col="hostname"

  # домен: из настроек → из маршрута nginx → спросить
  local domain=""
  domain=$(sqlite3 "$XUI_DB" "SELECT json_extract(settings,'\$.${sn_col}') FROM inbounds WHERE id=$id;" 2>/dev/null || true)
  [[ -z "$domain" || "$domain" == "null" ]] && domain=""
  if [[ -z "$domain" ]]; then
    domain=$(grep -E "^\s+\S+\s+inb_${id}_backend" "$SNI_CONF" 2>/dev/null | awk '{print $1}' | head -1 || true)
  fi
  if [[ -z "$domain" ]]; then
    local def="n.example.com"
    [[ "$proto" == "anytls" ]] && def="at.example.com"
    [[ "$proto" == "trusttunnel" || "$proto" == "trust-tunnel" ]] && def="tt.example.com"
    ask_sni_domain domain "$id" "$def"
  fi
  [[ -z "$domain" || "$domain" == "null" ]] && { err "Домен не указан"; return 1; }
  local owner=""
  owner=$(sni_domain_owner "$domain" "$id") || true
  [[ -n "$owner" ]] && { err "Домен $domain занят ($owner)"; return 1; }

  sni_upstream_add "inb_${id}_backend" "$port"
  sni_map_add "$domain" "inb_${id}_backend"
  SNI_USED["$domain"]="inb_${id}_backend"

  # сертификат
  cert_issue "$domain" || return 1
  local cp_line="" cert="" key=""
  cp_line=$(cert_paths "$domain") || true
  [[ -z "$cp_line" ]] && { err "cert для $domain не найден"; return 1; }
  cert="${cp_line%% *}"; key="${cp_line##* }"

  # текущие значения — генерируем только пустые
  local cur_user="" cur_pass="" cur_seed="" cur_pw="" cur_prefix="" cur_clients=""
  cur_user=$(sqlite3 "$XUI_DB" "SELECT json_extract(settings,'\$.authUser') FROM inbounds WHERE id=$id;" 2>/dev/null || true)
  cur_pass=$(sqlite3 "$XUI_DB" "SELECT json_extract(settings,'\$.authPass') FROM inbounds WHERE id=$id;" 2>/dev/null || true)
  cur_seed=$(sqlite3 "$XUI_DB" "SELECT json_extract(settings,'\$.authSeed') FROM inbounds WHERE id=$id;" 2>/dev/null || true)
  cur_pw=$(sqlite3 "$XUI_DB" "SELECT json_extract(settings,'\$.password') FROM inbounds WHERE id=$id;" 2>/dev/null || true)
  cur_prefix=$(sqlite3 "$XUI_DB" "SELECT json_extract(settings,'\$.clientRandomPrefix') FROM inbounds WHERE id=$id;" 2>/dev/null || true)
  cur_clients=$(sqlite3 "$XUI_DB" "SELECT json_extract(settings,'\$.clients') FROM inbounds WHERE id=$id;" 2>/dev/null || true)
  [[ -z "$cur_user" || "$cur_user" == "null" ]] && cur_user=$(gen_hex 4)
  [[ -z "$cur_pass" || "$cur_pass" == "null" ]] && cur_pass=$(gen_b64)
  [[ -z "$cur_seed" || "$cur_seed" == "null" ]] && cur_seed=$(gen_hex 32)
  [[ -z "$cur_pw" || "$cur_pw" == "null" ]] && cur_pw=$(gen_b64)
  [[ -z "$cur_prefix" || "$cur_prefix" == "null" ]] && cur_prefix="$(gen_hex 4)/ffffffff"

  # --- json_set поверх текущего settings (ничего не затираем) ---
  local upd="UPDATE inbounds SET settings=json_set(CASE WHEN json_valid(settings) THEN settings ELSE '{}' END,
    '\$.${sn_col}','$domain','\$.certFile','$cert','\$.keyFile','$key','\$.authSeed','$cur_seed'"
  local new_settings
  case "$proto" in
    naive)
      upd+=",'\$.authUser','$cur_user','\$.authPass','$cur_pass','\$.useAcme',json('false'),'\$.behindCover',json('false'),'\$.hideOn443',json('false'),'\$.routeThroughXray',json('false')"
      [[ -z "$cur_clients" || "$cur_clients" == "null" ]] && upd+=",'\$.clients',json('[{\"email\":\"user\",\"enable\":true}]')"
      ;;
    anytls)
      upd+=",'\$.password','$cur_pw','\$.enabled',json('true'),'\$.port',$port"
      ;;
    trusttunnel|trust-tunnel)
      upd+=",'\$.clientRandomPrefix','$cur_prefix','\$.upstreamProtocol','http2','\$.listenPreset','fast','\$.clientDns',COALESCE(json_extract(settings,'\$.clientDns'),'1.1.1.1'),'\$.routeThroughXray',json('false')"
      [[ -z "$cur_clients" || "$cur_clients" == "null" ]] && upd+=",'\$.clients',json('[{\"email\":\"user\",\"enable\":true}]')"
      ;;
  esac
  upd+=") , listen=CASE WHEN COALESCE(listen,'')='' THEN '127.0.0.1' ELSE listen END WHERE id=$id;"
  local err_out
  err_out=$(sqlite3 "$XUI_DB" "$upd" 2>&1) || { err "SQL: $err_out"; return 1; }

  # cred-файл пользователю
  umask 077
  {
    echo "=== $proto #$id — ЗАПОЛНЕНО ==="
    echo "Домен (SNI): $domain"
    echo "Порт: $port (панель слушает 127.0.0.1:$port, снаружи https://$domain:443)"
    if [[ "$proto" == "naive" ]]; then
      echo "Сервисный логин: $cur_user"
      echo "Сервисный пароль: $cur_pass"
      echo "URL: naive+https://$cur_user:$cur_pass@$domain:443"
    elif [[ "$proto" == "anytls" ]]; then
      echo "Пароль: $cur_pw"
      echo "URL: anytls://$cur_pw@$domain:443/?sni=$domain"
    else
      echo "Клиентские tt:// ссылки с логином/паролем — в панели (инбаунд → share)"
    fi
    echo "authSeed: $cur_seed"
  } > "/root/.lucx-$proto-info"
  chmod 600 "/root/.lucx-$proto-info" 2>/dev/null || true
  umask 022

  # проверка из БД
  local chk_dom
  chk_dom=$(sqlite3 "$XUI_DB" "SELECT json_extract(settings,'\$.${sn_col}') FROM inbounds WHERE id=$id;" 2>/dev/null || true)
  if [[ "$chk_dom" == "$domain" ]]; then
    log "Заполнено: $proto #$id → $domain, ключи из wildcard, креды в /root/.lucx-$proto-info"
  else
    err "Проверка не прошла: settings.$sn_col = '$chk_dom'"
  fi
  nginx_reload || true
  systemctl restart x-ui >/dev/null 2>&1 || true
  log "Панель перезапущена — сервис $proto должен подняться (смотрите journalctl -u x-ui | grep tunnel)"
  return 0
}

# =====================================================================
# ПОЧИНКА ИНБАУНДА: SNI + сертификат + Reality dest (каноническая перезапись)
# =====================================================================
fix_inbound() {
  line; echo -e "${B}   ПОЧИНИТЬ ИНБАУНД (SNI + CERT + DEST)${N}"; line
  [[ -z "$XUI_DB" || ! -f "$XUI_DB" ]] && { err "x-ui.db не найден"; return 1; }
  [[ ! -f "$SNI_CONF" ]] && { err "Нет $SNI_CONF — сначала выполните п.1"; return 1; }
  sqlite3 -header -column "$XUI_DB" "SELECT id, protocol, port, remark FROM inbounds WHERE enable=1;" 2>/dev/null || true
  echo
  local id=""
  ask id "ID инбаунда" "" '^[0-9]+$'
  local proto="" port="" stream=""
  while IFS='|' read -r p po st; do proto="$p"; port="$po"; stream="$st"; done \
    < <(sqlite3 "$XUI_DB" "SELECT protocol, port, COALESCE(stream_settings,'') FROM inbounds WHERE id=$id AND enable=1;" 2>/dev/null || true)
  [[ -z "$proto" ]] && { err "Инбаунд #$id не найден"; return 1; }
  # --- типы, с которыми скрипт не работает / которые не нужно трогать ---
  if is_udp_proto "$proto"; then
    warn "С данным типом подключения скрипт не работает: #$id — $proto (UDP). SNI-скрытие за 443 применимо только к TCP (TLS/Reality)."
    return 0
  fi
  if [[ "$proto" == "tproxy" ]]; then
    warn "#$id tproxy — это tg web proxy: за 443 ведёт свой маршрут (setup_tproxy_web), отдельная настройка не нужна."
    return 0
  fi
  # SNI-скрытие требует TLS или Reality: голый tcp/ws без TLS за SNI не спрятать
  if ! grep -Eqi '"security": ?"tls"|"security":"tls"|reality' <<<"$stream" \
     && [[ "$proto" != naive* && "$proto" != "anytls" && "$proto" != trust* ]]; then
    warn "С данным типом подключения скрипт не работает: #$id ($proto, TLS/Reality не найдены в stream_settings)."
    return 0
  fi

  # tunnel-инбаунды LucX: заполняем settings (домен, ключи, креды), не stream
  case "$proto" in
    naive|anytls|trusttunnel|trust-tunnel)
      tunnel_inbound_fill "$id" "$proto" "$port"
      return $?
      ;;
  esac

  sni_used_load 2>/dev/null || true
  local panel_domain="${PANEL_DOMAIN:-}"
  [[ -z "$panel_domain" ]] && panel_domain=$(xui_get subDomain)
  [[ -z "$panel_domain" ]] && ask panel_domain "Домен панели" "panel.example.com" '^[a-zA-Z0-9.-]+$'
  [[ -n "$panel_domain" ]] && SNI_USED["$panel_domain"]="panel_backend"

  # --- vless reality: выбираем режим КАК при создании (свой/чужой) ---
  local is_reality=false
  if [[ "$proto" == "vless" ]] && { grep -qi '"security": *"reality"' <<<"$stream" || grep -qi '"security":"reality"' <<<"$stream"; }; then
    is_reality=true
  fi
  if [[ "$is_reality" == true ]]; then
    local cur_dest="" cur_sni=""
    cur_dest=$(sqlite3 "$XUI_DB" "SELECT COALESCE(json_extract(stream_settings,'\$.realitySettings.dest'),'') FROM inbounds WHERE id=$id;" 2>/dev/null || true)
    cur_sni=$(sqlite3 "$XUI_DB" "SELECT COALESCE(json_extract(stream_settings,'\$.realitySettings.serverNames[0]'),'') FROM inbounds WHERE id=$id;" 2>/dev/null || true)
    echo
    echo "  #$id vless reality — текущая цель: ${cur_sni:-не задана}, dest: ${cur_dest:-нет}"
    echo "   1) Чужой реалити «найти цели» — за 443 по SNI цели, серт НЕ нужен"
    echo "   2) Свой SNI-домен — нужен серт + decoy"
    local rmode=""
    local def_mode="2"
    [[ -n "$cur_dest" && "$cur_dest" != 127.0.0.1:* ]] && def_mode="1"
    ask rmode "Выбор [1/2]" "$def_mode" '^[12]$'
    if [[ "$rmode" == "1" ]]; then
      local tgt=""
      reality_target_menu tgt "#$id"
      REALITY_EXT_TARGET="$tgt"
      reality_ext_hide "$id" "$tgt" "$port" || warn "  не удалось спрятать #$id за 443 по цели"
      systemctl restart x-ui >/dev/null 2>&1 || true
      nginx_reload || true
      return 0
    fi
  fi

  # домен: из существующего маршрута, иначе спросить
  local domain=""
  domain=$(grep -E "^\s+\S+\s+inb_${id}_backend" "$SNI_CONF" 2>/dev/null | awk '{print $1}' | head -1 || true)
  if [[ -z "$domain" ]]; then
    local def="r.example.com"; [[ "$proto" == "anytls" ]] && def="at.example.com"
    ask_sni_domain domain "$id" "$def"
  fi
  local owner=""
  owner=$(sni_domain_owner "$domain" "$id") || true
  [[ -n "$owner" ]] && { err "Домен $domain занят ($owner)"; return 1; }
  SNI_USED["$domain"]="inb_${id}_backend"

  sni_upstream_add "inb_${id}_backend" "$port"
  sni_map_add "$domain" "inb_${id}_backend"

  # сертификат
  cert_issue "$domain" || return 1
  local cp_line="" cert="" key=""
  cp_line=$(cert_paths "$domain") || true
  [[ -z "$cp_line" ]] && { err "cert для $domain не найден"; return 1; }
  cert="${cp_line%% *}"; key="${cp_line##* }"

  # decoy ТОЛЬКО для Reality (dest для рукопожатия); остальным протоколам decoy не нужен
  local tls_port="" rdtpl="default"
  if grep -qi reality <<<"$stream"; then
    decoy_template_choose rdtpl "Decoy-заглушка для #$id (страница на SNI-домене)" "corporate"
    tls_port=$(( 4444 + id ))
    while ss -tlnH "sport = :$tls_port" 2>/dev/null | grep -q .; do tls_port=$((tls_port+1)); done
    mk_decoy "$tls_port" "$domain" "$cert" "$key" "/var/www/decoy-$id" "$rdtpl"
    log "  + decoy (Reality) на порту $tls_port ($rdtpl)"
  else
    log "  decoy не нужен ($proto — не Reality)"
  fi

  # hosts (подписки): address=домен панели, sni=домен инбаунда
  local has_hosts cols remark fields vals
  has_hosts=$(sqlite3 "$XUI_DB" "SELECT name FROM sqlite_master WHERE type='table' AND name='hosts';" 2>/dev/null || true)
  if [[ -n "$has_hosts" ]]; then
    cols=$(sqlite3 "$XUI_DB" "PRAGMA table_info(hosts);" 2>/dev/null | awk -F'|' '{print $2}' | tr '\n' ' ' || true)
    remark=$(proto_remark "$proto" "$stream")
    sqlite3 "$XUI_DB" "DELETE FROM hosts WHERE inbound_id=$id AND port=443;" 2>/dev/null || true
    fields="inbound_id,address,port"; vals="$id,'$panel_domain',443"
    grep -qw remark      <<<"$cols" && { fields+=",remark";      vals+=",'$remark'"; }
    # SNI («безопасность») не заполняем — панель на заполненное поле ругается
    grep -qw sni         <<<"$cols" && { fields+=",sni";         vals+=",''"; }
    grep -qw fingerprint <<<"$cols" && { fields+=",fingerprint"; vals+=",'firefox'"; }
    grep -qw is_disabled <<<"$cols" && { fields+=",is_disabled"; vals+=",0"; }
    grep -qw enable      <<<"$cols" && { fields+=",enable";      vals+=",1"; }
    sqlite3 "$XUI_DB" "INSERT INTO hosts ($fields) VALUES ($vals);" 2>/dev/null || true
  fi

  # --- каноническая перезапись stream_settings ---
  local new_stream=""
  if grep -qi reality <<<"$stream"; then
    local priv pub short_id keys xh_path transport="tcp" tr_settings=""
    priv=$(sqlite3 "$XUI_DB" "SELECT json_extract(stream_settings,'\$.realitySettings.privateKey') FROM inbounds WHERE id=$id;" 2>/dev/null || true)
    pub=$(sqlite3 "$XUI_DB" "SELECT json_extract(stream_settings,'\$.realitySettings.settings.publicKey') FROM inbounds WHERE id=$id;" 2>/dev/null || true)
    short_id=$(sqlite3 "$XUI_DB" "SELECT json_extract(stream_settings,'\$.realitySettings.shortIds[0]') FROM inbounds WHERE id=$id;" 2>/dev/null || true)
    xh_path=$(sqlite3 "$XUI_DB" "SELECT json_extract(stream_settings,'\$.xhttpSettings.path') FROM inbounds WHERE id=$id;" 2>/dev/null || true)
    if [[ -z "$priv" || "$priv" == "null" ]]; then
      keys=$(gen_reality_keys); priv="${keys%%|*}"; pub="${keys##*|}"
    fi
    [[ -z "$pub" || "$pub" == "null" ]] && pub=""
    [[ -z "$short_id" || "$short_id" == "null" ]] && short_id=$(gen_hex 8)
    if grep -qi '"network": *"xhttp"' <<<"$stream" || grep -qi '"network":"xhttp"' <<<"$stream"; then
      transport="xhttp"
      [[ -z "$xh_path" || "$xh_path" == "null" ]] && xh_path="/$(gen_hex 6)"
      tr_settings="\"xhttpSettings\":{\"path\":\"$xh_path\",\"host\":\"\",\"mode\":\"auto\"}"
    else
      tr_settings="\"tcpSettings\":{\"acceptProxyProtocol\":false,\"header\":{\"type\":\"none\"}}"
    fi
    new_stream="{\"network\":\"$transport\",\"security\":\"reality\",\"realitySettings\":{\"show\":false,\"xver\":0,\"dest\":\"127.0.0.1:$tls_port\",\"target\":\"127.0.0.1:$tls_port\",\"serverNames\":[\"$domain\"],\"privateKey\":\"$priv\",\"shortIds\":[\"$short_id\"],\"settings\":{\"publicKey\":\"$pub\",\"fingerprint\":\"firefox\",\"serverName\":\"\",\"spiderX\":\"/\"},\"fingerprint\":\"firefox\"},$tr_settings}"
  elif grep -Eq '"security": ?"tls"' <<<"$stream" || [[ "$proto" == naive* || "$proto" == "anytls" || "$proto" == trust* ]]; then
    new_stream="{\"network\":\"tcp\",\"security\":\"tls\",\"tlsSettings\":{\"serverName\":\"$domain\",\"minVersion\":\"1.2\",\"certificates\":[{\"certificateFile\":\"$cert\",\"keyFile\":\"$key\"}]},\"tcpSettings\":{\"acceptProxyProtocol\":false,\"header\":{\"type\":\"none\"}}}"
  else
    warn "Инбаунд #$id не Reality/TLS — stream_settings не менял (SNI/decoy/hosts обновлены)"
  fi

  [[ -n "$new_stream" ]] && sqlite3 "$XUI_DB" "UPDATE inbounds SET stream_settings='$new_stream' WHERE id=$id;" 2>/dev/null || true

  # --- проверка результата прямо из БД ---
  local chk="" ok=false
  chk=$(sqlite3 "$XUI_DB" "SELECT COALESCE(stream_settings,'') FROM inbounds WHERE id=$id;" 2>/dev/null || true)
  grep -Eq "\"dest\": ?\"127\.0\.0\.1:$tls_port\"" <<<"$chk" && ok=true
  grep -q "certificateFile\":\"$cert\"" <<<"$chk" && ok=true
  echo
  if [[ "$ok" == true ]]; then
    log "Готово — инбаунд #$id записан:"
  else
    err "Проверка не прошла — строка stream_settings:"
  fi
  echo "  ${chk:0:600}"
  nginx_reload || true
  systemctl restart x-ui >/dev/null 2>&1 || true
  log "В панели: Цель (dest) = 127.0.0.1:$tls_port · SNI = $domain · uTLS = firefox"
  pause
}

# =====================================================================
# ДОБАВИТЬ / ПРОВЕРИТЬ INBOUND
# =====================================================================
add_inbound() {
  line; echo -e "${B}   ДОБАВИТЬ / ПРОВЕРИТЬ INBOUND${N}"; line
  sqlite3 -header -column "$XUI_DB" "SELECT id, protocol, port, enable, remark FROM inbounds WHERE enable=1;" 2>/dev/null || true
  echo

  # Автодетект: TCP-инбаунды, созданные руками в панели и НЕ спрятанные за 443.
  # При активном файрволе (allowlist) их порт снаружи закрыт — они не работают.
  local -a UNHID=()
  local _id _proto _port _st
  while IFS='|' read -r _id _proto _port; do
    [[ -z "$_id" || -z "$_proto" ]] && continue
    is_udp_proto "$_proto" && continue
    grep -qE "^\s+\S+\s+inb_${_id}_backend" "$SNI_CONF" 2>/dev/null && continue
    # чужой reality (dest = внешняя цель) уже спрятан за 443 по SNI цели
    _st=$(sqlite3 "$XUI_DB" "SELECT COALESCE(stream_settings,'') FROM inbounds WHERE id=$_id;" 2>/dev/null || true)
    grep -qi '"security": *"reality"' <<<"$_st" && ! grep -Eq '"dest": *"127\.0\.0\.1:' <<<"$_st" && continue
    UNHID+=("$_id|$_proto|$_port")
  done < <(sqlite3 "$XUI_DB" "SELECT id, protocol, port FROM inbounds WHERE enable=1 AND port>0;" 2>/dev/null || true)
  if [[ ${#UNHID[@]} -gt 0 ]]; then
    warn "TCP-инбаунды НЕ за 443 — при включённом файрволе снаружи они НЕ работают:"
    local _u
    for _u in "${UNHID[@]}"; do echo "    • #${_u%%|*} ${_u#*|}"; done
    echo "    (UDP-инбаунды за 443 не прячутся — после создания примени п.11 заново)"
    local hide_all=""
    askyn hide_all "Спрятать их за 443 (по очереди спросит домен)?" "y"
    if [[ "$hide_all" == true ]]; then
      local pd0="${PANEL_DOMAIN:-$(xui_get subDomain 2>/dev/null || true)}"
      for _u in "${UNHID[@]}"; do
        IFS='|' read -r _id _proto _port <<<"$_u"
        configure_sni_for_inbound "$_id" "$_proto" "$_port" "$pd0" || warn "  #$_id: не удалось — см. п.2 → 2"
      done
      return 0
    fi
  fi

  echo "  1) Проверить все инбаунды в SNI"
  echo "  2) Настроить конкретный инбаунд"
  echo "  3) Создать новый инбаунд (VLESS Reality/TLS, anytls, naive, AWG...)"
  echo "  4) Починить/заполнить инбаунд (домен+ключи+креды; Reality dest)"
  echo "  0) Назад"
  local mode=""
  ask mode "Выбор" "1" '^[0-9]$'
  [[ "$mode" == "0" ]] && return 0
  if [[ "$mode" == "3" ]]; then
    create_inbounds_menu
    return 0
  fi
  if [[ "$mode" == "4" ]]; then
    fix_inbound
    return 0
  fi

  local panel_domain="${PANEL_DOMAIN:-}"
  [[ -z "$panel_domain" ]] && panel_domain=$(xui_get subDomain)
  [[ -z "$panel_domain" ]] && ask panel_domain "Домен панели" "panel.example.com" '^[a-zA-Z0-9.-]+$'

  if [[ "$mode" == "1" ]]; then
    local id proto port count=0
    while IFS='|' read -r id proto port; do
      [[ -z "$id" || -z "$proto" ]] && continue
      is_udp_proto "$proto" && continue
      local existing=""
      existing=$(grep -E "^\s+\S+\s+inb_${id}_backend" "$SNI_CONF" 2>/dev/null | awk '{print $1}' || true)
      if [[ -n "$existing" ]]; then
        log "#$id ($proto/$port) → SNI: $existing ✓"
        # hosts-починка: адрес = домен панели; SNI = цель reality (если это
        # чужой реалити), иначе сам домен
        local hsni="${panel_domain:-$existing}"
        if [[ "$proto" == "vless" ]]; then
          local dhost=""
          dhost=$(sqlite3 "$XUI_DB" "SELECT COALESCE(json_extract(stream_settings,'\$.realitySettings.dest'),'') FROM inbounds WHERE id=$id;" 2>/dev/null || true)
          dhost="${dhost%%:*}"
          [[ -n "$dhost" && "$dhost" != "127.0.0.1" ]] && hsni="$dhost"
        fi
        hosts_upsert "$id" "${panel_domain:-$existing}" "$hsni"
      else
        warn "#$id ($proto/$port) → НЕ в SNI"
        askyn do_it "Настроить #$id сейчас?" "y"
        [[ "$do_it" == true ]] && configure_sni_for_inbound "$id" "$proto" "$port" "$panel_domain"
      fi
      count=$((count+1))
    done < <(sqlite3 "$XUI_DB" "SELECT id, protocol, port FROM inbounds WHERE enable=1 AND port>0;" 2>/dev/null || true)
    # hosts-строки, ссылающиеся на несуществующие/выключенные инбаунды, — мусор
    # (например, от старого vless с неверной конечной точкой). Чистим.
    sqlite3 "$XUI_DB" "DELETE FROM hosts WHERE inbound_id NOT IN (SELECT id FROM inbounds WHERE enable=1);" 2>/dev/null || true
    log "Проверено: $count"
    sni_cleanup_stale   # убрать SNI-записи, не занятые инбаундами
    return 0
  fi

  local id=""
  ask id "ID инбаунда" "" '^[0-9]+$'
  local proto="" port=""
  while IFS='|' read -r p po; do proto="$p"; port="$po"; done < <(sqlite3 "$XUI_DB" "SELECT protocol, port FROM inbounds WHERE id=$id AND enable=1;" 2>/dev/null || true)
  [[ -z "$proto" ]] && { err "Инбаунд #$id не найден"; return 1; }
  configure_sni_for_inbound "$id" "$proto" "$port" "$panel_domain"
}

# =====================================================================
# УДАЛИТЬ INBOUND
# =====================================================================
remove_inbound() {
  line; echo -e "${B}   УДАЛИТЬ INBOUND${N}"; line
  [[ -z "$XUI_DB" || ! -f "$XUI_DB" ]] && { err "x-ui.db не найден"; return 1; }
  sni_used_load 2>/dev/null || true

  # список: ВСЕ инбаунды панели (и UDP тоже); SNI-привязка — пометкой,
  # домен панели помечен как неудаляемый здесь
  local -A SNI_BY_ID=()
  while IFS='|' read -r dom be iid; do
    [[ -n "$iid" ]] && SNI_BY_ID["$iid"]="$dom|$be"
  done < <(sni_map_domains)

  local iid proto port found=0 dom be
  while IFS='|' read -r iid proto port; do
    [[ -z "$iid" ]] && continue
    dom=""; be=""
    [[ -n "${SNI_BY_ID[$iid]:-}" ]] && IFS='|' read -r dom be <<<"${SNI_BY_ID[$iid]}"
    if [[ "$be" == "panel_backend" ]]; then
      printf "  #%-3s %-10s порт %-6s %s — домен ПАНЕЛИ (здесь не удалять)\n" "$iid" "${proto:-?}" "${port:-?}" "$dom"
    else
      printf "  #%-3s %-10s порт %-6s %s\n" "$iid" "${proto:-?}" "${port:-?}" "${dom:+[SNI: $dom]}"
    fi
    found=$((found+1))
  done < <(sqlite3 -cmd ".timeout 3000" "$XUI_DB" "SELECT id, protocol, port FROM inbounds ORDER BY id;" 2>/dev/null || true)
  [[ $found -eq 0 ]] && warn "Инбаундов в панели нет"

  echo
  local id=""
  ask id "ID инбаунда" "" '^[0-9]+$'

  local dom="" be=""
  while IFS='|' read -r d b i; do
    [[ "$i" == "$id" ]] && { dom="$d"; be="$b"; }
  done < <(sni_map_domains)

  local exists
  exists=$(sqlite3 "$XUI_DB" "SELECT COUNT(*) FROM inbounds WHERE id=$id;" 2>/dev/null || echo 0)
  [[ "$exists" == "0" && -z "$dom" ]] && { err "Инбаунд #$id не найден ни в SNI, ни в панели"; return 1; }

  # защита: домен панели удалять нельзя
  if [[ "$be" == "panel_backend" ]]; then
    err "«$dom» — домен ПАНЕЛИ. Удалять его здесь нельзя (п.17 убирает только устаревшие записи панели)."
    return 1
  fi

  # Что доступно: SNI-привязка / сам инбаунд
  local has_sni=false has_inb=false
  [[ -n "$dom" ]] && has_sni=true
  [[ "$exists" != "0" ]] && has_inb=true

  echo
  echo "  Что делать с #$id${dom:+ (SNI: $dom)}?"
  local a_sni="" a_inb="" n=0
  if [[ "$has_sni" == true ]]; then
    n=$((n+1)); a_sni="$n"
    echo "   $n) Удалить ТОЛЬКО SNI-привязку (инбаунд остаётся, уходит с 443)"
  fi
  if [[ "$has_inb" == true ]]; then
    n=$((n+1)); a_inb="$n"
    if [[ "$has_sni" == true ]]; then
      echo "   $n) Удалить инбаунд из панели + его SNI-привязку"
    else
      echo "   $n) Удалить инбаунд из панели"
    fi
  fi
  echo "   0) Отмена"
  line
  local action=""
  ask action "Выбор" "0" '^[0-9]+$'
  [[ "$action" == "0" ]] && return 0

  local do_sni=false do_inb=false
  [[ -n "$a_sni" && "$a_sni" == "$action" ]] && do_sni=true
  [[ -n "$a_inb" && "$a_inb" == "$action" ]] && { do_inb=true; do_sni=true; }
  [[ "$do_sni" == false && "$do_inb" == false ]] && { err "Нет такого выбора"; return 1; }

  # подтверждение
  local what=""
  if [[ "$do_inb" == false && "$do_sni" == true ]]; then
    what="SNI-привязку ($dom) для #$id — инбаунд останется, но tcp-порт уйдёт с 443"
  elif [[ "$do_inb" == true && "$do_sni" == true && -n "$dom" ]]; then
    what="SNI-привязку${dom:+ ($dom)} И сам инбаунд #$id из панели"
  else
    what="инбаунд #$id из панели"
  fi
  local confirm=""
  askyn confirm "Удалить $what?" "y"
  [[ "$confirm" == true ]] || return 0

  # 1) SNI-привязка
  if [[ "$do_sni" == true && -n "$dom" ]]; then
    sni_map_remove "$dom"
    [[ -n "$be" && "$be" != "panel_backend" ]] && sni_upstream_remove "$be"
    unset "SNI_USED[$dom]" 2>/dev/null || true
    stack_del_decoy "$dom"   # decoy-блок в stack.conf
    sqlite3 "$XUI_DB" "DELETE FROM hosts WHERE sni='$dom' OR (inbound_id=$id AND port=443);" 2>/dev/null || true
    log "SNI-привязка снята: $dom → #$id"
  fi

  # 2) сам инбаунд
  if [[ "$do_inb" == true && "$exists" != "0" ]]; then
    cp -n "$XUI_DB" "${XUI_DB}.bak.$(date +%Y%m%d%H%M%S)" 2>/dev/null || true
    sqlite3 "$XUI_DB" "DELETE FROM inbounds WHERE id=$id;" 2>/dev/null || true
    log "Инбаунд #$id удалён из панели (x-ui.db)"
  fi

  nginx_reload || true
  systemctl restart x-ui >/dev/null 2>&1 || true
  log "Готово."
}

# =====================================================================
# ОЧИСТКА SNI: оставляем только записи, занятые инбаундами
# =====================================================================
sni_map_domains() {
  [[ -f "$SNI_CONF" ]] || return 0
  local line
  local _re='^[[:space:]]+([A-Za-z0-9.-]+)[[:space:]]+inb_([0-9]+)_backend;'
  while IFS= read -r line; do
    [[ "$line" =~ $_re ]] || continue
    echo "${BASH_REMATCH[1]}|inb_${BASH_REMATCH[2]}_backend|${BASH_REMATCH[2]}"
  done < "$SNI_CONF"
}

sni_cleanup_stale() {
  line; echo -e "${B}   ОЧИСТКА SNI — ОСТАВИТЬ ТОЛЬКО ЗАНЯТОЕ${N}"; line
  [[ -z "$XUI_DB" || ! -f "$XUI_DB" ]] && { err "x-ui.db не найден"; return 1; }
  [[ ! -f "$SNI_CONF" ]] && { warn "$SNI_CONF не найден — чистить нечего"; return 0; }

  local -a dead_map=() dead_hosts=() dead_upstreams=()
  local tg_route_broken=0
  local row dom be iid cnt decoy pdom cur_panel uline uname
  cur_panel=$(xui_get subDomain)

  # 1) SNI-записи (map), за которыми нет живого инбаунда
  while IFS='|' read -r dom be iid; do
    [[ -z "$dom" ]] && continue
    # Разбор id не удался — перестраховка: запись не трогаем
    [[ ! "$iid" =~ ^[0-9]+$ ]] && continue
    # Читаем БД с таймаутом: x-ui периодически держит блокировку (трафик-статы),
    # без .timeout чтение падает с «database is locked» и даёт ПУСТОЙ ответ,
    # который раньше трактовался как «инбаунда нет» → ложное удаление.
    local cnt=""
    cnt=$(sqlite3 -cmd ".timeout 3000" "$XUI_DB" \
          "SELECT COUNT(*) FROM inbounds WHERE id=$iid;" 2>/dev/null | tr -d '[:space:]') || true
    if [[ -z "$cnt" ]]; then
      warn "  #$iid: БД не ответила (блокировка?) — SNI-запись «$dom» сохраняю (перестраховка)"
      continue
    fi
    if [[ "$cnt" == "0" ]]; then
      warn "  #$iid: в $XUI_DB инбаунда нет — SNI-запись «$dom» на удаление"
      dead_map+=("$dom|$be|$iid")
      continue
    fi
    # инбаунд есть; выключенный (enable=0) — тоже «есть»: запись сохраняем
    local en=""
    en=$(sqlite3 -cmd ".timeout 3000" "$XUI_DB" \
         "SELECT COALESCE(enable,'1') FROM inbounds WHERE id=$iid;" 2>/dev/null | tr -d '[:space:]') || true
    if [[ "$en" == "0" ]]; then
      log "  #$iid: инбаунд выключен (enable=0) — SNI-запись «$dom» сохраняю (включишь — заработает сразу)"
      continue
    fi
    # tproxy (tg web proxy) обслуживается ТОЛЬКО через tg_backend (setup_tproxy_web).
    # Любые «домен → inb_<id>_backend» для него — мусор прошлых багов (svc-N.example.com).
    local tproto=""
    tproto=$(sqlite3 -cmd ".timeout 3000" "$XUI_DB" \
             "SELECT protocol FROM inbounds WHERE id=$iid;" 2>/dev/null | tr -d '[:space:]') || true
    if [[ "$tproto" == "tproxy" && "$be" != "tg_backend" ]]; then
      warn "  #$iid tproxy: маршрут «$dom → $be» лишний (tg ведёт tg_backend) — на удаление"
      tg_route_broken=1
      dead_map+=("$dom|$be|$iid")
      continue
    fi
    # Чужой таргет reality, который инбаунд УЖЕ не использует → лишний SNI:
    # клиент берёт serverNames из инбаунда, домен в nginx должен СОВПАДАТЬ,
    # иначе соединение уходит в default и виснет по таймауту.
    local t tgt="" dst=""
    for t in "${REALITY_TARGETS[@]}"; do [[ "$dom" == "$t" ]] && { tgt=1; break; }; done
    if [[ -n "$tgt" ]]; then
      dst=$(sqlite3 -cmd ".timeout 3000" "$XUI_DB" "SELECT COALESCE(json_extract(stream_settings,'\$.realitySettings.dest'),'') FROM inbounds WHERE id=$iid;" 2>/dev/null || true)
      dst="${dst%%:*}"
      dst="$(printf '%s' "$dst" | tr -d '[:space:]')"
      if [[ -z "$dst" ]]; then
        warn "  #$iid: не смог сверить dest из БД — SNI-запись «$dom» сохраняю (перестраховка)"
      elif [[ "$dst" != "$dom" ]]; then
        dead_map+=("$dom|$be|$iid")
      fi
    fi
  done < <(sni_map_domains)

  # 2) старые домены панели в map (не совпадают с текущим subDomain панели)
  local _pre='^[[:space:]]+([A-Za-z0-9.-]+)[[:space:]]+panel_backend;'
  while IFS= read -r pdom; do
    [[ -z "$pdom" ]] && continue
    [[ "$pdom" == "default" ]] && continue
    [[ -z "$cur_panel" ]] && continue            # не знаем актуальный домен — не трогаем
    [[ "$pdom" == "$cur_panel" ]] && continue
    dead_map+=("$pdom|panel_backend|")
  done < <(grep -E "$_pre" "$SNI_CONF" 2>/dev/null | awk '{print $1}' || true)

  # 3) hosts-записи (порт 443 = «SNI включён») у инбаундов, которых нет в SNI
  while IFS='|' read -r iid dom; do
    [[ -z "$iid" ]] && continue
    grep -qE "^[[:space:]]+[A-Za-z0-9.-]+[[:space:]]+inb_${iid}_backend;" "$SNI_CONF" 2>/dev/null || dead_hosts+=("$iid|$dom")
  done < <(sqlite3 "$XUI_DB" "SELECT inbound_id, COALESCE(sni,'') FROM hosts WHERE port=443;" 2>/dev/null || true)

  # 4) upstream-ы, на которые не ссылается ни одна map-запись
  local _ure='^upstream ([A-Za-z0-9_-]+) \{'
  while IFS= read -r uline; do
    [[ "$uline" =~ $_ure ]] || continue
    uname="${BASH_REMATCH[1]}"
    [[ "$uname" == "panel_backend" ]] && continue
    grep -qE "[[:space:]]${uname};" "$SNI_CONF" 2>/dev/null || dead_upstreams+=("$uname")
  done < <(grep -E '^upstream ' "$SNI_CONF" 2>/dev/null || true)

  if [[ ${#dead_map[@]} -eq 0 && ${#dead_hosts[@]} -eq 0 && ${#dead_upstreams[@]} -eq 0 ]]; then
    log "Все SNI-записи заняты инбаундами — чистить нечего."
    return 0
  fi

  echo "▸ Будет удалено (не занято инбаундами / неактуально):"
  for row in "${dead_map[@]}"; do
    IFS='|' read -r dom be iid <<<"$row"
    if [[ -n "$iid" ]]; then
      echo "  map/upstream: $dom → $be (инбаунда #$iid нет)"
    else
      echo "  map: $dom → $be (не текущий домен панели${cur_panel:+, сейчас: $cur_panel})"
    fi
  done
  for row in "${dead_hosts[@]}"; do
    IFS='|' read -r iid dom <<<"$row"
    echo "  hosts (SNI-флаг): инбаунд #$iid, домен ${dom:-—}"
  done
  for uname in "${dead_upstreams[@]}"; do
    echo "  upstream: $uname (нет ссылок в map)"
  done
  echo
  askyn confirm "Удалить?" "y"
  [[ "$confirm" == true ]] || return 0

  for row in "${dead_map[@]}"; do
    IFS='|' read -r dom be iid <<<"$row"
    sni_map_remove "$dom"
    [[ -n "$be" && "$be" != "panel_backend" ]] && sni_upstream_remove "$be"
    unset "SNI_USED[$dom]" 2>/dev/null || true
    if [[ -n "$iid" ]]; then
      stack_del_decoy "$dom"
      sqlite3 "$XUI_DB" "DELETE FROM hosts WHERE inbound_id=$iid AND port=443;" 2>/dev/null || true
      sqlite3 "$XUI_DB" "DELETE FROM hosts WHERE sni='$dom';" 2>/dev/null || true
    fi
    log "Удалено из SNI: $dom"
  done
  for row in "${dead_hosts[@]}"; do
    IFS='|' read -r iid dom <<<"$row"
    sqlite3 "$XUI_DB" "DELETE FROM hosts WHERE inbound_id=$iid AND port=443;" 2>/dev/null || true
    log "Очищен SNI-флаг hosts: инбаунд #$iid"
  done
  for uname in "${dead_upstreams[@]}"; do
    sni_upstream_remove "$uname"
    log "Удалён upstream: $uname"
  done

  # Если удаляли лишний tproxy-маршрут — канонический tg-мап мог отсутствовать
  # (нарушение = tg без маршрута). Пересобираем: setup_tproxy_web идемпотентен,
  # вернёт upstream tg_backend + «tg-домен → tg_backend».
  if [[ "$tg_route_broken" == 1 ]]; then
    log "Восстанавливаю tg-маршрут (tg_backend + домен tproxy)…"
    setup_tproxy_web || warn "  пересборка tg-маршрута не прошла — запусти setup_tproxy_web вручную"
  fi

  nginx_reload || true
  systemctl restart x-ui >/dev/null 2>&1 || true
  log "Готово — остались только записи, занятые инбаундами."
}

# =====================================================================
# СМЕНА DECOY
# =====================================================================
change_decoy() {
  line; echo -e "${B}   СМЕНА DECOY${N}"; line
  stack_ensure
  local mline mport mdom
  local -a DOM_LIST=()
  local panel_conf="$STACK_CONF"
  local panel_dom=""
  panel_dom=$(xui_get subDomain 2>/dev/null || true)

  # ── Блок 1: домены инбаундов (из маркеров stack.conf)
  echo -e "${B}▸ Домены инбаундов (SNI):${N}"
  while IFS= read -r mline; do
    [[ "$mline" != "# >>> decoy "* ]] && continue
    mport=$(grep -oE 'port=[0-9]+'   <<<"$mline" | head -1 | cut -d= -f2)
    mdom=$(grep  -oE 'domain=[^ ]+$' <<<"$mline" | head -1 | cut -d= -f2-)
    [[ -z "$mdom" ]] && continue
    # панельный домен в маркерах не показываем (он пойдёт во второй блок)
    [[ -n "$panel_dom" && "$mdom" == "$panel_dom" ]] && continue
    DOM_LIST+=("$mdom")
    printf "  %2s) %-32s порт %s\n" "${#DOM_LIST[@]}" "$mdom" "$mport"
  done < "$STACK_CONF"
  [[ ${#DOM_LIST[@]} -eq 0 ]] && echo "  (нет)"

  # ── Блок 2: домен панели (отдельно, чтобы не путать с инбаундами)
  if [[ -n "$panel_dom" ]]; then
    echo
    echo -e "${B}▸ Домен панели:${N}"
    DOM_LIST+=("$panel_dom")
    printf "  %2s) %-32s порт 4443 [панель]\n" "${#DOM_LIST[@]}" "$panel_dom"
  fi

  [[ ${#DOM_LIST[@]} -eq 0 ]] && { err "SNI-домены не найдены — сначала п.1"; pause; return 1; }
  echo
  local pick=""
  ask pick "Номер домена (1-${#DOM_LIST[@]}, 0 — отмена)" "0" '^[0-9]+$'
  [[ "$pick" == "0" ]] && return 0
  (( pick > ${#DOM_LIST[@]} )) && { err "Нет такого номера"; pause; return 1; }
  local domain="${DOM_LIST[$((pick-1))]}"
  log "Выбран: $domain"
  log "Выбран: $domain"

  # --- смена decoy для домена панели ---
  if [[ -n "$panel_dom" && "$domain" == "$panel_dom" ]]; then
    # Корень панели = прокси на AdGuard? Шаблон ставить НЕЛЬЗЯ: перестанут
    # открываться AdGuard UI и работать DoH.
    # ВАЖНО: в блоке 4443 ЕСТЬ и другие proxy_pass (панель, подписки) —
    # отказ только если реально проксируемся на ТЕКУЩИЙ порт AdGuard.
    # AdGuard не установлен → adg_config_port пуст → шаблон менять МОЖНО.
    local pd_any="" adg_port_now=""
    pd_any=$(sed -n '/listen 127\.0\.0\.1:4443/,/^}/p' "$panel_conf" 2>/dev/null \
             | grep -oE 'proxy_pass https://127\.0\.0\.1:[0-9]+' || true)
    adg_port_now=$(adg_config_port 2>/dev/null || true)
    if [[ -n "$adg_port_now" ]] && grep -q ":$adg_port_now$" <<<"$pd_any"; then
      warn "Корень домена панели сейчас — прокси на AdGuard Home (порт $adg_port_now)."
      warn "Смена на шаблон ЗАПРЕЩЕНА: перестанет открываться AdGuard UI и работать DoH."
      warn "Варианты:"
      warn "  • п.1 «Первичная настройка» → другой режим AdGuard (отдельный SNI-домен / локально),"
      warn "  • п.14 «AdGuard Home: установить / удалить», затем п.4 — выбрать шаблон."
      pause; return 0
    fi
    local tpl=""
    decoy_template_choose tpl "Новый decoy панели" "corporate"
    if [[ "$tpl" == custom:* ]]; then
      local custom_path="${tpl#custom:}"
      if [[ -d "$custom_path" ]]; then
        if panel_decoy_apply custom "$custom_path"; then
          log "Decoy панели: свой сайт из $custom_path"
        else
          warn "Не удалось обновить stack.conf — смотри ошибки выше"
        fi
      else
        err "Папка $custom_path не найдена"
      fi
      pause; return 0
    fi
    # если сейчас PANEL_DECOY_DIR — symlink/каталог от прошлого custom, пересоздаём
    if [[ -L "$PANEL_DECOY_DIR" ]]; then
      rm -f "$PANEL_DECOY_DIR"
      panel_decoy_apply stub >/dev/null 2>&1 || true
    fi
    mkdir -p "$PANEL_DECOY_DIR" 2>/dev/null || true
    local tpl_src="$DECOY_TPL_DIR/$tpl.html"
    is_login_template "$tpl" && tpl_src="$DECOY_LOGIN_DIR/$tpl.html"
    if [[ -f "$tpl_src" ]]; then
      cp -f "$tpl_src" "$PANEL_DECOY_DIR/index.html" 2>/dev/null || true
      chown www-data:www-data "$PANEL_DECOY_DIR/index.html" 2>/dev/null || true
      nginx_reload || true
      log "Decoy панели сменён на «$tpl»"
    else
      err "Шаблон «$tpl» не найден (ищу $tpl_src). Доступны:"
      ls -1 "$DECOY_TPL_DIR" 2>/dev/null | sed 's/^/    /'
    fi
    pause; return 0
  fi

  local meta port="" root_old="" cert="" key=""
  meta=$(stack_decoy_meta "$domain")
  if [[ -z "$meta" ]]; then
    err "Decoy-блок для $domain не найден в $STACK_CONF."
    grep "# >>> decoy" "$STACK_CONF" 2>/dev/null | sed 's/^/    /' || warn "    (ни одного)"
    pause; return 1
  fi
  read -r port root_old cert key <<<"$meta"

  local tpl=""
  decoy_template_choose tpl "Новый decoy" "default"
  [[ -z "$tpl" ]] && { warn "Шаблон не определён — применяю default"; tpl="default"; }

  # opts для mk_decoy: redirect — спросить URL; остальным — UA-свитч для ботов
  local opts=""
  if [[ "$tpl" == "redirect" ]]; then
    local rurl=""
    ask rurl "Куда редиректить (URL)" "https://www.google.com/" '^https?://[A-Za-z0-9.-]+'
    opts="redir=$rurl"
  elif [[ "$tpl" != "locked" ]]; then
    local ub="true"
    askyn ub "Прятать сайт от ботов/сканеров (404 по User-Agent)?" "y"
    [[ "$ub" == true ]] && opts="ua404=1" || opts="ua404=0"
  fi

  local final_root="$root_old"
  if [[ "$tpl" == custom:* ]]; then
    final_root="${tpl#custom:}"
  elif [[ "$root_old" != /var/www/decoy-* ]]; then
    local safe
    safe=$(echo "$domain" | tr -c "a-z0-9" "_")
    final_root="/var/www/decoy-${safe}"
    mkdir -p "$final_root" 2>/dev/null || true
    log "Каталог $root_old оставляю нетронутым (custom-папка)"
    log "  Шаблон «$tpl» -> $final_root"
  fi
  mk_decoy "$port" "$domain" "$cert" "$key" "$final_root" "$tpl" "$opts"

  # Перечитать НОВЫЙ root из маркера: для custom он отличается от старого
  local meta_new="" root_new=""
  meta_new=$(stack_decoy_meta "$domain") || meta_new=""
  [[ -n "$meta_new" ]] && read -r _p root_new _c _k <<<"$meta_new"

  if ! nginx -t >/dev/null 2>&1; then
    err "nginx -t не прошёл после смены decoy:"
    nginx -t 2>&1 | tail -5 | sed 's/^/    /'
    pause; return 1
  fi
  nginx_reload || true

  # Живая проверка: что реально отдаёт nginx под этим доменом
  local live_code="" live_md5="" idx_md5="" verdict=""
  live_code=$(curl -sk -o /tmp/.decoy_check -w '%{http_code}' --max-time 6 \
    -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124 Safari/537.36" \
    -H "Host: $domain" "https://127.0.0.1:$port/" 2>/dev/null || echo 000)
  case "$tpl" in
    custom:*)
      idx_md5=$(md5sum "${tpl#custom:}/index.html" 2>/dev/null | awk '{print $1}')
      live_md5=$(md5sum /tmp/.decoy_check 2>/dev/null | awk '{print $1}')
      if [[ "$live_code" == "200" && -n "$idx_md5" && "$live_md5" == "$idx_md5" ]]; then
        verdict="HTTP 200, контент = ${tpl#custom:}/index.html ✓"
      elif [[ "$live_code" == "200" && -z "$idx_md5" ]]; then
        verdict="HTTP 200, но ${tpl#custom:}/index.html НЕ найден (nginx мог отдать другой файл)"
      elif [[ "$live_code" == "200" ]]; then
        verdict="HTTP 200, но контент ОТЛИЧАЕТСЯ от ${tpl#custom:}/index.html"
      else
        verdict="HTTP $live_code — nginx не может отдать файл (права / try_files)"
      fi
      ;;
    redirect|locked)
      verdict="HTTP $live_code (ожидаемо для redirect/locked)"
      ;;
    *)
      if [[ "$live_code" == "200" ]]; then verdict="HTTP 200 — decoy «$tpl» отдаётся ✓"
      else verdict="HTTP $live_code — decoy не отвечает"; fi
      ;;
  esac
  rm -f /tmp/.decoy_check 2>/dev/null || true

  log "Decoy применён: «$tpl» (root=${root_new:-${root_old:-?}})"
  echo "    Проверка nginx: $verdict"
  case "$live_code" in
    200|302|401) ;;
    *) warn "Смотри /var/log/nginx/error.log и права www-data на ${root_new:-$root_old}" ;;
  esac
  warn "Если в браузере всё ещё старая страница — Ctrl+F5 (кэш браузера, не сервера)"
  pause
}

# =====================================================================
# СТАТУС
# =====================================================================
show_status() {
  line; echo -e "${B}   СТАТУС${N}"; line
  echo "  nginx:    $(systemctl is-active nginx 2>/dev/null || echo unknown)"
  echo "  x-ui:     $(systemctl is-active x-ui 2>/dev/null || echo unknown)"
  [[ "$ADG_PRESENT" == true && -n "$ADG_SERVICE" ]] && echo "  $ADG_SERVICE: $(systemctl is-active "$ADG_SERVICE" 2>/dev/null || echo unknown)"
  echo "  fail2ban: $(systemctl is-active fail2ban 2>/dev/null || echo unknown)"
  echo "  xray bin: ${XRAY_BIN:-не найден}"

  # ── Доступы: URL панели / AdGuard / DoH + логины-пароли из cred-файлов
  local pdom="" ppath="" adg_url="" doh_url=""
  pdom=$(xui_get webDomain 2>/dev/null || true)
  [[ -z "$pdom" || "$pdom" == "null" ]] && pdom="${PANEL_DOMAIN:-}"
  ppath=$(xui_get webBasePath 2>/dev/null || true)
  [[ "$ppath" == "null" ]] && ppath=""
  echo; echo "▸ Доступы:"
  if [[ -n "$pdom" ]]; then
    echo "  Панель:  https://$pdom$ppath"
  else
    echo "  Панель:  домен не задан"
  fi
  if [[ "$ADG_PRESENT" == true ]]; then
    # режим AdGuard: за панелью (прокси в 4443-блоке) / отдельный SNI-домен / локально
    if grep -q "listen 127.0.0.1:4443" "$STACK_CONF" 2>/dev/null && \
       sed -n '/listen 127\.0\.0\.1:4443/,/^}/p' "$STACK_CONF" 2>/dev/null | grep -q "proxy_pass https://127.0.0.1:"; then
      adg_url="https://$pdom/"
    elif grep -qE "^[[:space:]]+[A-Za-z0-9.-]+[[:space:]]+agh_backend;" "$SNI_CONF" 2>/dev/null; then
      local adom=""
      adom=$(grep -E "^[[:space:]]+[A-Za-z0-9.-]+[[:space:]]+agh_backend;" "$SNI_CONF" 2>/dev/null | awk '{print $1}' | head -1)
      [[ -n "$adom" ]] && adg_url="https://$adom/"
    fi
    if [[ -n "$adg_url" ]]; then
      doh_url="${adg_url}dns-query"
    else
      local aport=""
      aport=$(adg_config_port 2>/dev/null || true)
      adg_url="http://127.0.0.1:${aport:-3000} (локально, SSH-туннель)"
      doh_url="— (AdGuard локально)"
    fi
    echo "  AdGuard: $adg_url"
    echo "  DoH:     $doh_url"
  fi
  if [[ -f /root/panel-credentials.txt ]]; then
    echo "  ── панель (/root/panel-credentials.txt):"
    sed 's/^/  │    /' /root/panel-credentials.txt
  fi
  if [[ "$ADG_PRESENT" == true && -f /root/adguard-credentials.txt ]]; then
    echo "  ── AdGuard (/root/adguard-credentials.txt):"
    sed 's/^/  │    /' /root/adguard-credentials.txt
  fi

  echo; echo "▸ SNI:"
  grep -E '^\s+[a-zA-Z0-9.-]+\.|^upstream' "$SNI_CONF" 2>/dev/null | sed 's/^/  /' || true
  echo; echo "▸ Inbounds:"
  sqlite3 -header -column "$XUI_DB" "SELECT id, protocol, port, listen, enable, remark FROM inbounds ORDER BY id;" 2>/dev/null || true
  # баны: в шапке меню — сумма по всем jail'ам, детали — в п.7; здесь не дублируем
  pause
}


# =====================================================================
# PRE-INSTALL SNAPSHOT — снимок всего, во что скрипт может вмешаться.
# Делается при первом запуске (по согласию пользователя) или по п.24.
# Хранится в /root/stack-backups/pre-install-<timestamp>/
# =====================================================================
take_pre_install_snapshot() {
  local ts; ts=$(date +%Y%m%d-%H%M%S)
  local dir="$BACKUP_DIR/pre-install-$ts"
  mkdir -p "$dir" 2>/dev/null || { err "Не могу создать $dir"; return 1; }

  log "Снимок состояния: $dir"
  log "  (x-ui.db, nginx, UFW, iptables, fail2ban, systemd-units, letsencrypt-renewal, AdGuard)"

  # 1. x-ui.db + /etc/x-ui
  if [[ -n "$XUI_DB" && -f "$XUI_DB" ]]; then
    cp -a "$XUI_DB" "$dir/x-ui.db" 2>/dev/null || true
    [[ -d /etc/x-ui ]] && cp -a /etc/x-ui "$dir/etc-x-ui" 2>/dev/null || true
  fi

  # 2. nginx — весь конфиг целиком
  mkdir -p "$dir/nginx"
  cp -a /etc/nginx/nginx.conf "$dir/nginx/" 2>/dev/null || true
  for d in sites-available sites-enabled streams-available streams-enabled snippets conf.d; do
    [[ -d "/etc/nginx/$d" ]] && cp -a "/etc/nginx/$d" "$dir/nginx/" 2>/dev/null || true
  done

  # 3. UFW + iptables + маршруты
  mkdir -p "$dir/ufw"
  [[ -d /etc/ufw ]] && cp -a /etc/ufw "$dir/ufw/etc-ufw" 2>/dev/null || true
  [[ -f /etc/default/ufw ]] && cp -a /etc/default/ufw "$dir/ufw/" 2>/dev/null || true
  iptables-save   > "$dir/ufw/iptables.v4"  2>/dev/null || true
  ip6tables-save  > "$dir/ufw/iptables.v6"  2>/dev/null || true
  ip -4 route show > "$dir/ufw/routes.v4" 2>/dev/null || true
  ip -6 route show > "$dir/ufw/routes.v6" 2>/dev/null || true

  # 4. fail2ban
  if [[ -d /etc/fail2ban ]]; then
    mkdir -p "$dir/fail2ban"
    cp -a /etc/fail2ban "$dir/fail2ban/etc-fail2ban" 2>/dev/null || true
  fi

  # 5. systemd units стека
  mkdir -p "$dir/systemd"
  cp -a /etc/systemd/system/stack-heal.service /etc/systemd/system/stack-heal.timer "$dir/systemd/" 2>/dev/null || true
  cp -a /etc/systemd/system/x-ui.service "$dir/systemd/" 2>/dev/null || true

  # 6. letsencrypt renewal (без ключей)
  if [[ -d /etc/letsencrypt ]]; then
    mkdir -p "$dir/letsencrypt"
    cp -a /etc/letsencrypt/renewal "$dir/letsencrypt/" 2>/dev/null || true
    cp -a /etc/letsencrypt/renewal-hooks "$dir/letsencrypt/" 2>/dev/null || true
    cp -a /etc/letsencrypt/cli.ini "$dir/letsencrypt/" 2>/dev/null || true
  fi

  # 7. logrotate стека
  [[ -f /etc/logrotate.d/stack-decoy ]] && cp -a /etc/logrotate.d/stack-decoy "$dir/" 2>/dev/null || true

  # 8. AdGuard Home config
  if [[ -n "$ADG_CONFIG" && -f "$ADG_CONFIG" ]]; then
    cp -a "$ADG_CONFIG" "$dir/AdGuardHome.yaml" 2>/dev/null || true
  fi

  # 9. Контекст: пакеты + мета
  dpkg --get-selections > "$dir/dpkg-selections.txt" 2>/dev/null || true
  apt-mark showmanual > "$dir/apt-manual.txt" 2>/dev/null || true
  {
    echo "Дата: $(date '+%F %T')"
    echo "Хост: $(hostname)"
    echo "Панель: ${PANEL_FLAVOR:-unknown}"
    echo "x-ui.db: $XUI_DB"
    echo "AdGuard: ${ADG_SERVICE:-—}"
    echo "nginx: $(nginx -v 2>&1 || echo —)"
    echo "fail2ban: $(fail2ban-client --version 2>/dev/null | head -1 || echo —)"
  } > "$dir/INFO.txt"

  # Архив
  (cd "$BACKUP_DIR" && tar czf "pre-install-$ts.tar.gz" "pre-install-$ts" 2>/dev/null) || true

  log "Снимок готов: $dir"
  log "  архив: $BACKUP_DIR/pre-install-$ts.tar.gz"
  return 0
}

restore_pre_install_snapshot() {
  line; echo -e "${B}   ВОССТАНОВЛЕНИЕ ИЗ PRE-INSTALL СНИМКА${N}"; line
  local snaps
  snaps=$(ls -1dt "$BACKUP_DIR"/pre-install-* 2>/dev/null | grep -v "\.tar\.gz$" | head -20)
  if [[ -z "$snaps" ]]; then
    warn "Снимков не найдено в $BACKUP_DIR/pre-install-*"; pause; return 0
  fi
  local i=1 d
  while IFS= read -r d; do
    [[ -z "$d" ]] && continue
    local info
    info=$(head -1 "$d/INFO.txt" 2>/dev/null || echo "—")
    printf "  %2d) %-40s %s
" "$i" "$(basename "$d")" "$info"
    i=$((i+1))
  done <<<"$snaps"
  echo
  local pick=""
  ask pick "Номер снимка (0 — отмена)" "0" '^[0-9]+$'
  [[ "$pick" == "0" ]] && return 0
  local chosen=""
  chosen=$(printf '%s
' "$snaps" | sed -n "${pick}p")
  [[ -z "$chosen" || ! -d "$chosen" ]] && { err "Не найден снимок #$pick"; pause; return 1; }

  echo
  echo -e "${R}ВНИМАНИЕ:${N} восстановление перезапишет текущее состояние:"
  echo "  • $XUI_DB (инбаунды и настройки панели)"
  echo "  • /etc/nginx (все сайты и стримы)"
  echo "  • правила UFW/iptables"
  echo "  • /etc/fail2ban (если был в снимке)"
  echo "  • systemd units стека (stack-heal, x-ui.service)"
  echo "  • /etc/letsencrypt/renewal + renewal-hooks"
  echo
  local sure=""
  ask sure "Для подтверждения введи YES" "" '^YES$'
  [[ "$sure" == "YES" ]] || { log "Отменено"; pause; return 0; }
  audit "rollback: восстановление из pre-install snapshot $chosen"

  log "Бэкап текущего состояния перед восстановлением…"
  take_pre_install_snapshot >/dev/null 2>&1 || true

  log "Остановка сервисов…"
  systemctl stop x-ui 2>/dev/null || true
  systemctl stop nginx 2>/dev/null || true
  [[ -n "$ADG_SERVICE" ]] && systemctl stop "$ADG_SERVICE" 2>/dev/null || true

  if [[ -f "$chosen/x-ui.db" && -n "$XUI_DB" ]]; then
    cp -a "$chosen/x-ui.db" "$XUI_DB" 2>/dev/null && log "  x-ui.db восстановлен"
  fi
  if [[ -d "$chosen/etc-x-ui" ]]; then
    cp -a "$chosen/etc-x-ui/." /etc/x-ui/ 2>/dev/null || true
  fi

  if [[ -d "$chosen/nginx" ]]; then
    [[ -f "$chosen/nginx/nginx.conf" ]] && cp -a "$chosen/nginx/nginx.conf" /etc/nginx/nginx.conf 2>/dev/null
    for d in sites-available sites-enabled streams-available streams-enabled snippets conf.d; do
      if [[ -d "$chosen/nginx/$d" ]]; then
        rm -rf "/etc/nginx/$d"
        cp -a "$chosen/nginx/$d" "/etc/nginx/" 2>/dev/null || true
      fi
    done
    log "  /etc/nginx восстановлен"
  fi

  if [[ -d "$chosen/ufw" ]]; then
    [[ -f "$chosen/ufw/iptables.v4" ]] && iptables-restore  < "$chosen/ufw/iptables.v4" 2>/dev/null && log "  iptables v4 восстановлены"
    [[ -f "$chosen/ufw/iptables.v6" ]] && ip6tables-restore < "$chosen/ufw/iptables.v6" 2>/dev/null || true
    if [[ -d "$chosen/ufw/etc-ufw" ]]; then
      rm -rf /etc/ufw
      cp -a "$chosen/ufw/etc-ufw" /etc/ufw 2>/dev/null || true
      [[ -f "$chosen/ufw/ufw" ]] && cp -a "$chosen/ufw/ufw" /etc/default/ufw 2>/dev/null || true
      log "  /etc/ufw восстановлен"
    fi
  fi

  if [[ -d "$chosen/fail2ban/etc-fail2ban" ]]; then
    rm -rf /etc/fail2ban
    cp -a "$chosen/fail2ban/etc-fail2ban" /etc/fail2ban 2>/dev/null || true
    log "  /etc/fail2ban восстановлен"
  fi

  if [[ -d "$chosen/systemd" ]]; then
    for u in stack-heal.service stack-heal.timer x-ui.service; do
      [[ -f "$chosen/systemd/$u" ]] && cp -a "$chosen/systemd/$u" /etc/systemd/system/ 2>/dev/null
    done
    systemctl daemon-reload 2>/dev/null || true
    log "  systemd units восстановлены"
  fi

  if [[ -d "$chosen/letsencrypt" ]]; then
    [[ -d "$chosen/letsencrypt/renewal" ]] && { rm -rf /etc/letsencrypt/renewal; cp -a "$chosen/letsencrypt/renewal" /etc/letsencrypt/ 2>/dev/null; }
    [[ -d "$chosen/letsencrypt/renewal-hooks" ]] && { rm -rf /etc/letsencrypt/renewal-hooks; cp -a "$chosen/letsencrypt/renewal-hooks" /etc/letsencrypt/ 2>/dev/null; }
    [[ -f "$chosen/letsencrypt/cli.ini" ]] && cp -a "$chosen/letsencrypt/cli.ini" /etc/letsencrypt/ 2>/dev/null
    log "  letsencrypt renewal восстановлен"
  fi

  [[ -f "$chosen/stack-decoy" ]] && cp -a "$chosen/stack-decoy" /etc/logrotate.d/ 2>/dev/null || true

  if [[ -f "$chosen/AdGuardHome.yaml" && -n "$ADG_CONFIG" ]]; then
    cp -a "$chosen/AdGuardHome.yaml" "$ADG_CONFIG" 2>/dev/null && log "  AdGuardHome.yaml восстановлен"
  fi

  log "Запуск сервисов…"
  systemctl start nginx 2>/dev/null || true
  systemctl start x-ui 2>/dev/null || true
  [[ -n "$ADG_SERVICE" ]] && systemctl start "$ADG_SERVICE" 2>/dev/null || true
  systemctl restart fail2ban 2>/dev/null || true
  nginx -t >/dev/null 2>&1 && log "  nginx -t OK" || warn "  nginx -t провалился — проверь конфиг"

  line
  log "Восстановление из pre-install завершено: $chosen"
  line
  pause
}

# =====================================================================
# БЭКАП
# =====================================================================
backup_config() {
  line; echo -e "${B}   БЭКАП${N}"; line
  mkdir -p "$BACKUP_DIR" 2>/dev/null || true
  local ts file
  ts=$(date +%F_%H%M%S)
  file="$BACKUP_DIR/stack-backup-$ts.tar.gz"
  local -a files=(
    /etc/nginx/nginx.conf /etc/nginx/streams-enabled/ /etc/nginx/sites-enabled/
    "$XUI_DB" /etc/letsencrypt/renewal/
    /etc/fail2ban/jail.d/decoy-login.local
    /etc/fail2ban/filter.d/decoy-login.conf
  )
  [[ -n "$ADG_CONFIG" && -f "$ADG_CONFIG" ]] && files+=("$ADG_CONFIG")
  tar czf "$file" "${files[@]}" 2>/dev/null || true
  log "Бэкап: $file"
  ls -lh "$file" 2>/dev/null || true
  pause
}

restore_config() {
  line; echo -e "${B}   ВОССТАНОВЛЕНИЕ${N}"; line
  mkdir -p "$BACKUP_DIR" 2>/dev/null || true
  ls -1t "$BACKUP_DIR"/stack-backup-*.tar.gz 2>/dev/null | nl -w2 -s') ' || { warn "Нет бэкапов"; pause; return 0; }
  local choice=""
  ask choice "Номер (0 — отмена)" "0" '^[0-9]+$'
  [[ "$choice" == 0 ]] && return 0
  local file=""
  file=$(ls -1t "$BACKUP_DIR"/stack-backup-*.tar.gz 2>/dev/null | sed -n "${choice}p" || true)
  [[ -z "$file" || ! -f "$file" ]] && { err "Не найден"; return 1; }
  askyn confirm "Восстановить из $file?" "n"
  [[ "$confirm" == true ]] || return 0
  audit "restore: восстановление конфигурации из $(basename "$file")"
  backup_config >/dev/null 2>&1 || true
  systemctl stop nginx 2>/dev/null || true
  systemctl stop x-ui  2>/dev/null || true
  [[ "$ADG_PRESENT" == true && -n "$ADG_SERVICE" ]] && systemctl stop "$ADG_SERVICE" 2>/dev/null || true
  tar xzf "$file" -C / 2>/dev/null && log "Файлы восстановлены"
  nginx -t 2>/dev/null && systemctl start nginx && log "Nginx запущен"
  systemctl start x-ui 2>/dev/null || true
  [[ "$ADG_PRESENT" == true && -n "$ADG_SERVICE" ]] && systemctl start "$ADG_SERVICE" 2>/dev/null || true
  systemctl restart fail2ban 2>/dev/null || true
  pause
}

# =====================================================================
# ПЕРЕЕЗД ДОМЕНА ПАНЕЛИ: серт + БД (webDomain/hosts) + nginx (блоки/map)
# + decoy-маркер + credentials. Старый серт опционально отзывается.
# =====================================================================
panel_domain_migrate() {
  line; echo -e "${B}   ПЕРЕЕЗД ДОМЕНА ПАНЕЛИ${N}"; line
  [[ -f "$XUI_DB" ]] || { err "x-ui.db не найден"; pause; return 1; }
  local old=""; old=$(xui_get webDomain 2>/dev/null | tr -d '[:space:]')
  if [[ -z "$old" || "$old" == "null" ]]; then
    ask old "Текущий домен панели (не найден в БД)" "" '^[a-zA-Z0-9.-]+$'
  fi
  [[ -z "$old" ]] && { warn "Отмена"; pause; return 0; }
  local new=""
  ask new "НОВЫЙ домен панели" "" '^[a-zA-Z0-9.-]+$'
  [[ -z "$new" || "$new" == "$old" ]] && { warn "Отмена"; pause; return 0; }

  echo
  echo "  Будет сделано:"
  echo "   • серт для $new (certbot, с текущим email LE)"
  echo "   • панель: webDomain → $new (stop → edit → start)"
  echo "   • hosts-записи: address $old → $new (ссылки подписок обновятся сами)"
  echo "   • nginx: stack.conf + SNI-map, маркер decoy панели, credentials-файл"
  if check_domain_points_to_server "$new" >/dev/null 2>&1; then
    ok "DNS: $new указывает на этот сервер"
  else
    local go=""
    askyn go "DNS: $new НЕ указывает на сервер (или не резолвится). Продолжить?" "n"
    [[ "$go" == true ]] || { pause; return 0; }
  fi
  local go=""
  askyn go "Начать переезд $old → $new?" "n"
  [[ "$go" == true ]] || { pause; return 0; }
  auto_backup_stack >/dev/null 2>&1 || true

  # 1) серт нового домена (уважает заморозку п.25 — снял freeze, если надо)
  cert_issue "$new" || warn "Серт $new не выпущен — панель временно на старом серте; повтори п.10 позже"

  # 2) БД панели: webDomain + hosts
  systemctl stop x-ui 2>/dev/null || true
  sqlite3 "$XUI_DB" "UPDATE settings SET value='$new' WHERE key='webDomain';" 2>/dev/null || true
  sqlite3 "$XUI_DB" "UPDATE hosts SET address='$new' WHERE address='$old';" 2>/dev/null || true

  # 3) nginx: панельные вхождения old → new (домен панели нигде больше не используется)
  local oesc="${old//./\\.}"
  local confs=("$STACK_CONF" "$SNI_CONF")
  local cf
  for cf in "${confs[@]}"; do
    [[ -f "$cf" ]] && cp -a "$cf" "$cf.bak-migrate-$(date +%Y%m%d-%H%M%S)"
  done
  sed -i "s/$oesc/$new/g" "$STACK_CONF" 2>/dev/null || true
  [[ -f "$SNI_CONF" ]] && sed -i "s/$oesc/$new/g" "$SNI_CONF" 2>/dev/null || true
  [[ -f /root/panel-credentials.txt ]] && sed -i "s/$oesc/$new/g" /root/panel-credentials.txt 2>/dev/null || true

  if nginx -t >/dev/null 2>&1; then
    nginx_reload || true
  else
    err "nginx -t не прошёл после замены — откатываю конфиги:"
    nginx -t 2>&1 | tail -4 | sed 's/^/    /'
    for cf in "${confs[@]}"; do
      local bak; bak=$(ls -t "$cf".bak-migrate-* 2>/dev/null | head -1)
      [[ -n "$bak" ]] && cp -a "$bak" "$cf"
    done
    systemctl start x-ui 2>/dev/null || true
    pause; return 1
  fi
  systemctl start x-ui 2>/dev/null || true

  # 4) старый серт — предложить убрать
  if cert_paths "$old" >/dev/null 2>&1; then
    local del=""
    askyn del "Отозвать и удалить старый серт $old? (клиенты должны перейти на $new)" "n"
    if [[ "$del" == true ]]; then
      certbot delete --cert-name "$old" -n >/dev/null 2>&1 \
        && log "Старый серт $old удалён" \
        || warn "Не удалось удалить серт $old — удали вручную: certbot delete --cert-name $old"
    fi
  fi

  echo
  ok "Переезд завершён: панель и подписки теперь на $new"
  warn "  • проверь панель и подписку в браузере (Ctrl+F5)"
  warn "  • у клиентов обнови ссылки (или просто перечитай подписку — URL меняется на $new)"
  warn "  • если decoy панели показывал старый домен в тексте — смени шаблон п.4"
  audit "panel: домен панели $old → $new"
  pause
}

certs_menu() {
  line; echo -e "${B}   СЕРТИФИКАТЫ${N}"; line
  # активный серт панели из настроек x-ui (в т.ч. выпущенный через меню x-ui)
  local db_line dc dk dd
  db_line=$(panel_cert_from_db) || true
  if [[ -n "$db_line" ]]; then
    dc="${db_line%% *}"; dk=$(echo "$db_line" | awk '{print $2}'); dd=$(echo "$db_line" | awk '{print $3}')
    echo -e "  ${G}▸ Активный серт панели (вписан в x-ui):${N} ${dd:-домен не определён}"
    echo "      cert: $dc"
    echo "      key:  $dk"
    echo "      действует до: $(openssl x509 -noout -enddate -in "$dc" 2>/dev/null | cut -d= -f2)"
  else
    echo "  ▸ Активный серт панели: в настройках x-ui не найден"
  fi
  echo
  certbot certificates 2>/dev/null | grep -E 'Certificate Name|Domains|Expiry' | sed 's/^/  /' || true
  echo
  echo "  Wildcard Cloudflare: ${WILDCARD_DOMAIN:-выключен}  |  токен: ${CF_CREDS}"
  echo
  echo "  1) Обновить все сертификаты (renew)"
  echo "  2) Dry-run продления"
  echo "  3) Выпустить wildcard (Cloudflare DNS-01)"
  echo "  4) Wildcard вкл/выкл"
  echo "  5) Выпуск серта через меню x-ui (освободить :80)"
  echo "  6) Показать все серты и email (обзор)"
  echo "  7) Сбросить email Let's Encrypt (спросить заново)"
  echo "  8) Переезд домена панели (серт/БД/hosts/nginx)"
  echo "  9) Мультисерт (SAN): домены разных зон одним сертом"
  echo "  0) Назад"
  line
  local action=""
  read -rp "$(echo -e "${B}Выбор:${N} ")" action || action="0"
  [[ "$action" == "0" ]] && return 0
  case "$action" in
    1) certbot renew --quiet && log "OK" || true ;;
    2) certbot renew --dry-run 2>&1 | tail -20 || true ;;
    3) cert_wildcard_issue ;;
    4) wildcard_toggle ;;
    5) xui_cert_menu_helper ;;
    6) certs_view ;;
    7) le_email_forget; log "Email сброшен — при следующем выпуске спросит заново"; pause ;;
    8) panel_domain_migrate ;;
    9) multi_cert_menu ;;
  esac
  pause
}

# статистика decoy-посещений за 24ч (парсинг decoy_ext через python3)
decoy_stats() {
  [[ -s "$DECOY_LOG_ACCESS" ]] || { warn "Лог деко-доступов пуст"; pause; return 0; }
  python3 - "$DECOY_LOG_ACCESS" <<'PY'
import sys, time, re, collections
cut = time.time() - 86400
hits = 0
ips = collections.Counter()
hosts = collections.Counter()
paths = collections.Counter()
for line in open(sys.argv[1], errors="replace"):
    m = re.match(r'(\S+) \[([^]]+)\] "([^"]*)" (\d+) "([^"]*)" host=(\S+)', line)
    if not m:
        continue
    try:
        t = time.mktime(time.strptime(m.group(2).split(" +")[0], "%d/%b/%Y:%H:%M:%S"))
    except Exception:
        continue
    if t < cut:
        continue
    hits += 1
    ips[m.group(1)] += 1
    hosts[m.group(6)] += 1
    p = m.group(3).split(" ")[1] if len(m.group(3).split(" ")) > 1 else "/"
    paths[p[:60]] += 1
print(f"  Запросов за 24ч: {hits}")
print(f"  Уникальных IP:   {len(ips)}")
if hosts:
    print("  По доменам:")
    for h, c in hosts.most_common(10):
        print(f"    {h:40s} {c}")
if paths:
    print("  Топ путей:")
    for p, c in paths.most_common(8):
        print(f"    {p:42s} {c}")
if ips:
    print("  Топ IP:")
    for ip, c in ips.most_common(8):
        print(f"    {ip:42s} {c}")
PY
  pause
}

# забанить всех, кто открывал decoy за N часов
decoy_ban_watchers() {
  local hrs="" ips="" own_ip
  ask hrs "За сколько часов (1-168)" "24" '^[0-9]{1,3}$'
  ips=$(python3 - "$DECOY_LOG_ACCESS" "$hrs" <<'PY'
import sys, time, re
cut = time.time() - int(sys.argv[2]) * 3600
seen = []
for line in open(sys.argv[1], errors="replace"):
    m = re.match(r'(\S+) \[([^]]+)\] ', line)
    if not m:
        continue
    try:
        t = time.mktime(time.strptime(m.group(2).split(" +")[0], "%d/%b/%Y:%H:%M:%S"))
    except Exception:
        continue
    if t >= cut and m.group(1) not in seen:
        seen.append(m.group(1))
print(" ".join(seen))
PY
)
  [[ -z "$ips" ]] && { warn "Никого не нашлось"; pause; return 0; }
  own_ip=$(curl -s --max-time 3 https://api.ipify.org 2>/dev/null || true)
  echo "  Найдены IP:"
  local ip banned=0 skipped=0
  for ip in $ips; do
    if [[ "$ip" == "$own_ip" ]]; then
      echo "    $ip  (твой сервер/выход — пропущен)"; skipped=$((skipped+1))
    else
      echo "    $ip"
    fi
  done
  local conf="false"
  askyn conf "Забанить все НЕ-серверные IP в jail decoy-login?" "n"
  if [[ "$conf" == true ]]; then
    for ip in $ips; do
      [[ "$ip" == "$own_ip" ]] && continue
      fail2ban-client set decoy-login banip "$ip" >/dev/null 2>&1 && banned=$((banned+1))
    done
    log "Забанено: $banned"
  fi
  pause
}

security_menu() {
  line; echo -e "${B}   БЕЗОПАСНОСТЬ — БАНЫ, DECOY-ЛОГИНЫ, FAIL2BAN${N}"; line

  # --- деко-логины (jail decoy-login) ---
  echo -e "${B}▸ Декои (jail decoy-login)${N}"
  fail2ban-client status decoy-login 2>/dev/null | sed 's/^/  /' || echo "  jail не активен"
  local ips=""
  ips=$(fail2ban-client get decoy-login banip 2>/dev/null || true)
  echo "  Забаненные IP:"
  [[ -n "$ips" ]] && echo "$ips" | tr ' ' '\n' | sed 's/^/    /' || echo "    —"

  # --- остальные jail (sshd и пр.) ---
  local jails j
  jails=$(fail2ban-client status 2>/dev/null | sed -n 's/^.*Jail list:\s*//p' | tr ',' ' ')
  for j in $jails; do
    [[ "$j" == "decoy-login" ]] && continue
    echo
    echo -e "${B}▸ jail: $j${N}"
    fail2ban-client status "$j" 2>/dev/null | sed 's/^/  /'
  done

  echo
  echo "  1) Разбанить IP"
  echo "  2) Разбанить все (во всех jail)"
  echo "  3) Очистить лог деко-попыток"
  echo "  4) Добавить IP в whitelist (ignoreip)"
  echo "  5) Статистика decoy-посещений (24ч)"
  echo "  6) Забанить всех, кто открывал decoy"
  echo "  7) Включить jail recidive (рецидивисты — бан на неделю)"
  echo "  8) Живой лог fail2ban (tail -f)"
  echo "  0) Назад"
  line
  local c=""
  read -rp "$(echo -e "${B}Выбор:${N} ")" c || c="0"
  case "$c" in
    5) decoy_stats ;;
    6) decoy_ban_watchers ;;
    7) f2b_recidive_setup; pause ;;
    8) f2b_tail ;;
    1)
      local jj="" ip=""
      ask jj "Jail (Enter — decoy-login)" "decoy-login" '^[A-Za-z0-9_-]*$'
      [[ -z "$jj" ]] && jj="decoy-login"
      ask ip "IP для разбана" "" '^[0-9a-fA-F.:]+$'
      fail2ban-client set "$jj" unbanip "$ip" >/dev/null 2>&1 && { log "Разбанен: $ip (jail $jj)"; audit "f2b: unban $ip (jail $jj)"; } || err "Не получилось — проверь jail и IP"
      pause
      ;;
    2)
      local ca=""
      askyn ca "Снять ВСЕ баны во всех jail?" "n"
      [[ "$ca" == true ]] && { fail2ban-client unban --all >/dev/null 2>&1 && { log "Все баны сняты"; audit "f2b: unban all"; } || err "Не вышло (похоже, старый fail2ban)"; }
      pause
      ;;
    3)
      > "$DECOY_LOG_ACCESS" 2>/dev/null || true
      systemctl restart fail2ban 2>/dev/null || true
      log "Лог деко-попыток очищен, fail2ban перезапущен"
      pause
      ;;
    4)
      local wip="" f="/etc/fail2ban/jail.local"
      ask wip "IP или подсеть для whitelist (напр. 203.0.113.5)" "" '^[0-9a-fA-F.:/]{3,45}$'
      if [[ -f "$f" ]]; then
        if grep -qE "^ignoreip" "$f" 2>/dev/null; then
          if grep -E "^ignoreip" "$f" | grep -qw "$wip"; then
            warn "Этот IP уже в whitelist"
          else
            sed -i "s|^\(ignoreip.*\)$|\1 $wip|" "$f"
            systemctl restart fail2ban 2>/dev/null || true
            log "Whitelist обновлён (+$wip), fail2ban перезапущен — этот IP больше не забанят"
          fi
        else
          printf '\nignoreip = 127.0.0.1/8 %s\n' "$wip" >> "$f"
          systemctl restart fail2ban 2>/dev/null || true
          log "Whitelist создан (+$wip), fail2ban перезапущен"
        fi
      else
        err "$f не найден — fail2ban настраивается в п.1"
      fi
      pause
      ;;
  esac
}

# DNS для Xray удалён из скрипта: xray резолвит системно (dns-секция шаблона
# не трогается), настройки DNS Xray делаются в панели при необходимости.

# =====================================================================
# FIREWALL
# =====================================================================
scan_ports() {
  {
    ss -tlnpH 2>/dev/null | awk '{print "tcp|" $4}'
    # udp: только НАСТОЯЩИЕ слушатели (peer *:*); сокеты с конкретным peer —
    # это исходящие сессии на ephemeral-портах, в UFW им делать нечего
    ss -ulnpH 2>/dev/null | awk '$5 == "*:*" {print "udp|" $4}'
  } 2>/dev/null | while IFS='|' read -r proto bind; do
    [[ -z "$proto" || -z "$bind" ]] && continue
    echo "$proto|${bind##*:}|${bind%:*}"
  done | sort -u
}

fw_allow() {
  local port="$1" proto="$2" comment="${3:-}"
  [[ -z "$port" || "$port" == "0" ]] && return 0
  local args=(allow)
  [[ -n "$comment" ]] && args+=(comment "$comment")
  ufw "${args[@]}" "$port/$proto" >/dev/null 2>&1 || true
}

# Порты, которые НИКОГДА не открываются наружу (служебные/системные/амлификации)
fw_port_locked() {
  local port="$1"
  case "$port" in
    53)          return 0;;  # DNS — только localhost (amplification)
    323)         return 0;;  # chrony cmdmon
    6010|6011|6012|6013|6014|6015|6016|6017|6018|6019)
                             return 0;;  # X11 forwarding sshd
    46002)       return 0;;  # служебный web csqtt (46000+2) — только localhost
    11443)       return 0;;  # tproxy (TG web-proxy): наружу ТОЛЬКО через 443;
                             # UDP-сокет здесь — HTTP/3 caddy, светить нельзя
  esac
  return 1
}

# Явное закрытие портов панели/подписок наружу (страховка при default allow)
fw_deny_panel_ports() {
  command -v ufw >/dev/null 2>&1 || return 0
  # PANEL_PORT/SUB_PORT известны после initial_setup; иначе берём из БД панели
  local pp="${PANEL_PORT:-}" sp="${SUB_PORT:-}"
  [[ -z "$pp" || "$pp" == "0" ]] && pp=$(xui_get webPort 2>/dev/null || true)
  [[ -z "$sp" || "$sp" == "0" ]] && sp=$(xui_get subPort 2>/dev/null || true)
  local p
  for p in "$pp" "$sp"; do
    [[ -z "$p" || "$p" == "0" ]] && continue
    ufw deny "$p/tcp" >/dev/null 2>&1 || true
  done
}

firewall_menu() {
  while :; do
    clear
    line; echo -e "${B}   ФАЙРВОЛ (UFW)${N}"; line
    echo "  Статус: $(ufw status 2>/dev/null | head -1 | awk '{print $2}' || echo unknown)"
    local pol="allowlist"
    [[ -f "$BACKUP_DIR/fw-policy" ]] && pol=$(head -n1 "$BACKUP_DIR/fw-policy" 2>/dev/null | tr -d '[:space:]')
    [[ "$pol" != "hideonly" ]] && pol="allowlist"
    local pol_desc="allowlist — «всё закрыть, кроме списка» (reset + только нужное)"
    [[ "$pol" == "hideonly" ]] && pol_desc="hide-only — «закрыть только спрятанное» (без reset, deny для панельных/11443)"
    echo "  Политика: $pol_desc"
    echo
    declare -A REQ=()
    # SSH только через туннель? (sshd слушает loopback) — 22 наружу не открываем
    if ss -tln 2>/dev/null | grep -qE '127\.0\.0\.1:22([[:space:]]|$)'; then
      echo "  SSH: только через туннель (loopback) — 22 наружу не открываем"
    else
      REQ["tcp:$SSH_PORT"]="SSH"
    fi
    # tcp/80 НЕ открываем: сертификаты — wildcard через DNS-хук (DNS-01),
    # HTTP-01 не нужен; при необходимости открыть разово: ufw allow 80/tcp
    systemctl is-active --quiet nginx 2>/dev/null && REQ["tcp:443"]="HTTPS/SNI"
    # UDP — только инбаунды из БД панели (сокеты чрезмерно шумят: ephemeral)
    local up
    for up in $(udp_inbound_ports); do
      fw_port_locked "$up" && continue
      REQ["udp:$up"]="udp-инбаунд (панель)"
    done

    echo "▸ Открытыми БУДУТ:"
    local k
    for k in $(printf '%s\n' "${!REQ[@]}" | sort -t: -k1,1 -k2,2n); do
      printf "  %-6s %-6s %s\n" "${k%%:*}" "${k##*:}" "${REQ[$k]}"
    done
    echo
    line
    echo "  1) ПРИМЕНИТЬ"
    echo "  2) Включить UFW"
    echo "  3) Выключить UFW"
    echo "  4) Показать правила"
    echo "  5) Удалить правило по номеру"
    echo "  6) Сменить политику файрвола"
    echo "  7) Снимок состояния"
    echo "  8) Восстановить из снимка"
    echo "  0) Назад"
    line
    local c=""
    read -rp "$(echo -e "${B}Выбор:${N} ")" c || c="0"
    case "$c" in
      1)
        if [[ "$pol" == "hideonly" ]]; then
          askyn confirm "Применить hide-only? (правила НЕ сбрасываются: панельные/11443 закрываются явно)" "n"
          [[ "$confirm" == true ]] || continue
          save_firewall_state
          if ! ss -tln 2>/dev/null | grep -qE '127\.0\.0\.1:22([[:space:]]|$)'; then
            fw_allow "$SSH_PORT" tcp "SSH"
          fi
          systemctl is-active --quiet nginx 2>/dev/null && fw_allow 443 tcp "HTTPS/SNI"
          local hp
          for hp in "$(xui_get webPort 2>/dev/null)" "$(xui_get subPort 2>/dev/null)" 11443; do
            [[ -z "$hp" || "$hp" == "0" ]] && continue
            ufw delete allow "$hp/tcp" >/dev/null 2>&1 || true
            ufw delete allow "$hp/udp" >/dev/null 2>&1 || true
            ufw deny "$hp/tcp" >/dev/null 2>&1 || true
          done
          fw_deny_panel_ports
          ufw --force enable >/dev/null 2>&1 || true
          log "hide-only применено: панельные/служебные закрыты явно, остальное не тронуто"
        else
          askyn confirm "Применить? (allowlist: reset + открыть только список ниже)" "n"
          [[ "$confirm" == true ]] || continue
          save_firewall_state
          ufw --force reset >/dev/null 2>&1 || true
          ufw default deny incoming >/dev/null 2>&1 || true
          ufw default allow outgoing >/dev/null 2>&1 || true
          fw_allow "$SSH_PORT" tcp "SSH"
          for k in "${!REQ[@]}"; do
            local pr="${k%%:*}" pt="${k##*:}"
            [[ "$pr:$pt" == "tcp:$SSH_PORT" ]] && continue
            fw_allow "$pt" "$pr" "${REQ[$k]}"
          done
          # порты панели/подписок наружу закрыты явно (они живут на 127.0.0.1)
          fw_deny_panel_ports
          ufw --force enable >/dev/null 2>&1 || true
          log "Применено (allowlist)"
        fi
        pause
        ;;
      6)
        echo "  Политики:"
        echo "   1) allowlist — «всё закрыть, кроме списка»: reset, наружу только SSH/443/UDP-инбаунды (текущая логика)"
        echo "   2) hide-only — «закрыть только спрятанное»: без reset; deny для панельных портов и 11443;"
        echo "      всё, что ты открыл руками, остаётся как есть"
        local pc=""; ask pc "Политика" "$pol" '^[12]$'
        case "$pc" in
          1) printf 'allowlist\n' > "$BACKUP_DIR/fw-policy"; log "Политика: allowlist" ;;
          2) mkdir -p "$BACKUP_DIR" 2>/dev/null; printf 'hideonly\n' > "$BACKUP_DIR/fw-policy"; log "Политика: hide-only" ;;
        esac
        pause ;;
      2) ufw --force enable 2>&1 | sed 's/^/  /'; pause ;;
      3) ufw disable 2>&1 | sed 's/^/  /'; pause ;;
      4) ufw status numbered 2>&1 | sed 's/^/  /'; pause ;;
      5) ufw status numbered 2>&1 | sed 's/^/  /'
         local n=""; ask n "Номер" "0" '^[0-9]+$'
         [[ "$n" == 0 ]] && continue
         ufw --force delete "$n" 2>&1 | sed 's/^/  /'; pause ;;
      7) save_firewall_state; pause ;;
      8) restore_firewall_state ;;
      0) return 0 ;;
      *) sleep 1 ;;
    esac
  done
}

# пересборка ВСЕХ decoy-блоков: подтянуть robots/honeypot/UA-404/логи с доменом.
# Шаблон берём из маркера (tpl=), если нет — угадываем по md5 index.html.
decoy_rebuild_all() {
  [[ -f "$STACK_CONF" ]] || { err "stack.conf не найден"; pause; return 1; }
  local mline mport mroot mcert mkey mdom mtpl muaf idx hash tf troot found
  local -A TPL_OF=()
  local -a ROWS=()
  while IFS= read -r mline; do
    [[ "$mline" != "# >>> decoy "* ]] && continue
    mport=$(grep -oE 'port=[0-9]+'   <<<"$mline" | head -1 | cut -d= -f2)
    mroot=$(grep -oE 'root=[^ ]+'    <<<"$mline" | head -1 | cut -d= -f2-)
    mcert=$(grep -oE 'cert=[^ ]+'    <<<"$mline" | head -1 | cut -d= -f2-)
    mkey=$(grep  -oE ' key=[^ ]+'    <<<"$mline" | head -1 | sed 's/^ key=//')
    mdom=$(grep  -oE 'domain=[^ ]+$' <<<"$mline" | head -1 | cut -d= -f2-)
    mtpl=$(grep -oE 'tpl=[^ ]+'      <<<"$mline" | head -1 | cut -d= -f2-)
    muaf=$(grep -oE 'ua404=[0-9]'    <<<"$mline" | head -1 | cut -d= -f2-)
    [[ -z "$mdom" || -z "$mport" || -z "$mroot" ]] && continue
    if [[ -z "$mtpl" && -f "$mroot/index.html" ]]; then
      hash=$(md5sum "$mroot/index.html" 2>/dev/null | awk '{print $1}')
      found=""
      for tf in "$DECOY_TPL_DIR"/*.html "$DECOY_LOGIN_DIR"/*.html; do
        [[ -f "$tf" ]] || continue
        [[ "$(md5sum "$tf" 2>/dev/null | awk '{print $1}')" == "$hash" ]] && { found=$(basename "$tf" .html); break; }
      done
      mtpl="${found:-corporate}"
    fi
    [[ -z "$mtpl" ]] && mtpl="corporate"
    [[ -z "$muaf" ]] && muaf=1
    ROWS+=("$mport|$mdom|$mcert|$mkey|$mroot|$mtpl|$muaf")
  done < "$STACK_CONF"
  [[ ${#ROWS[@]} -eq 0 ]] && { warn "Decoy-блоки не найдены"; pause; return 0; }
  local r
  for r in "${ROWS[@]}"; do
    IFS='|' read -r mport mdom mcert mkey mroot mtpl muaf <<<"$r"
    mk_decoy "$mport" "$mdom" "$mcert" "$mkey" "$mroot" "$mtpl" "ua404=$muaf"
    log "  $mdom → «$mtpl» (ua404=$muaf, robots+honeypot+логи)"
  done
  audit "decoy: пересборка всех блоков"
  if nginx -t >/dev/null 2>&1; then
    nginx_reload || true
    log "Все decoy-блоки пересобраны ✓"
  else
    err "nginx -t не прошёл:"; nginx -t 2>&1 | tail -5 | sed 's/^/    /'
  fi
  pause
}

# «проверить как посторонний»: что реально увидит человек и сканер
decoy_outsider_check() {
  local mline mport mdom
  local -a DOM_LIST=()
  local -A PORT_OF=()
  while IFS= read -r mline; do
    [[ "$mline" != "# >>> decoy "* ]] && continue
    mport=$(grep -oE 'port=[0-9]+'   <<<"$mline" | head -1 | cut -d= -f2)
    mdom=$(grep  -oE 'domain=[^ ]+$' <<<"$mline" | head -1 | cut -d= -f2-)
    [[ -n "$mdom" ]] && { DOM_LIST+=("$mdom"); PORT_OF[$mdom]="$mport"; }
  done < "$STACK_CONF"
  [[ ${#DOM_LIST[@]} -eq 0 ]] && { warn "Decoy-доменов нет"; pause; return 0; }
  local i=1 d pick
  for d in "${DOM_LIST[@]}"; do printf "  %d) %s\n" "$i" "$d"; i=$((i+1)); done
  ask pick "Проверить какой домен" "1" '^[0-9]+$'
  (( pick > ${#DOM_LIST[@]} )) && { err "Нет такого"; pause; return 1; }
  mdom="${DOM_LIST[$((pick-1))]}"
  mport="${PORT_OF[$mdom]}"
  local HUA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"
  local cb ch title
  cb=$(curl -sk -A "curl/8.5.0" -o /dev/null -w "%{http_code}" "https://127.0.0.1:$mport/" 2>/dev/null)
  curl -sk -A "$HUA" "https://127.0.0.1:$mport/" -o /tmp/smg_out.html 2>/dev/null
  ch=$(curl -sk -A "$HUA" -o /dev/null -w "%{http_code}" "https://127.0.0.1:$mport/" 2>/dev/null)
  title=$(grep -oE '<title>[^<]*' /tmp/smg_out.html 2>/dev/null | head -1 | sed 's/<title>//')
  echo
  echo "  Домен: $mdom (локальный порт $mport)"
  echo "  ---------------------------------------------"
  echo "  Человек (браузер): HTTP $ch   title: ${title:-—}"
  echo "  Сканер (curl):     HTTP $cb   $( [[ "$cb" == 404 ]] && echo '← бот видит пустоту ✓' )"
  echo
  echo "  Заголовки (как для браузера):"
  curl -skI -A "$HUA" "https://127.0.0.1:$mport/" 2>/dev/null | head -6 | sed 's/^/    /'
  rm -f /tmp/smg_out.html
  pause
}

view_decoy_templates() {
  line; echo -e "${B}   DECOY-ШАБЛОНЫ${N}"; line
  echo "▸ Статические HTML:"
  local tpl name desc size
  for tpl in "${DECOY_TEMPLATES[@]}"; do
    name="${tpl%%|*}"; desc="${tpl##*|}"
    is_login_template "$name" && continue
    size=0
    [[ -f "$DECOY_TPL_DIR/$name.html" ]] && size=$(stat -c%s "$DECOY_TPL_DIR/$name.html" 2>/dev/null || echo 0)
    printf "  %-15s %6s B  %s\n" "$name" "$size" "$desc"
  done
  echo
  echo "▸ Login-шаблоны:"
  for tpl in "${DECOY_TEMPLATES[@]}"; do
    name="${tpl%%|*}"; desc="${tpl##*|}"
    is_login_template "$name" || continue
    size=0
    [[ -f "$DECOY_LOGIN_DIR/$name.html" ]] && size=$(stat -c%s "$DECOY_LOGIN_DIR/$name.html" 2>/dev/null || echo 0)
    printf "  %-15s %6s B  %s\n" "$name" "$size" "$desc"
  done
  echo
  echo -e "${B}▸ Свой сайт (custom):${N} доступен в любом меню выбора шаблона —"
  echo "    выбрать пункт «custom» и указать путь к папке с index.html (статика)."
  echo
  echo "  1) Пересобрать все decoy-блоки (включить robots/honeypot/UA-404/логи)"
  echo "  2) Проверить домен как посторонний (человек vs сканер)"
  echo "  0) Назад"
  local c=""
  read -rp "$(echo -e "${B}Выбор:${N} ")" c || c="0"
  case "$c" in
    1) decoy_rebuild_all ;;
    2) decoy_outsider_check ;;
  esac
  pause
}

# =====================================================================
# ГЛАВНОЕ МЕНЮ
# =====================================================================
# =====================================================================
# УДАЛЕНИЕ КОМПОНЕНТОВ
# =====================================================================
# AdGuard Home: остановка, удаление файлов/сервиса, заглушка вместо
# прокси на AdGuard в stack.conf
uninstall_adguard() {
  detect_env
  if [[ "$ADG_PRESENT" != true ]]; then
    warn "AdGuard Home не установлен."
    return 1
  fi
  line; echo -e "${B}   УДАЛЕНИЕ ADGUARD HOME${N}"; line
  echo "  Будут удалены: сервис, /opt/AdGuardHome, конфигурация и статистика."
  echo "  Бэкап конфига: /root/adguard-backup-<дата>.tar.gz"
  local sure=false
  askyn sure "Удалить AdGuard Home?" "n"
  [[ "$sure" == true ]] || { log "Отменено."; return 0; }

  tar -czf "/root/adguard-backup-$(date +%Y%m%d-%H%M%S).tar.gz" \
    -C / opt/AdGuardHome/AdGuardHome.yaml 2>/dev/null || true

  systemctl stop "$ADG_SERVICE" 2>/dev/null || true
  systemctl disable "$ADG_SERVICE" 2>/dev/null || true
  rm -f "/etc/systemd/system/$ADG_SERVICE.service" 2>/dev/null || true
  systemctl daemon-reload 2>/dev/null || true
  rm -rf /opt/AdGuardHome 2>/dev/null || true

  # stack.conf: location / (прокси на AdGuard) → заглушка
  if [[ -f "$STACK_CONF" ]] && grep -q "proxy_pass https\?://127.0.0.1:[0-9]*;" "$STACK_CONF"; then
    local tmp
    tmp=$(mktemp)
    awk '
      /^    location \/ \{/ { instub=1; print; print "        return 302 /404.html;"; next }
      instub && /^    \}$/ { instub=0; print; next }
      instub { next }
      { print }
    ' "$STACK_CONF" > "$tmp" 2>/dev/null && mv "$tmp" "$STACK_CONF"
    nginx_reload || true
  fi
  ADG_PRESENT=false
  log "AdGuard Home удалён. Бэкап конфига: /root/adguard-backup-*.tar.gz"
}

# Панель LucX UI (x-ui): остановка, бэкап БД, удаление файлов/сервиса.
# Опционально — конфиги nginx стека (SNI-роутер + stack.conf).
uninstall_panel_lucx() {
  detect_env
  line; echo -e "${B}   УДАЛЕНИЕ ПАНЕЛИ LUCX UI (X-UI)${N}"; line
  if [[ -z "$XUI_DB" || ! -f "$XUI_DB" ]]; then
    warn "Панель не установлена (x-ui.db не найден)."
  else
    echo "  Будут удалены: сервис x-ui, /usr/local/x-ui, /etc/x-ui (БД + инбаунды!), /usr/bin/x-ui."
    echo "  Бэкап: /root/x-ui-backup-<дата>.tar.gz (восстановление распаковкой в /)."
  fi
  local sure=false
  askyn sure "Удалить панель LucX UI?" "n"
  [[ "$sure" == true ]] || { log "Отменено."; return 0; }

  # таймер автопочинки ссылается на скрипт — снимаем вместе с панелью
  uninstall_heal_timer

  if [[ -f "$XUI_DB" ]]; then
    tar -czf "/root/x-ui-backup-$(date +%Y%m%d-%H%M%S).tar.gz" -C / etc/x-ui 2>/dev/null || true
    log "Бэкап БД: /root/x-ui-backup-*.tar.gz"
  fi

  systemctl stop x-ui 2>/dev/null || true
  systemctl disable x-ui 2>/dev/null || true
  rm -f /etc/systemd/system/x-ui.service /etc/systemd/system/multi-user.target.wants/x-ui.service 2>/dev/null || true
  systemctl daemon-reload 2>/dev/null || true
  rm -rf /usr/local/x-ui /etc/x-ui 2>/dev/null || true
  rm -f /usr/bin/x-ui 2>/dev/null || true
  XUI_DB=""

  # конфиги nginx стека: без панели SNI-роутер и stack.conf не имеют смысла
  local drop_nginx=false
  askyn drop_nginx "Удалить и конфиги nginx стека (SNI-роутер, stack.conf)?" "y"
  if [[ "$drop_nginx" == true ]]; then
    rm -f /etc/nginx/streams-enabled/sni-router.conf /etc/nginx/streams-available/sni-router.conf 2>/dev/null || true
    rm -f "$STACK_LINK" "$STACK_CONF" 2>/dev/null || true
    nginx_reload || true
    log "Конфиги nginx стека удалены."
  fi
  log "Панель LucX UI удалена. Бэкап: /root/x-ui-backup-*.tar.gz"

  # Без панели стек мёртв — предлагаем сразу установить панель с инбаундами.
  local redeploy=false
  askyn redeploy "Приступить к установке панели с настройкой инбаундов?" "y"
  if [[ "$redeploy" == true ]]; then
    initial_setup || err "Первоначальная установка завершилась с ошибкой — запусти п.1 вручную"
  else
    log "Выход из скрипта."
    exit 0
  fi
}

# --- Обновление скрипта с GitHub ---------------------------------------------
# URL берётся из /root/.stack-src (сохраняется после первого обновления).
STACK_SRC_URL="$(cat /root/.stack-src 2>/dev/null || echo 'https://raw.githubusercontent.com/vladufqaa/stack-manager/main/stack-manager.sh')"

update_self() {
  line; echo -e "${B}   ОБНОВЛЕНИЕ СКРИПТА С GITHUB${N}"; line
  local cur="/root/stack-manager.sh" tmp="/root/stack-manager.sh.new"
  local src_url="$STACK_SRC_URL"
  ask src_url "Raw-URL скрипта (Enter — сохранённый)" "$src_url" '^https?://'
  log "Качаю: $src_url"
  # raw.githubusercontent кэшируется ~5 минут (Fastly): сразу после пуша можно
  # скачать старую версию и получить ложное «обновление не требуется».
  # ?ts=… меняет ключ кэша → всегда свежий файл. В /root/.stack-src пишем
  # чистый URL (без бастера).
  local bust_url="${src_url}?ts=$(date +%s)"
  if ! curl -fsSL --max-time 30 "$bust_url" -o "$tmp"; then
    err "Не удалось скачать (проверь URL/доступность репозитория)"
    rm -f "$tmp"; return 1
  fi
  if ! bash -n "$tmp"; then
    err "Новый файл не проходит bash -n — обновление отменено"
    rm -f "$tmp"; return 1
  fi
  if cmp -s "$tmp" "$cur"; then
    log "Обновление не требуется — файл байт-в-байт идентичен (sha256: $(sha256sum "$tmp" 2>/dev/null | cut -c1-12)…)"
    rm -f "$tmp"; return 0
  fi
  echo "  было:  $(stat -c%s "$cur" 2>/dev/null || echo '?') байт (sha256: $(sha256sum "$cur" 2>/dev/null | cut -c1-12)…)"
  echo "  стало: $(stat -c%s "$tmp") байт (sha256: $(sha256sum "$tmp" | cut -c1-12)…)"
  local yn=false
  askyn yn "Заменить $cur и перезапустить?" "y"
  if [[ "$yn" != true ]]; then rm -f "$tmp"; log "Отменено"; return 0; fi
  mv "$tmp" "$cur" && chmod +x "$cur"
  printf '%s' "$src_url" > /root/.stack-src && chmod 600 /root/.stack-src
  log "Обновлено ✓ — перезапускаюсь…"
  exec bash "$cur"
}

# =====================================================================
# ЕДИНЫЕ БЛОКИ ВОПРОСОВ УСТАНОВКИ — общий путь для п.1 (первичная
# настройка), п.17 (переустановка после удаления) и авто-подъёма.
# Порядок ВСЕГДА: панель (пароль+порты) → AdGuard (да/нет+пароль+где) →
# заглушка панели → серты (тип 1/2, уже в cert_issue) → инбаунды.
# =====================================================================
ask_panel_creds() {
  # ПАНЕЛЬ УЖЕ УСТАНОВЛЕНА → берём её текущие значения и НИЧЕГО не спрашиваем:
  # порты/пути остаются как есть, пароль в БД не трогаем (его всё равно
  # нельзя «прочитать» — а спрашивать = предлагать сменить, это ломает вход).
  if [[ -n "$XUI_DB" && -f "$XUI_DB" ]]; then
    local _wp _ws _bp _sp
    _wp=$(xui_get webPort);     _ws=$(xui_get subPort)
    _bp=$(xui_get webBasePath); _sp=$(xui_get subPath)
    if [[ -n "$_wp" && -n "$_bp" && -n "$_sp" && -n "$_ws" ]]; then
      U_PANEL_PASS="${U_PANEL_PASS:-}"   # пароль не спрашиваем и не меняем
      U_PANEL_PORT="$_wp"; U_PANEL_PATH="$_bp"
      U_SUB_PORT="$_ws";   U_SUB_PATH="$_sp"
      log "Панель уже установлена — беру её настройки без изменений:"
      log "  панель   : $_wp $_bp"
      log "  подписки : $_ws $_sp"
      return 0
    fi
  fi
  # свежая панель (или п.17 удалил): обычный путь — вопросы
  if [[ -n "${U_PANEL_PASS:-}" && -n "$XUI_DB" && -f "$XUI_DB" ]]; then
    :
  else
    U_PANEL_USER="${U_PANEL_USER:-admin}"
    U_PANEL_PASS=$(openssl rand -base64 18 2>/dev/null | tr -dc 'a-zA-Z0-9' | head -c 16)
    if [[ -t 0 ]]; then
      ask U_PANEL_USER "Логин панели (Enter — admin)" "$U_PANEL_USER" '^[a-zA-Z0-9._-]{3,32}$'
      ask U_PANEL_PASS "Пароль панели (Enter — случайный)" "$U_PANEL_PASS" '^.{6,}$'
    fi
  fi
  U_PANEL_PORT=""; U_SUB_PORT=""; U_PANEL_PATH=""; U_SUB_PATH=""
  ask U_PANEL_PORT "Порт панели (Enter — случайный)"       "" '^[0-9]*$'
  ask U_PANEL_PATH "Путь панели (Enter — случайный)"       "/$(gen_random_string 12)/" '^[a-zA-Z0-9/_-]*$'
  ask U_SUB_PORT  "Порт подписок (Enter — случайный)"     "" '^[0-9]*$'
  ask U_SUB_PATH  "Путь подписок (Enter — случайный)"     "/$(gen_random_string 10)/" '^[a-zA-Z0-9/_-]*$'
  [[ "$U_PANEL_PATH" != /* ]] && U_PANEL_PATH="/$U_PANEL_PATH"
  [[ "$U_PANEL_PATH" != */ ]] && U_PANEL_PATH="$U_PANEL_PATH/"
  [[ "$U_SUB_PATH"  != /* ]] && U_SUB_PATH="/$U_SUB_PATH"
  [[ "$U_SUB_PATH"  != */ ]] && U_SUB_PATH="$U_SUB_PATH/"
  [[ -n "$U_PANEL_PORT" && ( "$U_PANEL_PORT" -lt 1    || "$U_PANEL_PORT" -gt 65535 ) ]] && { err "Некорректный порт панели"; return 1; }
  [[ -n "$U_SUB_PORT"   && ( "$U_SUB_PORT"   -lt 1    || "$U_SUB_PORT"   -gt 65535 ) ]] && { err "Некорректный порт подписок"; return 1; }
  if [[ -n "$U_PANEL_PORT" && -n "$U_SUB_PORT" && "$U_PANEL_PORT" == "$U_SUB_PORT" ]]; then
    err "Порт панели и порт подписок совпадают ($U_PANEL_PORT) — укажите разные."; return 1
  fi
  if [[ "$U_PANEL_PATH" == "$U_SUB_PATH" ]]; then
    err "Путь панели и путь подписок совпадают ($U_PANEL_PATH) — укажите разные."; return 1
  fi
  return 0
}

ask_adguard_and_decoy() {
  # AdGuard: да/нет → установка → пароль → размещение
  if [[ "$ADG_PRESENT" != true ]]; then
    local adg_install=false
    [[ -t 0 ]] && askyn adg_install "Установить AdGuard Home?" "n"
    if [[ "$adg_install" == true ]]; then
      install_adguard_home || warn "AdGuard не установился — продолжаем без него."
      detect_env
      [[ "$ADG_PRESENT" == true ]] && ADG_JUST_INSTALLED=true
    fi
  fi
  ADG_PLACEMENT=""
  local adg_installed_now=false
  if [[ "$ADG_PRESENT" == true ]]; then
    if [[ -t 0 ]]; then
      if [[ "${ADG_JUST_INSTALLED:-}" == true ]]; then
        # установили ТОЛЬКО ЧТО в этом запуске — креды спрашиваем
        adg_installed_now=true
        if [[ -z "${U_ADG_PASS:-}" ]]; then
          U_ADG_USER="${U_ADG_USER:-admin}"
          U_ADG_PASS=$(openssl rand -base64 18 2>/dev/null | tr -dc 'a-zA-Z0-9' | head -c 16)
          [[ -z "$U_ADG_PASS" ]] && U_ADG_PASS="AdG$(date +%s)"
          ask U_ADG_USER "Логин AdGuard (Enter — admin)" "$U_ADG_USER" '^[a-zA-Z0-9._-]{3,32}$'
          ask U_ADG_PASS "Пароль AdGuard (Enter — случайный)" "$U_ADG_PASS" '^.{6,}$'
        elif [[ -z "${U_ADG_USER_SET:-}" ]]; then
          # пароль уже задан (установкой выше), логин уточняем один раз
          U_ADG_USER="${U_ADG_USER:-admin}"
          ask U_ADG_USER "Логин AdGuard (Enter — admin)" "$U_ADG_USER" '^[a-zA-Z0-9._-]{3,32}$'
          U_ADG_USER_SET=1
        fi
      else
        # был установлен РАНЬШЕ — креды не трогаем и не спрашиваем (как с панелью)
        log "AdGuard Home уже установлен — логин/пароль не трогаю (креды: /root/adguard-credentials.txt или твои)"
      fi
      echo "  AdGuard Home — где показывать веб-интерфейс?"
      echo "   1) За доменом панели   (https://<панель>/, DoH там же)"
      echo "   2) Отдельный SNI-домен (adguard.<база>)"
      echo "   3) Не трогать (только локально)"
      local ap=""
      ask ap "Размещение [1/2/3]" "1" '^[123]$'
      case "$ap" in 2) ADG_PLACEMENT="sni" ;; 3) ADG_PLACEMENT="local" ;; *) ADG_PLACEMENT="panel" ;; esac
    else
      ADG_PLACEMENT="${ADG_PLACEMENT:-panel}"   # не-TTY: сохраняем выбор авто-потока
    fi
  fi
  # заглушка панели — ПОСЛЕ AdGuard (если корень не занят самим AdGuard)
  PDECOY="${PDECOY:-stub}"
  if [[ -t 0 && "$ADG_PLACEMENT" != "panel" ]]; then
    local pdc3=""
    decoy_panel_choose pdc3 "1"
    PDECOY="$pdc3"
  fi
}

# Единый файрвол: сброс → SSH+443 (TCP) → нужные UDP → DENY панельных портов.
# Вызывается и из авто-подъёма, и из п.1 (при переустановке убивает старые
# правила прошлой установки — «почему открыты TCP-порты» лечится здесь).
firewall_apply() {
  # Снимок «до стека» — один раз, чтобы откат (п.12 / п.23 → 2) имел к чему вернуться.
  # save_firewall_state сам защищён от перезаписи: если снимок уже есть — молча выйдет.
  save_firewall_state >/dev/null 2>&1 || true
  log "Файрвол: сброс и только необходимое…"
  ufw --force reset >/dev/null 2>&1 || true
  ufw default deny incoming >/dev/null 2>&1 || true
  ufw default allow outgoing >/dev/null 2>&1 || true
  # SSH: если sshd слушает только loopback («через туннель») — 22 наружу не открываем
  if ! ss -tln 2>/dev/null | grep -qE '127\.0\.0\.1:22([[:space:]]|$)'; then
    fw_allow "${SSH_PORT:-22}" tcp "SSH"
  else
    ufw delete allow "${SSH_PORT:-22}/tcp" >/dev/null 2>&1 || true
  fi
  fw_allow 443 tcp "HTTPS/SNI"
  # UDP — только инбаунды из БД панели (скан-сокеты шумят ephemeral-мусором)
  local up
  for up in $(udp_inbound_ports); do
    fw_port_locked "$up" && continue
    fw_allow "$up" udp "udp-инбаунд"
  done
  # доктрина 443: 11443 наружу никогда (TCP туннеля идёт через nginx:443,
  # UDP — это HTTP/3 caddy). Гасим, если правило когда-то засело.
  ufw delete allow 11443/tcp >/dev/null 2>&1 || true
  ufw delete allow 11443/udp >/dev/null 2>&1 || true
  fw_deny_panel_ports
  ufw --force enable >/dev/null 2>&1 || true
  sleep 1
}

# =====================================================================
# ЗДОРОВЬЕ: UFW-fallback, recidive, живой лог, шаблоны decoy
# ссылок, смена домена инбаунда
# =====================================================================

# Статус UFW с запасным путём: бинарь может не находиться в PATH — тогда
# смотрим сервис (oneshot ufw.service остаётся active после применения правил).
ufw_is_active() {
  local ub
  ub=$(command -v ufw 2>/dev/null || true)
  [[ -z "$ub" && -x /usr/sbin/ufw ]] && ub=/usr/sbin/ufw
  if [[ -n "$ub" ]]; then
    LC_ALL=C "$ub" status 2>/dev/null | head -1 | grep -q "Status: active" && return 0
    return 1
  fi
  systemctl is-active --quiet ufw 2>/dev/null
}

# Jail recidive: рецидивисты (3 бана за сутки) получают бан на неделю,
# который переживает рестарты fail2ban.
f2b_recidive_setup() {
  command -v fail2ban-client >/dev/null 2>&1 || { err "fail2ban не установлен"; return 1; }
  local f=/etc/fail2ban/jail.d/recidive.local
  cat > "$f" <<'EOF'
[recidive]
enabled   = true
filter    = recidive
logpath   = /var/log/fail2ban.log
banaction = iptables-allports
bantime   = 1w
findtime  = 1d
maxretry  = 3
EOF
  systemctl restart fail2ban 2>/dev/null || fail2ban-client reload >/dev/null 2>&1 || true
  sleep 1
  if fail2ban-client status recidive >/dev/null 2>&1; then
    log "recidive включён: 3 бана за сутки → бан на неделю (переживает рестарты)"
    audit "f2b: recidive jail включён"
  else
    err "recidive не поднялся — смотри /var/log/fail2ban.log (возможно, нет banaction iptables-allports)"
    return 1
  fi
}

f2b_tail() {
  local f=/var/log/fail2ban.log
  [[ -f "$f" ]] || { err "$f не найден"; return 1; }
  line; echo -e "${B}   FAIL2BAN — ЖИВОЙ ЛОГ (Ctrl+C — выход)${N}"; line
  tail -n 30 -f "$f"
}

# Смена домена инбаунда без пересоздания: stop панели → правка JSON/hosts/
# SNI-карты → start → nginx reload. Reality: свой decoy перепривязывается
# через reality_set_dest, чужая цель — через замену dest/serverNames.
inbound_change_domain() {
  line; echo -e "${B}   СМЕНА ДОМЕНА ИНБАУНДА (без пересоздания)${N}"; line
  [[ -z "$XUI_DB" || ! -f "$XUI_DB" ]] && { err "x-ui.db не найден"; return 1; }
  inbounds_live
  local id=""
  ask id "ID инбаунда (0 — отмена)" "0" '^[0-9]+$'
  [[ "$id" == 0 ]] && return 0
  local row
  row=$(python3 - "$XUI_DB" "$id" <<'PYROW' 2>/dev/null
import sqlite3, json, sys
con = sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True, timeout=5)
r = con.execute("SELECT protocol,port,settings,stream_settings FROM inbounds WHERE id=?", (int(sys.argv[2]),)).fetchone()
if not r: sys.exit(1)
proto, port, s1, s2 = r
se = json.loads(s1 or "{}"); st = json.loads(s2 or "{}")
rs = st.get("realitySettings") or {}
dom = se.get("domain") or se.get("hostname") or se.get("sni") \
   or (st.get("tlsSettings") or {}).get("serverName") \
   or (rs.get("serverNames") or [""])[0] or ""
dest = rs.get("dest") or rs.get("target") or ""
cert = se.get("certFile") or ""
if not cert:
    c = (st.get("tlsSettings") or {}).get("certificates") or []
    if c: cert = c[0].get("certificateFile", "")
print(f"{proto}|{port}|{dom}|{(st.get('security') or '').lower()}|{dest}|{cert}")
PYROW
) || { err "Инбаунд #$id не найден"; return 1; }
  local proto port old sec dest cert
  IFS='|' read -r proto port old sec dest cert <<<"$row"
  [[ -z "$old" ]] && { err "У инбаунда не найден текущий домен — меняй вручную"; return 1; }
  echo "  #$id: $proto $port/tcp · домен: $old · security: ${sec:-none} · dest: ${dest:--}"
  local nd=""
  ask nd "Новый домен (A-запись → этот сервер)" "" '^[a-zA-Z0-9.-]+$'
  [[ -z "$nd" ]] && return 0
  [[ "$nd" == "$old" ]] && { warn "Домен не изменился"; return 0; }
  local srv_ip dip
  srv_ip=$(server_ip4)
  dip=$(dig +short A "$nd" 2>/dev/null | tail -1)
  if [[ "$dip" != "$srv_ip" ]]; then
    warn "DNS: $nd → ${dip:-не резолвится}, а сервер: $srv_ip"
    local go=""
    askyn go "Продолжить всё равно (клиенты не подключатся, пока DNS не поправишь)?" "n"
    [[ "$go" == true ]] || return 0
  fi
  if [[ "$sec" == "tls" ]] && ! cert_paths "$nd" >/dev/null 2>&1; then
    if [[ -n "$WILDCARD_DOMAIN" && "$nd" == *."$WILDCARD_DOMAIN" ]]; then
      log "Сёрт: wildcard *.$WILDCARD_DOMAIN покрывает $nd"
    else
      log "Сёрта для $nd нет — выпускаю на месте (certbot)"
      cert_issue "$nd" || warn "Серт для $nd не выпущен — сделай это через п.10 и повтори"
    fi
  fi
  echo "  План: JSON стрима/настроек ($old→$nd), hosts, SNI-карта, reality-dest при необходимости."
  local go=""
  askyn go "Менять? (панель будет остановлена на время правки)" "n"
  [[ "$go" == true ]] || return 0
  auto_backup_stack >/dev/null 2>&1 || true
  local xui_was=""
  if systemctl is-active --quiet x-ui 2>/dev/null; then
    xui_was=1; systemctl stop x-ui >/dev/null 2>&1 || true; sleep 1
  fi
  local pyok=1
  python3 - "$XUI_DB" "$id" "$old" "$nd" <<'PYSET' && pyok=0 || pyok=1
import sqlite3, json, sys
db, iid, old, new = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
def walk(v):
    if isinstance(v, str):
        return new if v == old else v
    if isinstance(v, list):
        return [walk(x) for x in v]
    if isinstance(v, dict):
        return {k: walk(x) for k, x in v.items()}
    return v
con = sqlite3.connect(db, timeout=10)
con.execute("PRAGMA busy_timeout=8000")
s1, s2 = con.execute("SELECT settings,stream_settings FROM inbounds WHERE id=?", (iid,)).fetchone()
se = json.loads(s1 or "{}"); st = json.loads(s2 or "{}")
se = walk(se); st = walk(st)
# reality: dest с чужим доменом → новый:443; локальный decoy (127.*) не трогаем
rs = st.get("realitySettings") or {}
for k in ("dest", "target"):
    d = rs.get(k)
    if isinstance(d, str) and d.startswith(old + ":"):
        rs[k] = new + ":443"
if rs: st["realitySettings"] = rs
# tls: свой серт на новый домен, если выпущен
if (st.get("security") or "").lower() == "tls":
    fc, fk = f"/etc/letsencrypt/live/{new}/fullchain.pem", f"/etc/letsencrypt/live/{new}/privkey.pem"
    import os
    if os.path.isfile(fc) and os.path.isfile(fk):
        for c in (st.get("tlsSettings") or {}).get("certificates") or []:
            if c.get("certificateFile"): c["certificateFile"] = fc
            if c.get("keyFile"):        c["keyFile"] = fk
con.execute("UPDATE inbounds SET settings=?, stream_settings=? WHERE id=?",
            (json.dumps(se, ensure_ascii=False), json.dumps(st, ensure_ascii=False), iid))
con.commit()
print("[+] JSON обновлён")
PYSET
  if [[ "$pyok" != 0 ]]; then
    err "Правка БД не прошла — панель НЕ трогаю дальше"; [[ "$xui_was" == 1 ]] && systemctl start x-ui; return 1
  fi
  hosts_upsert "$id" "$nd"
  # SNI-карта: переносим бэкенд старого домена на новый
  local backend
  backend=$(grep -E "^\s+$old\s+" "$SNI_CONF" 2>/dev/null | awk '{print $2}' | head -1)
  if [[ -n "$backend" ]]; then
    sni_map_remove "$old"; sni_map_add "$nd" "$backend"
    log "  SNI-карта: $old → $nd (бэкенд $backend сохранён)"
  else
    sni_upstream_add "inb_${id}_backend" "$port"
    sni_map_add "$nd" "inb_${id}_backend"
    log "  SNI-карта: $nd → inb_${id}_backend (старой записи не было)"
  fi
  [[ "$xui_was" == 1 ]] && { systemctl start x-ui >/dev/null 2>&1 || true; sleep 2; }
  nginx_reload || true
  audit "inbound: смена домена #$id: $old → $nd"
  echo
  log "Готово: #$id теперь $nd. Проверь таблицу ниже — порт слушается, домен новый."
  inbounds_live
}

# =====================================================================
# САМОДИАГНОСТИКА (read-only health check): сервисы, порты, SNI, серты,
# UFW, DNS. НИЧЕГО не меняет — только показывает проблемы и подсказки.
# =====================================================================
stack_doctor() {
  line; echo -e "${B}   САМОДИАГНОСТИКА СТЕКА${N}"; line
  local problems=0
  ok()   { echo -e "  ${G}[✓]${N} $*"; }
  bad()  { echo -e "  ${R}[x]${N} $*"; problems=$((problems+1)); }
  warn2(){ echo -e "  ${Y}[!]${N} $*"; }
  hint() { echo -e "      ${Y}→${N} $*"; }

  echo -e "${B}— Сервисы —${N}"
  local s
  for s in nginx x-ui; do
    if systemctl is-active --quiet "$s" 2>/dev/null; then ok "$s: активен"; else bad "$s: НЕ активен"; hint "systemctl restart $s"; fi
  done
  if [[ "$ADG_PRESENT" == true && -n "$ADG_SERVICE" ]]; then
    if systemctl is-active --quiet "$ADG_SERVICE" 2>/dev/null; then ok "AdGuard ($ADG_SERVICE): активен"; else bad "AdGuard: НЕ активен"; hint "systemctl restart $ADG_SERVICE"; fi
  else
    warn2 "AdGuard не установлен (необязательно)"
  fi

  echo -e "${B}— Слушающие порты —${N}"
  if ss -tlnH "sport = :443" 2>/dev/null | grep -q .; then ok "443/tcp слушает nginx"; else bad "443/tcp НЕ слушается"; hint "п.1 пересборка стека / systemctl restart nginx"; fi
  if ss -tlnH "sport = :80" 2>/dev/null | grep -q .; then ok "80/tcp слушается (ACME webroot)"; else warn2 "80/tcp не слушается — HTTP-01 выпуска не будет (wildcard DNS-01 не страдает)"; fi
  local wp sp wl sl
  wp=$(xui_get webPort); sp=$(xui_get subPort); wl=$(xui_get webListen); sl=$(xui_get subListen)
  if [[ "$wl" == "127.0.0.1" ]]; then ok "панель слушает 127.0.0.1:$wp (наружу не торчит)"; else bad "панель слушает ${wl:-?}:$wp — доктрина 443 нарушена"; hint "п.1 (запишет 127.0.0.1)"; fi
  if [[ "$sl" == "127.0.0.1" || -z "$sl" ]]; then ok "подписки слушают 127.0.0.1:$sp"; else bad "подписки слушают ${sl:-?}:$sp — наружу торчат"; fi
  # инбаунды: TCP должен слушать 127.0.0.1 (tproxy — 0.0.0.0)
  local iid iproto ilisten iport isec idest
  while IFS='|' read -r iid iproto iport ilisten isec idest; do
    [[ -z "$iid" ]] && continue
    if [[ "$iproto" == "tproxy" ]]; then
      [[ "$ilisten" == "0.0.0.0" || "$ilisten" == "::" ]] && ok "#$iid tproxy на 0.0.0.0:$iport" || warn2 "#$iid tproxy слушает $ilisten — маршруту tg нужен 0.0.0.0"
      continue
    fi
    if is_udp_proto "$iproto"; then continue; fi   # UDP наружу напрямую — не проверяем
    if [[ "$ilisten" != "127.0.0.1" && "$ilisten" != "" ]]; then
      bad "#$iid ($iproto:$iport) слушает $ilisten — должен 127.0.0.1 (за 443)"
      hint "п.4 → Починить инбаунд #$iid"
    fi
  done < <(sqlite3 -cmd ".timeout 3000" "$XUI_DB" \
    "SELECT id, protocol, port, COALESCE(listen,''), COALESCE(json_extract(stream_settings,'\$.security'),''), COALESCE(json_extract(stream_settings,'\$.realitySettings.dest'),'') FROM inbounds WHERE enable=1;" 2>/dev/null || true)

  echo -e "${B}— SNI-маршрут —${N}"
  if [[ -f "$SNI_CONF" ]]; then
    ok "$SNI_CONF на месте ($(grep -c 'upstream ' "$SNI_CONF" 2>/dev/null || echo 0) upstream-ов)"
    grep -qE "panel_backend;" "$SNI_CONF" 2>/dev/null && ok "домен панели замаплен (panel_backend)" || bad "panel_backend не найден в $SNI_CONF"
  else
    bad "$SNI_CONF не найден"; hint "п.1 — первичная настройка"
  fi
  if nginx -t >/dev/null 2>&1; then ok "nginx -t: конфиг валиден"; else bad "nginx -t провален:"; nginx -t 2>&1 | tail -3 | sed 's/^/      /'; fi

  echo -e "${B}— Сертификаты (истекают < 14 дн — [!]) —${N}"
  local ldir crt end_left
  ldir="/etc/letsencrypt/live"
  if [[ -d "$ldir" ]] && ls -1 "$ldir" 2>/dev/null | grep -q .; then
    local d
    for d in "$ldir"/*/; do
      d=$(basename "$d"); crt="$ldir/$d/fullchain.pem"
      [[ -f "$crt" ]] || { warn2 "$d: fullchain.pem нет"; continue; }
      end_left=$(( ($(date -d "$(openssl x509 -enddate -noout -in "$crt" 2>/dev/null | cut -d= -f2)" +%s 2>/dev/null || echo 0) - $(date +%s)) / 86400 ))
      if [[ "$end_left" -ge 14 ]]; then ok "$d: ~${end_left} дн"; elif [[ "$end_left" -ge 0 ]]; then warn2 "$d: истекает через ~${end_left} дн"; hint "п.10 → обновить"; else bad "$d: ПРОСРОЧЕН"; hint "п.10 → обновить"; fi
    done
  else
    warn2 "сертов в /etc/letsencrypt/live нет"
  fi

  echo -e "${B}— UFW —${N}"
  if ufw_is_active; then
    ok "UFW активен"
    ufw status 2>/dev/null | grep -qE "443/tcp\s+ALLOW" && ok "443/tcp разрешён" || bad "443/tcp НЕ разрешён"; hint "п.11"
    ufw status 2>/dev/null | grep -qE "${SSH_PORT:-22}/tcp\s+ALLOW" && ok "SSH (${SSH_PORT:-22}/tcp) разрешён" || warn2 "SSH-порт не помечен ALLOW — проверь, как подключаешься"
    local extra
    extra=$(ufw status 2>/dev/null | grep -E "ALLOW" | grep -E "/tcp" | grep -vE "443/tcp|${SSH_PORT:-22}/tcp" | head -5)
    [[ -n "$extra" ]] && { warn2 "лишние TCP-разрешения:"; echo "$extra" | sed 's/^/        /'; hint "п.11 → сброс (только SSH+443+UDP)"; }
  else
    bad "UFW не активен (или бинарь не найден — проверь: systemctl is-active ufw)"; hint "п.11"
  fi

  echo -e "${B}— fail2ban —${N}"
  if systemctl is-active --quiet fail2ban 2>/dev/null; then
    ok "fail2ban активен"
    fail2ban-client status decoy-login >/dev/null 2>&1 && ok "jail decoy-login работает" || bad "jail decoy-login НЕ работает"; hint "п.1/п.7"
    fail2ban-client status recidive >/dev/null 2>&1 && ok "jail recidive работает (рецидивисты — бан на неделю)" || warn2 "recidive выключен (п.7 → вкл.)"
  else
    bad "fail2ban НЕ активен"; hint "systemctl restart fail2ban"
  fi

  echo -e "${B}— Decoy-страницы (что реально отвечает nginx) —${N}"
  if [[ -f "$STACK_CONF" ]] && grep -q "^# >>> decoy " "$STACK_CONF" 2>/dev/null; then
    local mline mport mdom mroot code body_md5 idx_md5 n_ok=0 n_bad=0
    while IFS= read -r mline; do
      mport=$(grep -oE 'port=[0-9]+'  <<<"$mline" | head -1 | cut -d= -f2)
      mdom=$(grep  -oE 'domain=[^ ]+$' <<<"$mline" | head -1 | cut -d= -f2-)
      mroot=$(grep -oE 'root=[^ ]+'   <<<"$mline" | head -1 | cut -d= -f2-)
      [[ -z "$mdom" || -z "$mport" ]] && continue
      # UA — браузерный: decoy с ua404=1 отдаёт curl'у 404, доктор должен видеть
      # страницу глазами «человека»
      code=$(curl -sk --max-time 5 -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124 Safari/537.36" -o /tmp/.decoy_body -w '%{http_code}' -H "Host: $mdom" "https://127.0.0.1:$mport/" 2>/dev/null || echo 000)
      if [[ "$code" == "200" || "$code" == "302" || "$code" == "401" ]]; then
        if [[ "$code" == "200" && -f "$mroot/index.html" ]]; then
          body_md5=$(md5sum /tmp/.decoy_body 2>/dev/null | awk '{print $1}')
          idx_md5=$(md5sum "$mroot/index.html" 2>/dev/null | awk '{print $1}')
          if [[ "$body_md5" == "$idx_md5" ]]; then ok "$mdom (:$mport): 200, контент = шаблон"; n_ok=$((n_ok+1))
          else bad "$mdom (:$mport): 200, но контент НЕ совпадает с $mroot/index.html"; n_bad=$((n_bad+1)); fi
        else
          ok "$mdom (:$mport): HTTP $code (ожидаемо для redirect/locked)"; n_ok=$((n_ok+1))
        fi
      else
        bad "$mdom (:$mport): ответ $code — decoy НЕ отвечает"; hint "п.4/пересборка decoy, systemctl restart nginx"; n_bad=$((n_bad+1))
      fi
    done < <(grep "^# >>> decoy " "$STACK_CONF")
    rm -f /tmp/.decoy_body 2>/dev/null || true
    [[ "$n_bad" -gt 0 ]] && problems=$((problems+n_bad))
    [[ "$n_ok" -eq 0 && "$n_bad" -eq 0 ]] && warn2 "decoy-блоки не распарсились"
  else
    warn2 "decoy-блоков в stack.conf нет"
  fi

  echo -e "${B}— Порты инбаундов (быстро; подробно — п.19) —${N}"
  if [[ -n "$XUI_DB" && -f "$XUI_DB" ]]; then
    local dead
    dead=$(python3 - "$XUI_DB" <<'PYPORTS' 2>/dev/null
import sqlite3, json, sys, subprocess, re
UDP_PROTOS={"hysteria","hysteria2","qwdtt","csqtt","tuic","wireguard","amnezia","amneziawg","awg"}
try:
    con=sqlite3.connect(f"file:{sys.argv[1]}?mode=ro",uri=True,timeout=5)
    rows=con.execute("SELECT id,protocol,port,COALESCE(listen,''),settings,stream_settings FROM inbounds WHERE enable=1").fetchall()
except Exception: sys.exit(0)
def listening(net,p):
    if net=="tcp":
        out=subprocess.run(["ss","-tln"],capture_output=True,text=True,timeout=5).stdout
        return bool(re.search(rf":{p}(\s|$)",out))
    out=subprocess.run(["ss","-ulan"],capture_output=True,text=True,timeout=5).stdout
    if re.search(rf":{p}(\s|$)",out): return True
    return False
for iid,proto,port,listen,s1,s2 in rows:
    try: se=json.loads(s1 or "{}")
    except Exception: se={}
    try: st=json.loads(s2 or "{}")
    except Exception: st={}
    try: p=int(se.get("port") or port or 0)
    except Exception: p=int(port or 0)
    if p<=0: continue
    net="udp" if proto.lower() in UDP_PROTOS else (st.get("network") or "tcp")
    # xhttp/ws/grpc/httpupgrade — TCP-транспорты: наружу проверяем как tcp,
    # иначе «не слушается» на живом инбаунде (панель при этом права)
    if net!="udp": net="tcp"
    if not listening(net,p): print(f"#{iid} {proto} {p}/{net}")
PYPORTS
)
    if [[ -z "$dead" ]]; then
      ok "все включённые инбаунды слушают свои порты"
    else
      local dl
      while IFS= read -r dl; do [[ -z "$dl" ]] && continue; bad "не слушается: $dl"; done <<<"$dead"
      hint "systemctl restart x-ui; если не помогло — п.19/логи xray"
    fi
  fi

  echo -e "${B}— Ресурсы —${N}"
  local duse
  duse=$(df -Pm / 2>/dev/null | awk 'NR==2{print $5}' | tr -d '%')
  if [[ -n "$duse" ]]; then
    if (( duse >= 90 )); then bad "диск: занято ${duse}% — критично"; hint "почистить /root/stack-backups, /var/log"
    elif (( duse >= 80 )); then warn2 "диск: занято ${duse}%"; else ok "диск: занято ${duse}%"; fi
  fi
  if [[ -n "$XUI_DB" && -f "$XUI_DB" ]]; then
    local dbsize nbak nauto nman fresh
    dbsize=$(du -h "$XUI_DB" 2>/dev/null | awk '{print $1}')
    nauto=$(ls -1dt "$BACKUP_DIR"/auto-* 2>/dev/null | wc -l)              # автобэкап (старт скрипта)
    nman=$(ls -1 "$BACKUP_DIR"/stack-backup-*.tar.gz 2>/dev/null | wc -l)  # ручные (п.8)
    nbak=$((nauto + nman))
    fresh=$(ls -1dt "$BACKUP_DIR"/auto-* "$BACKUP_DIR"/stack-backup-*.tar.gz 2>/dev/null | head -1 | xargs -r basename)
    ok "x-ui.db: ${dbsize:-?} · бэкапов: $nbak (авто:$nauto/руками:$nman; свежий: $fresh)"
    (( nbak == 0 )) && warn2 "бэкапов нет — п.8"
  fi
  if [[ -f /var/run/reboot-required ]]; then
    bad "система ждёт ПЕРЕЗАГРУЗКУ (обновлено ядро/библиотеки)"
    hint "reboot в удобное окно: стек поднимется сам (nginx/x-ui/AdGuard/fail2ban — systemd)"
  fi

  echo -e "${B}— DNS / домены стека —${N}"
  local srv_ip
  srv_ip=$(server_ip4)
  local doms pd
  pd="${PANEL_DOMAIN:-$(xui_get webDomain 2>/dev/null || true)}"
  doms=$(python3 - "$XUI_DB" "${REALITY_TARGETS[@]}" <<'PYDOMS' 2>/dev/null
import sqlite3, json, sys
skip=set(a.lower() for a in sys.argv[2:])
seen=set(); out=[]
def add(d):
    d=(d or "").strip().lower()
    if d and d not in skip and d not in seen:
        seen.add(d); out.append(d)
try:
    con=sqlite3.connect(f"file:{sys.argv[1]}?mode=ro",uri=True,timeout=5)
    for setts_s,stream_s in con.execute("SELECT settings,stream_settings FROM inbounds WHERE enable=1 AND port>0"):
        try: se=json.loads(setts_s or "{}")
        except Exception: se={}
        try: st=json.loads(stream_s or "{}")
        except Exception: st={}
        rs=st.get("realitySettings") or {}
        add(se.get("domain")); add(se.get("hostname")); add(se.get("sni"))
        add((st.get("tlsSettings") or {}).get("serverName"))
        add((rs.get("serverNames") or [None])[0])   # чужие цели отсеет skip-список
except Exception:
    pass
print("\n".join(out))
PYDOMS
)
  [[ -n "$pd" ]] && doms="$pd"$'\n'"$doms"
  local d a_ip
  while IFS= read -r d; do
    [[ -z "$d" ]] && continue
    a_ip=$(dig +short A "$d" 2>/dev/null | tail -1)
    if [[ -n "$a_ip" && "$a_ip" == "$srv_ip" ]]; then ok "$d → $a_ip ✓"
    elif [[ -z "$a_ip" ]]; then warn2 "$d: A-запись не резолвится"
    else warn2 "$d → $a_ip, а сервер: $srv_ip"; fi
  done <<<"$doms"

  echo -e "${B}— Heal-таймер —${N}"
  if systemctl is-enabled --quiet stack-heal.timer 2>/dev/null; then
    ok "самолечение включено (каждые 2 мин); последний лог: $(tail -1 /root/stack-heal.log 2>/dev/null | head -c 80)"
  else
    warn2 "самолечение выключено (отклонения чинятся только вручную: п.1/п.4)"
  fi

  echo
  line
  if [[ "$problems" -eq 0 ]]; then
    echo -e "${G}  Итог: проблем не найдено ✓${N}"
  else
    echo -e "${R}  Итог: проблем — $problems${N} (подсказки [→] выше)"
  fi
  line
  return 0
}

# п.18 с обёрткой: одиночный прогон или наблюдение каждые 10 сек
stack_doctor_menu() {
  stack_doctor
  local wm=""
  askyn wm "Наблюдать непрерывно (обновление каждые 10 сек, любая клавиша — выход)?" "n"
  [[ "$wm" == true ]] || return 0
  while :; do
    local k=""
    read -t 10 -n 1 k 2>/dev/null && [[ -n "$k" ]] && break
    clear
    stack_doctor
  done
}

fmt_bytes() {   # <bytes> → человекочитаемо
  local b="${1:-0}"
  [[ -z "$b" || "$b" == "NULL" ]] && b=0
  if   (( b >= 1099511627776 )); then echo "$(( b / 1099511627776 )) ТБ"
  elif (( b >= 1073741824 ));    then echo "$(( b / 1073741824 )) ГБ"
  elif (( b >= 1048576 ));       then echo "$(( b / 1048576 )) МБ"
  elif (( b >= 1024 ));          then echo "$(( b / 1024 )) КБ"
  else echo "${b} Б"; fi
}

# п.19: live-таблица по всем инбаундам — порт слушает?, серт (дней), клиенты, трафик
inbounds_live() {
  line; echo -e "${B}   ИНБАУНДЫ — LIVE${N}"; line
  [[ -z "$XUI_DB" || ! -f "$XUI_DB" ]] && { err "x-ui.db не найден"; return 1; }

  printf "  %-5s %-11s %-7s %-5s %-8s %-5s %-9s %s\n" "ID" "Прото" "Порт" "Слух" "Серт" "Кл." "Трафик" "Домен"
  echo "  ─────────────────────────────────────────────────────────────────────────────"

  local out
  out=$(python3 - "$XUI_DB" <<'PYLIVE' 2>/dev/null
import sqlite3, json, sys
try:
    con=sqlite3.connect(f"file:{sys.argv[1]}?mode=ro",uri=True,timeout=5)
    rows=con.execute("SELECT id,protocol,port,COALESCE(listen,''),settings,stream_settings FROM inbounds ORDER BY id").fetchall()
except Exception:
    sys.exit(0)
for iid,proto,port,listen,setts_s,stream_s in rows:
    try: se=json.loads(setts_s or "{}")
    except Exception: se={}
    try: st=json.loads(stream_s or "{}")
    except Exception: st={}
    rs=st.get("realitySettings") or {}
    dom=(se.get("domain") or se.get("hostname") or se.get("sni")
         or (st.get("tlsSettings") or {}).get("serverName")
         or (rs.get("serverNames") or [None])[0] or "")
    try: p=int(se.get("port") or port or 0)
    except Exception: p=int(port or 0)
    # UDP-протоколы классифицируем ПО ИМЕНИ — поле network в stream_settings
    # бывает испорчено/наследовано (hysteria с network=tcp живёт у LucX)
    UDP_PROTOS={"hysteria","hysteria2","qwdtt","csqtt","tuic","wireguard","amnezia","amneziawg","awg"}
    net="udp" if proto.lower() in UDP_PROTOS else (st.get("network") or "tcp")
    cert=(se.get("certFile") or "")
    if not cert:
        certs=(st.get("tlsSettings") or {}).get("certificates") or []
        if certs: cert=certs[0].get("certificateFile","")
    if (st.get("security") or "").lower()=="reality": cert="REALITY"
    try: ncl=len(se.get("clients") or [])
    except Exception: ncl=0
    # трафик: панель может писать его и в client_traffics (по клиентам),
    # и в inbounds.up/down (по инбаунду) — берём максимум из обоих источников
    t1=t2=0
    try:
        r=con.execute("SELECT COALESCE(SUM(up),0)+COALESCE(SUM(down),0) FROM client_traffics WHERE inbound_id=?", (iid,)).fetchone()
        t1=r[0] if r else 0
    except Exception: pass
    try:
        r=con.execute("SELECT COALESCE(up,0)+COALESCE(down,0) FROM inbounds WHERE id=?", (iid,)).fetchone()
        t2=r[0] if r else 0
    except Exception: pass
    tot=max(int(t1 or 0), int(t2 or 0))
    print(f"{iid}\x1f{proto}\x1f{p}\x1f{net}\x1f{cert}\x1f{ncl}\x1f{dom}\x1f{tot}")
PYLIVE
)
  local iid proto p net cert ncl dom tot st_us days traf e
  while IFS=$'\x1f' read -r iid proto p net cert ncl dom tot; do
    [[ -z "$iid" ]] && continue
    if [[ "$net" == "udp" ]]; then
      if ss -ulan 2>/dev/null | grep -qE ":${p}([[:space:]]|\$)"; then
        st_us="✓"
      elif command -v nft >/dev/null 2>&1 && nft list ruleset 2>/dev/null | grep -qw "$p"; then
        st_us="✓*"   # порт открыт NAT-правилом (port hopping) — сокет слушает другой порт
      elif iptables -t nat -S 2>/dev/null | grep -qE "dport[ =]$p([ :]|$)|:$p([ :]|$)"; then
        st_us="✓*"   # то же, но legacy-iptables
      elif grep -qiE ":$(printf '%04X' "$p" 2>/dev/null)([[:space:]]|\$)" /proc/net/udp /proc/net/udp6 2>/dev/null; then
        st_us="✓"    # прямое чтение /proc — работает даже без ss
      else
        st_us="✗"
      fi
    else
      ss -tln 2>/dev/null | grep -qE ":${p}([[:space:]]|\$)" && st_us="✓" || st_us="✗"
    fi
    days="—"
    if [[ "$cert" == "REALITY" ]]; then
      days="RLTY"
    elif [[ -n "$cert" && -f "$cert" ]]; then
      e=$(openssl x509 -enddate -noout -in "$cert" 2>/dev/null | cut -d= -f2)
      days="$(( ($(date -d "$e" +%s 2>/dev/null || echo 0) - $(date +%s)) / 86400 )) дн"
      [[ "$days" == "-1 дн" || "$days" == "0 дн" ]] && days="ПРОСРОЧЕН"
    fi
    traf=$(fmt_bytes "${tot:-0}")
    printf "  %-5s %-11s %-7s %-5s %-8s %-5s %-9s %s\n" "#$iid" "$proto" "$p" "$st_us" "$days" "$ncl" "$traf" "$dom"
  done <<<"$out"
  echo
  warn "✗ — порт НЕ слушается (инбаунд не работает) · ✓* — UDP открыт через NAT (port hopping) · RLTY — reality: серт у decoy в nginx · Кл. — число клиентов"
  line
  return 0
}

# Единые пункты «установить/удалить»: смотрим текущее состояние и предлагаем
# обратное действие — вместо двух отдельных пунктов меню.
panel_manage() {
  line; echo -e "${B}   ПАНЕЛЬ LUCX UI — УСТАНОВКА / УДАЛЕНИЕ${N}"; line
  if [[ -n "$XUI_DB" && -f "$XUI_DB" ]]; then
    log "Панель уже установлена (x-ui.db: $XUI_DB)"
    local go=""
    askyn go "Удалить панель LucX UI со всеми данными?" "n"
    [[ "$go" == true ]] && uninstall_panel_lucx
    return 0
  fi
  log "Панель не найдена — установка."
  install_lucx_panel
}

adguard_manage() {
  line; echo -e "${B}   ADGUARD HOME — УСТАНОВКА / УДАЛЕНИЕ${N}"; line
  if [[ "$ADG_PRESENT" == true && -n "$ADG_SERVICE" ]]; then
    log "AdGuard Home уже установлен (service: $ADG_SERVICE)"
    local go=""
    askyn go "Удалить AdGuard Home?" "n"
    [[ "$go" == true ]] && uninstall_adguard
    return 0
  fi
  log "AdGuard Home не найден — установка."
  install_adguard_home
}

# =====================================================================
# Гигиена nginx и логов: server_tokens off, security-заголовки на decoy,
# ротация decoy-логов (если не покрыта системным logrotate).
# =====================================================================
nginx_hygiene() {
  line; echo -e "${B}   ГИГИЕНА NGINX И ЛОГОВ${N}"; line
  mkdir -p "$BACKUP_DIR" 2>/dev/null || true
  local changed=0
  # 1) server_tokens off — не показывать версию nginx
  # (сначала снимаем возможный дубль от прежнего запуска; директива
  #  может уже быть задана в любом регистре — тогда нормализуем к off)
  cp -a /etc/nginx/nginx.conf "$BACKUP_DIR/nginx.conf.bak-$(date +%Y%m%d-%H%M%S)" 2>/dev/null || true
  if grep -q 'server_tokens off; # stack-manager' /etc/nginx/nginx.conf 2>/dev/null; then
    sed -i '/server_tokens off; # stack-manager/d' /etc/nginx/nginx.conf
    log "server_tokens: убран дубль от прошлого запуска"; changed=1
  fi
  if grep -qiE '^[[:space:]]*server_tokens[[:space:]]+' /etc/nginx/nginx.conf 2>/dev/null; then
    sed -i -E 's/^([[:space:]]*server_tokens[[:space:]]+).*/\1off; # stack-manager/I' /etc/nginx/nginx.conf
    log "server_tokens: уже был задан в nginx.conf — приведён к off"
  else
    sed -i 's/^http {/http {\n    server_tokens off; # stack-manager/' /etc/nginx/nginx.conf
    if grep -q 'server_tokens off' /etc/nginx/nginx.conf; then
      log "server_tokens off → включён (версия nginx больше не светится)"
    else
      err "не нашёл 'http {' в nginx.conf — вставь 'server_tokens off;' вручную"
    fi
  fi
  grep -qiE '^[[:space:]]*server_tokens[[:space:]]+off' /etc/nginx/nginx.conf 2>/dev/null && { audit "nginx: server_tokens off"; changed=1; }
  # 2) security-заголовки decoy: сниппет + вживление во все блоки stack.conf
  mkdir -p /etc/nginx/snippets
  cat > /etc/nginx/snippets/decoy-headers.conf <<'EOF'
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "SAMEORIGIN" always;
add_header Referrer-Policy "no-referrer-when-downgrade" always;
EOF
  if grep -q 'snippets/decoy-headers' "$STACK_CONF" 2>/dev/null; then
    log "заголовки decoy: уже подключены"
  elif [[ -f "$STACK_CONF" ]]; then
    cp -a "$STACK_CONF" "$BACKUP_DIR/stack.conf.bak-hygiene-$(date +%Y%m%d-%H%M%S)" 2>/dev/null || true
    sed -i '/^    ssl_certificate_key /a\    include /etc/nginx/snippets/decoy-headers.conf;' "$STACK_CONF"
    log "заголовки decoy: подключены ко всем блокам stack.conf"; audit "nginx: decoy-заголовки (nosniff/SAMEORIGIN/referrer)"; changed=1
  fi
  # 3) ротация decoy-логов (если не покрыта общим logrotate nginx)
  if grep -rqs 'var/log/nginx' /etc/logrotate.d/ 2>/dev/null; then
    log "ротация логов nginx: уже настроена (/etc/logrotate.d)"
  else
    cat > /etc/logrotate.d/stack-decoy <<'EOF'
/var/log/nginx/decoy-access.log /var/log/nginx/decoy-error.log {
    daily
    rotate 14
    size 50M
    missingok
    notifempty
    compress
    delaycompress
    sharedscripts
    postrotate
        [ -f /var/run/nginx.pid ] && kill -USR1 $(cat /var/run/nginx.pid) 2>/dev/null || true
    endscript
}
EOF
    log "ротация decoy-логов: создана (день / 14 копий / сжатие)"; audit "logrotate: stack-decoy создан"; changed=1
  fi
  # 4) проверка и перезагрузка
  if (( changed )); then
    if nginx -t >/dev/null 2>&1; then
      nginx_reload
      log "Гигиена применена ✓"
    else
      err "nginx -t не прошёл — откат: $BACKUP_DIR/*.bak-hygiene-*"
      nginx -t 2>&1 | tail -3
      return 1
    fi
  else
    log "Всё уже в порядке — менять нечего ✓"
  fi
  pause
}

# =====================================================================
# СТЕЛС-АУДИТ: что о сервере увидит Shodan/Censys/crt.sh.
# Только чтение — ничего не меняет.
# =====================================================================
stealth_audit() {
  line; echo -e "${B}   СТЕЛС-АУДИТ (глазами сканера)${N}"; line
  local base="${WILDCARD_DOMAIN:-${PANEL_DOMAIN:-}}"
  # последние два лейбла: *.vladufqaa.online / vladufqaa.online / panel.vladufqaa.online → vladufqaa.online
  local _p
  IFS='.' read -r -a _p <<<"$base"
  local _n=${#_p[@]}
  if (( _n >= 3 )); then base="${_p[_n-2]}.${_p[_n-1]}"; fi

  local ufw_on=0
  ufw_is_active && ufw_on=1
  local allowed=""
  if [[ "$ufw_on" == 1 ]]; then
    allowed=$(LC_ALL=C ufw status 2>/dev/null | awk '/ALLOW/ {print $1}' | sort -u)
  else
    warn "UFW не активен — ВСЕ слушающие порты видны интернету!"
  fi
  stealth_vis() {   # порт/протокол виден миру? (ufw off → виден всё)
    [[ "$ufw_on" == 1 ]] || return 0
    grep -qE "^${1}/${2}([[:space:]]|$)" <<<"$allowed" \
      || grep -qE "^${1}([[:space:]]|$)" <<<"$allowed"
  }

  echo; echo -e "${B}— 1. Слушающие TCP-порты —${N}"
  local p
  for p in $(ss -tln 2>/dev/null | awk 'NR>1 { if ($4 ~ /^127\./ || $4 ~ /^\[::1\]/) next; split($4,a,":"); print a[length(a)] }' | sort -un); do
    if ! stealth_vis "$p" tcp; then
      ok "порт $p — слушается, но закрыт UFW (сканерам невидим)"
    elif [[ "$p" == "443" ]]; then
      ok "порт 443 — SNI-роутер (decoy-доктрина)"
    elif [[ "$p" == "80" ]]; then
      log "порт 80 — HTTP (обычно для ACME); что отдаёт — см. раздел 3"
    elif [[ "$p" == "22" ]]; then
      warn "порт 22 — SSH открыт миру: банер + host key привязывают тебя между IP (см. раздел 5)"
    else
      err "порт $p — нестандартный и ОТКРЫТ: сканеры его индексируют (инбаунд?). Лучше за 443/SNI или reality"
      echo "      (пропустило правило UFW: $(grep -E "^${p}/" <<<"$allowed" | head -1))"
    fi
  done

  echo; echo -e "${B}— 2. Слушающие UDP-порты (QUIC/крауты) —${N}"
  local any_udp=0
  for p in $(ss -uln 2>/dev/null | awk 'NR>1 { if ($4 ~ /^127\./ || $4 ~ /^\[::1\]/) next; if ($5 != "*:*") next; split($4,a,":"); print a[length(a)] }' | sort -un); do
    any_udp=1
    if ! stealth_vis "$p" udp; then
      ok "udp $p — закрыт UFW (невидим)"
    elif [[ "$p" == "53" ]]; then
      warn "udp 53 — DNS; если отвечает наружу — open resolver (см. раздел 5)"
    else
      err "udp $p — открыт (hysteria/tuic?): QUIC-банер фингерпринтится Censys"
      echo "      (пропустило правило UFW: $(grep -E "^${p}/" <<<"$allowed" | head -1))"
    fi
  done
  [[ "$any_udp" == 0 ]] && ok "открытых UDP-слушателей нет"

  echo; echo -e "${B}— 3. Что видит сканер на :443 БЕЗ SNI —${N}"
  local subj
  subj=$(echo | timeout 8 openssl s_client -connect 127.0.0.1:443 -noservername 2>/dev/null | openssl x509 -noout -subject 2>/dev/null)
  if [[ -z "$subj" ]]; then
    warn "сертификат не получен — проверь руками: openssl s_client -connect $(hostname -I 2>/dev/null | awk '{print $1}'):443"
  else
    echo "    $subj"
    if [[ -n "$PANEL_DOMAIN" && "$subj" == *"$PANEL_DOMAIN"* ]]; then
      err "443 отдаёт серт ПАНЕЛИ → Shodan привяжет «$PANEL_DOMAIN» к IP. Смени default-блок (decoy-серт)."
    elif [[ -n "$base" && "$subj" == *"$base"* ]]; then
      ok "свой wildcard/decoy-серт — приемлемо (панель не светится)"
    else
      ok "чужой серт — идеально (выглядишь чужим сайтом)"
    fi
  fi

  echo; echo -e "${B}— 4. HTTP :80 —${N}"
  if ! stealth_vis "80" tcp; then
    ok "80 закрыт UFW — невидим (ACME п.4 временно открывает сам)"
  else
    local code; code=$(curl -s -o /dev/null -w '%{http_code}' -m 6 http://127.0.0.1/ 2>/dev/null)
    case "$code" in
      301|302|308) ok "редирект на HTTPS ($code) — нейтрально" ;;
      000) warn "80 открыт в UFW, но не отвечает — лучше закрыть" ;;
      *) warn "ответ $code — сканер индексирует содержимое; проверь, что там decoy/заглушка, а не служебное" ;;
    esac
  fi

  echo; echo -e "${B}— 5. SSH :22 —${N}"
  if ! stealth_vis "22" tcp; then
    ok "22 закрыт UFW для мира — сканерам невиден"
  else
    warn "22 открыт: host key Shodan связывает все твои IP (переезд не помогает)."
    echo "      Смягчение: UFW только на свой IP, смена порта или knocking (ТОЛЬКО на 22, не на 443!)."
  fi

  echo; echo -e "${B}— 6. DNS :53 наружу —${N}"
  local udp53; udp53=$(ss -uln 2>/dev/null | awk 'NR>1 && $4 ~ /:53$/ && $5 == "*:*" && $4 !~ /^127\./ && $4 !~ /^\[::1\]/ {c++} END {print c+0}')
  if [[ "$udp53" -eq 0 ]]; then
    ok "53 наружу не слушается ✓"
  elif ! stealth_vis "53" udp; then
    ok "53 слушается, но закрыт UFW ✓"
  else
    err "53 открыт миру — open resolver (абьюз + палево)! Закрой в UFW (п.11)."
  fi

  echo; echo -e "${B}— 7. Публичные имена (Certificate Transparency) —${N}"
  if [[ -z "$base" ]]; then
    log "базовый домен не определён — пропуск"
  else
    local ct
    ct=$(curl -s -m 25 --retry 2 --retry-delay 2 "https://crt.sh/?q=%25.${base}&output=json" 2>/dev/null | python3 -c '
import json, sys
try: d = json.load(sys.stdin)
except Exception: sys.exit(0)
names = set()
for r in d if isinstance(d, list) else []:
    for n in str(r.get("name_value", "")).split("\n"):
        n = n.strip().lstrip("*.")
        if n and "=" not in n: names.add(n)
for n in sorted(names)[:20]: print(n)' 2>/dev/null)
    if [[ -z "$ct" ]]; then
      log "crt.sh не ответил — проверь руками: https://crt.sh/?q=%.${base}"
    else
      warn "эти имена уже публичны (каждый выпуск серта = запись в CT-логах):"
      echo "$ct" | sed 's/^/      /'
      echo "      Правило: чувствительным именам не выпускать отдельных сертов — только wildcard."
    fi
  fi

  echo; echo -e "${B}— 8. Опт-аут из поисковиков —${N}"
  echo "      Shodan: аккаунт → shodan.io → «Request IP Removal» для $(server_ip4 2>/dev/null)"
  echo "      Censys: search.censys.io → ваш хост → Opt-Out Host"
  echo "      Сначала закрыть дыры (выше), потом опт-аут — иначе ре-скан всё вернёт."
  echo
  log "Аудит только читал — ничего не менял."
  pause
}

# =====================================================================
# ОТКАТ И ДЕМОНТАЖ СТЕКА (п.23)
#   Подменю поэтапного возврата к «плоскому» состоянию:
#     1) открыть порты наружу (панель/подписки/инбаунды)
#     2) правила UFW (снимок / по одному / reset+open)
#     3) службы и интеграции стека
#     4) конфиги и каталоги стека
#     5) удаление nginx (пакет + конфиги)
#     6) полный откат (всё выше, тихо, подтверждение YES)
#   AdGuard Home и серты LE НЕ трогаются — у AdGuard свой пункт (п.14),
#   серты не наши, могут использоваться другими сервисами.
# =====================================================================

# Список служб/интеграций, которые создаёт stack-manager
rb_services_list() {
  printf '%s\n' \
    "stack-heal.timer|таймер автопочинки инбаундов (каждые 2 мин)|/etc/systemd/system/stack-heal.timer|systemd" \
    "stack-heal.service|служба автопочинки (oneshot, запускается таймером)|/etc/systemd/system/stack-heal.service|systemd" \
    "fail2ban jail decoy-login|бан за POST /login к decoy-страницам|/etc/fail2ban/jail.d/decoy-login.local|f2b" \
    "fail2ban filter decoy-login|фильтр для jail decoy-login|/etc/fail2ban/filter.d/decoy-login.conf|f2b" \
    "certbot deploy-hook|рестарт x-ui/nginx/AdGuard после renew сертов|/etc/letsencrypt/renewal-hooks/deploy/stack-cert-mirror.sh|file"
}

# Список конфигов и каталогов стека
rb_configs_list() {
  printf '%s\n' \
    "/etc/nginx/sites-available/stack.conf|основной http-конфиг стека (ACME :80 + панель :4443 + decoy)|file" \
    "/etc/nginx/sites-enabled/stack.conf|симлинк основного конфига|link" \
    "/etc/nginx/streams-available/sni-router.conf|SNI-роутер 443 (map + upstream)|file" \
    "/etc/nginx/streams-enabled/sni-router.conf|симлинк SNI-роутера|link" \
    "/etc/nginx/snippets/decoy-headers.conf|security-заголовки decoy|file" \
    "/etc/logrotate.d/stack-decoy|ротация decoy-логов|file" \
    "/var/www/panel-decoy|decoy-заглушка корня домена панели|dir" \
    "/var/www/decoy-templates|шаблоны decoy (corporate, blog, docs…)|dir" \
    "/var/www/decoy-login|login-шаблоны (adguard, portainer, jellyfin…)|dir"
}

# --- 23.1 Открыть порты наружу (панель/подписки/инбаунды) --------------
rb_open_ports() {
  line; echo -e "${B}   ОТКРЫТЬ ПОРТЫ НАРУЖУ${N}"; line
  echo "  Сейчас панель/подписки/инбаунды живут за SNI-роутером (127.0.0.1)."
  echo "  Здесь — открыть их напрямую на 0.0.0.0 (по каждому пункту спрошу)."
  echo
  [[ -f "$XUI_DB" ]] || { err "x-ui.db не найден"; pause; return 1; }
  auto_backup_stack >/dev/null 2>&1 || true

  local wp wl sp sl
  wp=$(xui_get webPort); wl=$(xui_get webListen)
  sp=$(xui_get subPort); sl=$(xui_get subListen)

  local need_restart=0
  systemctl stop x-ui 2>/dev/null || true

  echo "▸ Панель: bind=${wl:-<пусто>} port=${wp:-?}"
  if [[ -n "$wp" && ( "$wl" == "127.0.0.1" || "$wl" == "::1" || -z "$wl" ) ]]; then
    local go=""
    askyn go "  Открыть панель ($wp) наружу (0.0.0.0)?" "n"
    if [[ "$go" == true ]]; then
      xui_set_setting webListen '0.0.0.0'
      log "  webListen → 0.0.0.0 (панель $wp)"; need_restart=1
      audit "rollback: webListen → 0.0.0.0"
    fi
  else
    [[ -n "$wp" ]] && log "  панель уже слушает ${wl:-0.0.0.0}:$wp" || warn "  webPort не найден"
  fi

  echo
  echo "▸ Подписки: bind=${sl:-<пусто>} port=${sp:-?}"
  if [[ -n "$sp" && ( "$sl" == "127.0.0.1" || "$sl" == "::1" || -z "$sl" ) ]]; then
    local go=""
    askyn go "  Открыть подписки ($sp) наружу (0.0.0.0)?" "n"
    if [[ "$go" == true ]]; then
      xui_set_setting subListen '0.0.0.0'
      log "  subListen → 0.0.0.0 (подписки $sp)"; need_restart=1
      audit "rollback: subListen → 0.0.0.0"
    fi
  else
    [[ -n "$sp" ]] && log "  подписки уже слушают ${sl:-0.0.0.0}:$sp" || warn "  subPort не найден"
  fi

  echo
  echo "▸ Инбаунды:"
  # ВАЖНО: сначала собрать строки, потом спрашивать — иначе read внутри
  # while < <(...) съест следующую строку sqlite как ответ на askyn.
  local -a rows=()
  local _l
  while IFS= read -r _l; do rows+=("$_l"); done < <(sqlite3 -cmd ".timeout 3000" "$XUI_DB" \
    "SELECT id, protocol, port, COALESCE(listen,''), COALESCE(json_extract(stream_settings,'\$.security'),'') FROM inbounds ORDER BY id;" 2>/dev/null || true)

  if [[ ${#rows[@]} -eq 0 ]]; then
    warn "  инбаундов в панели нет"
  else
    local row iid iproto iport ilisten isec note go
    for row in "${rows[@]}"; do
      IFS='|' read -r iid iproto iport ilisten isec <<<"$row"
      [[ -z "$iid" ]] && continue
      note=""
      case "$isec" in
        tls)     note=" [TLS — без nginx серт-пути в settings могут стать недостижимы]" ;;
        reality) note=" [Reality — dest указывает на локальный decoy nginx]" ;;
      esac
      echo "  #$iid $iproto :$iport (bind=${ilisten:-0.0.0.0})$note"
      if [[ "$ilisten" == "127.0.0.1" || "$ilisten" == "::1" ]]; then
        askyn go "    Открыть #$iid наружу?" "n"
        if [[ "$go" == true ]]; then
          sqlite3 -cmd ".timeout 3000" "$XUI_DB" "UPDATE inbounds SET listen='0.0.0.0' WHERE id=$iid;" 2>/dev/null || true
          log "    #$iid listen → 0.0.0.0"; need_restart=1
          audit "rollback: inbound #$iid listen → 0.0.0.0"
        fi
      else
        echo "    уже слушает наружу"
      fi
    done
  fi

  systemctl start x-ui 2>/dev/null || true
  [[ "$need_restart" == 1 ]] && log "x-ui перезапущен — новые bind'ы применены"
  pause
}

# --- 23.2 Правила UFW -------------------------------------------------
rb_firewall() {
  line; echo -e "${B}   ПРАВИЛА ФАЙРВОЛА (UFW)${N}"; line
  if ! command -v ufw >/dev/null 2>&1; then
    warn "UFW не установлен — чистить нечего"; pause; return 0
  fi
  echo "  Статус: $(ufw status 2>/dev/null | head -1)"
  echo
  ufw status numbered 2>/dev/null | sed 's/^/    /'
  echo

  if [[ -f "$FW_STATE_DIR/saved" ]]; then
    log "Есть снимок состояния UFW: $FW_STATE_DIR/saved"
    local rs=""
    askyn rs "Восстановить из снимка (отменит все правила, добавленные стеком)?" "y"
    if [[ "$rs" == true ]]; then
      restore_firewall_state
      audit "rollback: UFW восстановлен из снимка"
      return 0
    fi
  fi

  echo "  1) Пройти по каждому правилу (оставить/удалить)"
  echo "  2) Reset UFW (default deny) + открыть всё слушающееся"
  echo "  0) Отмена"
  line
  local c=""
  read -rp "$(echo -e "${B}Выбор:${N} ")" c || c="0"
  case "$c" in
    1)
      # Собираем номера правил, потом спрашиваем — иначе read внутри
      # while < <(...) съест следующую строку ufw как ответ.
      local -a nums=()
      local _n
      while IFS= read -r _n; do nums+=("$_n"); done < <(
        ufw status numbered 2>/dev/null | grep -oE '^\[[[:space:]]*[0-9]+\]' | grep -oE '[0-9]+' | sort -rn
      )
      local -a to_del=()
      local n rule del
      for n in "${nums[@]}"; do
        rule=$(ufw status numbered 2>/dev/null | grep -E "^\[[[:space:]]*$n\]" || true)
        [[ -z "$rule" ]] && continue
        echo "  $rule"
        askyn del "    Удалить это правило?" "n"
        [[ "$del" == true ]] && to_del+=("$n")
      done
      local deleted=0
      for n in "${to_del[@]}"; do
        if ufw --force delete "$n" >/dev/null 2>&1; then
          log "  правило $n удалено"; deleted=$((deleted+1))
        else
          warn "  правило $n не удалилось"
        fi
      done
      [[ "$deleted" -eq 0 ]] && log "Ничего не удалено."
      audit "rollback: UFW удалено правил: $deleted"
      ;;
    2)
      local go=""
      askyn go "Сбросить UFW (default deny + открыть всё слушающееся)?" "n"
      [[ "$go" == true ]] || { pause; return 0; }
      save_firewall_state
      ufw --force reset >/dev/null 2>&1 || true
      ufw default deny incoming >/dev/null 2>&1 || true
      ufw default allow outgoing >/dev/null 2>&1 || true
      fw_allow "${SSH_PORT:-22}" tcp "SSH"
      local p
      for p in $(ss -tln 2>/dev/null | awk 'NR>1 { if ($4 ~ /^127\./ || $4 ~ /^\[::1\]/) next; split($4,a,":"); print a[length(a)] }' | sort -un); do
        [[ -n "$p" && "$p" != "${SSH_PORT:-22}" ]] && fw_allow "$p" tcp "rollback-open"
      done
      for p in $(ss -uln 2>/dev/null | awk 'NR>1 { if ($4 ~ /^127\./ || $4 ~ /^\[::1\]/) next; if ($5 != "*:*") next; split($4,a,":"); print a[length(a)] }' | sort -un); do
        [[ -n "$p" ]] && fw_allow "$p" udp "rollback-open"
      done
      ufw --force enable >/dev/null 2>&1 || true
      log "UFW: reset + открыто всё слушающееся"
      audit "rollback: UFW reset + open listening"
      ;;
    *) pause; return 0 ;;
  esac
  pause
}

# --- 23.3 Службы и интеграции -----------------------------------------
rb_services() {
  line; echo -e "${B}   СЛУЖБЫ И ИНТЕГРАЦИИ СТЕКА${N}"; line
  local -a items=()
  local _l
  while IFS= read -r _l; do items+=("$_l"); done < <(rb_services_list)

  local found=0 name desc path typ exists unit c
  local item
  for item in "${items[@]}"; do
    IFS='|' read -r name desc path typ <<<"$item"
    [[ -z "$name" ]] && continue
    exists=false
    [[ -e "$path" ]] && exists=true
    [[ "$exists" != true ]] && continue
    found=$((found+1))
    echo "  ─ $name"
    echo "    $desc"
    echo "    файл: $path"
    echo "      1) Удалить   2) Отключить (файл оставить)   3) Отмена"
    c=""
    ask c "    Выбор" "3" '^[123]$'
    case "$c" in
      1)
        case "$typ" in
          systemd)
            unit=$(basename "$path")
            systemctl disable --now "$unit" >/dev/null 2>&1 || true
            rm -f "$path" 2>/dev/null || true
            systemctl daemon-reload >/dev/null 2>&1 || true
            ;;
          f2b)
            rm -f "$path" 2>/dev/null || true
            systemctl restart fail2ban >/dev/null 2>&1 || true
            ;;
          file)
            rm -f "$path" 2>/dev/null || true
            ;;
        esac
        log "    удалено"; audit "rollback: удалено — $name"
        ;;
      2)
        case "$typ" in
          systemd)
            unit=$(basename "$path")
            systemctl disable --now "$unit" >/dev/null 2>&1 || true
            ;;
          f2b)
            sed -i -E 's/^enabled[[:space:]]*=.*/enabled  = false/' "$path" 2>/dev/null || true
            systemctl restart fail2ban >/dev/null 2>&1 || true
            ;;
          file)
            chmod -x "$path" 2>/dev/null || true
            ;;
        esac
        log "    отключено (файл на месте)"; audit "rollback: отключено — $name"
        ;;
    esac
  done
  [[ "$found" -eq 0 ]] && log "Служб/интеграций стека не найдено — чистить нечего."
  pause
}

# --- 23.4 Конфиги и каталоги ------------------------------------------
rb_configs() {
  line; echo -e "${B}   КОНФИГИ И КАТАЛОГИ СТЕКА${N}"; line
  local -a items=()
  local _l
  while IFS= read -r _l; do items+=("$_l"); done < <(rb_configs_list)

  local found=0 path desc typ exists go
  local item
  for item in "${items[@]}"; do
    IFS='|' read -r path desc typ <<<"$item"
    [[ -z "$path" ]] && continue
    exists=false
    case "$typ" in
      file|link) [[ -e "$path" ]] && exists=true ;;
      dir)       [[ -d "$path" ]] && exists=true ;;
    esac
    [[ "$exists" != true ]] && continue
    found=$((found+1))
    echo "  ─ $path"
    echo "    $desc"
    askyn go "    Удалить?" "n"
    if [[ "$go" == true ]]; then
      case "$typ" in
        dir) rm -rf "$path" ;;
        *)   rm -f "$path" ;;
      esac
      log "    удалено"; audit "rollback: удалено — $path"
    fi
  done

  # per-inbound decoy-каталоги
  local -a decoy_dirs=()
  local d
  for d in /var/www/decoy-*; do
    [[ -d "$d" ]] && decoy_dirs+=("$d")
  done
  for d in "${decoy_dirs[@]}"; do
    found=$((found+1))
    echo "  ─ $d"
    echo "    decoy-заглушка инбаунда"
    askyn go "    Удалить?" "n"
    if [[ "$go" == true ]]; then
      rm -rf "$d"; log "    удалено"; audit "rollback: удалено — $d"
    fi
  done

  [[ "$found" -eq 0 ]] && log "Конфигов/каталогов стека не найдено."
  nginx -t >/dev/null 2>&1 && nginx_reload >/dev/null 2>&1 || true
  pause
}

# --- 23.5 Удаление nginx ----------------------------------------------
rb_remove_nginx() {
  line; echo -e "${B}   УДАЛЕНИЕ NGINX${N}"; line
  command -v nginx >/dev/null 2>&1 || { warn "nginx не установлен — нечего удалять"; pause; return 0; }
  echo "  ${R}ВНИМАНИЕ:${N} без nginx стек работать НЕ БУДЕТ как SNI-роутер."
  echo "  • Панель/подписки/инбаунды сейчас на 127.0.0.1 — станут недоступны снаружи,"
  echo "    пока не откроешь их через п.23 → 1 (Открыть порты наружу)."
  echo "  • Серты на :443 перестанут отдаваться; decoy-страницы; DoH AdGuard."
  echo "  • Конфиги /etc/nginx будут удалены пакетом (это же делает apt purge)."
  echo
  local go=""
  askyn go "Удалить nginx (пакет + конфиги + сервис)?" "n"
  [[ "$go" == true ]] || { pause; return 0; }
  local sure=""
  ask sure "Для подтверждения введи YES" "" '^YES$'
  [[ "$sure" == "YES" ]] || { log "Отменено"; pause; return 0; }
  audit "rollback: удаление nginx (purge)"
  systemctl stop nginx 2>/dev/null || true
  systemctl disable nginx 2>/dev/null || true
  DEBIAN_FRONTEND=noninteractive apt-get purge -y nginx nginx-common nginx-full libnginx-mod-stream >/dev/null 2>&1 || true
  apt-get autoremove -y >/dev/null 2>&1 || true
  rm -rf /etc/nginx /var/log/nginx 2>/dev/null || true
  log "nginx удалён (пакет + /etc/nginx + /var/log/nginx)"
  pause
}

# --- 23.6 Полный откат (тихо) -----------------------------------------
rb_full_rollback() {
  line; echo -e "${R}   ПОЛНЫЙ ОТКАТ СТЕКА${N}"; line
  echo "  Будет выполнено (без вопросов, по шагам):"
  echo "    1) Бэкап x-ui.db и nginx-конфигов стека"
  echo "    2) Удаление служб и интеграций (stack-heal, decoy-login jail, certbot hook)"
  echo "    3) Удаление конфигов и каталогов стека"
  echo "    4) Открытие панели/подписок/инбаундов наружу (0.0.0.0)"
  echo "    5) UFW: восстановление из снимка (если есть), иначе reset + открытие слушающегося"
  echo "    6) Удаление nginx (пакет + конфиги)"
  echo
  echo "  ${G}НЕ трогается:${N} AdGuard Home, серты Let's Encrypt в /etc/letsencrypt/live/, x-ui.db."
  echo
  local sure=""
  ask sure "Для подтверждения введи YES" "" '^YES$'
  [[ "$sure" == "YES" ]] || { log "Отменено"; pause; return 0; }
  audit "rollback: ПОЛНЫЙ ОТКАТ СТЕКА (silent)"

  log "[1/6] Бэкап…"
  auto_backup_stack >/dev/null 2>&1 || true

  log "[2/6] Службы и интеграции…"
  uninstall_heal_timer >/dev/null 2>&1 || true
  rm -f /etc/fail2ban/jail.d/decoy-login.local /etc/fail2ban/filter.d/decoy-login.conf 2>/dev/null || true
  rm -f /etc/letsencrypt/renewal-hooks/deploy/stack-cert-mirror.sh 2>/dev/null || true
  systemctl restart fail2ban >/dev/null 2>&1 || true

  log "[3/6] Конфиги и каталоги стека…"
  rm -f /etc/nginx/sites-enabled/stack.conf /etc/nginx/sites-available/stack.conf 2>/dev/null || true
  rm -f /etc/nginx/streams-enabled/sni-router.conf /etc/nginx/streams-available/sni-router.conf 2>/dev/null || true
  rm -f /etc/nginx/snippets/decoy-headers.conf /etc/logrotate.d/stack-decoy 2>/dev/null || true
  rm -rf /var/www/panel-decoy /var/www/decoy-templates /var/www/decoy-login 2>/dev/null || true
  rm -rf /var/www/decoy-* 2>/dev/null || true

  log "[4/6] Открытие портов наружу…"
  systemctl stop x-ui 2>/dev/null || true
  xui_set_setting webListen '0.0.0.0'
  xui_set_setting subListen '0.0.0.0'
  sqlite3 -cmd ".timeout 3000" "$XUI_DB" \
    "UPDATE inbounds SET listen='0.0.0.0' WHERE COALESCE(listen,'') IN ('127.0.0.1','::1');" 2>/dev/null || true
  systemctl start x-ui 2>/dev/null || true

  log "[5/6] UFW…"
  # в полном откате действуем тихо: если снимок есть — восстанавливаем его логику
  # без интерактивного запроса (restore_firewall_state спрашивает — обходим)
  if [[ -f "$FW_STATE_DIR/saved" ]]; then
    . "$FW_STATE_DIR/state" 2>/dev/null || true
    [[ -f "$FW_STATE_DIR/iptables.v4" ]] && iptables-restore  < "$FW_STATE_DIR/iptables.v4"  2>/dev/null || true
    [[ -f "$FW_STATE_DIR/iptables.v6" ]] && ip6tables-restore < "$FW_STATE_DIR/iptables.v6"  2>/dev/null || true
    if [[ "${UFW_WAS_INSTALLED:-0}" == "1" && -f "$FW_STATE_DIR/ufw-config.tar" ]]; then
      tar -xpf "$FW_STATE_DIR/ufw-config.tar" -C / 2>/dev/null || true
      [[ "${UFW_WAS_ACTIVE:-0}" == "1" ]] && ufw --force enable >/dev/null 2>&1 || ufw --force disable >/dev/null 2>&1
    fi
    rm -f "$FW_STATE_DIR/saved"
    log "  восстановлено из снимка $FW_STATE_DIR (тихо)"
  else
    save_firewall_state >/dev/null 2>&1 || true
    ufw --force reset >/dev/null 2>&1 || true
    ufw default deny incoming >/dev/null 2>&1 || true
    ufw default allow outgoing >/dev/null 2>&1 || true
    fw_allow "${SSH_PORT:-22}" tcp "SSH"
    local p
    for p in $(ss -tln 2>/dev/null | awk 'NR>1 { if ($4 ~ /^127\./ || $4 ~ /^\[::1\]/) next; split($4,a,":"); print a[length(a)] }' | sort -un); do
      [[ -n "$p" && "$p" != "${SSH_PORT:-22}" ]] && fw_allow "$p" tcp "rollback-open"
    done
    for p in $(ss -uln 2>/dev/null | awk 'NR>1 { if ($4 ~ /^127\./ || $4 ~ /^\[::1\]/) next; if ($5 != "*:*") next; split($4,a,":"); print a[length(a)] }' | sort -un); do
      [[ -n "$p" ]] && fw_allow "$p" udp "rollback-open"
    done
    ufw --force enable >/dev/null 2>&1 || true
    log "  reset + открыто всё слушающееся"
  fi

  log "[6/6] Удаление nginx…"
  systemctl stop nginx 2>/dev/null || true
  systemctl disable nginx 2>/dev/null || true
  DEBIAN_FRONTEND=noninteractive apt-get purge -y nginx nginx-common nginx-full libnginx-mod-stream >/dev/null 2>&1 || true
  apt-get autoremove -y >/dev/null 2>&1 || true
  rm -rf /etc/nginx /var/log/nginx 2>/dev/null || true

  line
  log "ПОЛНЫЙ ОТКАТ ЗАВЕРШЁН"
  line
  local wp
  wp=$(xui_get webPort 2>/dev/null || echo '?')
  echo "  Панель:  http://$(server_ip4):$wp"
  echo "  Серты:   сохранены (/etc/letsencrypt/live/)"
  echo "  AdGuard: не трогался"
  echo "  Бэкап:   $BACKUP_DIR/auto-*"
  line
  pause
}

# --- Подменю отката ---------------------------------------------------
rollback_menu() {
  while :; do
    clear
    line; echo -e "${B}   ОТКАТ И ДЕМОНТАЖ СТЕКА${N}"; line
    local heal="нет" jail="нет" hook="нет" ngx="нет" sni="нет" snap="нет"
    systemctl list-unit-files 2>/dev/null | grep -q '^stack-heal\.' && heal="да"
    [[ -f /etc/fail2ban/jail.d/decoy-login.local ]] && jail="да"
    [[ -x /etc/letsencrypt/renewal-hooks/deploy/stack-cert-mirror.sh ]] && hook="да"
    command -v nginx >/dev/null 2>&1 && ngx="да"
    [[ -f /etc/nginx/streams-available/sni-router.conf ]] && sni="да"
    [[ -f "$FW_STATE_DIR/saved" ]] && snap="да"
    echo "  Текущее состояние стека:"
    printf "    nginx:                 %s\n" "$ngx"
    printf "    SNI-роутер (443):      %s\n" "$sni"
    printf "    stack-heal:            %s\n" "$heal"
    printf "    fail2ban decoy-jail:   %s\n" "$jail"
    printf "    certbot deploy-hook:   %s\n" "$hook"
    printf "    снимок UFW:            %s\n" "$snap"
    echo
    line
    echo "  1) 🌐 Открыть порты наружу (панель / подписки / инбаунды)"
    echo "  2) 🚧 Правила файервола (UFW)"
    echo "  3) 🛠️  Службы и интеграции стека"
    echo "  4) 📁 Конфиги и каталоги стека"
    echo "  5) 🗑️  Удалить nginx (пакет + конфиги)"
    echo "  6) 💣 ПОЛНЫЙ ОТКАТ (всё выше, тихо, подтверждение YES)"
    echo "  0) Назад"
    line
    local c=""
    read -rp "$(echo -e "${B}Выбор:${N} ")" c || c="0"
    case "$c" in
      1) rb_open_ports ;;
      2) rb_firewall ;;
      3) rb_services ;;
      4) rb_configs ;;
      5) rb_remove_nginx ;;
      6) rb_full_rollback ;;
      0) return 0 ;;
      *) sleep 1 ;;
    esac
  done
}


# --- Подменю 24: pre-install snapshot ---------------------------------
preinstall_menu() {
  while :; do
    clear
    line; echo -e "${B}   PRE-INSTALL СНИМОК СОСТОЯНИЯ${N}"; line
    local cnt
    cnt=$(ls -1d "$BACKUP_DIR"/pre-install-* 2>/dev/null | grep -v "\.tar\.gz$" | wc -l)
    echo "  Снимков в $BACKUP_DIR/pre-install-*: $cnt"
    echo
    echo "  Что сохраняется:"
    echo "    x-ui.db, /etc/x-ui, /etc/nginx/*, правила UFW/iptables, /etc/fail2ban,"
    echo "    systemd units стека, /etc/letsencrypt/renewal+hooks, logrotate, AdGuardHome.yaml"
    echo
    line
    echo "  1) 📸 Сделать новый снимок сейчас"
    echo "  2) ♻️  Восстановить из снимка (перезапишет текущее состояние)"
    echo "  3) 🗑️  Удалить старый снимок"
    echo "  0) Назад"
    line
    local c=""
    read -rp "$(echo -e "${B}Выбор:${N} ")" c || c="0"
    case "$c" in
      1) take_pre_install_snapshot; pause ;;
      2) restore_pre_install_snapshot ;;
      3)
        local snaps
        snaps=$(ls -1dt "$BACKUP_DIR"/pre-install-* 2>/dev/null | grep -v "\.tar\.gz$" | head -20)
        [[ -z "$snaps" ]] && { warn "Снимков нет"; pause; continue; }
        local i=1 d
        while IFS= read -r d; do
          [[ -z "$d" ]] && continue
          printf "  %2d) %s\n" "$i" "$(basename "$d")"
          i=$((i+1))
        done <<<"$snaps"
        local pick=""; ask pick "Номер (0 — отмена)" "0" '^[0-9]+$'
        [[ "$pick" == "0" ]] && continue
        local ch
        ch=$(printf '%s\n' "$snaps" | sed -n "${pick}p")
        [[ -z "$ch" ]] && { err "Нет такого"; pause; continue; }
        local sure=""; askyn sure "Удалить $(basename "$ch") и его .tar.gz?" "n"
        [[ "$sure" == true ]] && { rm -rf "$ch" "$ch.tar.gz" 2>/dev/null; log "Удалено"; }
        pause
        ;;
      0) return 0 ;;
      *) sleep 1 ;;
    esac
  done
}

# Действие пункта меню — вызывается в ПОД-ОБОЛОЧКЕ: exit 42 внутри (токен «q»
# в любом вопросе) гасит только её, и мы оказываемся назад в меню.
run_menu_action() {
  audit "menu:${1:-}"     # каждое обращение к пункту — в журнал действий
  case "$1" in
    1) initial_setup ;;
    2) add_inbound; pause ;;
    3) remove_inbound; pause ;;
    4) change_decoy ;;
    5) view_decoy_templates ;;
    6) show_status ;;
    7) security_menu ;;
    8) backup_config ;;
    9) restore_config ;;
    10) certs_menu ;;
    11) firewall_menu ;;
    12) restore_firewall_state ;;
    13) panel_manage; pause ;;
    14) adguard_manage; pause ;;
    15) sni_cleanup_stale; pause ;;
    16) change_admin_passwords; pause ;;
    17) update_self; pause ;;
    18) stack_doctor_menu; pause ;;
    19) inbounds_live; pause ;;
    20) inbound_change_domain ;;
    21) nginx_hygiene ;;
    22) stealth_audit ;;
    23) rollback_menu ;;
    24) preinstall_menu ;;
    25) freeze_menu ;;
    *) warn "Нет такого пункта"; sleep 1 ;;
  esac
}

# ─── Стиль меню: боксы со счётчиками (как RKN-GUARD) ─────────────────
# Рамки с эмодзи считает python3 (unicodedata): под LC_ALL=C баш итерирует
# строку по БАЙТАМ и ломает выравнивание, поэтому ширина — не его работа.
svc_dot() { systemctl is-active --quiet "$1" 2>/dev/null && echo "🟢" || echo "🔴"; }
menu_header() { # <ngx> <xui> <adg> <f2b> <ufw_ok> <nb> <att> <bans> <amin> <duse> <db> <mtime>
  python3 - "$@" <<'PYHDR'
import sys, unicodedata, re
G,R,Y,B,D,N = "\033[0;32m","\033[0;31m","\033[1;33m","\033[0;36m","\033[90m","\033[0m"
ngx,xui,adg,f2b,ufw_ok,nb,att,bans,amin,duse,db,mtime = sys.argv[1:13]
def w(s):
    s = re.sub(r"\x1b\[[0-9;]*m", "", s)          # ANSI-коды не видны — не ширина
    total, prev = 0, 0
    for ch in s:
        total += wch(ord(ch), prev)
        prev = ord(ch)
    return total
def wch(cp, prev):
    if cp == 0xFE0F:
        return 1 if 0x2B00 <= prev <= 0x2BFF else 0   # ⬇️/➡️ становятся широкими
    if cp == 0x200D:
        return 0
    wide = unicodedata.east_asian_width(chr(cp)) in ('W','F') \
        or 0x1F000 <= cp <= 0x1FAFF or 0x2600 <= cp <= 0x27BF
    return 2 if wide else 1
def line(s, W):
    return "│" + s + " " * max(W - w(s), 0) + "│"
def center(s, W):
    pad = max(W - w(s), 0); l = pad // 2
    return "│" + " " * l + s + " " * (pad - l) + "│"
W = 58
dot = lambda v: "🟢" if v == "1" else "🔴"
cs = "—" if amin == "—" else (f"{R}{amin} дн{N}" if amin.isdigit() and int(amin) < 14 else f"{amin} дн")
print(f"{B}╔{'═'*W}╗{N}")
print(f"{B}{center('STACK MANAGER', W)}{N}")
print(f"{B}{center('SNI-роутер · LucX/x-ui · AdGuard · decoy', W)}{N}")
print(f"{B}╚{'═'*W}╝{N}")
print(f"{B}┌{'─'*W}┐{N}")
print(line(f"{dot(ngx)} nginx  {dot(xui)} x-ui  {adg} AdGuard  {dot(f2b)} f2b", W))
print(line(f"👥 инбаунды: {G}{nb}{N}   🔥 decoy-хиты: {Y}{att}{N}   ⛔ баны: {R}{bans}{N}", W))
print(line(f"🔒 серты: мин. {cs}   💾 диск: {duse}%   📁 {db}", W))
ufw = f"🚧 UFW {G}active{N}" if ufw_ok == "1" else f"🚧 UFW {R}down{N}"
print(line(f"{ufw}   🩺 самодиагностика — п.18", W))
print(f"{B}└{'─'*W}┘{N}")
print(f"{D}  └─ ◆ stack-manager · правка: {mtime}{N}")
PYHDR
}

# =====================================================================
# П.25 ЗАМОРОЗКА САМОЛЕЧЕНИЯ
#   Файл /root/stack-frozen.txt: cert:<domain> / inbound:<id> / ALL-CERTS.
#   Heal-таймер и авто-выпуск сертов пропускают замороженное молча.
#   Ручные действия через меню НЕ блокируются.
# =====================================================================
freeze_menu() {
  line; echo -e "${B}   ЗАМОРОЗКА САМОЛЕЧЕНИЯ${N}"; line
  echo "  Автопочинка (stack-heal, 2 мин) и авто-выпуск сертов НЕ трогают то,"
  echo "  что заморожено здесь. Ручные действия через меню работают как раньше."
  echo
  if [[ -s "$FROZEN_FILE" ]]; then
    echo -e "  ${B}Заморожено:${N}"
    sed 's/^/    • /' "$FROZEN_FILE"
  else
    echo "  Замороженного нет — самолечение работает по всему стеку."
  fi
  echo
  echo "   1) Заморозить инбаунд (не трогать его серты/decoy/hosts)"
  echo "   2) Заморозить серт домена (не выпускать и не перевыпускать)"
  echo "   3) ALL-CERTS: заморозить/разморозить ВСЕ сертификаты"
  echo "   4) Разморозить строку"
  echo "   0) Назад"
  line
  local a=""; ask a "Выбор" "0" '^[0-9]+$'
  case "$a" in
    1)
      [[ -f "$XUI_DB" ]] || { err "x-ui.db не найден"; pause; return 1; }
      sqlite3 -header -column "$XUI_DB" "SELECT id, protocol, port, remark FROM inbounds WHERE enable=1 AND port>0 ORDER BY id;" 2>/dev/null | sed 's/^/    /'
      local id=""; ask id "ID инбаунда" "" '^[0-9]+$'
      [[ -z "$id" ]] && return 0
      if frozen "inbound:$id"; then warn "inbound:$id уже заморожен"; else
        printf 'inbound:%s\n' "$id" >> "$FROZEN_FILE" 2>/dev/null || { err "не могу писать $FROZEN_FILE"; pause; return 1; }
        log "Заморожено: inbound:$id"
      fi
      ;;
    2)
      local d=""; ask d "Домен серта" "" '^[a-zA-Z0-9.-]+$'
      [[ -z "$d" ]] && return 0
      if frozen "cert:$d"; then warn "cert:$d уже заморожен"; else
        printf 'cert:%s\n' "$d" >> "$FROZEN_FILE" 2>/dev/null || { err "не могу писать $FROZEN_FILE"; pause; return 1; }
        log "Заморожено: cert:$d (авто-выпуск пропускает)"
      fi
      ;;
    3)
      touch "$FROZEN_FILE" 2>/dev/null || { err "не могу писать $FROZEN_FILE"; pause; return 1; }
      if grep -qxF 'ALL-CERTS' "$FROZEN_FILE"; then
        sed -i '/^ALL-CERTS$/d' "$FROZEN_FILE"; log "ALL-CERTS разморожен"
      else
        printf 'ALL-CERTS\n' >> "$FROZEN_FILE"; log "ALL-CERTS заморожен — авто-выпуск сертов выключен"
      fi
      ;;
    4)
      [[ -s "$FROZEN_FILE" ]] || { warn "Замороженного нет"; pause; return 0; }
      local ln=""; nl -ba "$FROZEN_FILE" | sed 's/^/    /'
      ask ln "Номер строки для разморозки" "" '^[0-9]+$'
      [[ -z "$ln" ]] && return 0
      sed -i "${ln}d" "$FROZEN_FILE" 2>/dev/null && log "Разморожено (строка $ln)"
      ;;
    *) return 0 ;;
  esac
  pause
}

main_menu() {
  decoy_full_init || true
  local W=58
  while :; do
    clear
    detect_env >/dev/null 2>&1 || true     # состояние для шапки
    local adg_dot="➖" nb att bans amin="" cd crt duse ufw_ok
    [[ "$ADG_PRESENT" == true && -n "$ADG_SERVICE" ]] && adg_dot=$(svc_dot "$ADG_SERVICE")
    ufw_ok=0; ufw_is_active && ufw_ok=1
    nb=$(sqlite3 -cmd ".timeout 3000" "$XUI_DB" "SELECT COUNT(*) FROM inbounds WHERE enable=1;" 2>/dev/null || echo 0)
    att=$(tail -n 20000 "$DECOY_LOG_ACCESS" 2>/dev/null | grep -c "$(date +%d/%b/%Y)" 2>/dev/null); att=${att:-0}
    # баны по ВСЕМ jail'ам (decoy-login + sshd + recidive…), не только decoy
    bans=0
    for j in $(fail2ban-client status 2>/dev/null | sed -n 's/^.*Jail list:\s*//p' | tr ',' ' '); do
      n=$(fail2ban-client get "$j" banip 2>/dev/null | wc -w)
      bans=$((bans + ${n:-0}))
    done
    for crt in /etc/letsencrypt/live/*/fullchain.pem; do
      [[ -f "$crt" ]] || continue
      cd=$(( ($(date -d "$(openssl x509 -enddate -noout -in "$crt" 2>/dev/null | cut -d= -f2)" +%s 2>/dev/null || echo 0) - $(date +%s)) / 86400 ))
      [[ -z "$amin" || "$cd" -lt "$amin" ]] && amin=$cd
    done
    amin=${amin:-—}
    duse=$(df -Pm / 2>/dev/null | awk 'NR==2{print $5}' | tr -d '%')
    menu_header "$(svc_dot nginx)" "$(svc_dot x-ui)" "$adg_dot" "$(svc_dot fail2ban)" \
      "$ufw_ok" "${nb:-0}" "${att:-0}" "${bans:-0}" "$amin" "${duse:-?}" \
      "$(basename "${XUI_DB:-нет}")" "$(date -r "$0" '+%d.%m.%y %H:%M')"
    echo
    echo -e "  ${B} 1)${N} 🧭 Первичная настройка SNI-роутера"
    echo -e "  ${B} 2)${N} ➕ Добавить / проверить inbound"
    echo -e "  ${B} 3)${N} 🗑️  Удалить inbound"
    echo -e "  ${B} 4)${N} 🎭 Сменить decoy для SNI-домена"
    echo -e "  ${B} 5)${N} 🖼️  Каталог decoy-шаблонов"
    echo -e "  ${B} 6)${N} 📊 Показать статус"
    echo -e "  ${B} 7)${N} 🛡️  Безопасность: баны, деко-логины, fail2ban"
    echo -e "  ${B} 8)${N} 💾 Бэкап конфигурации"
    echo -e "  ${B} 9)${N} ♻️  Восстановить из бэкапа"
    echo -e "  ${B}10)${N} 🔒 Управление сертификатами"
    echo -e "  ${B}11)${N} 🚧 Файрвол: только нужные порты"
    echo -e "  ${B}12)${N} 🧯 Восстановить состояние фаервола"
    echo -e "  ${B}13)${N} 📥 Панель LucX UI: установить / удалить"
    echo -e "  ${B}14)${N} 🛰️  AdGuard Home: установить / удалить"
    echo -e "  ${B}15)${N} 🧹 Очистка SNI: записи без инбаундов"
    echo -e "  ${B}16)${N} 🔑 Сменить пароли admin (панель / AdGuard)"
    echo -e "  ${B}17)${N} ⬇️  Обновить скрипт с GitHub"
    echo -e "  ${B}18)${N} 🩺 Самодиагностика (проверка стека)"
    echo -e "  ${B}19)${N} 📡 Инбаунды: live-таблица"
    echo -e "  ${B}20)${N} 🔀 Сменить домен инбаунда (без пересоздания)"
    echo -e "  ${B}21)${N} 🧽 Гигиена nginx (server_tokens, заголовки, логи)"
    echo -e "  ${B}22)${N} 🕶 Стелс-аудит (глазами Shodan/Censys)"
    echo -e "  ${B}23)${N} 💣 Откат и демонтаж стека"
    echo -e "  ${B}24)${N} 📸 Pre-install снимок (состояние до скрипта)"
    echo -e "  ${B}25)${N} ❄️  Заморозка самолечения (серты/инбаунды от автоматики)"
    echo
    echo -e "  ${B} 0)${N} 🚪 Выход   ${Y}(q в любом вопросе — выход в меню)${N}"
    line
    local c="" rc
    read -rp "$(echo -e "${Y}👉${N} Ваш выбор: ")" c || c="0"
    case "$c" in
      0) exit 0 ;;
      q|quit|exit|выход) exit 0 ;;
      *) ( run_menu_action "$c" )
         rc=$?
         if [[ $rc -eq 42 ]]; then warn "Возврат в меню"; sleep 1
         elif [[ $rc -ne 0 ]]; then warn "Пункт завершился с ошибкой (код $rc)"; sleep 1; fi ;;
    esac
  done
}

# =====================================================================
# ПОЛНЫЙ АВТОПОДЪЁМ ПОСЛЕ ЧИСТОЙ УСТАНОВКИ ПАНЕЛИ
# (инбаунды → initial_setup → UFW → итоговая сводка)
# =====================================================================
auto_full_setup() {
  local base="${PANEL_DOMAIN:-$(xui_get webDomain 2>/dev/null || true)}"
  [[ -z "$base" || "$base" == "panel.example.com" ]] && { err "Домен панели неизвестен — автоподъём пропущен"; return 1; }
  detect_env
  line; echo -e "${B}   АВТОПОДЪЁМ СТЕКА (чистая установка)${N}"; line

  # --- 1+2+3) ЕДИНЫЙ путь вопросов: панель → AdGuard → заглушка панели
  ask_panel_creds || return 1
  local u_port="$U_PANEL_PORT" u_subport="$U_SUB_PORT" u_path="$U_PANEL_PATH" u_subpath="$U_SUB_PATH"
  ask_adguard_and_decoy
  local pdecoy="$PDECOY"

  # --- 4) ИНБАУНДЫ: какие ставить? (Enter — весь набор)
  echo -e "${B}Выберите инбаунды для установки:${N}"
  local i=1 entry
  local -a CAND=()
  for entry in "${RECOMMENDED_INBOUNDS[@]}"; do
    printf "  %2d) %s\n" "$i" "${entry%%|*}"
    CAND+=("$entry"); i=$((i+1))
  done
  echo
  echo "  Enter — установить ВСЕ"
  local choices=""
  ask choices "Номера (через пробел)" "" '^[0-9 ]*$'
  local -a SEL=()
  local num
  if [[ -z "$choices" ]]; then
    SEL=("${CAND[@]}")
  else
    for num in $choices; do
      (( num >= 1 && num <= ${#CAND[@]} )) && SEL+=("${CAND[$((num-1))]}") || warn "Пропуск: $num"
    done
  fi
  [[ ${#SEL[@]} -eq 0 ]] && { warn "Ничего не выбрано — инбаунды не создаются"; }
  local have_qwdtt=false
  for entry in "${SEL[@]}"; do
    [[ "$entry" == *"|qwdtt|"* || "$entry" == *"|csqtt|"* ]] && have_qwdtt=true
  done

  # --- 2) VK call hashes (если выбраны qwdtt/csqtt); Enter — создать без них
  local vk=""
  if [[ "$have_qwdtt" == true ]]; then
    ask vk "VK call hashes для qwdtt/csqtt (через запятую, БЕЗ пробелов; Enter — пропустить)" "" '^[a-zA-Z0-9,_-]*$'
  fi

  # --- 2b) Тип сертификатов — ЕДИНАЯ ветка установки. Тип влияет только на
  #         ВЫПУСК (один wildcard vs персональные на каждый домен), порядок
  #         вопросов одинаковый. Выбор запоминается: cert_issue не переспрашивает.
  if [[ -z "${CERT_MODE_CHOICE:-}" ]]; then
    if [[ -t 0 ]]; then
      echo "  Сертификаты:"
      echo "   1) Wildcard Cloudflare — один серт на $base и все поддомены (нужен API-токен)"
      echo "   2) Персональные — отдельный серт на каждый домен (HTTP-01)"
      local cm=""
      ask cm "Выбор [1/2]" "2" '^[12]$'
      [[ "$cm" == "1" ]] && CERT_MODE_CHOICE="wildcard" || CERT_MODE_CHOICE="personal"
    else
      CERT_MODE_CHOICE="personal"
    fi
  fi
  log "Тип сертификатов: ${CERT_MODE_CHOICE}"

  # --- 3) SNI-домены для TLS-инбаундов (Enter — префикс по умолчанию)
  local -A PREFIX=( [vless-tcp]="r" [vless-xhttp]="rx" [naive-naive]="n" [anytls-anytls]="at" [trusttunnel-trusttunnel]="tt" [hysteria-hysteria]="h" )
  local -A SELDOM=()
  # --- 4c) Reality-вопросы (режим → цель/домен → порт → заглушка) задаются
  #         в цикле создания — по каждому инбаунду, на его месте в очереди.
  REALITY_EXT=false
  local -A REALITY_MODE=() REALITY_TGT=() REALITY_DECOY_TPL_BYID=()

  # (tg-домен спрашивается в цикле создания — на месте самого tg-инбаунда)

  # (пароль панели и порты/пути спрашиваются в начале — шаг 1)
  # (отдельный цикл доменов убран: домен спрашивается в цикле создания
  #  перед портом — «SNI → порт → следующий инбаунд»)
  # (decoy-шаблон для reality спрашивается ПО КАЖДОМУ инбаунду в цикле создания)

  # --- 5) Создание выбранных инбаундов. Порядок вопросов на КАЖДЫЙ инбаунд:
  #        reality: свой/чужой → (цель | SNI-домен) → порт → заглушка (свой SNI)
  #        TLS:     SNI-домен → серт (есть/выпуск) → порт
  log "Создание инбаундов…"
  local -A A_DOM=()
  local -a used_ports=()
  local new_id=""
  for entry in "${SEL[@]}"; do
    IFS='|' read -r name proto transport security flow net <<<"$entry"
    local pfx="${PREFIX[$proto-$transport]:-}"
    local port sn="" dom="${SELDOM[$proto-$transport]:-}"
    # ── Reality: режим + цель/домен — прямо здесь, перед портом
    if [[ "$proto" == "vless" && "$security" == "reality" ]]; then
      local e_key="$proto-$transport" rmode=""
      if [[ -t 0 ]]; then
        echo
        echo "  $name:"
        echo "   1) Чужой реалити «найти цели» — за 443 по SNI цели, серт НЕ нужен"
        echo "   2) Свой SNI-домен — нужен серт + decoy"
        ask rmode "Выбор [1/2]" "1" '^[12]$'
      else
        rmode="1"
      fi
      REALITY_MODE["$e_key"]="$rmode"
      if [[ "$rmode" == "1" ]]; then
        REALITY_EXT=true
        local tgt=""
        reality_target_menu tgt "$name"
        REALITY_TGT["$e_key"]="$tgt"
        REALITY_EXT_TARGET="$tgt"
        printf '%s' "$tgt" > /tmp/.reality-found-target 2>/dev/null || true
        log "  $name: цель → $tgt (dest+serverNames, за 443 по SNI цели)"
      else
        local d=""
        if [[ -t 0 ]]; then
          ask d "Домен для $name (нужен серт + decoy)" "${pfx:-r}.$base" '^[a-zA-Z0-9.-]+$'
        else
          d="${pfx:-r}.$base"
        fi
        SELDOM["$e_key"]="$d"
        dom="$d"
      fi
    elif [[ -z "$dom" && -n "$pfx" ]] && { [[ "$net" == "tcp" ]] || [[ "$proto" == "hysteria" ]]; }; then
      # ── TLS: SNI-домен (серт проверим сразу после порта)
      if [[ -t 0 ]]; then
        local d=""
        ask d "Домен для $name (нужен серт)" "$pfx.$base" '^[a-zA-Z0-9.-]+$'
        SELDOM["$proto-$transport"]="$d"
        dom="$d"
      else
        dom="$pfx.$base"
        SELDOM["$proto-$transport"]="$dom"
      fi
    fi
    # tg web proxy: домен — здесь же, перед его портом (не «после всех инбаундов»)
    if [[ "$proto" == "tproxy" && -t 0 ]]; then
      local tpd="${PANEL_DOMAIN:-$base}" base_dom="${PANEL_DOMAIN:-$base}" tdom_ask=""
      base_dom="${base_dom#*.}"
      [[ "$base_dom" != *.* ]] && base_dom="$tpd"
      ask tdom_ask "Домен tg web proxy (Enter — tg.$base_dom)" "tg.$base_dom" '^[a-zA-Z0-9.-]+$'
      T_PROXY_DOMAIN="$tdom_ask"
    fi
    case "$proto" in
      tproxy) port=11443 ;;
      qwdtt)  port=56000 ;;
      csqtt)  port=46000 ;;
      *)      port=$(make_port) ;;
    esac
    # порт: 443/80 нельзя (nginx), занятые другими инбаундами — нельзя
    if [[ -t 0 ]]; then
      local port_ok=false
      while [[ "$port_ok" != true ]]; do
        ask port "Порт для $name (Enter — $port)" "$port" '^[0-9]{2,5}$'
        if [[ "$port" == "443" || "$port" == "80" ]]; then
          err "Порт $port занят nginx (SNI-роутер/ACME) — выбери другой"
          continue
        fi
        if [[ " ${used_ports[*]:-} " == *" $port "* ]]; then
          err "Порт $port уже назначен другому инбаунду в этой установке"
          continue
        fi
        if [[ -n "$XUI_DB" && -f "$XUI_DB" ]] && \
           [[ "$(sqlite3 "$XUI_DB" "SELECT COUNT(*) FROM inbounds WHERE port=$port;" 2>/dev/null || echo 0)" != "0" ]]; then
          err "Порт $port уже используется инбаундом в панели — выбери другой"
          continue
        fi
        port_ok=true
      done
    fi
    used_ports+=("$port")
    # ── Заглушка для reality со своим SNI — ПО КАЖДОМУ инбаунду, после порта
    local rdtpl=""
    if [[ "$proto" == "vless" && "$security" == "reality" && "${REALITY_MODE[$proto-$transport]:-}" == "2" ]]; then
      rdtpl="corporate"
      if [[ -t 0 ]]; then
        decoy_template_choose rdtpl "Decoy-заглушка для $name (страница на SNI-домене)" "corporate"
      fi
    fi
    # sn: TCP-класс TLS-инбаунды И hysteria (UDP, но TLS обязателен)
    if [[ -n "$dom" ]] && { [[ "$net" == "tcp" ]] || [[ "$proto" == "hysteria" ]]; }; then
      sn="$dom"
    fi
    local vkn=""
    [[ "$proto" == "qwdtt" || "$proto" == "csqtt" ]] && vkn="$vk"
    # TLS-инбаундам серт нужен СРАЗУ (naive/anytls/trusttunnel/hysteria).
    # Тип (wildcard/персональный) учтён ВНУТРИ cert_issue: при живом wildcard
    # это no-op (переиспользует его), иначе выпустит персональный.
    if [[ -n "$dom" ]] && { [[ "$net" == "tcp" && "$security" == "tls" ]] || [[ "$proto" == "hysteria" ]]; }; then
      cert_issue "$dom" || warn "  ИТОГ: серт $dom НЕ выпущен — #${id} (${proto}) не поднимется; доукати позже: Сертификаты → обновить (причина выше)"
    fi
    local remark="${proto}-${transport}"
    [[ "$proto" == "vless" && "$transport" == "tcp"  && "$security" == "reality" ]] && remark="vless-reality"
    [[ "$proto" == "vless" && "$transport" == "xhttp" ]] && remark="vless-xhttp"
    # цель «чужого реалити» уже в REALITY_EXT_TARGET (шаг выше)
    new_id=$(create_inbound_db "$proto" "$transport" "$security" "$flow" "$port" "$remark" "$net" "$sn" "$vkn") || true
    if [[ -n "$new_id" ]]; then
      log "  → #$new_id $remark :$port${sn:+ (SNI $sn)}"
      [[ -n "$dom" ]] && A_DOM["$new_id"]="$dom"
      # своя заглушка на этот инбаунд (для initial_setup)
      [[ -n "$rdtpl" ]] && REALITY_DECOY_TPL_BYID["$new_id"]="$rdtpl"
    else
      warn "$name не создан"
    fi
  done
  systemctl restart x-ui 2>/dev/null || true
  sleep 5

  # --- 6) initial_setup с готовыми ответами (порядок вопросов стабилен)
  local ansf="/root/ans-auto-$(date +%H%M%S).txt"
  {
    echo "admin@$base"                          # EMAIL
                                                # PANEL_DOMAIN уже задан
    # AdGuard/заглушка/порты: в не-TTY initial_setup вопросов НЕ задаёт —
    # всё берётся из глобальных (заданы вопросами авто-подъёма выше), строк не пишем
    local id idproto idport dom stream_s
    while IFS='|' read -r id idproto idport stream_s; do
      [[ -z "$id" ]] && continue
      is_udp_proto "$idproto" && continue       # UDP — без вопросов в initial_setup
      # уже привязан к SNI — initial_setup вопросов по нему не задаёт, строк не пишем
      grep -Eq "^[[:space:]]*[^[:space:]]+[[:space:]]+inb_${id}_backend" "$SNI_CONF" 2>/dev/null && continue
      dom="${A_DOM[$id]:-}"
      if [[ -z "$dom" ]]; then
        echo "n"                                # домен не задан → не скрывать
      else
        echo "y"; echo "$dom"
        if grep -qi '"security": *"reality"' <<<"$stream_s"; then
          echo "${REALITY_DECOY_TPL_BYID[$id]:-corporate}"   # своя заглушка инбаунда
        fi
      fi
    done < <(sqlite3 "$XUI_DB" "SELECT id, protocol, port, COALESCE(stream_settings,'') FROM inbounds WHERE enable=1 AND port>0 ORDER BY id;" 2>/dev/null)
    echo "n"                                    # файрвол: настроим сами ниже
  } > "$ansf"
  log "Первичная настройка (автоответы: $ansf)…"
  initial_setup < "$ansf" >/tmp/auto-setup.log 2>&1 || warn "initial_setup вернул ошибку — смотри /tmp/auto-setup.log"
  grep -E "\[\+\]|\[!\]|\[x\]" /tmp/auto-setup.log 2>/dev/null | tail -12

  # --- 2с) Логин/пароль AdGuard, заданные при установке: применяем ВСЕГДА
  #         (даже если у AdGuard уже были пользователи — выбор пользователя важнее)
  if [[ "$ADG_PRESENT" == true && -n "${U_ADG_PASS:-}" ]]; then
    U_ADG_USER="${U_ADG_USER:-admin}"
    if adg_set_admin "$U_ADG_USER" "$U_ADG_PASS"; then
      log "Логин/пароль AdGuard установлены ($U_ADG_USER) — заданы при установке"
      printf 'AdGuard Home — %s\n  Логин:  %s\n  Пароль: %s\n' "$(date "+%Y-%m-%d %H:%M:%S")" "$U_ADG_USER" "$U_ADG_PASS" > /root/adguard-credentials.txt
      chmod 600 /root/adguard-credentials.txt
    else
      warn "Не удалось установить креды AdGuard — причина выше"
    fi
  fi

  # --- 3) UFW: SSH + 443 + слушающие порты туннелей; панельные порты в DENY
  firewall_apply

  # --- 3c) Автопочинка правок панели (каждые 2 мин; трогает x-ui только при находке)
  install_heal_timer
  # --- 4) ИТОГ
  local pp="" panel_pass adg_pass adg_user
  pp=$(xui_get webBasePath 2>/dev/null || true)
  pp="/${pp#/}"
  panel_pass=$(grep -i "пароль" /root/panel-credentials.txt 2>/dev/null | awk '{print $NF}' | head -1)
  local panel_user=""
  panel_user=$(grep -i "логин" /root/panel-credentials.txt 2>/dev/null | awk '{print $NF}' | head -1)
  adg_pass=$(grep -i "пароль" /root/adguard-credentials.txt 2>/dev/null | awk '{print $NF}' | head -1)
  adg_user=$(grep -i "логин"  /root/adguard-credentials.txt 2>/dev/null | awk '{print $NF}' | head -1)
  line
  echo -e "${G}   ИТОГ УСТАНОВКИ${N}"
  line
  echo "  ПАНЕЛЬ:  https://$base$pp"
  echo "           логин: ${panel_user:-${U_PANEL_USER:-admin}}   пароль: ${panel_pass:-см. /root/panel-credentials.txt}"
  if [[ "$ADG_PRESENT" == true ]]; then
    echo "  ADGUARD: https://$base/   (DoH: https://$base/dns-query)"
    echo "           логин: ${adg_user:-admin}   пароль: ${adg_pass:-см. /root/adguard-credentials.txt}"
  fi
  echo "  ИНБАУНДЫ:"
  sqlite3 "$XUI_DB" "SELECT id, protocol, port, remark FROM inbounds WHERE enable=1 ORDER BY id;" 2>/dev/null \
    | awk -F"|" '{printf "    #%s  %-12s :%-6s %s\n", $1, $2, $3, $4}'
  echo "  UFW:     активен (SSH+443+туннели; :80 закрыт; панельные порты DENY)"
  line
  echo "  Логины и пароли продублированы:"
  echo "    панель  → /root/panel-credentials.txt"
  [[ "$ADG_PRESENT" == true ]] && echo "    adguard → /root/adguard-credentials.txt"
  line
  read -rp "$(echo -e "${B}Нажмите Enter чтобы продолжить…${N}")" _ || true
  return 0
}

# =====================================================================
# ТОЧКА ВХОДА (только при прямом запуске; при source функции доступны для теста)
# =====================================================================
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  check_os
  ensure_deps
  detect_env
  [[ -f /var/run/reboot-required ]] && warn "Система ждёт ПЕРЕЗАГРУЗКУ (обновлено ядро) — сервер работает не на свежем ядре. См. п.18 → «Ресурсы»."

  # Первый запуск — предложить pre-install снимок состояния
  if [[ ! -f "$BACKUP_DIR/.pre-install-done" ]]; then
    echo
    warn "Первый запуск скрипта в этой системе."
    echo "  Рекомендуется сохранить снимок ТЕКУЩЕГО состояния — всех файлов,"
    echo "  которые скрипт может изменить: x-ui.db, /etc/nginx, UFW/iptables,"
    echo "  fail2ban, systemd units, certbot renewal-hooks, AdGuardHome.yaml."
    echo "  Это позволит откатить любые изменения одним кликом (п.24)."
    echo
    mk_snap=""
    askyn mk_snap "Сделать pre-install снимок сейчас?" "y"
    if [[ "$mk_snap" == true ]]; then
      mkdir -p "$BACKUP_DIR" 2>/dev/null || true
      take_pre_install_snapshot && touch "$BACKUP_DIR/.pre-install-done" 2>/dev/null || true
    else
      warn "Снимок не сделан. Можно сделать позже через п.24."
    fi
    echo
  fi
  # Автобэкап x-ui.db + nginx-конфигов стека (последние 5 копий)
  auto_backup_stack
  # deploy-hook renew (сертиф. живут в live/, зеркала нет) + дедупликация
  cert_hook_install
  cert_sync_all
  # если серты появились позже установки — дозаписать пути в инбаунды
  sync_inbound_certs
  [[ -f "$WILDCARD_STATE" ]] && WILDCARD_DOMAIN=$(head -n 1 "$WILDCARD_STATE" 2>/dev/null | tr -d '[:space:]' || true)
  # wildcard виден в п.6/п.18 — на старте не шумим

  # ПОРЯДОК ВАЖЕН: сначала ПАНЕЛЬ + её сертификат, потом AdGuard
  # (AdGuard берёт сертификат панели/wildcard для своего https).
  auto_full=false   # НЕ local: точка входа — вне функции
  if [[ -z "$XUI_DB" || ! -f "$XUI_DB" ]]; then
    warn "x-ui.db не найден — панель (LucX UI / 3x-ui) не установлена."
    echo "  Установка доступна через меню (п.13 — панель LucX UI)."
    echo "  Если уже стоит оригинальный 3x-ui — убедись, что x-ui.db в /etc/x-ui/."
    local install_now=""
    askyn install_now "Установить панель LucX UI сейчас?" "n"
    if [[ "$install_now" == true ]]; then
      install_lucx_panel || warn "Установка не удалась — можно повторить через п.13."
      [[ -n "$XUI_DB" && -f "$XUI_DB" ]] && auto_full=true
    else
      warn "Панель не установлена — меню откроется, установка доступна через п.13."
    fi
  fi

  # чистая установка → авто: инбаунды + настройка + UFW + итоговая сводка
  if [[ "$auto_full" == true ]]; then
    auto_full_setup || warn "Автоподъём прошёл не полностью — доделай в меню (п.1 и п.10)."
  fi

  main_menu
fi
