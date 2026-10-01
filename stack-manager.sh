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
line() { echo -e "${B}────────────────────────────────────────────────────────${N}"; }

[[ $EUID -eq 0 ]] || { err "Запустите от root (sudo $0)"; exit 1; }
export DEBIAN_FRONTEND=noninteractive

BACKUP_DIR="/root/stack-backups"
FW_STATE_DIR="/root/stack-backups/firewall-state"

# Wildcard-сертификат Cloudflare (один на все поддомены базового домена)
WILDCARD_DOMAIN=""
WILDCARD_STATE="/root/stack-backups/wildcard-domain"
CF_CREDS="/root/.secrets/cloudflare.ini"

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
ADG_PRESENT=false
ADG_SERVICE=""
ADG_CONFIG=""
EMAIL=""
SSH_PORT="22"

DECOY_TEMPLATES=(
  "default|Nginx default — стандартная заглушка"
  "blank|Пустая белая страница"
  "corporate|Корпоративный лендинг"
  "blog|Персональный блог"
  "docs|Документация / wiki"
  "cloudflare|Cloudflare-style"
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
    adguard|portainer|pihole|omv|jellyfin|homeassistant|uptime-kuma) return 0 ;;
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
    hysteria|hysteria2|wireguard|amnezia|amneziawg|awg|qwdtt|csqdtt|csqtt) return 0 ;;
    *) return 1 ;;
  esac
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

# Камуфляж-сайт для tproxy (Telegram WEB-proxy)
ensure_tproxy_site() {
  mkdir -p /var/www/html 2>/dev/null || true
  [[ -s /var/www/html/index.html ]] || printf '%s\n' \
    '<!DOCTYPE html><html><head><meta charset="utf-8"><title></title></head><body></body></html>' \
    > /var/www/html/index.html
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
  local mode="$1"
  [[ -f "$STACK_CONF" ]] || return 1
  grep -q "listen 127.0.0.1:4443" "$STACK_CONF" 2>/dev/null || return 1
  local adg_port=""
  adg_port=$(adg_config_port 2>/dev/null || true)
  [[ -z "$adg_port" ]] && adg_port="${ADG_WEB_PORT:-3000}"
  PD_MODE="$mode" PD_PORT="$adg_port" PD_DIR="$PANEL_DECOY_DIR" python3 - "$STACK_CONF" <<'PYPDA'
import sys, os
mode, adg_port, pdir = os.environ["PD_MODE"], os.environ["PD_PORT"], os.environ["PD_DIR"]
path = sys.argv[1]
src = open(path).read()
if mode == "adguard":
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
{"clients":[{"id":"$uuid","flow":"$flow","email":"user@$port","limitIp":0,"totalGB":0,"expiryTime":0,"enable":true,"tgId":0,"subId":"$sub_id","reset":0,"fingerprint":"firefox"}],"decryption":"none","fallbacks":[]}
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
{"remark":"trusttunnel-$port","hostname":"$sn","listen":"","ipv6":false,"certFile":"$cert","keyFile":"$key","clientDns":"1.1.1.1","upstreamProtocol":"http2","routeThroughXray":false,"routeXrayPort":0,"outboundTag":"","metricsPort":0,"listenPreset":"fast","clientRandomPrefix":"$(gen_hex 4)/ffffffff","authSeed":"$(gen_hex 32)","clients":[{"email":"user","enable":true}]}
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
    # VK call hashes — только для qwdtt/csqtt; пусто → поле остаётся пустым
    local vk=""
    if [[ "$proto" == "qwdtt" || "$proto" == "csqtt" ]]; then
      ask vk "VK call hashes (через запятую, БЕЗ пробелов; Enter — пропустить)" "" '^[a-zA-Z0-9,_-]*$'
    fi
    log "Создаю: $name (proto=$proto, transport=$transport, sec=$security, port=$port)"
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

  tpl_write "$DECOY_TPL_DIR/default.html" <<'HTML'
<!doctype html><html><head><meta charset="utf-8"><title>Welcome to nginx!</title>
<style>body{font-family:sans-serif;background:#f4f4f4;text-align:center;padding-top:80px;color:#333}
h1{color:#2b6cb0}p{color:#666}</style></head>
<body><h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and working.</p></body></html>
HTML

  tpl_write "$DECOY_TPL_DIR/blank.html" <<'HTML'
<!doctype html><html><head><meta charset="utf-8"><title> </title></head><body></body></html>
HTML

  tpl_write "$DECOY_TPL_DIR/corporate.html" <<'HTML'
<!doctype html><html><head><meta charset="utf-8"><title>Corp — Solutions</title>
<style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:-apple-system,sans-serif;color:#111;line-height:1.6}
nav{padding:20px 40px;border-bottom:1px solid #eee;display:flex;justify-content:space-between}nav a{color:#111;text-decoration:none;margin-left:24px;font-size:14px}
.logo{font-weight:600;font-size:18px}.hero{padding:100px 40px;max-width:1100px;margin:auto}
h1{font-size:52px;font-weight:600;letter-spacing:-1px;margin-bottom:24px}p.lead{font-size:20px;color:#555;max-width:600px}
.btn{display:inline-block;margin-top:32px;padding:14px 28px;background:#111;color:#fff;text-decoration:none;border-radius:6px}
footer{padding:40px;border-top:1px solid #eee;color:#888;font-size:13px;text-align:center}</style></head><body>
<nav><div class="logo">Corp</div><div><a href="#">Product</a><a href="#">Solutions</a><a href="#">Contact</a></div></nav>
<div class="hero"><h1>Building the future of infrastructure.</h1>
<p class="lead">We help enterprises scale with confidence.</p><a href="#" class="btn">Learn more</a></div>
<footer>© 2026 Corp Inc. All rights reserved.</footer></body></html>
HTML

  tpl_write "$DECOY_TPL_DIR/blog.html" <<'HTML'
<!doctype html><html><head><meta charset="utf-8"><title>Notes</title>
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:Georgia,serif;max-width:720px;margin:auto;padding:60px 24px;color:#222;line-height:1.7}
h1{font-size:32px;margin-bottom:8px}.sub{color:#888;font-size:14px;margin-bottom:48px}article{margin-bottom:48px}
article h2{font-size:22px;margin-bottom:8px}article .meta{color:#888;font-size:13px;margin-bottom:12px}article p{color:#444}</style></head><body>
<h1>Notes</h1><p class="sub">Thoughts on software, systems, and craft.</p>
<article><h2>On simple systems</h2><div class="meta">March 12, 2026</div>
<p>The best systems are the ones you can hold in your head.</p></article>
<article><h2>The quiet majority</h2><div class="meta">March 5, 2026</div>
<p>Most software does its job silently.</p></article></body></html>
HTML

  tpl_write "$DECOY_TPL_DIR/docs.html" <<'HTML'
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
<pre>npm install @example/sdk</pre><p>Then call <code>client.connect()</code>.</p></main></body></html>
HTML

  tpl_write "$DECOY_TPL_DIR/cloudflare.html" <<'HTML'
<!doctype html><html><head><meta charset="utf-8"><title>Attention Required! | Cloudflare</title>
<style>body{font-family:sans-serif;background:#f5f5f5;color:#333;margin:0;padding:60px 20px}
.container{max-width:800px;margin:auto;background:#fff;border-radius:6px;padding:60px;box-shadow:0 2px 12px rgba(0,0,0,.06)}
h1{font-size:26px;margin-bottom:24px;color:#111}p{line-height:1.7;color:#555;margin-bottom:16px}
.footer{border-top:1px solid #eee;margin-top:40px;padding-top:20px;color:#888;font-size:13px}</style></head><body>
<div class="container"><h1>Attention Required!</h1>
<p>You are unable to access this site.</p><p>Please enable cookies and JavaScript.</p>
<div class="footer">Cloudflare Ray ID: 8a3f... &nbsp;•&nbsp; Performance &amp; security by Cloudflare</div>
</div></body></html>
HTML

  log "Статические decoy-шаблоны готовы"
}

# =====================================================================
# DECOY: LOGIN-ШАБЛОНЫ
# =====================================================================
decoy_login_templates_init() {
  mkdir -p "$DECOY_LOGIN_DIR" 2>/dev/null || true

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
<!doctype html><html><head><meta charset="utf-8"><title>AdGuard Home</title>
$css<style>
body{font-family:-apple-system,sans-serif;background:#67b279;display:flex;align-items:center;justify-content:center;min-height:100vh}
.card{background:#fff;padding:40px;width:360px;border-radius:6px;box-shadow:0 8px 24px rgba(0,0,0,.15)}
h1{font-size:22px;color:#3d3d3d;text-align:center;margin-bottom:8px}
.sub{font-size:13px;color:#888;text-align:center;margin-bottom:24px}
button{background:#67b279;color:#fff}
</style></head><body><div class="card">
<h1>AdGuard Home</h1><div class="sub">Sign in to continue</div>
<div id="msg" class="msg"></div>
<form id="form" method="POST" action="/login">
<label>Username</label><input name="u" required autocomplete="off">
<label>Password</label><input name="p" type="password" required>
<button>Sign in</button>
</form></div>$js</body></html>
HTML

  tpl_write "$DECOY_LOGIN_DIR/portainer.html" <<HTML
<!doctype html><html><head><meta charset="utf-8"><title>Portainer</title>
$css<style>
body{font-family:-apple-system,sans-serif;background:#f4f4f4;display:flex;align-items:center;justify-content:center;min-height:100vh}
.card{background:#fff;padding:48px;width:400px;border-radius:8px;box-shadow:0 8px 32px rgba(0,0,0,.08)}
.logo{width:52px;height:52px;background:#13b5ea;border-radius:6px;margin:0 auto 20px}
h1{font-size:22px;color:#333;text-align:center;margin-bottom:32px}
label{text-transform:uppercase;letter-spacing:.5px;font-size:12px}
button{background:#13b5ea;color:#fff}
</style></head><body><div class="card">
<div class="logo"></div><h1>Portainer</h1>
<div id="msg" class="msg"></div>
<form id="form" method="POST" action="/login">
<label>Username</label><input name="u" required autocomplete="off">
<label>Password</label><input name="p" type="password" required>
<button>Log in</button>
</form></div>$js</body></html>
HTML

  tpl_write "$DECOY_LOGIN_DIR/pihole.html" <<HTML
<!doctype html><html><head><meta charset="utf-8"><title>Pi-hole</title>
$css<style>
body{font-family:-apple-system,sans-serif;background:#fff;display:flex;align-items:center;justify-content:center;min-height:100vh;color:#333}
.card{width:420px;padding:40px;text-align:center}
h1{font-size:26px;color:#c00;margin-bottom:8px}
.sub{color:#888;font-size:13px;margin-bottom:32px}
label{text-align:left}
button{background:#c00;color:#fff}
</style></head><body><div class="card">
<h1>Pi-hole</h1><div class="sub">Admin console</div>
<div id="msg" class="msg"></div>
<form id="form" method="POST" action="/login">
<label>Password</label><input name="p" type="password" required>
<button>Log in</button>
</form></div>$js</body></html>
HTML

  tpl_write "$DECOY_LOGIN_DIR/omv.html" <<HTML
<!doctype html><html><head><meta charset="utf-8"><title>openmediavault</title>
$css<style>
body{font-family:-apple-system,sans-serif;background:#e9eef2;display:flex;align-items:center;justify-content:center;min-height:100vh;color:#333}
.card{background:#fff;width:400px;border-radius:4px;box-shadow:0 2px 12px rgba(0,0,0,.08);overflow:hidden}
.head{background:#5d7789;color:#fff;padding:20px 24px;font-size:18px;font-weight:500}
.body{padding:32px 24px}
button{background:#5d7789;color:#fff}
</style></head><body><div class="card">
<div class="head">openmediavault</div><div class="body">
<div id="msg" class="msg"></div>
<form id="form" method="POST" action="/login">
<label>Username</label><input name="u" required autocomplete="off">
<label>Password</label><input name="p" type="password" required>
<button>Login</button>
</form></div></div>$js</body></html>
HTML

  tpl_write "$DECOY_LOGIN_DIR/jellyfin.html" <<HTML
<!doctype html><html><head><meta charset="utf-8"><title>Jellyfin</title>
$css<style>
body{font-family:-apple-system,sans-serif;background:linear-gradient(135deg,#101010,#1a0033);color:#fff;display:flex;align-items:center;justify-content:center;min-height:100vh}
.card{width:380px;padding:40px 32px;background:rgba(255,255,255,.04);border-radius:12px;border:1px solid rgba(255,255,255,.08)}
.logo{width:56px;height:56px;background:#aa5cc3;border-radius:12px;margin:0 auto 16px}
h1{font-size:20px;text-align:center;margin-bottom:32px;font-weight:500}
label{color:#bbb}
input{background:#1a1a1a;border:1px solid #333;color:#fff}
button{background:#aa5cc3;color:#fff}
</style></head><body><div class="card">
<div class="logo"></div><h1>Jellyfin</h1>
<div id="msg" class="msg"></div>
<form id="form" method="POST" action="/login">
<label>Username</label><input name="u" required autocomplete="off">
<label>Password</label><input name="p" type="password" required>
<button>Sign In</button>
</form></div>$js</body></html>
HTML

  tpl_write "$DECOY_LOGIN_DIR/homeassistant.html" <<HTML
<!doctype html><html><head><meta charset="utf-8"><title>Home Assistant</title>
$css<style>
body{font-family:-apple-system,sans-serif;background:#03a9f4;display:flex;align-items:center;justify-content:center;min-height:100vh}
.card{background:#fff;padding:40px 32px;width:380px;border-radius:4px;box-shadow:0 4px 20px rgba(0,0,0,.15)}
h1{font-size:24px;color:#0388d1;text-align:center;margin-bottom:32px;font-weight:500}
button{background:#03a9f4;color:#fff}
</style></head><body><div class="card">
<h1>Home Assistant</h1>
<div id="msg" class="msg"></div>
<form id="form" method="POST" action="/login">
<label>Username</label><input name="u" required autocomplete="off">
<label>Password</label><input name="p" type="password" required>
<button>Log in</button>
</form></div>$js</body></html>
HTML

  tpl_write "$DECOY_LOGIN_DIR/uptime-kuma.html" <<HTML
<!doctype html><html><head><meta charset="utf-8"><title>Uptime Kuma</title>
$css<style>
body{font-family:-apple-system,sans-serif;background:#5cdd8b;display:flex;align-items:center;justify-content:center;min-height:100vh}
.card{background:#fff;padding:36px 32px;width:360px;border-radius:8px;box-shadow:0 8px 28px rgba(0,0,0,.12)}
h1{font-size:20px;color:#333;text-align:center;margin-bottom:28px}
button{background:#5cdd8b;color:#fff}
</style></head><body><div class="card">
<h1>Uptime Kuma</h1>
<div id="msg" class="msg"></div>
<form id="form" method="POST" action="/login">
<label>Username</label><input name="u" required autocomplete="off">
<label>Password</label><input name="p" type="password" required>
<button>Login</button>
</form></div>$js</body></html>
HTML

  chown -R www-data:www-data "$DECOY_LOGIN_DIR" 2>/dev/null || true
  log "7 login-шаблонов установлены"
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
failregex = ^<HOST> - \S+ \[[^\]]+\] "POST /login HTTP/[0-9.]+" 401
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
    local base="${PANEL_DOMAIN#*.}"
    [[ "$base" != *.* ]] && base="$PANEL_DOMAIN"
    tdom="tg.${base:-example.com}"
  fi
  # сайт-заглушка обязательна: без index.html в siteDir caddy tproxy не поднимается
  mkdir -p /var/www/html
  [[ -f /var/www/html/index.html ]] || { cp "$DECOY_TPL_DIR/corporate.html" /var/www/html/index.html 2>/dev/null || echo '<html><body><h1>Welcome</h1></body></html>' > /var/www/html/index.html; }
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
  # маршрут 443 → tproxy (idempotent)
  if [[ -f "$SNI_CONF" ]] && ! grep -q "tg_backend" "$SNI_CONF"; then
    sed -i "s|^\(    default\)|    $tdom              tg_backend;\n\1|" "$SNI_CONF" 2>/dev/null || true
    sed -i "1i upstream tg_backend { server 127.0.0.1:11443; }" "$SNI_CONF" 2>/dev/null || true
  fi
  ufw allow 11443/tcp >/dev/null 2>&1 || true
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

sync_inbound_certs() {
  [[ -z "$XUI_DB" || ! -f "$XUI_DB" ]] && return 1
  local cnt=0 id proto dom stream line cert key
  # x-ui держит inbounds в памяти и при рестарте сбрасывает её поверх БД —
  # поэтому ВСЕ правки inbounds делаем только при ОСТАНОВЛЕННОМ x-ui
  systemctl stop x-ui 2>/dev/null || true
  # tproxy (caddy) отказывается стартовать без index.html в siteDir
  if [[ -d /var/www/html && ! -f /var/www/html/index.html && -n "$DECOY_TPL_DIR" && -f "$DECOY_TPL_DIR/corporate.html" ]]; then
    cp "$DECOY_TPL_DIR/corporate.html" /var/www/html/index.html 2>/dev/null || true
  fi
  # Читаем через python: панель хранит stream/settings pretty-JSON (многострочно),
  # sqlite3|while-read обрезал бы значение на первом переносе — reality-инбаунды
  # молча выпадали из самолечения и не получали серты/decoy.
  while IFS=$'\x1f' read -r id proto dom stream; do
    [[ -z "$id" || -z "$dom" || "$dom" == "null" ]] && continue
    dom="$(printf '%s' "$dom" | tr -d '[:space:]')"   # хвост-пробел/CR ломает пути live/<домен>
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
    python3 - "$XUI_DB" "$id" "$proto" "$dom" "$cert" "$key" <<'PY' && cnt=$((cnt+1))
import sqlite3, json, sys
db, i, proto, dom, cert, key = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6]
con = sqlite3.connect(db)
def one(sql, *a):
    return con.execute(sql, a).fetchone()
if proto == "hysteria":
    st = json.loads((one("SELECT stream_settings FROM inbounds WHERE id=?", i)[0] or "{}"))
    st["network"] = st.get("network") or "udp"
    st["security"] = "tls"
    tls = st.get("tlsSettings") or {}
    tls["serverName"] = dom
    tls["certificates"] = [{"certificateFile": cert, "keyFile": key}]
    st["tlsSettings"] = tls
    con.execute("UPDATE inbounds SET stream_settings=? WHERE id=?", (json.dumps(st), i))
else:
    try:
        s = json.loads((one("SELECT settings FROM inbounds WHERE id=?", i)[0] or "{}"))
    except Exception:
        s = {}
    if "certFile" in s:
        s["certFile"] = cert; s["keyFile"] = key
        con.execute("UPDATE inbounds SET settings=? WHERE id=?", (json.dumps(s), i))
    if proto in ("anytls", "trusttunnel", "trust-tunnel", "vless"):
        st2 = json.loads((one("SELECT stream_settings FROM inbounds WHERE id=?", i)[0] or "{}"))
        if st2.get("security") not in (None, "", "tls"):
            con.commit(); sys.exit(0)   # reality и прочие — stream не трогаем
        st2["network"] = "tcp"; st2["security"] = "tls"
        st2["tlsSettings"] = {"serverName": dom, "certificates": [{"certificateFile": cert, "keyFile": key}]}
        con.execute("UPDATE inbounds SET stream_settings=? WHERE id=?", (json.dumps(st2), i))
con.commit()
print(f"  #{i} ({proto}): cert вписан ({dom} → {cert})")
PY
  done < <(python3 - "$XUI_DB" <<'PYROWS' 2>/dev/null
import sqlite3, json, sys
try:
    con = sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True, timeout=5)
    rows = con.execute("SELECT id, protocol, settings, stream_settings FROM inbounds WHERE enable=1").fetchall()
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
    rows = con.execute("SELECT id, protocol, settings, stream_settings FROM inbounds WHERE enable=1").fetchall()
except Exception:
    sys.exit(1)   # БД недоступна — не считаем поломкой

SKIP = {"qwdtt", "csqdtt", "csqtt", "wireguard", "amnezia", "amneziawg", "awg", "mtproto", "tun"}
for iid, proto, setts_s, stream_s in rows:
    if proto in SKIP:
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

cert_issue() {
  local d="$1"
  # невидимый хвост (пробел/CR из БД или ans-файла) ломает пути live/<домен> —
  # certbot нормализует имя, скрипт ищет файлы по «грязному» пути и не находит
  d="$(printf '%s' "$d" | tr -d '[:space:]')"
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

# Выпуск wildcard: base + *.base через Cloudflare DNS-01
# base можно передать аргументом; если wildcard уже выпущен и свеж — переустановки не будет
cert_wildcard_issue() {
  [[ -z "$EMAIL" ]] && ask EMAIL "Email для Let's Encrypt" "" '^[^@]+@[^@]+\.[^@]+$'
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
  local tpl
  for tpl in "${DECOY_TEMPLATES[@]}"; do
    local name="${tpl%%|*}" desc="${tpl##*|}"
    printf "  %2d) %-15s %s\n" "$i" "$name" "$desc" >&2
    NAMES+=("$name"); i=$((i+1))
  done
  echo >&2
  local choice=""
  ask choice "$prompt" "$default" '^[0-9]+$|^[a-z-]+$' 2>/dev/null || { printf -v "$__result" '%s' "$default"; return 0; }
  if [[ "$choice" =~ ^[0-9]+$ ]]; then
    if (( choice >= 1 && choice <= ${#NAMES[@]} )); then
      printf -v "$__result" '%s' "${NAMES[$((choice-1))]}"
    else
      printf -v "$__result" '%s' "$default"
    fi
  else
    printf -v "$__result" '%s' "$choice"
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
  local port="$1" dom="$2" cert="$3" key="$4" root="$5"
  local tpl="${6:-default}"
  mkdir -p "$root" 2>/dev/null || true
  local body

  if is_login_template "$tpl"; then
    cp -f "$DECOY_LOGIN_DIR/$tpl.html" "$root/index.html" 2>/dev/null || true
    chown www-data:www-data "$root/index.html" 2>/dev/null || true
    body=$(cat <<EOF
server {
    listen 127.0.0.1:$port ssl http2;
    server_name $dom;
    ssl_certificate     $cert;
    ssl_certificate_key $key;
    root $root;
    index index.html;
    access_log $DECOY_LOG_ACCESS;
    error_log  /var/log/nginx/decoy-error.log;
    location / { try_files \$uri \$uri/ /index.html; }
    location = /login { limit_except POST { deny all; } return 401; }
}
EOF
)
  else
    if [[ -f "$DECOY_TPL_DIR/$tpl.html" ]]; then
      cp -f "$DECOY_TPL_DIR/$tpl.html" "$root/index.html" 2>/dev/null || true
    else
      cp -f "$DECOY_TPL_DIR/default.html" "$root/index.html" 2>/dev/null || true
    fi
    chown www-data:www-data "$root/index.html" 2>/dev/null || true
    body=$(cat <<EOF
server {
    listen 127.0.0.1:$port ssl http2;
    server_name $dom;
    ssl_certificate     $cert;
    ssl_certificate_key $key;
    root $root;
    index index.html;
}
EOF
)
  fi

  stack_ensure
  stack_del_decoy "$dom"   # замена блока того же домена (upsert)
  {
    echo "# >>> decoy port=$port root=$root cert=$cert key=$key domain=$dom"
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
#   $1 = inbound_id, $2 = адрес (домен панели/IP), $3 = SNI (по умолчанию = адрес;
#        для чужого реалити это serverNames ЦЕЛИ, а не домен панели!)
hosts_upsert() {   # <inbound_id> <address> [sni]
  [[ -z "$XUI_DB" || ! -f "$XUI_DB" ]] && return 0
  local id="$1" dom="$2" sni="${3:-$2}"
  [[ -z "$id" || -z "$dom" || "$dom" == "null" ]] && return 0
  [[ -z "$sni" ]] && sni="$dom"
  local has_hosts
  has_hosts=$(sqlite3 "$XUI_DB" "SELECT name FROM sqlite_master WHERE type='table' AND name='hosts';" 2>/dev/null || true)
  [[ -z "$has_hosts" ]] && return 0
  local cols
  cols=$(sqlite3 "$XUI_DB" "PRAGMA table_info(hosts);" 2>/dev/null | awk -F'|' '{print $2}' | tr '\n' ' ')
  local remark
  remark=$(sqlite3 "$XUI_DB" "SELECT remark FROM inbounds WHERE id=$id;" 2>/dev/null || true)
  sqlite3 "$XUI_DB" "DELETE FROM hosts WHERE inbound_id=$id AND port=443;" 2>/dev/null || true
  local fields="inbound_id,address,port" vals="$id,'$dom',443"
  grep -qw remark       <<<"$cols" && { fields+=",remark";       vals+=",'$(printf '%s' "$remark" | sed "s/'/''/g")'"; }
  grep -qw sni          <<<"$cols" && { fields+=",sni";          vals+=",'$sni'"; }
  grep -qw fingerprint  <<<"$cols" && { fields+=",fingerprint";  vals+=",'firefox'"; }
  grep -qw is_disabled  <<<"$cols" && { fields+=",is_disabled";  vals+=",0"; }
  grep -qw enable       <<<"$cols" && { fields+=",enable";       vals+=",1"; }
  if sqlite3 "$XUI_DB" "INSERT INTO hosts ($fields) VALUES ($vals);" 2>/dev/null; then
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

  nginx_reload || true
  log "SNI настроен: $domain -> inb_${id}_backend"
}

# =====================================================================
# ПЕРВИЧНАЯ НАСТРОЙКА
# =====================================================================
initial_setup() {
  line; echo -e "${B}   ПЕРВИЧНАЯ НАСТРОЙКА SNI-РОУТЕРА${N}"; line
  # ПЕРЕУСТАНОВКА (п.17 → сюда): таймер самолечения лезет в x-ui каждые 2 мин
  # и рушит схему «стоп → правка БД → старт». Гасим до начала, вернём в конце.
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
    askyn install_now "Установить панель LucX UI сейчас?" "y"
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

  ask EMAIL "Email для Let's Encrypt" "" '^[^@]+@[^@]+\.[^@]+$'
  if [[ -z "$PANEL_DOMAIN" ]]; then
    ask PANEL_DOMAIN "Домен панели" "panel.example.com" '^[a-zA-Z0-9.-]+$'
  else
    log "Домен панели: $PANEL_DOMAIN (задан ранее)"
  fi
  sni_used_load
  SNI_USED["$PANEL_DOMAIN"]="panel_backend"   # домен панели тоже занят — инбаунды не могут его использовать

  # ЕДИНЫЙ ПУТЬ (тот же, что в авто-подъёме):
  # пароль+порты — только в TTY; в ans-режиме всё уже в глобальных (U_*)
  if [[ -t 0 ]]; then
    ask_panel_creds || return 1
  fi
  ask_adguard_and_decoy               # AdGuard да/нет → пароль → где → заглушка
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
  done < <(sqlite3 "$XUI_DB" "SELECT id, protocol, port, COALESCE(stream_settings,'') FROM inbounds WHERE enable=1;" 2>/dev/null || true)

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
    decoy_block=$(cat <<EOF
    location / {
        root $PANEL_DECOY_DIR;
        try_files /index.html =404;
    }
EOF
)
  fi

  { cat >> "$STACK_CONF" <<EOF
server {
    listen 127.0.0.1:4443 ssl http2;
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
  done < <(sqlite3 "$XUI_DB" "SELECT id, protocol, COALESCE(json_extract(stream_settings,'\$.security'),''), COALESCE(json_extract(stream_settings,'\$.realitySettings.dest'),'') FROM inbounds WHERE enable=1;" 2>/dev/null || true)

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
      grep -qw sni         <<<"$cols" && { fields+=",sni";         vals+=",'$dom'"; }
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
    askyn do_create "Стек готов. Создать инбаунды сейчас?" "y"
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
  askyn fw_now "Настроить файрвол сейчас (сброс: только SSH+443+UDP)?" "y"
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
    grep -qw sni         <<<"$cols" && { fields+=",sni";         vals+=",'$domain'"; }
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
    done < <(sqlite3 "$XUI_DB" "SELECT id, protocol, port FROM inbounds WHERE enable=1;" 2>/dev/null || true)
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

  # список: ТОЛЬКО инбаунды с SNI-привязкой (домен панели здесь не показывается и не удаляется)
  local row dom be iid proto port found=0
  while IFS='|' read -r dom be iid; do
    [[ -z "$dom" || -z "$iid" ]] && continue
    proto=$(sqlite3 "$XUI_DB" "SELECT protocol FROM inbounds WHERE id=$iid;" 2>/dev/null || true)
    port=$(sqlite3 "$XUI_DB" "SELECT port FROM inbounds WHERE id=$iid;" 2>/dev/null || true)
    printf "  #%-3s %-28s %-10s порт %s\n" "$iid" "$dom" "${proto:-?}" "${port:-?}"
    found=$((found+1))
  done < <(sni_map_domains)
  [[ $found -eq 0 ]] && warn "Инбаундов с SNI-привязкой нет"

  echo
  local id=""
  ask id "ID инбаунда для удаления" "" '^[0-9]+$'

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

  local what="SNI-привязку ($dom)"
  [[ "$exists" != "0" ]] && what="SNI-привязку${dom:+ ($dom)} И сам инбаунд #$id из панели"
  askyn confirm "Удалить $what?" "y"
  [[ "$confirm" == true ]] || return 0

  if [[ -n "$dom" ]]; then
    sni_map_remove "$dom"
    [[ -n "$be" && "$be" != "panel_backend" ]] && sni_upstream_remove "$be"
    unset "SNI_USED[$dom]" 2>/dev/null || true
    stack_del_decoy "$dom"   # decoy-блок в stack.conf
    sqlite3 "$XUI_DB" "DELETE FROM hosts WHERE sni='$dom' OR (inbound_id=$id AND port=443);" 2>/dev/null || true
  else
    sqlite3 "$XUI_DB" "DELETE FROM hosts WHERE inbound_id=$id;" 2>/dev/null || true
  fi

  if [[ "$exists" != "0" ]]; then
    cp -n "$XUI_DB" "${XUI_DB}.bak.$(date +%s)" 2>/dev/null || true
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
  while IFS= read -r mline; do
    [[ "$mline" != "# >>> decoy "* ]] && continue
    mport=$(grep -oE 'port=[0-9]+'   <<<"$mline" | head -1 | cut -d= -f2)
    mdom=$(grep  -oE 'domain=[^ ]+$' <<<"$mline" | head -1 | cut -d= -f2-)
    if [[ -n "$mdom" ]]; then
      DOM_LIST+=("$mdom")
      printf "  %s) %-30s порт %s\n" "${#DOM_LIST[@]}" "$mdom" "$mport"
    fi
  done < "$STACK_CONF"

  # decoy домена панели (panel-блок в stack.conf: 127.0.0.1:4443) — тоже доступен для смены
  local panel_conf="$STACK_CONF"
  local panel_dom=""
  panel_dom=$(xui_get subDomain 2>/dev/null || true)
  if [[ -n "$panel_dom" ]]; then
    DOM_LIST+=("$panel_dom")
    printf "  %s) %-30s порт 4443 [домен панели]\n" "${#DOM_LIST[@]}" "$panel_dom"
  fi
  [[ ${#DOM_LIST[@]} -eq 0 ]] && { err "SNI-домены не найдены — сначала п.1"; pause; return 1; }
  echo
  local pick=""
  ask pick "Номер домена (1-${#DOM_LIST[@]}, 0 — отмена)" "1" '^[0-9]+$'
  [[ "$pick" == "0" ]] && return 0
  (( pick > ${#DOM_LIST[@]} )) && { err "Нет такого номера"; pause; return 1; }
  local domain="${DOM_LIST[$((pick-1))]}"
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
      warn "  • п.16 «Удалить AdGuard Home», затем п.4 — выбрать шаблон."
      pause; return 0
    fi
    mkdir -p "$PANEL_DECOY_DIR" 2>/dev/null || true
    local tpl=""
    decoy_template_choose tpl "Новый decoy панели" "corporate"
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

  local meta port="" root="" cert="" key=""
  meta=$(stack_decoy_meta "$domain")
  if [[ -z "$meta" ]]; then
    err "Decoy-блок для $domain не найден в $STACK_CONF. Найдены маркеры:"
    grep "# >>> decoy" "$STACK_CONF" 2>/dev/null | sed 's/^/    /' || warn "    (ни одного)"
    pause; return 1
  fi
  read -r port root cert key <<<"$meta"
  local old_hash="" new_hash="" tpl=""
  old_hash=$(md5sum "$root/index.html" 2>/dev/null | awk '{print $1}')
  decoy_template_choose tpl "Новый decoy" "default"
  mk_decoy "$port" "$domain" "$cert" "$key" "$root" "$tpl"
  new_hash=$(md5sum "$root/index.html" 2>/dev/null | awk '{print $1}')
  if ! nginx -t >/dev/null 2>&1; then
    err "nginx -t не прошёл после смены decoy:"
    nginx -t 2>&1 | tail -5 | sed 's/^/    /'
    pause; return 1
  fi
  nginx_reload || true
  if [[ -n "$new_hash" && "$new_hash" != "$old_hash" ]]; then
    log "Decoy сменён на «$tpl» ✓ ($root/index.html обновлён)"
    warn "Если в браузере всё ещё старая страница — обнови с Ctrl+F5 (кэш)"
  elif [[ -n "$new_hash" ]]; then
    log "Decoy применён: «$tpl» — файл совпал с прежним (вероятно, тот же шаблон уже стоял)"
  else
    err "index.html НЕ записался в $root — проверь шаблон: ls $DECOY_TPL_DIR"
  fi
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
  echo; echo "▸ Забаненные IP:"
  local ips=""
  ips=$(fail2ban-client get decoy-login banip 2>/dev/null || true)
  [[ -n "$ips" ]] && echo "$ips" | tr ' ' '\n' | sed 's/^/  /' || echo "  —"
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
  esac
  pause
}

decoy_ban_status() {
  line; echo -e "${B}   LOGIN-ДЕКОИ И БАНЫ${N}"; line
  fail2ban-client status decoy-login 2>/dev/null | sed 's/^/  /' || echo "  jail не активен"
  echo; echo "▸ Забаненные IP:"
  local ips=""
  ips=$(fail2ban-client get decoy-login banip 2>/dev/null || true)
  [[ -n "$ips" ]] && echo "$ips" | tr ' ' '\n' | sed 's/^/  /' || echo "  —"
  echo
  echo "  1) Разбанить IP"
  echo "  2) Разбанить все"
  echo "  3) Очистить лог"
  echo "  0) Назад"
  line
  local c=""
  read -rp "$(echo -e "${B}Выбор:${N} ")" c || c="0"
  case "$c" in
    1) local ip=""; ask ip "IP" "" '^[0-9.]+$'; fail2ban-client set decoy-login unbanip "$ip" 2>/dev/null && log "OK" || warn "Fail" ;;
    2) fail2ban-client unban --all 2>/dev/null && log "OK" || warn "Fail" ;;
    3) > "$DECOY_LOG_ACCESS" 2>/dev/null || true; systemctl restart fail2ban 2>/dev/null || true; log "OK" ;;
  esac
  pause
}

# DNS для Xray удалён из скрипта: xray резолвит системно (dns-секция шаблона
# не трогается), настройки DNS Xray делаются в панели при необходимости.

# =====================================================================
# FIREWALL
# =====================================================================
scan_ports() {
  {
    ss -tlnpH 2>/dev/null | awk '{print "tcp|" $4}'
    ss -ulnpH 2>/dev/null | awk '{print "udp|" $4}'
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
    echo
    declare -A REQ=()
    REQ["tcp:$SSH_PORT"]="SSH"
    # tcp/80 НЕ открываем: сертификаты — wildcard через DNS-хук (DNS-01),
    # HTTP-01 не нужен; при необходимости открыть разово: ufw allow 80/tcp
    systemctl is-active --quiet nginx 2>/dev/null && REQ["tcp:443"]="HTTPS/SNI"
    while IFS='|' read -r proto port addr; do
      [[ -z "$port" || -z "$proto" ]] && continue
      # loopback в любом виде: 127.x, ::1, [::1], 127.0.0.53%lo (systemd-resolved)
      case "$addr" in
        127.*|::1|\[::1\]) continue;;
      esac
      [[ "$proto" == "tcp" ]] && continue   # доктрина 443: TCP наружу только SSH/443 (выше)
      fw_port_locked "$port" && continue
      REQ["$proto:$port"]="${REQ[$proto:$port]:-udp-listen}"
    done < <(scan_ports 2>/dev/null || true)

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
    echo "  7) Снимок состояния"
    echo "  8) Восстановить из снимка"
    echo "  0) Назад"
    line
    local c=""
    read -rp "$(echo -e "${B}Выбор:${N} ")" c || c="0"
    case "$c" in
      1)
        askyn confirm "Применить?" "n"
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
        log "Применено"; pause
        ;;
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
    [[ -t 0 ]] && askyn adg_install "Установить AdGuard Home?" "y"
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
  log "Файрвол: сброс и только необходимое…"
  ufw --force reset >/dev/null 2>&1 || true
  ufw default deny incoming >/dev/null 2>&1 || true
  ufw default allow outgoing >/dev/null 2>&1 || true
  fw_allow "${SSH_PORT:-22}" tcp "SSH"
  fw_allow 443 tcp "HTTPS/SNI"
  local proto port addr
  while IFS="|" read -r proto port addr; do
    [[ -z "$port" || -z "$proto" ]] && continue
    case "$addr" in 127.*|::1*|\[::1\]*) continue;; esac
    [[ "$proto" == "tcp" ]] && continue   # доктрина 443: TCP наружу только SSH/443
    fw_port_locked "$port" && continue
    fw_allow "$port" "$proto" "udp-listen"
  done < <(scan_ports 2>/dev/null || true)
  fw_deny_panel_ports
  ufw --force enable >/dev/null 2>&1 || true
  sleep 1
}

# Действие пункта меню — вызывается в ПОД-ОБОЛОЧКЕ: exit 42 внутри (токен «q»
# в любом вопросе) гасит только её, и мы оказываемся назад в меню.
run_menu_action() {
  case "$1" in
    1) initial_setup ;;
    2) add_inbound; pause ;;
    3) remove_inbound; pause ;;
    4) change_decoy ;;
    5) view_decoy_templates ;;
    6) show_status ;;
    7) decoy_ban_status ;;
    8) backup_config ;;
    9) restore_config ;;
    10) certs_menu ;;
    11) firewall_menu ;;
    12) restore_firewall_state ;;
    13) install_lucx_panel; pause ;;
    14) install_adguard_home; pause ;;
    15) sni_cleanup_stale; pause ;;
    16) uninstall_adguard; pause ;;
    17) uninstall_panel_lucx; pause ;;
    18) change_admin_passwords; pause ;;
    19) update_self; pause ;;
    *) warn "Нет такого пункта"; sleep 1 ;;
  esac
}

main_menu() {
  decoy_full_init || true
  while :; do
    clear
    echo -e "${B}╔══════════════════════════════════════════════════════╗${N}"
    echo -e "${B}║       STACK MANAGER — SNI-роутер + 3x-ui/LucX        ║${N}"
    echo -e "${B}╚══════════════════════════════════════════════════════╝${N}"
    echo "  x-ui.db:  ${XUI_DB:-не найден}"
    if [[ "$ADG_PRESENT" == true ]]; then
      echo "  AdGuard:  ${ADG_SERVICE:-конфиг найден}"
    else
      echo "  AdGuard:  не найден"
    fi
    echo "  Nginx:    $(systemctl is-active nginx 2>/dev/null || echo -)  |  fail2ban: $(systemctl is-active fail2ban 2>/dev/null || echo -)"
    echo "  UFW:      $(ufw status 2>/dev/null | head -1 | awk '{print $2}' || echo unknown)"
    echo "  xray:     ${XRAY_BIN:-не найден}"
    line
    echo "   1) Первичная настройка SNI-роутера"
    echo "   2) Добавить / проверить inbound"
    echo "   3) Удалить inbound"
    echo "   4) Сменить decoy для SNI-домена"
    echo "   5) Просмотр каталога decoy-шаблонов"
    echo "   6) Показать статус"
    echo "   7) Статус login-декоев и управление банами"
    echo "   8) Бэкап конфигурации"
    echo "   9) Восстановить из бэкапа"
    echo "  10) Управление сертификатами"
    echo "  11) Файрвол: только нужные порты"
    echo "  12) Восстановить состояние фаервола из снимка"
    echo "  13) Установить панель LucX UI"
    echo "  14) Установить AdGuard Home"
    echo "  15) Очистка SNI: удалить записи без инбаундов"
    echo "  16) Удалить AdGuard Home"
    echo "  17) Удалить панель LucX UI (x-ui)"
    echo "  18) Сменить пароли admin (панель / AdGuard)"
    echo "  19) Обновить скрипт с GitHub"
    echo "   0) Выход     (q в любом вопросе — выход в меню)"
    line
    local c="" rc
    read -rp "$(echo -e "${B}Выбор:${N} ")" c || c="0"
    detect_env >/dev/null 2>&1 || true     # освежить состояние после прошлого пункта
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
    done < <(sqlite3 "$XUI_DB" "SELECT id, protocol, port, COALESCE(stream_settings,'') FROM inbounds WHERE enable=1 ORDER BY id;" 2>/dev/null)
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
  # Автобэкап x-ui.db + nginx-конфигов стека (последние 5 копий)
  auto_backup_stack
  # deploy-hook renew (сертиф. живут в live/, зеркала нет) + дедупликация
  cert_hook_install
  cert_sync_all
  # если серты появились позже установки — дозаписать пути в инбаунды
  sync_inbound_certs
  [[ -f "$WILDCARD_STATE" ]] && WILDCARD_DOMAIN=$(head -n 1 "$WILDCARD_STATE" 2>/dev/null | tr -d '[:space:]' || true)
  [[ -n "$WILDCARD_DOMAIN" ]] && log "Wildcard-сертификат: *.$WILDCARD_DOMAIN (используется для всех поддоменов)"

  # ПОРЯДОК ВАЖЕН: сначала ПАНЕЛЬ + её сертификат, потом AdGuard
  # (AdGuard берёт сертификат панели/wildcard для своего https).
  auto_full=false   # НЕ local: точка входа — вне функции
  if [[ -z "$XUI_DB" || ! -f "$XUI_DB" ]]; then
    warn "x-ui.db не найден — панель LucX UI не установлена."
    if [[ -z "$PANEL_DOMAIN" ]]; then
      ask PANEL_DOMAIN "Домен панели (A-запись → этот сервер)" "panel.example.com" '^[a-zA-Z0-9.-]+$'
    fi
    askyn install_now "Установить панель LucX UI сейчас?" "y"
    if [[ "$install_now" == true ]]; then
      install_lucx_panel || { err "Не удалось установить панель. Выход."; exit 1; }
      auto_full=true
    else
      err "Без панели работа невозможна. Выход."; exit 1
    fi
  fi

  if [[ "$ADG_PRESENT" != true ]]; then
    warn "AdGuard Home не установлен."
    askyn install_adg "Установить AdGuard Home сейчас?" "y"
    if [[ "$install_adg" == true ]]; then
      install_adguard_home || warn "Установка не удалась — продолжаем без AdGuard."
      detect_env
    fi
  else
    log "AdGuard Home уже установлен (${ADG_SERVICE:-service})"
  fi

  # чистая установка → авто: инбаунды + настройка + UFW + итоговая сводка
  if [[ "$auto_full" == true ]]; then
    auto_full_setup || warn "Автоподъём прошёл не полностью — доделай в меню (п.1 и п.10)."
  fi

  main_menu
fi