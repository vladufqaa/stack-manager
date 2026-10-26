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
  # какой панели принадлежит найденная БД: lucx | 3x-ui | none
  PANEL_FLAVOR=$(detect_panel_flavor)

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

# Консервативно определяет внешний Reality по фактическому dest/target,
# а не по закрытому списку REALITY_TARGETS.
reality_external_dest() {
  local id="$1" d=""
  d=$(sqlite3 "$XUI_DB" "SELECT COALESCE(json_extract(stream_settings,'\$.realitySettings.dest'),json_extract(stream_settings,'\$.realitySettings.target'),'') FROM inbounds WHERE id=$id;" 2>/dev/null || true)
  d="${d%%:*}"
  [[ -n "$d" && "$d" != "127.0.0.1" && "$d" != "::1" && "$d" != "localhost" ]]
}

# Единая read-only классификация decoy-политики для inbound.
decoy_policy_classify() {
  local id="$1" proto="$2" stream="${3:-}"
  [[ "$proto" == "tproxy" ]] && { echo tproxy; return 0; }
  if grep -qi '"security"[[:space:]]*:[[:space:]]*"reality"' <<<"$stream"; then
    if reality_external_dest "$id"; then echo reality-external; else echo reality-local; fi
    return 0
  fi
  case "$proto" in
    openflux|open-flux)
      echo no-decoy ;;
    naive|anytls|trusttunnel|trust-tunnel|hysteria|hysteria2|qwdtt|csqtt|csqdtt|wireguard|amnezia|amneziawg|awg|mtproto|tun)
      echo unsupported ;;
    *) echo no-decoy ;;
  esac
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

# Заморозка самолечения и защита БД выведены из архитектуры: отклонения
# чинятся вручную через меню. db_protect_on/off/remove — no-op заглушки,
# оставленные под существующие вызовы; отдельного состояния защиты нет.
db_protect_on() { return 0; }
db_protect_off() { return 0; }

# Для функций скрипта, осознанно меняющих защищённые ключи (dest/target,
# литералы сертов, certFile/keyFile/hostname).
#
# ВАЖНО (исправление): раньше здесь стояла RETURN-ловушка
# (`trap 'db_protect_on' RETURN`), но bash выполняет RETURN-ловушку СРАЗУ при
# возврате из самой db_protect_suspend — триггеры возвращались ДО правки, и
# каждая запись dest/сертов молча откатывалась триггером, хотя скрипт писал
# «Reality dest → …». Отсюда вечный цикл «автопочинки» каждые 2 минуты и
# расхождение конфига с работающим nginx.
#
# Теперь триггеры не роняются: ставится «аренда» (строка в sm_protect_off), при
# которой sm_prot_inb не вмешивается. Аренда снимается явно
# (db_protect_resume) либо истекает сама через 15 минут — защита не остаётся
# выключенной навсегда.
DB_PROTECT_SUSPENDED=0
db_protect_suspend() { return 0; }
db_protect_resume() { return 0; }

# =====================================================================
