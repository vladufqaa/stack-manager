# ВВОД
# =====================================================================
ask() {
  # внутренние имена с __: если целевая переменная тоже называется d/in/p/r,
  # printf -v попадал в локальную ask, а не в вызывающую функцию (потеря ввода)
  local __v="$1" __p="$2" __d="$3" __r="${4:-}" __in
  while :; do
    # Единый read для обеих веток: EOF-защита обязательна в ОБЕИХ. Раньше
    # ветка без дефолта крутилась вечно: EOF → пустой ответ → regex мимо →
    # «Некорректно» → снова read (90k ошибок в авто-установке 28.10).
    if ! read_safe "? ${__p}${__d:+ [${__d}]}: " __in; then
      if [[ -n "$__d" ]]; then
        warn "Ввод завершён (EOF) — принято значение по умолчанию: $__d"
        __in="$__d"
      elif [[ ! -t 0 ]]; then
        warn "Ввод завершён (EOF, авто-ответы) — пустой ответ"
        __in=""
      else
        warn "Ввод завершён (EOF) — возврат в меню"
        exit 42
      fi
    fi
    # Убираем CR от Windows/вставки и пробелы вокруг ответа.
    __in="${__in//$'\r'/}"
    __in="${__in#"${__in%%[![:space:]]*}"}"
    __in="${__in%"${__in##*[![:space:]]}"}"
    [[ -z "$__in" && -n "$__d" ]] && __in="$__d"
    case "${__in,,}" in
      q|quit|exit|выход)
        warn "Прервано — возврат в меню"
        exit 42 ;;          # под-оболочка пункта меню ловит 42 → назад в меню
    esac
    [[ -z "$__r" || "$__in" =~ $__r ]] && { printf -v "$__v" '%s' "$__in"; return; }
    if [[ ! -t 0 ]]; then
      # Авто-ответы (файл/пайп): повторный read бесполезен — вернётся то же
      # самое. Принимаем как есть, чтобы рассинхрон анкеты не превращался
      # в бесконечный спин «Некорректно».
      warn "Авто-ответ не прошёл проверку (${__p}) — принято как есть: ${__in:-<пусто>}"
      printf -v "$__v" '%s' "$__in"
      return
    fi
    err "Некорректно."
  done
}

askyn() {
  local __v="$1" __p="$2" __d="$3" __in
  while :; do
    # Не зацикливаться при stdin без TTY/EOF (например, запуск через tee):
    # в этом случае безопасно принять значение по умолчанию.
    if ! read_safe "? ${__p} [${__d}]: " __in; then
      warn "Ввод недоступен (EOF) — принято значение по умолчанию: $__d"
      __in="$__d"
    fi
    # Убираем CR от Windows/вставки и пробелы вокруг ответа.
    __in="${__in//$'\r'/}"
    __in="${__in#"${__in%%[![:space:]]*}"}"
    __in="${__in%"${__in##*[![:space:]]}"}"
    __in="${__in:-$__d}"
    case "${__in,,}" in
      q|quit|exit|выход)
        warn "Прервано — возврат в меню"
        exit 42 ;;
      y|yes|д|да) printf -v "$__v" 'true'; return;;
      n|no|н|нет) printf -v "$__v" 'false'; return;;
    esac
    if [[ ! -t 0 ]]; then
      # Авто-ответы: повтор бесполезен — берём дефолт, не крутим «y/n».
      if [[ "${__d:0:1}" == "y" || "${__d:0:1}" == "д" ]]; then
        warn "Авто-ответ не распознан (${__p}) — принято значение по умолчанию: $__d"
        printf -v "$__v" 'true'
      else
        warn "Авто-ответ не распознан (${__p}) — принято значение по умолчанию: ${__d:-n}"
        printf -v "$__v" 'false'
      fi
      return
    fi
    err "y/n"
  done
}

pause() { read_safe "Нажмите Enter" _; }
# Ошибка сертификата не должна исчезать среди последующих сообщений.
# В интерактивном мастере обязательно ждём Enter; в автоматическом запуске
# не блокируем stdin, но полный текст ошибки всё равно остаётся в логе.
cert_error_pause() {
  if [[ -t 0 && "${ERROR_PAUSED:-0}" != 1 ]]; then
    pause
  fi
  ERROR_PAUSED=0
}

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
# Единые проверки состояния стека — не дублировать проверки путей по меню.
sni_router_present() {
  [[ -f "$SNI_CONF" || -f /etc/nginx/streams-enabled/sni-router.conf || -f /etc/nginx/streams-available/sni-router.conf ]]
}
stack_heal_present() {
  [[ -f /etc/systemd/system/stack-heal.timer || -f /etc/systemd/system/stack-heal.service ]] || \
    systemctl is-enabled --quiet stack-heal.timer 2>/dev/null || \
    systemctl is-active --quiet stack-heal.timer 2>/dev/null
}
nginx_ready() {
  command -v nginx >/dev/null 2>&1 && [[ -f /etc/nginx/nginx.conf ]]
}

# Безопасное восстановление связки SNI-файлов без пересоздания инбаундов.
# Ничего не меняет в БД и не генерирует новые маршруты.

# Пересборка SNI-карты из текущей БД, без изменений БД и сертификатов.
rebuild_sni_from_db() {
  line; echo -e "${B}   ПЕРЕСБОРКА SNI ИЗ ТЕКУЩЕЙ БД${N}"; line
  nginx_ready || { err "nginx или nginx.conf отсутствует"; pause; return 1; }
  [[ -f "$XUI_DB" && -f "$SNI_CONF" ]] || { err "Нужны x-ui.db и существующий SNI-конфиг"; pause; return 1; }
  local pd="${PANEL_DOMAIN:-}"; [[ -z "$pd" ]] && pd=$(xui_get webDomain 2>/dev/null || true)
  [[ "$pd" =~ ^[A-Za-z0-9.-]+$ ]] || { err "Некорректный домен панели"; pause; return 1; }
  local tmp bak rows count=0 id proto port dom backend sec dest
  tmp=$(mktemp "${SNI_CONF}.rebuild.XXXXXX") || { err "Не удалось создать временный SNI-конфиг"; pause; return 1; }
  if ! rows=$(python3 - "$XUI_DB" <<'PY'
import sqlite3,json,sys,re
con=sqlite3.connect(sys.argv[1]); con.row_factory=sqlite3.Row
skip={'wireguard','amnezia','amneziawg','awg','qwdtt','csqtt','csqdt','mtproto','tun'}
for r in con.execute("SELECT id,protocol,port,settings,stream_settings FROM inbounds WHERE enable=1 AND port>0 ORDER BY id"):
    try: s=json.loads(r['settings'] or '{}'); t=json.loads(r['stream_settings'] or '{}')
    except Exception: continue
    net=(t.get('network') or '').lower(); proto=(r['protocol'] or '').lower()
    if proto in skip or net in ('udp','quic'): continue
    dom=s.get('domain') or s.get('hostname') or s.get('sni')
    tls=t.get('tlsSettings') or {}; dom=dom or tls.get('serverName')
    rs=t.get('realitySettings') or {}; names=rs.get('serverNames') or []
    dom=dom or (names[0] if names else '')
    if not isinstance(dom,str) or not re.fullmatch(r'[A-Za-z0-9.-]+',dom): continue
    dest=rs.get('dest') or rs.get('target') or ''
    backend='tproxy' if proto=='tproxy' else f'inb_{r["id"]}_backend'
    port=11443 if proto=='tproxy' else int(r['port'])
    print(f'{r["id"]}|{proto}|{port}|{dom}|{backend}|{dest}')
PY
); then
    rm -f "$tmp"
    err "Не удалось прочитать БД при пересборке SNI"
    pause; return 1
  fi
  {
    echo 'map $ssl_preread_server_name $backend {'
    echo '    default                       panel_backend;'
    printf '    %-30s panel_backend;\n' "$pd"
    while IFS='|' read -r id proto port dom backend sec dest; do
      [[ -n "$dom" ]] || continue
      printf '    %-30s %s;\n' "$dom" "$backend"
      count=$((count+1))
    done <<<"$rows"
    # Сохраняем существующий AdGuard SNI-маршрут, если он был.
    awk '/^[[:space:]]+[A-Za-z0-9.-]+[[:space:]]+agh_backend;/{print}' "$SNI_CONF" 2>/dev/null
    # CDN-профили: SNI origin/cdn → единый локальный TLS-фронтенд nginx
    cdn_profiles_load
    local _cp_row _cp_origin _cp_cdn
    while IFS='|' read -r _cp_row; do
      _cp_origin=$(printf '%s' "$_cp_row" | cut -d'|' -f3)
      _cp_cdn=$(printf '%s' "$_cp_row" | cut -d'|' -f4)
      [[ -n "$_cp_origin" ]] && { printf '    %-30s cdn_frontend;\n' "$_cp_origin"; count=$((count+1)); }
      [[ -n "$_cp_cdn" ]] && printf '    %-30s cdn_frontend;\n' "$_cp_cdn"
    done < <(cat "$CDN_PROFILES" 2>/dev/null)
    echo '}'
    echo
    echo 'upstream panel_backend { server 127.0.0.1:4443; }'
    # cdn_frontend — только если есть хотя бы один CDN-профиль
    if [[ -s "$CDN_PROFILES" ]]; then
      echo "upstream cdn_frontend { server 127.0.0.1:$CDN_FE_PORT; }"
    fi
    while IFS='|' read -r id proto port dom backend sec dest; do
      [[ -n "$backend" ]] || continue
      printf 'upstream %s { server 127.0.0.1:%s; }\n' "$backend" "$port"
    done <<<"$rows"
    if grep -q '^upstream agh_backend[[:space:]]*{' "$SNI_CONF" 2>/dev/null; then
      awk '/^upstream agh_backend[[:space:]]*\{/{p=1} p{print} p&&/^}/{exit}' "$SNI_CONF"
    fi
    echo
    echo 'server {'
    echo '    listen 443;'
    echo '    proxy_pass $backend;'
    echo '    ssl_preread on;'
    echo '    proxy_connect_timeout 5s;'
    echo '    proxy_timeout 10m;'
    echo '}'
  } > "$tmp" || { rm -f "$tmp"; err "Не удалось записать временный SNI-конфиг"; pause; return 1; }
  bak="${SNI_CONF}.bak-rebuild-$(date +%Y%m%d-%H%M%S)"
  cp -a "$SNI_CONF" "$bak" || { rm -f "$tmp"; err "Не удалось сохранить резервную копию SNI"; pause; return 1; }
  mv -f "$tmp" "$SNI_CONF" || { rm -f "$tmp"; err "Не удалось заменить SNI-конфиг"; pause; return 1; }
  if ! nginx -t 2>/dev/null; then
    mv -f "$bak" "$SNI_CONF"; err "nginx -t не прошёл — исходный SNI восстановлен"; nginx -t 2>&1 | tail -6; pause; return 1
  fi
  mkdir -p /etc/nginx/streams-available 2>/dev/null || true
  rm -f /etc/nginx/streams-available/sni-router.conf 2>/dev/null || true
  ln -s "$SNI_CONF" /etc/nginx/streams-available/sni-router.conf 2>/dev/null || cp -f "$SNI_CONF" /etc/nginx/streams-available/sni-router.conf 2>/dev/null || true
  nginx_reload || { mv -f "$bak" "$SNI_CONF"; nginx_reload >/dev/null 2>&1 || true; err "SNI заменён, но nginx не перезагрузился — восстановлен старый"; pause; return 1; }
  log "SNI пересобран из БД: маршрутов $count; БД и сертификаты не менялись."
  pause
}

ensure_deps() {  local missing=() t
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
    apt-get update -y >/dev/null 2>&1 || { err "apt-get update не удался — зависимости не установлены"; return 1; }
    apt-get install -y "${missing[@]}" >/dev/null 2>&1 || { err "apt-get install не удался: ${missing[*]}"; return 1; }
  fi
  local _need _miss_after=()
  for _need in sqlite3 jq curl ss nginx certbot openssl dig ufw fail2ban-client nc xxd; do
    command -v "$_need" >/dev/null 2>&1 || _miss_after+=("$_need")
  done
  dpkg -s libnginx-mod-stream >/dev/null 2>&1 || _miss_after+=(libnginx-mod-stream)
  if [[ ${#_miss_after[@]} -gt 0 ]]; then
    err "После установки отсутствуют зависимости: ${_miss_after[*]}"
    return 1
  fi
  # nginx числится установленным, но конфигов /etc/nginx нет ИЛИ набор усечён
  # (после отката/демонтажа apt не возвращает conffiles — считает их «удалёнными
  # администратором»). Проверяем не только nginx.conf: без mime.types/snippets
  # nginx вообще не стартует, а без modules-enabled динамический модуль stream не
  # подключается и директива stream становится «unknown directive».
  local _ngx_missing=() _ngxf
  [[ -f /etc/nginx/nginx.conf ]] || _ngx_missing+=(nginx.conf)
  for _ngxf in mime.types fastcgi_params uwsgi_params scgi_params \
               snippets/fastcgi-php.conf snippets/snakeoil.conf; do
    [[ -f "/etc/nginx/$_ngxf" ]] || _ngx_missing+=("$_ngxf")
  done
  if dpkg -s nginx >/dev/null 2>&1 && [[ ${#_ngx_missing[@]} -gt 0 ]]; then
    log "nginx: не хватает файлов конфигурации (${_ngx_missing[*]}) — переустанавливаю пакеты (conffiles)"
    local _ngx_pkgs
    _ngx_pkgs=$(dpkg -l 2>/dev/null | awk '/^ii/ && $2 ~ /nginx/ {print $2}' | tr '\n' ' ')
    [[ -z "$_ngx_pkgs" ]] && _ngx_pkgs="nginx nginx-common nginx-full"
    local -a _ngx_pkgs_arr=()
    read -r -a _ngx_pkgs_arr <<< "$_ngx_pkgs"
    apt-get install -y --reinstall -o Dpkg::Options::=--force-confmiss "${_ngx_pkgs_arr[@]}" >/dev/null 2>&1 || true
    if [[ ! -f /etc/nginx/nginx.conf ]]; then
      # nginx.conf и базовые каталоги принадлежат nginx-common, а не всегда
      # пакету nginx. force-confmiss нужен для conffile, удалённого вручную.
      apt-get install -y --reinstall -o Dpkg::Options::=--force-confmiss \
        nginx nginx-common nginx-core nginx-full >/dev/null 2>&1 || true
    fi
    if [[ ! -f /etc/nginx/nginx.conf ]]; then
      mkdir -p /etc/nginx/{sites-available,sites-enabled,streams-available,streams-enabled,snippets,conf.d} 2>/dev/null || true
      # После ручного rm -rf dpkg иногда считает nginx.conf «удалённым
      # администратором» и не возвращает conffile даже с reinstall. В этом
      # случае берём штатный конфиг непосредственно из deb-пакета.
      local _ngx_tmp="" _got=""
      _ngx_tmp=$(mktemp -d /tmp/nginx-common.XXXXXX 2>/dev/null || true)
      if [[ -n "$_ngx_tmp" ]] && (cd "$_ngx_tmp" && apt-get download nginx-common >/dev/null 2>&1); then
        _got=$(ls -1t "$_ngx_tmp"/nginx-common_*.deb 2>/dev/null | head -1 || true)
        if [[ -n "$_got" ]]; then
          dpkg-deb --fsys-tarfile "$_got" 2>/dev/null | tar -xOf - ./etc/nginx/nginx.conf > /etc/nginx/nginx.conf 2>/dev/null || true
        fi
      fi
      rm -rf "$_ngx_tmp" 2>/dev/null || true
    fi
    # Последний fallback: минимальный рабочий конфиг. Он достаточен для
    # последующей сборки stack.conf и SNI-router; пакетный conffile мог быть
    # недоступен из-за DNS/репозитория или нестандартного состояния dpkg.
    if [[ ! -f /etc/nginx/nginx.conf ]]; then
      cat > /etc/nginx/nginx.conf <<'NGINXCFG'
# Загружаем stream-модуль до events (нужен для SNI на 443).
load_module /usr/lib/nginx/modules/ngx_stream_module.so;
user www-data;
worker_processes auto;
pid /run/nginx.pid;
error_log /var/log/nginx/error.log;
events { worker_connections 1024; }
stream { include /etc/nginx/streams-enabled/*.conf; }
http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    access_log /var/log/nginx/access.log;
    sendfile on;
    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
NGINXCFG
      [[ -f /etc/nginx/nginx.conf ]] && log "  создан минимальный базовый /etc/nginx/nginx.conf"
    fi
    if [[ ! -f /etc/nginx/nginx.conf ]]; then
      err "  nginx.conf не восстановлен: проверь состояние nginx-пакетов и DNS репозитория"
      err "  Выполни: apt-get update && apt-get install -y --reinstall nginx nginx-common"
      return 1
    else
      log "  /etc/nginx восстановлен"
    fi
  fi
  # Модуль stream (443/SNI): подключаем сразу, иначе сборка с --with-stream=dynamic
  # не знает директиву stream и любой stream-блок ломает конфиг целиком.
  if ! nginx_stream_module_enable; then
    warn "nginx: модуль stream не подключился — 443/SNI работать не будет (проверь пакет libnginx-mod-stream)"
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
