# NGINX ХЕЛПЕРЫ
# =====================================================================
sni_conf_ensure() {
  local d
  d=$(dirname "$SNI_CONF")
  mkdir -p "$d" /etc/nginx/streams-enabled /etc/nginx/streams-available 2>/dev/null || true
  # SNI_CONF уже находится в streams-enabled. Нельзя создавать ссылку
  # /streams-enabled/sni-router.conf -> самому себе: это даёт ELOOP.
  if [[ -L "$SNI_CONF" ]]; then
    local _sni_target=""
    _sni_target=$(readlink -f "$SNI_CONF" 2>/dev/null || true)
    rm -f "$SNI_CONF" 2>/dev/null || true
    # Если старый self-link был единственным объектом, создаём обычный файл.
    [[ -n "$_sni_target" && -f "$_sni_target" && "$_sni_target" != "$SNI_CONF" ]] && cp -f "$_sni_target" "$SNI_CONF" 2>/dev/null || true
  fi
  if [[ ! -s "$SNI_CONF" ]]; then
    cat > "$SNI_CONF" <<'EOF'
map $ssl_preread_server_name $backend {
    default panel_backend;
}
upstream panel_backend { server 127.0.0.1:4443; }
server {
    listen 443;
    proxy_pass $backend;
    ssl_preread on;
    proxy_connect_timeout 5s;
    proxy_timeout 10m;
}
EOF
  fi
}
sni_upstream_add() {
  local name="$1" port="$2"
  sni_conf_ensure
  grep -q "upstream $name " "$SNI_CONF" 2>/dev/null && return 0
  if grep -q "^upstream panel_backend" "$SNI_CONF" 2>/dev/null; then
    sed -i "/^upstream panel_backend/i upstream $name { server 127.0.0.1:$port; }" "$SNI_CONF"
  else
    # нет якоря panel_backend — вставляем в начало файла
    sed -i "1i upstream $name { server 127.0.0.1:$port; }" "$SNI_CONF"
  fi
}
sni_upstream_remove() { sed -i "/^upstream $1 /d" "$SNI_CONF" 2>/dev/null || true; }

sni_conf_repair_map() {
  # Удаляет из map повреждённые строки с лишними параметрами. Такие строки
  # возникают после старых/прерванных запусков CDN и делают nginx -t фатальным.
  [[ -f "$SNI_CONF" && ! -L "$SNI_CONF" ]] || return 0
  awk '
    /^[[:space:]]*map[[:space:]]/ { inmap=1; print; next }
    inmap && /^[[:space:]]*}/ { inmap=0; print; next }
    inmap {
      line=$0; sub(/^[[:space:]]+/,"",line); sub(/[[:space:]]+$/, "", line)
      if (line == "" || line ~ /^#/) next
      n=split(line,a,/[[:space:]]+/)
      if (n == 2) {
        sub(/;$/, "", a[2])
        print "    " a[1] "    " a[2] ";"
      }
      next
    }
    { print }
  ' "$SNI_CONF" > "$SNI_CONF.tmp" && mv "$SNI_CONF.tmp" "$SNI_CONF"
}
sni_map_add() {
  local domain="$1" backend="$2"
  [[ "$domain" =~ ^[A-Za-z0-9._-]+$ && "$backend" =~ ^[A-Za-z0-9._-]+$ ]] || return 1
  sni_conf_ensure
  sni_conf_repair_map
  # В map nginx каждый домен должен встречаться ровно один раз. Если старый
  # запуск оставил дубликаты, удаляем их перед добавлением нового маршрута.
  awk -v dom="$domain" -v be="$backend" '
    BEGIN { inmap=0; kept=0 }
    /^[[:space:]]*map[[:space:]]/ { inmap=1; print; next }
    inmap && /^[[:space:]]*}/ { inmap=0; print; next }
    inmap && $1 == dom {
      if (!kept) { print "    " dom "    " be ";"; kept=1 }
      next
    }
    { print }
  ' "$SNI_CONF" > "$SNI_CONF.tmp" && mv "$SNI_CONF.tmp" "$SNI_CONF"
  if awk -v dom="$domain" '$1 == dom { found=1 } END { exit(found ? 0 : 1) }' "$SNI_CONF" 2>/dev/null; then
    awk -v dom="$domain" -v be="$backend" 'BEGIN{OFS=" "} $1 == dom {$0="    " dom "    " be ";"} {print}' "$SNI_CONF" > "$SNI_CONF.tmp" && mv "$SNI_CONF.tmp" "$SNI_CONF"
    return 0
  fi
  awk -v dom="$domain" -v be="$backend" '
    /^[[:space:]]*map[[:space:]]/ { inmap=1 }
    inmap && /^[[:space:]]*}/ && !done { print "    " dom "    " be ";"; done=1 }
    { print }
  ' "$SNI_CONF" > "$SNI_CONF.tmp" && mv "$SNI_CONF.tmp" "$SNI_CONF"
  sni_conf_repair_map
}
sni_map_remove() { sed -i "/^[[:space:]]*${1}[[:space:]]\+/d" "$SNI_CONF" 2>/dev/null || true; }
# Удаление по backend надёжнее доменного имени: чистит SNI даже если строка
# была отформатирована нестандартно или домен не прочитался из карты.
sni_map_remove_backend() { sed -i "/^[[:space:]]*[A-Za-z0-9.-][A-Za-z0-9.-]*[[:space:]]\+${1};[[:space:]]*$/d" "$SNI_CONF" 2>/dev/null || true; }

nginx_reload() {
  if ! command -v nginx >/dev/null 2>&1; then
    warn "nginx не установлен — проверка/перезагрузка пропущена"
    return 0
  fi
  # СТРИМ-конфиг (443/SNI) обязан быть подключён ДО старта/перезагрузки nginx:
  # если nginx поднимется раньше, чем в nginx.conf появится
  # `include /etc/nginx/streams-enabled/*.conf`, порт 443 не откроется вообще
  # (в логе будет «Nginx запущен», а панель и все домены снаружи недоступны).
  # Сначала — модуль stream: в сборках Ubuntu он динамический, и без
  # load_module директива stream делает конфиг невалидным целиком.
  nginx_stream_module_enable >/dev/null 2>&1 || true
  ensure_stream_include >/dev/null 2>&1 || true
  # Перед каждой проверкой nginx повторно нормализуем map: это также чинит
  # старые повреждённые записи, созданные до обновления скрипта.
  sni_conf_repair_map >/dev/null 2>&1 || true
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

# ── Модуль stream (SNI-роутер на 443) ──────────────────────────────────
# В сборках Ubuntu/Debian stream собран как ДИНАМИЧЕСКИЙ модуль
# (--with-stream=dynamic) и доступен только после load_module. Откат/демонтаж
# часто уносит /etc/nginx/modules-enabled — тогда блок stream{} в nginx.conf
# делает конфиг невалидным («unknown directive "stream"»), nginx не стартует
# вообще, а панель и все домены становятся недоступны.
NGX_STREAM_SO="/usr/lib/nginx/modules/ngx_stream_module.so"

# Сборка nginx вообще умеет stream?
nginx_stream_resolvable() {
  nginx -V 2>&1 | tr ' ' '\n' | grep -q '^--with-stream'
}

# Директива stream реально доступна этому бинарю.
#   • статическая сборка (--with-stream без =dynamic) — модуль внутри бинаря;
#   • динамическая (--with-stream=dynamic) — нужен load_module, то есть файл
#     в /etc/nginx/modules-enabled, ссылающийся на ngx_stream_module.so.
# ВАЖНО: пакетный 50-mod-stream.conf — СИМЛИНК, а `grep -r` по симлинкам не
# ходит (нужен -R) — из-за этого детектор ошибочно считал модуль отсутствующим.
nginx_stream_loaded() {
  nginx_stream_resolvable || return 1
  nginx -V 2>&1 | grep -q -- '--with-stream=' || return 0
  [[ -f "$NGX_STREAM_SO" ]] || return 1
  local f
  for f in /etc/nginx/modules-enabled/*; do
    [[ -f "$f" ]] || continue          # -f верен и для рабочего симлинка
    grep -qs 'load_module.*stream' "$f" 2>/dev/null && return 0
  done
  return 1
}

# Подключить модуль stream. 0 — доступен, 1 — подключить не удалось.
nginx_stream_module_enable() {
  nginx_stream_loaded && return 0
  nginx_stream_resolvable || return 1
  if [[ ! -f "$NGX_STREAM_SO" ]]; then
    # после отката пакет числится установленным, а файлы могут быть снесены:
    # сначала обновляем списки, потом переустанавливаем пакет целиком
    DEBIAN_FRONTEND=noninteractive apt-get update -y >/dev/null 2>&1 || true
    DEBIAN_FRONTEND=noninteractive apt-get install -y --reinstall libnginx-mod-stream >/dev/null 2>&1 || true
  fi
  [[ -f "$NGX_STREAM_SO" ]] || return 1
  mkdir -p /etc/nginx/modules-enabled 2>/dev/null || true
  local _mf="/etc/nginx/modules-enabled/50-mod-stream.conf"
  # Рабочий файл пакета (симлинк) не трогаем; битый/пустой/чужой — заменяем
  # обычным файлом с абсолютным путём к модулю.
  if [[ -f "$_mf" ]] && grep -qs 'load_module.*stream' "$_mf" 2>/dev/null; then
    :
  else
    rm -f "$_mf" 2>/dev/null || true
    printf 'load_module %s;\n' "$NGX_STREAM_SO" > "$_mf" 2>/dev/null || true
  fi
  # nginx.conf обязан подключать modules-enabled — после правок/отката строка
  # могла исчезнуть, и тогда load_module не сработает
  if ! grep -q 'modules-enabled' /etc/nginx/nginx.conf 2>/dev/null; then
    sed -i '1i include /etc/nginx/modules-enabled/*.conf;' /etc/nginx/nginx.conf 2>/dev/null || true
  fi
  nginx_stream_loaded
}

ensure_stream_include() {
  grep -q "streams-enabled" /etc/nginx/nginx.conf 2>/dev/null && return 0
  # Сначала модуль: без него stream{} — фатальная ошибка конфига, nginx не
  # поднимется вообще. Если модуль недоступен — блок НЕ пишем (443/SNI не
  # поднять, но остальной стек остаётся рабочим).
  if ! nginx_stream_module_enable; then
    warn "nginx без модуля stream (libnginx-mod-stream): SNI-роутер (443) не подключить, stream-блок в nginx.conf не добавляю — иначе nginx не стартует"
    return 1
  fi
  local _bak=""
  if [[ -f /etc/nginx/nginx.conf ]]; then
    _bak=$(mktemp /tmp/nginx.conf.bak.XXXXXX 2>/dev/null || true)
    [[ -n "$_bak" ]] && { cp -f /etc/nginx/nginx.conf "$_bak" 2>/dev/null || true; }
  fi
  if ! grep -qE '^\s*stream\s*\{' /etc/nginx/nginx.conf 2>/dev/null; then
    sed -i '/^\s*http\s*{/i stream {\n    include /etc/nginx/streams-enabled/*.conf;\n}\n' /etc/nginx/nginx.conf
  else
    sed -i '/^\s*stream\s*{/a \    include /etc/nginx/streams-enabled/*.conf;' /etc/nginx/nginx.conf
  fi
  # Контроль: битый конфиг откатываем, чтобы nginx остался рабочим
  if ! nginx -t >/dev/null 2>&1; then
    if [[ -n "$_bak" && -f "$_bak" ]]; then
      cp -f "$_bak" /etc/nginx/nginx.conf 2>/dev/null || true
      warn "правка nginx.conf (stream-блок) не прошла nginx -t — конфиг возвращён как был"
    fi
    rm -f "$_bak" 2>/dev/null || true
    return 1
  fi
  rm -f "$_bak" 2>/dev/null || true
  return 0
}

# Фактическая проверка 443/SNI: без него панель и все домены недоступны снаружи,
# поэтому «п.1 завершён» при мёртвом 443 — ложь. Печатает причину и лечение.
nginx_443_check() {   # [quiet]
  local q="${1:-0}" _i=0
  # после reload воркер биндит 443 не мгновенно — даём несколько секунд
  while (( _i < 5 )); do
    if ss -tlnH 'sport = :443' 2>/dev/null | grep -q .; then
      (( q )) || log "443/SNI слушается — панель и домены доступны снаружи"
      return 0
    fi
    sleep 1; _i=$((_i+1))
  done
  err "443/SNI НЕ слушается — панель и все домены недоступны снаружи!"
  if ! nginx_stream_resolvable; then
    err "  причина: nginx собран без модуля stream — установи пакет nginx с модулем stream"
  elif ! nginx_stream_loaded; then
    err "  причина: модуль stream не подключён. Лечение: apt-get update && apt-get install -y --reinstall libnginx-mod-stream, затем повтори п.1"
  elif ! grep -q 'streams-enabled' /etc/nginx/nginx.conf 2>/dev/null; then
    err "  причина: в nginx.conf нет включения SNI-карты (streams-enabled) — повтори п.1"
  elif ! nginx -t >/dev/null 2>&1; then
    err "  причина: конфиг nginx не проходит проверку — смотри вывод nginx -t выше"
  else
    err "  причина: nginx не запущен или не перечитал конфиг — проверь systemctl status nginx"
  fi
  return 1
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
