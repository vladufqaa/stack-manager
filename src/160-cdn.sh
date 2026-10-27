# CDN-РЕЖИМ XHTTP: общая механика (профили, nginx-фронтенд, маршрутизация)
# =====================================================================
# Кандидат на CDN: ЛЮБОЙ протокол с транспортом xhttp, у которого
# security нет/none (идеальный вход) или tls (существующий, будет переведён).
inbound_was_created_as_tls_xhttp() {   # <inbound_id>
  local id="$1" listed=" ${XHTTP_TLS_CREATED_IDS:-} "
  [[ " $listed " == *" $id "* ]]
}

# TLS/Reality XHTTP никогда не предлагает CDN. Проверяем сохранённую запись,
# а не только временный список ID, который теряется при повторном запуске меню.
inbound_xhttp_has_tls_or_reality() {   # <stream_json>
  local s="$1"
  grep -Eqi '"security"[[:space:]]*:[[:space:]]*"(tls|reality)"' <<<"$s"
}

inbound_is_xhttp_cdn_candidate() {   # <stream_json>
  local s="$1"
  [[ -z "$s" ]] && return 1
  grep -Eqi '"network"[[:space:]]*:[[:space:]]*"xhttp"' <<<"$s" || return 1
  if   grep -Eqi '"security"[[:space:]]*:[[:space:]]*"tls"' <<<"$s"; then return 0; fi
  if   grep -Eqi '"security"[[:space:]]*:[[:space:]]*"none"' <<<"$s"; then return 0; fi
  grep -Eqi '"security"' <<<"$s" || return 0   # ключа нет вообще = security none
  return 1
}

# «exemple» из origin-домена: ts.exemple.ru → exemple; exemple.ru → exemple
cdn_base_from_origin() {
  local o="${1%%.*}" rest="${1#*.}"
  if [[ "$rest" == *.* ]]; then
    printf '%s' "${rest%%.*}"          # ≥3 меток: база = вторая метка
  else
    printf '%s' "$o"                   # 2 метки: база = первая
  fi
}
cdn_default_path() { printf '/api/stream/%s.m3u8' "$(cdn_base_from_origin "$1")"; }

# Профили CDN: id|proto|origin|cdn|path|tpl|decoy_port
cdn_profiles_load() {
  CDN_PROFILE_IDS=()
  [[ -s "$CDN_PROFILES" ]] || return 0
  local l id
  local -a _stale=()
  while IFS= read -r l; do
    id="${l%%|*}"
    [[ "$id" =~ ^[0-9]+$ ]] || continue
    if [[ -f "$XUI_DB" ]] && [[ "$(sqlite3 "$XUI_DB" "SELECT COUNT(*) FROM inbounds WHERE id=$id;" 2>/dev/null || echo 0)" == "0" ]]; then
      _stale+=("$id")
    else
      CDN_PROFILE_IDS+=("$id")
    fi
  done < "$CDN_PROFILES"
  # Удаляем осиротевшие профили после удаления инбаунда, чтобы старый ID
  # не появлялся в меню decoy и не восстанавливался автопочинкой.
  local _sid _srow _sorigin _sdport _tmp
  for _sid in "${_stale[@]}"; do
    _srow=$(grep -m1 -E "^${_sid}\\|" "$CDN_PROFILES" 2>/dev/null || true)
    _sorigin=$(printf '%s' "$_srow" | cut -d'|' -f3)
    _sdport=$(printf '%s' "$_srow" | cut -d'|' -f7)
    [[ -n "$_sorigin" ]] && stack_cdn_del "$_sorigin" 2>/dev/null || true
    [[ "$_sdport" =~ ^[0-9]+$ && "$_sdport" != "0" ]] && stack_del_decoy "$_sorigin" 2>/dev/null || true
    sqlite3 "$XUI_DB" "DELETE FROM hosts WHERE inbound_id=$_sid;" 2>/dev/null || true
    _tmp=$(mktemp)
    grep -vE "^${_sid}\\|" "$CDN_PROFILES" > "$_tmp" 2>/dev/null || true
    mv -f "$_tmp" "$CDN_PROFILES"
    warn "Удалён осиротевший CDN-профиль #$_sid: инбаунд отсутствует"
  done
}
cdn_profile_get() {   # <id> → печатает строку профиля (пусто — нет)
  [[ -s "$CDN_PROFILES" ]] || return 1
  grep -m1 -E "^${1}\|" "$CDN_PROFILES" 2>/dev/null
}
cdn_profile_field() {   # <id> <номер поля 1..8> → значение
  local row; row=$(cdn_profile_get "$1") || return 1
  printf '%s' "$row" | cut -d'|' -f"$2"
}
cdn_profile_provider() {   # <id> → beget|yandex|other|"" (старые профили без поля)
  local row; row=$(cdn_profile_get "$1") || return 1
  printf '%s' "$row" | cut -d'|' -f8
}
cdn_provider_label() {   # <код> → человекочитаемое имя провайдера
  case "$1" in
    beget)  printf 'Beget' ;;
    yandex) printf 'Yandex Cloud' ;;
    other)  printf 'Свой CDN' ;;
    *)      printf 'не указан' ;;
  esac
}
cdn_profile_save_add() {   # <id> <proto> <origin> <cdn> <path> <tpl> <decoy_port> [provider]
  cdn_profile_remove "$1"
  mkdir -p "$(dirname "$CDN_PROFILES")" 2>/dev/null || true
  printf '%s|%s|%s|%s|%s|%s|%s|%s\n' "$1" "$2" "$3" "$4" "$5" "$6" "$7" "${8:-}" >> "$CDN_PROFILES"
}
cdn_profile_remove() {   # <id>
  [[ -s "$CDN_PROFILES" ]] || return 0
  local tmp; tmp=$(mktemp)
  grep -vE "^${1}\|" "$CDN_PROFILES" > "$tmp" 2>/dev/null || true
  mv -f "$tmp" "$CDN_PROFILES"
}

# Домены CDN-фронтов (поле 4 профилей: то, что привязано к внешнему CDN).
# Это НЕ наши домены: серт на них не выпускается (TLS терминирует CDN) и в SAN
# они не включаются. ORIGIN (поле 3) — наш домен, он в SAN идёт как обычно.
cdn_front_domains() {   # домены-фронты из $CDN_PROFILES (4-е поле)
  local f="$CDN_PROFILES" row
  [[ -s "$f" ]] || return 0
  while IFS= read -r row; do
    [[ -n "$row" ]] || continue
    row="${row//$'\r'/}"
    printf '%s\n' "$(printf '%s' "$row" | cut -d'|' -f4)"
  done < "$f"
}

# Является ли домен CDN-фронтом (исключается из SAN)
cdn_front_domain_is() {   # <domain>
  local d="${1:-}" x
  [[ -n "$d" ]] || return 1
  while IFS= read -r x; do
    [[ -n "$x" && "$x" == "$d" ]] && return 0
  done < <(cdn_front_domains)
  return 1
}

# Удалить cdn-блок по домену (маркеры # >>> cdn ... domain=X)
stack_cdn_del() {
  local dom="$1"
  [[ -f "$STACK_CONF" ]] || return 0
  local tmp
  tmp=$(mktemp)
  awk -v dom="$dom" '
    !skip && index($0, "# >>> cdn ") == 1 {
      tail = $0
      sub(/^.* domain=/, "", tail)
      if (tail == dom) { skip = 1; next }
    }
    skip && index($0, "# <<< cdn ") == 1 { skip = 0; next }
    !skip { print }
  ' "$STACK_CONF" > "$tmp" 2>/dev/null && mv "$tmp" "$STACK_CONF"
}

# Upsert cdn-блока: TLS-фронтенд на loopback, запросы строго на транспортный
# путь уходят в xray (голый xhttp), всё остальное — в decoy ORIGIN-домена.
stack_cdn_upsert() {   # <origin> <cdn> <path> <inb_port> <decoy_port> <cert> <key>
  local origin="$1" cdn="$2" path="$3" inb_port="$4" decoy_port="$5" cert="$6" key="$7"
  # префикс для сессионных запросов: xhttp при sessionIDPlacement=path просит
  # $path/<sessionID>?... — ловим префиксом, «$path/» без добавления, если путь
  # сам заканчивается на /
  local loc_prefix="$path/"
  [[ "$path" == */ ]] && loc_prefix="$path"
  stack_ensure
  stack_cdn_del "$origin"
  {
    echo "# >>> cdn origin=$origin cdn=$cdn path=$path inb=$inb_port decoy=$decoy_port domain=$origin"
    cat <<EOF
server {
    listen 127.0.0.1:$CDN_FE_PORT ssl;
    server_name $origin $cdn;
    ssl_certificate     $cert;
    ssl_certificate_key $key;
    include /etc/nginx/snippets/decoy-headers.conf;
    access_log $DECOY_LOG_ACCESS decoy_ext;
    error_log  /var/log/nginx/decoy-error.log;
    location = $path {
        # HEAD/GET без сессионных признаков — «проверка доступности» клиента:
        # отвечаем 200 сами (xray на пустой запрос даёт 404, и клиент
        # помечает профиль «HEAD error / неизвестная версия»)
        if (\$request_method = HEAD) { add_header Content-Type application/vnd.apple.mpegurl always; return 200 ""; }
        proxy_pass http://127.0.0.1:$inb_port;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_buffering off;
        proxy_request_buffering off;
        proxy_read_timeout 300s;
        proxy_send_timeout 300s;
    }
    # СЕССИИ xhttp: реальные запросы идут на $path/<sessionID> (sessionIDPlacement=path).
    # Точное совпадение location= их не ловит — без этого блока сессии падали
    # в decoy, клиент получал HTML и ругался «unknown version: 60» ('<'=60).
    location ^~ $loc_prefix {
        proxy_pass http://127.0.0.1:$inb_port;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_buffering off;
        proxy_request_buffering off;
        proxy_read_timeout 300s;
        proxy_send_timeout 300s;
    }
    location / {
        proxy_pass https://127.0.0.1:$decoy_port;
        proxy_ssl_verify off;
        proxy_set_header Host \$host;
    }
}
EOF
    echo "# <<< cdn domain=$origin"
  } >> "$STACK_CONF"
}

# Stream-роутер: SNI origin и cdn → единый локальный cdn_frontend.
# Reality/TLS-маршруты не трогаются; логика обратимо идемпотентна.
cdn_frontend_ensure() {
  sni_upstream_add "cdn_frontend" "$CDN_FE_PORT"
  local origin="$1" cdn="$2"
  sni_map_add "$origin" "cdn_frontend"
  [[ -n "$cdn" ]] && sni_map_add "$cdn" "cdn_frontend"
}

# Аудит согласованности CDN без исправлений: база, hosts, профиль, nginx,
# decoy и сертификат. Это read-only проверка в стиле desired/runtime state.
cdn_audit_report() {
  line; echo -e "${B}   АУДИТ CDN И DRIFT${N}"; line
  [[ -f "$XUI_DB" ]] || { err "x-ui.db не найден"; return 1; }
  cdn_profiles_load
  if (( ! ${#CDN_PROFILE_IDS[@]} )); then
    log "CDN-профилей нет — проверять нечего"; return 0
  fi
  local id proto origin cdn path tpl dport port st host ipath haddr hsni hhost hsec blk cert key issues=0
  for id in "${CDN_PROFILE_IDS[@]}"; do
    proto=$(cdn_profile_field "$id" 2); origin=$(cdn_profile_field "$id" 3)
    cdn=$(cdn_profile_field "$id" 4); path=$(cdn_profile_field "$id" 5)
    tpl=$(cdn_profile_field "$id" 6); dport=$(cdn_profile_field "$id" 7)
    echo; echo "CDN #$id ($proto, провайдер: $(cdn_provider_label "$(cdn_profile_field "$id" 8)")): origin=$origin cdn=$cdn path=$path"
    if ! sqlite3 "$XUI_DB" "SELECT 1 FROM inbounds WHERE id=$id AND enable=1;" 2>/dev/null | grep -q 1; then
      err "  DRIFT: inbound отсутствует или выключен"; issues=$((issues+1)); continue
    fi
    read -r host ipath port st <<<"$(sqlite3 -separator ' ' "$XUI_DB" "SELECT COALESCE(json_extract(stream_settings,'\$.xhttpSettings.host'),''),COALESCE(json_extract(stream_settings,'\$.xhttpSettings.path'),''),port,COALESCE(stream_settings,'') FROM inbounds WHERE id=$id;" 2>/dev/null || true)"
    [[ "$host" == "$origin" ]] && log "  DB host: OK" || { err "  DRIFT: DB host=$host (ожидался $origin)"; issues=$((issues+1)); }
    [[ "$ipath" == "$path" ]] && log "  DB path: OK" || { err "  DRIFT: DB path=$ipath (ожидался $path)"; issues=$((issues+1)); }
    IFS='|' read -r haddr hsni hhost hsec <<<"$(sqlite3 -separator '|' "$XUI_DB" "SELECT COALESCE(address,''),COALESCE(sni,''),COALESCE(host_header,''),COALESCE(security,'') FROM hosts WHERE inbound_id=$id AND port=443 LIMIT 1;" 2>/dev/null || true)"
    [[ "$haddr" == "$cdn" && "$hsni" == "$cdn" && "$hhost" == "$cdn" && "$hsec" == "tls" ]] && log "  hosts: OK" || { err "  DRIFT: hosts address/sni/host/security = $haddr/$hsni/$hhost/$hsec"; issues=$((issues+1)); }
    blk=$(sed -n "/# >>> cdn .*domain=${origin//./\.}/,/# <<< cdn/p" "$STACK_CONF" 2>/dev/null || true)
    [[ -n "$blk" && "$blk" == *"location ^~"* ]] && log "  nginx block: OK" || { err "  DRIFT: nginx CDN-блок отсутствует или неполон"; issues=$((issues+1)); }
    stack_decoy_meta "$origin" >/dev/null 2>&1 && log "  decoy $origin: OK" || { err "  DRIFT: decoy $origin отсутствует"; issues=$((issues+1)); }
    cert_preflight "$origin" >/dev/null 2>&1 && log "  certificate $origin: OK (domain/expiry/key)" || { err "  DRIFT: сертификат $origin не прошёл проверку домена/срока/ключа"; issues=$((issues+1)); }
  done
  echo; if (( issues )); then err "Аудит завершён: проблем $issues"; return 1; fi
  log "Аудит завершён: CDN-профили согласованы"
}

# Полный read-only аудит стека: inbound/hosts/SNI/CDN/decoy/certs/services/UFW.
stack_full_audit() {
  line; echo -e "${B}   ПОЛНЫЙ АУДИТ СТЕКА (READ-ONLY)${N}"; line
  local issues=0 id proto port listen en st dom backend cert key exp svc _ss d _crt _left certn dbbad
  [[ -f "$XUI_DB" ]] || { err "x-ui.db не найден"; return 1; }
  echo "[ Inbounds / hosts ]"
  while IFS='|' read -r id proto port listen en st; do
    [[ -n "$id" ]] || continue
    if [[ "$en" != 1 ]]; then warn "#${id} $proto:$port — disabled"; continue; fi
    [[ "$port" =~ ^[0-9]+$ && "$port" != 0 ]] || { err "#${id}: некорректный порт $port"; issues=$((issues+1)); continue; }
    # Публичные UDP-туннели (Hysteria, qwdtt/csqtt, Awg/WireGuard) должны
    # принимать трафик не только с loopback. Для них внешний listen — норма.
    case "$proto" in
      hysteria|hysteria2|qwdtt|csqtt|awg|wireguard|amnezia|amneziawg) ;;
      *)
        if [[ "$port" != 443 && "$listen" != 127.0.0.1 ]]; then
          warn "#${id} $proto:$port — слушает не loopback"; issues=$((issues+1))
        fi
        ;;
    esac
    if grep -Eqi '"security"[[:space:]]*:[[:space:]]*"(tls|reality)"' <<<"$st"; then
      cert=$(grep -oE '"certificateFile"[[:space:]]*:[[:space:]]*"[^"]+"' <<<"$st" | head -1 | sed -E 's/.*"([^"]+)"/\1/')
      key=$(grep -oE '"keyFile"[[:space:]]*:[[:space:]]*"[^"]+"' <<<"$st" | head -1 | sed -E 's/.*"([^"]+)"/\1/')
      if [[ "$st" == *'"security":"tls"'* && ( -z "$cert" || ! -f "$cert" || -z "$key" || ! -f "$key" ) ]]; then
        warn "#${id}: TLS-сертификат/ключ не найден"; issues=$((issues+1))
      fi
      if [[ "$st" == *'"security":"tls"'* ]]; then
        dom=$(grep -oE '"serverName"[[:space:]]*:[[:space:]]*"[^"]+"' <<<"$st" | head -1 | sed -E 's/.*"([^"]+)"/\1/')
        if [[ -n "$dom" ]] && ! cert_preflight "$dom" >/dev/null 2>&1; then
          warn "#${id}: сертификат не прошёл проверку домена/срока/ключа ($dom)"; issues=$((issues+1))
        fi
      fi
    fi
    # hosts-строки в панели — генератор ссылок подписок, НЕ маршрутизация
    # (она живёт в sni-router.conf + stream_settings). Модель пользователя:
    # минимум hosts (одна строка) — отсутствие строки инбаунда не проблема.
  done < <(sqlite3 -separator '|' "$XUI_DB" "SELECT id,protocol,port,COALESCE(listen,''),enable,COALESCE(stream_settings,'') FROM inbounds ORDER BY id;" 2>/dev/null || true)
  echo "[ SNI / nginx ]"
  if command -v nginx >/dev/null 2>&1; then nginx -t >/dev/null 2>&1 && log "nginx -t: OK" || { err "nginx -t: FAIL"; issues=$((issues+1)); }; fi
  [[ -f "$SNI_CONF" ]] && log "SNI-конфиг: найден" || { warn "SNI-конфиг отсутствует"; issues=$((issues+1)); }
  echo "[ Services ]"
  for svc in nginx x-ui; do
    systemctl is-active --quiet "$svc" 2>/dev/null && log "$svc: active" || warn "$svc: не active"
  done
  echo "[ Listening ports ]"
  while IFS='|' read -r id proto port listen en; do
    [[ "$en" == 1 && "$port" =~ ^[0-9]+$ && "$port" != 0 ]] || continue
    # ss -t видит только TCP: для UDP-протоколов слушателя ищем через -u,
    # иначе здоровый UDP-инбаунд помечается «не слушает».
    _ss="-ltnup"; is_udp_proto "$proto" && _ss="-lnup"
    if ! ss "$_ss" 2>/dev/null | grep -Eq ":${port}[[:space:]]"; then
      # Порт мог попасть в момент перезапуска xray («то слушает, то нет»):
      # одна перепроверка через 2 с перед тем, как ставить замечание.
      sleep 2
      if ! ss "$_ss" 2>/dev/null | grep -Eq ":${port}[[:space:]]"; then
        warn "#${id} $proto:$port — сокет не слушает"; issues=$((issues+1))
        continue
      fi
      log "#${id} $proto:$port — socket OK (поднялся при перепроверке)"
    else
      log "#${id} $proto:$port — socket OK"
    fi
  done < <(sqlite3 -separator '|' "$XUI_DB" "SELECT id,protocol,port,COALESCE(listen,''),enable FROM inbounds WHERE enable=1 AND port>0;" 2>/dev/null || true)
  echo "[ CDN ]"
  cdn_audit_report || issues=$((issues+1))
  echo "[ CDN profile orphans ]"
  if [[ -s "$CDN_PROFILES" ]]; then
    while IFS='|' read -r id proto origin cdn path tpl dport; do
      [[ "$id" =~ ^[0-9]+$ ]] || continue
      if ! sqlite3 "$XUI_DB" "SELECT 1 FROM inbounds WHERE id=$id;" 2>/dev/null | grep -q 1; then
        warn "orphan CDN profile #$id ($origin → $cdn)"; issues=$((issues+1))
      fi
    done < "$CDN_PROFILES"
  fi
  echo "[ Certificates ]"
  if [[ -d /etc/letsencrypt/live ]]; then
    certn=0
    for d in /etc/letsencrypt/live/*; do
      [[ -d "$d" ]] || continue; certn=$((certn+1)); _crt="$d/fullchain.pem"
      [[ -f "$_crt" ]] || { err "$(basename "$d"): fullchain отсутствует"; issues=$((issues+1)); continue; }
      _left=$((($(date -d "$(openssl x509 -enddate -noout -in "$_crt" 2>/dev/null | cut -d= -f2)" +%s 2>/dev/null || echo 0)-$(date +%s))/86400))
      if (( _left < 0 )); then
        err "$(basename "$d"): сертификат просрочен"; issues=$((issues+1))
      elif (( _left < 14 )); then
        warn "$(basename "$d"): истекает через $_left дн"
      else
        log "$(basename "$d"): $_left дн"
      fi
    done
    (( certn == 0 )) && warn "Сертификатов нет"
  else
    warn "/etc/letsencrypt/live отсутствует"
  fi
  echo "[ DB JSON ]"
  dbbad=$(sqlite3 -readonly -cmd '.timeout 3000' "$XUI_DB" "SELECT COUNT(*) FROM inbounds WHERE enable=1 AND (port IS NULL OR port<=0 OR (COALESCE(settings,'') <> '' AND json_valid(settings)=0) OR (COALESCE(stream_settings,'') <> '' AND json_valid(stream_settings)=0));" 2>/dev/null || echo -1)
  if [[ "$dbbad" == 0 ]]; then
    log "JSON и порты inbounds валидны"
  elif [[ "$dbbad" == "-1" ]]; then
    warn "не удалось проверить JSON/порты inbounds"; issues=$((issues+1))
  else
    err "проблемные inbounds: $dbbad"; issues=$((issues+1))
  fi
  echo "[ UFW ]"
  if command -v ufw >/dev/null 2>&1; then ufw status | head -1; else warn "ufw не установлен"; fi
  echo; if (( issues )); then err "Полный аудит: проблем $issues"; return 1; fi
  log "Полный аудит: критических проблем не найдено"
}

# Ждём, пока ВСЕ включённые инбаунды начнут слушать (deadline сек, полл 3 с).
# Возвращает 0 — всё слушает, 1 — дедлайн истёк. Нужен после рестарта x-ui:
# перепривязываются не только «мёртвые» порты, но и живые, поэтому сразу
# после рестарта контрольный аудит ловит сокеты в моменте.
stack_wait_ports() {   # [deadline_sec]
  # LucX в стартовом окне пересоздаёт обработчики инбаундов через xray API:
  # порт может подняться и снова исчезнуть (ядро xray при этом не рестартует,
  # в journal это не видно). Поэтому сходимость = ДВА чистых прохода ПОДРЯД.
  local deadline="${1:-90}" waited=0 miss streak=0 _pid _proto _port _wss
  while :; do
    miss=0
    while IFS='|' read -r _pid _proto _port; do
      [[ -n "$_pid" ]] || continue
      [[ "$_port" =~ ^[0-9]+$ && "$_port" != 0 ]] || continue
      _wss="-ltnup"; is_udp_proto "$_proto" && _wss="-lnup"
      ss "$_wss" 2>/dev/null | grep -Eq ":${_port}[[:space:]]" || { miss=1; break; }
    done < <(sqlite3 -separator '|' "$XUI_DB" "SELECT id,protocol,port FROM inbounds WHERE enable=1 AND port>0;" 2>/dev/null || true)
    if (( miss == 0 )); then
      (( streak >= 1 )) && return 0
      streak=$((streak+1))
    else
      streak=0
    fi
    (( waited >= deadline )) && return 1
    sleep 3; waited=$((waited+3))
  done
}

# ⚡ ПРОВЕРКА И ПОЧИНКА одним действием: полный read-only аудит → безопасная
# автопочинка найденного → контрольный аудит с дельтой. Принципы:
#   • чиним только детерминированное: упавшие сервисы, серты/decoy инбаундов
#     (sync_inbound_certs), CDN-дрейф (cdn_repair), отсутствующие UDP-правила
#     UFW, пересборку xray-конфига (рестарт x-ui) для мёртвых сокетов;
#   • НЕ выпускаем сертификаты LE (квоты/DNS — раздел 3) и не правим битый
#     nginx-конфиг вслепую — только показываем причину.
stack_check_fix() {
  line; echo -e "${B}   ПРОВЕРКА И ПОЧИНКА (одним действием)${N}"; line
  [[ -n "$XUI_DB" && -f "$XUI_DB" ]] || { err "x-ui.db не найден — проверять нечего"; return 1; }
  local _a1 _a2 before after
  _a1="$(mktemp /tmp/stack-doctor.XXXXXX)"; _a2="$(mktemp /tmp/stack-doctor.XXXXXX)"
  log "Этап 1/3: полная проверка стека (read-only)…"
  stack_full_audit > "$_a1" 2>&1 || true
  cat "$_a1"
  # Исключаем итоговую строку аудита «[x] Полный аудит: проблем N» —
  # иначе счётчик завышен на 1 («было 5 → осталось 4» при 4 реальных).
  before=$(grep -E '\[!\]|\[x\]' "$_a1" 2>/dev/null | grep -vc 'Полный аудит: проблем' || true)
  before="${before:-0}"
  if (( before == 0 )); then
    rm -f "$_a1" "$_a2"
    log "Проблем не найдено — починка не требуется"
    return 0
  fi
  echo
  # Без промежуточных вопросов: сам пункт меню называется «проверить и починить»,
  # выбор пункта — уже согласие на безопасную автопочинку.
  log "Найдено замечаний: $before — применяю безопасную автопочинку"

  log "Этап 2/3: починка…"
  local svc id proto port row dports="" _ss waited=0 restarted=0
  # 1) Упавшие сервисы
  for svc in nginx x-ui; do
    if ! systemctl is-active --quiet "$svc" 2>/dev/null; then
      systemctl start "$svc" 2>/dev/null || true
      if systemctl is-active --quiet "$svc" 2>/dev/null; then
        log "  сервис $svc поднят"
      else
        err "  сервис $svc не поднимается — смотрите journalctl -u $svc -n 20"
      fi
    fi
  done
  # 2) Серты/decoy инбаундов (молчит, если чинить нечего)
  sync_inbound_certs || true
  # 3) CDN-дрейф (SNI-маршрут, http-блок, hosts, путь; сам делает reload);
  #    quiet=1 — без интерактивных вопросов внутри одноразовой починки
  cdn_repair 1 0 || true
  # 4) UDP-порты без правил UFW
  while IFS='|' read -r id proto port; do
    [[ -n "$id" && "$port" =~ ^[0-9]+$ && "$port" != 0 ]] || continue
    is_udp_proto "$proto" || continue
    if ! ufw status 2>/dev/null | awk -v p="$port" '$0 ~ ("[[:space:]]" p "/udp([[:space:]]|$)") || $0 ~ ("[[:space:]]" p "([[:space:]]|$)") {found=1} END{exit !found}'; then
      fw_allow "$port" udp "udp-инбаунд #$id"
      log "  UDP/$port открыт в UFW (инбаунд #$id $proto)"
    fi
  done < <(sqlite3 -separator '|' "$XUI_DB" "SELECT id,protocol,port FROM inbounds WHERE enable=1 AND port>0;" 2>/dev/null || true)
  if command -v ufw >/dev/null 2>&1; then ufw --force enable >/dev/null 2>&1 || true; fi
  # 5) Мёртвые сокеты → пересборка xray-конфига (рестарт x-ui), затем перепроверка
  local -a dead=() still=() pending=()
  while IFS='|' read -r id proto port; do
    [[ "$port" =~ ^[0-9]+$ && "$port" != 0 ]] || continue
    _ss="-ltnup"; is_udp_proto "$proto" && _ss="-lnup"
    ss "$_ss" 2>/dev/null | grep -Eq ":${port}[[:space:]]" || dead+=("$id|$proto|$port")
  done < <(sqlite3 -separator '|' "$XUI_DB" "SELECT id,protocol,port FROM inbounds WHERE enable=1 AND port>0;" 2>/dev/null || true)
  if (( ${#dead[@]} )); then
    for row in "${dead[@]}"; do dports+="${row##*|} "; done
    log "  не слушаются порты: ${dports% } — пересобираю конфиг xray (рестарт x-ui)"
    restarted=1
    systemctl restart x-ui 2>/dev/null || true
    # xray с Reality/туннелями поднимает сокеты долго (trusttunnel — до ~15 с):
    # фиксированный sleep 3 ловил момент «раздевания» и давал ложные
    # «сокет не слушает». Ждём до 60 с.
    still=("${dead[@]}")
    while (( ${#still[@]} )) && (( waited < 60 )); do
      sleep 3; waited=$((waited+3))
      pending=()
      for row in "${still[@]}"; do
        IFS='|' read -r id proto port <<<"$row"
        _ss="-ltnup"; is_udp_proto "$proto" && _ss="-lnup"
        if ss "$_ss" 2>/dev/null | grep -Eq ":${port}[[:space:]]"; then
          log "  #$id $proto:$port — поднялся (через ${waited}с)"
        else
          pending+=("$row")
        fi
      done
      still=("${pending[@]}")
    done
    if (( ${#still[@]} )); then
      warn "  не поднялось автоматически (протокол не поддерживается ядром или битый конфиг):"
      for row in "${still[@]}"; do
        IFS='|' read -r id proto port <<<"$row"
        warn "    #$id $proto:$port — причины: journalctl -u x-ui | grep $port"
      done
    fi
  fi
  # 5b) Рестарт перекидывает ВСЕ сокеты, включая живые: ждём сходимости всех
  #     включённых портов, иначе контрольный аудит ловит порт в моменте
  #     («то слушает, то не слушает» между соседними проверками).
  if (( restarted )); then
    log "  жду сходимости всех сокетов (до 90 с, 2 стабильных прохода)…"
    stack_wait_ports 90 || warn "  часть сокетов не поднялась за 90 с — см. контрольный аудит"
  fi
  # 6) Битый nginx-конфиг не чиним вслепую
  if ! nginx -t >/dev/null 2>&1; then
    err "  nginx -t: FAIL — конфиг битый, правится вручную (nginx -T покажет место)"
  fi

  log "Этап 3/3: контрольная проверка…"
  stack_full_audit > "$_a2" 2>&1 || true
  cat "$_a2"
  after=$(grep -E '\[!\]|\[x\]' "$_a2" 2>/dev/null | grep -vc 'Полный аудит: проблем' || true)
  after="${after:-0}"
  rm -f "$_a1" "$_a2"
  echo
  if (( after == 0 )); then
    log "Готово: было замечаний $before → осталось 0"
  elif (( after < before )); then
    log "Готово: было замечаний $before → осталось $after (остаток расшифрован выше)"
  else
    warn "Готово: было замечаний $before → осталось $after (автопочинка здесь не помогает — см. выше)"
  fi
  (( after == 0 ))
}

# Проверка и починка CDN-маршрутизации по профилям: SNI-map, upstream,
# http-блок, decoy. Живой тест: путь → xray (любой HTTP-ответ), остальное → decoy.
#   quiet=1 — без вопросов/логов восстановления (вызов из автопутей)
cdn_repair() {   # [quiet] [noreload]
  # quiet=1    — без вопросов/логов восстановления (вызов из автопутей)
  # noreload=1 — только конфиги, БЕЗ старта/reload nginx (вызов из середины п.1)
  local quiet="${1:-0}" noreload="${2:-0}"
  cdn_profiles_load
  (( ${#CDN_PROFILE_IDS[@]} )) || { (( quiet )) || log "CDN-профилей нет — проверять нечего"; return 0; }
  local fixed=0 id proto origin cdn path tpl dport port cp_line cert key code
  for id in "${CDN_PROFILE_IDS[@]}"; do
    proto=$(cdn_profile_field "$id" 2) ; origin=$(cdn_profile_field "$id" 3)
    cdn=$(cdn_profile_field "$id" 4)   ; path=$(cdn_profile_field "$id" 5)
    tpl=$(cdn_profile_field "$id" 6)   ; dport=$(cdn_profile_field "$id" 7)
    # 1) SNI-маршрут origin/cdn → cdn_frontend
    if ! grep -qE "^[[:space:]]+${origin//./\\.}[[:space:]]+cdn_frontend;" "$SNI_CONF" 2>/dev/null; then
      [[ -f "$SNI_CONF" ]] || { (( quiet )) || err "CDN #$id: нет $SNI_CONF"; continue; }
      cdn_frontend_ensure "$origin" "$cdn"; fixed=1
      (( quiet )) || warn "  CDN #$id: восстановлен SNI-маршрут $origin → cdn_frontend (маршрут отсутствовал!)"
    fi
    grep -q "^upstream cdn_frontend " "$SNI_CONF" 2>/dev/null || { sni_upstream_add "cdn_frontend" "$CDN_FE_PORT"; fixed=1; }
    # 2) http-блок в stack.conf (+ в блоке обязателен location ^~: сессии
    #    xhttp идут на $path/<sessionID> и без него падают в decoy)
    local _blk=""
    _blk=$(sed -n "/# >>> cdn .*domain=${origin//./\\.}/,/# <<< cdn/p" "$STACK_CONF" 2>/dev/null || true)
    if [[ -z "$_blk" || "$_blk" != *"location ^~"* ]]; then
      port=$(sqlite3 -cmd ".timeout 3000" "$XUI_DB" "SELECT port FROM inbounds WHERE id=$id;" 2>/dev/null || true)
      cp_line=$(cert_paths "$origin") || true
      if [[ -z "$port" || -z "$cp_line" ]]; then
        if [[ -n "$_blk" ]]; then
          (( quiet )) || warn "  CDN #$id: блок $origin устарел (нет location ^~ — сессии падали в decoy), но для пересборки нет серта $origin или порта инбаунда"
        else
          (( quiet )) || warn "  CDN #$id: http-блок отсутствует, но нет серта $origin или порта инбаунда — заполни и повтори"
        fi
        continue
      fi
      cert="${cp_line%% *}"; key="${cp_line##* }"
      # decoy: живой блок уже есть? если нет — пересоздаём по профилю
      stack_decoy_meta "$origin" >/dev/null 2>&1 || {
        [[ "$dport" =~ ^[0-9]+$ ]] || dport=$((47000 + id))
        while ss -tlnH "sport = :$dport" 2>/dev/null | grep -q .; do dport=$((dport+1)); done
        mk_decoy "$dport" "$origin" "$cert" "$key" "/var/www/decoy-cdn-$id" "$(decoy_tpl_for "$origin")" >/dev/null 2>&1 || dport=0
      }
      stack_cdn_upsert "$origin" "$cdn" "$path" "$port" "${dport:-0}" "$cert" "$key"
      fixed=1
      if [[ -n "$_blk" ]]; then
        (( quiet )) || warn "  CDN #$id: блок $origin пересобран (добавлен location ^~ — сессии xhttp идут в xray, не в decoy)"
      else
        (( quiet )) || warn "  CDN #$id: восстановлен http-блок $origin (путь $path → 127.0.0.1:$port)"
      fi
      # обновить профиль актуальным decoy-портом
      cdn_profile_save_add "$id" "$proto" "$origin" "$cdn" "$path" "$tpl" "${dport:-0}" "$(cdn_profile_provider "$id")"
    fi
    # 3) hosts-строка: address/sni/host_header = CDN-домен, security=tls явно
    #    (в нашей схеме TLS терминирует nginx; 'same' унаследовал бы none),
    #    remark = CDN_<proto>
    local _ha="" _hs="" _hh="" _hsec=""
    IFS='|' read -r _ha _hs _hh _hsec <<<"$(sqlite3 -cmd '.timeout 3000' -separator '|' "$XUI_DB" \
      "SELECT COALESCE(address,''),COALESCE(sni,''),COALESCE(host_header,''),COALESCE(security,'') FROM hosts WHERE inbound_id=$id AND port=443 ORDER BY id LIMIT 1;" 2>/dev/null || true)"
    if [[ "$_ha" != "$cdn" || "$_hs" != "$cdn" || "$_hh" != "$cdn" || "$_hsec" != "tls" ]]; then
      hosts_cdn_upsert "$id" "$cdn" "$proto"
      fixed=1
      (( quiet )) || warn "  CDN #$id: hosts-запись исправлена → address/sni/host=$cdn, security=tls (было: addr=${_ha:-пусто}, sni=${_hs:-пусто}, sec=${_hsec:-наследуется})"
    fi
    # 4) путь/хост инбаунда обязаны совпадать с профилем: nginx-блок проксирует
    #    ровно $path, а xray отвечает только на свой transport-path
    local _ipath="" _ihost=""
    IFS='|' read -r _ipath _ihost <<<"$(sqlite3 -cmd '.timeout 3000' -separator '|' "$XUI_DB" \
      "SELECT COALESCE(json_extract(stream_settings,'\$.xhttpSettings.path'),''),COALESCE(json_extract(stream_settings,'\$.xhttpSettings.host'),'') FROM inbounds WHERE id=$id;" 2>/dev/null || true)"
    if [[ "$_ipath" != "$path" || "$_ihost" != "$origin" ]]; then
      local _xw=1; systemctl is-active --quiet x-ui 2>/dev/null || _xw=0
      (( _xw )) && { systemctl stop x-ui >/dev/null 2>&1 || true; sleep 1; }
      sqlite3 -cmd ".timeout 3000" "$XUI_DB" \
        "UPDATE inbounds SET stream_settings=json_set(COALESCE(stream_settings,'{}'),'\$.xhttpSettings.path','$(sql_escape "$path")','\$.xhttpSettings.host','$(sql_escape "$origin")') WHERE id=$id;" 2>/dev/null || true
      (( _xw )) && { systemctl start x-ui >/dev/null 2>&1 || true; sleep 2; }
      fixed=1
      (( quiet )) || warn "  CDN #$id: путь инбаунда приведён к профилю (было: path=${_ipath:-пусто}, host=${_ihost:-пусто} → $path, $origin)"
    fi
    # 5) инбаунд должен быть без security (TLS у nginx)
    if (( ! quiet )); then
      local _sec=""; _sec=$(sqlite3 -cmd ".timeout 3000" "$XUI_DB" \
        "SELECT COALESCE(json_extract(stream_settings,'\$.security'),'') FROM inbounds WHERE id=$id;" 2>/dev/null || true)
      if [[ -n "$_sec" && "$_sec" != "none" ]]; then
        warn "  CDN #$id: в инбаунде security=$_sec — CDN-режим требует none/пусто! TLS у nginx, xray принимает голый HTTP."
        warn "     Исправь: п.2 → 2 (починить инбаунд) или заново ответь на вопрос CDN в п.1."
      fi
      local _ext=""; _ext=$(sqlite3 -cmd ".timeout 3000" "$XUI_DB" \
        "SELECT json_extract(stream_settings,'\$.externalProxy') FROM inbounds WHERE id=$id;" 2>/dev/null || true)
      [[ -n "$_ext" && "$_ext" != "null" ]] && warn "  CDN #$id: в stream есть externalProxy — он уводит трафик мимо nginx-маршрута, должен быть удалён"
    fi
    # 6) живой тест через локальный фронтенд
    if (( ! quiet )); then
      code=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 6 "https://127.0.0.1:$CDN_FE_PORT$path" -H "Host: $origin" 2>/dev/null || true)
      code="${code:-000}"
      if [[ "$code" == "000" || "$code" == "502" || "$code" == "503" ]]; then
        warn "  CDN #$id: ПУТЬ $path → ${code} — xray не принял соединение. Причины:"
        warn "     • в инбаунде #$id остался security=tls (должен быть none/пусто) — прогони п.2 → 2 (починить) или пункт 1"
        warn "     • x-ui/xray не активен, или инбаунд #$id не слушает порт"
      else
        log "  CDN #$id: путь $path → $code (ответ xray — норма)"
      fi
      # ГЛАВНЫЙ тест: сессия $path/<sid> обязана уходить в xray, а не в decoy.
      # Если в ответ HTML (начинается с '<' = 60) — клиент увидит «unknown version: 60».
      local _sess_url="https://127.0.0.1:$CDN_FE_PORT${path%/}/sm-selfcheck-0000"
      local _sess_code="" _sess_head=""
      _sess_code=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 6 "$_sess_url" -H "Host: $origin" 2>/dev/null || true)
      _sess_code="${_sess_code:-000}"
      _sess_head=$(curl -sk --max-time 6 "$_sess_url" -H "Host: $origin" 2>/dev/null | head -c 15 || true)
      if [[ "$_sess_code" == "200" && "$_sess_head" == "<"* ]]; then
        warn "  CDN #$id: запрос СЕССИИ ($path/<sid>) получает HTML decoy — НЕ доходит до xray!"
        warn "     В блоке нет location ^~ $path/ — прогони «Сверить и починить» (п.2 → 4 → 1)"
      elif [[ "$_sess_code" == "000" || "$_sess_code" == "502" || "$_sess_code" == "503" ]]; then
        warn "  CDN #$id: сессия $path/<sid> → $_sess_code — xray не принял (проверь x-ui и порт инбаунда)"
      else
        log "  CDN #$id: сессия $path/<sid> → $_sess_code (xray ответил — норма)"
      fi
      code=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 6 "https://127.0.0.1:$CDN_FE_PORT/ne-pyt" -H "Host: $origin" 2>/dev/null || true)
      code="${code:-000}"
      # 404 от decoy — норма: UA-блок отдаёт пустую 404 сканерам (curl/wget)
      if [[ "$code" == "200" || "$code" == "301" || "$code" == "302" || "$code" == "401" || "$code" == "403" || "$code" == "404" ]]; then
        log "  CDN #$id: прочие пути → $code (decoy — норма; 404 = UA-блок для сканеров)"
      else
        warn "  CDN #$id: прочие пути → $code (ожидался decoy) — проверь decoy-блок $origin"
      fi
    fi
  done
  # noreload=1 — вызов из середины п.1: nginx там ещё остановлен, а поднимать его
  # обязан штатный шаг ПОСЛЕ ensure_stream_include и всех правок конфигов, иначе
  # stream-секция (443/SNI-роутер) не загрузится и снаружи всё будет недоступно.
  if (( ! noreload )); then
    (( fixed )) && nginx_reload || true
  fi
  return 0
}

# Проверить, не занят ли домен ORIGIN существующей настройкой панели:
# hosts-записями и SNI/host-полями активных инбаундов. skip_id нужен
# при редактировании текущего CDN-инбаунда, чтобы он не конфликтовал сам с собой.
cdn_origin_in_panel() {   # <domain> [skip_inbound_id]
  local domain="${1,,}" skip_id="${2:-0}"
  [[ -n "$domain" && -f "$XUI_DB" ]] || return 1
  sqlite3 "$XUI_DB" "
    SELECT 1 FROM hosts
      WHERE lower(COALESCE(address,''))='$domain'
         OR lower(COALESCE(sni,''))='$domain'
         OR lower(COALESCE(host_header,''))='$domain'
    UNION ALL
    SELECT 1 FROM inbounds
      WHERE enable=1 AND id!=$skip_id AND (
        lower(COALESCE(json_extract(stream_settings,'$.tlsSettings.serverName'),''))='$domain'
        OR lower(COALESCE(json_extract(stream_settings,'$.xhttpSettings.host'),''))='$domain'
        OR EXISTS (SELECT 1 FROM json_each(COALESCE(json_extract(stream_settings,'$.realitySettings.serverNames'),'[]'))
                   WHERE lower(value)='$domain')
      ) LIMIT 1;" 2>/dev/null | grep -q 1
}

# Вопросы CDN-профиля: домены + путь + шаблон decoy. Заполняет глобальные
# CDN_ORIGIN/CDN_DOM/CDN_PATH/CDN_TPL. Не-TTY → детерминированные дефолты.
# Провайдер CDN — кто терминирует TLS от клиентов перед нашим nginx:
#   beget | yandex | other. Влияет на подсказки настройки у провайдера,
#   сохраняется 8-м полем CDN-профиля. CDN_PRE_PROVIDER задаёт ответ заранее
#   (неинтерактивные сценарии), пусто/не-TTY → other.
cdn_ask_provider() {   # → CDN_PROVIDER
  if [[ -n "${CDN_PRE_PROVIDER:-}" ]]; then
    CDN_PROVIDER="$CDN_PRE_PROVIDER"
    return 0
  fi
  if [[ ! -t 0 ]]; then
    CDN_PROVIDER="other"
    return 0
  fi
  local pv=""
  echo
  echo "  Провайдер CDN (кто принимает TLS от клиентов перед сервером):"
  echo "   1) Beget"
  echo "   2) Yandex Cloud"
  echo "   3) Другой / свой"
  ask pv "Выбор [1/2/3]" "1" '^[123]$'
  case "$pv" in
    2) CDN_PROVIDER="yandex" ;;
    3) CDN_PROVIDER="other" ;;
    *) CDN_PROVIDER="beget" ;;
  esac
}

cdn_ask_profile() {   # <id> <proto>
  local id="$1" proto="$2" base="${PANEL_DOMAIN:-$(xui_get webDomain 2>/dev/null || true)}"
  [[ "$base" == *.example.* ]] && base="exemple.com"
  cdn_ask_provider
  case "$CDN_PROVIDER" in
    beget)
      echo "  Beget: в панели Beget включи CDN для cdn-домена (CNAME на их edge),"
      echo "  origin = ORIGIN-домен, HTTPS к origin на порт 443, кэш выключи"
      echo "  (правило «не кэшировать»), POST/uploads разрешены (packet-up)."
      ;;
    yandex)
      echo "  Yandex Cloud: создай CDN-ресурс — origin = ORIGIN-домен (HTTPS, порт 443),"
      echo "  дополнительный домен = cdn-домен (CNAME → *.edgecdn.ru), сертификат на стороне"
      echo "  Яндекса (LE от Яндекса или свой), кэш выключи, Host/SNI к origin = ORIGIN."
      ;;
  esac
  if [[ -n "${CDN_PRE_CDN:-}" && -n "${CDN_PRE_ORIGIN:-}" ]]; then
    CDN_DOM="$CDN_PRE_CDN"; CDN_ORIGIN="$CDN_PRE_ORIGIN"
  else
    echo
    echo -e "${B}CDN-профиль #$id ($proto, transport=xhttp):${N}"
    ask CDN_DOM   "Домен, привязанный к CDN (например cdn.$base)"  "cdn.$base"  '^[a-zA-Z0-9.-]+$'
    ask CDN_ORIGIN "ORIGIN-домен (A-запись → этот сервер)"          "$base"   '^[a-zA-Z0-9.-]+$'
  fi
  # ORIGIN не должен совпадать ни с одним доменом, уже занятым панелью.
  if cdn_origin_in_panel "$CDN_ORIGIN"; then
    warn "ORIGIN $CDN_ORIGIN уже используется в настройках панели/инбаундов. Выбери отдельный свободный домен, иначе существующий SNI/маршрут может сломаться."
    return 1
  fi
  local def_path; def_path=$(cdn_default_path "$CDN_ORIGIN")
  if [[ -n "${CDN_PRE_PATH:-}" ]]; then
    CDN_PATH="$CDN_PRE_PATH"
  else
    local pm=""
    if [[ -t 0 ]]; then
      echo
      echo "  Путь транспорта (секретный маршрут xray):"
      echo "   1) По домену: $def_path"
      echo "   2) Сгенерировать автоматически"
      echo "   3) Ввести вручную"
      ask pm "Выбор [1/2/3]" "1" '^[123]$'
    else
      pm="1"
    fi
    case "$pm" in
      2) CDN_PATH="/api/stream/$(gen_hex 6).m3u8" ;;
      3) ask CDN_PATH "Путь (начинается с /)" "$def_path" '^/[A-Za-z0-9._/-]+$' ;;
      *) CDN_PATH="$def_path" ;;
    esac
  fi
  CDN_TPL="${CDN_PRE_TPL:-${SELECTED_DECOY_TPL:-corporate}}"
  if [[ -t 0 && -z "${CDN_PRE_TPL:-}" ]]; then
    # по умолчанию предлагаем общий шаблон, выбранный ранее в анкете п.1
    decoy_template_choose CDN_TPL "Decoy для ORIGIN $CDN_ORIGIN (всё, кроме пути транспорта)" "${SELECTED_DECOY_TPL:-corporate}"
  fi
}

# Вопрос про CDN + настройка CDN-профиля. Возвращает:
#   0 — инбаунд настроен как CDN (вызвавшему пункту дальше ничего делать не надо)
#   1 — не xhttp-кандидат или пользователь ответил «нет» (продолжить обычную логику)
# CDN-вариант создаётся как VLESS+XHTTP с security=none (HTTP к Xray за nginx).
# XHTTP+TLS и XHTTP+Reality остаются отдельными режимами.
xhttp_cdn_setup() {   # <inbound_id> <proto> <port>
  local id="$1" proto="$2" port="$3"
  [[ "$proto" != "vless" ]] && return 1
  [[ -z "$XUI_DB" || ! -f "$XUI_DB" || -z "$id" ]] && return 1
  local stream=""
  stream=$(sqlite3 -cmd ".timeout 3000" "$XUI_DB" "SELECT COALESCE(stream_settings,'') FROM inbounds WHERE id=$id;" 2>/dev/null || true)
  inbound_is_xhttp_cdn_candidate "$stream" || return 1
  # Защитная проверка ДО меню: TLS/Reality не переводим в CDN/plain.
  inbound_xhttp_has_tls_or_reality "$stream" && return 1
  inbound_was_created_as_tls_xhttp "$id" && return 1
  # Любой реальный TLS/Reality в stream_settings исключает CDN-вопрос.
  # Исключение по временному ID нужно для TLS-конфигураций LucX, где security
  # может не сериализоваться как ожидается сразу после создания.
  inbound_xhttp_has_tls_or_reality "$stream" && return 1
  inbound_was_created_as_tls_xhttp "$id" && return 1
  local _was_tls=false
  # XHTTP TLS — отдельный режим. CDN для него не предлагаем и не переводим
  # security=tls в security=none: TLS должен оставаться на Xray.
  [[ "$_was_tls" == true ]] && return 1
  echo
  echo -e "${B}Инбаунд #$id ($proto): transport=xhttp${N}"
  local use_cdn=""
  if [[ -n "${CDN_PRE_ANSWER:-}" ]]; then
    use_cdn="$CDN_PRE_ANSWER"
  elif [[ "$_was_tls" == true && -t 0 ]]; then
    warn "  Сейчас в инбаунде security=tls (TLS терминирует Xray)."
    warn "  CDN-режим переведёт его в security=none: TLS будет терминировать nginx,"
    warn "  xray останется голым на 127.0.0.1 — клиенты, у которых прошлая ссылка,"
    warn "  после этого подключаются только через nginx/CDN-маршрут."
    askyn use_cdn "Это соединение будет работать через CDN?" "n"
  else
    askyn use_cdn "Это соединение будет работать через CDN?" "n"
  fi
  if [[ "$use_cdn" != true ]]; then
    log "  CDN не используется — обычная настройка (адрес/SNI = SNI-домен)"
    return 1
  fi

  # --- вопросы: CDN/ORIGIN-домены, путь транспорта, шаблон decoy ---
  cdn_ask_profile "$id" "$proto"
  local cdn_dom="$CDN_DOM" origin_dom="$CDN_ORIGIN" new_path="$CDN_PATH" _cdn_tpl="$CDN_TPL"

  # --- серт для ORIGIN: TLS терминирует nginx ---
  local cp_line="" cert="" key=""
  cp_line=$(cert_paths "$origin_dom") || true
  # Для ORIGIN=домена панели используем уже настроенный сертификат панели.
  # cert_paths может не видеть его из-за разных записей в LucX, поэтому
  # берём пару путей непосредственно из webDomain/settings.
  local _panel_dom="${PANEL_DOMAIN:-}"
  [[ -z "$_panel_dom" ]] && _panel_dom=$(xui_get webDomain 2>/dev/null || true)
  [[ -z "$_panel_dom" ]] && _panel_dom=$(xui_get subDomain 2>/dev/null || true)
  if [[ -z "$cp_line" && -n "$_panel_dom" && "$origin_dom" == "$_panel_dom" ]]; then
    cert=$(xui_get webCertFile 2>/dev/null || true)
    key=$(xui_get webKeyFile 2>/dev/null || true)
    [[ -z "$key" ]] && key=$(xui_get subKeyFile 2>/dev/null || true)
    [[ -f "$cert" && -f "$key" ]] && cp_line="$cert $key"
  fi
  if [[ -z "$cp_line" ]]; then
    cert_issue "$origin_dom" >/dev/null 2>&1 || true
    cp_line=$(cert_paths "$origin_dom") || true
  fi
  if [[ -z "$cp_line" ]]; then
    warn "  серт для $origin_dom не выпущен — nginx-фронтенд не настраиваю."
    warn "  Выпиши серт (Сертификаты → обновить) и повтори пункт; инбаунд не менялся."
    return 1
  fi
  if ! cert_preflight "$origin_dom" >/dev/null 2>&1 && [[ "$origin_dom" != "$_panel_dom" ]]; then
    warn "  сертификат ORIGIN $origin_dom не прошёл строгую проверку — CDN не применён"
    return 1
  fi
  [[ -z "$cert" ]] && cert="${cp_line%% *}"
  [[ -z "$key" ]] && key="${cp_line##* }"
  cert="${cp_line%% *}"; key="${cp_line##* }"

  # --- правки БД — только при остановленной панели ---
  local xui_was=""
  if systemctl is-active --quiet x-ui 2>/dev/null; then
    xui_was=1
    systemctl stop x-ui >/dev/null 2>&1 || true
    sleep 1
  fi
  panel_journal_capture_row inbounds "$id"   # снимок строки для отката (п.2/п.3)
  audit "cdn:inbound=$id proto=$proto origin=$origin_dom cdn=$cdn_dom path=$new_path"
  db_protect_suspend   # осознанный перевод инбаунда в CDN-режим
  # 1) security → none, tlsSettings/externalProxy → удалить (TLS теперь у nginx,
  #    externalProxy увёл бы трафик мимо nginx-маршрута), xhttp-параметры — по README CDN:
  # Уведомление о удалении externalProxy, если оно было
  if grep -q 'externalProxy' <<<""; then
    warn "  CDN #: externalProxy удалён из stream settings (требуется для CDN-режима, чтобы трафик шёл через nginx)."
  fi
  # Уведомление о удалении externalProxy, если оно было
  if grep -q ""externalProxy"" <<<""; then
    warn "  CDN #: externalProxy удалён из stream settings (требуется для CDN-режима, чтобы трафик шёл через nginx)."
  fi
  local sql="UPDATE inbounds SET stream_settings=json_set(json_remove(stream_settings,'\$.security','\$.tlsSettings','\$.externalProxy'),"
  sql+="'\$.security','none',"
  sql+="'\$.xhttpSettings.host','$origin_dom',"
  sql+="'\$.xhttpSettings.path','$new_path',"
  sql+="'\$.xhttpSettings.mode','packet-up',"
  sql+="'\$.xhttpSettings.uplinkHTTPMethod','GET',"
  sql+="'\$.xhttpSettings.uplinkChunkSize',2048,"
  sql+="'\$.xhttpSettings.uplinkDataPlacement','header',"
  sql+="'\$.xhttpSettings.uplinkDataKey','X-Data',"
  sql+="'\$.xhttpSettings.xPaddingBytes','100-1000',"
  sql+="'\$.xhttpSettings.xPaddingPlacement','queryInHeader',"
  sql+="'\$.xhttpSettings.xPaddingHeader','X-Cache',"
  sql+="'\$.xhttpSettings.xPaddingKey','_dc',"
  sql+="'\$.xhttpSettings.xPaddingMethod','tokenish',"
  sql+="'\$.xhttpSettings.xPaddingObfsMode',json('true'),"
  sql+="'\$.xhttpSettings.xmux',json('{\"maxConnections\":2,\"hKeepAliveMs\":30000,\"h2KeepAliveIdleMs\":1000,\"h2KeepAliveIntervalMs\":1000}'),"
  sql+="'\$.xhttpSettings.scMaxBufferedPosts',30)"
  sql+=" WHERE id=$id;"
  local err_out
  err_out=$(sqlite3 -cmd ".timeout 3000" "$XUI_DB" "$sql" 2>&1) || {
    err "SQL: $err_out"; [[ "$xui_was" == 1 ]] && systemctl start x-ui >/dev/null 2>&1; return 1;
  }
  db_set_listen "$id" '127.0.0.1' direct 2>/dev/null || true
  db_protect_resume   # защищённые ключи (security/dest/xhttp-путь) записаны — вернуть защиту

  # 2) decoy ORIGIN-домена: всё, что не транспортный путь, — сюда
  local _cdn_decoy_port=$((47000 + id))
  while ss -tlnH "sport = :$_cdn_decoy_port" 2>/dev/null | grep -q .; do _cdn_decoy_port=$((_cdn_decoy_port+1)); done
  mk_decoy "$_cdn_decoy_port" "$origin_dom" "$cert" "$key" "/var/www/decoy-cdn-$id" "$_cdn_tpl" >/dev/null 2>&1 || _cdn_decoy_port=""
  if [[ -z "$_cdn_decoy_port" ]]; then
    warn "  decoy $origin_dom не создался — весь трафик origin пойдёт в xray-маршрут (путь) или 404"
  fi

  # 3) nginx: единый TLS-фронтенд + cdn-блок (путь → xray, остальное → decoy)
  cdn_frontend_ensure "$origin_dom" "$cdn_dom"
  stack_cdn_upsert "$origin_dom" "$cdn_dom" "$new_path" "$port" "${_cdn_decoy_port:-0}" "$cert" "$key"

  # 4) старая SNI-привязка инбаунда больше не нужна: вход только через cdn_frontend
  sed -i "/^upstream inb_${id}_backend /d" "$SNI_CONF" 2>/dev/null || true
  sed -i "/^\s*[^[:space:]]\+[[:space:]]\+inb_${id}_backend;/d" "$SNI_CONF" 2>/dev/null || true
  unset "SNI_USED[inb_${id}_backend]" 2>/dev/null || true

  # 5) hosts: адрес/SNI/Host header = CDN, security=tls (для клиента «TLS есть»)
  hosts_cdn_upsert "$id" "$cdn_dom" "$proto"
  cdn_profile_save_add "$id" "$proto" "$origin_dom" "$cdn_dom" "$new_path" "$_cdn_tpl" "${_cdn_decoy_port:-0}" "$CDN_PROVIDER"

  [[ "$xui_was" == 1 ]] && { systemctl start x-ui >/dev/null 2>&1 || true; sleep 2; }
  nginx_reload || true
  # 6) самопроверка маршрутизации (map/блок/decoy + живой curl)
  cdn_repair
  echo
  log "CDN-профиль инбаунда #$id ($proto) настроен:"
  log "  ORIGIN: $origin_dom — nginx TLS (серт origin) → путь $new_path в xray, остальное → decoy ($_cdn_tpl)"
  log "  CDN:    $cdn_dom — hosts: адрес/SNI/Host header = CDN, security=tls"
  log "  Инбаунд: security=none, listen=127.0.0.1:$port, mode=packet-up, GET+X-Data"
  log "  hosts: адрес/SNI/Host header = $cdn_dom, security=tls"
  return 0
}

# Снять CDN-режим с инбаунда: nginx-блок, decoy, SNI-маршруты origin/cdn,
# hosts-запись, профиль. Сам инбаунд остаётся (security=none — для обычного
# SNI-режима потом прогнать «Починить инбаунд»).
cdn_disable_for_inbound() {   # <id>
  local id="$1"
  local row; row=$(cdn_profile_get "$id" 2>/dev/null)
  [[ -z "$row" ]] && { warn "У инбаунда #$id нет CDN-профиля"; return 1; }
  local origin cdn dport
  origin=$(printf '%s' "$row" | cut -d'|' -f3)
  cdn=$(printf '%s' "$row" | cut -d'|' -f4)
  dport=$(printf '%s' "$row" | cut -d'|' -f7)
  stack_cdn_del "$origin"
  [[ "$dport" =~ ^[0-9]+$ && "$dport" != "0" ]] && stack_del_decoy "$origin"
  sni_map_remove "$origin"
  [[ -n "$cdn" && "$cdn" != "$origin" ]] && sni_map_remove "$cdn"
  cdn_profile_remove "$id"
  if [[ ! -s "$CDN_PROFILES" ]]; then
    sed -i "/^upstream cdn_frontend /d" "$SNI_CONF" 2>/dev/null || true
  fi
  sqlite3 -cmd ".timeout 3000" "$XUI_DB" "DELETE FROM hosts WHERE inbound_id=$id AND port=443;" 2>/dev/null || true
  hosts_owned_delete "$id" 443
  nginx_reload || true
  audit "cdn:removed inbound=$id origin=$origin cdn=$cdn"
  log "CDN-режим снят с #$id (origin=$origin, cdn=$cdn)"
  warn "Инбаунд #$id остался с security=none — для обычного SNI-режима прогони «Починить инбаунд» (п.2 → 4)."
  return 0
}

# Сменить decoy CDN ORIGIN без изменения CDN-доменов и пути.
cdn_change_decoy() {   # <id>
  local id="$1" row proto origin cdn path oldtpl dport port tpl cp cert key ndport
  row=$(cdn_profile_get "$id" 2>/dev/null) || return 1
  [[ -n "$row" ]] || { err "У #$id нет CDN-профиля"; return 1; }
  proto=$(printf '%s' "$row" | cut -d'|' -f2); origin=$(printf '%s' "$row" | cut -d'|' -f3)
  cdn=$(printf '%s' "$row" | cut -d'|' -f4); path=$(printf '%s' "$row" | cut -d'|' -f5)
  oldtpl=$(printf '%s' "$row" | cut -d'|' -f6); dport=$(printf '%s' "$row" | cut -d'|' -f7)
  port=$(sqlite3 -noheader "$XUI_DB" "SELECT port FROM inbounds WHERE id=$id;" 2>/dev/null || true)
  decoy_template_choose_impl tpl "Decoy для ORIGIN $origin" "$oldtpl" || return 1
  tpl="${tpl:-$oldtpl}"
  cp=$(cert_paths "$origin" 2>/dev/null || true)
  [[ -z "$cp" && "$origin" == "$(xui_get webDomain 2>/dev/null || true)" ]] && cp="$(xui_get webCertFile) $(xui_get webKeyFile)"
  cert="${cp%% *}"; key="${cp##* }"
  [[ -f "$cert" && -f "$key" ]] || { err "Серт ORIGIN $origin не найден"; return 1; }
  [[ "$dport" =~ ^[0-9]+$ ]] || dport=$((47000 + id))
  ndport="$dport"
  while ss -tlnH "sport = :$ndport" 2>/dev/null | grep -q .; do ndport=$((ndport+1)); done
  [[ "$ndport" != "$dport" ]] && dport="$ndport"
  mk_decoy "$dport" "$origin" "$cert" "$key" "/var/www/decoy-cdn-$id" "$tpl" || return 1
  stack_cdn_upsert "$origin" "$cdn" "$path" "$port" "$dport" "$cert" "$key"
  cdn_profile_save_add "$id" "$proto" "$origin" "$cdn" "$path" "$tpl" "$dport" "$(printf '%s' "$row" | cut -d'|' -f8)"
  nginx_reload || true
  log "CDN ORIGIN $origin: decoy обновлён ($tpl)"
}

# Мини-меню для инбаунда, у которого CDN-профиль уже есть.
cdn_existing_menu() {   # <id>
  local id="$1"
  log "Инбаунд #$id уже в CDN-режиме ($(cdn_provider_label "$(cdn_profile_provider "$id")")): $(cdn_profile_field "$id" 3) → $(cdn_profile_field "$id" 4)"
  echo "   1) Сверить и починить (маршрут/блок/hosts/путь)"
  echo "   2) Перенастроить (домены/путь/шаблон decoy)"
  echo "   3) Снять CDN-режим (инбаунд останется)"
  echo "   0) Ничего не делать"
  local a=""
  ask a "Выбор" "1" '^[0-3]$'
  case "$a" in
    1) cdn_repair ;;
    2) cdn_change_profile "$id" ;;
    3) cdn_disable_for_inbound "$id" ;;
  esac
  return 0
}

# Перенастройка существующего CDN-профиля: домены/путь/шаблон. Инбаунд тот же,
# клиенты получают новую ссылку из hosts (адрес = CDN-домен).
cdn_change_profile() {   # <id>
  local id="$1"
  local row; row=$(cdn_profile_get "$id" 2>/dev/null)
  [[ -z "$row" ]] && { err "У инбаунда #$id нет CDN-профиля"; return 1; }
  local proto origin cdn path tpl dport port
  proto=$(printf '%s' "$row" | cut -d'|' -f2)
  origin=$(printf '%s' "$row" | cut -d'|' -f3)
  cdn=$(printf '%s' "$row" | cut -d'|' -f4)
  path=$(printf '%s' "$row" | cut -d'|' -f5)
  tpl=$(printf '%s' "$row" | cut -d'|' -f6)
  dport=$(printf '%s' "$row" | cut -d'|' -f7)
  port=$(sqlite3 -cmd ".timeout 3000" "$XUI_DB" "SELECT port FROM inbounds WHERE id=$id;" 2>/dev/null || true)
  echo "  Профиль #$id: $proto · origin=$origin · cdn=$cdn · путь=$path · decoy=${dport:-0} · шаблон=$tpl · провайдер=$(cdn_provider_label "$(printf '%s' "$row" | cut -d'|' -f8)")"
  echo
  echo "   1) Сменить домены (CDN и/или origin)"
  echo "   2) Сменить путь"
  echo "   3) Сменить шаблон decoy"
  echo "   4) Всё заново (полные вопросы)"
  echo "   0) Отмена"
  local a=""
  ask a "Выбор" "0" '^[0-4]$'
  [[ "$a" == "0" ]] && return 0
  local n_origin="$origin" n_cdn="$cdn" n_path="$path" n_tpl="$tpl"
  local n_prov; n_prov=$(printf '%s' "$row" | cut -d'|' -f8)
  case "$a" in
    1)
      ask n_cdn    "Новый домен, привязанный к CDN" "$cdn" '^[a-zA-Z0-9.-]+$'
      ask n_origin "Новый ORIGIN-домен (A-запись → этот сервер)" "$origin" '^[a-zA-Z0-9.-]+$'
      ;;
    2)
      ask n_path "Новый путь (начинается с /)" "$(cdn_default_path "$(cdn_base_from_origin "$origin")")" '^/[A-Za-z0-9._/-]+$'
      ;;
    3)
      ask n_tpl "Шаблон decoy (имя каталога или custom:/путь/к/сайту)" "$tpl" '.+'
      ;;
    4)
      CDN_PRE_CDN=""; CDN_PRE_ORIGIN=""; CDN_PRE_ANSWER=""
      cdn_ask_profile "$id" "$proto"
      n_cdn="$CDN_DOM"; n_origin="$CDN_ORIGIN"; n_path="$CDN_PATH"; n_tpl="$CDN_TPL"; n_prov="$CDN_PROVIDER"
      ;;
  esac
  # При редактировании разрешаем сохранить текущий ORIGIN этого профиля,
  # но блокируем домены, используемые любыми другими panel/inbound-настройками.
  if cdn_origin_in_panel "$n_origin" "$id"; then
    err "ORIGIN $n_origin уже используется настройками панели/другого инбаунда. Укажи свободный отдельный домен, чтобы не нарушить существующий SNI/маршрут."
    return 1
  fi
  [[ "$n_origin" == "$origin" && "$n_cdn" == "$cdn" && "$n_path" == "$path" && "$n_tpl" == "$tpl" ]] && {
    warn "Ничего не изменилось"; return 0; }

  # серты под новый origin
  if [[ "$n_origin" != "$origin" ]] && ! cert_paths "$n_origin" >/dev/null 2>&1; then
    log "Сёрта для $n_origin нет — выпускаю (certbot)"
    cert_issue "$n_origin" || { err "Серт $n_origin не выпущен — CDN-блок не собрать"; return 1; }
  fi
  local cp_line cert="" key=""
  cp_line=$(cert_paths "$n_origin") || true
  [[ -n "$cp_line" ]] && { cert="${cp_line%% *}"; key="${cp_line##* }"; }
  [[ -z "$cert" ]] && { err "Нет серта для $n_origin — выпусти через п.10 и повтори"; return 1; }

  echo "  План: $origin/$cdn → $n_origin/$n_cdn · путь → $n_path · decoy → $n_tpl"
  local go=""
  askyn go "Применить? (панель кратко остановится)" "y"
  [[ "$go" == true ]] || return 0
  auto_backup_stack >/dev/null 2>&1 || true

  # 1) снять старую nginx-обвязку
  stack_cdn_del "$origin"
  [[ "$dport" =~ ^[0-9]+$ && "$dport" != "0" ]] && stack_del_decoy "$origin"
  sni_map_remove "$origin"
  [[ "$cdn" != "$n_cdn" ]] && sni_map_remove "$cdn"

  # 2) путь/хост в инбаунде (панель стоп)
  local xui_was=1
  systemctl is-active --quiet x-ui 2>/dev/null || xui_was=0
  (( xui_was )) && { systemctl stop x-ui >/dev/null 2>&1 || true; sleep 1; }
  sqlite3 -cmd ".timeout 3000" "$XUI_DB" \
    "UPDATE inbounds SET stream_settings=json_set(COALESCE(stream_settings,'{}'),'\$.xhttpSettings.path','$(sql_escape "$n_path")','\$.xhttpSettings.host','$(sql_escape "$n_origin")') WHERE id=$id;" 2>/dev/null || true
  (( xui_was )) && { systemctl start x-ui >/dev/null 2>&1 || true; sleep 2; }

  # 3) decoy под новый origin (если живого нет)
  if ! stack_decoy_meta "$n_origin" >/dev/null 2>&1; then
    local ndport="$dport"
    [[ "$ndport" =~ ^[0-9]+$ ]] || ndport=$((47000 + id))
    while ss -tlnH "sport = :$ndport" 2>/dev/null | grep -q .; do ndport=$((ndport+1)); done
    mk_decoy "$ndport" "$n_origin" "$cert" "$key" "/var/www/decoy-cdn-$id" "$n_tpl" >/dev/null 2>&1 || ndport=0
    dport="$ndport"
  fi

  # 4) блок + маршрут + hosts + профиль
  cdn_frontend_ensure "$n_origin" "$n_cdn"
  stack_cdn_upsert "$n_origin" "$n_cdn" "$n_path" "$port" "${dport:-0}" "$cert" "$key"
  hosts_cdn_upsert "$id" "$n_cdn" "$proto"
  cdn_profile_save_add "$id" "$proto" "$n_origin" "$n_cdn" "$n_path" "$n_tpl" "${dport:-0}" "$n_prov"
  nginx_reload || true
  audit "cdn:reprofiled inbound=$id: $origin/$cdn → $n_origin/$n_cdn path=$n_path"
  log "CDN-профиль #$id перенастроен: $n_origin → $n_cdn, путь $n_path"
  cdn_repair   # живая проверка
  return 0
}

configure_sni_for_inbound() {
  local id="$1" proto="$2" port="$3" panel_domain="$4" pre_domain="${5:-}" pre_tpl="${6:-}"
  is_udp_proto "$proto" && { warn "UDP ($proto) не маршрутизируется через SNI."; return 0; }
  [[ ! -f "$SNI_CONF" ]] && { err "$SNI_CONF не найден — сначала выполните 'Первичную настройку SNI-роутера' (пункт 1)."; return 1; }
  sni_used_load
  [[ -n "$panel_domain" ]] && SNI_USED["$panel_domain"]="${SNI_USED[$panel_domain]:-panel_backend}"

  # === VLESS XHTTP без security: единственный режим с предложением CDN.
  # Если пользователь ответил «да» — инбаунд полностью настроен как CDN-профиль
  # (nginx TLS-фронтенд, hosts с доменом CDN) и обычная логика не нужна.
  # Уже настроенный CDN-профиль повторно не спрашиваем и не ломаем,
  # но предлагаем сверку/перенастройку/снятие.
  if [[ -n "$(cdn_profile_get "$id" 2>/dev/null)" ]]; then
    cdn_existing_menu "$id"
    return 0
  fi
  # Только VLESS+XHTTP без TLS/Reality может получить предложение CDN.
  # Выбранный вариант «VLESS XHTTP TLS» всегда сохраняет TLS на Xray.
  # Этот флажок нужен, потому что после вставки записи в SQLite исходная
  # переменная security больше не передаётся в configure_sni_for_inbound.
  local _skip_xhttp_cdn_prompt=false
  inbound_was_created_as_tls_xhttp "$id" && _skip_xhttp_cdn_prompt=true
  # CDN спрашиваем только у XHTTP без TLS: это отдельный CDN-режим.
  # XHTTP+TLS из меню — обычный TLS-инбаунд и не должен неожиданно
  # предлагать CDN; CDN-вариант выбирается отдельным пунктом.
  local _xhttp_stream=""
  _xhttp_stream=$(sqlite3 "$XUI_DB" "SELECT COALESCE(stream_settings,'') FROM inbounds WHERE id=$id;" 2>/dev/null || true)
  if [[ "$proto" == "vless" && "$_skip_xhttp_cdn_prompt" != true ]] && \
     grep -Eqi '"network"[[:space:]]*:[[:space:]]*"xhttp"' <<<"$_xhttp_stream" && \
     grep -Eqi '"security"[[:space:]]*:[[:space:]]*"none"' <<<"$_xhttp_stream"; then
    if xhttp_cdn_setup "$id" "$proto" "$port"; then
      return 0
    fi
  fi
  # При ручной настройке не-CDN XHTTP+TLS продолжаем обычную ветку,
  # чтобы спросить SNI и шаблон decoy, а не завершать настройку молча.

  local existing_domain=""
  existing_domain=$(grep -E "^\s+\S+\s+inb_${id}_backend" "$SNI_CONF" 2>/dev/null | awk '{print $1}' || true)
  if [[ -n "$existing_domain" ]]; then
    log "Инбаунд #$id уже в SNI: $existing_domain"
    grep -qE "^upstream inb_${id}_backend" "$SNI_CONF" 2>/dev/null || { sni_upstream_add "inb_${id}_backend" "$port"; nginx_reload || true; }

    # если это Reality с чужим/пустым dest (не 127.0.0.1:*) — чиним автоматически:
    # создаём decoy и проставляем dest = 127.0.0.1:<порт decoy>
    local stream_chk=""
    stream_chk=$(sqlite3 "$XUI_DB" "SELECT COALESCE(stream_settings,'') FROM inbounds WHERE id=$id;" 2>/dev/null || true)
    local _policy=""
    _policy=$(decoy_policy_classify "$id" "$proto" "$stream_chk")
    if [[ "$_policy" == reality-external ]]; then
      log "  Reality (#$id) имеет внешний dest — не трогаю"
      return 0
    fi
    if [[ "$_policy" == reality-local ]] && ! grep -Eq "\"dest\": ?\"127\.0\.0\.1:" <<<"$stream_chk"; then
      # Чужой реалити (dest = внешняя цель из списка) — это НЕ поломка:
      # инбаунд спрятан за 443 по SNI цели, decoy/серт ему не нужны
      warn "  Reality dest локальный/пустой — чиню (decoy + dest)"
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
        local _dtpl=""
        [[ -t 0 ]] && decoy_template_choose_impl _dtpl "Decoy-заглушка для $existing_domain (страница этого домена)" "$(decoy_tpl_current "$existing_domain")"
        _dtpl="${_dtpl:-$(decoy_tpl_for "$existing_domain")}"
        decoy_tpl_store_set "$existing_domain" "$_dtpl" >/dev/null 2>&1 || true
        mk_decoy "$tls_port" "$existing_domain" "$c" "$k" "/var/www/decoy-$id" "$_dtpl"
        reality_set_dest "$id" "$tls_port" "$existing_domain"
        nginx_reload || true
        systemctl restart x-ui >/dev/null 2>&1 || true
        log "  Reality dest (#$id) исправлен → 127.0.0.1:$tls_port"
      else
        warn "  cert для $existing_domain недоступен — Reality dest не обновлён"
      fi
    fi
    # Existing SNI не означает, что decoy/fallback действительно есть.
    # Повторный запуск должен восстанавливать их идемпотентно.
    if [[ "$proto" == vless || "$proto" == trojan ]]; then
      tls_decoy_ensure_existing "$id" "$existing_domain" || warn "  #$id: TLS decoy не удалось восстановить"
    fi
    return 0
  fi

  local def="svc-$id.example.com"
  case "$proto" in
    vless) def="r.example.com";;
    anytls) def="at.example.com";;
    mtproto) def="tg.example.com";;
  esac
  local domain="$existing_domain" HIDE_EXT_443=false
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
  [[ "$proto" == "vless" || "$proto" == "trojan" ]] && grep -q '"security": *"reality"' <<<"$stream" && is_reality=true

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
    if [[ -z "$pre_tpl" && -t 0 ]]; then
      decoy_template_choose_impl pre_tpl "Decoy-заглушка для $domain (страница на этом домене)" "$(decoy_tpl_current "$domain")"
    fi
    pre_tpl="${pre_tpl:-$(decoy_tpl_for "$domain")}"; decoy_tpl_store_set "$domain" "$pre_tpl" >/dev/null 2>&1 || true
    mk_decoy "$tls_port" "$domain" "$cert" "$key" "/var/www/decoy-$id" "$pre_tpl"
    reality_set_dest "$id" "$tls_port" "$domain"
    systemctl restart x-ui >/dev/null 2>&1 || true
    log "  + decoy (Reality) на порту $tls_port ($pre_tpl)"
  elif [[ "$proto" == "vless" || "$proto" == "trojan" ]] && grep -Eqi '"security"[[:space:]]*:[[:space:]]*"tls"' <<<"$stream"; then
    # Для VLESS/Trojan TCP+TLS, включая XHTTP+TLS, HTTPS-заглушка обязательна.
    # Для VLESS TLS пользователь должен иметь такой же явный выбор шаблона,
    # как и для собственного Reality. В неинтерактивном режиме используем
    # сохранённый/безопасный шаблон без остановки автоматической установки.
    local cp_line="" cert="" key="" tls_port tpl
    cp_line=$(cert_paths "$domain" 2>/dev/null || true)
    [[ -z "$cp_line" ]] && cert_issue "$domain" >/dev/null 2>&1 || true
    cp_line=$(cert_paths "$domain" 2>/dev/null || true)
    cert="${cp_line%% *}"; key="${cp_line##* }"
    tpl="$(decoy_tpl_current "$domain")"
    if [[ -t 0 ]]; then
      decoy_template_choose_impl tpl "Decoy-заглушка для $domain (страница на этом домене)" "$tpl"
      tpl="${tpl:-$(decoy_tpl_for "$domain")}"
      decoy_tpl_store_set "$domain" "$tpl" >/dev/null 2>&1 || true
    fi
    if [[ -f "$cert" && -f "$key" ]]; then
      tls_port=$((47000 + id)); while ss -tlnH "sport = :$tls_port" 2>/dev/null | grep -q .; do tls_port=$((tls_port+1)); done
      mk_decoy "$tls_port" "$domain" "$cert" "$key" "/var/www/decoy-tls-$id" "$tpl" >/dev/null 2>&1 || true
      log "  + HTTPS-decoy для TLS создан автоматически"
    fi
  fi

  nginx_reload || true
  log "SNI настроен: $domain -> inb_${id}_backend"
}

# =====================================================================
