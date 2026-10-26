# SNI ДЛЯ ИНБАУНДА
# =====================================================================
# Канонический порт decoy для инбаунда: 4444 + id.
# Это же правило используют configure_sni_for_inbound, decoy_ensure_all и
# самолечение (sync_inbound_needs). Раньше п.1 нумеровал
# порты последовательно (4444, 4445, 4446…), из-за чего самолечение каждые
# 2 минуты считало reality-dest сбитым, переписывало decoy-блоки на «свои»
# порты и не перезагружало nginx — конфиг расходился с работающим nginx,
# и заглушки становились недоступны.
decoy_port_for_id() {   # <inbound_id>
  local d="${1:-0}"
  [[ "$d" =~ ^[0-9]+$ ]] || d=0
  printf '%s' "$(( 4444 + d ))"
}

# Reality dest → локальный decoy nginx (внутренний IP:порт decoy-конфа)
# + синхронизация serverNames с выбранным SNI-доменом.
# Если домен пустой или www.microsoft.com — ничего не меняем (остаётся microsoft).
reality_set_dest() {
  local id="$1" decoy_port="$2" dom="${3:-}" stream=""
  stream=$(sqlite3 "$XUI_DB" "SELECT COALESCE(stream_settings,'') FROM inbounds WHERE id=$id;" 2>/dev/null || true)
  grep -qi reality <<<"$stream" || return 0
  db_protect_suspend   # осознанная смена dest — триггеры вернутся на выходе
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
  panel_journal_capture_row inbounds "$id"   # снимок строки для отката (п.2/п.3)
  sqlite3 -cmd ".timeout 3000" "$XUI_DB" "UPDATE inbounds SET stream_settings='$new_stream' WHERE id=$id;" 2>/dev/null || true
  # КОНТРОЛЬ: значение обязано реально лечь в БД. Раньше триггер защиты молча
  # откатывал запись, скрипт писал «dest → …», а в базе оставалось старое —
  # отсюда вечная «автопочинка» и расхождение decoy-блоков с dest.
  local _stored=""
  _stored=$(sqlite3 -cmd ".timeout 3000" "$XUI_DB" "SELECT COALESCE(json_extract(stream_settings,'\$.realitySettings.dest'),'') FROM inbounds WHERE id=$id;" 2>/dev/null || true)
  if [[ "$_stored" != "127.0.0.1:$decoy_port" ]]; then
    warn "  Reality dest НЕ удержался в БД (#$id: в базе '${_stored:-пусто}', ожидалось 127.0.0.1:$decoy_port) — перепроверь decoy-порт (п.2)"
  fi
  db_protect_resume
  log "  Reality dest → 127.0.0.1:$decoy_port (decoy nginx)"
  return 0
}

# VLESS/Trojan TCP+TLS fallback → локальный HTTPS-decoy.
# XHTTP TLS также обслуживается локальным nginx frontend: путь XHTTP уходит
# в Xray, обычный браузерный запрос — в HTTPS-decoy.
tls_fallback_set() {   # <inbound_id> <decoy_port>
  local id="$1" decoy_port="$2" proto net sec st new_settings stored
  [[ "$id" =~ ^[0-9]+$ && "$decoy_port" =~ ^[0-9]+$ ]] || return 1
  proto=$(sqlite3 "$XUI_DB" "SELECT protocol FROM inbounds WHERE id=$id;" 2>/dev/null || true)
  [[ "$proto" == "vless" || "$proto" == "trojan" ]] || return 1
  st=$(sqlite3 "$XUI_DB" "SELECT COALESCE(stream_settings,'{}') FROM inbounds WHERE id=$id;" 2>/dev/null || true)
  net=$(grep -oE '"network"[[:space:]]*:[[:space:]]*"[^"]+' <<<"$st" | head -1 | sed 's/.*"//')
  sec=$(grep -oE '"security"[[:space:]]*:[[:space:]]*"[^"]+' <<<"$st" | head -1 | sed 's/.*"//')
  [[ "$sec" == "tls" && ( "$net" == "tcp" || "$net" == "xhttp" ) ]] || {
    warn "  #$id: fallback не включён (требуется TCP/XHTTP+TLS; получено ${net:-?}/${sec:-?})"
    return 2
  }
  db_protect_suspend
  new_settings=$(sqlite3 "$XUI_DB" "SELECT json_set(COALESCE(settings,'{}'),'\$.fallbacks',json('[{\"dest\":\"127.0.0.1:$decoy_port\"}]')) FROM inbounds WHERE id=$id;" 2>/dev/null || true)
  [[ -n "$new_settings" && "$new_settings" != "null" ]] || { db_protect_resume; return 1; }
  sqlite3 -cmd ".timeout 3000" "$XUI_DB" "UPDATE inbounds SET settings='$(sql_escape "$new_settings")' WHERE id=$id;" 2>/dev/null || { db_protect_resume; return 1; }
  stored=$(sqlite3 "$XUI_DB" "SELECT json_extract(settings,'\$.fallbacks[0].dest') FROM inbounds WHERE id=$id;" 2>/dev/null || true)
  db_protect_resume
  [[ "$stored" == "127.0.0.1:$decoy_port" ]] || { warn "  #$id: fallback не удержался в БД"; return 1; }
  log "  #$id: TLS fallback → 127.0.0.1:$decoy_port"
  return 0
}


# Восстановить HTTPS-заглушку для уже существующего SNI-маршрута.
# Важно: configure_sni_for_inbound раньше сразу выходил из existing_domain,
# поэтому повторный запуск «Починить инбаунд» пропускал TLS decoy.
tls_decoy_ensure_existing() {   # <id> <domain>
  local id="$1" dom="$2" st proto net sec port cp cert key tpl dport path
  [[ "$id" =~ ^[0-9]+$ && -n "$dom" ]] || return 1
  st=$(sqlite3 "$XUI_DB" "SELECT COALESCE(stream_settings,'') FROM inbounds WHERE id=$id;" 2>/dev/null || true)
  proto=$(sqlite3 "$XUI_DB" "SELECT protocol FROM inbounds WHERE id=$id;" 2>/dev/null || true)
  port=$(sqlite3 "$XUI_DB" "SELECT port FROM inbounds WHERE id=$id;" 2>/dev/null || true)
  net=$(grep -oE '"network"[[:space:]]*:[[:space:]]*"[^" ]+' <<<"$st" | head -1 | sed 's/.*"//')
  sec=$(grep -oE '"security"[[:space:]]*:[[:space:]]*"[^" ]+' <<<"$st" | head -1 | sed 's/.*"//')
  [[ "$proto" == vless || "$proto" == trojan ]] || return 0
  [[ "$sec" == tls ]] || return 0
  # XHTTP TLS работает напрямую в Xray через SNI passthrough.
  # Для этого режима decoy не создаём и шаблон не запрашиваем.
  [[ "$net" == xhttp ]] && return 0
  cp=$(cert_paths "$dom" 2>/dev/null || true)
  [[ -n "$cp" ]] || { cert_issue "$dom" >/dev/null 2>&1 || true; cp=$(cert_paths "$dom" 2>/dev/null || true); }
  [[ -n "$cp" ]] || { warn "  #$id: cert для $dom не найден"; return 1; }
  cert="${cp%% *}"; key="${cp##* }"; tpl="$(decoy_tpl_current "$dom")"; tpl="${tpl:-$(decoy_tpl_for "$dom")}"; decoy_tpl_store_set "$dom" "$tpl" >/dev/null 2>&1 || true
  dport=$(decoy_port_for_id "$id")
  while ss -tlnH "sport = :$dport" 2>/dev/null | grep -q .; do dport=$((dport+1)); done
  mk_decoy "$dport" "$dom" "$cert" "$key" "/var/www/decoy-tls-$id" "$tpl" || return 1
  if [[ "$net" == xhttp ]]; then
    path=$(sqlite3 "$XUI_DB" "SELECT COALESCE(json_extract(stream_settings,'\$.xhttpSettings.path'),'') FROM inbounds WHERE id=$id;" 2>/dev/null || true)
    [[ -n "$path" ]] || return 1
    db_protect_suspend
    sqlite3 "$XUI_DB" "UPDATE inbounds SET stream_settings=json_remove(json_set(COALESCE(stream_settings,'{}'),'\$.security','none'),'\$.tlsSettings') WHERE id=$id;" >/dev/null 2>&1 || true
    db_protect_resume
    stack_cdn_upsert "$dom" "$dom" "$path" "$port" "$dport" "$cert" "$key"
    cdn_frontend_ensure "$dom" "$dom"
    log "  #$id: XHTTP TLS переведён на nginx frontend, decoy → 127.0.0.1:$dport"
  elif [[ "$net" == tcp ]]; then
    local pp=$((dport+1)); while ss -tlnH "sport = :$pp" 2>/dev/null | grep -q .; do pp=$((pp+1)); done
    mk_plain_fallback_decoy "$pp" "$dom" "/var/www/decoy-tls-$id" || return 1
    tls_fallback_set "$id" "$pp" || return 1
    log "  #$id: TCP TLS fallback → 127.0.0.1:$pp, decoy → 127.0.0.1:$dport"
  fi
  nginx_reload || true
  return 0
}

# Вставить/обновить запись hosts в панели для TCP-инбаунда (адрес=домен, порт 443).
# Нужна ВСЕМ TCP-инбаундам (vless, naive, anytls, trusttunnel, tproxy…) — иначе
# в подписках панели нет ссылок через 443. Таблицы может не быть — пропускаем.
#   $1 = inbound_id, $2 = адрес (домен панели/IP), $3 = SNI (СТАРЫЙ смысл).
# ПОЛЕ SNI («безопасность» в hosts) БОЛЬШЕ НЕ ЗАПОЛНЯЕМ — панель на него ругается.
# Исключение: чужой reality (dest = внешняя цель ≠ 127.0.0.1) — там SNI=цель
# обязателен, иначе подписочная ссылка теряет нужный serverName.
# Учёт владения hosts: скрипт удаляет только свои строки, чужие строки
# панели или пользователя не затрагиваются.
hosts_ownership_ensure() {
  [[ -n "$XUI_DB" && -f "$XUI_DB" ]] || return 1
  sqlite3 -cmd ".timeout 3000" "$XUI_DB" "CREATE TABLE IF NOT EXISTS sm_hosts_owned (inbound_id INTEGER NOT NULL, port INTEGER NOT NULL, address TEXT NOT NULL, sni TEXT NOT NULL DEFAULT '', PRIMARY KEY(inbound_id,port,address,sni));" 2>/dev/null
}
hosts_owned_delete() {
  local id="$1" port="${2:-443}"
  hosts_ownership_ensure || return 0
  sqlite3 -cmd ".timeout 3000" "$XUI_DB" "DELETE FROM hosts WHERE inbound_id=$id AND port=$port AND EXISTS (SELECT 1 FROM sm_hosts_owned o WHERE o.inbound_id=hosts.inbound_id AND o.port=hosts.port AND o.address=COALESCE(hosts.address,'') AND o.sni=COALESCE(hosts.sni,'')); DELETE FROM sm_hosts_owned WHERE inbound_id=$id AND port=$port;" 2>/dev/null || true
}
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
  hosts_ownership_ensure
  local remark
  remark=$(sqlite3 -cmd ".timeout 3000" "$XUI_DB" "SELECT remark FROM inbounds WHERE id=$id;" 2>/dev/null || true)
  panel_journal_capture_row hosts "$id"   # снимок строки для отката (п.2/п.3)
  hosts_owned_delete "$id" 443
  local fields="inbound_id,address,port" vals="$id,'$dom',443"
  grep -qw remark       <<<"$cols" && { fields+=",remark";       vals+=",'$(printf '%s' "$remark" | sed "s/'/''/g")'"; }
  grep -qw sni          <<<"$cols" && { fields+=",sni";          vals+=",'$sni'"; }
  grep -qw fingerprint  <<<"$cols" && { fields+=",fingerprint";  vals+=",'firefox'"; }
  grep -qw is_disabled  <<<"$cols" && { fields+=",is_disabled";  vals+=",0"; }
  grep -qw enable       <<<"$cols" && { fields+=",enable";       vals+=",1"; }
  if sqlite3 -cmd ".timeout 3000" "$XUI_DB" "INSERT INTO hosts ($fields) VALUES ($vals);" 2>/dev/null; then
    sqlite3 -cmd ".timeout 3000" "$XUI_DB" "INSERT OR REPLACE INTO sm_hosts_owned(inbound_id,port,address,sni) VALUES($id,443,'$(printf '%s' "$dom" | sed "s/'/''/g")','$(printf '%s' "$sni" | sed "s/'/''/g")');" 2>/dev/null || true
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

inbound_is_xhttp_tls() {   # <stream_json> → 0, если network=xhttp и security=tls
  local s="$1"
  [[ -z "$s" ]] && return 1
  grep -Eqi '"network"[[:space:]]*:[[:space:]]*"xhttp"' <<<"$s" || return 1
  grep -Eqi '"security"[[:space:]]*:[[:space:]]*"tls"' <<<"$s" || return 1
  return 0
}

# hosts-запись CDN-профиля: адрес/SNI/Host header = домен CDN, security=tls,
# remark = "CDN_<протокол>" (по образцу hosts_upsert, но с host_header и SNI=CDN)
hosts_cdn_upsert() {   # <inbound_id> <cdn_domain> [proto]
  [[ -z "$XUI_DB" || ! -f "$XUI_DB" ]] && return 0
  local id="$1" cdn="$2" proto="${3:-}"
  [[ -z "$id" || -z "$cdn" ]] && return 0
  # защита БД вернула бы прежнюю строку hosts из тени — на время перезаписи off
  db_protect_suspend
  local has_hosts
  has_hosts=$(sqlite3 -cmd ".timeout 3000" "$XUI_DB" "SELECT name FROM sqlite_master WHERE type='table' AND name='hosts';" 2>/dev/null || true)
  [[ -z "$has_hosts" ]] && return 0
  local cols
  cols=$(sqlite3 -cmd ".timeout 3000" "$XUI_DB" "PRAGMA table_info(hosts);" 2>/dev/null | awk -F'|' '{print $2}' | tr '\n' ' ')
  panel_journal_capture_row hosts "$id"   # снимок строки для отката (п.2/п.3)
  # Для одного inbound должна существовать ровно одна строка hosts: CDN
  # заменяет прежнюю обычную/SNI-запись, иначе панель выдаёт две ссылки.
  # Удаляем только строки этого inbound на 443, чужие inbounds не трогаем.
  sqlite3 -cmd ".timeout 3000" "$XUI_DB" \
    "DELETE FROM hosts WHERE inbound_id=$id AND port=443;" 2>/dev/null || true
  hosts_owned_delete "$id" 443
  # В разных версиях панели hosts имеет обязательные NOT NULL-поля. Сначала
  # заполняем минимальную совместимую строку, затем добавляем опциональные.
  local _remark="CDN"
  [[ -n "$proto" ]] && _remark="CDN_${proto}"
  local fields="inbound_id,address,port" vals="$id,'$cdn',443"
  grep -qw remark      <<<"$cols" && { fields+=",remark";      vals+=",'$_remark'"; }
  grep -qw sni         <<<"$cols" && { fields+=",sni";         vals+=",'$cdn'"; }
  grep -qw host_header <<<"$cols" && { fields+=",host_header"; vals+=",'$cdn'"; }
  # ВАЖНО: TLS терминирует nginx-фронтенд, в инбаунде security=none → 'same'
  # унаследовал бы none и клиент пошёл бы голым HTTP на 443 («HEAD, неизвестная
  # версия»). Поэтому у CDN-хоста security=tls ЯВНО, в отличие от README
  # (там TLS на Xray и 'same' наследует tls).
  grep -qw security    <<<"$cols" && { fields+=",security";    vals+=",'tls'"; }
  grep -qw fingerprint <<<"$cols" && { fields+=",fingerprint"; vals+=",'firefox'"; }
  grep -qw is_disabled <<<"$cols" && { fields+=",is_disabled"; vals+=",0"; }
  grep -qw enable      <<<"$cols" && { fields+=",enable";      vals+=",1"; }
  if sqlite3 -cmd ".timeout 3000" "$XUI_DB" "INSERT INTO hosts ($fields) VALUES ($vals);" 2>/dev/null; then
    sqlite3 -cmd ".timeout 3000" "$XUI_DB" "INSERT OR REPLACE INTO sm_hosts_owned(inbound_id,port,address,sni) VALUES($id,443,'$(printf '%s' "$cdn" | sed "s/'/''/g")','$(printf '%s' "$cdn" | sed "s/'/''/g")');" 2>/dev/null || true
    log "  hosts: #$id → $cdn:443 (адрес/SNI/Host header = CDN, security=tls, remark=$_remark) ✓"
  else
    warn "  hosts: CDN-вставка для #$id не прошла — проверь схему таблицы hosts"
  fi
  return 0
}

# =====================================================================
