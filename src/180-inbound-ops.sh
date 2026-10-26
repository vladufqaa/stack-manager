# ПОЧИНКА ИНБАУНДА: SNI + сертификат + Reality dest (каноническая перезапись)
# =====================================================================
fix_inbound() {
  # $1 (необязательно) — ID инбаунда; без аргумента спрашивает
  local _arg_id="${1:-}"
  line; echo -e "${B}   ПОЧИНИТЬ ИНБАУНД (SNI + CERT + DEST)${N}"; line
  [[ -z "$XUI_DB" || ! -f "$XUI_DB" ]] && { err "x-ui.db не найден"; return 1; }
  [[ ! -f "$SNI_CONF" ]] && { err "Нет $SNI_CONF — сначала выполните п.1"; return 1; }
  db_protect_suspend
  sqlite3 -header -column "$XUI_DB" "SELECT id, protocol, port, remark FROM inbounds WHERE enable=1;" 2>/dev/null || true
  echo
  local id=""
  if [[ -n "$_arg_id" ]]; then
    id="$_arg_id"
    log "Инбаунд: #$id"
  else
    ask id "ID инбаунда" "" '^[0-9]+$'
  fi
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
  # VLESS XHTTP без security — кандидат на CDN:
  # вопрос задаётся ниже, отказ от CDN с голым xhttp всё равно не спрятать за SNI
  if [[ "$proto" != "vless" ]] && ! grep -Eqi '"security": ?"tls"|"security":"tls"|reality' <<<"$stream" \
     && [[ "$proto" != naive* && "$proto" != "anytls" && "$proto" != trust* ]]; then
    if ! grep -Eqi '"network"[[:space:]]*:[[:space:]]*"xhttp"' <<<"$stream"; then
      warn "С данным типом подключения скрипт не работает: #$id ($proto, TLS/Reality не найдены в stream_settings)."
      return 0
    fi
    warn "#$id ($proto) — xhttp без security: за SNI-роутер напрямую не прячется, только CDN-режим (nginx TLS)."
  fi

  # === VLESS XHTTP без security: единственный режим с предложением CDN.
  # Важно: без этого хука ветка TLS ниже переписала бы xhttp-инбаунд в голый tcp.
  if [[ "$proto" == "vless" ]] && grep -Eqi '"network"[[:space:]]*:[[:space:]]*"xhttp"' <<<"$stream"; then
    if [[ -n "$(cdn_profile_get "$id" 2>/dev/null)" ]]; then
      cdn_existing_menu "$id"
      pause
      return 0
    fi
  fi
  if xhttp_cdn_setup "$id" "$proto" "$port"; then
    pause
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

  # Reality и VLESS/Trojan TCP TLS получают браузерную decoy-страницу.
  # XHTTP TLS намеренно исключён: он работает напрямую в Xray.
  local tls_port="" rdtpl="default"
  if grep -qi reality <<<"$stream" || \
     { [[ "$proto" == "vless" || "$proto" == "trojan" ]] && grep -Eqi '"network"[[:space:]]*:[[:space:]]*"tcp"' <<<"$stream" && grep -Eqi '"security"[[:space:]]*:[[:space:]]*"tls"' <<<"$stream"; }; then
    decoy_template_choose_impl rdtpl "Decoy-заглушка для $domain (страница на этом домене)" "$(decoy_tpl_current "$domain")"
    rdtpl="${rdtpl:-$(decoy_tpl_for "$domain")}"
    decoy_tpl_store_set "$domain" "$rdtpl" >/dev/null 2>&1 || true
    tls_port=$(( 4444 + id ))
    while ss -tlnH "sport = :$tls_port" 2>/dev/null | grep -q .; do tls_port=$((tls_port+1)); done
    mk_decoy "$tls_port" "$domain" "$cert" "$key" "/var/www/decoy-$id" "$rdtpl"
     if grep -Eqi '"security"[[:space:]]*:[[:space:]]*"tls"' <<<"$stream" && grep -Eqi '"network"[[:space:]]*:[[:space:]]*"tcp"' <<<"$stream"; then
       local plain_port=$((tls_port + 1))
        while ss -tlnH "sport = :$plain_port" 2>/dev/null | grep -q .; do plain_port=$((plain_port+1)); done
        mk_plain_fallback_decoy "$plain_port" "$domain" "/var/www/decoy-$id" || warn "  #$id: plain fallback-decoy не создан"
        tls_fallback_set "$id" "$plain_port" || warn "  #$id: fallback не включён"
     fi
     log "  + decoy (TLS fallback/Reality) на порту $tls_port ($rdtpl)"
  else
    log "  decoy не нужен ($proto — не Reality)"
  fi
   # XHTTP TLS остаётся TLS passthrough через SNI в Xray.
   # HTTP-frontend и decoy для этого режима не создаются.

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
    if [[ "$_proto" == "tproxy" ]]; then
      # tproxy прячется через спец-бэкенды (tg_backend от setup_tproxy_web
      # или "tproxy"), а не inb_<id>_backend — проверяем их, иначе
      # спрятанный tproxy вечно попадает в «непрятанные»
      grep -qE '^\s+\S+\s+(tproxy|tg_backend);' "$SNI_CONF" 2>/dev/null && continue
      UNHID+=("$_id|$_proto|$_port")
      continue
    fi
    grep -qE "^[[:space:]]+[^[:space:]]+[[:space:]]+inb_${_id}_backend;[[:space:]]*$" "$SNI_CONF" 2>/dev/null && continue
    # LucX sidecar-инбаунды должны скрываться автоматически сразу после
    # создания: не показываем пользователю повторное окно «Спрятать за 443?».
    if [[ "$_proto" == "naive" || "$_proto" == "anytls" || "$_proto" == "trusttunnel" || "$_proto" == "trust-tunnel" ]]; then
      local _side_pd="${PANEL_DOMAIN:-$(xui_get subDomain 2>/dev/null || true)}"
      configure_sni_for_inbound "$_id" "$_proto" "$_port" "$_side_pd" >/dev/null 2>&1 || true
      grep -qE "^[[:space:]]+[^[:space:]]+[[:space:]]+inb_${_id}_backend;[[:space:]]*$" "$SNI_CONF" 2>/dev/null && continue
    fi
    # CDN-инбаунд спрятан через cdn_frontend (nginx TLS), а не inb_N — не «непрятанный»
    cdn_profiles_load
    [[ " ${CDN_PROFILE_IDS[*]:-} " == *" $_id "* ]] && continue
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
    local id proto port stream count=0
    while IFS='|' read -r id proto port stream; do
      [[ -z "$id" || -z "$proto" ]] && continue
      is_udp_proto "$proto" && continue
      local existing=""
      existing=$(grep -E "^\s+\S+\s+inb_${id}_backend" "$SNI_CONF" 2>/dev/null | awk '{print $1}' || true)
      if [[ -n "$existing" ]]; then
         # Для любого XHTTP без TLS предложить CDN так же, как при создании VLESS XHTTP.
         if [[ "$proto" == "vless" ]] && inbound_is_xhttp_cdn_candidate "$stream" && [[ -z "$(cdn_profile_get "$id" 2>/dev/null)" ]]; then
           xhttp_cdn_setup "$id" "$proto" "$port" || true
         fi
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
        # shellcheck disable=SC2154 # задаётся askyn выше
        [[ "$do_it" == true ]] && configure_sni_for_inbound "$id" "$proto" "$port" "$panel_domain"
      fi
      count=$((count+1))
    done < <(sqlite3 -separator '|' "$XUI_DB" "SELECT id, protocol, port, COALESCE(stream_settings,'') FROM inbounds WHERE enable=1 AND port>0;" 2>/dev/null || true)
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

  # Что доступно: SNI-привязка / сам инбаунд / (для CDN — снятие CDN-режима)
  local has_sni=false has_inb=false has_cdn=false
  [[ -n "$dom" ]] && has_sni=true
  [[ "$exists" != "0" ]] && has_inb=true
  [[ -n "$(cdn_profile_get "$id" 2>/dev/null)" ]] && has_cdn=true

  echo
  echo "  Что делать с #$id${dom:+ (SNI: $dom)}${has_cdn:+ (CDN-режим)}?"
  local a_sni="" a_inb="" a_cdn="" n=0
  if [[ "$has_cdn" == true ]]; then
    n=$((n+1)); a_cdn="$n"
    echo "   $n) Снять ТОЛЬКО CDN-режим (nginx-блок/decoy/SNI/hosts/профиль; инбаунд остаётся)"
  fi
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

  local do_sni=false do_inb=false do_cdn=false
  [[ -n "$a_sni" && "$a_sni" == "$action" ]] && do_sni=true
  [[ -n "$a_inb" && "$a_inb" == "$action" ]] && { do_inb=true; do_sni=true; }
  [[ -n "$a_cdn" && "$a_cdn" == "$action" ]] && do_cdn=true
  [[ "$do_sni" == false && "$do_inb" == false && "$do_cdn" == false ]] && { err "Нет такого выбора"; return 1; }

  # подтверждение
  local what=""
  if [[ "$do_inb" == false && "$do_cdn" == true ]]; then
    what="только CDN-режим #$id (nginx-блок/decoy/SNI-маршруты/hosts/профиль) — инбаунд останется с security=none"
  elif [[ "$do_inb" == false && "$do_sni" == true ]]; then
    what="SNI-привязку ($dom) для #$id — инбаунд останется, но tcp-порт уйдёт с 443"
  elif [[ "$do_inb" == true && "$do_sni" == true && -n "$dom" ]]; then
    what="SNI-привязку${dom:+ ($dom)} И сам инбаунд #$id из панели"
  else
    what="инбаунд #$id из панели"
  fi
  # CDN-профиль инбаунда удаляется вместе с любым из действий
  local _cdn_row=""
  [[ "$do_cdn" == true || "$do_inb" == true ]] && _cdn_row=$(cdn_profile_get "$id" 2>/dev/null || true)
  if [[ -n "$_cdn_row" ]]; then
    local _o _c; _o=$(printf '%s' "$_cdn_row" | cut -d'|' -f3); _c=$(printf '%s' "$_cdn_row" | cut -d'|' -f4)
    what="CDN-профиль #${id} (${_o}/${_c}) и ${what/#и /}"
  fi
  local confirm=""
  askyn confirm "Удалить $what?" "y"
  [[ "$confirm" == true ]] || return 0

  # 0) CDN-очистка: nginx-блок, decoy, SNI-маршруты, hosts, профиль
  if [[ -n "$_cdn_row" ]]; then
    cdn_disable_for_inbound "$id"
  fi

  # 1) SNI-привязка
  if [[ "$do_sni" == true ]]; then
    [[ -n "$dom" ]] && sni_map_remove "$dom"
    [[ -n "$be" && "$be" != "panel_backend" ]] && { sni_map_remove_backend "$be"; sni_upstream_remove "$be"; }
    unset "SNI_USED[$dom]" 2>/dev/null || true
    stack_del_decoy "$dom"   # decoy-блок в stack.conf
    local _qd; _qd=$(sql_escape "$dom")
    sqlite3 "$XUI_DB" "DELETE FROM hosts WHERE sni='$_qd' OR (inbound_id=$id AND port=443 AND (COALESCE(sni,'')='' OR sni='$_qd'));" 2>/dev/null || true
    log "SNI-привязка снята: $dom → #$id"
  fi

  # 2) сам инбаунд. Панель держит in-memory reconcile, а защита БД может
  # вернуть строку при работающем x-ui. Поэтому останавливаем панель,
  # временно приостанавливаем защитные триггеры и удаляем связанные строки.
  if [[ "$do_inb" == true && "$exists" != "0" ]]; then
    cp -n "$XUI_DB" "${XUI_DB}.bak.$(date +%Y%m%d%H%M%S)" 2>/dev/null || true
    local _xui_was=false
    systemctl is-active --quiet x-ui 2>/dev/null && { _xui_was=true; systemctl stop x-ui >/dev/null 2>&1 || true; sleep 1; }
    db_protect_suspend >/dev/null 2>&1 || true
    sqlite3 -cmd ".timeout 3000" "$XUI_DB" "
      DELETE FROM client_inbounds WHERE inbound_id=$id;
      DELETE FROM hosts WHERE inbound_id=$id;
      DELETE FROM inbounds WHERE id=$id;
    " 2>/dev/null || true
    db_protect_resume >/dev/null 2>&1 || true
    local _left
    _left=$(sqlite3 "$XUI_DB" "SELECT COUNT(*) FROM inbounds WHERE id=$id;" 2>/dev/null || echo 0)
    if [[ "$_left" == "0" ]]; then
      log "Инбаунд #$id удалён из панели (x-ui.db)"
    else
      err "Инбаунд #$id не удалился из x-ui.db — проверь права/защиту БД"
    fi
    [[ "$_xui_was" == true ]] && systemctl start x-ui >/dev/null 2>&1 || true
  fi

  nginx_reload || true
  # При удалении inbound x-ui уже был остановлен и запущен выше.
  # Повторный немедленный restart создаёт гонку с его дочерними tunnel-процессами
  # и может привести к failed/start-limit-hit. Для остальных действий restart нужен.
  if [[ "${do_inb:-false}" != true ]]; then
    systemctl restart x-ui >/dev/null 2>&1 || true
  fi
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
  cdn_profiles_load
  while IFS='|' read -r iid dom; do
    [[ -z "$iid" ]] && continue
    # CDN-инбаунд: его hosts (sni=CDN-домен) живёт через cdn_frontend, не inb_N
    [[ " ${CDN_PROFILE_IDS[*]:-} " == *" $iid "* ]] && continue
    grep -qE "^[[:space:]]+[A-Za-z0-9.-]+[[:space:]]+inb_${iid}_backend;" "$SNI_CONF" 2>/dev/null || dead_hosts+=("$iid|$dom")
  done < <(sqlite3 "$XUI_DB" "SELECT inbound_id, COALESCE(sni,'') FROM hosts WHERE port=443;" 2>/dev/null || true)

  # 4) upstream-ы, на которые не ссылается ни одна map-запись
  local _ure='^upstream ([A-Za-z0-9_-]+) \{'
  while IFS= read -r uline; do
    [[ "$uline" =~ $_ure ]] || continue
    uname="${BASH_REMATCH[1]}"
    [[ "$uname" == "panel_backend" ]] && continue
    # cdn_frontend нужен, пока есть хотя бы один CDN-профиль (даже без map — починит cdn_repair)
    [[ "$uname" == "cdn_frontend" && ${#CDN_PROFILE_IDS[@]} -gt 0 ]] && continue
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
      if [[ "$be" == "inb_${iid}_backend" ]]; then
        echo "  map/upstream: $dom → $be (инбаунда #$iid нет)"
      else
        echo "  map: $dom → $be (у tproxy #$iid должен использоваться tg_backend)"
      fi
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
