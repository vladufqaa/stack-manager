# СМЕНА DECOY
# =====================================================================
# ── Раздать decoy всем SNI-инбаундам (кроме TG WEB-PROXY) ───────────────
#   Свой Reality   → nginx-декой (маркер stack.conf) + dest=127.0.0.1:<порт>
#   VLESS+TLS (tcp)→ fallback → 127.0.0.1:80 (браузер видит заглушку)
#   TG WEB-PROXY   → пропуск: сам проксирует живую цель
#   Чужой Reality  → пропуск: спрятан за SNI цели, декой не нужен
decoy_ensure_all() {
  line; echo -e "${B}   DECOY: РАЗДАТЬ ВСЕМ SNI-ИНБАУНДАМ${N}"; line
  stack_ensure
  [[ -n "$XUI_DB" && -f "$XUI_DB" ]] || { err "x-ui.db не найден"; pause; return 1; }
  local used_ports
  used_ports=$(grep -oE 'port=[0-9]+' "$STACK_CONF" 2>/dev/null | cut -d= -f2 | sort -u)
  local tls_cur=8443 _free=0
  while (( _free < 1 )); do
    if grep -qx "$tls_cur" <<<"$used_ports" || port_in_use "$tls_cur"; then tls_cur=$((tls_cur+1)); else _free=1; fi
  done
  local id dom be proto dest dport line_ok=0
  local hport hmeta hcp hc hk hroot
  local -a done_ids=()
  while IFS='|' read -r dom be; do
    if [[ "$be" =~ ^inb_([0-9]+)_backend$ || "$be" =~ ^hysteria_([0-9]+)_web$ ]]; then
      id="${BASH_REMATCH[1]}"
      [[ -z "$id" ]] && id="${BASH_REMATCH[2]}"
    else
      continue
    fi
    [[ " ${done_ids[*]} " == *" $id "* ]] && continue
    done_ids+=("$id")
    proto=$(sqlite3 -cmd ".timeout 3000" "$XUI_DB" "SELECT protocol FROM inbounds WHERE id=$id AND enable=1;" 2>/dev/null || true)
    [[ -z "$proto" ]] && continue
    if [[ "$proto" == "tproxy" ]]; then
      echo "  #$id $dom — TG WEB-PROXY: пропуск (живая цель, декой не нужен)"
      continue
    fi
    local st
    st=$(sqlite3 -cmd ".timeout 3000" "$XUI_DB" "SELECT COALESCE(stream_settings,'') FROM inbounds WHERE id=$id;" 2>/dev/null || true)
    dest=$(sqlite3 -cmd ".timeout 3000" "$XUI_DB" \
      "SELECT COALESCE(json_extract(stream_settings,'\$.realitySettings.dest'),json_extract(stream_settings,'\$.realitySettings.target'),'') FROM inbounds WHERE id=$id;" 2>/dev/null || true)
    dest="${dest%%:*}"
    if [[ "$proto" == "hysteria" || "$proto" == "hysteria2" ]]; then
      hmeta=$(stack_decoy_meta "$dom" 2>/dev/null || true)
      if [[ -z "$hmeta" ]]; then
        hcp=$(cert_paths "$dom" 2>/dev/null || true)
        if [[ -n "$hcp" ]]; then
          hc="${hcp%% *}"; hk="${hcp##* }"; hport=$((47000 + id))
          while ss -tlnH "sport = :$hport" 2>/dev/null | grep -q .; do hport=$((hport+1)); done
          mk_decoy "$hport" "$dom" "$hc" "$hk" "/var/www/decoy-hysteria-$id" "$(decoy_tpl_for "$dom")" || continue
          sni_upstream_add "hysteria_${id}_web" "$hport"
          sni_map_add "$dom" "hysteria_${id}_web"
          line_ok=1
        else
          warn "  #$id $dom — сертификат не найден, TCP-decoy отложен"
        fi
      fi
      continue
    fi
    local policy=""
    policy=$(decoy_policy_classify "$id" "$proto" "$st")
    if [[ "$policy" == reality-external ]]; then
      echo "  #$id $dom — внешний Reality: пропуск (decoy не применяется)"
      continue
    fi
    if [[ "$policy" == reality-local ]]; then
      local meta="" cp_line c="" k=""
      meta=$(stack_decoy_meta "$dom" 2>/dev/null || true)
      if [[ -n "$meta" ]]; then
        dport="${meta%% *}"
      else
        cp_line=$(cert_paths "$dom") || true
        if [[ -z "$cp_line" ]]; then
          warn "  #$id $dom — серта нет, декой отложен (п.10 → пересборка, затем повторить)"
          continue
        fi
        c="${cp_line%% *}"; k="${cp_line##* }"
        dport="$tls_cur"; tls_cur=$((tls_cur+1))
        mk_decoy "$dport" "$dom" "$c" "$k" "/var/www/decoy-$id" "$(decoy_tpl_for "$dom")"
      fi
      db_protect_suspend
      reality_set_dest "$id" "$dport" "$dom"
      log "  #$id $dom — декой на 127.0.0.1:$dport, Reality dest выставлен"
      line_ok=1
      continue
    fi
    # VLESS/Trojan TCP TLS получают тот же HTTPS-decoy через Xray fallback.
    if [[ "$proto" == "vless" || "$proto" == "trojan" ]] && grep -Eqi '"security"[[:space:]]*:[[:space:]]*"tls"' <<<"$st" && grep -Eqi '"network"[[:space:]]*:[[:space:]]*"(tcp|xhttp)"' <<<"$st"; then
      local tmeta tcp cpk tc tk trt
      tmeta=$(stack_decoy_meta "$dom" 2>/dev/null || true)
      if [[ -n "$tmeta" ]]; then
        tcp="${tmeta%% *}"
        local plain_tcp=$((tcp + 1))
        while ss -tlnH "sport = :$plain_tcp" 2>/dev/null | grep -q .; do plain_tcp=$((plain_tcp+1)); done
        mk_plain_fallback_decoy "$plain_tcp" "$dom" "/var/www/decoy-$id" || true
        tls_fallback_set "$id" "$plain_tcp" && line_ok=1
        echo "  #$id $dom — TLS fallback → 127.0.0.1:$tcp"
      else
        cpk=$(cert_paths "$dom" 2>/dev/null || true)
        if [[ -n "$cpk" ]]; then
          tc="${cpk%% *}"; tk="${cpk##* }"; tcp=$(decoy_port_for_id "$id"); trt=$(decoy_tpl_for "$dom")
          mk_decoy "$tcp" "$dom" "$tc" "$tk" "/var/www/decoy-$id" "$trt" && mk_plain_fallback_decoy "$((tcp + 1))" "$dom" "/var/www/decoy-$id" && tls_fallback_set "$id" "$((tcp + 1))" && line_ok=1
          echo "  #$id $dom — HTTPS-decoy + TLS fallback на $tcp"
        else
          warn "  #$id $dom — сертификат не найден, TLS fallback отложен"
        fi
      fi
    else
      echo "  #$id $dom ($proto) — decoy не назначается"
    fi
  done < <(awk '
    /^map / { inmap=1; next }
    inmap && /^}/ { inmap=0 }
    inmap && /^[[:space:]]/ && NF >= 2 {
      dom = $1; sub(/;$/, "", dom); be = $2; sub(/;$/, "", be)
      if (dom != "" && dom != "default" && ((be ~ /_backend$/ && be !~ /^(panel|agh)_backend$/) || be ~ /^hysteria_[0-9]+_web$/)) print dom "|" be
    }' "$SNI_CONF" 2>/dev/null)
  if (( line_ok )); then
    nginx_reload || true
  fi
  log "Готово: декой гарантирован для всех применимых SNI-инбаундов (TG WEB-PROXY исключён)."
  pause
}

# ── Выборочный decoy: выбрать SNI-инбаунд → его заглушка ────────────────
#   Свой Reality     → выбор шаблона (создать/сменить), dest обновится
#   VLESS/Trojan+TLS → вкл/выкл fallback на 127.0.0.1:80
#   TG WEB-PROXY     → отказ (инбаунд сам проксирует живую цель)
#   Чужой Reality    → отказ (спрятан за SNI цели)
#   naive/anytls/trusttunnel  → отказ: TLS терминирует sidecar LucX,
#       nginx-декой в цепочку не вставить (сломает протокол)
decoy_pick_inbound() {
  stack_ensure
  [[ -n "$XUI_DB" && -f "$XUI_DB" ]] || { err "x-ui.db не найден"; pause; return 1; }
  local -a L=()
  local dom be id proto port mark
  local preset_id="${1:-}" preset_dom="${2:-}" preset_port=""
  if [[ -n "$preset_id" ]]; then
    id="$preset_id"; dom="$preset_dom"
    proto=$(sqlite3 -cmd ".timeout 3000" "$XUI_DB" "SELECT protocol FROM inbounds WHERE id=$id AND enable=1;" 2>/dev/null || true)
    preset_port=$(sqlite3 -cmd ".timeout 3000" "$XUI_DB" "SELECT port FROM inbounds WHERE id=$id;" 2>/dev/null || true)
  else
  echo
  echo -e "${B}▸ SNI-инбаунды:${N}"
  while IFS='|' read -r dom be; do
    if [[ "$be" =~ ^inb_([0-9]+)_backend$ ]]; then
      id="${BASH_REMATCH[1]}"
    elif [[ "$be" =~ ^hysteria_([0-9]+)_web$ ]]; then
      id="${BASH_REMATCH[1]}"
    else
      continue
    fi
    proto=$(sqlite3 -cmd ".timeout 3000" "$XUI_DB" "SELECT protocol FROM inbounds WHERE id=$id AND enable=1;" 2>/dev/null || true)
    [[ -z "$proto" ]] && continue
    st=$(sqlite3 -cmd ".timeout 3000" "$XUI_DB" "SELECT COALESCE(stream_settings,'') FROM inbounds WHERE id=$id;" 2>/dev/null || true)
    # В меню смены decoy показываем собственный Reality и Hysteria TCP-decoy.
    port=$(sqlite3 -cmd ".timeout 3000" "$XUI_DB" "SELECT port FROM inbounds WHERE id=$id;" 2>/dev/null || true)
    if [[ "$proto" == "hysteria" || "$proto" == "hysteria2" ]]; then
      L+=("$dom|$id|$proto|$port")
      mark="декой есть"
      stack_decoy_meta "$dom" >/dev/null 2>&1 || mark="декоя нет"
      printf "  %2d) #%-3s %-30s %-9s :%-5s %s\n" "${#L[@]}" "$id" "$dom" "$proto" "$port" "$mark"
      continue
    fi
    [[ "$proto" == "vless" ]] || continue
    grep -qi '"security": *"reality"' <<<"$st" || continue
    port=$(sqlite3 -cmd ".timeout 3000" "$XUI_DB" "SELECT port FROM inbounds WHERE id=$id;" 2>/dev/null || true)
    mark="декоя нет"
    stack_decoy_meta "$dom" >/dev/null 2>&1 && mark="декой есть"
    L+=("$dom|$id|$proto|$port")
    printf "  %2d) #%-3s %-30s %-9s :%-5s %s\n" "${#L[@]}" "$id" "$dom" "$proto" "$port" "$mark"
  done < <(awk '
    /^map / { inmap=1; next }
    inmap && /^}/ { inmap=0 }
    inmap && /^[[:space:]]/ && NF >= 2 {
      dom = $1; sub(/;$/, "", dom); be = $2; sub(/;$/, "", be)
      if (dom != "" && dom != "default" && ((be ~ /_backend$/ && be !~ /^(panel|agh)_backend$/) || be ~ /^hysteria_[0-9]+_web$/)) print dom "|" be
    }' "$SNI_CONF" 2>/dev/null)
    # Добавляем Hysteria даже при старом/отсутствующем SNI-map.
    while IFS='|' read -r hid hproto hport hdom; do
      [[ -n "$hid" ]] || continue
      [[ -z "$hdom" ]] && hdom="__missing_sni__"
      local already=false item
      for item in "${L[@]}"; do [[ "${item%%|*}" == "$hdom" ]] && already=true; done
      [[ "$already" == true ]] && continue
      L+=("$hdom|$hid|$hproto|$hport")
      mark="декоя нет"; stack_decoy_meta "$hdom" >/dev/null 2>&1 && mark="декой есть"
      printf "  %2d) #%-3s %-30s %-9s :%-5s %s\n" "${#L[@]}" "$hid" "$hdom" "$hproto" "$hport" "$mark"
    done < <(sqlite3 -separator '|' "$XUI_DB" "SELECT id,protocol,port FROM inbounds WHERE port>0 AND lower(protocol) LIKE '%hysteria%' ORDER BY id;" 2>/dev/null | while IFS='|' read -r hid hproto hport; do
      [[ -n "$hid" ]] || continue
      hdom=$(sqlite3 -noheader "$XUI_DB" "SELECT COALESCE((SELECT sni FROM hosts WHERE inbound_id=$hid AND port=443 LIMIT 1),(SELECT address FROM hosts WHERE inbound_id=$hid AND port=443 LIMIT 1),json_extract(stream_settings,'\$.tlsSettings.serverName'),json_extract(settings,'\$.tlsSettings.serverName'),json_extract(stream_settings,'\$.serverName'),json_extract(settings,'\$.serverName'),json_extract(stream_settings,'\$.hysteriaSettings.serverName'),json_extract(settings,'\$.hysteriaSettings.serverName'),json_extract(stream_settings,'\$.realitySettings.serverNames[0]'),'') FROM inbounds WHERE id=$hid;" 2>/dev/null | head -1 || true)
      [[ -z "$hdom" || "$hdom" == "null" ]] && hdom="__missing_sni__"
      printf '%s|%s|%s|%s\n' "$hid" "$hproto" "$hport" "$hdom"
    done)
  fi
  if [[ -n "$preset_id" ]]; then
    L=("$dom|$id|$proto|$preset_port")
  fi
  [[ ${#L[@]} -eq 0 ]] && { warn "Собственных Reality-инбаундов не найдено"; pause; return 1; }
  local pick=""
  if [[ -n "$preset_id" ]]; then
    pick=1
  else
    echo
    ask pick "Номер Reality-инбаунда (0 — отмена)" "0" '^[0-9]+$'
    [[ "$pick" == "0" ]] && return 0
  fi
  (( pick > ${#L[@]} )) && { err "Нет такого номера"; pause; return 1; }
  IFS='|' read -r dom id proto port <<<"${L[$((pick-1))]}"
  local st
  st=$(sqlite3 -cmd ".timeout 3000" "$XUI_DB" "SELECT COALESCE(stream_settings,'') FROM inbounds WHERE id=$id;" 2>/dev/null || true)
  local dest
  dest=$(sqlite3 -cmd ".timeout 3000" "$XUI_DB" \
    "SELECT COALESCE(json_extract(stream_settings,'\$.realitySettings.dest'),json_extract(stream_settings,'\$.realitySettings.target'),'') FROM inbounds WHERE id=$id;" 2>/dev/null || true)
  dest="${dest%%:*}"
  if [[ "$proto" == "tproxy" ]]; then
    warn "TG WEB-PROXY ($dom): decoy не ставится — инбаунд сам проксирует живую цель."
    pause; return 0
  fi
  if [[ -n "$dest" && "$dest" != "127.0.0.1" ]]; then
    warn "Чужой Reality ($dom → $dest): decoy не нужен — домен спрятан за SNI цели."
    pause; return 0
  fi
  if [[ "$proto" == "hysteria" || "$proto" == "hysteria2" ]]; then
    local tpl="" meta dport="" c="" k="" root="" hcp hport
    decoy_template_choose_impl tpl "Decoy для Hysteria #$id ($dom)" "$(decoy_tpl_current "$dom")"
    tpl="${tpl:-$(decoy_tpl_for "$dom")}"
    decoy_tpl_store_set "$dom" "$tpl" >/dev/null 2>&1 || true
    hcp=$(cert_paths "$dom" 2>/dev/null || true)
    if [[ -z "$hcp" && "$dom" != "__missing_sni__" ]]; then
      # Wildcard может использоваться панелью, даже если маркер wildcard
      # скрипта потерян после восстановления backup. Берём фактические пути
      # сертификата панели и проверяем их наличие — новый ACME-серт не нужен.
      local _wc _wk
      _wc=$(xui_get webCertFile 2>/dev/null || true)
      _wk=$(xui_get webKeyFile 2>/dev/null || true)
      if [[ -f "$_wc" && -f "$_wk" ]]; then
        hcp="$_wc $_wk"
        log "Использую действующий сертификат панели для $dom (включая wildcard)"
      fi
    fi
    if [[ -z "$hcp" && "$dom" != "__missing_sni__" ]]; then
      warn "Сертификат $dom не найден — пытаюсь выпустить его для HTTPS-decoy"
      cert_issue "$dom" || true
      hcp=$(cert_paths "$dom" 2>/dev/null || true)
    fi
    [[ -z "$hcp" ]] && { err "Серта $dom нет — decoy отложен; сначала выпусти сертификат в разделе «Сертификаты»"; pause; return 1; }
    c="${hcp%% *}"; k="${hcp##* }"
    meta=$(stack_decoy_meta "$dom" 2>/dev/null || true)
    if [[ -n "$meta" ]]; then read -r dport root _ _ <<<"$meta"; else
      dport=$((47000 + id)); while ss -tlnH "sport = :$dport" 2>/dev/null | grep -q .; do dport=$((dport+1)); done
      root="/var/www/decoy-hysteria-$id"
    fi
    mk_decoy "$dport" "$dom" "$c" "$k" "$root" "$tpl"
    sni_upstream_add "hysteria_${id}_web" "$dport"
    sni_map_add "$dom" "hysteria_${id}_web"
    nginx_reload || true
    log "Hysteria #$id: TCP-decoy обновлён, UDP-инбаунд не изменён"
    pause; return 0
  fi
  if grep -qi '"security"[[:space:]]*:[[:space:]]*"reality"' <<<"$st" || \
     { [[ "$proto" == "vless" || "$proto" == "trojan" ]] && grep -Eqi '"security"[[:space:]]*:[[:space:]]*"tls"' <<<"$st"; }; then
    local tpl="" meta dport="" c="" k="" root=""
    decoy_template_choose_impl tpl "Decoy для #$id ($dom)" "$(decoy_tpl_current "$dom")"
    tpl="${tpl:-$(decoy_tpl_for "$dom")}"
    decoy_tpl_store_set "$dom" "$tpl" >/dev/null 2>&1 || true
    meta=$(stack_decoy_meta "$dom" 2>/dev/null || true)
    if [[ -n "$meta" ]]; then
      read -r dport root c k <<<"$meta"
      mk_decoy "$dport" "$dom" "$c" "$k" "$root" "$tpl"
    else
      local cp_line
      cp_line=$(cert_paths "$dom") || true
      [[ -z "$cp_line" ]] && { cert_issue "$dom" || true; cp_line=$(cert_paths "$dom") || true; }
      [[ -z "$cp_line" ]] && { err "Серта $dom нет — decoy отложен (п.10, затем повторить)"; pause; return 1; }
      c="${cp_line%% *}"; k="${cp_line##* }"
      dport=$(( 4444 + id ))
      while ss -tlnH "sport = :$dport" 2>/dev/null | grep -q .; do dport=$((dport+1)); done
      mk_decoy "$dport" "$dom" "$c" "$k" "/var/www/decoy-$id" "$tpl"
    fi
    if grep -Eqi '"security"[[:space:]]*:[[:space:]]*"reality"' <<<"$st"; then
      db_protect_suspend
      reality_set_dest "$id" "$dport" "$dom" || { err "Не удалось записать Reality dest для #$id"; pause; return 1; }
    fi
    nginx_reload || { err "Decoy создан, но nginx не перезагрузился"; pause; return 1; }
    log "Decoy #$id ($dom): «$tpl» на 127.0.0.1:$dport"
    pause; return 0
  fi
  # Обычный TLS/туннельный инбаунд без поддерживаемого decoy не попадает в список.
  # Штатная схема меню — только собственный Reality и панель.
  case "$proto" in
    naive|anytls|trusttunnel|trust-tunnel|hy2|hysteria)
      warn "$proto ($dom): TLS терминирует sidecar LucX — nginx-декой в цепочку не вставить (сломает протокол)."
      warn "Посторонний вид уже даёт сам sidecar (отвечает, а не молчит)."
      ;;
    *)
      warn "$proto ($dom): decoy-механика для этого протокола не применяется."
      ;;
  esac
  pause; return 0
}

# ── Убрать decoy инбаундов: вернуть как изначально ─────────────────────
#   Исходная доктрина: decoy-вхост только у Reality-инбаундов и панели.
#   П.4.1 мог раздать decoy всем — здесь снимается всё «лишнее»:
#     • decoy-блоки stack.conf у не-Reality SNI-доменов удаляются
#     • vless/trojan+TLS: decoy-fallback (dest = 127.0.0.1:80 или 80)
#       снимается целиком; боевой fallback (другой dest) не трогается
#     • свой Reality — decoy остаётся (заглушка обязательна)
#     • TG WEB-PROXY — пропуск (decoy ему не ставится)

# ── Шаблоны decoy по доменам: свой шаблон (или свой сайт) каждому домену ──
# Меню: задать шаблон каждому домену (или один на всех), сбросить к общему.

change_decoy() {
  line; echo -e "${B}   DECOY: ДОСТУПНЫЕ ОБЪЕКТЫ ДЛЯ СМЕНЫ${N}"; line
  # change_decoy может вызываться из главного меню без предварительного
  # detect_env; без него XUI_DB пуст и fallback-поиск Hysteria не выполняется.
  detect_env
  stack_ensure
  local panel_dom=""
  panel_dom=$(xui_get subDomain 2>/dev/null || true)
  [[ -z "$panel_dom" || "$panel_dom" == "null" ]] && panel_dom=$(xui_get webDomain 2>/dev/null || true)
  [[ -z "$panel_dom" || "$panel_dom" == "null" ]] && { err "Домен панели не найден — сначала п.1"; pause; return 1; }
  echo "  Доступные объекты:"
  local _panel_tpl=""
  _panel_tpl=$(decoy_tpl_current "$panel_dom" 2>/dev/null || true)
  [[ -z "$_panel_tpl" ]] && _panel_tpl="default"
  printf "   1) Панель — %-30s (decoy=%s)\n" "$panel_dom" "$_panel_tpl"
  local -a _decoy_rows=() _decoy_row
  # Hysteria выводится напрямую из БД независимо от наличия SNI-map.
  # Это важно после восстановления старого бэкапа: nginx-конфигов может не быть.
  local _hid _hproto _hport _hjson _hdom
  while IFS='|' read -r _hid _hproto _hport _hjson; do
    [[ -n "$_hid" ]] || continue
    _hdom=$(grep -oE '"serverName"[[:space:]]*:[[:space:]]*"[^" ]+"' <<<"$_hjson" | head -1 | sed -E 's/.*"serverName"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/' || true)
    [[ -z "$_hdom" ]] && _hdom="__missing_sni__"
    _decoy_rows+=("$_hdom|$_hid|$_hport")
    _decoy_row="${#_decoy_rows[@]}"
    local _h_tpl="$(decoy_tpl_current "$_hdom" 2>/dev/null || true)"; [[ -z "$_h_tpl" ]] && _h_tpl="default"
    printf "   %s) Hysteria #%-3s — %-30s :%s (decoy=%s)\n" "$((_decoy_row+1))" "$_hid" "$_hdom" "$_hport" "$_h_tpl"
  done < <(sqlite3 -separator '|' "$XUI_DB" "SELECT id,protocol,port,COALESCE(stream_settings,'') FROM inbounds WHERE port>0 AND lower(protocol) LIKE '%hysteria%' ORDER BY id;" 2>/dev/null || true)
  local _d_dom _d_be _d_id _d_proto _d_st _d_port
  while IFS='|' read -r _d_dom _d_be; do
    [[ "$_d_be" =~ ^inb_([0-9]+)_backend$ ]] || continue
    _d_id="${BASH_REMATCH[1]}"
    _d_proto=$(sqlite3 -cmd ".timeout 3000" "$XUI_DB" "SELECT protocol FROM inbounds WHERE id=$_d_id AND enable=1;" 2>/dev/null || true)
    _d_st=$(sqlite3 -cmd ".timeout 3000" "$XUI_DB" "SELECT COALESCE(stream_settings,'') FROM inbounds WHERE id=$_d_id;" 2>/dev/null || true)
    # Только XHTTP+TLS не имеет decoy. XHTTP+Reality, напротив, оставляем:
    # для Reality decoy является dest и его можно менять.
    if grep -Eqi '"network"[[:space:]]*:[[:space:]]*"xhttp"' <<<"$_d_st" && \
       grep -Eqi '"security"[[:space:]]*:[[:space:]]*"tls"' <<<"$_d_st"; then
      continue
    fi
    # В список попадают только реально поддерживаемые объекты:
    # собственный Reality, VLESS/Trojan TCP+TLS и Hysteria TCP-decoy.
    # Чужой Reality (внешний dest) исключаем: у него decoy не применяется.
    [[ "$_d_proto" == "vless" || "$_d_proto" == "trojan" ]] || continue
    local _d_is_reality=false _d_is_tls=false _d_dest=""
    grep -Eqi '"security"[[:space:]]*:[[:space:]]*"reality"' <<<"$_d_st" && _d_is_reality=true
    grep -Eqi '"security"[[:space:]]*:[[:space:]]*"tls"' <<<"$_d_st" && _d_is_tls=true
    if [[ "$_d_is_reality" == true ]]; then
      _d_dest=$(sqlite3 -noheader "$XUI_DB" "SELECT COALESCE(json_extract(stream_settings,'\$.realitySettings.dest'),json_extract(stream_settings,'\$.realitySettings.target'),'') FROM inbounds WHERE id=$_d_id;" 2>/dev/null || true)
      _d_dest="${_d_dest%%:*}"
      [[ -n "$_d_dest" && "$_d_dest" != "127.0.0.1" ]] && continue
    elif [[ "$_d_is_tls" != true ]]; then
      continue
    fi
    _d_port=$(sqlite3 -cmd ".timeout 3000" "$XUI_DB" "SELECT port FROM inbounds WHERE id=$_d_id;" 2>/dev/null || true)
    _decoy_rows+=("$_d_dom|$_d_id|$_d_port")
    _decoy_row="${#_decoy_rows[@]}"
    local _d_tpl="$(decoy_tpl_current "$_d_dom" 2>/dev/null || true)"; [[ -z "$_d_tpl" ]] && _d_tpl="default"
    if [[ "$_d_is_tls" == true ]]; then
      printf "   %s) %s TLS #%-3s — %-30s :%s (decoy=%s)\n" "$((_decoy_row+1))" "${_d_proto^^}" "$_d_id" "$_d_dom" "$_d_port" "$_d_tpl"
    else
      printf "   %s) Reality #%-3s — %-30s :%s (decoy=%s)\n" "$((_decoy_row+1))" "$_d_id" "$_d_dom" "$_d_port" "$_d_tpl"
    fi
  done < <(awk '
    /^map / { inmap=1; next }
    inmap && /^}/ { inmap=0 }
    inmap && /^[[:space:]]/ && NF >= 2 {
      dom=$1; sub(/;$/, "", dom); be=$2; sub(/;$/, "", be)
      if (dom != "" && dom != "default" && (be ~ /^inb_[0-9]+_backend$/ || be ~ /^hysteria_[0-9]+_web$/)) print dom "|" be
    }' "$SNI_CONF" 2>/dev/null)
  # Восстановление из БД для TCP/TLS может понадобиться после старого backup;
  # XHTTP+TLS здесь намеренно не показывается — у него нет decoy.
  while IFS='|' read -r _tid _tproto _tport _tst; do
    [[ "$_tproto" == "vless" || "$_tproto" == "trojan" ]] || continue
    grep -Eqi '"security"[[:space:]]*:[[:space:]]*"tls"' <<<"$_tst" || continue
    # Исключаем только XHTTP+TLS; XHTTP+Reality имеет decoy через Reality dest.
    if grep -Eqi '"network"[[:space:]]*:[[:space:]]*"xhttp"' <<<"$_tst" && \
       grep -Eqi '"security"[[:space:]]*:[[:space:]]*"tls"' <<<"$_tst"; then
      continue
    fi
    _tdom=$(sqlite3 -noheader "$XUI_DB" "SELECT COALESCE(json_extract(stream_settings,'\$.tlsSettings.serverName'),json_extract(settings,'\$.tlsSettings.serverName'),'') FROM inbounds WHERE id=$_tid;" 2>/dev/null | head -1 || true)
    [[ -z "$_tdom" || "$_tdom" == "null" ]] && continue
    local _tid_seen=false _trow
    for _trow in "${_decoy_rows[@]}"; do
      [[ "${_trow#*|}" == "$_tid|"* ]] && _tid_seen=true
    done
    [[ "$_tid_seen" == true ]] && continue
    _decoy_rows+=("$_tdom|$_tid|$_tport")
    _decoy_row="${#_decoy_rows[@]}"
    local _t_tpl="$(decoy_tpl_current "$_tdom" 2>/dev/null || true)"; [[ -z "$_t_tpl" ]] && _t_tpl="default"
    printf "   %s) %s TLS #%-3s — %-30s :%s (decoy=%s)\\n" "$((_decoy_row+1))" "${_tproto^^}" "$_tid" "$_tdom" "$_tport" "$_t_tpl"
  done < <(sqlite3 -separator '|' "$XUI_DB" "SELECT id,protocol,port,COALESCE(stream_settings,'') FROM inbounds WHERE enable=1 AND port>0 AND (protocol='vless' OR protocol='trojan') ORDER BY id;" 2>/dev/null || true)
  # Hysteria может быть в БД, но ещё не иметь SNI-map (например, после
  # восстановления старого бэкапа). Добавляем её напрямую из stream_settings.
  while IFS='|' read -r _hid _hproto _hport; do
    [[ -n "$_hid" ]] || continue
    _d_dom=$(sqlite3 -noheader "$XUI_DB" "SELECT COALESCE(json_extract(stream_settings,'\$.tlsSettings.serverName'),json_extract(settings,'\$.tlsSettings.serverName'),'') FROM inbounds WHERE id=$_hid;" 2>/dev/null | head -1 || true)
    if [[ -z "$_d_dom" || "$_d_dom" == "null" ]]; then
      _d_dom=$(sqlite3 -noheader "$XUI_DB" "SELECT COALESCE(stream_settings,'') FROM inbounds WHERE id=$_hid;" 2>/dev/null | grep -oE '"serverName"[[:space:]]*:[[:space:]]*"[^"]+"' | head -1 | sed -E 's/.*"serverName"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/' || true)
    fi
    [[ -z "$_d_dom" || "$_d_dom" == "null" ]] && _d_dom="__missing_sni__"
    local _seen=false _row
    for _row in "${_decoy_rows[@]}"; do [[ "${_row%%|*}" == "$_d_dom" ]] && _seen=true; done
    [[ "$_seen" == true ]] && continue
    _decoy_rows+=("$_d_dom|$_hid|$_hport")
    _decoy_row="${#_decoy_rows[@]}"
    local _hm_tpl="$(decoy_tpl_current "$_d_dom" 2>/dev/null || true)"; [[ -z "$_hm_tpl" ]] && _hm_tpl="default"
    printf "   %s) Hysteria #%-3s — %-30s :%s (decoy=%s)\n" "$((_decoy_row+1))" "$_hid" "$_d_dom" "$_hport" "$_hm_tpl"
  done < <(sqlite3 -separator '|' "$XUI_DB" "SELECT id,protocol,port FROM inbounds WHERE port>0 AND lower(protocol) LIKE '%hysteria%' ORDER BY id;" 2>/dev/null || true)
  # CDN-инбаунд не попадает в SNI-map: его decoy обслуживается ORIGIN-доменом
  # через nginx CDN-фронтенд. Показываем ORIGIN в этом меню отдельно.
  local -a _cdn_decoy_ids=()
  local _cid _cproto _corigin _ccdn _cpath _ctpl _cdport
  cdn_profiles_load
  while IFS='|' read -r _cid _cproto _corigin _ccdn _cpath _ctpl _cdport; do
    [[ -n "$_cid" && -n "$_corigin" ]] || continue
    _decoy_rows+=("$_corigin|$_cid|${_cdport:-0}")
    _cdn_decoy_ids+=("$_cid")
    _decoy_row="${#_decoy_rows[@]}"
    local _cdn_tpl="${_ctpl:-$(decoy_tpl_current "$_corigin" 2>/dev/null || true)}"; [[ -z "$_cdn_tpl" ]] && _cdn_tpl="default"
    printf "   %s) CDN ORIGIN #%-3s — %-30s :%s (decoy=%s)\n" "$((_decoy_row+1))" "$_cid" "$_corigin" "${_cdport:-0}" "$_cdn_tpl"
  done < <(cat "$CDN_PROFILES" 2>/dev/null)
  echo "   0) Назад"
  local m=""
  ask m "Объект" "1" '^[0-9]+$'
  [[ "$m" == "0" ]] && return 0
  if (( m > 1 )); then
    local _ri=$((m-2))
    (( _ri >= 0 && _ri < ${#_decoy_rows[@]} )) || { err "Нет такого объекта"; pause; return 1; }
    IFS='|' read -r _pick_dom _pick_id _pick_port <<<"${_decoy_rows[$_ri]}"
    if [[ -n "$(cdn_profile_get "$_pick_id" 2>/dev/null)" ]]; then
      cdn_change_decoy "$_pick_id"
      return $?
    fi
    decoy_pick_inbound "$_pick_id" "$_pick_dom"
    return $?
  fi
  # ── 1) decoy домена панели ──
  local panel_conf="$STACK_CONF"
  local panel_dom=""
  panel_dom=$(xui_get subDomain 2>/dev/null || true)
  [[ -z "$panel_dom" || "$panel_dom" == "null" ]] && panel_dom=$(xui_get webDomain 2>/dev/null || true)
  [[ -z "$panel_dom" || "$panel_dom" == "null" ]] && { err "Домен панели не найден — сначала п.1"; pause; return 1; }
  local domain="$panel_dom"
  log "Домен панели: $domain"

  # Корень панели = прокси на AdGuard? Смену decoy ЗАПРЕЩАЕМ:
  # шаблон заменит прокси и сломает AdGuard UI/DoH.
  # Проверяем фактический proxy_pass и сохранённый режим установки.
  local pd_any="" adg_port_now="" adg_panel_root=false
  pd_any=$(sed -n '/listen 127\.0\.0\.1:4443/,/^}/p' "$panel_conf" 2>/dev/null \
           | grep -oE 'proxy_pass https://127\.0\.0\.1:[0-9]+' || true)
  adg_port_now=$(adg_config_port 2>/dev/null || true)
  if [[ -n "$adg_port_now" ]] && grep -q ":$adg_port_now$" <<<"$pd_any"; then
    adg_panel_root=true
  fi
  if [[ "${ADG_PLACEMENT:-}" == "panel" ]] && [[ "${ADG_PRESENT:-false}" == true ]]; then
    adg_panel_root=true
  fi
  if [[ "$adg_panel_root" == true ]]; then
    warn "Корень домена панели обслуживает AdGuard Home."
    warn "Смена decoy ЗАПРЕЩЕНА: будет сломан AdGuard UI/DoH."
    warn "Сначала перенеси AdGuard через п.1 на отдельный SNI-домен или в локальный режим."
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
      # Одной замены index.html недостаточно: после удаления AdGuard или
      # прежней смены decoy в stack.conf мог остаться return 302 /404.html.
      # Пересобираем только корневой location панели, сохраняя webBasePath
      # и subPath подписки.
      panel_decoy_apply stub "$PANEL_DECOY_DIR" || {
        warn "Не удалось применить корневой location decoy панели"
        return 1
      }
      nginx_reload || true
      log "Decoy панели сменён на «$tpl»"
    else
      err "Шаблон «$tpl» не найден (ищу $tpl_src). Доступны:"
      ls -1 "$DECOY_TPL_DIR" 2>/dev/null | sed 's/^/    /'
    fi
    pause; return 0
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
    # Сервис числится установленным, но не активен — честно говорим об этом,
    # а не рисуем URL, по которому всё равно 502.
    if [[ -n "$ADG_SERVICE" ]] && ! systemctl is-active --quiet "$ADG_SERVICE" 2>/dev/null; then
      echo "  AdGuard: сервис '$ADG_SERVICE' не активен (переустановка — раздел 7-2)"
    else
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
  fi
  # ── Креды: cred-файлы — это СНИМОК пароля на момент установки/смены,
  # а не живые данные: пароль часто меняют позже, и дамп содержимого
  # вводит в заблуждение. Показываем путь и дату снимка, не сам пароль.
  local cf cdate
  cf=/root/panel-credentials.txt
  if [[ -f "$cf" ]]; then
    cdate=$(grep -m1 -oE '[0-9]{4}-[0-9]{2}-[0-9]{2}' "$cf" 2>/dev/null || true)
    echo "  Креды панели:  $cf (снимок ${cdate:-без даты}; пароль меняли — используйте свой)"
  fi
  if [[ "$ADG_PRESENT" == true && -f /root/adguard-credentials.txt ]]; then
    cdate=$(grep -m1 -oE '[0-9]{4}-[0-9]{2}-[0-9]{2}' /root/adguard-credentials.txt 2>/dev/null || true)
    echo "  Креды AdGuard: /root/adguard-credentials.txt (снимок ${cdate:-без даты})"
  fi

  echo; echo "▸ SNI:"
  grep -E '^\s+[a-zA-Z0-9.-]+\.|^upstream' "$SNI_CONF" 2>/dev/null | sed 's/^/  /' || true
  echo; echo "▸ Inbounds:"
  sqlite3 -header -column "$XUI_DB" "SELECT id, protocol, port, listen, enable, remark FROM inbounds ORDER BY id;" 2>/dev/null || true
  # баны: в шапке меню — сумма по всем jail'ам, детали — в п.7; здесь не дублируем
  pause
}


# =====================================================================
