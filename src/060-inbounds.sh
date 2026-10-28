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
{"remark":"anytls-$port","enabled":true,"port":$port,"listen":"127.0.0.1","password":"$(gen_b64)","sni":"$sn","certFile":"$cert","keyFile":"$key"}
EOF
) ;;
    trusttunnel|trust-tunnel)
      # tunnel-инбаунд LucX (trusttunnel_inbound.go): hostname+cert обязательны,
      # клиенты → HMAC-креды из authSeed (панель покажет их и в share-ссылках)
      settings_json=$(cat <<EOF
{"remark":"trusttunnel-$port","hostname":"$sn","listen":"127.0.0.1","port":$port,"ipv6":false,"certFile":"$cert","keyFile":"$key","clientDns":"1.1.1.1","upstreamProtocol":"http2","routeThroughXray":false,"routeXrayPort":0,"outboundTag":"","metricsPort":0,"listenPreset":"fast","clientRandomPrefix":"$(gen_hex 4)/ffffffff","authSeed":"$(gen_hex 32)","clients":[]}
EOF
) ;;
    naive|naiveproxy)
      # tunnel-инбаунд LucX (naive_inbound.go): caddy forward_proxy за nginx 443.
      # СЕРВИСНЫЙ логин/пароль генерируем сразу + authSeed для клиентских пар.
      settings_json=$(cat <<EOF
{"remark":"naive-$port","listen":"127.0.0.1","port":$port,"domain":"$sn","useAcme":false,"acmeEmail":"","certFile":"$cert","keyFile":"$key","authUser":"$(gen_hex 4)","authPass":"$(gen_b64)","enableH3":false,"probeResistance":false,"logLevel":"WARN","extraArgs":"","routeThroughXray":false,"routeXrayPort":0,"outboundTag":"","useRawConfig":false,"rawConfig":"","behindCover":false,"hideOn443":false,"authSeed":"$(gen_hex 32)","clients":[{"email":"user","enable":true}]}
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
      # LucX sidecar: settings генерирует awg_settings_json (версия в transport:
      # awg31 → AmneziaWG 3.1, awg20 → 2.0; профиль обфускации Amnezia Premium)
      settings_json=$(awg_settings_json "${transport#awg}" "$port") ;;
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
          stream_json="{\"network\":\"tcp\",\"security\":\"tls\",\"tlsSettings\":{\"serverName\":\"$sn\",\"minVersion\":\"1.2\",\"alpn\":[\"http/1.1\"],\"certificates\":[{\"certificateFile\":\"$cert\",\"keyFile\":\"$key\"}]},\"tcpSettings\":{\"acceptProxyProtocol\":false,\"header\":{\"type\":\"none\"}}}"
        else
          stream_json="{\"network\":\"tcp\",\"security\":\"tls\",\"tlsSettings\":{\"serverName\":\"$sn\",\"minVersion\":\"1.2\",\"alpn\":[\"http/1.1\"]},\"tcpSettings\":{\"acceptProxyProtocol\":false,\"header\":{\"type\":\"none\"}}}"
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
      elif [[ "$security" == "tls" ]]; then
        if [[ -n "$cert" && -n "$key" ]]; then
          stream_json="{\"network\":\"xhttp\",\"security\":\"tls\",\"tlsSettings\":{\"serverName\":\"$sn\",\"minVersion\":\"1.2\",\"certificates\":[{\"certificateFile\":\"$cert\",\"keyFile\":\"$key\"}]},\"xhttpSettings\":{\"path\":\"/$(gen_hex 6)\",\"host\":\"$sn\",\"mode\":\"auto\"}}"
        else
          stream_json="{\"network\":\"xhttp\",\"security\":\"tls\",\"tlsSettings\":{\"serverName\":\"$sn\",\"minVersion\":\"1.2\"},\"xhttpSettings\":{\"path\":\"/$(gen_hex 6)\",\"host\":\"$sn\",\"mode\":\"auto\"}}"
        fi
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
    awg)
      # kernel-инбаунд панели: stream_settings пустая строка (как у созданных в UI)
      stream_json=''
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
    awg)
      sniffing_json='' ;;   # kernel-инбаунд: без sniffing (как у созданных в UI)
  esac
  local listen
  case "$proto" in
    qwdtt|csqtt|hysteria) listen="" ;;          # порт живёт в settings.listenAddr
    tproxy)               listen="127.0.0.1" ;; # наружу только через nginx 443
    awg)                  listen="" ;;          # порт живёт в settings (ListenPort конфига)
    *) [[ "$net" == "udp" ]] && listen="0.0.0.0" || listen="127.0.0.1" ;;
  esac
  local tag_name="inbound-$port"
  case "$proto" in
    qwdtt) tag_name="inbound-qwdtt" ;;
    csqtt) tag_name="inbound-csqtt" ;;
    tproxy) tag_name="inbound-tproxy" ;;
    awg)   tag_name="in-$port-tcp" ;;   # панель LucX именует теги AWG так
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
  if [[ "$proto" == "vless" && "$transport" == "xhttp" && "$security" == "tls" ]]; then
    XHTTP_TLS_CREATED_IDS="${XHTTP_TLS_CREATED_IDS:-} $new_id"
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
    qwdtt|csqtt|tproxy|awg) ensure_shareonly_triggers ;;
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
  # Гейт по типу панели: в оригинальном 3x-ui доступны VLESS и Hysteria2.
  # QWDTT/CSQTT/tproxy/naive/anytls/trusttunnel/hysteria — рецепты LucX UI:
  # панель LucX сама поднимает sidecar'ы и понимает свои форматы settings.
  local flavor="${PANEL_FLAVOR:-}"
  [[ -z "$flavor" ]] && flavor=$(detect_panel_flavor)
  case "$flavor" in
    lucx) echo "  Обнаружена панель: LucX UI — доступны LucX sidecar-протоколы." ;;
    3x-ui) echo "  Обнаружена панель: оригинальный 3x-ui — доступны только VLESS и Hysteria2." ;;
    *) echo "  Панель не распознана — доступны только базовые протоколы VLESS и Hysteria2." ;;
  esac
  if [[ "$flavor" != "lucx" ]]; then
    warn "Панель: ${flavor:-неизвестно} — показываю только то, что она умеет запускать."
    [[ "$flavor" == "3x-ui" ]] && warn "QWDTT/CSQTT/tproxy/naive/anytls/trusttunnel — доступны только в LucX UI: п.7 → «Мигрировать 3x-ui → LucX UI»."
  fi
  local i=1 entry name proto
  local -a NAMES=()
  for entry in "${RECOMMENDED_INBOUNDS[@]}"; do
    IFS='|' read -r _ proto _ <<<"$entry"
    [[ "$flavor" != "lucx" && "$proto" != "vless" && "$proto" != "hysteria" ]] && continue
    name="${entry%%|*}"
    printf "  %2d) %s\n" "$i" "$name"
    NAMES+=("$entry")
    i=$((i+1))
  done
  if [[ ${#NAMES[@]} -eq 0 ]]; then
    err "Для панели ${flavor:-неизвестно} доступных протоколов нет — открой п.7 и проверь установленную панель."
    return 1
  fi
  echo
  echo "  0) Отмена"
  echo
  if [[ "$flavor" == "lucx" ]]; then
    echo "Пример: 1 2    (VLESS TCP Reality, VLESS XHTTP Reality)"
  else
    echo "Пример: 1 2    (из показанных протоколов VLESS или Hysteria2)"
  fi
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

    # Фиксированный пункт CDN в ручном мастере тоже должен пройти полный
    # CDN-профиль. Раньше create_inbounds_menu создавал только голый XHTTP,
    # потому что CDN-логика была реализована лишь в auto_full_setup.
    local _is_cdn=false
    CDN_PRE_ANSWER=""; CDN_PRE_CDN=""; CDN_PRE_ORIGIN=""; CDN_PRE_PATH=""; CDN_PRE_TPL=""; CDN_PRE_PROVIDER=""
    if [[ "$name" == "VLESS XHTTP (через CDN)" ]]; then
      _is_cdn=true
      cdn_ask_profile "0" "$proto"
      CDN_PRE_ANSWER="true"
      CDN_PRE_CDN="$CDN_DOM"; CDN_PRE_ORIGIN="$CDN_ORIGIN"; CDN_PRE_PATH="$CDN_PATH"; CDN_PRE_TPL="$CDN_TPL"; CDN_PRE_PROVIDER="$CDN_PROVIDER"
      security="none"
    fi

    local port
    case "$proto" in
      tproxy) port=11443 ;;
      qwdtt)  port=56000; while port_in_use "$port"; do port=$((port+100)); done ;;
      csqtt)  port=46000; while port_in_use "$port"; do port=$((port+100)); done ;;
      awg)    port=$(awg_port_next); [[ -z "$port" ]] && port=$(make_port) ;;
      *)      port=$(make_port) ;;
    esac
    local remark
    remark=$(inbound_remark_next "$proto" "$transport" "$security")

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
    if [[ "$security" == "reality" ]]; then
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
    elif [[ "$security" == "reality" && "$rmode" == "1" ]]; then
      # чужой реалити: живая проверка кандидатов + выбор цели (как в панели)
      local tgt=""
      reality_target_menu tgt "$name"
      REALITY_EXT_TARGET="$tgt"
      printf '%s' "$tgt" > /tmp/.reality-found-target 2>/dev/null || true
      log "  $name: цель → $tgt (dest+serverNames, за 443 по SNI цели)"
    elif [[ "$proto" == "hysteria" || "$proto" == "tproxy" || "$proto" == "naive" || "$proto" == "anytls" || "$proto" == "trusttunnel" || "$proto" == "trust-tunnel" || "$security" == "reality" || ( "$security" == "tls" && ( "$proto" == "trojan" || "$proto" == "vless" ) && ! ( "$proto" == "vless" && "$transport" == "xhttp" && "$name" == "VLESS XHTTP (через CDN)" ) ) ]]; then
      echo
      if [[ -z "$panel_domain" ]]; then
        panel_domain="${PANEL_DOMAIN:-}"
        [[ -z "$panel_domain" ]] && panel_domain=$(xui_get subDomain)
        [[ -z "$panel_domain" ]] && ask panel_domain "Домен панели" "panel.example.com" '^[a-zA-Z0-9.-]+$'
        [[ -n "$panel_domain" ]] && SNI_USED["$panel_domain"]="${SNI_USED[$panel_domain]:-panel_backend}"
      fi
      local def2="h.example.com"
      case "$proto" in
        trojan) def2="t.example.com";;
        vless)
          if [[ "$transport" == "xhttp" ]]; then def2="x.example.com"; else def2="r.example.com"; fi ;;
        naive) def2="n.example.com";;
        anytls) def2="at.example.com";;
        trusttunnel|trust-tunnel) def2="tt.example.com";;
        tproxy) def2="tg.example.com";;
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
      if [[ "$security" == "reality" && "$rmode" != "1" ]]; then
        # Свой SNI у Reality использует только настройки Reality.
        :
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
      if [[ "$port" == "443" ]]; then

        err "Порт 443 запрещён для inbound — это только внешний SNI/nginx-порт"

        continue

      fi

      if [[ "$port" == "80" ]]; then

        err "Порт 80 занят ACME/nginx — выбери другой"
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
        awg)
          # AmneziaWG (LucX sidecar): панель сама напишет /etc/amnezia/amneziawg/
          # awg<id>.conf и поднимет kernel-интерфейс при рестарте x-ui.
          log "  → id=$new_id (UDP $port, AWG $([[ "$transport" == awg31 ]] && echo 3.1 || echo 2.0), Premium-профиль)"
          fw_allow "$port" udp "AmneziaWG awg${new_id}"
          systemctl restart x-ui >/dev/null 2>&1 || true
          sleep 3
          if ip link show "awg${new_id}" >/dev/null 2>&1; then
            log "  → интерфейс awg${new_id} поднят, клиенты: панель → инбаунд → «Сгенерировать»"
          else
            warn "  интерфейс awg${new_id} ещё не поднялся — смотри журнал панели (до 30 с)"
          fi
          ;;
        hysteria)
          log "  → id=$new_id (UDP $port, SNI $sni_domain)"
          SNI_USED["$sni_domain"]="hysteria_${new_id}_web"
          ufwd_allow_udp "$port"
          # UDP Hysteria не может обслужить браузерный TCP/443. Создаём
          # отдельный локальный HTTPS-decoy с тем же доменом и маршрутом SNI.
          local hdecoy_port=$((47000 + new_id)) hcp hcert hkey
          while ss -tlnH "sport = :$hdecoy_port" 2>/dev/null | grep -q .; do hdecoy_port=$((hdecoy_port+1)); done
          hcp=$(cert_paths "$sni_domain" 2>/dev/null || true)
          hcert="${hcp%% *}"; hkey="${hcp##* }"
          if [[ -n "$hcert" && -f "$hcert" && -f "$hkey" ]]; then
            local htpl=""
            decoy_template_choose_impl htpl "Decoy для Hysteria #$new_id ($sni_domain)" "$(decoy_tpl_current "$sni_domain")"
            htpl="${htpl:-$(decoy_tpl_for "$sni_domain")}"
            decoy_tpl_store_set "$sni_domain" "$htpl" >/dev/null 2>&1 || true
            mk_decoy "$hdecoy_port" "$sni_domain" "$hcert" "$hkey" "/var/www/decoy-hysteria-$new_id" "$htpl"
            sni_upstream_add "hysteria_${new_id}_web" "$hdecoy_port"
            sni_map_add "$sni_domain" "hysteria_${new_id}_web"
            nginx_reload || true
            log "  → TCP/443 для $sni_domain ведёт в 404-decoy (UDP Hysteria не изменён)"
          else
            warn "  Сертификат $sni_domain не найден — TCP-decoy не создан"
          fi
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
           if [[ "${_is_cdn:-false}" == true ]]; then
             CDN_FORCE_IDS="${CDN_FORCE_IDS:-} $new_id"
             xhttp_cdn_setup "$new_id" "$proto" "$port" || warn "  CDN-профиль для #$new_id не применён"
           fi
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
