# =====================================================================
# AMNEZIAWG (LucX sidecar): инбаунды протокола 'awg' в панели.
# Панель LucX сама пишет /etc/amnezia/amneziawg/awg<id>.conf и поднимает
# kernel-интерфейс (модуль amneziawg 3.x) при рестарте. Скрипт только
# создаёт инбаунд в БД с корректным settings-JSON — «кнопка Сгенерировать».
# Две версии (профиль обфускации Amnezia Premium, obfLevel=4, mimicry tls):
#   3.1 — header protection + content padding + таймеры-диапазоны, H1-H4 не
#         используются (заглушки 1..4), I1-маскировка под TLS ClientHello;
#   2.0 — H1-H4 как ДИАПАЗОНЫ, S1-S4, I1; без header protection.
# I1-шаблоны взяты из реальных инбаундов LucX (регион ru, browser chrome).
# =====================================================================

# Генератор ключей AWG: <privateKey>|<publicKey>
awg_keypair() {
  local priv="" pub=""
  if command -v awg >/dev/null 2>&1; then
    priv=$(awg genkey 2>/dev/null) || true
    [[ -n "$priv" ]] && pub=$(printf '%s' "$priv" | awg pubkey 2>/dev/null) || true
  fi
  if [[ -z "$priv" || -z "$pub" ]]; then
    # fallback: чистый wireguard-toolset формат (base64 32 байта)
    priv=$(openssl rand -base64 32 2>/dev/null) || true
    pub=""
  fi
  [[ -z "$priv" ]] && { err "awg genkey недоступен (нужен пакет amneziawg-tools)"; return 1; }
  echo "${priv}|${pub}"
  return 0
}

# Случайный диапазон "a-b" (для H1-H4 2.0 и таймеров 3.1)
__awg_range() {   # <start_min> <start_max> <width_min> <width_max>
  local a=$(( (RANDOM % ($2 - $1 + 1)) + $1 ))
  local w=$(( (RANDOM % ($4 - $3 + 1)) + $3 ))
  echo "$a-$(( a + w ))"
}

# Следующая свободная подсеть 10.2XX.0.1/24 (XX: 200..249) по существующим awg
awg_subnet_next() {
  local used="" a
  if [[ -n "$XUI_DB" && -f "$XUI_DB" ]]; then
    while IFS= read -r a; do
      [[ "$a" =~ ^10\.([0-9]+)\.0\. ]] && used+=" ${BASH_REMATCH[1]} "
    done < <(sqlite3 -noheader "$XUI_DB" \
      "SELECT COALESCE(json_extract(settings,'\$.address'),'') FROM inbounds WHERE protocol='awg';" 2>/dev/null || true)
  fi
  local n
  for n in $(seq 200 249); do
    [[ " $used " != *" $n "* ]] && { echo "$n"; return 0; }
  done
  err "Подсети 10.200-10.249 исчерпаны"
  return 1
}

# Свободный UDP-порт под AWG (20000-59999, вне БД и сокетов)
awg_port_next() {
  local p tries=0 in_db
  while (( tries < 40 )); do
    p=$(( (RANDOM % 40000) + 20000 ))
    in_db=0
    [[ -n "$XUI_DB" && -f "$XUI_DB" ]] && \
      in_db=$(sqlite3 "$XUI_DB" "SELECT COUNT(*) FROM inbounds WHERE port=$p;" 2>/dev/null || echo 1)
    if ! port_in_use "$p" && [[ "$in_db" == "0" ]]; then
      echo "$p"; return 0
    fi
    tries=$((tries+1))
  done
  echo ""
  return 1
}

# I1-маскировочный пакет: шаблон TLS ClientHello (легитимный SNI внутри).
#   3.1 → ozon-профиль (как в панели LucX), 2.0 → facebook-профиль
awg_i1_for() {   # <31|20>
  case "$1" in
    31)
      echo '<b 0x1603010137010001330303><r 32><b 0x20><r 32><b 0x00209a9a130113021303c02bc02fc02cc030cca9cca8c013c014009c009d002f0035010000ca5a5a00000000000c000a0000076f7a6f6e2e727500170000ff01000100000a000a00087a7a001d00170018000b00020100002300000010000e000c02683208687474702f312e31000500050100000000000d0014001204030804040105030805020308060402020100120000002b0007068a8a030403030033002b00294a4a000100001d0020a9af016c4da0e62c79c34ba5dead40d42a123795c336c8091f18104ed611de08002d00020101001b000302000244690004000268323a3a00000015000700000000000000>'
      ;;
    20)
      echo '<b 0x160301014b010001470303><r 32><b 0x20><r 32><b 0x0020aaaa130113021303c02bc02fc02cc030cca9cca8c013c014009c009d002f0035010000de5a5a000000000011000f00000c66616365626f6f6b2e636f6d00170000ff01000100000a000a00080a0a001d00170018000b00020100002300000010000e000c02683208687474702f312e31000500050100000000000d0014001204030804040105030805020308060402020100120000002b0007065a5a030403030033002b00299a9a000100001d00209deaea5f5cc268bab070c4de1eb07c9a1a4b233811ead9a717858eb4aac79ae9002d00020101001b00030200024469000400026832baba00000015001600000000000000000000000000000000000000000000>'
      ;;
  esac
}

# settings-JSON инбаунда awg. $1 = 31|20, $2 = UDP-порт
awg_settings_json() {   # <31|20> <port>
  local ver="$1" port="$2"
  [[ "$ver" != "31" && "$ver" != "20" ]] && { err "AWG версия: 31 или 20"; return 1; }
  local kp priv pub
  kp=$(awg_keypair) || return 1
  priv="${kp%%|*}"; pub="${kp##*|}"
  [[ -z "$pub" ]] && { err "не удалось получить publicKey"; return 1; }

  local subnet; subnet=$(awg_subnet_next) || return 1
  # Профиль обфускации Amnezia Premium (obfLevel=4): значения как в панели LucX
  local jc=5 jmin=10 jmax=80 s1=164 s2=528 s3=389 s4=12
  local i1; i1=$(awg_i1_for "$ver")
  local hpk="" h1 h2 h3 h4 cpa rkt rat kat mha rt dc
  if [[ "$ver" == "31" ]]; then
    hpk=$(awg genkey 2>/dev/null || openssl rand -base64 32)
    h1=1; h2=2; h3=3; h4=4                       # заглушки: заголовки закрыты HPK
    cpa="10-100"                                 # как в профиле панели LucX
    rat="100-120"; rkt="4-8"; kat="7-13"; mha="13-15"
    rt="true"; dc="true"
  else
    h1=$(__awg_range 20000 60000 40000 90000)
    h2=$(__awg_range 100000 160000 40000 90000)
    h3=$(__awg_range 200000 260000 40000 90000)
    h4=$(__awg_range 300000 360000 40000 90000)
    cpa="0"; rat="0"; rkt="0"; kat="0"; mha="0"
    rt="false"; dc="false"
  fi
  # ВАЖНО: json-строки без переносов; I1 уже однострочный
  cat <<EOF
{"privateKey":"$priv","publicKey":"$pub","address":"10.$subnet.0.1/24","mtu":1420,"dns":"1.1.1.1, 1.0.0.1","obfLevel":4,"mimicryProfile":"tls","browserProfile":"chrome","region":"ru","jc":$jc,"jmin":$jmin,"jmax":$jmax,"s1":$s1,"s2":$s2,"s3":$s3,"s4":$s4,"h1":"$h1","h2":"$h2","h3":"$h3","h4":"$h4","i1":"$i1","i2":"","i3":"","i4":"","i5":"","headerProtectionKey":"$hpk","contentPaddingAddition":"$cpa","rekeyAfterTime":"$rat","rekeyTimeout":"$rkt","rejectAfterTime":"$rat","keepaliveTimeout":"$kat","maxHandshakeAttempts":"$mha","randomTrailers":$rt,"disableCookies":$dc,"awgVersion":"$([[ "$ver" == 31 ]] && echo 3.1 || echo 2)","clients":[],"routeThroughXray":true,"xrayRoutingMode":"tun","tproxyPort":51453,"outboundTag":"","p2p":false}
EOF
  return 0
}

# Список AWG-инбаундов панели: id|порт|версия|адрес
awg_inbounds_list() {
  [[ -z "$XUI_DB" || ! -f "$XUI_DB" ]] && return 0
  sqlite3 -separator '|' "$XUI_DB" \
    "SELECT id, port, COALESCE(json_extract(settings,'\$.awgVersion'),'?'), COALESCE(json_extract(settings,'\$.address'),'') FROM inbounds WHERE protocol='awg' AND enable=1 ORDER BY id;" 2>/dev/null || true
}

# __awg_ufw_has <порт> → 0, если правило UDP есть (и UFW активен); 1 — нет/выключен
__awg_ufw_has() {
  command -v ufw >/dev/null 2>&1 || return 1
  ufw status 2>/dev/null | grep -q "Status: active" || return 1
  ufw status 2>/dev/null | awk -v p="$1" \
    '$0 ~ ("(^|[[:space:]])" p "/udp([[:space:]]|$)") || $0 ~ ("(^|[[:space:]])" p "([[:space:]]|$)") {found=1} END{exit !found}'
}

# Секция аудита для stack_full_audit (п.4). Число проблем — в $AWG_AUDIT_ISSUES.
awg_audit() {
  AWG_AUDIT_ISSUES=0
  local row id port ver addr n=0 cfg ifc
  while IFS='|' read -r id port ver addr; do
    [[ -z "$id" ]] && continue
    n=$((n+1))
    cfg="нет"; [[ -f "/etc/amnezia/amneziawg/awg${id}.conf" ]] && cfg="да"
    ifc="нет"; ip link show "awg${id}" >/dev/null 2>&1 && ifc="да"
    local msg="  #$id AWG v$ver UDP/$port $addr — конфиг: $cfg, интерфейс: $ifc"
    if [[ "$cfg" == "нет" || "$ifc" == "нет" ]]; then
      warn "$msg"; AWG_AUDIT_ISSUES=$((AWG_AUDIT_ISSUES+1))
    else
      log "$msg"
    fi
    if __awg_ufw_has "$port"; then
      log "  #$id: UFW UDP/$port — есть"
    elif command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
      warn "  #$id: UFW UDP/$port — правила нет"; AWG_AUDIT_ISSUES=$((AWG_AUDIT_ISSUES+1))
    fi   # UFW выключен — не замечание
  done < <(awg_inbounds_list)
  (( n == 0 )) && echo "  (AWG-инбаундов нет)"
  return 0
}

# Починка AWG для п.6.1: отсутствующие UFW-правила + не поднятые интерфейсы.
# Конфиги awg<id>.conf НЕ пишем — их генерирует панель; если интерфейсов нет,
# рестарт x-ui заставляет панель пересоздать их из БД.
awg_repair() {
  local any=0 missing=0 id port ver addr
  while IFS='|' read -r id port ver addr; do
    [[ -z "$id" ]] && continue
    any=$((any+1))
    ip link show "awg${id}" >/dev/null 2>&1 || missing=$((missing+1))
    if ! __awg_ufw_has "$port"; then
      fw_allow "$port" udp "AmneziaWG awg${id}"
      log "  AWG #$id: UDP/$port открыт в UFW"
    fi
  done < <(awg_inbounds_list)
  (( any == 0 )) && return 0
  if (( missing > 0 )); then
    warn "  AWG: интерфейсов нет у $missing из $any — рестарт x-ui (панель поднимает их сама)"
    systemctl restart x-ui >/dev/null 2>&1 || true
    sleep 4
    local still=0
    while IFS='|' read -r id port ver addr; do
      [[ -z "$id" ]] && continue
      if ! ip link show "awg${id}" >/dev/null 2>&1; then
        still=$((still+1))
        warn "  AWG #$id: интерфейс awg${id} не поднялся — journalctl -u x-ui | tail -30"
      fi
    done < <(awg_inbounds_list)
    (( still == 0 )) && log "  AWG: все интерфейсы подняты"
  fi
  return 0
}

# Статус AWG: инбаунды панели + живые kernel-интерфейсы
awg_status() {
  line; echo -e "${B}   AMNEZIAWG: СТАТУС${N}"; line
  echo -e "${B}Инбаунды панели:${N}"
  local row n=0
  while IFS='|' read -r id port ver addr; do
    [[ -z "$id" ]] && continue
    echo "  #$id  UDP/$port  AWG v$ver  $addr"
    n=$((n+1))
  done < <(awg_inbounds_list)
  (( n == 0 )) && echo "  (нет — создай через п.6.3 → «AMNEZIAWG»)"
  echo
  echo -e "${B}Kernel-интерфейсы (awg show):${N}"
  command -v awg >/dev/null 2>&1 && awg show 2>/dev/null | sed -n '1,80p' || warn "  awg не найден"
  return 0
}

awg_menu() {
  line; echo -e "${B}   AMNEZIAWG (LUCX SIDECAR)${N}"; line
  echo "  1) Создать инбаунд AWG 3.1 (Premium-профиль)"
  echo "  2) Создать инбаунд AWG 2.0 (Premium-профиль)"
  echo "  3) Статус (инбаунды + интерфейсы)"
  echo "  0) Назад"
  local m=""
  ask m "Выбор" "0" '^[0-9]$'
  case "$m" in
    1|2)
      local ver="31"; [[ "$m" == "2" ]] && ver="20"
      local port; port=$(awg_port_next)
      [[ -z "$port" ]] && { err "Не нашёл свободный UDP-порт"; return 1; }
      local name="AMNEZIAWG $([[ "$ver" == 31 ]] && echo 3.1 || echo 2.0) (UDP, Premium)"
      local transport="awg$ver"
      local proto="awg" security="-" flow="-" net="udp" sni_domain="" vk=""
      local remark; remark=$(inbound_remark_next "$proto" "$transport" "$security")
      log "Создаю: $name (port=$port)"
      local new_id
      new_id=$(create_inbound_db "$proto" "$transport" "$security" "$flow" "$port" "$remark" "$net" "$sni_domain" "$vk") || return 1
      [[ -z "$new_id" ]] && return 1
      ufwd_allow_udp "$port"
      systemctl restart x-ui >/dev/null 2>&1 || true
      sleep 3
      log "  → id=$new_id (UDP/$port). Интерфейс поднимет панель (awg$ver-профиль)."
      log "  Клиенты: панель → инбаунд #$new_id → «Сгенерировать» (QR/конфиг)."
      ;;
    3) awg_status ;;
  esac
  return 0
}
