# FIREWALL
# =====================================================================

fw_allow() {
  local port="$1" proto="$2" comment="${3:-}"
  [[ -z "$port" || "$port" == "0" ]] && return 0
  local args=(allow)
  [[ -n "$comment" ]] && args+=(comment "$comment")
  ufw "${args[@]}" "$port/$proto" >/dev/null 2>&1 || true
}

# SSH «через туннель»: sshd слушает только loopback → порт наружу не открываем.
# Порт берём из SSH_PORT (sshd мог переехать с 22 — раньше проверки были на
# хардкод 22 и на кастомном порту ошибочно открывали SSH наружу).
ssh_loopback_only() {
  local sp="${SSH_PORT:-22}"
  ss -tln 2>/dev/null | grep -qE "127\.0\.0\.1:${sp}([[:space:]]|$)" && return 0
  ss -tln 2>/dev/null | grep -qE "\[::1\]:${sp}([[:space:]]|$)" && return 0
  return 1
}

# Переключение web/sub-портов x-ui между loopback и внешним слушателем.
# Используется TUI файрвола: изменение привязки и правила UFW выполняются
# одной операцией, чтобы интерфейс не показывал рассинхронизированное состояние.
xui_set_listen() {
  # Совместимость с TUI: xui_set_listen <port> <mode> и старым
  # внутренним вызовом xui_set_listen <mode>. Настройки web/sub общие.
  local mode="$1" db=""
  [[ "$mode" =~ ^[0-9]+$ ]] && mode="${2:-}"
  [[ "$mode" == "0.0.0.0" || "$mode" == "127.0.0.1" ]] || return 1
  for db in /etc/x-ui/x-ui.db /usr/local/x-ui/x-ui.db /opt/x-ui/x-ui.db; do
    [[ -f "$db" ]] && break
  done
  [[ -f "$db" ]] || { err "x-ui.db не найден"; return 1; }
  systemctl stop x-ui >/dev/null 2>&1 || true
  local ok=1
  # ВАЖНО: если ключей webListen/subListen в settings ещё нет, UPDATE меняет
  # 0 строк и «успешно» ничего не делает — при скрытии панель осталась бы на
  # 0.0.0.0 при рапорте «спрятан». После UPDATE проверяем наличие обоих ключей
  # и вставляем недостающие (upsert).
  if command -v sqlite3 >/dev/null 2>&1; then
    sqlite3 "$db" "UPDATE settings SET value='$mode' WHERE key IN ('webListen','subListen');" >/dev/null 2>&1 || ok=0
    if [[ "$ok" == 1 ]]; then
      local nkeys
      nkeys=$(sqlite3 "$db" "SELECT count(*) FROM settings WHERE key IN ('webListen','subListen');" 2>/dev/null || echo 0)
      if [[ "$nkeys" != "2" ]]; then
        sqlite3 "$db" "INSERT OR REPLACE INTO settings(key,value) VALUES('webListen','$mode'),('subListen','$mode');" >/dev/null 2>&1 || ok=0
      fi
    fi
  else
    ok=0
  fi
  if [[ "$ok" == 0 ]] && command -v python3 >/dev/null 2>&1; then
    python3 - "$db" "$mode" <<'PYX'
import sqlite3, sys
con = sqlite3.connect(sys.argv[1])
cur = con.cursor()
cur.execute("UPDATE settings SET value=? WHERE key IN ('webListen','subListen')", (sys.argv[2],))
n = con.execute("SELECT count(*) FROM settings WHERE key IN ('webListen','subListen')").fetchone()[0]
if n < 2:
    cur.execute("INSERT OR REPLACE INTO settings(key,value) VALUES('webListen',?),('subListen',?)",
                (sys.argv[2], sys.argv[2]))
con.commit(); con.close()
PYX
    ok=$?
  fi
  systemctl start x-ui >/dev/null 2>&1 || true
  [[ "$ok" == 0 ]] && return 1
  sleep 2
  return 0
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
    11443)       return 0;;  # tproxy (TG web-proxy): наружу ТОЛЬКО через 443;
                             # UDP-сокет здесь — HTTP/3 caddy, светить нельзя
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

# Основной интерфейс firewall — сразу компактный TUI обзора сокетов и правил.
# Полное старое меню доступно клавишей m из основного TUI.
firewall_menu_legacy() {
  while :; do
    clear
    line; echo -e "${B}   ФАЙРВОЛ (UFW)${N}"; line
    echo "  Статус: $(ufw status 2>/dev/null | head -1 | awk '{print $2}' || echo unknown)"
    local pol="allowlist"
    [[ -f "$BACKUP_DIR/fw-policy" ]] && pol=$(head -n1 "$BACKUP_DIR/fw-policy" 2>/dev/null | tr -d '[:space:]')
    [[ "$pol" != "hideonly" ]] && pol="allowlist"
    local pol_desc="allowlist — «всё закрыть, кроме списка» (reset + только нужное)"
    [[ "$pol" == "hideonly" ]] && pol_desc="hide-only — «закрыть только спрятанное» (без reset, deny для панельных/11443)"
    echo "  Политика: $pol_desc"
    echo
    declare -A REQ=()
    # SSH только через туннель? (sshd слушает loopback) — 22 наружу не открываем
    if ss -tln 2>/dev/null | grep -qE '127\.0\.0\.1:22([[:space:]]|$)'; then
      echo "  SSH: только через туннель (loopback) — 22 наружу не открываем"
    else
      REQ["tcp:$SSH_PORT"]="SSH"
    fi
    # tcp/80 НЕ открываем: сертификаты — wildcard через DNS-хук (DNS-01),
    # HTTP-01 не нужен; при необходимости открыть разово: ufw allow 80/tcp
    systemctl is-active --quiet nginx 2>/dev/null && REQ["tcp:443"]="HTTPS/SNI"
    # UDP — только инбаунды из БД панели (сокеты чрезмерно шумят: ephemeral)
    local up
    for up in $(udp_inbound_ports); do
      fw_port_locked "$up" && continue
      REQ["udp:$up"]="udp-инбаунд (панель)"
    done
    # СВОИ порты (п.9): то, что запрещено закрывать любой политикой (файл прото/порт)
    declare -A EXTRA=()
    if [[ -s "$BACKUP_DIR/fw-extra" ]]; then
      local ex_proto ex_port
      while IFS=/ read -r ex_proto ex_port; do
        [[ "$ex_proto" =~ ^(tcp|udp)$ && "$ex_port" =~ ^[0-9]+$ ]] || continue
        EXTRA["${ex_proto}:${ex_port}"]="свой порт — не закрывать"
      done < "$BACKUP_DIR/fw-extra"
    fi

    echo "▸ Открытыми БУДУТ:"
    local k
    for k in $(printf '%s\n' "${!REQ[@]}" | sort -t: -k1,1 -k2,2n); do
      printf "  %-6s %-6s %s\n" "${k%%:*}" "${k##*:}" "${REQ[$k]}"
    done
    if [[ ${#EXTRA[@]} -gt 0 ]]; then
      echo "▸ Плюс СВОИ порты (п.9 — политиками не закрываются):"
      for k in $(printf '%s\n' "${!EXTRA[@]}" | sort -t: -k1,1 -k2,2n); do
        printf "  %-6s %-6s %s\n" "${k%%:*}" "${k##*:}" "${EXTRA[$k]}"
      done
    fi
    echo
    line
    echo "  1) ПРИМЕНИТЬ"
    echo "  2) Включить UFW"
    echo "  3) Выключить UFW"
    echo "  4) Показать правила"
    echo "  5) Удалить правило по номеру"
    echo "  6) Сменить политику файрвола"
    echo "  7) Снимок состояния"
    echo "  8) Восстановить из снимка"
    echo "  9) Свои порты — добавить/убрать (не закрываются политиками)"
    echo "  10) Обзор портов: сокет × правило UFW (быстрый список)"
    echo "  11) TUI-обзор (полноэкранный, медленный)"
    echo "  0) Назад"
    line
    local c=""
    read -rp "$(echo -e "${B}Выбор:${N} ")" c || c="0"
    case "$c" in
      1)
        if [[ "$pol" == "hideonly" ]]; then
          askyn confirm "Применить hide-only? (правила НЕ сбрасываются: панельные/11443 закрываются явно)" "n"
          [[ "$confirm" == true ]] || continue
          save_firewall_state
          if ! ssh_loopback_only; then
            fw_allow "$SSH_PORT" tcp "SSH"
          fi
          systemctl is-active --quiet nginx 2>/dev/null && fw_allow 443 tcp "HTTPS/SNI"
          # свои порты открываем явно (idempotent) — политикой не закрываются
          local kk
          for kk in "${!EXTRA[@]}"; do
            fw_allow "${kk##*:}" "${kk%%:*}" "свой порт"
          done
          local hp
          for hp in "$(xui_get webPort 2>/dev/null)" "$(xui_get subPort 2>/dev/null)" 11443; do
            [[ -z "$hp" || "$hp" == "0" ]] && continue
            ufw delete allow "$hp/tcp" >/dev/null 2>&1 || true
            ufw delete allow "$hp/udp" >/dev/null 2>&1 || true
            ufw deny "$hp/tcp" >/dev/null 2>&1 || true
          done
          fw_deny_panel_ports
          ufw --force enable >/dev/null 2>&1 || true
          log "hide-only применено: панельные/служебные закрыты явно, остальное не тронуто"
        else
          askyn confirm "Применить? (allowlist: reset + открыть только список ниже)" "n"
          [[ "$confirm" == true ]] || continue
          save_firewall_state
          ufw --force reset >/dev/null 2>&1 || true
          ufw default deny incoming >/dev/null 2>&1 || true
          ufw default allow outgoing >/dev/null 2>&1 || true
          # SSH-туннель: если sshd слушает только loopback — наружу не открываем
          if ! ssh_loopback_only; then
            fw_allow "$SSH_PORT" tcp "SSH"
          else
            ufw delete allow "${SSH_PORT}/tcp" >/dev/null 2>&1 || true
          fi
          for k in "${!REQ[@]}"; do
            local pr="${k%%:*}" pt="${k##*:}"
            [[ "$pr:$pt" == "tcp:$SSH_PORT" ]] && continue
            fw_allow "$pt" "$pr" "${REQ[$k]}"
          done
          # свои порты — всегда открыты (после reset их нужно вернуть)
          local kk
          for kk in "${!EXTRA[@]}"; do
            fw_allow "${kk##*:}" "${kk%%:*}" "свой порт"
          done
          # порты панели/подписок наружу закрыты явно (они живут на 127.0.0.1)
          fw_deny_panel_ports
          ufw --force enable >/dev/null 2>&1 || true
          log "Применено (allowlist)"
        fi
        pause
        ;;
      6)
        echo "  Политики:"
        echo "   1) allowlist — «всё закрыть, кроме списка»: reset, наружу только SSH/443/UDP-инбаунды + свои порты (п.9)"
        echo "   2) hide-only — «закрыть только спрятанное»: без reset; deny для панельных портов и 11443;"
        echo "      свои порты (п.9) открываются явно, остальное остаётся как есть"
        local pc=""; ask pc "Политика" "$pol" '^[12]$'
        case "$pc" in
          1) printf 'allowlist\n' > "$BACKUP_DIR/fw-policy"; log "Политика: allowlist" ;;
          2) mkdir -p "$BACKUP_DIR" 2>/dev/null; printf 'hideonly\n' > "$BACKUP_DIR/fw-policy"; log "Политика: hide-only" ;;
        esac
        pause ;;
      2) ufw --force enable 2>&1 | sed 's/^/  /'; pause ;;
      3) ufw disable 2>&1 | sed 's/^/  /'; pause ;;
      4) ufw status numbered 2>&1 | sed 's/^/  /'; pause ;;
      5) ufw status numbered 2>&1 | sed 's/^/  /'
         local n=""; ask n "Номер" "0" '^[0-9]+$'
         [[ "$n" == 0 ]] && continue
         ufw --force delete "$n" 2>&1 | sed 's/^/  /'; pause ;;
      7) save_firewall_state; pause ;;
      8) restore_firewall_state ;;
      9)
        echo "  Свои порты (всегда открыты; allowlist их сохраняет, hide-only — открывает явно):"
        if [[ -s "$BACKUP_DIR/fw-extra" ]]; then
          nl -ba "$BACKUP_DIR/fw-extra" | sed 's/^/    /'
        else
          echo "    (пусто)"
        fi
        echo "   1) Добавить порт"
        echo "   2) Убрать порт"
        echo "   0) Назад"
        local sc9=""; ask sc9 "Выбор" "0" '^[0-9]$'
        case "$sc9" in
          1)
            local ep=""; ask ep "Порт" "" '^[0-9]+$'
            [[ -z "$ep" ]] && continue
            if fw_port_locked "$ep"; then
              warn "  Порт $ep — служебный (скрытые панели/DNS/amplification), наружу открывать нельзя"
              pause; continue
            fi
            local epr=""; ask epr "Протокол tcp/udp" "tcp" '^(tcp|udp)$'
            mkdir -p "$BACKUP_DIR" 2>/dev/null
            if grep -qxE "${epr}/${ep}" "$BACKUP_DIR/fw-extra" 2>/dev/null; then
              echo "  Уже в списке"; pause; continue
            fi
            printf '%s/%s\n' "$epr" "$ep" >> "$BACKUP_DIR/fw-extra"
            fw_allow "$ep" "$epr" "свой порт"
            log "Свой порт $epr/$ep: добавлен в исключения файрвола и открыт сразу"
            ;;
          2)
            [[ -s "$BACKUP_DIR/fw-extra" ]] || { echo "  Список пуст"; pause; continue; }
            local en=""; ask en "Номер строки" "0" '^[0-9]+$'
            [[ -z "$en" || "$en" == 0 ]] && continue
            local dline
            dline=$(sed -n "${en}p" "$BACKUP_DIR/fw-extra")
            [[ -z "$dline" ]] && continue
            ufw delete allow "${dline##*/}/${dline%%/*}" >/dev/null 2>&1 || true
            sed -i "${en}d" "$BACKUP_DIR/fw-extra"
            log "Свой порт убран из исключений: $dline (правило UFW снято)"
            ;;
        esac
        pause ;;
      10) firewall_apply_menu; pause ;;
      11) firewall_apply_menu_tui; pause ;;
      0) return 0 ;;
      *) sleep 1 ;;
    esac
  done
}

firewall_menu() {
  # Основной экран — классическое меню управления UFW.
  # TUI сокетов остаётся отдельным пунктом 10 внутри него.
  firewall_menu_legacy
}

# =====================================================================
# БЫСТРЫЙ ОБЗОР ПОРТОВ (замена медленного TUI):
#   — один вызов ufw status, по одному ss на протокол, один запрос udp-портов
#   — нумерованный список «сокет × правило»; переключение по номеру
#     применяется СРАЗУ (allow/deny, без ufw reset)
# =====================================================================
firewall_apply_menu() {
  if [[ ! -t 0 ]]; then
    log "UFW (неинтерактивно): SSH+443+UDP-инбаунды панели"
    save_firewall_state >/dev/null 2>&1 || true
    ufw --force reset >/dev/null 2>&1 || true
    ufw default deny incoming >/dev/null 2>&1 || true
    ufw default allow outgoing >/dev/null 2>&1 || true
    if ! ssh_loopback_only; then
      fw_allow "${SSH_PORT:-22}" tcp "SSH"
    else
      ufw delete allow "${SSH_PORT:-22}/tcp" >/dev/null 2>&1 || true
    fi
    fw_allow 443 tcp "HTTPS/SNI"
    local up
    for up in $(udp_inbound_ports); do
      fw_port_locked "$up" && continue
      fw_allow "$up" udp "udp-инбаунд"
    done
    fw_deny_panel_ports
    ufw --force enable >/dev/null 2>&1 || true
    return 0
  fi

  local G Y R N
  if command -v tput >/dev/null 2>&1; then
    G=$(tput setaf 2); Y=$(tput setaf 3); R=$(tput setaf 1); N=$(tput sgr0)
  else
    G=''; Y=''; R=''; N=''
  fi

  # UDP-порты инбаундов — ОДИН запрос к БД на весь экран
  local -a UDP_PORTS=()
  local _u
  for _u in $(udp_inbound_ports); do UDP_PORTS+=("$_u"); done

  local -A UFW_ALLOW=() UFW_DENY=() SOCK_OUT=() SOCK_LOOP=() SOCK_PID=() LOOPGRP=()
  local UFW_ACTIVE=0

  # ── Сбор состояния: 1×ufw status + 1×ss tcp + 1×ss udp (парсинг в bash) ──
  fw_load_state() {
    UFW_ALLOW=(); UFW_DENY=(); SOCK_OUT=(); SOCK_LOOP=(); SOCK_PID=(); LOOPGRP=()
    UFW_ACTIVE=0
    ufw_is_active && UFW_ACTIVE=1
    local _ln _pt _act
    if [[ "$UFW_ACTIVE" == 1 ]]; then
      while IFS= read -r _ln; do
        read -r _pt _act _ <<<"$_ln"
        [[ "$_pt" =~ ^[0-9]+/(tcp|udp)$ ]] || continue
        case "$_act" in
          ALLOW) UFW_ALLOW["$_pt"]=1 ;;
          DENY)  UFW_DENY["$_pt"]=1 ;;
        esac
      done < <(ufw status 2>/dev/null | awk '$1 ~ /^[0-9]+\/(tcp|udp)$/ && ($2 == "ALLOW" || $2 == "DENY") { print $1, $2 }')
    fi
    local _line _st _rq _sq _addr _peer _info _port _proc _pid
    while IFS= read -r _line; do
      read -r _st _rq _sq _addr _peer _info <<<"$_line"
      [[ -n "$_addr" ]] || continue
      _port="${_addr##*:}"
      [[ "$_port" =~ ^[0-9]+$ ]] || continue
      _proc="—"; _pid="—"
      if [[ "$_info" =~ \"([^\"]+)\".*pid=([0-9]+) ]]; then
        _proc="${BASH_REMATCH[1]}"; _pid="${BASH_REMATCH[2]}"
      fi
      [[ "$_proc" == xray-linux* ]] && _proc="xray"
      if [[ "$_addr" == 127.* || "$_addr" == \[::1\]:* || "$_addr" == ::1:* ]]; then
        SOCK_LOOP["${_port}/tcp"]="$_proc"; SOCK_PID["${_port}/tcp"]="$_pid"
      else
        SOCK_OUT["${_port}/tcp"]="$_proc"; SOCK_PID["${_port}/tcp"]="$_pid"
      fi
    done < <(ss -tlnpH 2>/dev/null)
    while IFS= read -r _line; do
      read -r _st _rq _sq _addr _peer _info <<<"$_line"
      [[ "$_peer" == "*:*" || "$_peer" == "0.0.0.0:*" || "$_peer" == "[::]:*" ]] || continue
      _port="${_addr##*:}"
      [[ "$_port" =~ ^[0-9]+$ ]] || continue
      _proc="—"; _pid="—"
      if [[ "$_info" =~ \"([^\"]+)\".*pid=([0-9]+) ]]; then
        _proc="${BASH_REMATCH[1]}"; _pid="${BASH_REMATCH[2]}"
      fi
      [[ "$_proc" == xray-linux* ]] && _proc="xray"
      if [[ "$_addr" == 127.* || "$_addr" == \[::1\]:* || "$_addr" == ::1:* ]]; then
        SOCK_LOOP["${_port}/udp"]="$_proc"; SOCK_PID["${_port}/udp"]="$_pid"
      else
        SOCK_OUT["${_port}/udp"]="$_proc"; SOCK_PID["${_port}/udp"]="$_pid"
      fi
    done < <(ss -ulnpH 2>/dev/null)
  }

  # ── Построение строк списка (быстро: без fork на строку) ──
  fw_build_items() {
    # NB: items — переменная вызывающей функции (local items в firewall_apply_menu),
    # здесь её НЕ шадоунить локальной декларацией, иначе список умрёт на выходе.
    LOOPGRP=()
    local seen="" key proto port proc pid state note ex _u2
    for key in "${!SOCK_LOOP[@]}"; do
      LOOPGRP[${SOCK_LOOP[$key]}]+=" ${key%/*}/${key#*/}"
    done
    # 1) сокеты снаружи
    for key in "${!SOCK_OUT[@]}"; do
      proto="${key#*/}"; port="${key%/*}"
      proc="${SOCK_OUT[$key]}"; pid="${SOCK_PID[$key]:-—}"
      note=""
      if [[ "$UFW_ACTIVE" == 1 ]]; then
        if [[ -n "${UFW_ALLOW[$key]:-}" ]]; then
          state=1
        elif [[ -n "${UFW_DENY[$key]:-}" ]]; then
          state=0; note="DENY (правило UFW)"
        else
          state=0; note="UFW блокирует (default deny)"
        fi
      else
        state=1; note="UFW не активен"
      fi
      ex=""
      case "$port" in 22) ex="SSH" ;; 80) ex="ACME" ;; 443) ex="стек (SNI)" ;; esac
      if [[ "$proto" == "udp" ]]; then
        for _u2 in "${UDP_PORTS[@]}"; do
          [[ "$_u2" == "$port" ]] && { ex="${ex:+$ex · }UDP-инбаунд"; break; }
        done
      fi
      [[ -n "$ex" ]] && note="${note:+$note · }$ex"
      items+=("${proto}|${port}|${pid}|${proc}|${state}|${note}")
      seen+=" $key"
    done
    # 2) правила UFW без слушателя
    if [[ "$UFW_ACTIVE" == 1 ]]; then
      for key in "${!UFW_ALLOW[@]}"; do
        [[ -n "${SOCK_OUT[$key]:-}" || " $seen " == *" $key "* ]] && continue
        items+=("${key#*/}|${key%/*}|—|—|1|правило UFW, слушателя нет")
        seen+=" $key"
      done
      for key in "${!UFW_DENY[@]}"; do
        [[ -n "${SOCK_OUT[$key]:-}" || " $seen " == *" $key "* ]] && continue
        items+=("${key#*/}|${key%/*}|—|—|0|DENY (правило UFW), слушателя нет")
        seen+=" $key"
      done
    fi
    # 3) SSH-порт проекта, если не попал в сокеты
    local ssh_port="${SSH_PORT:-22}" has=0 it
    for it in "${items[@]}"; do
      [[ "${it#*|}" == "${ssh_port}|"* ]] && has=1
    done
    [[ "$has" == 0 ]] && items=("tcp|${ssh_port}|—|sshd (не слушает снаружи)|1|SSH" "${items[@]}")
    # 4) 443 — обязательный вход стека
    has=0
    for it in "${items[@]}"; do
      [[ "${it#*|}" == "443|"* ]] && has=1
    done
    [[ "$has" == 0 ]] && items+=("tcp|443|—|nginx/SNI (обязательный)|1|HTTPS/SNI")
    # 5) панельные порты, слушающие loopback
    local _pp _sp _px
    _pp=$(xui_get webPort 2>/dev/null || true)
    _sp=$(xui_get subPort 2>/dev/null || true)
    for _px in "$_pp" "$_sp"; do
      [[ -z "$_px" || "$_px" == "0" || ! "$_px" =~ ^[0-9]+$ ]] && continue
      [[ " $seen " == *" ${_px}/tcp "* ]] && continue
      seen+=" ${_px}/tcp"
      items+=("tcp|${_px}|—|x-ui (панель, loopback)|0|панель x-ui (127.0.0.1)")
    done
    # 11443 наружу не публикуем
    local _row _rp _rport _rest
    local -a _flt=()
    for _row in "${items[@]}"; do
      IFS='|' read -r _rp _rport _rest <<<"$_row"
      [[ "$_rport" == "11443" ]] && continue
      _flt+=("$_row")
    done
    items=("${_flt[@]}")
    # сортировка по порту
    local -a _srt=()
    while IFS= read -r _row; do _srt+=("$_row"); done < <(
      printf '%s\n' "${items[@]}" | awk -F'|' '{printf "%06d %s\n", $2, $0}' | sort -n | cut -d' ' -f2-)
    items=("${_srt[@]}")
  }

  # ── Отрисовка простым списком (без cursor-TUI) ──
  fw_render() {
    clear
    line
    echo -e "${B}   FIREWALL (UFW) — ПОРТЫ: СОКЕТ × ПРАВИЛО${N}"
    line
    local st="inactive"
    [[ "$UFW_ACTIVE" == 1 ]] && st="active"
    echo "  Статус UFW: $st · переключение по номеру применяется сразу (без ufw reset)"
    echo
    printf "   %-3s %-5s %-6s %-22s %s\n" "#" "Прото" "Порт" "Процесс" "Статус · примечание"
    printf "   %s\n" "──────────────────────────────────────────────────────────────"
    local i=0 it proto port pid proc state note mark
    for it in "${items[@]}"; do
      IFS='|' read -r proto port pid proc state note <<<"$it"
      if [[ "$state" == 1 ]]; then mark="${G}● открыт${N}"; else mark="${Y}○ закрыт${N}"; fi
      printf "   %-3s %-5s %-6s %-22s %b%s\n" "$((i+1))" "$proto" "$port" "$proc" "$mark" "${note:+ ← $note}"
      i=$((i+1))
    done
    echo
    echo -e "${B}▸ Спрятано настройками (UFW не при чём — порты на 127.0.0.1):${N}"
    if [[ ${#LOOPGRP[@]} -eq 0 ]]; then
      echo "  —"
    else
      local _pr _ports
      for _pr in x-ui nginx xray csqtt; do
        [[ -n "${LOOPGRP[$_pr]:-}" ]] || continue
        _ports=$(printf '%s\n' ${LOOPGRP[$_pr]} | sort -t/ -k1,1n | tr '\n' ',' | sed 's/,$//; s/,/, /g')
        printf "    %-18s %s\n" "${_pr}:" "$_ports"
      done
      for _pr in "${!LOOPGRP[@]}"; do
        case "$_pr" in x-ui|nginx|xray|csqtt) continue ;; esac
        _ports=$(printf '%s\n' ${LOOPGRP[$_pr]} | sort -t/ -k1,1n | tr '\n' ',' | sed 's/,$//; s/,/, /g')
        printf "    %-18s %s\n" "${_pr}:" "$_ports"
      done
    fi
    echo
    line
    echo "  N) вкл/выкл порт по номеру · a) добавить свой порт · r) обновить · 0) назад"
    line
  }

  # ── Переключение одного порта ──
  fw_toggle() {
    local idx="$1" it proto port pid proc state note _a
    it="${items[$((idx-1))]}"
    IFS='|' read -r proto port pid proc state note <<<"$it"
    if [[ "$state" == 1 ]] && fw_port_locked "$port"; then
      warn "Порт $port закреплён (п.9) — закрывать нельзя"; sleep 1; return
    fi
    # панельный loopback-порт: переключаем привязку + правило одной операцией
    if [[ "${SOCK_LOOP[${port}/${proto}]:-}" == "x-ui" ]]; then
      echo "  ⚠ x-ui перезапустится — туннели (xray/caddy/…) кратко оборвутся"
      if [[ "$state" == 1 ]]; then
        read -rp "  Вернуть панель на 127.0.0.1 и закрыть порт $port? [y/N]: " _a || _a=""
        [[ "${_a,,}" == "y" ]] || return
        xui_set_listen "$port" "127.0.0.1" || { err "не удалось сменить привязку"; sleep 1; return; }
        ufw delete allow "$port/$proto" >/dev/null 2>&1 || true
        ufw deny "$port/$proto" >/dev/null 2>&1 || true
      else
        read -rp "  Открыть панель наружу (0.0.0.0:$port)? [y/N]: " _a || _a=""
        [[ "${_a,,}" == "y" ]] || return
        xui_set_listen "$port" "0.0.0.0" || { err "не удалось сменить привязку"; sleep 1; return; }
        ufw delete deny "$port/$proto" >/dev/null 2>&1 || true
        fw_allow "$port" "$proto" "x-ui"
      fi
    elif [[ "$port" == "${SSH_PORT:-22}" && "$state" == 1 ]]; then
      echo -e "${R}⚠ Закрытие SSH (${SSH_PORT:-22}) отрежет доступ снаружи.${N}"
      read -rp "  Для подтверждения введи YES: " _a || _a=""
      [[ "$_a" == "YES" ]] || { log "Отменено"; sleep 1; return; }
      ufw delete allow "$port/$proto" >/dev/null 2>&1 || true
      ufw deny "$port/$proto" >/dev/null 2>&1 || true
    elif [[ "$port" == "443" || "$port" == "80" ]] && [[ "$state" == 1 ]]; then
      read -rp "  ⚠ Порт $port — служебный для стека. Закрыть? [y/N]: " _a || _a=""
      [[ "${_a,,}" == "y" ]] || return
      ufw delete allow "$port/$proto" >/dev/null 2>&1 || true
      ufw deny "$port/$proto" >/dev/null 2>&1 || true
    elif [[ "$state" == 1 ]]; then
      ufw delete allow "$port/$proto" >/dev/null 2>&1 || true
      ufw deny "$port/$proto" >/dev/null 2>&1 || true
      log "Порт $port/$proto закрыт (deny)"
    else
      ufw delete deny "$port/$proto" >/dev/null 2>&1 || true
      fw_allow "$port" "$proto" "ручное открытие"
      log "Порт $port/$proto открыт (allow)"
    fi
  }

  # ── Добавление «своего» порта (п.9) ──
  fw_add_extra() {
    local nport="" nproto="tcp" nnum=""
    read -rp "Новый порт (8090 или 22000/udp): " nport || nport=""
    nport="${nport// /}"
    case "$nport" in
      */tcp) nnum="${nport%/*}" ;;
      */udp) nnum="${nport%/*}"; nproto="udp" ;;
      *)     nnum="$nport" ;;
    esac
    if [[ "$nnum" =~ ^[0-9]+$ ]] && (( nnum >= 1 && nnum <= 65535 )); then
      mkdir -p "$BACKUP_DIR" 2>/dev/null || true
      grep -qxF "${nproto}/${nnum}" "$BACKUP_DIR/fw-extra" 2>/dev/null || \
        printf '%s/%s\n' "$nproto" "$nnum" >> "$BACKUP_DIR/fw-extra"
      fw_allow "$nnum" "$nproto" "свой порт"
      log "Свой порт $nnum/$nproto добавлен и открыт"
      sleep 1
    else
      warn "Некорректный порт: $nport"; sleep 1
    fi
  }

  local items=()
  fw_load_state
  fw_build_items
  local c=""
  while :; do
    fw_render
    read -rp "  Выбор: " c || c="0"
    case "$c" in
      0|q|Q) return 0 ;;
      r|R)   fw_load_state; fw_build_items ;;
      a|A)   fw_add_extra ;;
      '') ;;
      *[!0-9]*) warn "Нет такого пункта"; sleep 1 ;;
      *)
        if (( c >= 1 && c <= ${#items[@]} )); then
          fw_toggle "$c"
          fw_load_state; fw_build_items
        else
          warn "Нет такого пункта"; sleep 1
        fi
        ;;
    esac
  done
}

# Старый полноэкранный TUI оставлен как запасной вариант (медленный:
# дублирующие проходы ss, ufw status дважды, sqlite на каждую строку).
firewall_apply_menu_tui() {
  if [[ ! -t 0 ]]; then
    log "UFW (неинтерактивно): SSH+443+UDP-инбаунды панели"
    save_firewall_state >/dev/null 2>&1 || true
    ufw --force reset >/dev/null 2>&1 || true
    ufw default deny incoming >/dev/null 2>&1 || true
    ufw default allow outgoing >/dev/null 2>&1 || true
    if ! ssh_loopback_only; then
      fw_allow "${SSH_PORT:-22}" tcp "SSH"
    else
      ufw delete allow "${SSH_PORT:-22}/tcp" >/dev/null 2>&1 || true
    fi
    fw_allow 443 tcp "HTTPS/SNI"
    local up
    for up in $(udp_inbound_ports); do
      fw_port_locked "$up" && continue
      fw_allow "$up" udp "udp-инбаунд"
    done
    fw_deny_panel_ports
    ufw --force enable >/dev/null 2>&1 || true
    return 0
  fi

  local G Y B R N
  if command -v tput >/dev/null 2>&1; then
    G=$(tput setaf 2); Y=$(tput setaf 3); B=$(tput setaf 6); R=$(tput setaf 1); N=$(tput sgr0)
  else
    G=''; Y=''; B=''; R=''; N=''
  fi

  local old_stty=""
  old_stty=$(stty -g </dev/tty 2>/dev/null || true)
  tui_restore() {
    [[ -n "$old_stty" ]] && stty "$old_stty" </dev/tty 2>/dev/null || true
    tput cnorm 2>/dev/null || true
    tput sgr0  2>/dev/null || true
  }
  trap 'tui_restore; return 1' INT TERM

  local W_PTR=1 W_PROTO=6 W_PORT=7 W_PID=8 W_PROC=22 W_STATE=10

  # ── Кэш видимой длины. Ключ = "__v_" + строка. Префикс гарантирует
  # непустой ключ даже для пустой строки → "${CACHE[$k]:-}" работает всегда.
  local -A VIS_CACHE=()
  vis_len() {
    local s="$1"
    local k="__v_${s}"
    if [[ -n "${VIS_CACHE[$k]:-}" ]]; then
      printf '%s' "${VIS_CACHE[$k]}"
      return
    fi
    local no_ansi len
    no_ansi=$(printf '%s' "$s" | sed $'s/\033\\[[0-9;]*[a-zA-Z]//g')
    len=$(printf '%s' "$no_ansi" | LC_ALL=C.UTF-8 wc -m | tr -d ' ')
    VIS_CACHE["$k"]="$len"
    printf '%s' "$len"
  }
  pad_vis() {
    local s="$1" w="$2" len add
    len=$(vis_len "$s")
    add=$(( w - len ))
    (( add < 0 )) && add=0
    printf '%s' "$s"
    (( add > 0 )) && printf '%*s' "$add" ""
  }

  # ── Активен ли UFW ──
  local ufw_active=0
  ufw_is_active && ufw_active=1

  # ── Правила UFW: ALLOW и DENY. Только IPv4-строки (без "(v6)"),
  #    чтобы не дублировать.
  declare -A UFW_ALLOW=() UFW_DENY=()
  local _ln
  if [[ "$ufw_active" == "1" ]]; then
    while IFS= read -r _ln; do
      [[ -z "$_ln" ]] && continue
      # ожидаем: "22/tcp ALLOW IN Anywhere" или "22222/tcp DENY IN Anywhere"
      local _pt _act
      _pt=$(awk '{print $1}' <<<"$_ln")
      _act=$(awk '{print $2}' <<<"$_ln")
      [[ ! "$_pt" =~ ^[0-9]+/(tcp|udp)$ ]] && continue
      case "$_act" in
        ALLOW) UFW_ALLOW["$_pt"]=1 ;;
        DENY)  UFW_DENY["$_pt"]=1 ;;
      esac
    done < <(ufw status 2>/dev/null | awk '
      $1 ~ /^[0-9]+\/(tcp|udp)$/ && ($2 == "ALLOW" || $2 == "DENY") { print $1, $2 }')
  fi

  # ── Сокеты: сбор одним проходом на протокол (без awk/sed/grep на каждую строку) ──
  declare -A SOCK_OUT=() SOCK_LOOP=() SOCK_PID_OUT=() SOCK_PID_LOOP=()
  local port proc pid addr peer info
  collect_sockets() {
    local proto="$1" line c1 c2 c3 c4 c5 c6
    while IFS= read -r line; do
      [[ -z "$line" ]] && continue
      read -r c1 c2 c3 c4 c5 c6 <<<"$line"
      addr="$c4"; peer="$c5"; info="$c6"
      [[ -n "$addr" ]] || continue
      [[ "$proto" == "udp" && "$peer" != "*:*" && "$peer" != "0.0.0.0:*" && "$peer" != "[::]:*" ]] && continue
      port="${addr##*:}"
      [[ "$port" =~ ^[0-9]+$ ]] || continue
      proc="—"; pid="—"
      if [[ "$info" =~ \"([^\"]+)\".*pid=([0-9]+) ]]; then
        proc="${BASH_REMATCH[1]}"; pid="${BASH_REMATCH[2]}"
      fi
      [[ "$proc" == xray-linux* ]] && proc="xray"
      local key="${port}/${proto}"
      case "$addr" in
        127.*|\[::1\]:*|::1:*) SOCK_LOOP["$key"]="$proc"; SOCK_PID_LOOP["$key"]="$pid" ;;
        *) SOCK_OUT["$key"]="$proc"; SOCK_PID_OUT["$key"]="$pid" ;;
      esac
    done
  }
  collect_sockets tcp < <(ss -tlnpH 2>/dev/null)
  collect_sockets udp < <(ss -ulnpH 2>/dev/null)

  while IFS= read -r _ln; do
    [[ -z "$_ln" ]] && continue
    addr=$(awk '{print $4}' <<<"$_ln")
    case "$addr" in 127.*|\[::1\]:*|::1:*) continue ;; esac
    port=$(awk '{split($4,a,":"); print a[length(a)]}' <<<"$_ln")
    [[ -z "$port" || ! "$port" =~ ^[0-9]+$ ]] && continue
    proc=$(sed -n 's/.*users:(("\([^"]*\)".*/\1/p' <<<"$_ln" | head -1)
    [[ -z "$proc" ]] && proc="—"
    pid=$(grep -oE 'pid=[0-9]+' <<<"$_ln" | head -1 | cut -d= -f2)
    [[ -z "$pid" ]] && pid="—"
    case "$proc" in xray-linux*) proc="xray" ;; esac
    SOCK_OUT["${port}/tcp"]="$proc"
    SOCK_PID_OUT["${port}/tcp"]="$pid"
  done < <(ss -tlnpH 2>/dev/null)

  while IFS= read -r _ln; do
    [[ -z "$_ln" ]] && continue
    addr=$(awk '{print $4}' <<<"$_ln")
    case "$addr" in 127.*|\[::1\]:*|::1:*) ;; *) continue ;; esac
    port=$(awk '{split($4,a,":"); print a[length(a)]}' <<<"$_ln")
    [[ -z "$port" || ! "$port" =~ ^[0-9]+$ ]] && continue
    proc=$(sed -n 's/.*users:(("\([^"]*\)".*/\1/p' <<<"$_ln" | head -1)
    [[ -z "$proc" ]] && proc="—"
    case "$proc" in xray-linux*) proc="xray" ;; esac
    pid=$(grep -oE 'pid=[0-9]+' <<<"$_ln" | head -1 | cut -d= -f2)
    [[ -z "$pid" ]] && pid="—"
    SOCK_LOOP["${port}/tcp"]="$proc"
    SOCK_PID_LOOP["${port}/tcp"]="$pid"
  done < <(ss -tlnpH 2>/dev/null)

  while IFS= read -r _ln; do
    [[ -z "$_ln" ]] && continue
    [[ "$(awk '{print $5}' <<<"$_ln")" == "*:*" ]] || continue
    addr=$(awk '{print $4}' <<<"$_ln")
    case "$addr" in 127.*|\[::1\]:*|::1:*) continue ;; esac
    port=$(awk '{split($4,a,":"); print a[length(a)]}' <<<"$_ln")
    [[ -z "$port" || ! "$port" =~ ^[0-9]+$ ]] && continue
    proc=$(sed -n 's/.*users:(("\([^"]*\)".*/\1/p' <<<"$_ln" | head -1)
    [[ -z "$proc" ]] && proc="—"
    case "$proc" in xray-linux*) proc="xray" ;; esac
    pid=$(grep -oE 'pid=[0-9]+' <<<"$_ln" | head -1 | cut -d= -f2)
    [[ -z "$pid" ]] && pid="—"
    SOCK_OUT["${port}/udp"]="$proc"
    SOCK_PID_OUT["${port}/udp"]="$pid"
  done < <(ss -ulnpH 2>/dev/null)

  while IFS= read -r _ln; do
    [[ -z "$_ln" ]] && continue
    [[ "$(awk '{print $5}' <<<"$_ln")" == "*:*" ]] || continue
    addr=$(awk '{print $4}' <<<"$_ln")
    case "$addr" in 127.*|\[::1\]:*|::1:*) ;; *) continue ;; esac
    port=$(awk '{split($4,a,":"); print a[length(a)]}' <<<"$_ln")
    [[ -z "$port" || ! "$port" =~ ^[0-9]+$ ]] && continue
    proc=$(sed -n 's/.*users:(("\([^"]*\)".*/\1/p' <<<"$_ln" | head -1)
    [[ -z "$proc" ]] && proc="—"
    case "$proc" in xray-linux*) proc="xray" ;; esac
    pid=$(grep -oE 'pid=[0-9]+' <<<"$_ln" | head -1 | cut -d= -f2)
    [[ -z "$pid" ]] && pid="—"
    SOCK_LOOP["${port}/udp"]="$proc"
    SOCK_PID_LOOP["${port}/udp"]="$pid"
  done < <(ss -ulnpH 2>/dev/null)

  # UDP-инбаунды панели
  local _up
  for _up in $(udp_inbound_ports); do
    fw_port_locked "$_up" && continue
    SOCK_OUT["${_up}/udp"]="${SOCK_OUT[${_up}/udp]:-xray}"
  done

  # ── items ──
  local -a items=()
  local seen=""
  add_item() {
    local proto="$1" port="$2" pid="$3" proc="$4" state="$5" note="$6"
    [[ -z "$port" ]] && return 0
    local key="${port}/${proto}"
    [[ " $seen " == *" $key "* ]] && return 0
    seen+=" $key"
    items+=("${proto}|${port}|${pid:-—}|${proc:-—}|${state}|${note}")
  }

  # Функция: пометка для порта (SSH/ACME/стек/UDP)
  port_extra() {
    local proto="$1" port="$2"
    local ex=""
    case "$port" in
      22)  ex="SSH" ;;
      80)  ex="ACME" ;;
      443) ex="стек (SNI)" ;;
    esac
    local isup=0 u2
    for u2 in $(udp_inbound_ports); do [[ "$u2" == "$port" && "$proto" == "udp" ]] && isup=1; done
    [[ "$isup" == "1" ]] && ex="${ex:+$ex · }UDP-инбаунд"
    printf '%s' "$ex"
  }

  # 1. Сокеты снаружи
  local key
  for key in "${!SOCK_OUT[@]}"; do
    local proto="${key#*/}" port="${key%/*}" proc="${SOCK_OUT[$key]}" pid="${SOCK_PID_OUT[$key]:-—}"
    local state note=""
    if [[ "$ufw_active" == "1" ]]; then
      if [[ -n "${UFW_ALLOW[$key]:-}" ]]; then
        state="1"
      elif [[ -n "${UFW_DENY[$key]:-}" ]]; then
        state="0"; note="← DENY (правило UFW)"
      else
        state="0"; note="← UFW блокирует (default deny)"
      fi
    else
      state="1"
    fi
    local ex; ex=$(port_extra "$proto" "$port")
    if [[ -n "$ex" ]]; then
      [[ -z "$note" ]] && note="← $ex" || note="← $ex · ${note#← }"
    fi
    add_item "$proto" "$port" "$pid" "$proc" "$state" "$note"
  done

  # 2. Правила UFW без сокета
  if [[ "$ufw_active" == "1" ]]; then
    local k
    for k in "${!UFW_ALLOW[@]}"; do
      [[ -n "${SOCK_OUT[$k]:-}" ]] && continue
      local proto="${k#*/}" port="${k%/*}"
      add_item "$proto" "$port" "—" "—" "1" "← правило UFW, слушателя нет"
    done
    for k in "${!UFW_DENY[@]}"; do
      [[ -n "${SOCK_OUT[$k]:-}" ]] && continue
      local proto="${k#*/}" port="${k%/*}"
      add_item "$proto" "$port" "—" "—" "0" "← DENY (правило UFW), слушателя нет"
    done
  fi

  # 3. SSH-порт проекта (не захардкоженный 22)
  local has_ssh="" ssh_port="${SSH_PORT:-22}"
  local it
  for it in "${items[@]}"; do
    [[ "${it#*|}" == "${ssh_port}|"* ]] && has_ssh=1
  done
  if [[ -z "$has_ssh" ]]; then
    local stssh="0" ntsh=""
    if [[ "$ufw_active" == "0" ]]; then
      stssh="1"
    elif [[ -n "${UFW_ALLOW[${ssh_port}/tcp]:-}" ]]; then
      stssh="1"
    elif [[ -n "${UFW_DENY[${ssh_port}/tcp]:-}" ]]; then
      stssh="0"; ntsh="← DENY (правило UFW)"
    else
      stssh="0"; ntsh="← UFW блокирует (default deny)"
    fi
    [[ -z "$ntsh" ]] && ntsh="← SSH"
    items=("tcp|${ssh_port}|—|sshd (не слушает снаружи)|${stssh}|${ntsh}" "${items[@]}")
  fi
  # 4. 443 — обязательный внешний вход проекта, даже если nginx сейчас
  # перезапускается и временно не имеет сокета.
  local has_https=""
  for it in "${items[@]}"; do
    [[ "${it#*|}" == "443|"* ]] && has_https=1
  done
  if [[ -z "$has_https" ]]; then
    local sthttps=1 nthttps="← HTTPS/SNI (обязательный)"
    if [[ "$ufw_active" == "1" && -z "${UFW_ALLOW[443/tcp]:-}" ]]; then
      sthttps=0
    fi
    items+=("tcp|443|—|nginx/SNI (обязательный)|${sthttps}|${nthttps}")
  fi
  # 5. Панельные порты (web/sub): x-ui обычно слушает их на 127.0.0.1,
  # внешнего сокета нет, и без этой строки TUI вообще не давал их
  # открыть/спрятать (особенно при выключенном UFW или без deny-правила).
  local _pp="" _sp="" _px
  _pp=$(xui_get webPort 2>/dev/null || true)
  _sp=$(xui_get subPort 2>/dev/null || true)
  for _px in "$_pp" "$_sp"; do
    [[ -z "$_px" || "$_px" == "0" || ! "$_px" =~ ^[0-9]+$ ]] && continue
    fw_port_locked "$_px" && continue
    [[ " $seen " == *" ${_px}/tcp "* ]] && continue
    seen+=" ${_px}/tcp"
    local _pst=0 _pnote="← панель x-ui (слушает 127.0.0.1)"
    if [[ "$ufw_active" == "1" ]]; then
      if [[ -n "${UFW_ALLOW[${_px}/tcp]:-}" ]]; then
        _pst=1; _pnote="← панель x-ui (0.0.0.0)"
      elif [[ -n "${UFW_DENY[${_px}/tcp]:-}" ]]; then
        _pst=0; _pnote="← панель x-ui (127.0.0.1) · DENY (правило UFW)"
      else
        _pst=0; _pnote="← панель x-ui (127.0.0.1) · UFW блокирует"
      fi
    fi
    items+=("tcp|${_px}|—|x-ui (панель, loopback)|${_pst}|${_pnote}")
  done
  # 11443 никогда не должен появляться как открываемый пользовательский порт.
  local _filtered=() _row _rp _rport
  for _row in "${items[@]}"; do
    IFS='|' read -r _rp _rport _ _ _ <<<"$_row"
    [[ "$_rport" == "11443" ]] && continue
    _filtered+=("$_row")
  done
  items=("${_filtered[@]}")

  # Сортировка
  local -a sorted=()
  while IFS= read -r it; do sorted+=("$it"); done < <(
    printf '%s\n' "${items[@]}" | awk -F'|' '{printf "%06d %s\n", $2, $0}' | sort -n | cut -d' ' -f2-
  )
  items=("${sorted[@]}")
  local N_items=${#items[@]}

  # ── Нижний блок ──
  local -A LOOP_BY_PROC=()
  local _lk
  for _lk in "${!SOCK_LOOP[@]}"; do
    local _lp="${_lk%/*}" _lpr="${_lk#*/}" _lproc="${SOCK_LOOP[$_lk]}"
    LOOP_BY_PROC["$_lproc"]+=" ${_lp}/${_lpr}"
  done

  # ── Отрисовка ──
  draw_tui() {
    tput cup 0 0 2>/dev/null || printf '\033[H'
    tput ed 2>/dev/null || printf '\033[J'

    local ufw_state_txt="inactive"
    [[ "$ufw_active" == "1" ]] && ufw_state_txt="active"
    echo "${B}FIREWALL (UFW) — управление портами${N}"
    echo "${B}════════════════════════════════════════════════════════════════════════════${N}"
    echo "  Статус UFW: $ufw_state_txt"
    echo

    local hdr=""
    hdr+="  "
    hdr+=$(pad_vis ""          "$W_PTR");   hdr+=" "
    hdr+=$(pad_vis "Прото"     "$W_PROTO"); hdr+=" "
    hdr+=$(pad_vis "Порт"      "$W_PORT");  hdr+=" "
    hdr+=$(pad_vis "PID"       "$W_PID");   hdr+=" "
     hdr+=$(pad_vis "Процесс"   "$W_PROC");  hdr+=" "
    hdr+=$(pad_vis "Статус"    "$W_STATE"); hdr+=" "
    hdr+="Примечание"
    printf '%s\n' "$hdr"
    printf "  %s\n" "────────────────────────────────────────────────────────────────────────────"

    local i=0 proto port pid proc state note ptr state_txt state_color
    for it in "${items[@]}"; do
      IFS='|' read -r proto port pid proc state note <<<"$it"
      ptr=" "; [[ $i -eq $cur ]] && ptr="▶"
      if [[ "$state" == "1" ]]; then
        state_txt="● открыт"; state_color="$G"
      else
        state_txt="○ закрыт"; state_color="$Y"
      fi
      local line=""
      line+="  "
      line+=$(pad_vis "$ptr"   "$W_PTR");   line+=" "
      line+=$(pad_vis "$proto" "$W_PROTO"); line+=" "
      line+=$(pad_vis "$port"  "$W_PORT");  line+=" "
      line+=$(pad_vis "$pid"   "$W_PID");   line+=" "
       line+=$(pad_vis "$proc"  "$W_PROC");  line+=" "
      local st_padded
      st_padded=$(pad_vis "$state_txt" "$W_STATE")
      line+="${state_color}${st_padded}${N}"
      line+=" "
      line+="$note"
      printf '%s\n' "$line"
      i=$((i+1))
    done

    echo
    echo "${B}▸ Спрятано настройками (UFW не при чём — эти порты на 127.0.0.1):${N}"
    if [[ ${#LOOP_BY_PROC[@]} -eq 0 ]]; then
      echo "  —"
    else
      local _order=("x-ui" "nginx" "xray" "csqtt")
      local _done=""
      local _o _pr
      for _o in "${_order[@]}"; do
        for _pr in "${!LOOP_BY_PROC[@]}"; do
          [[ "$_pr" == "$_o" ]] || continue
          local _ports="${LOOP_BY_PROC[$_pr]}"
          _ports=$(printf '%s' "$_ports" | tr ' ' '\n' | grep -v '^$' | sort -t/ -k1,1n | tr '\n' ',' | sed 's/,$//; s/,/, /g')
          printf "    %-18s %s\n" "${_pr}:" "$_ports"
          _done+=" $_pr"
        done
      done
      for _pr in "${!LOOP_BY_PROC[@]}"; do
        [[ " $_done " == *" $_pr "* ]] && continue
        local _ports="${LOOP_BY_PROC[$_pr]}"
        _ports=$(printf '%s' "$_ports" | tr ' ' '\n' | grep -v '^$' | sort -t/ -k1,1n | tr '\n' ',' | sed 's/,$//; s/,/, /g')
        printf "    %-18s %s\n" "${_pr}:" "$_ports"
      done
    fi

    echo
    printf "${B}%s${N}\n" "────────────────────────────────────────────────────────────────────────────"
    echo "  ${Y}↑/↓${N} выбор · ${Y}Пробел${N} вкл/выкл · ${Y}d${N} закрыть · ${Y}a${N} добавить порт"
    echo "  ${Y}Enter${N} применить · ${Y}q${N} отмена"
  }

  # Быстрая перерисовка одной строки: навигация и обычное вкл/выкл
  # больше не очищают весь экран и не пересобирают таблицу.
  draw_item_row() {
    local ri="$1" rit rproto rport rpid rproc rstate rnote rptr rtxt rcolor rline
    rit="${items[$ri]}"
    IFS='|' read -r rproto rport rpid rproc rstate rnote <<<"$rit"
    rptr=" "; [[ "$ri" -eq "$cur" ]] && rptr="▶"
    if [[ "$rstate" == "1" ]]; then rtxt="● открыт"; rcolor="$G"; else rtxt="○ закрыт"; rcolor="$Y"; fi
    rline="  "
    rline+=$(pad_vis "$rptr" "$W_PTR"); rline+=" "
    rline+=$(pad_vis "$rproto" "$W_PROTO"); rline+=" "
    rline+=$(pad_vis "$rport" "$W_PORT"); rline+=" "
    rline+=$(pad_vis "$rpid" "$W_PID"); rline+=" "
    rline+=$(pad_vis "$rproc" "$W_PROC"); rline+=" "
    rline+="${rcolor}$(pad_vis "$rtxt" "$W_STATE")${N} "
    rline+="$rnote"
    tput cup "$((6 + ri))" 0 2>/dev/null || printf '\033[%d;1H' "$((7 + ri))"
    printf '\033[K%s' "$rline"
  }

  local cur=0
  draw_tui

  while :; do
    local k rest need_full=0
    IFS= read -rsn1 k </dev/tty || k="q"
    case "$k" in
      $'\x1b')
        IFS= read -rsn2 -t 0.05 rest </dev/tty || rest=""
        local old_cur=$cur
        case "$rest" in
          '[A') ((cur--)); ((cur < 0)) && cur=$((N_items-1)) ;;
          '[B') ((cur++)); ((cur >= N_items)) && cur=0 ;;
        esac
        [[ "$old_cur" != "$cur" ]] && { draw_item_row "$old_cur"; draw_item_row "$cur"; tput cup "$((6 + cur))" 0 2>/dev/null || true; }
        ;;
      ' ')
        IFS='|' read -r proto port pid proc state note <<<"${items[$cur]}"
        # Для x-ui переключаем не только правило UFW, но и фактический
        # web/sub listen: это поведение standalone-TUI из message (2).txt.
        if [[ "$proto" == "tcp" && "${SOCK_LOOP[${port}/${proto}]:-}" == "x-ui" ]]; then
          tui_restore
          echo
          local _xans=""
          if [[ "$state" == "1" ]]; then
            echo "  ⚠ x-ui перезапустится — туннели (xray/caddy/…) кратко оборвутся"
            read -rp "Вернуть x-ui на 127.0.0.1 и закрыть порт $port? [y/N]: " _xans || _xans=""
            if [[ "${_xans,,}" == "y" ]] && xui_set_listen "$port" "127.0.0.1"; then
              ufw delete allow "$port/tcp" >/dev/null 2>&1 || true
              # Явный deny вместо полагания на default deny: безопасно и при
              # любой политике, и статус TUI на следующем входе будет честным.
              ufw deny "$port/tcp" >/dev/null 2>&1 || true
              state="0"; note="← x-ui спрятан (127.0.0.1)"
            fi
          else
            echo "  ⚠ x-ui перезапустится — туннели (xray/caddy/…) кратко оборвутся"
            read -rp "Вытащить x-ui наружу на 0.0.0.0:$port? [y/N]: " _xans || _xans=""
            if [[ "${_xans,,}" == "y" ]] && xui_set_listen "$port" "0.0.0.0"; then
              # ПОРЯДОК ВАЖЕН: ufw применяет первое совпавшее правило. Для
              # панельного порта deny уже висит в цепочке (fw_deny_panel_ports),
              # поэтому allow, добавленный ПОСЛЕ него, никогда не сработал —
              # TUI показывал «открыт», а порт оставался закрыт. Сначала
              # снимаем deny, только потом добавляем allow.
              ufw delete deny "$port/tcp" >/dev/null 2>&1 || true
              ufw delete deny "$port/udp" >/dev/null 2>&1 || true
              fw_allow "$port" tcp "x-ui"
              state="1"; note="← x-ui открыт наружу (0.0.0.0)"
            fi
          fi
          items[$cur]="${proto}|${port}|${pid}|${proc}|${state}|${note}"
          [[ -n "$old_stty" ]] && stty "$old_stty" </dev/tty 2>/dev/null || true
          tput civis 2>/dev/null || true
        elif [[ "$port" == "${SSH_PORT:-22}" && "$state" == "1" ]]; then
          tui_restore
          echo
          local ans=""
          read -rp "${R}?${N} Закрыть SSH (порт ${SSH_PORT:-22})? Потеряешь доступ снаружи! [y/N]: " ans || ans=""
          case "${ans,,}" in
            y|yes|д|да) state=0 ;;
            *)          state=1 ;;
          esac
          [[ -n "$old_stty" ]] && stty "$old_stty" </dev/tty 2>/dev/null || true
          tput civis 2>/dev/null || true
        else
          [[ "$state" == "1" ]] && state=0 || state=1
        fi
        items[$cur]="${proto}|${port}|${pid}|${proc}|${state}|${note}"
        ;;
      'a')
        need_full=1
        tui_restore
        echo
        local nport=""
        read -rp "Новый порт (8090 или 22000/udp): " nport || nport=""
        nport=$(printf '%s' "$nport" | tr -d ' ')
        if [[ -n "$nport" ]]; then
          local nproto="tcp" nnum="$nport"
          case "$nport" in
            */tcp) nnum="${nport%/*}" ;;
            */udp) nnum="${nport%/*}"; nproto="udp" ;;
          esac
          if [[ "$nnum" =~ ^[0-9]+$ ]] && (( nnum >= 1 && nnum <= 65535 )); then
            local nkey="${nnum}/${nproto}"
            if [[ " $seen " == *" $nkey "* ]]; then
              warn "Порт $nnum/$nproto уже в списке"
              sleep 1
            else
              seen+=" $nkey"
              mkdir -p "$BACKUP_DIR" 2>/dev/null || true
              if ! grep -qxF "${nproto}/${nnum}" "$BACKUP_DIR/fw-extra" 2>/dev/null; then
                printf '%s/%s\n' "$nproto" "$nnum" >> "$BACKUP_DIR/fw-extra"
              fi
              items+=("${nproto}|${nnum}|—|manual|1|← добавлен (сохранён)")
              local -a sorted2=()
              while IFS= read -r it; do sorted2+=("$it"); done < <(
                printf '%s\n' "${items[@]}" | awk -F'|' '{printf "%06d %s\n", $2, $0}' | sort -n | cut -d' ' -f2-
              )
              items=("${sorted2[@]}")
              N_items=${#items[@]}
              cur=$((N_items-1))
            fi
          else
            warn "Некорректный порт: $nport"; sleep 1
          fi
        fi
        [[ -n "$old_stty" ]] && stty "$old_stty" </dev/tty 2>/dev/null || true
        tput civis 2>/dev/null || true
        ;;
      'd')
        need_full=1
        IFS='|' read -r proto port pid proc state note <<<"${items[$cur]}"
        if [[ "$state" == "0" ]]; then
          : # уже закрыт
        elif [[ "$port" == "${SSH_PORT:-22}" ]]; then
          tui_restore
          echo
          echo -e "${R}⚠ Закрытие SSH (порт ${SSH_PORT:-22}) оборвёт твою текущую сессию,${N}"
          echo -e "${R}  если ты подключён по нему снаружи.${N}"
          local ans=""
          read -rp "$(echo -e "? Для подтверждения введи ${Y}YES${N}: ")" ans || ans=""
          case "$ans" in
            YES)
              state=0
              items[$cur]="${proto}|${port}|${pid}|${proc}|${state}|${note}"
              log "SSH (${SSH_PORT:-22}) помечен как закрытый — применится по Enter"
              ;;
            *) log "Отменено" ;;
          esac
          [[ -n "$old_stty" ]] && stty "$old_stty" </dev/tty 2>/dev/null || true
          tput civis 2>/dev/null || true
        elif [[ "$port" == "443" || "$port" == "80" ]]; then
          tui_restore
          echo
          echo -e "${Y}⚠ Порт $port — ${note:-служебный для стека}.${N}"
          local ans=""
          read -rp "$(echo -e "? Закрыть $port? [y/N]: ")" ans || ans=""
          case "${ans,,}" in
            y|yes|д|да)
              state=0
              items[$cur]="${proto}|${port}|${pid}|${proc}|${state}|${note}"
              log "Порт $port помечен как закрытый"
              ;;
            *) log "Отменено" ;;
          esac
          [[ -n "$old_stty" ]] && stty "$old_stty" </dev/tty 2>/dev/null || true
          tput civis 2>/dev/null || true
        else
          state=0
          items[$cur]="${proto}|${port}|${pid}|${proc}|${state}|${note}"
        fi
        ;;
      'q'|$'\x03')
        tui_restore
        echo
        log "Отменено — UFW не тронут"
        return 0
        ;;
      ''|$'\r'|$'\n')
        tui_restore
        echo
        # Защита от само-блокировки: применение конфигурации, в которой SSH
        # помечен закрытым, отрежет текущую сессию. Требуем явного YES,
        # иначе возвращаем SSH в открытые.
        local _ssh_port="${SSH_PORT:-22}" _ssh_closed="" _it5 _i5
        for _it5 in "${items[@]}"; do
          [[ "${_it5%%|*}" == "tcp" && "${_it5#*|}" == "${_ssh_port}|"* ]] || continue
          local _f5=""
          IFS='|' read -r _ _ _ _ _f5 _ <<<"$_it5"
          [[ "$_f5" == "0" ]] && { _ssh_closed=1; break; }
        done
        if [[ -n "$_ssh_closed" ]]; then
          echo -e "${R}⚠ В конфигурации закрыт SSH-порт ($_ssh_port) — применением ты отрежешь текущий доступ!${N}"
          local _yes5=""
          read -rp "$(echo -e "? Для подтверждения введи ${Y}YES${N}: ")" _yes5 || _yes5=""
          if [[ "$_yes5" != "YES" ]]; then
            _i5=0
            for _it5 in "${items[@]}"; do
              if [[ "${_it5%%|*}" == "tcp" && "${_it5#*|}" == "${_ssh_port}|"* ]]; then
                local _p1="" _p2="" _p3="" _p4="" _p6=""
                IFS='|' read -r _p1 _p2 _p3 _p4 _ _p6 <<<"$_it5"
                items[$_i5]="${_p1}|${_p2}|${_p3}|${_p4}|1|${_p6}"
              fi
              _i5=$((_i5+1))
            done
            log "SSH оставлен открытым (для закрытия введи YES при подтверждении)"
            [[ -n "$old_stty" ]] && stty "$old_stty" </dev/tty 2>/dev/null || true
            tput civis 2>/dev/null || true
          fi
        fi
        echo -e "${B}▸ Итог:${N}"
        local open_list close_list
        open_list=""; close_list=""
        for it in "${items[@]}"; do
          IFS='|' read -r proto port pid proc state note <<<"$it"
          if [[ "$state" == "1" ]]; then open_list+=" ${port}/${proto}"; else close_list+=" ${port}/${proto}"; fi
        done
        echo "  Откроются:${open_list:- <пусто>}"
        [[ -n "$close_list" ]] && echo "  Закроются:${close_list}"
        warn "  Внимание: apply делает ufw reset — сторонние правила (docker и т.п.) будут стёрты"
        echo
        local ok=""
        read_safe "? Применить новую конфигурацию UFW? [y/N]: " ok
        case "${ok,,}" in
          y|yes|д|да) ;;
          *) log "Отменено"; return 0 ;;
        esac
        save_firewall_state >/dev/null 2>&1 || true
        ufw --force reset >/dev/null 2>&1 || true
        ufw default deny incoming >/dev/null 2>&1 || true
        ufw default allow outgoing >/dev/null 2>&1 || true
        local opened_tcp="" _op
        for it in "${items[@]}"; do
          IFS='|' read -r proto port pid proc state note <<<"$it"
          [[ "$state" == "1" ]] || continue
          fw_port_locked "$port" && continue
          fw_allow "$port" "$proto" "kept"
          [[ "$proto" == "tcp" ]] && opened_tcp+="$port "
        done
        fw_deny_panel_ports
        # Панельные порты, ЯВНО открытые пользователем в этой сессии:
        # fw_deny_panel_ports ставит deny следом за allow — пара правил
        # путает следующие прогоны и status. Снимаем deny у открытых.
        for _op in $opened_tcp; do
          ufw delete deny "$_op/tcp" >/dev/null 2>&1 || true
        done
        # 11443 — внутренний tproxy/HTTP3, наружу не публикуем даже если
        # он случайно попал в список сокетов.
        ufw delete allow 11443/tcp >/dev/null 2>&1 || true
        ufw delete allow 11443/udp >/dev/null 2>&1 || true
        ufw deny 11443/tcp >/dev/null 2>&1 || true
        # После reset/изменения правил явно перезагружаем конфигурацию.
        ufw --force enable >/dev/null 2>&1 || true
        ufw reload >/dev/null 2>&1 || true
        sleep 1
        log "UFW применён"
        ufw status 2>/dev/null | grep -E "ALLOW|DENY" | sed 's/^/    /'
        return 0
        ;;
      *) ;;
    esac
    draw_tui
  done
}

# =====================================================================
# ЗДОРОВЬЕ: UFW-fallback, recidive, живой лог, шаблоны decoy
# ссылок, смена домена инбаунда
# =====================================================================

# Статус UFW с запасным путём: бинарь может не находиться в PATH — тогда
# смотрим сервис (oneshot ufw.service остаётся active после применения правил).
# пересборка ВСЕХ decoy-блоков: подтянуть robots/honeypot/UA-404/логи с доменом.
# Шаблон берём из маркера (tpl=), если нет — угадываем по md5 index.html.
decoy_rebuild_all() {
  [[ -f "$STACK_CONF" ]] || { err "stack.conf не найден"; pause; return 1; }
  local mline mport mroot mcert mkey mdom mtpl muaf mus4 idx hash tf troot found
  local -A TPL_OF=()
  local -a ROWS=()
  while IFS= read -r mline; do
    [[ "$mline" != "# >>> decoy "* ]] && continue
    mport=$(grep -oE 'port=[0-9]+'   <<<"$mline" | head -1 | cut -d= -f2)
    mroot=$(grep -oE 'root=[^ ]+'    <<<"$mline" | head -1 | cut -d= -f2-)
    mcert=$(grep -oE 'cert=[^ ]+'    <<<"$mline" | head -1 | cut -d= -f2-)
    mkey=$(grep  -oE ' key=[^ ]+'    <<<"$mline" | head -1 | sed 's/^ key=//')
    mdom=$(grep  -oE 'domain=[^ ]+$' <<<"$mline" | head -1 | cut -d= -f2-)
    mtpl=$(grep -oE 'tpl=[^ ]+'      <<<"$mline" | head -1 | cut -d= -f2-)
    muaf=$(grep -oE 'ua404=[0-9]'    <<<"$mline" | head -1 | cut -d= -f2-)
    mus4=$(grep -oE 'status404=[0-9]' <<<"$mline" | head -1 | cut -d= -f2-)
    [[ -z "$mus4" ]] && mus4=0
    [[ -z "$mdom" || -z "$mport" || -z "$mroot" ]] && continue
    if [[ -z "$mtpl" && -f "$mroot/index.html" ]]; then
      hash=$(md5sum "$mroot/index.html" 2>/dev/null | awk '{print $1}')
      found=""
      for tf in "$DECOY_TPL_DIR"/*.html "$DECOY_LOGIN_DIR"/*.html; do
        [[ -f "$tf" ]] || continue
        [[ "$(md5sum "$tf" 2>/dev/null | awk '{print $1}')" == "$hash" ]] && { found=$(basename "$tf" .html); break; }
      done
      mtpl="${found:-corporate}"
    fi
    [[ -z "$mtpl" ]] && mtpl="corporate"
    [[ -z "$muaf" ]] && muaf=1
    ROWS+=("$mport|$mdom|$mcert|$mkey|$mroot|$mtpl|$muaf")
  done < "$STACK_CONF"
  [[ ${#ROWS[@]} -eq 0 ]] && { warn "Decoy-блоки не найдены"; pause; return 0; }
  local r
  for r in "${ROWS[@]}"; do
    IFS='|' read -r mport mdom mcert mkey mroot mtpl muaf <<<"$r"
    mk_decoy "$mport" "$mdom" "$mcert" "$mkey" "$mroot" "$mtpl" "ua404=$muaf status404=$mus4"
    log "  $mdom → «$mtpl» (ua404=$muaf, robots+honeypot+логи)"
  done
  audit "decoy: пересборка всех блоков"
  if nginx -t >/dev/null 2>&1; then
    nginx_reload || true
    log "Все decoy-блоки пересобраны ✓"
  else
    err "nginx -t не прошёл:"; nginx -t 2>&1 | tail -5 | sed 's/^/    /'
  fi
  pause
}

# «проверить как посторонний»: что реально увидит человек и сканер
decoy_outsider_check() {
  local mline mport mdom
  local -a DOM_LIST=()
  local -A PORT_OF=()
  while IFS= read -r mline; do
    [[ "$mline" != "# >>> decoy "* ]] && continue
    mport=$(grep -oE 'port=[0-9]+'   <<<"$mline" | head -1 | cut -d= -f2)
    mdom=$(grep  -oE 'domain=[^ ]+$' <<<"$mline" | head -1 | cut -d= -f2-)
    [[ -n "$mdom" ]] && { DOM_LIST+=("$mdom"); PORT_OF[$mdom]="$mport"; }
  done < "$STACK_CONF"
  [[ ${#DOM_LIST[@]} -eq 0 ]] && { warn "Decoy-доменов нет"; pause; return 0; }
  local i=1 d pick
  for d in "${DOM_LIST[@]}"; do printf "  %d) %s\n" "$i" "$d"; i=$((i+1)); done
  ask pick "Проверить какой домен" "1" '^[0-9]+$'
  (( pick > ${#DOM_LIST[@]} )) && { err "Нет такого"; pause; return 1; }
  mdom="${DOM_LIST[$((pick-1))]}"
  mport="${PORT_OF[$mdom]}"
  local HUA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"
  local cb ch title
  cb=$(curl -sk -A "curl/8.5.0" -o /dev/null -w "%{http_code}" "https://127.0.0.1:$mport/" 2>/dev/null)
  curl -sk -A "$HUA" "https://127.0.0.1:$mport/" -o /tmp/smg_out.html 2>/dev/null
  ch=$(curl -sk -A "$HUA" -o /dev/null -w "%{http_code}" "https://127.0.0.1:$mport/" 2>/dev/null)
  title=$(grep -oE '<title>[^<]*' /tmp/smg_out.html 2>/dev/null | head -1 | sed 's/<title>//')
  echo
  echo "  Домен: $mdom (локальный порт $mport)"
  echo "  ---------------------------------------------"
  echo "  Человек (браузер): HTTP $ch   title: ${title:-—}"
  echo "  Сканер (curl):     HTTP $cb   $( [[ "$cb" == 404 ]] && echo '← бот видит пустоту ✓' )"
  echo
  echo "  Заголовки (как для браузера):"
  curl -skI -A "$HUA" "https://127.0.0.1:$mport/" 2>/dev/null | head -6 | sed 's/^/    /'
  rm -f /tmp/smg_out.html
  pause
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
  echo
  echo -e "${B}▸ Свой сайт (custom):${N} доступен в любом меню выбора шаблона —"
  echo "    выбрать пункт «custom» и указать путь к папке с index.html (статика)."
  echo
  echo "  1) Пересобрать все decoy-блоки (включить robots/honeypot/UA-404/логи)"
  echo "  2) Проверить домен как посторонний (человек vs сканер)"
  echo "  0) Назад"
  local c=""
  read -rp "$(echo -e "${B}Выбор:${N} ")" c || c="0"
  case "$c" in
    1) decoy_rebuild_all ;;
    2) decoy_outsider_check ;;
  esac
  pause
}

# =====================================================================
