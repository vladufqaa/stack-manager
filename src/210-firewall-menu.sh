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
    # локальной декларацией её НЕ затенять, иначе список умрёт на выходе.
    items=()
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
    echo "  N) вкл/выкл: номер СТРОКИ списка или номер ПОРТА · a) свой порт · r) обновить · 0) назад"
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
        # Ввод: номер строки списка (1..N) ИЛИ номер порта (напр. 56000).
        local _idx=0 _row _hproto _hp _rest2 _match=-1 _count=0
        for _row in "${items[@]}"; do
          _idx=$((_idx+1))
          IFS='|' read -r _hproto _hp _rest2 <<<"$_row"
          if [[ "$_hp" == "$c" ]]; then _match=$_idx; _count=$((_count+1)); fi
        done
        if (( _count == 1 )); then
          fw_toggle "$_match"            # по порту (однозначно)
        elif (( _count > 1 )); then
          warn "Порт $c есть и в tcp, и в udp — введите номер строки (1..${#items[@]})"; sleep 1
        elif (( c >= 1 && c <= ${#items[@]} )); then
          fw_toggle "$c"                  # по номеру строки
        else
          warn "Нет такого пункта (номер строки 1..${#items[@]} или порт)"; sleep 1
        fi
        fw_load_state; fw_build_items
        ;;
    esac
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
