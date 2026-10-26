# ПОЛНЫЙ АВТОПОДЪЁМ ПОСЛЕ ЧИСТОЙ УСТАНОВКИ ПАНЕЛИ
# (инбаунды → initial_setup → UFW → итоговая сводка)
# =====================================================================
auto_full_setup() {
  local base="${PANEL_DOMAIN:-$(xui_get webDomain 2>/dev/null || true)}"
  [[ -z "$base" || "$base" == "panel.example.com" ]] && { err "Домен панели неизвестен — автоподъём пропущен"; return 1; }
  detect_env
  line; echo -e "${B}   АВТОПОДЪЁМ СТЕКА (чистая установка)${N}"; line

  # --- 1+2+3) ЕДИНЫЙ путь вопросов: панель → AdGuard → заглушка панели
  ask_panel_creds || return 1
  local u_port="$U_PANEL_PORT" u_subport="$U_SUB_PORT" u_path="$U_PANEL_PATH" u_subpath="$U_SUB_PATH"
  ask_adguard_and_decoy
  local pdecoy="$PDECOY"
  le_email_load || true
  [[ "$EMAIL" == "none" || ! "$EMAIL" =~ ^[^@]+@[^@]+\.[^@]+$ ]] && EMAIL=""
  if [[ -z "$EMAIL" ]]; then
    ask EMAIL "Email для Let's Encrypt" "" '^[^@]+@[^@]+\.[^@]+$' || return 1
    le_email_save "$EMAIL" || return 1
  fi

  # Сначала выбираем тип сертификатов для домена панели и выпускаем его
  # в штатном initial_setup; выбор не должен появляться посреди мастера инбаундов.
  cert_type_ask force

  # --- 4) ИНБАУНДЫ: какие ставить? (Enter — весь доступный набор)
  echo -e "${B}Выберите доступные для этой панели инбаунды:${N}"
  local i=1 entry entry_proto
  local -a CAND=()
  local _auto_flavor="${PANEL_FLAVOR:-$(detect_panel_flavor)}"
  for entry in "${RECOMMENDED_INBOUNDS[@]}"; do
    IFS='|' read -r _ entry_proto _ <<<"$entry"
    if [[ "$_auto_flavor" != "lucx" && "$entry_proto" != "vless" && "$entry_proto" != "hysteria" ]]; then
      continue
    fi
    printf "  %2d) %s\n" "$i" "${entry%%|*}"
    CAND+=("$entry"); i=$((i+1))
  done
  echo
  if [[ "$_auto_flavor" == "lucx" ]]; then
    echo "  Enter — установить ВСЕ доступные LucX-инбаунды"
  else
    echo "  Enter — установить VLESS и Hysteria2"
  fi
  local choices=""
  ask choices "Номера (через пробел)" "" '^[0-9 ]*$'
  local -a SEL=()
  local num
  if [[ -z "$choices" ]]; then
    SEL=("${CAND[@]}")
  else
    for num in $choices; do
      (( num >= 1 && num <= ${#CAND[@]} )) && SEL+=("${CAND[$((num-1))]}") || warn "Пропуск: $num"
    done
  fi
  [[ ${#SEL[@]} -eq 0 ]] && { warn "Ничего не выбрано — инбаунды не создаются"; }
  # VK call hashes запрашиваются в цикле создания отдельно для каждого
  # qwdtt/csqtt, рядом с его портом и остальными параметрами.
  local vk=""

  # Тип сертификатов уже выбран до мастера инбаундов — здесь повторно не спрашиваем.

  # --- 3) SNI-домены для TLS-инбаундов (Enter — префикс по умолчанию)
  local -A PREFIX=( [vless-tcp]="r" [vless-xhttp]="rx" [naive-naive]="n" [anytls-anytls]="at" [trusttunnel-trusttunnel]="tt" [hysteria-hysteria]="h" )
  local -A SELDOM=()
  # --- 4c) Reality-вопросы (режим → цель/домен → порт → заглушка) задаются
  #         в цикле создания — по каждому инбаунду, на его месте в очереди.
  REALITY_EXT=false
  local -A REALITY_MODE=() REALITY_TGT=() REALITY_DECOY_TPL_BYID=()

  # (tg-домен спрашивается в цикле создания — на месте самого tg-инбаунда)

  # (пароль панели и порты/пути спрашиваются в начале — шаг 1)
  # (отдельный цикл доменов убран: домен спрашивается в цикле создания
  #  перед портом — «SNI → порт → следующий инбаунд»)
  # (decoy-шаблон спрашивается ПО КАЖДОМУ инбаунду, если нужен свой SNI:
  #  Reality и VLESS TCP TLS; XHTTP TLS работает без decoy)

  # --- 5) Создание выбранных инбаундов. Порядок вопросов на КАЖДЫЙ инбаунд:
  #        reality: свой/чужой → (цель | SNI-домен) → порт → заглушка (свой SNI)
  #        VLESS TCP TLS: SNI-домен → серт → порт → выбор decoy-заглушки
  #        VLESS XHTTP TLS: SNI-домен → серт → порт, без decoy
  log "Создание инбаундов…"
  local -A A_DOM=()
  local -a used_ports=()
  local new_id=""
  for entry in "${SEL[@]}"; do
    IFS='|' read -r name proto transport security flow net <<<"$entry"
    INBOUND_CREATE_MODE="$security"
    local pfx="${PREFIX[$proto-$transport]:-}"
    local port sn="" dom="${SELDOM[$proto-$transport]:-}"
    # ── CDN-профиль только для явно выбранного пункта VLESS XHTTP (через CDN):
    # создаём сразу без security, nginx терминирует TLS. Ответы — в CDN_PRE_*,
    # их подхватит xhttp_cdn_setup при configure_sni_for_inbound (в initial_setup).
    CDN_PRE_ANSWER=""; CDN_PRE_CDN=""; CDN_PRE_ORIGIN=""; CDN_PRE_PATH=""; CDN_PRE_TPL=""; CDN_PRE_PROVIDER=""
    local _is_cdn=false
    if [[ "$transport" == "xhttp" && "$security" != "reality" ]]; then
       if [[ "$name" == "VLESS XHTTP (через CDN)" ]]; then
         # Фиксированный пункт означает CDN без дополнительного y/n.
         _is_cdn=true
       elif [[ "$name" == "VLESS XHTTP TLS" ]]; then
         # Явный TLS-пункт: CDN не спрашиваем.
         security="tls"
         _is_cdn=false
       elif [[ "$name" == "VLESS XHTTP" && "$proto" == "vless" && "$security" == "none" && -t 0 ]]; then
         local _cdn_ans=""
         echo
         askyn _cdn_ans "Это соединение будет работать через CDN (nginx TLS, инбаунд без security)?" "n"
         [[ "$_cdn_ans" == true ]] && _is_cdn=true
       fi
      if [[ "$_is_cdn" == true ]]; then
        cdn_ask_profile "0" "$proto"   # спросит CDN/ORIGIN-домены, путь, decoy
        CDN_PRE_ANSWER="true"
        CDN_PRE_CDN="$CDN_DOM"; CDN_PRE_ORIGIN="$CDN_ORIGIN"; CDN_PRE_PATH="$CDN_PATH"; CDN_PRE_TPL="$CDN_TPL"; CDN_PRE_PROVIDER="$CDN_PROVIDER"
        security="none"     # TLS терминирует nginx — инбаунд создаём голым
        dom=""; sn=""       # SNI-домен/серт инбаунду не нужны
        rdtpl=""
      fi
    fi
    # ── Reality: режим + цель/домен — прямо здесь, перед портом
    if [[ "$security" == "reality" ]]; then
      local e_key="$proto-$transport" rmode=""
      if [[ -t 0 ]]; then
        echo
        echo "  $name:"
        echo "   1) Чужой реалити «найти цели» — за 443 по SNI цели, серт НЕ нужен"
        echo "   2) Свой SNI-домен — нужен серт + decoy"
        ask rmode "Выбор [1/2]" "1" '^[12]$'
      else
        rmode="1"
      fi
      REALITY_MODE["$e_key"]="$rmode"
      if [[ "$rmode" == "1" ]]; then
        REALITY_EXT=true
        local tgt=""
        reality_target_menu tgt "$name"
        REALITY_TGT["$e_key"]="$tgt"
        REALITY_EXT_TARGET="$tgt"
        printf '%s' "$tgt" > /tmp/.reality-found-target 2>/dev/null || true
        log "  $name: цель → $tgt (dest+serverNames, за 443 по SNI цели)"
      else
        local d=""
        if [[ -t 0 ]]; then
          ask d "Домен для $name (нужен серт + decoy)" "${pfx:-r}.$base" '^[a-zA-Z0-9.-]+$'
        else
          d="${pfx:-r}.$base"
        fi
        SELDOM["$e_key"]="$d"
        dom="$d"
      fi
    elif [[ -z "$dom" && -n "$pfx" && "${_is_cdn:-}" != true ]] && { [[ "$net" == "tcp" ]] || [[ "$proto" == "hysteria" ]]; }; then
      # ── TLS: SNI-домен (серт проверим сразу после порта)
      if [[ -t 0 ]]; then
        local d=""
        ask d "Домен для $name (нужен серт)" "$pfx.$base" '^[a-zA-Z0-9.-]+$'
        SELDOM["$proto-$transport"]="$d"
        dom="$d"
      else
        dom="$pfx.$base"
        SELDOM["$proto-$transport"]="$dom"
      fi
    fi
    # tg web proxy: домен — здесь же, перед его портом (не «после всех инбаундов»)
    if [[ "$proto" == "tproxy" && -t 0 ]]; then
      local tpd="${PANEL_DOMAIN:-$base}" base_dom="${PANEL_DOMAIN:-$base}" tdom_ask=""
      base_dom="${base_dom#*.}"
      [[ "$base_dom" != *.* ]] && base_dom="$tpd"
      ask tdom_ask "Домен tg web proxy (Enter — tg.$base_dom)" "tg.$base_dom" '^[a-zA-Z0-9.-]+$'
      T_PROXY_DOMAIN="$tdom_ask"
    fi
    case "$proto" in
      tproxy) port=11443 ;;
      qwdtt)  port=56000 ;;
      csqtt)  port=46000 ;;
      *)      port=$(make_port) ;;
    esac
    # порт: 443/80 нельзя (nginx), занятые другими инбаундами — нельзя
    if [[ -t 0 ]]; then
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
    fi
    used_ports+=("$port")
    # Для собственного Reality и VLESS TCP TLS спрашиваем конкретный
    # decoy-шаблон. XHTTP TLS работает напрямую через SNI passthrough и
    # намеренно не использует decoy.
    local rdtpl=""
    local _tpl_dom="${sni_domain:-${dom:-}}"
    local _needs_decoy_choice=false
    if [[ "$security" == "reality" && -n "$dom" ]]; then
      _needs_decoy_choice=true
    elif [[ "$proto" == "vless" && "$transport" != "xhttp" && "$security" == "tls" && -n "$_tpl_dom" ]]; then
      _needs_decoy_choice=true
    fi
    if [[ "$_needs_decoy_choice" == true ]]; then
      rdtpl="$(decoy_tpl_current "$_tpl_dom")"
      if [[ -t 0 ]]; then
        decoy_template_choose_impl rdtpl "Decoy-заглушка для ${_tpl_dom:-$name} (страница на этом домене)" "$rdtpl"
      fi
    fi
    if [[ -n "$_tpl_dom" && -n "$rdtpl" ]]; then
      decoy_tpl_store_set "$_tpl_dom" "$rdtpl" >/dev/null 2>&1 || true
    fi
    # sn: TCP-класс TLS-инбаунды И hysteria (UDP, но TLS обязателен)
    if [[ -n "$dom" ]] && { [[ "$net" == "tcp" ]] || [[ "$proto" == "hysteria" ]]; }; then
      sn="$dom"
    fi
    local vkn=""
    [[ "$proto" == "qwdtt" || "$proto" == "csqtt" ]] && vkn="$vk"
    # CDN-XHTTP не получает отдельный SNI/decoy: его домены и decoy
    # запрашиваются только в CDN-профиле ниже.
    # Сертификат нужен TLS-инбаундам и собственному SNI Reality:
    # для Reality-режима 2 nginx/decoy обслуживает домен, поэтому сертификат
    # должен быть выпущен до генерации маршрута, как и для обычного TLS.
    # Тип (wildcard/персональный) учтён внутри cert_issue: при живом wildcard
    # это no-op (переиспользует его), иначе выпускается персональный сертификат.
    local _own_reality=false
    [[ "$security" == "reality" && "${REALITY_MODE[$proto-$transport]:-}" == "2" ]] && _own_reality=true
    if [[ -n "$dom" ]] && { [[ "$net" == "tcp" && "$security" == "tls" ]] || [[ "$proto" == "hysteria" ]] || [[ "$_own_reality" == true ]]; }; then
      log "  Сертификат для $dom: проверка/выпуск перед настройкой $name"
      cert_issue "$dom" || warn "  ИТОГ: серт $dom НЕ выпущен — $name (${proto}) не поднимется; докати позже: Сертификаты → обновить (причина выше)"
    fi
    local remark
    remark=$(inbound_remark_next "$proto" "$transport" "$security")
    # цель «чужого реалити» уже в REALITY_EXT_TARGET (шаг выше)
    new_id=$(create_inbound_db "$proto" "$transport" "$security" "$flow" "$port" "$remark" "$net" "$sn" "$vkn") || true
    if [[ -n "$new_id" ]]; then
      if [[ "${_is_cdn:-false}" == true ]]; then
        CDN_FORCE_IDS="${CDN_FORCE_IDS:-} $new_id"
        # Профиль CDN нужно применить сразу к созданной строке БД:
        # initial_setup запускается позже и не должен быть единственным местом,
        # где пытаемся заполнить stream_settings/hosts.
        xhttp_cdn_setup "$new_id" "$proto" "$port" || warn "  CDN-профиль для #$new_id не применён — повтори настройку инбаунда"
      fi
      log "  → #$new_id $remark :$port${sn:+ (SNI $sn)}"
      [[ -n "$dom" ]] && A_DOM["$new_id"]="$dom"
      # своя заглушка на этот инбаунд (для initial_setup)
      [[ -n "$rdtpl" ]] && REALITY_DECOY_TPL_BYID["$new_id"]="$rdtpl"
    else
      warn "$name не создан"
    fi
  done
  systemctl restart x-ui 2>/dev/null || true
  sleep 5

  # --- 6) initial_setup с готовыми ответами (порядок вопросов стабилен)
  local ansf="/root/ans-auto-$(date +%H%M%S).txt"
  {
    le_email_load || true
    if [[ -z "$EMAIL" ]]; then
      err "Email Let's Encrypt не задан — автоподъём остановлен. Укажи email в анкете/переменной EMAIL."
      return 1
    fi
    echo "$EMAIL"                              # EMAIL
                                                # PANEL_DOMAIN уже задан
    # AdGuard/заглушка/порты: в не-TTY initial_setup вопросов НЕ задаёт —
    # всё берётся из глобальных (заданы вопросами авто-подъёма выше), строк не пишем
    local id idproto idport dom stream_s
    while IFS='|' read -r id idproto idport stream_s; do
      [[ -z "$id" ]] && continue
      is_udp_proto "$idproto" && continue       # UDP — без вопросов в initial_setup
      [[ "$idproto" == "tproxy" || "$idproto" == "naive" || "$idproto" == "anytls" || "$idproto" == "trusttunnel" || "$idproto" == "trust-tunnel" ]] && continue # sidecar/TG уже настроены своим SNI-механизмом
      # уже привязан к SNI — initial_setup вопросов по нему не задаёт, строк не пишем
      grep -Eq "^[[:space:]]*[^[:space:]]+[[:space:]]+inb_${id}_backend" "$SNI_CONF" 2>/dev/null && continue
      # CDN-профиль назначен в мастере: xhttp_cdn_setup ответит сам (CDN_PRE_*),
      # initial_setup вопросов по нему НЕ задаёт — строк в анкету не пишем
      if [[ "${CDN_PRE_ANSWER:-}" == "true" && -n "${CDN_PRE_ORIGIN:-}" ]]; then
        continue
      fi
      dom="${A_DOM[$id]:-}"
      if [[ -z "$dom" ]]; then
        echo "n"                                # домен не задан → не скрывать
      else
        echo "y"; echo "$dom"
        if grep -qi '"security": *"reality"' <<<"$stream_s" || grep -qi '"network": *"xhttp"' <<<"$stream_s"; then
          echo "${REALITY_DECOY_TPL_BYID[$id]:-corporate}"   # своя заглушка/страница
        fi
      fi
    done < <(sqlite3 "$XUI_DB" "SELECT id, protocol, port, COALESCE(stream_settings,'') FROM inbounds WHERE enable=1 AND port>0 ORDER BY id;" 2>/dev/null)
    INBOUND_CREATE_MODE=""
    echo "n"                                    # файрвол: настроим сами ниже
    # Завершающий Enter не даёт EOF превратить последний вопрос в цикл.
    echo ""
  } > "$ansf"
  log "Первичная настройка (автоответы: $ansf)…"
  initial_setup < "$ansf" > >(tee /tmp/stack-initial-setup.log /tmp/auto-setup.log) 2>&1 || warn "initial_setup вернул ошибку — смотри /tmp/stack-initial-setup.log"
  grep -E "\[\+\]|\[!\]|\[x\]" /tmp/stack-initial-setup.log 2>/dev/null | tail -12

  # --- 2с) Логин/пароль AdGuard, заданные при установке: применяем ВСЕГДА
  #         (даже если у AdGuard уже были пользователи — выбор пользователя важнее)
  if [[ "$ADG_PRESENT" == true && -n "${U_ADG_PASS:-}" ]]; then
    U_ADG_USER="${U_ADG_USER:-admin}"
    if adg_set_admin "$U_ADG_USER" "$U_ADG_PASS"; then
      log "Логин/пароль AdGuard установлены ($U_ADG_USER) — заданы при установке"
      printf 'AdGuard Home — %s\n  Логин:  %s\n  Пароль: %s\n' "$(date "+%Y-%m-%d %H:%M:%S")" "$U_ADG_USER" "$U_ADG_PASS" > /root/adguard-credentials.txt
      chmod 600 /root/adguard-credentials.txt
    else
      warn "Не удалось установить креды AdGuard — причина выше"
    fi
  fi

  # --- 3) UFW: SSH + 443 + слушающие порты туннелей; панельные порты в DENY
  firewall_apply

  # --- 3c) Автопочинка правок панели (каждые 2 мин; трогает x-ui только при находке)
  # --- 4) ИТОГ
  local pp="" panel_pass adg_pass adg_user
  pp=$(xui_get webBasePath 2>/dev/null || true)
  pp="/${pp#/}"
  panel_pass=$(grep -i "пароль" /root/panel-credentials.txt 2>/dev/null | awk '{print $NF}' | head -1)
  local panel_user=""
  panel_user=$(grep -i "логин" /root/panel-credentials.txt 2>/dev/null | awk '{print $NF}' | head -1)
  adg_pass=$(grep -i "пароль" /root/adguard-credentials.txt 2>/dev/null | awk '{print $NF}' | head -1)
  adg_user=$(grep -i "логин"  /root/adguard-credentials.txt 2>/dev/null | awk '{print $NF}' | head -1)
  line
  echo -e "${G}   ИТОГ УСТАНОВКИ${N}"
  line
  echo "  ПАНЕЛЬ:  https://$base$pp"
  echo "           логин: ${panel_user:-${U_PANEL_USER:-admin}}   пароль: ${panel_pass:-см. /root/panel-credentials.txt}"
  if [[ "$ADG_PRESENT" == true ]]; then
    echo "  ADGUARD: https://$base/   (DoH: https://$base/dns-query)"
    echo "           логин: ${adg_user:-admin}   пароль: ${adg_pass:-см. /root/adguard-credentials.txt}"
  fi
  echo "  ИНБАУНДЫ:"
  sqlite3 "$XUI_DB" "SELECT id, protocol, port, remark FROM inbounds WHERE enable=1 ORDER BY id;" 2>/dev/null \
    | awk -F"|" '{printf "    #%s  %-12s :%-6s %s\n", $1, $2, $3, $4}'
  echo "  UFW:     активен (SSH+443+туннели; :80 закрыт; панельные порты DENY)"
  line
  echo "  Установка завершена. Нажмите Enter для возврата в главное меню."
  echo "  Логины и пароли продублированы:"
  echo "    панель  → /root/panel-credentials.txt"
  [[ "$ADG_PRESENT" == true ]] && echo "    adguard → /root/adguard-credentials.txt"
  line
  stack_mark_configured || warn "Не удалось сохранить маркер настройки; автоматические исправления останутся отключены."
  pause
  return 0
}

# =====================================================================
# ТОЧКА ВХОДА (только при прямом запуске; при source функции доступны для теста)
# =====================================================================
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  # страховка: если «аренда» снятия защиты БД осталась висеть — снять на выходе
  if [[ "${1:-}" == "--check" || "${1:-}" == "--self-test" ]]; then
    detect_env
    stack_full_audit
    exit $?
  fi
  # СТРОГИЙ БЕЗОПАСНЫЙ СТАРТ:
  # пока пользователь явно не завершил первичную настройку, запуск скрипта
  # ничего не пишет и не перезапускает. Даже бэкап, hook, nginx, x-ui и heal
  # здесь запрещены — существующий стек принадлежит пользователю.
  # check_os/ensure_deps могут менять пакеты и конфигурацию, поэтому до
  # явной настройки выполняем только определение окружения.
  detect_env
  if stack_is_configured; then
    ensure_deps || { err "Невозможно продолжить без обязательных зависимостей"; exit 1; }
    backfill_country_remarks
    if nginx_stream_module_enable && ensure_stream_include; then
      ss -tlnH 'sport = :443' 2>/dev/null | grep -q . || nginx_reload >/dev/null 2>&1 || true
    fi
    [[ -f /var/run/reboot-required ]] && warn "Система ждёт ПЕРЕЗАГРУЗКУ (обновлено ядро) — откройте раздел 6 → диагностика."
    mkdir -p "$BACKUP_DIR" 2>/dev/null || true
    touch "$BACKUP_DIR/.stack-ever-ran" 2>/dev/null || true
    auto_backup_stack
  else
    warn "Безопасный первый запуск: существующий сервер не изменяется."
    warn "Откройте меню и явно запустите первичную настройку, когда будете готовы."
  fi
  [[ -f "$WILDCARD_STATE" ]] && WILDCARD_DOMAIN=$(head -n 1 "$WILDCARD_STATE" 2>/dev/null | tr -d '[:space:]' || true)
  # wildcard виден в меню сертификатов и диагностике — на старте не шумим

  # ПОРЯДОК ВАЖЕН: сначала ПАНЕЛЬ + её сертификат, потом AdGuard
  # (AdGuard берёт сертификат панели/wildcard для своего https).
  auto_full=false   # НЕ local: точка входа — вне функции
  if [[ -z "$XUI_DB" || ! -f "$XUI_DB" ]]; then
    warn "x-ui.db не найден — панель (LucX UI / 3x-ui) не установлена."
    echo "  Установка доступна через п.7 — Панель и AdGuard → Управление LucX/3x-ui."
    echo "  Если уже стоит оригинальный 3x-ui — убедись, что x-ui.db в /etc/x-ui/."
    install_now=""
    askyn install_now "Установить панель LucX UI сейчас?" "n"
    if [[ "$install_now" == true ]]; then
      install_lucx_panel || warn "Установка не удалась — можно повторить через п.7."
      [[ -n "$XUI_DB" && -f "$XUI_DB" ]] && auto_full=true
    else
      warn "Панель не установлена — меню откроется, установка доступна через п.7."
    fi
  fi

  # чистая установка → авто: инбаунды + настройка + UFW + итоговая сводка
  if [[ "$auto_full" == true ]]; then
    auto_full_setup || warn "Автоподъём прошёл не полностью — доделай в меню (п.1 и п.10)."
  fi

  main_menu
fi











