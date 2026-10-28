# ПЕРВИЧНАЯ НАСТРОЙКА
# =====================================================================
initial_setup() {
  # Сохраняем полный вывод п.1, чтобы ошибка не исчезала при возврате в меню.
  local _setup_log="/tmp/stack-initial-setup.log"
  : > "$_setup_log" 2>/dev/null || true
  exec 3>&1 4>&2
  # Логирование выполняется вызывающим меню через tee; здесь сохраняем маркер.
  line; echo -e "${B}   ПЕРВИЧНАЯ НАСТРОЙКА SNI-РОУТЕРА${N}"; line
  # Откат/демонтаж мог выполниться в этом же процессе меню и удалить nginx
  # уже после стартовой проверки зависимостей. Перед п.1 проверяем повторно,
  # иначе сборка SNI продолжается без nginx и выглядит как «п.1 ничего не сделал».
  ensure_deps
  if ! command -v nginx >/dev/null 2>&1 || [[ ! -f /etc/nginx/nginx.conf ]]; then
    err "nginx не установлен или /etc/nginx/nginx.conf отсутствует — п.1 остановлен"
    err "Проверь apt-get install nginx и запусти п.1 повторно"
    pause
    return 1
  fi
  # Предохранитель: стек уже собран? Повторный прогон может перезаписать
  # работающие настройки — по умолчанию отказываемся.
  if [[ -f "$STACK_CONF" ]] && { [[ -f /etc/nginx/streams-available/sni-router.conf ]] || [[ -n "$XUI_DB" && -f "$XUI_DB" ]]; }; then
    # файлы могли пересоздаться при полу-сборке (например после отката карта
    # пустая) — fuse обязан это увидеть и не пугать ложным «уже выполнено»
    local _map_n=0 _fuse_dflt="n"
    _map_n=$(grep -cE '^[[:space:]]+[^[:space:]]+[[:space:]]+[a-z][a-z0-9_]*_backend;' /etc/nginx/streams-available/sni-router.conf 2>/dev/null || true)
    _map_n=${_map_n:-0}
    if (( _map_n == 0 )); then
      warn "НО: SNI-карта пуста (маршрутов нет) — инбаунды не привязаны к 443, стек полу-собранный."
      _fuse_dflt="y"
    fi
    warn "Похоже, первичная настройка уже выполнена:"
    echo "    ✓ $STACK_CONF"
    echo "    ✓ SNI-роутер (:443, streams-available/sni-router.conf)"
    [[ -n "$XUI_DB" && -f "$XUI_DB" ]] && echo "    ✓ панель установлена (x-ui.db)"
    echo "  Точечные изменения — через п.2/п.4 (инбаунды, decoy), п.11 (файрвол), п.21 (гигиена)."
    local rerun=""
    # В автоматическом вызове ответы уже подготовлены вызывающим мастером.
    # Нельзя добавлять сюда вопрос: он сдвигает поток ответов (email
    # становится ответом y/n, а затем Reality получает EOF).
    if [[ ! -t 0 ]]; then
      rerun=true
      log "Автоматический режим: повторная первичная настройка разрешена"
    else
      askyn rerun "Всё равно запустить первичную настройку заново?" "$_fuse_dflt"
    fi
    [[ "$rerun" == true ]] || { log "Отменено — конфигурация не тронута."; return 0; }
    warn "Повторная настройка: ответы на вопросы нужно будет дать заново."
  fi
  # ПЕРЕУСТАНОВКА (п.17 → сюда): таймер самолечения лезет в x-ui каждые 2 мин
  # и рушит схему «стоп → правка БД → старт». Гасим до начала, вернём в конце.
  # === ФАЗА А: анкета и план — НИКАКИХ изменений до подтверждения ===
  local PLAN_INSTALL=true PLAN_CREATE=true PLAN_FW=true
  local PLAN_EMAIL_DONE=0 PLAN_CREDS_DONE=0 PLAN_ADG_DONE=0
  if [[ -z "$XUI_DB" || ! -f "$XUI_DB" ]]; then
    if [[ -z "$PANEL_DOMAIN" || "$PANEL_DOMAIN" == "panel.example.com" ]]; then
      local pd0=""
      ask pd0 "Домен панели (A-запись → этот сервер)" "${PANEL_DOMAIN:-panel.example.com}" '^[a-zA-Z0-9.-]+$'
      PANEL_DOMAIN="$pd0"
    fi
    askyn PLAN_INSTALL "Ставить панель LucX UI сейчас?" "y"
    if [[ "$PLAN_INSTALL" != true ]]; then
      err "Без панели стек не собирается — отмена."
      return 1
    fi
  fi
  le_email_load || true
  [[ "$EMAIL" == "none" || ! "$EMAIL" =~ ^[^@]+@[^@]+\.[^@]+$ ]] && EMAIL=""
  if [[ -n "$EMAIL" ]]; then
    local _keep_le_email=false
    askyn _keep_le_email "Использовать сохранённый email Let's Encrypt: $EMAIL? (n — указать другой)" "y"
    if [[ "$_keep_le_email" != true ]]; then
      ask EMAIL "Новый email для Let's Encrypt" "" '^[^@]+@[^@]+\.[^@]+$'
      le_email_save "$EMAIL"
    fi
  else
    ask EMAIL "Email для Let's Encrypt" "" '^[^@]+@[^@]+\.[^@]+$'
    le_email_save "$EMAIL"
  fi
  PLAN_EMAIL_DONE=1
  # Тип сертификата выбирается явно в анкете п.1, до создания инбаундов.
  # Без force: auto_full_setup уже спросил его перед вызовом п.1.
  cert_type_ask
  if [[ -t 0 ]]; then
    ask_panel_creds || return 1
    PLAN_CREDS_DONE=1
  fi
  ask_adguard_and_decoy               # AdGuard да/нет → пароль → где → заглушка
  PLAN_ADG_DONE=1
  askyn PLAN_CREATE "В конце создать инбаунды (мастер создания)?" "y"
  askyn PLAN_FW "В конце настроить файрвол (только нужные порты)?" "y"
  echo
  line
  echo -e "${B}   ПЛАН НАСТРОЙКИ${N}"; line
  local _pan_state="уже установлена"
  [[ -z "$XUI_DB" || ! -f "$XUI_DB" ]] && _pan_state="будет установлена (LucX UI)"
  echo "  • панель: $PANEL_DOMAIN — $_pan_state"
  echo "  • email LE: ${EMAIL:-<не задан>}"
  echo "  • AdGuard: ${ADG_PRESENT:-false} · размещение: ${ADG_PLACEMENT:--} · decoy панели: ${PDECOY:--}"
  echo "  • инбаунды в конце: $([[ "$PLAN_CREATE" == true ]] && echo да || echo нет)"
  echo "  • файрвол в конце: $([[ "$PLAN_FW" == true ]] && echo да || echo нет)"
  line
  local go_apply=""
  askyn go_apply "План верный — применять?" "y"
  [[ "$go_apply" == true ]] || { warn "Отменено — ничего не изменено"; return 0; }
  # === ФАЗА Б: применение (вопросы выше пропускаются по PLAN_*-флагам) ===
  # Шаблоны должны быть готовы ДО создания первых decoy в этой же первичной
  # установке. Раньше они инициализировались только поздними пунктами меню,
  # поэтому п.1 мог выбрать шаблон, но mk_decoy не находил его; после п.2
  # шаблоны уже существовали и всё внезапно начинало работать.
  decoy_templates_init || true
  decoy_login_templates_init || true
  systemctl stop stack-heal.timer 2>/dev/null || true
  systemctl disable stack-heal.timer 2>/dev/null || true
  # Панели нет? НЕ валимся — ставим прямо здесь (первоначальная установка
  # должна работать и после удаления панели через п.17).
  if [[ -z "$XUI_DB" || ! -f "$XUI_DB" ]]; then
    warn "Панель LucX UI не установлена (x-ui.db не найден)."
    if [[ -z "$PANEL_DOMAIN" || "$PANEL_DOMAIN" == "panel.example.com" ]]; then
      local pd_ask=""
      ask pd_ask "Домен панели (A-запись → этот сервер)" "${PANEL_DOMAIN:-panel.example.com}" '^[a-zA-Z0-9.-]+$'
      PANEL_DOMAIN="$pd_ask"
    fi
    install_now=false
    [[ "$PLAN_INSTALL" == true ]] && install_now=true
    if [[ "$install_now" != true ]]; then
      err "Без панели работа невозможна."
      return 1
    fi
    install_lucx_panel || { err "Не удалось установить панель LucX UI."; return 1; }
  fi

  local inb_count=0
  inb_count=$(sqlite3 "$XUI_DB" "SELECT COUNT(*) FROM inbounds WHERE enable=1;" 2>/dev/null || echo 0)
  if [[ "$inb_count" -eq 0 ]]; then
    warn "Нет активных инбаундов — создадим их в КОНЦЕ п.1, когда SNI-стек уже собран (иначе нет ни SNI_CONF, ни сертов, ни домена)."
  fi

  local panel_port panel_path sub_port sub_path
  local PANEL_PORT PANEL_PATH SUB_PORT SUB_PATH
  panel_port=$(xui_get webPort); panel_port="${panel_port:-2053}"
  panel_path=$(xui_get webBasePath); panel_path="/${panel_path#/}"; panel_path="${panel_path%/}/"
  sub_port=$(xui_get subPort); sub_port="${sub_port:-2096}"
  sub_path=$(xui_get subPath); sub_path="/${sub_path#/}"; sub_path="${sub_path%/}/"

  if [[ "${PLAN_EMAIL_DONE:-0}" == 1 ]]; then
    log "Email для Let's Encrypt: $EMAIL (из анкеты)"
  else
  le_email_load || true
  if [[ -n "$EMAIL" ]]; then
    log "Email для Let's Encrypt: $EMAIL (сохранён)"
    if [[ -t 0 ]]; then
      local _keep_email=""
      askyn _keep_email "Оставить этот email? (n — указать новый)" "y"
      if [[ "$_keep_email" != true ]]; then
        ask EMAIL "Новый Email для Let's Encrypt" "$EMAIL" '^[^@]+@[^@]+\.[^@]+$'
        le_email_save "$EMAIL"
      fi
    fi
  else
    ask EMAIL "Email для Let's Encrypt" "" '^[^@]+@[^@]+\.[^@]+$'
    le_email_save "$EMAIL"
  fi
  fi
  # Если панель уже установлена, сначала берём её фактический домен из БД.
  # webDomain приоритетнее subDomain; вопрос показываем только если оба пусты.
  if [[ -z "$PANEL_DOMAIN" || "$PANEL_DOMAIN" == "panel.example.com" ]]; then
    local _existing_panel_domain=""
    _existing_panel_domain=$(xui_get webDomain 2>/dev/null || true)
    [[ -z "$_existing_panel_domain" || "$_existing_panel_domain" == "null" ]] && \
      _existing_panel_domain=$(xui_get subDomain 2>/dev/null || true)
    if [[ "$_existing_panel_domain" =~ ^[a-zA-Z0-9.-]+$ && "$_existing_panel_domain" != "panel.example.com" ]]; then
      PANEL_DOMAIN="$_existing_panel_domain"
      log "Домен панели взят из уже установленной панели: $PANEL_DOMAIN"
    else
      ask PANEL_DOMAIN "Домен панели" "panel.example.com" '^[a-zA-Z0-9.-]+$'
    fi
  else
    log "Домен панели: $PANEL_DOMAIN (задан ранее)"
  fi
  sni_used_load
  SNI_USED["$PANEL_DOMAIN"]="panel_backend"   # домен панели тоже занят — инбаунды не могут его использовать

  # ЕДИНЫЙ ПУТЬ (тот же, что в авто-подъёме):
  # пароль+порты — только в TTY; в ans-режиме всё уже в глобальных (U_*)
  if [[ "${PLAN_CREDS_DONE:-0}" != 1 ]]; then
    if [[ -t 0 ]]; then
      ask_panel_creds || return 1
    fi
  fi
  if [[ "${PLAN_ADG_DONE:-0}" != 1 ]]; then
    ask_adguard_and_decoy               # AdGuard да/нет → пароль → где → заглушка
  fi
  local panel_decoy="$PDECOY"
  if [[ "$ADG_PRESENT" == true && "$ADG_PLACEMENT" == "panel" ]]; then
    panel_decoy="adguard"
    log "AdGuard будет настроен за панелью: TLS+серт панели, порт, nginx-локация"
    # сторонний AdGuard мог слушать :80/:443 — nginx не сможет забиндиться
    local p80_owner=""
    p80_owner=$(ss -tlnpH "sport = :80" 2>/dev/null | grep -oE '\("[^"]+"' | head -1 | tr -d '("')
    if [[ -n "$p80_owner" && "$p80_owner" != "nginx" ]]; then
      warn ":80 занят процессом '$p80_owner' — nginx не сможет слушать 80 (нужен для ACME webroot)."
      warn "Освободи порт или переведи тот сервис (AdGuard) на другой порт перед п.1."
    fi
  fi
  if [[ "$ADG_PLACEMENT" == "sni" ]]; then
    local abase="${PANEL_DOMAIN#*.}"
    [[ "$abase" != *.* ]] && abase="$PANEL_DOMAIN"
    ADG_MODE_SNI_DOM="adguard.${abase:-example.com}"
    panel_decoy="stub"
    log "AdGuard: отдельный домен $ADG_MODE_SNI_DOM (настрою сразу после SNI-роутера)"
  fi
  log "Decoy панели: $panel_decoy"

  if [[ -n "$U_PANEL_PORT$U_SUB_PORT$U_PANEL_PATH$U_SUB_PATH" ]]; then
    PANEL_PORT="$U_PANEL_PORT"; PANEL_PATH="$U_PANEL_PATH"
    SUB_PORT="$U_SUB_PORT";     SUB_PATH="$U_SUB_PATH"
    log "Порты/пути: панель $PANEL_PORT $PANEL_PATH · подписки $SUB_PORT $SUB_PATH"
  else
    PANEL_PORT=$(make_port); PANEL_PATH="/$(gen_random_string 12)/"
    SUB_PORT=$(make_port);   SUB_PATH="/$(gen_random_string 10)/"
    log "Автогенерация: панель $PANEL_PORT $PANEL_PATH · подписки $SUB_PORT $SUB_PATH"
  fi

  if [[ "$PANEL_PORT" == "$SUB_PORT" ]]; then
    err "Порт панели и порт подписок совпадают ($PANEL_PORT) — укажите разные."
    return 1
  fi

  declare -A INB_PROTO INB_PORT INB_STREAM
  local -a INB_IDS=()
  local id proto port stream
  while IFS='|' read -r id proto port stream; do
    [[ -z "$id" ]] && continue
    INB_IDS+=("$id")
    INB_PROTO[$id]="$proto"; INB_PORT[$id]="$port"; INB_STREAM[$id]="$stream"
  done < <(sqlite3 "$XUI_DB" "SELECT id, protocol, port, COALESCE(stream_settings,'') FROM inbounds WHERE enable=1 AND port>0;" 2>/dev/null || true)

  declare -A DOMAIN HIDE TLS_PORT DECOY_TPL REALITY_EXT_TARGET_BYID
  for id in "${INB_IDS[@]}"; do
    proto="${INB_PROTO[$id]}"; port="${INB_PORT[$id]}"
    if is_udp_proto "$proto"; then
      warn "#$id $proto (UDP/$port) — пропускаем"
      HIDE[$id]=false; continue
    fi
    if [[ "$proto" == "tproxy" ]]; then
      # tg web proxy прячется СВОИМ механизмом (hosts: address=панель, sni=tg-домен;
      # маршрут в SNI_CONF ведёт setup_tproxy_web с бэкендом tg_backend) —
      # вопросы «Скрыть/SNI-домен» к нему не относятся
      log "#$id tproxy ($port) — прячется своим механизмом (tg web proxy за 443), повторно не спрашиваю"
      HIDE[$id]=false; continue
    fi

    # CDN-профили обслуживаются только для VLESS+XHTTP без безопасности.
    if [[ "$proto" == "vless" ]] && grep -Eqi '"network"[[:space:]]*:[[:space:]]*"xhttp"' <<<"${INB_STREAM[$id]}"; then
      if [[ -n "$(cdn_profile_get "$id" 2>/dev/null)" ]]; then
        log "#$id ($proto) уже в CDN-режиме ($(cdn_profile_field "$id" 3)) — сверяю CDN-настройку"
      fi
      if inbound_is_xhttp_cdn_candidate "${INB_STREAM[$id]}"; then
        if xhttp_cdn_setup "$id" "$proto" "$port"; then
          HIDE[$id]=true
          continue
        fi
      fi
    fi

    # уже привязан к SNI (создан в п.2/п.16 или ранее) — НЕ спрашиваем второй раз
    local existing_dom=""
    existing_dom=$(grep -E "^\s+\S+\s+inb_${id}_backend" "$SNI_CONF" 2>/dev/null | awk '{print $1}' | head -1 || true)
    if [[ -n "$existing_dom" ]]; then
      log "#$id ($proto/$port) уже в SNI: $existing_dom — повторно не спрашиваю"
      HIDE[$id]=true
      DOMAIN[$id]="$existing_dom"
      local meta=""
      meta=$(stack_decoy_meta "$existing_dom") || true
      # Порт decoy — канонический (4444 + id), см. decoy_port_for_id. Если блок
      # уже стоял на другом порту, он будет пересоздан на каноническом: только
      # так совпадают decoy-блок, reality-dest и ожидания самолечения.
      TLS_PORT[$id]=$(decoy_port_for_id "$id")
      if [[ -n "$meta" && "${meta%% *}" != "${TLS_PORT[$id]}" ]]; then
        warn "  #$id: decoy $existing_dom переносится на канонический порт ${TLS_PORT[$id]} (был ${meta%% *})"
      fi
      local is_reality=false
      grep -qi reality <<<"${INB_STREAM[$id]}" && is_reality=true
      if [[ "$is_reality" == true ]]; then
        # Шаблон домена: по умолчанию — тот, что стоит сейчас (из decoy-блока
        # или сохранённого выбора), поэтому Enter ничего не меняет, но домен
        # можно перевести на свой/другой шаблон независимо от остальных.
        local _cur="" _dt=""
        _cur=$(decoy_tpl_current "$existing_dom")
        if [[ -t 0 ]]; then
          decoy_template_choose_impl _dt "Decoy для $existing_dom (страница этого домена)" "$_cur"
          _dt="${_dt:-$_cur}"
        else
          _dt="$_cur"
        fi
        DECOY_TPL[$id]="$_dt"
        decoy_tpl_store_set "$existing_dom" "$_dt" >/dev/null 2>&1 || true
      else
        DECOY_TPL[$id]=""
      fi
      continue
    fi

    echo; echo -e "${Y}── #$id $proto на $port ──${N}"
    local h_hide=""
    askyn h_hide "Скрыть за 443?" "y"
    HIDE[$id]="$h_hide"
    [[ "${HIDE[$id]}" == true ]] || continue

    local def="svc-$id.example.com"
    local is_reality=false
    grep -qi '"security"[[:space:]]*:[[:space:]]*"reality"' <<<"${INB_STREAM[$id]}" && is_reality=true
    case "$proto" in
      anytls) def="at.example.com";;
      trusttunnel|trust-tunnel) def="tt.example.com";;
      naive|naiveproxy) def="n.example.com";;
      mtproto) def="tg.example.com";;
      vless) def="r.example.com";;
    esac
    local d_new=""
    if [[ "$is_reality" == true ]]; then
      echo "  Reality #$id:"
      echo "   1) Найти внешнюю цель (без своего сертификата/decoy)"
      echo "   2) Указать свой SNI-домен (сертификат + decoy)"
      local rmode_new=""
      ask rmode_new "Режим Reality [1/2]" "2" '^[12]$'
      if [[ "$rmode_new" == "1" ]]; then
        local tgt_new=""
        reality_target_menu tgt_new "#$id"
        # В этом цикле transport не заполняется: ключуем режим по ID,
        # иначе Bash воспринимает vless- как арифметическое выражение.
        REALITY_MODE["$id"]="1"
        REALITY_EXT_TARGET_BYID["$id"]="$tgt_new"
        # Для генерации map нужен сам внешний SNI-домен. Decoy не создаётся,
        # но маршрут по этому имени должен попасть в SNI-карту.
        DOMAIN[$id]="$tgt_new"
        HIDE[$id]=true
        DECOY_TPL[$id]=""
        continue
      fi
      ask_sni_domain d_new "$id" "$def" "SNI-домен для Reality #$id (домен будет использоваться клиентом)"
    else
      ask_sni_domain d_new "$id" "$def"
    fi
    DOMAIN[$id]="$d_new"

    # Для Reality явно выбираем страницу, которая будет показана при
    # открытии SNI в браузере; это отдельная decoy-заглушка, не протокол.
    if [[ "$is_reality" == true ]]; then
      local dtpl="" _dom_new="${DOMAIN[$id]}"
      decoy_template_choose_impl dtpl "Decoy-заглушка для $_dom_new (страница на этом домене)" "$(decoy_tpl_current "$_dom_new")"
      DECOY_TPL[$id]="${dtpl:-$(decoy_tpl_for "$_dom_new")}"
      decoy_tpl_store_set "$_dom_new" "${DECOY_TPL[$id]}" >/dev/null 2>&1 || true
      TLS_PORT[$id]=$(decoy_port_for_id "$id")   # канонический порт (см. decoy_port_for_id)
    else
      DECOY_TPL[$id]=""
      TLS_PORT[$id]=""
    fi
  done


  local nginx_was_running=false xui_was_running=false adg_was_running=false
  systemctl is-active --quiet nginx 2>/dev/null && { nginx_was_running=true; systemctl stop nginx 2>/dev/null || true; }
  systemctl is-active --quiet x-ui  2>/dev/null && { xui_was_running=true;   systemctl stop x-ui  2>/dev/null || true; }
  if [[ "$ADG_PRESENT" == true && -n "$ADG_SERVICE" ]] && systemctl is-active --quiet "$ADG_SERVICE" 2>/dev/null; then
    adg_was_running=true; systemctl stop "$ADG_SERVICE" 2>/dev/null || true
  fi
  sleep 2

  restore_running_services() {
    [[ "$xui_was_running" == true ]] && systemctl start x-ui 2>/dev/null || true
    [[ "$adg_was_running" == true && -n "$ADG_SERVICE" ]] && systemctl start "$ADG_SERVICE" 2>/dev/null || true
    [[ "$nginx_was_running" == true ]] && systemctl start nginx 2>/dev/null || true
  }

  local pc="" pk="" cp_line="" db_line=""
  # ПРИОРИТЕТ №1: серт, ВПИСАННЫЙ в настройки x-ui (в т.ч. выпущенный через меню x-ui)
  db_line=$(panel_cert_from_db) || true
  if [[ -n "$db_line" ]]; then
    pc="${db_line%% *}"; pk=$(echo "$db_line" | awk '{print $2}')
    log "Панель: используется вписанный серт x-ui → $pc"
  fi
  # Приоритет №2: cert_paths (wildcard/персональный по домену)
  if [[ -z "$pc" ]]; then
    cp_line=$(cert_paths "$PANEL_DOMAIN") || true
    [[ -n "$cp_line" ]] && { pc="${cp_line%% *}"; pk="${cp_line##* }"; }
  fi
  if [[ -z "$pc" ]]; then
    log "Выпуск сертификата панели: $PANEL_DOMAIN"
    if ! cert_issue "$PANEL_DOMAIN"; then
      err "Не удалось выпустить cert"; restore_running_services; return 1
    fi
    cp_line=$(cert_paths "$PANEL_DOMAIN") || true
    if [[ -n "$cp_line" ]]; then pc="${cp_line%% *}"; pk="${cp_line##* }"; fi
  fi
  if [[ -z "$pc" || ! -f "$pc" || ! -f "$pk" ]]; then
    err "Сертификат панели не найден"; restore_running_services; return 1
  fi

  # СЕРТ ПАНЕЛИ ОБЯЗАН БЫТЬ ВПИСАН В НАСТРОЙКИ x-ui: без него панель слушает
  # HTTP, а nginx проксирует по https → 502 Bad Gateway. Вписываем всегда,
  # независимо от того, откуда пришёл серт (x-ui меню / cert_paths / выпуск).
  # ПУТИ — из /etc/letsencrypt/live/<домен>/ (единое место, без зеркала).
  local cr_line=""
  cr_line=$(cert_mirror_to_certroot "$(dirname "$pc")" "$PANEL_DOMAIN" 2>/dev/null || true)
  [[ -n "$cr_line" ]] && { pc="${cr_line%% *}"; pk="${cr_line##* }"; }
  xui_set_setting webDomain   "$PANEL_DOMAIN"
  xui_set_setting webCertFile "$pc"
  xui_set_setting webKeyFile  "$pk"
  xui_set_setting subCertFile "$pc"
  xui_set_setting subKeyFile  "$pk"
  xui_set_setting subDomain   "$PANEL_DOMAIN"
  xui_set_setting subURI      "$(suburi_build "$PANEL_DOMAIN")"
  log "Серт панели вписан в настройки x-ui (HTTPS-режим): $pc"

  for id in "${INB_IDS[@]}"; do
    [[ "${HIDE[$id]}" == true ]] || continue
    [[ -z "${DECOY_TPL[$id]}" ]] && continue
    local _cert_proto="${INB_PROTO[$id]:-unknown}"
    cert_issue "${DOMAIN[$id]}" || warn "  ИТОГ: серт ${DOMAIN[$id]} НЕ выпущен — #$id ($_cert_proto) не поднимется (причина выше)"
  done

  # CDN: ORIGIN-домену серт нужен ровно так же, как доменам инбаундов (TLS
  # терминирует nginx) — обрабатываем и печатаем его в том же виде, чтобы в логе
  # было видно его состояние, а не «тишина». Домен CDN-фронта (cdn.*) в SAN НЕ
  # входит: он принадлежит внешнему CDN, серт там терминируется самим CDN.
  cdn_profiles_load
  local _cid _corigin
  for _cid in "${CDN_PROFILE_IDS[@]}"; do
    _corigin=$(cdn_profile_field "$_cid" 3) || continue
    [[ -n "$_corigin" ]] || continue
    cert_issue "$_corigin" || warn "  ИТОГ: серт ${_corigin} НЕ выпущен — CDN-ORIGIN #$_cid не поднимется (причина выше)"
  done
  if (( ${#CDN_PROFILE_IDS[@]} > 0 )); then
    local _cfr=""
    _cfr=$(cdn_front_domains | tr '\n' ' ')
    [[ -n "${_cfr// /}" ]] && log "CDN-домены вне SAN (серт выдаёт CDN, не мы): ${_cfr% }"
  fi
  # пути сертификатов → в settings инбаундов (naive/anytls/trusttunnel/tproxy/hysteria)
  # режим выпуска сертов (A/B) + мультисерт по всем доменам стека
  cert_mode_ask
  # До этого места SNI-карта ещё не записана, поэтому одной синхронизации
  # cert_domains_sync_from_sni недостаточно: при первой установке домены из
  # анкеты находятся только в массиве DOMAIN[]. Регистрируем их в линиях
  # заранее, иначе режим B создаёт только панельную линию, а для остальных
  # позже пытается найти несуществующую all.<база>.
  local _setup_id _setup_dom _setup_line
  for _setup_id in "${INB_IDS[@]}"; do
    [[ "${HIDE[$_setup_id]}" == true ]] || continue
    _setup_dom="${DOMAIN[$_setup_id]:-}"
    [[ -n "$_setup_dom" ]] || continue
    # Внешний Reality использует SNI-цель третьей стороны — сертификат для
    # неё не выпускаем. Для всех остальных скрытых инбаундов (включая
    # VLESS TCP/XHTTP TLS без выбранного шаблона) домен должен попасть в линию.
    [[ "${REALITY_MODE[$_setup_id]:-}" == "1" ]] && continue
    if [[ "${CERT_MODE:-A}" == "B" ]]; then
      _setup_line=$(cert_line_for "$_setup_dom" 2>/dev/null || true)
      [[ -n "$_setup_line" ]] && cert_line_domains_add "$_setup_line" "$_setup_dom"
    else
      cert_domains_add "$_setup_dom"
    fi
  done
  # ORIGIN CDN — наш домен, ему тоже нужна запись в SAN-линии.
  cdn_profiles_load
  local _setup_cid _setup_origin
  for _setup_cid in "${CDN_PROFILE_IDS[@]}"; do
    _setup_origin=$(cdn_profile_field "$_setup_cid" 3 2>/dev/null || true)
    [[ -n "$_setup_origin" ]] || continue
    if [[ "${CERT_MODE:-A}" == "B" ]]; then
      _setup_line=$(cert_line_for "$_setup_origin" 2>/dev/null || true)
      [[ -n "$_setup_line" ]] && cert_line_domains_add "$_setup_line" "$_setup_origin"
    else
      cert_domains_add "$_setup_origin"
    fi
  done
  CERT_DEFER=0
  cert_batch_flush || warn "Мультисерт не выпущен — часть доменов может не работать (проверь DNS и п.10)"

  mkdir -p "$NGINX_STREAM_DIR" /etc/nginx/streams-available 2>/dev/null || true
  {
    echo "map \$ssl_preread_server_name \$backend {"
    echo "    default                       panel_backend;"
    # Один SNI в nginx stream map может иметь только одно значение. Сначала
    # резервируем домен панели: если старый/повторный запуск случайно выдал
    # его инбаунду, панельный маршрут сохраняется, а дубликат не печатается.
    local -A _sni_emitted=()
    if [[ -n "${PANEL_DOMAIN:-}" ]]; then
      echo "    $PANEL_DOMAIN                 panel_backend;"
      _sni_emitted["$PANEL_DOMAIN"]="panel_backend"
    fi
    for id in "${INB_IDS[@]}"; do
      # Не выводим пустой SNI: иначе получается строка только с backend,
      # и nginx сообщает «invalid number of the map parameters».
      local _sni_dom="${DOMAIN[$id]:-}"
      [[ "${HIDE[$id]}" == true && -n "$_sni_dom" ]] || continue
      if [[ -n "${_sni_emitted[$_sni_dom]+x}" ]]; then
        warn "SNI $_sni_dom уже занят (${_sni_emitted[$_sni_dom]}) — маршрут inb_${id}_backend не добавлен"
        continue
      fi
      echo "    $_sni_dom    inb_${id}_backend;"
      _sni_emitted["$_sni_dom"]="inb_${id}_backend"
    done
    # CDN-профили: SNI origin/cdn → локальный TLS-фронтенд (xhttp-инбаунды
    # без security входят через nginx). Карта перегенерируется — маршруты держим здесь.
    cdn_profiles_load
    local _cp_row _cp_origin _cp_cdn
    while IFS= read -r _cp_row; do
      _cp_origin=$(printf '%s' "$_cp_row" | cut -d'|' -f3)
      _cp_cdn=$(printf '%s' "$_cp_row" | cut -d'|' -f4)
      if [[ -n "$_cp_origin" ]]; then
        if [[ -z "${_sni_emitted[$_cp_origin]+x}" ]]; then
          echo "    $_cp_origin    cdn_frontend;"
          _sni_emitted["$_cp_origin"]="cdn_frontend"
        else
          warn "SNI $_cp_origin уже занят (${_sni_emitted[$_cp_origin]}) — CDN origin не добавлен"
        fi
      fi
      if [[ -n "$_cp_cdn" ]]; then
        if [[ -z "${_sni_emitted[$_cp_cdn]+x}" ]]; then
          echo "    $_cp_cdn    cdn_frontend;"
          _sni_emitted["$_cp_cdn"]="cdn_frontend"
        else
          warn "SNI $_cp_cdn уже занят (${_sni_emitted[$_cp_cdn]}) — CDN domain не добавлен"
        fi
      fi
    done < "$CDN_PROFILES" 2>/dev/null || true
    echo "}"
    echo
    echo "upstream panel_backend { server 127.0.0.1:4443; }"
    if [[ -s "$CDN_PROFILES" ]]; then
      echo "upstream cdn_frontend { server 127.0.0.1:$CDN_FE_PORT; }"
    fi
    for id in "${INB_IDS[@]}"; do
      [[ "${HIDE[$id]}" == true ]] && echo "upstream inb_${id}_backend { server 127.0.0.1:${INB_PORT[$id]}; }"
    done
    echo
    echo "server {"
    echo "    listen 443;"
    echo "    proxy_pass \$backend;"
    echo "    ssl_preread on;"
    echo "    proxy_connect_timeout 5s;"
    echo "    proxy_timeout 10m;"
    echo "}"
  } > "$SNI_CONF"
  # Единый источник истины: доступный файл — ссылка на реально включённый.
  # Так fuse/status/rollback и nginx смотрят на одну и ту же карту.
  mkdir -p /etc/nginx/streams-available 2>/dev/null || true
  rm -f /etc/nginx/streams-available/sni-router.conf 2>/dev/null || true
  ln -s "$SNI_CONF" /etc/nginx/streams-available/sni-router.conf 2>/dev/null || \
    cp -f "$SNI_CONF" /etc/nginx/streams-available/sni-router.conf 2>/dev/null || true

  # ПРОВЕРКА: SNI-записи домена панели в nginx — без неё decoy панели (4443)
  # недостижим по домену (сработает только default). Самолечение при наличии.
  if grep -qE "^[[:space:]]*${PANEL_DOMAIN//./\\.}[[:space:]]+panel_backend;" "$SNI_CONF" 2>/dev/null; then
    log "SNI-запись панели в nginx: $PANEL_DOMAIN → panel_backend ✓"
  else
    sed -i "0,/^[[:space:]]*default[[:space:]]\+panel_backend;/s||    $PANEL_DOMAIN                 panel_backend;\n&|" "$SNI_CONF" 2>/dev/null || true
    if grep -qE "^[[:space:]]*${PANEL_DOMAIN//./\\.}[[:space:]]+panel_backend;" "$SNI_CONF"; then
      warn "SNI-запись панели отсутствовала — добавлена: $PANEL_DOMAIN → panel_backend"
    else
      err "Не удалось добавить SNI-запись панели в $SNI_CONF — проверь вручную"
    fi
  fi

  # AdGuard на ОТДЕЛЬНОМ SNI-домене (режим 2): серт + TLS 3002 + маршрут.
  # nginx сейчас остановлен — карта подхватится финальным стартом nginx.
  if [[ -n "${ADG_MODE_SNI_DOM:-}" ]]; then
    adg_setup_sni_domain "$ADG_MODE_SNI_DOM" || warn "AdGuard SNI-домен не настроился — перезапусти п.1"
  fi

  mkdir -p "$NGINX_SITES_DIR" 2>/dev/null || true
  rm -f "$NGINX_SITES_DIR"/default 2>/dev/null || true
  # миграция: старые отдельные конфиги больше не нужны — всё будет в stack.conf
  rm -f "$NGINX_SITES_DIR"/decoy-*.conf 2>/dev/null || true
  rm -f "$NGINX_SITES_DIR"/panel.conf "$NGINX_SITES_DIR"/http80.conf 2>/dev/null || true
  stack_ensure
  stack_del_all_decoy
  printf '# stack-manager: единый конфиг (ACME :80, панель :4443, decoy)\n' > "$STACK_CONF"

  local decoy_block=""
  if [[ "$panel_decoy" == "adguard" ]]; then
    [[ "$ADG_PRESENT" == true && -n "$ADG_SERVICE" ]] && { systemctl start "$ADG_SERVICE" 2>/dev/null || true; sleep 1; }
    # фактический порт AdGuard (после configure может измениться — скорректируем ниже)
    local adg_port_build=""
    adg_port_build=$(adg_config_port)
    ADG_WEB_PORT="$adg_port_build"
    decoy_block=$(cat <<EOF
    location / {
        proxy_pass https://127.0.0.1:$ADG_WEB_PORT;
        proxy_ssl_verify off;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 86400;
    }
EOF
)
  else
    local panel_try='try_files /index.html =404;'
    if [[ "$panel_decoy" == tpl:custom:* ]]; then
      local custom_path="${panel_decoy#tpl:custom:}"
      if [[ -d "$custom_path" ]]; then
        PANEL_DECOY_DIR="$custom_path"
        panel_try='try_files $uri $uri/ /index.html;'
        log "Decoy панели: свой сайт из $custom_path"
      else
        warn "Папка $custom_path не найдена — стандартная заглушка"
        panel_decoy_stub_init
      fi
    else
      panel_decoy_stub_init
      # decoy-шаблон из каталога (tpl:ИМЯ) — кладём его как index.html панели
      if [[ "$panel_decoy" == tpl:* ]]; then
        local tpl_name="${panel_decoy#tpl:}"
        local tpl_src="$DECOY_TPL_DIR/$tpl_name.html"
        is_login_template "$tpl_name" && tpl_src="$DECOY_LOGIN_DIR/$tpl_name.html"
        if [[ -f "$tpl_src" ]]; then
          cp -f "$tpl_src" "$PANEL_DECOY_DIR/index.html" 2>/dev/null || true
          chown www-data:www-data "$PANEL_DECOY_DIR/index.html" 2>/dev/null || true
          log "Decoy панели: шаблон «$tpl_name»"
        else
          warn "Шаблон «$tpl_name» не найден — остаётся стандартная заглушка"
        fi
      fi
    fi
    decoy_block=$(cat <<EOF
    location / {
        root $PANEL_DECOY_DIR;
        $panel_try
    }
EOF
)
  fi

  { cat >> "$STACK_CONF" <<EOF
server {
    listen 127.0.0.1:4443 ssl;
    server_name $PANEL_DOMAIN;
    ssl_certificate     $pc;
    ssl_certificate_key $pk;
    set_real_ip_from 127.0.0.1;

    location $PANEL_PATH {
        proxy_pass https://127.0.0.1:$PANEL_PORT;
        proxy_ssl_verify off;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 86400;
    }

    location $SUB_PATH {
        proxy_pass https://127.0.0.1:$SUB_PORT;
        proxy_ssl_verify off;
        proxy_ssl_server_name on;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 86400;
    }

$decoy_block
}
EOF
  }

  { cat >> "$STACK_CONF" <<'EOF'
server {
    listen 80 default_server;
    server_name _;
    location /.well-known/acme-challenge/ { root /var/www/html; }
    location / { return 302 https://$host$request_uri; }
}
EOF
  }

  for id in "${INB_IDS[@]}"; do
    [[ "${HIDE[$id]}" == true ]] || continue
    if [[ -n "${REALITY_EXT_TARGET_BYID[$id]:-}" ]]; then
      reality_ext_hide "$id" "${REALITY_EXT_TARGET_BYID[$id]}" "${INB_PORT[$id]}" || warn "  #$id: внешний Reality не спрятан за 443"
      continue
    fi
    [[ -z "${DECOY_TPL[$id]}" ]] && continue
    local dom="${DOMAIN[$id]}" cp_line="" c="" k=""
    cp_line=$(cert_paths "$dom") || true
    if [[ -n "$cp_line" ]]; then
      c="${cp_line%% *}"; k="${cp_line##* }"
      local _dpl="${DECOY_TPL[$id]:-$(decoy_tpl_for "$dom")}"
      mk_decoy "${TLS_PORT[$id]}" "$dom" "$c" "$k" "/var/www/decoy-$id" "$_dpl"
      decoy_tpl_store_set "$dom" "$_dpl" >/dev/null 2>&1 || true
      reality_set_dest "$id" "${TLS_PORT[$id]}" "$dom"   # dest = внутренний IP decoy nginx + serverNames = домен
    else
      warn "  cert для $dom не найден — decoy пропущен"
    fi
  done

  # CDN: выше stack.conf пересобран с нуля (stack_del_all_decoy + перезапись),
  # поэтому http-блоки cdn_frontend (listen 127.0.0.1:$CDN_FE_PORT) снесены.
  # Восстанавливаем их СРАЗУ — до nginx -t и штатного старта nginx; иначе
  # CDN-соединение оживает только со второго прогона «Починить инбаунд».
  # noreload=1: nginx поднимает штатный шаг ниже, уже после ensure_stream_include.
  cdn_repair 1 1

  cp -n "$XUI_DB" "${XUI_DB}.bak.$(date +%s)" 2>/dev/null || true

  xui_set_setting webListen   '127.0.0.1'
  xui_set_setting webPort     "$PANEL_PORT"
  xui_set_setting webBasePath "$PANEL_PATH"
  xui_set_setting subListen   '127.0.0.1'
  xui_set_setting subPort     "$SUB_PORT"
  xui_set_setting subPath     "$SUB_PATH"
  xui_set_setting subDomain   "$PANEL_DOMAIN"
  # URL обратного прокси для подписок: иначе share-ссылки получают порт панели
  xui_set_setting subURI      "$(suburi_build "$PANEL_DOMAIN" "$SUB_PATH")"

  # самопроверка: указанные порты обязаны лечь в 3x-ui (панель остановлена —
  # запись пройдёт; снаружи всё закрывается nginx'ом на 443)
  local _chk_p _chk_s
  _chk_p=$(xui_get webPort); _chk_s=$(xui_get subPort)
  if [[ "$_chk_p" == "$PANEL_PORT" && "$_chk_s" == "$SUB_PORT" ]]; then
    log "Порты применены в 3x-ui: панель $PANEL_PORT, подписки $SUB_PORT (слушают 127.0.0.1, наружу — только 443 через nginx)"
  else
    err "Порты НЕ применились в 3x-ui (в базе panel=$_chk_p sub=$_chk_s, ожидалось $PANEL_PORT/$SUB_PORT)"
  fi

  local _id _proto _sec _dest
  while IFS='|' read -r _id _proto _sec _dest; do
    [[ -z "$_id" || -z "$_proto" ]] && continue
    # tproxy — прямой туннель без SNI-скрытия: всегда 0.0.0.0
    if is_udp_proto "$_proto" || [[ "$_proto" == "tproxy" ]]; then
      sqlite3 "$XUI_DB" "UPDATE inbounds SET listen='0.0.0.0' WHERE id=$_id;" 2>/dev/null || true
    elif [[ "$_proto" == "vless" && "$_sec" == "reality" && "$_dest" != 127.0.0.1:* ]]; then
      # Reality с внешним таргетом («найти цели»): доктрина «всё за 443» —
      # маршрут по SNI цели + hosts, слушаем 127.0.0.1, tcp-порт НЕ открываем
      local _dt="${_dest%%:*}"
      if [[ -n "$_dt" && "$_dt" != "127.0.0.1" ]]; then
        local _p_rt=""
        _p_rt=$(sqlite3 "$XUI_DB" "SELECT port FROM inbounds WHERE id=$_id;" 2>/dev/null || true)
        reality_ext_hide "$_id" "$_dt" "$_p_rt" || warn "  #$_id: не удалось спрятать за 443"
      else
        sqlite3 "$XUI_DB" "UPDATE inbounds SET listen='127.0.0.1' WHERE id=$_id;" 2>/dev/null || true
      fi
    else
      sqlite3 "$XUI_DB" "UPDATE inbounds SET listen='127.0.0.1' WHERE id=$_id;" 2>/dev/null || true
    fi
  done < <(sqlite3 "$XUI_DB" "SELECT id, protocol, COALESCE(json_extract(stream_settings,'\$.security'),''), COALESCE(json_extract(stream_settings,'\$.realitySettings.dest'),'') FROM inbounds WHERE enable=1 AND port>0;" 2>/dev/null || true)

  local has_hosts=""
  has_hosts=$(sqlite3 "$XUI_DB" "SELECT name FROM sqlite_master WHERE type='table' AND name='hosts';" 2>/dev/null || true)
  if [[ -n "$has_hosts" ]]; then
    cdn_profiles_load   # CDN-инбаунды исключаются из стандартной перезаписи hosts
    # SNI не занят инбаундом (не скрываем за 443) — hosts-запись («SNI включён») не нужна
    for id in "${INB_IDS[@]}"; do
      [[ "${HIDE[$id]}" == true ]] && continue
      [[ "${INB_PROTO[$id]}" == "tproxy" ]] && continue   # tg web proxy: hosts ведёт setup_tproxy_web
      # спрятан за 443 (свой домен ИЛИ чужой реалити по SNI цели) — hosts не трогаем
      grep -qE "^upstream inb_${id}_backend" "$SNI_CONF" 2>/dev/null && continue
      hosts_owned_delete "$id" 443
    done
    for id in "${INB_IDS[@]}"; do
      [[ "${HIDE[$id]}" == true ]] || continue
      # CDN-инбаунд: hosts ведёт hosts_cdn_upsert (адрес/SNI = CDN-домен,
      # security=tls) — стандартная запись панели затёрла бы его
      [[ " ${CDN_PROFILE_IDS[*]:-} " == *" $id "* ]] && continue
      # общая группа «один хост»: адрес = домен панели, security=same
      hosts_upsert "$id" "$PANEL_DOMAIN"
    done
  fi

  ensure_stream_include
  if ! nginx -t 2>/dev/null; then
    err "nginx -t упал:"; nginx -t 2>&1 | tail -5 | sed 's/^/  /'
    restore_running_services
    return 1
  fi

  if [[ "$panel_decoy" == "adguard" && -n "$ADG_SERVICE" ]]; then
    local adg_cred_pass=""
    adg_cred_pass=$(grep "Пароль" /root/adguard-credentials.txt 2>/dev/null | awk '{print $2}' | head -1 || true)
    if configure_adguard_doh "$adg_cred_pass" "$pc" "$pk"; then
      log "AdGuard Home добавлен в SNI-маршрут: https://$PANEL_DOMAIN/ (UI без пути) + /dns-query (DoH)"
    else
      warn "Не удалось настроить AdGuardHome.yaml для DoH"
    fi
    # configure мог сменить порт AdGuard — корректируем proxy_pass в stack.conf
    local adg_port_now=""
    adg_port_now=$(adg_config_port)
    if [[ -n "$adg_port_now" && "$adg_port_now" != "$adg_port_build" ]]; then
      sed -i "s|proxy_pass https://127.0.0.1:$adg_port_build;|proxy_pass https://127.0.0.1:$adg_port_now;|" "$STACK_CONF" 2>/dev/null || true
      nginx_reload || true
      log "AdGuard порт скорректирован в nginx: $adg_port_build → $adg_port_now"
    fi
    # визард не пройден (users пуст) — создаём админа автоматически и показываем пароль
    if grep -qE '^users: ?\[\]?' "$ADG_CONFIG" 2>/dev/null; then
      local adg_user="${U_ADG_USER:-admin}" adg_pass=""
      if [[ -n "${U_ADG_PASS:-}" ]]; then
        adg_pass="$U_ADG_PASS"   # пароль задан при установке
      else
        adg_pass=$(openssl rand -base64 18 2>/dev/null | tr -dc 'a-zA-Z0-9' | head -c 16)
        [[ -z "$adg_pass" ]] && adg_pass="AdG$(date +%s)"
      fi
      if adg_set_admin "$adg_user" "$adg_pass"; then
        {
          echo "AdGuard Home — $(date '+%F %T')"
          echo "  URL:    https://$PANEL_DOMAIN/"
          echo "  DoH:    https://$PANEL_DOMAIN/dns-query"
          echo "  Логин:  $adg_user"
          echo "  Пароль: $adg_pass"
        } > /root/adguard-credentials.txt 2>/dev/null || true
        chmod 600 /root/adguard-credentials.txt 2>/dev/null || true
        echo
        log "AdGuard UI:    https://$PANEL_DOMAIN/"
        log "AdGuard логин: $adg_user   пароль: $adg_pass  (сохранено в /root/adguard-credentials.txt)"
      fi
    fi
  fi

  systemctl start x-ui 2>/dev/null || true
  systemctl start nginx 2>/dev/null || true
  # 443/SNI обязан реально слушаться: без него панель и домены недоступны
  # снаружи, и «п.1 завершён» было бы ложью. Если модуль stream не был
  # подключён — пытаемся подключить и перезапустить nginx прямо здесь.
  if ! nginx_443_check 1; then
    if nginx_stream_module_enable; then
      ensure_stream_include >/dev/null 2>&1 || true
      nginx_reload >/dev/null 2>&1 || true
    fi
    nginx_443_check
  fi
  [[ "$adg_was_running" == true && -n "$ADG_SERVICE" ]] && systemctl start "$ADG_SERVICE" 2>/dev/null || true
  udp_inbound_firewall_check

  # tg web proxy: доводим tproxy-инбаунд до рабочего (hostname+серт+сайт+маршрут)
  setup_tproxy_web

  # --- Инбаунды на чистой установке: создаём ПОСЛЕ сборки стека.
  #     SNI_CONF готов, домен панели/email известны — вопросы в том же виде,
  #     что и в авто-подъёме (reality: свой/чужой → цель/домен → порт).
  inb_count=$(sqlite3 "$XUI_DB" "SELECT COUNT(*) FROM inbounds WHERE enable=1 AND port>0;" 2>/dev/null || echo 0)
  if [[ "$inb_count" -eq 0 ]]; then
    local do_create=false
    [[ "$PLAN_CREATE" == true ]] && do_create=true
    if [[ "$do_create" == true ]]; then
      echo
      line; echo -e "${B}   СОЗДАНИЕ ИНБАУНДОВ${N}"; line
      echo "  Активных пользовательских inbounds нет — запускаю мастер создания."
      create_inbounds_menu
    fi
  elif [[ "$PLAN_CREATE" == true ]]; then
    log "Активные инбаунды уже есть ($inb_count) — существующие не трогаю."
    if [[ -t 0 ]]; then
      local add_more=false
      askyn add_more "Запустить мастер и добавить новые инбаунды?" "n"
      [[ "$add_more" == true ]] && create_inbounds_menu
    else
      log "Добавить новые можно через раздел 1 → управление инбаундами."
    fi
  fi

  # --- Стелс-контроль п.1: TCP-инбаунды, не попавшие за 443 ---
  # После отката/восстановления инбаунды остаются в БД, а п.1 создаёт свои
  # только при пустой БД (не трогать боевые). Честно показать непрятанные
  # и предложить починку сразу — иначе это всплывёт только в п.15.
  local _hid _proto _port _remark _miss=()
  while IFS='|' read -r _hid _proto _port _remark; do
    [[ -z "$_hid" ]] && continue
    is_udp_proto "$_proto" && continue
    # CDN-инбаунд: TLS терминирует nginx (SNI origin/cdn → cdn_frontend), сам
    # xray слушает 127.0.0.1 — записи inb_<id>_backend в SNI-карте ему НЕ нужны.
    # Без этой проверки CDN-инбаунд попадал в «непрятанные» и тянул за собой
    # ложный прогон «Починить инбаунд» сразу после п.1.
    [[ -n "$(cdn_profile_get "$_hid" 2>/dev/null)" ]] && continue
    if [[ "$_proto" == "tproxy" ]]; then
      # спец-бэкенды tproxy: tg_backend (setup_tproxy_web) / "tproxy" (меню)
      grep -qE '^\s+\S+\s+(tproxy|tg_backend);' "$SNI_CONF" 2>/dev/null && continue
      _miss+=("${_hid}|${_proto}|${_port}|${_remark}")
      continue
    fi
    # CDN/XHTTP считается скрытым по ORIGIN-маршруту даже если hosts
    # содержит CDN-домен, а не отдельный обычный SNI.
    local _ist=""
    _ist=$(sqlite3 "$XUI_DB" "SELECT COALESCE(stream_settings,'') FROM inbounds WHERE id=$_hid;" 2>/dev/null || true)
    if inbound_is_xhttp_tls "$_ist" && grep -qE "^[[:space:]]+[^[:space:]]+[[:space:]]+inb_${_hid}_backend;" "$SNI_CONF" 2>/dev/null; then
      continue
    fi
    grep -qE "inb_${_hid}_backend;" "$SNI_CONF" 2>/dev/null && continue
    _miss+=("${_hid}|${_proto}|${_port}|${_remark}")
  done < <(sqlite3 "$XUI_DB" "SELECT id, protocol, port, remark FROM inbounds WHERE enable=1;" 2>/dev/null || true)
  if [[ ${#_miss[@]} -gt 0 ]]; then
    echo
    warn "TCP-инбаунды НЕ за 443 (в SNI-карте их нет — снаружи при закрытом UFW не работают):"
    local _r
    for _r in "${_miss[@]}"; do
      IFS='|' read -r _hid _proto _port _remark <<<"$_r"
      echo "    • #$_hid ${_remark:-без-имени} $_proto:$_port"
    done
    if [[ -t 0 ]]; then
      local _fix=false
      askyn _fix "Прогнать «Починить инбаунд» для каждого сейчас?" "y"
      if [[ "$_fix" == true ]]; then
        for _r in "${_miss[@]}"; do
          IFS='|' read -r _hid _proto _port _remark <<<"$_r"
          if [[ "$_proto" == "tproxy" ]]; then
            setup_tproxy_web   # у tproxy своя ветка: hostname+серт+сайт+маршрут
          else
            fix_inbound "$_hid"
          fi
        done
      fi
    else
      warn "  (не-интерактивный режим) спрячьте вручную: п.19 → инбаунд → «Починить», затем п.11 заново"
    fi
  fi

  log "Первичная настройка завершена."
  if [[ "$panel_decoy" == "adguard" ]]; then
    echo
    log "DoH доступен:  https://$PANEL_DOMAIN/dns-query"
    log "AdGuard UI:    https://$PANEL_DOMAIN/"
  fi
  echo
  # Переустановка: сброс старых правил прошлой установки (лишние TCP-порты)
  local fw_now=false
  [[ "$PLAN_FW" == true ]] && fw_now=true
  [[ "$fw_now" == true ]] && firewall_apply
  # Первичная настройка пересоздала SNI-карту и stack.conf с нуля — CDN-маршруты,
  # http-блоки, hosts-записи и путь инбаунда приводим к профилю. Это ТА ЖЕ
  # «Сверить и починить» (п.2 → 4 → 1), но выполненная ВНУТРИ п.1 и с живыми
  # проверками (путь/сессия/decoy) — повторный прогон обработчика не нужен.
  # Идемпотентно: при верном состоянии ничего не меняется, nginx не перезагружается.
  cdn_repair
}

# =====================================================================
# ЗАПОЛНЕНИЕ tunnel-инбаунда (naive/anytls/trusttunnel): домен + ключи + креды
# =====================================================================
tunnel_inbound_fill() {
  local id="$1" proto="$2" port="$3"
  [[ -z "$XUI_DB" || ! -f "$XUI_DB" ]] && { err "x-ui.db не найден"; return 1; }

  # снупет-поле настроек под протокол
  local sn_col="domain"
  [[ "$proto" == "anytls" ]] && sn_col="sni"
  [[ "$proto" == "trusttunnel" || "$proto" == "trust-tunnel" ]] && sn_col="hostname"

  # домен: из настроек → из маршрута nginx → спросить
  local domain=""
  domain=$(sqlite3 "$XUI_DB" "SELECT json_extract(settings,'\$.${sn_col}') FROM inbounds WHERE id=$id;" 2>/dev/null || true)
  [[ -z "$domain" || "$domain" == "null" ]] && domain=""
  if [[ -z "$domain" ]]; then
    domain=$(grep -E "^\s+\S+\s+inb_${id}_backend" "$SNI_CONF" 2>/dev/null | awk '{print $1}' | head -1 || true)
  fi
  if [[ -z "$domain" ]]; then
    local def="n.example.com"
    [[ "$proto" == "anytls" ]] && def="at.example.com"
    [[ "$proto" == "trusttunnel" || "$proto" == "trust-tunnel" ]] && def="tt.example.com"
    ask_sni_domain domain "$id" "$def"
  fi
  [[ -z "$domain" || "$domain" == "null" ]] && { err "Домен не указан"; return 1; }
  local owner=""
  owner=$(sni_domain_owner "$domain" "$id") || true
  [[ -n "$owner" ]] && { err "Домен $domain занят ($owner)"; return 1; }

  sni_upstream_add "inb_${id}_backend" "$port"
  sni_map_add "$domain" "inb_${id}_backend"
  SNI_USED["$domain"]="inb_${id}_backend"

  # сертификат
  cert_issue "$domain" || return 1
  local cp_line="" cert="" key=""
  cp_line=$(cert_paths "$domain") || true
  [[ -z "$cp_line" ]] && { err "cert для $domain не найден"; return 1; }
  cert="${cp_line%% *}"; key="${cp_line##* }"

  # текущие значения — генерируем только пустые
  local cur_user="" cur_pass="" cur_seed="" cur_pw="" cur_prefix="" cur_clients=""
  # Sidecar-инбаунды слушают только локальный backend: снаружи доступны
  # через nginx SNI на 443. Не оставляем старый/публичный listen — иначе
  # панель может занять внешний порт или закрывать TLS-соединение.
  sqlite3 "$XUI_DB" "UPDATE inbounds SET listen='127.0.0.1', enable=1 WHERE id=$id;" 2>/dev/null || true
  cur_user=$(sqlite3 "$XUI_DB" "SELECT json_extract(settings,'\$.authUser') FROM inbounds WHERE id=$id;" 2>/dev/null || true)
  cur_pass=$(sqlite3 "$XUI_DB" "SELECT json_extract(settings,'\$.authPass') FROM inbounds WHERE id=$id;" 2>/dev/null || true)
  cur_seed=$(sqlite3 "$XUI_DB" "SELECT json_extract(settings,'\$.authSeed') FROM inbounds WHERE id=$id;" 2>/dev/null || true)
  cur_pw=$(sqlite3 "$XUI_DB" "SELECT json_extract(settings,'\$.password') FROM inbounds WHERE id=$id;" 2>/dev/null || true)
  cur_prefix=$(sqlite3 "$XUI_DB" "SELECT json_extract(settings,'\$.clientRandomPrefix') FROM inbounds WHERE id=$id;" 2>/dev/null || true)
  cur_clients=$(sqlite3 "$XUI_DB" "SELECT json_extract(settings,'\$.clients') FROM inbounds WHERE id=$id;" 2>/dev/null || true)
  [[ -z "$cur_user" || "$cur_user" == "null" ]] && cur_user=$(gen_hex 4)
  [[ -z "$cur_pass" || "$cur_pass" == "null" ]] && cur_pass=$(gen_b64)
  [[ -z "$cur_seed" || "$cur_seed" == "null" ]] && cur_seed=$(gen_hex 32)
  [[ -z "$cur_pw" || "$cur_pw" == "null" ]] && cur_pw=$(gen_b64)
  [[ -z "$cur_prefix" || "$cur_prefix" == "null" ]] && cur_prefix="$(gen_hex 4)/ffffffff"

  # --- json_set поверх текущего settings (ничего не затираем) ---
  local upd="UPDATE inbounds SET settings=json_set(CASE WHEN json_valid(settings) THEN settings ELSE '{}' END,
    '\$.${sn_col}','$domain','\$.certFile','$cert','\$.keyFile','$key','\$.authSeed','$cur_seed'"
  local new_settings
  case "$proto" in
    naive)
      upd+=",'\$.authUser','$cur_user','\$.authPass','$cur_pass','\$.port',$port,'\$.useAcme',json('false'),'\$.behindCover',json('false'),'\$.hideOn443',json('false'),'\$.routeThroughXray',json('false')"
      [[ -z "$cur_clients" || "$cur_clients" == "null" ]] && upd+=",'\$.clients',json('[{\"email\":\"user\",\"enable\":true}]')"
      ;;
    anytls)
      upd+=",'\$.password','$cur_pw','\$.enabled',json('true'),'\$.port',$port"
      ;;
    trusttunnel|trust-tunnel)
      upd+=",'\$.port',$port,'\$.clientRandomPrefix','$cur_prefix','\$.upstreamProtocol','http2','\$.listenPreset','fast','\$.clientDns',COALESCE(json_extract(settings,'\$.clientDns'),'1.1.1.1'),'\$.routeThroughXray',json('false')"
      [[ -z "$cur_clients" || "$cur_clients" == "null" ]] && upd+=",'\$.clients',json('[{\"email\":\"user\",\"enable\":true}]')"
      ;;
  esac
  upd+=") , listen=CASE WHEN COALESCE(listen,'')='' THEN '127.0.0.1' ELSE listen END WHERE id=$id;"
  local err_out
  err_out=$(sqlite3 "$XUI_DB" "$upd" 2>&1) || { err "SQL: $err_out"; return 1; }

  # cred-файл пользователю
  umask 077
  {
    echo "=== $proto #$id — ЗАПОЛНЕНО ==="
    echo "Домен (SNI): $domain"
    echo "Порт: $port (панель слушает 127.0.0.1:$port, снаружи https://$domain:443)"
    if [[ "$proto" == "naive" ]]; then
      echo "Сервисный логин: $cur_user"
      echo "Сервисный пароль: $cur_pass"
      echo "URL: naive+https://$cur_user:$cur_pass@$domain:443"
    elif [[ "$proto" == "anytls" ]]; then
      echo "Пароль: $cur_pw"
      echo "URL: anytls://$cur_pw@$domain:443/?sni=$domain"
    else
      echo "Клиентские tt:// ссылки с логином/паролем — в панели (инбаунд → share)"
    fi
    echo "authSeed: $cur_seed"
  } > "/root/.lucx-$proto-info"
  chmod 600 "/root/.lucx-$proto-info" 2>/dev/null || true
  umask 022

  # проверка из БД
  local chk_dom
  chk_dom=$(sqlite3 "$XUI_DB" "SELECT json_extract(settings,'\$.${sn_col}') FROM inbounds WHERE id=$id;" 2>/dev/null || true)
  if [[ "$chk_dom" == "$domain" ]]; then
    log "Заполнено: $proto #$id → $domain, ключи из wildcard, креды в /root/.lucx-$proto-info"
  else
    err "Проверка не прошла: settings.$sn_col = '$chk_dom'"
  fi
  nginx_reload || true
  systemctl restart x-ui >/dev/null 2>&1 || true
  log "Панель перезапущена — сервис $proto должен подняться (смотрите journalctl -u x-ui | grep tunnel)"
  return 0
}

# =====================================================================
