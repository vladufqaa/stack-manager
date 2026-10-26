# PRE-INSTALL SNAPSHOT — снимок всего, во что скрипт может вмешаться.
# Делается при первом запуске (по согласию пользователя) или через раздел 5 → Pre-install snapshot.
# Хранится в /root/stack-backups/pre-install-<timestamp>/
# =====================================================================
take_pre_install_snapshot() {
  local ts; ts=$(date +%Y%m%d-%H%M%S)
  local dir="$BACKUP_DIR/pre-install-$ts"
  mkdir -p "$dir" 2>/dev/null || { err "Не могу создать $dir"; return 1; }

  log "Снимок состояния: $dir"
  log "  (x-ui.db, nginx, UFW, iptables, fail2ban, systemd-units, letsencrypt-renewal, AdGuard)"

  # 1. x-ui.db + /etc/x-ui
  if [[ -n "$XUI_DB" && -f "$XUI_DB" ]]; then
    # Консистентный SQLite-снимок: cp активной БД без WAL мог сохранить
    # незакоммиченные настройки Reality/hosts не полностью.
    local _snap_ok=false
    if command -v sqlite3 >/dev/null 2>&1; then
      sqlite3 "$XUI_DB" ".backup '$dir/x-ui.db'" >/dev/null 2>&1 && _snap_ok=true
    fi
    if [[ "$_snap_ok" != true ]]; then
      cp -a "$XUI_DB" "$dir/x-ui.db" 2>/dev/null || true
      [[ -f "${XUI_DB}-wal" ]] && cp -a "${XUI_DB}-wal" "$dir/x-ui.db-wal" 2>/dev/null || true
      [[ -f "${XUI_DB}-shm" ]] && cp -a "${XUI_DB}-shm" "$dir/x-ui.db-shm" 2>/dev/null || true
    fi
    [[ -d /etc/x-ui ]] && cp -a /etc/x-ui "$dir/etc-x-ui" 2>/dev/null || true
  fi

  # 2. nginx — весь конфиг целиком
  mkdir -p "$dir/nginx"
  cp -a /etc/nginx/nginx.conf "$dir/nginx/" 2>/dev/null || true
  for d in sites-available sites-enabled streams-available streams-enabled snippets conf.d; do
    [[ -d "/etc/nginx/$d" ]] && cp -a "/etc/nginx/$d" "$dir/nginx/" 2>/dev/null || true
  done

  # 3. UFW + iptables + маршруты
  mkdir -p "$dir/ufw"
  [[ -d /etc/ufw ]] && cp -a /etc/ufw "$dir/ufw/etc-ufw" 2>/dev/null || true
  [[ -f /etc/default/ufw ]] && cp -a /etc/default/ufw "$dir/ufw/" 2>/dev/null || true
  iptables-save   > "$dir/ufw/iptables.v4"  2>/dev/null || true
  ip6tables-save  > "$dir/ufw/iptables.v6"  2>/dev/null || true
  ip -4 route show > "$dir/ufw/routes.v4" 2>/dev/null || true
  ip -6 route show > "$dir/ufw/routes.v6" 2>/dev/null || true

  # 4. fail2ban
  if [[ -d /etc/fail2ban ]]; then
    mkdir -p "$dir/fail2ban"
    cp -a /etc/fail2ban "$dir/fail2ban/etc-fail2ban" 2>/dev/null || true
  fi

  # 5. systemd units стека
  mkdir -p "$dir/systemd"
  cp -a /etc/systemd/system/stack-heal.service /etc/systemd/system/stack-heal.timer "$dir/systemd/" 2>/dev/null || true
  cp -a /etc/systemd/system/x-ui.service "$dir/systemd/" 2>/dev/null || true

  # 6. letsencrypt renewal (без ключей)
  if [[ -d /etc/letsencrypt ]]; then
    mkdir -p "$dir/letsencrypt"
    cp -a /etc/letsencrypt/renewal "$dir/letsencrypt/" 2>/dev/null || true
    cp -a /etc/letsencrypt/renewal-hooks "$dir/letsencrypt/" 2>/dev/null || true
    cp -a /etc/letsencrypt/cli.ini "$dir/letsencrypt/" 2>/dev/null || true
  fi

  # 7. logrotate стека
  [[ -f /etc/logrotate.d/stack-decoy ]] && cp -a /etc/logrotate.d/stack-decoy "$dir/" 2>/dev/null || true

  # 8. AdGuard Home config
  if [[ -n "$ADG_CONFIG" && -f "$ADG_CONFIG" ]]; then
    cp -a "$ADG_CONFIG" "$dir/AdGuardHome.yaml" 2>/dev/null || true
  fi

  # 9. Контекст: пакеты + мета
  dpkg --get-selections > "$dir/dpkg-selections.txt" 2>/dev/null || true
  apt-mark showmanual > "$dir/apt-manual.txt" 2>/dev/null || true
  {
    echo "Дата: $(date '+%F %T')"
    echo "Хост: $(hostname)"
    echo "Панель: ${PANEL_FLAVOR:-unknown}"
    echo "x-ui.db: $XUI_DB"
    echo "AdGuard: ${ADG_SERVICE:-—}"
    echo "nginx: $(nginx -v 2>&1 || echo —)"
    echo "fail2ban: $(fail2ban-client --version 2>/dev/null | head -1 || echo —)"
  } > "$dir/INFO.txt"

  # Архив
  (cd "$BACKUP_DIR" && tar czf "pre-install-$ts.tar.gz" "pre-install-$ts" 2>/dev/null) || true

  log "Снимок готов: $dir"
  log "  архив: $BACKUP_DIR/pre-install-$ts.tar.gz"
  return 0
}

# Файл отсутствует в списке содержимого архива? (0 = отсутствует)
absent_in_list() {  # $1 = список путей, $2 = путь
  local e
  while IFS= read -r e; do
    [[ "$e" == "$2" || "$e" == "./$2" || "$e" == "${2#/}" ]] && return 1
  done <<<"$1"
  return 0
}

# Атомарная замена каталога из снимка: копируем во временное место, затем mv на
# место старого. Прежний каталог удаляется ТОЛЬКО после успешной установки нового;
# если cp/mv не удался — текущий конфиг остаётся нетронутым (раньше было
# «rm -rf + cp», и провал cp оставлял систему вообще без конфига).
safe_swap_dir() {   # $1 = источник (из снимка), $2 = целевой каталог
  local src="$1" dst="$2" t old
  [[ -d "$src" ]] || return 0
  t=$(mktemp -d "${dst}.restore.XXXXXX" 2>/dev/null) || { warn "mktemp для $dst не удался — пропускаю"; return 1; }
  if ! cp -a "$src" "$t/restore" 2>/dev/null; then
    rm -rf "$t" 2>/dev/null || true
    warn "копирование $src не удалось — $dst не тронут"
    return 1
  fi
  if [[ -e "$dst" ]]; then
    old="${dst}.old.$$"
    if ! mv "$dst" "$old" 2>/dev/null; then
      rm -rf "$t" 2>/dev/null || true
      warn "не удалось убрать старый $dst — оставляю как есть"
      return 1
    fi
    if mv "$t/restore" "$dst" 2>/dev/null; then
      rm -rf "$old" 2>/dev/null || true
    else
      mv "$old" "$dst" 2>/dev/null || true
      rm -rf "$t" 2>/dev/null || true
      warn "не удалось поставить новый $dst — откат к прежнему"
      return 1
    fi
  else
    mv "$t/restore" "$dst" 2>/dev/null || { rm -rf "$t" 2>/dev/null || true; return 1; }
  fi
  rm -rf "$t" 2>/dev/null || true
  return 0
}

restore_pre_install_snapshot() {
  line; echo -e "${B}   ВОССТАНОВЛЕНИЕ ИЗ PRE-INSTALL СНИМКА${N}"; line
  local snaps
  snaps=$(ls -1dt "$BACKUP_DIR"/pre-install-* 2>/dev/null | grep -v "\.tar\.gz$" | head -20)
  if [[ -z "$snaps" ]]; then
    warn "Снимков не найдено в $BACKUP_DIR/pre-install-*"; pause; return 0
  fi
  local i=1 d
  while IFS= read -r d; do
    [[ -z "$d" ]] && continue
    local info
    info=$(head -1 "$d/INFO.txt" 2>/dev/null || echo "—")
    printf "  %2d) %-40s %s
" "$i" "$(basename "$d")" "$info"
    i=$((i+1))
  done <<<"$snaps"
  echo
  local pick=""
  ask pick "Номер снимка (0 — отмена)" "0" '^[0-9]+$'
  [[ "$pick" == "0" ]] && return 0
  local chosen=""
  chosen=$(printf '%s
' "$snaps" | sed -n "${pick}p")
  [[ -z "$chosen" || ! -d "$chosen" ]] && { err "Не найден снимок #$pick"; pause; return 1; }

  echo
  echo -e "${R}ВНИМАНИЕ:${N} восстановление перезапишет текущее состояние:"
  echo "  • $XUI_DB (инбаунды и настройки панели)"
  echo "  • /etc/nginx (все сайты и стримы)"
  echo "  • правила UFW/iptables"
  echo "  • /etc/fail2ban (если был в снимке)"
  echo "  • systemd units стека (stack-heal, x-ui.service)"
  echo "  • /etc/letsencrypt/renewal + renewal-hooks"
  echo
  local sure=""
  ask sure "Для подтверждения введи YES" "" '^YES$'
  [[ "$sure" == "YES" ]] || { log "Отменено"; pause; return 0; }
  audit "rollback: восстановление из pre-install snapshot $chosen"

  log "Бэкап текущего состояния перед восстановлением…"
  take_pre_install_snapshot >/dev/null 2>&1 || true

  log "Остановка сервисов…"
  systemctl stop x-ui 2>/dev/null || true
  systemctl stop nginx 2>/dev/null || true
  [[ -n "$ADG_SERVICE" ]] && systemctl stop "$ADG_SERVICE" 2>/dev/null || true

  if [[ -f "$chosen/x-ui.db" && -n "$XUI_DB" ]]; then
    # WAL/SHM от текущей БД нельзя оставлять: SQLite применит их поверх
    # восстановленного снимка и вернёт старые SNI/hosts.
    sqlite3 "$XUI_DB" "PRAGMA wal_checkpoint(TRUNCATE);" >/dev/null 2>&1 || true
    rm -f "${XUI_DB}-wal" "${XUI_DB}-shm" 2>/dev/null || true
    cp -a "$chosen/x-ui.db" "$XUI_DB" 2>/dev/null && log "  x-ui.db восстановлен"
  fi
  if [[ -d "$chosen/etc-x-ui" ]]; then
    cp -a "$chosen/etc-x-ui/." /etc/x-ui/ 2>/dev/null || true
  fi

  if [[ -d "$chosen/nginx" ]]; then
    [[ -f "$chosen/nginx/nginx.conf" ]] && cp -a "$chosen/nginx/nginx.conf" /etc/nginx/nginx.conf 2>/dev/null
    for d in sites-available sites-enabled streams-available streams-enabled snippets conf.d; do
      if [[ -d "$chosen/nginx/$d" ]]; then
        safe_swap_dir "$chosen/nginx/$d" "/etc/nginx/$d" \
          && log "  /etc/nginx/$d восстановлен" \
          || warn "  /etc/nginx/$d НЕ восстановлен (см. выше)"
      fi
    done
    log "  /etc/nginx восстановлен"
  fi

  if [[ -d "$chosen/ufw" ]]; then
    [[ -f "$chosen/ufw/iptables.v4" ]] && iptables-restore  < "$chosen/ufw/iptables.v4" 2>/dev/null && log "  iptables v4 восстановлены"
    [[ -f "$chosen/ufw/iptables.v6" ]] && ip6tables-restore < "$chosen/ufw/iptables.v6" 2>/dev/null || true
    if [[ -d "$chosen/ufw/etc-ufw" ]]; then
      safe_swap_dir "$chosen/ufw/etc-ufw" /etc/ufw || warn "  /etc/ufw НЕ восстановлен"
      [[ -f "$chosen/ufw/ufw" ]] && cp -a "$chosen/ufw/ufw" /etc/default/ufw 2>/dev/null || true
      log "  /etc/ufw восстановлен"
    fi
  fi

  if [[ -d "$chosen/fail2ban/etc-fail2ban" ]]; then
    safe_swap_dir "$chosen/fail2ban/etc-fail2ban" /etc/fail2ban || warn "  /etc/fail2ban НЕ восстановлен"
    log "  /etc/fail2ban восстановлен"
  fi

  if [[ -d "$chosen/systemd" ]]; then
    for u in stack-heal.service stack-heal.timer x-ui.service; do
      [[ -f "$chosen/systemd/$u" ]] && cp -a "$chosen/systemd/$u" /etc/systemd/system/ 2>/dev/null
    done
    systemctl daemon-reload 2>/dev/null || true
    log "  systemd units восстановлены"
  fi

  if [[ -d "$chosen/letsencrypt" ]]; then
    safe_swap_dir "$chosen/letsencrypt/renewal" /etc/letsencrypt/renewal || warn "  letsencrypt/renewal НЕ восстановлен"
    safe_swap_dir "$chosen/letsencrypt/renewal-hooks" /etc/letsencrypt/renewal-hooks || warn "  letsencrypt/renewal-hooks НЕ восстановлен"
    [[ -f "$chosen/letsencrypt/cli.ini" ]] && cp -a "$chosen/letsencrypt/cli.ini" /etc/letsencrypt/ 2>/dev/null
    log "  letsencrypt renewal восстановлен"
  fi

  [[ -f "$chosen/stack-decoy" ]] && cp -a "$chosen/stack-decoy" /etc/logrotate.d/ 2>/dev/null || true

  if [[ -f "$chosen/AdGuardHome.yaml" && -n "$ADG_CONFIG" ]]; then
    cp -a "$chosen/AdGuardHome.yaml" "$ADG_CONFIG" 2>/dev/null && log "  AdGuardHome.yaml восстановлен"
  fi

  log "Запуск сервисов…"
  systemctl start nginx 2>/dev/null || true
  systemctl start x-ui 2>/dev/null || true
  [[ -n "$ADG_SERVICE" ]] && systemctl start "$ADG_SERVICE" 2>/dev/null || true
  systemctl restart fail2ban 2>/dev/null || true
  nginx -t >/dev/null 2>&1 && log "  nginx -t OK" || warn "  nginx -t провалился — проверь конфиг"

  line
  log "Восстановление из pre-install завершено: $chosen"
  line
  pause
}

# =====================================================================
# БЭКАП
# =====================================================================
backup_config() {
  line; echo -e "${B}   БЭКАП${N}"; line
  mkdir -p "$BACKUP_DIR" 2>/dev/null || true
  local ts file
  ts=$(date +%F_%H%M%S)
  file="$BACKUP_DIR/stack-backup-$ts.tar.gz"
  local -a files=(
    /etc/nginx/nginx.conf /etc/nginx/streams-enabled/ /etc/nginx/sites-enabled/
    "$XUI_DB" /etc/letsencrypt/renewal/
    /etc/fail2ban/jail.d/decoy-login.local
    /etc/fail2ban/filter.d/decoy-login.conf
  )
  [[ -n "$ADG_CONFIG" && -f "$ADG_CONFIG" ]] && files+=("$ADG_CONFIG")
  if ! tar czf "$file" "${files[@]}" 2>/dev/null; then
    rm -f "$file"
    err "Бэкап не создан: tar завершился с ошибкой"
    pause
    return 1
  fi
  sha256sum "$file" > "$file.sha256" 2>/dev/null || true
  log "Бэкап: $file"
  ls -lh "$file" 2>/dev/null || true
  pause
}

restore_config() {
  line; echo -e "${B}   ВОССТАНОВЛЕНИЕ${N}"; line
  mkdir -p "$BACKUP_DIR" 2>/dev/null || true
  ls -1t "$BACKUP_DIR"/stack-backup-*.tar.gz 2>/dev/null | nl -w2 -s') ' || { warn "Нет бэкапов"; pause; return 0; }
  local choice=""
  ask choice "Номер (0 — отмена)" "0" '^[0-9]+$'
  [[ "$choice" == 0 ]] && return 0
  local file=""
  file=$(ls -1t "$BACKUP_DIR"/stack-backup-*.tar.gz 2>/dev/null | sed -n "${choice}p" || true)
  [[ -z "$file" || ! -f "$file" ]] && { err "Не найден"; return 1; }
  askyn confirm "Восстановить из $file?" "n"
  [[ "$confirm" == true ]] || return 0
  audit "restore: восстановление конфигурации из $(basename "$file")"
  backup_config >/dev/null 2>&1 || true
  systemctl stop nginx 2>/dev/null || true
  systemctl stop x-ui  2>/dev/null || true
  [[ "$ADG_PRESENT" == true && -n "$ADG_SERVICE" ]] && systemctl stop "$ADG_SERVICE" 2>/dev/null || true
  tar xzf "$file" -C / 2>/dev/null && log "Файлы восстановлены"
  # Полный откат: убираем артефакты стека, которых в бэкапе нет — иначе
  # остаётся полу-настроенный стек и п.1 решает, что «уже всё настроено».
  local tlist _a
  tlist=$(tar tzf "$file" 2>/dev/null) || tlist=""
  for _a in "$STACK_CONF" \
            /etc/nginx/streams-available/sni-router.conf \
            /etc/nginx/streams-enabled/sni-router.conf \
            /etc/systemd/system/stack-heal.timer \
            /etc/systemd/system/stack-heal.service \
            /etc/letsencrypt/stack-domains.txt \
            /root/stack-frozen.txt \
            /etc/x-ui/x-ui.db /usr/local/x-ui/x-ui.db /opt/x-ui/x-ui.db; do
    if [[ -e "$_a" ]] && absent_in_list "$tlist" "$_a"; then
      rm -f "$_a" 2>/dev/null && log "  убрано (в бэкапе отсутствует): $_a"
    fi
  done
  [[ -e /etc/systemd/system/stack-heal.timer ]] || { systemctl disable --now stack-heal.timer 2>/dev/null || true; systemctl daemon-reload 2>/dev/null || true; }
  nginx -t 2>/dev/null && systemctl start nginx && log "Nginx запущен"
  systemctl start x-ui 2>/dev/null || true
  [[ "$ADG_PRESENT" == true && -n "$ADG_SERVICE" ]] && systemctl start "$ADG_SERVICE" 2>/dev/null || true
  systemctl restart fail2ban 2>/dev/null || true
  pause
}

# =====================================================================
# ПЕРЕЕЗД ДОМЕНА ПАНЕЛИ: серт + БД (webDomain/hosts) + nginx (блоки/map)
# + decoy-маркер + credentials. Старый серт опционально отзывается.
# =====================================================================
panel_domain_migrate() {
  line; echo -e "${B}   ПЕРЕЕЗД ДОМЕНА ПАНЕЛИ${N}"; line
  [[ -f "$XUI_DB" ]] || { err "x-ui.db не найден"; pause; return 1; }
  local old=""; old=$(xui_get webDomain 2>/dev/null | tr -d '[:space:]')
  if [[ -z "$old" || "$old" == "null" ]]; then
    ask old "Текущий домен панели (не найден в БД)" "" '^[a-zA-Z0-9.-]+$'
  fi
  [[ -z "$old" ]] && { warn "Отмена"; pause; return 0; }
  local new=""
  ask new "НОВЫЙ домен панели" "" '^[a-zA-Z0-9.-]+$'
  [[ -z "$new" || "$new" == "$old" ]] && { warn "Отмена"; pause; return 0; }

  echo
  echo "  Будет сделано:"
  echo "   • серт для $new (certbot, с текущим email LE)"
  echo "   • панель: webDomain → $new (stop → edit → start)"
  echo "   • hosts-записи: address $old → $new (ссылки подписок обновятся сами)"
  echo "   • nginx: stack.conf + SNI-map, маркер decoy панели, credentials-файл"
  if check_domain_points_to_server "$new" >/dev/null 2>&1; then
    ok "DNS: $new указывает на этот сервер"
  else
    local go=""
    askyn go "DNS: $new НЕ указывает на сервер (или не резолвится). Продолжить?" "n"
    [[ "$go" == true ]] || { pause; return 0; }
  fi
  local go=""
  askyn go "Начать переезд $old → $new?" "n"
  [[ "$go" == true ]] || { pause; return 0; }
  auto_backup_stack >/dev/null 2>&1 || true

  # 1) серт нового домена (уважает заморозку п.25 — снял freeze, если надо)
  cert_issue "$new" || warn "Серт $new не выпущен — панель временно на старом серте; повтори п.10 позже"

  # 2) БД панели: webDomain + hosts
  systemctl stop x-ui 2>/dev/null || true
  sqlite3 "$XUI_DB" "UPDATE settings SET value='$new' WHERE key='webDomain';" 2>/dev/null || true
  sqlite3 "$XUI_DB" "UPDATE hosts SET address='$new' WHERE address='$old';" 2>/dev/null || true

  # 3) nginx: панельные вхождения old → new (домен панели нигде больше не используется)
  local oesc="${old//./\\.}"
  local confs=("$STACK_CONF" "$SNI_CONF")
  local cf
  for cf in "${confs[@]}"; do
    [[ -f "$cf" ]] && cp -a "$cf" "$cf.bak-migrate-$(date +%Y%m%d-%H%M%S)"
  done
  sed -i "s/$oesc/$new/g" "$STACK_CONF" 2>/dev/null || true
  [[ -f "$SNI_CONF" ]] && sed -i "s/$oesc/$new/g" "$SNI_CONF" 2>/dev/null || true
  [[ -f /root/panel-credentials.txt ]] && sed -i "s/$oesc/$new/g" /root/panel-credentials.txt 2>/dev/null || true

  if nginx -t >/dev/null 2>&1; then
    nginx_reload || true
  else
    err "nginx -t не прошёл после замены — откатываю конфиги:"
    nginx -t 2>&1 | tail -4 | sed 's/^/    /'
    for cf in "${confs[@]}"; do
      local bak; bak=$(ls -t "$cf".bak-migrate-* 2>/dev/null | head -1)
      [[ -n "$bak" ]] && cp -a "$bak" "$cf"
    done
    systemctl start x-ui 2>/dev/null || true
    pause; return 1
  fi
  systemctl start x-ui 2>/dev/null || true

  # 4) старый серт — предложить убрать
  if cert_paths "$old" >/dev/null 2>&1; then
    local del=""
    askyn del "Отозвать и удалить старый серт $old? (клиенты должны перейти на $new)" "n"
    if [[ "$del" == true ]]; then
      certbot delete --cert-name "$old" -n >/dev/null 2>&1 \
        && log "Старый серт $old удалён" \
        || warn "Не удалось удалить серт $old — удали вручную: certbot delete --cert-name $old"
    fi
  fi

  echo
  ok "Переезд завершён: панель и подписки теперь на $new"
  warn "  • проверь панель и подписку в браузере (Ctrl+F5)"
  warn "  • у клиентов обнови ссылки (или просто перечитай подписку — URL меняется на $new)"
  warn "  • если decoy панели показывал старый домен в тексте — смени шаблон п.4"
  audit "panel: домен панели $old → $new"
  pause
}

certs_menu() {
  while :; do
  clear
  line; echo -e "${B}   СЕРТИФИКАТЫ${N}"; line
  # активный серт панели из настроек x-ui (в т.ч. выпущенный через меню x-ui)
  local db_line dc dk dd
  db_line=$(panel_cert_from_db) || true
  if [[ -n "$db_line" ]]; then
    dc="${db_line%% *}"; dk=$(echo "$db_line" | awk '{print $2}'); dd=$(echo "$db_line" | awk '{print $3}')
    echo -e "  ${G}▸ Активный серт панели (вписан в x-ui):${N} ${dd:-домен не определён}"
    echo "      cert: $dc"
    echo "      key:  $dk"
    echo "      действует до: $(openssl x509 -noout -enddate -in "$dc" 2>/dev/null | cut -d= -f2)"
  else
    echo "  ▸ Активный серт панели: в настройках x-ui не найден"
  fi
  echo
  certbot certificates 2>/dev/null | grep -E 'Certificate Name|Domains|Expiry' | sed 's/^/  /' || true
  echo
  echo "  Wildcard Cloudflare: ${WILDCARD_DOMAIN:-выключен}  |  токен: ${CF_CREDS}"
  echo
  echo "  1) Обновить все сертификаты (renew)"
  echo "  2) Dry-run продления"
  echo "  3) Выпустить wildcard (Cloudflare DNS-01)"
  echo "  4) Wildcard вкл/выкл"
  echo "  5) Выпуск серта через меню x-ui (освободить :80)"
  echo "  6) Показать домены и серты (обзор)"
  echo "  7) Сбросить email Let's Encrypt (спросить заново)"
  echo "  8) Переезд домена панели (серт/БД/hosts/nginx)"
  echo "  9) Пересобрать мультисерт из доменов панели/инбаундов"
  echo "  10) Добавить домен в мультисписок"
  echo "  11) Удалить домен из мультисписка"
  echo "  12) Аудит сертов — где что используется"
  echo "  13) Удалить серт по имени (с предупреждениями)"
  echo "  14) Логика выпуска сертификатов (A/B)"
  echo "  15) Очистка сирот (линии, которые нигде не используются)"
  echo "  16) Очистка дублей -0001"
  echo "  17) Аудит линий (SAN файла vs серт)"
  echo "  0) Назад"
  line
  local action=""
  read -rp "$(echo -e "${B}Выбор:${N} ")" action || action="0"
  [[ "$action" == "0" ]] && return 0
  case "$action" in
    1) certbot renew --quiet && log "OK" || true ;;
    2) certbot renew --dry-run 2>&1 | tail -20 || true ;;
    3) cert_wildcard_issue ;;
    4) wildcard_toggle ;;
    5) xui_cert_menu_helper ;;
    6) certs_view ;;
    7) le_email_forget; log "Email сброшен — при следующем выпуске спросит заново"; pause ;;
    8) panel_domain_migrate ;;
    9) cert_domains_load; log "Доменов в списке: ${#CERT_DOMAINS[@]}"; CERT_DEFER=0; cert_batch_flush; pause ;;
    10) certs_domain_add_manual ;;
    11) certs_domain_remove_manual ;;
    12) cert_audit ;;
    13) cert_delete_menu ;;
    14) cert_mode_menu ;;
    15) cert_lines_cleanup ;;
    16) cert_dedup_0001 ;;
    17) cert_lines_audit ;;
    0) return 0 ;;
    *) sleep 1 ;;
  esac
  done
}
decoy_stats() {
  [[ -s "$DECOY_LOG_ACCESS" ]] || { warn "Лог деко-доступов пуст"; pause; return 0; }
  python3 - "$DECOY_LOG_ACCESS" <<'PY'
import sys, time, re, collections
cut = time.time() - 86400
hits = 0
ips = collections.Counter()
hosts = collections.Counter()
paths = collections.Counter()
for line in open(sys.argv[1], errors="replace"):
    m = re.match(r'(\S+) \[([^]]+)\] "([^"]*)" (\d+) "([^"]*)" host=(\S+)', line)
    if not m:
        continue
    try:
        t = time.mktime(time.strptime(m.group(2).split(" +")[0], "%d/%b/%Y:%H:%M:%S"))
    except Exception:
        continue
    if t < cut:
        continue
    hits += 1
    ips[m.group(1)] += 1
    hosts[m.group(6)] += 1
    p = m.group(3).split(" ")[1] if len(m.group(3).split(" ")) > 1 else "/"
    paths[p[:60]] += 1
print(f"  Запросов за 24ч: {hits}")
print(f"  Уникальных IP:   {len(ips)}")
if hosts:
    print("  По доменам:")
    for h, c in hosts.most_common(10):
        print(f"    {h:40s} {c}")
if paths:
    print("  Топ путей:")
    for p, c in paths.most_common(8):
        print(f"    {p:42s} {c}")
if ips:
    print("  Топ IP:")
    for ip, c in ips.most_common(8):
        print(f"    {ip:42s} {c}")
PY
  pause
}

# забанить всех, кто открывал decoy за N часов
decoy_ban_watchers() {
  local hrs="" ips="" own_ip
  ask hrs "За сколько часов (1-168)" "24" '^[0-9]{1,3}$'
  ips=$(python3 - "$DECOY_LOG_ACCESS" "$hrs" <<'PY'
import sys, time, re
cut = time.time() - int(sys.argv[2]) * 3600
seen = []
for line in open(sys.argv[1], errors="replace"):
    m = re.match(r'(\S+) \[([^]]+)\] ', line)
    if not m:
        continue
    try:
        t = time.mktime(time.strptime(m.group(2).split(" +")[0], "%d/%b/%Y:%H:%M:%S"))
    except Exception:
        continue
    if t >= cut and m.group(1) not in seen:
        seen.append(m.group(1))
print(" ".join(seen))
PY
)
  [[ -z "$ips" ]] && { warn "Никого не нашлось"; pause; return 0; }
  own_ip=$(curl -s --max-time 3 https://api.ipify.org 2>/dev/null || true)
  echo "  Найдены IP:"
  local ip banned=0 skipped=0
  for ip in $ips; do
    if [[ "$ip" == "$own_ip" ]]; then
      echo "    $ip  (твой сервер/выход — пропущен)"; skipped=$((skipped+1))
    else
      echo "    $ip"
    fi
  done
  local conf="false"
  askyn conf "Забанить все НЕ-серверные IP в jail decoy-login?" "n"
  if [[ "$conf" == true ]]; then
    for ip in $ips; do
      [[ "$ip" == "$own_ip" ]] && continue
      fail2ban-client set decoy-login banip "$ip" >/dev/null 2>&1 && banned=$((banned+1))
    done
    log "Забанено: $banned"
  fi
  pause
}

security_menu() {
  line; echo -e "${B}   БЕЗОПАСНОСТЬ — БАНЫ, DECOY-ЛОГИНЫ, FAIL2BAN${N}"; line

  # --- деко-логины (jail decoy-login) ---
  echo -e "${B}▸ Декои (jail decoy-login)${N}"
  fail2ban-client status decoy-login 2>/dev/null | sed 's/^/  /' || echo "  jail не активен"
  local ips=""
  ips=$(fail2ban-client get decoy-login banip 2>/dev/null || true)
  echo "  Забаненные IP:"
  [[ -n "$ips" ]] && echo "$ips" | tr ' ' '\n' | sed 's/^/    /' || echo "    —"

  # --- остальные jail (sshd и пр.) ---
  local jails j
  jails=$(fail2ban-client status 2>/dev/null | sed -n 's/^.*Jail list:\s*//p' | tr ',' ' ')
  for j in $jails; do
    [[ "$j" == "decoy-login" ]] && continue
    echo
    echo -e "${B}▸ jail: $j${N}"
    fail2ban-client status "$j" 2>/dev/null | sed 's/^/  /'
  done

  echo
  echo "  1) Разбанить IP"
  echo "  2) Разбанить все (во всех jail)"
  echo "  3) Очистить лог деко-попыток"
  echo "  4) Добавить IP в whitelist (ignoreip)"
  echo "  5) Статистика decoy-посещений (24ч)"
  echo "  6) Забанить всех, кто открывал decoy"
  echo "  7) Включить jail recidive (рецидивисты — бан на неделю)"
  echo "  8) Живой лог fail2ban (tail -f)"
  echo "  0) Назад"
  line
  local c=""
  read -rp "$(echo -e "${B}Выбор:${N} ")" c || c="0"
  case "$c" in
    5) decoy_stats ;;
    6) decoy_ban_watchers ;;
    7) f2b_recidive_setup; pause ;;
    8) f2b_tail ;;
    1)
      local jj="" ip=""
      ask jj "Jail (Enter — decoy-login)" "decoy-login" '^[A-Za-z0-9_-]*$'
      [[ -z "$jj" ]] && jj="decoy-login"
      ask ip "IP для разбана" "" '^[0-9a-fA-F.:]+$'
      fail2ban-client set "$jj" unbanip "$ip" >/dev/null 2>&1 && { log "Разбанен: $ip (jail $jj)"; audit "f2b: unban $ip (jail $jj)"; } || err "Не получилось — проверь jail и IP"
      pause
      ;;
    2)
      local ca=""
      askyn ca "Снять ВСЕ баны во всех jail?" "n"
      [[ "$ca" == true ]] && { fail2ban-client unban --all >/dev/null 2>&1 && { log "Все баны сняты"; audit "f2b: unban all"; } || err "Не вышло (похоже, старый fail2ban)"; }
      pause
      ;;
    3)
      : > "$DECOY_LOG_ACCESS" 2>/dev/null || true
      systemctl restart fail2ban 2>/dev/null || true
      log "Лог деко-попыток очищен, fail2ban перезапущен"
      pause
      ;;
    4)
      local wip="" f="/etc/fail2ban/jail.local"
      ask wip "IP или подсеть для whitelist (напр. 203.0.113.5)" "" '^[0-9a-fA-F.:/]{3,45}$'
      if [[ -f "$f" ]]; then
        if grep -qE "^ignoreip" "$f" 2>/dev/null; then
          if grep -E "^ignoreip" "$f" | grep -qw "$wip"; then
            warn "Этот IP уже в whitelist"
          else
            sed -i "s|^\(ignoreip.*\)$|\1 $wip|" "$f"
            systemctl restart fail2ban 2>/dev/null || true
            log "Whitelist обновлён (+$wip), fail2ban перезапущен — этот IP больше не забанят"
          fi
        else
          printf '\nignoreip = 127.0.0.1/8 %s\n' "$wip" >> "$f"
          systemctl restart fail2ban 2>/dev/null || true
          log "Whitelist создан (+$wip), fail2ban перезапущен"
        fi
      else
        err "$f не найден — fail2ban настраивается в п.1"
      fi
      pause
      ;;
  esac
}

# ─────────────────────────────────────────────────────────────────────────────
# DNS Xray/LucX — глобальный шаблон панели
# Совместимо с xrayTemplateConfig LucX/3x-ui. Если установленная панель
# не хранит шаблон в БД, используем её фактический config.json как fallback.
# ─────────────────────────────────────────────────────────────────────────────
# Валидация пользовательских значений и реальная проверка DoH.
# Regex в ask() проверяет только форму ввода; здесь проверяем смысл:
# диапазоны IPv4, hostname, URL и ответ DNS-сервера. Иначе пользователь
# мог ввести формально подходящее, но заведомо нерабочее значение.
dns_validate_ipv4() {
  local ip="$1" oct
  [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  IFS=. read -r -a octs <<< "$ip"
  for oct in "${octs[@]}"; do
    (( oct <= 255 )) || return 1
  done
  return 0
}
dns_validate_hostname() {
  local h="$1"
  [[ -n "$h" && "$h" != .* && "$h" != *.*. && "$h" != *..* ]] || return 1
  [[ "$h" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]] || return 1
  [[ ${#h} -le 253 ]] || return 1
  return 0
}
dns_validate_doh() {
  local url="$1" host="$2" ip="$3" parsed_host code body q endpoint_host
  dns_validate_ipv4 "$ip" || { err "IPv4 DoH некорректен или содержит октет >255: $ip"; return 1; }
  [[ -n "$host" ]] || { err "DoH host не задан"; return 1; }
  for endpoint_host in $host; do
    dns_validate_hostname "$endpoint_host" || { err "DoH host некорректен: $endpoint_host"; return 1; }
  done
  [[ "$url" =~ ^https://[^/[:space:]]+/[^[:space:]]+$ ]] || {
    err "URL DoH должен быть HTTPS-адресом с путём, например https://dns.example/dns-query"; return 1;
  }
  parsed_host="${url#https://}"; parsed_host="${parsed_host%%/*}"
  [[ " $host " == *" $parsed_host "* ]] || {
    err "Host ($host) не содержит host из URL DoH ($parsed_host)"; return 1;
  }
  endpoint_host="$parsed_host"
  # Запрос A для example.com: проверяем именно DNS-ответ, а не просто TCP/HTTP.
  q='q80BAAABAAAAAAAAA3d3dwZnb29nbGUDY29tAAABAAE'
  body=$(mktemp /tmp/stack-doh-test.XXXXXX) || return 1
  code=$(curl -4 -ksS --max-time 8 --retry 1 --resolve "${endpoint_host}:443:${ip}" \
    -H 'accept: application/dns-message' \
    -H 'content-type: application/dns-message' \
    -o "$body" -w '%{http_code}' "${url}?dns=${q}" 2>/dev/null || true)
  if [[ "$code" != "200" ]] || ! python3 - "$body" <<'PYDNSCHECK'
import sys
p=sys.argv[1]
data=open(p,'rb').read()
# DNS header: 12 bytes; QR=1, RCODE=0, минимум один ответ.
ok=(len(data)>=12 and (data[2] & 0x80) and (data[3] & 0x0f)==0 and int.from_bytes(data[6:8],'big')>0)
raise SystemExit(0 if ok else 1)
PYDNSCHECK
  then
    rm -f "$body"
    err "DoH не прошёл реальную DNS-проверку: $url через $ip (HTTP $code, ответ не содержит успешный A-ответ)"
    return 1
  fi
  rm -f "$body"
  ok "DoH отвечает и реально резолвит DNS: $url → $ip"
  return 0
}

xray_dns_apply() {
  local mode="$1" doh_url="${2:-}" doh_host="${3:-}" doh_ip="${4:-}"
  case "$mode" in
    1) doh_url=""; doh_host=""; doh_ip="" ;;
    2) doh_url="https://cloudflare-dns.com/dns-query"; doh_host="cloudflare-dns.com one.one.one.one"; doh_ip="1.1.1.1" ;;
    3) doh_url="https://dns.google/dns-query"; doh_host="dns.google"; doh_ip="8.8.8.8" ;;
    4) doh_url="https://dns.quad9.net/dns-query"; doh_host="dns.quad9.net"; doh_ip="9.9.9.9" ;;
    5|6) [[ -n "$doh_url" && -n "$doh_host" && -n "$doh_ip" ]] || { err "Для пользовательского DoH нужны URL, host и IP"; return 1; } ;;
    *) err "Неизвестный профиль DNS"; return 1 ;;
  esac
  if [[ "$mode" != "1" ]]; then
    # Проверяем до остановки x-ui и до записи БД: ошибочный URL, host или IP
    # не должен оставлять панель без рабочего DNS.
    dns_validate_doh "$doh_url" "$doh_host" "$doh_ip" || return 1
  fi
  [[ -n "$XUI_DB" && -f "$XUI_DB" ]] || { err "x-ui.db не найден — DNS не изменён"; return 1; }
  # Если панель ещё не создала шаблон, инициализируем его из фактического
  # рабочего config.json. Это безопаснее, чем писать усечённый шаблон: api,
  # blackhole, direct и существующие routing.rules переносятся целиком.
  local has_template=0
  if sqlite3 "$XUI_DB" \
      "SELECT 1 FROM settings WHERE key='xrayTemplateConfig' AND value IS NOT NULL AND value<>'' LIMIT 1;" \
      2>/dev/null | grep -q '^1$'; then
    has_template=1
  fi
  if [[ "$has_template" -eq 0 && -f /usr/local/x-ui/bin/config.json ]]; then
    local seed_backup="$BACKUP_DIR/xray-template-seed-$(date +%Y%m%d-%H%M%S)-$$.db"
    mkdir -p "$BACKUP_DIR" 2>/dev/null || true
    cp -a "$XUI_DB" "$seed_backup" 2>/dev/null || {
      err "Не удалось создать backup x-ui.db — DNS не изменён"
      return 1
    }
    systemctl stop x-ui >/dev/null 2>&1 || true
    XRAY_CONFIG_SOURCE=/usr/local/x-ui/bin/config.json python3 - "$XUI_DB" <<'PYXSEED'
import json, os, sqlite3, sys
path, source = sys.argv[1], os.environ["XRAY_CONFIG_SOURCE"]
with open(source, encoding="utf-8") as fh:
    cfg = json.load(fh)
if not isinstance(cfg, dict):
    raise SystemExit("config.json: корень не является объектом")
outbounds = cfg.get("outbounds") if isinstance(cfg.get("outbounds"), list) else []
tags = {x.get("tag") for x in outbounds if isinstance(x, dict)}
if not {"direct", "blocked"}.issubset(tags):
    raise SystemExit("config.json: отсутствуют обязательные outbound direct/blocked")
routing = cfg.get("routing")
if not isinstance(routing, dict) or not isinstance(routing.get("rules"), list):
    raise SystemExit("config.json: отсутствует routing.rules")
value = json.dumps(cfg, ensure_ascii=False, indent=2)
con = sqlite3.connect(path, timeout=30)
try:
    cur = con.execute("UPDATE settings SET value=? WHERE key='xrayTemplateConfig'", (value,))
    if cur.rowcount == 0:
        con.execute("INSERT INTO settings(key,value) VALUES('xrayTemplateConfig',?)", (value,))
    con.commit()
finally:
    con.close()
PYXSEED
    local seed_rc=$?
    systemctl start x-ui >/dev/null 2>&1 || true
    if [[ "$seed_rc" -ne 0 ]]; then
      err "Не удалось создать xrayTemplateConfig из config.json — восстанавливаю backup"
      systemctl stop x-ui >/dev/null 2>&1 || true
      cp -a "$seed_backup" "$XUI_DB" 2>/dev/null || err "Не удалось восстановить $seed_backup"
      systemctl start x-ui >/dev/null 2>&1 || true
      return 1
    fi
    log "xrayTemplateConfig инициализирован из /usr/local/x-ui/bin/config.json"
  fi
  # Сначала проверяем наличие шаблона read-only: при его отсутствии не создаём
  # лишний backup и не запускаем восстановление заведомо неизменённой БД.
  python3 - "$XUI_DB" <<'PYXPRE'
import sqlite3, sys
con=sqlite3.connect(sys.argv[1], timeout=10)
try:
    row=con.execute("SELECT 1 FROM settings WHERE key='xrayTemplateConfig' AND value IS NOT NULL AND value<>'' LIMIT 1").fetchone()
finally:
    con.close()
if not row:
    print("xrayTemplateConfig отсутствует — безопасно отменено", file=sys.stderr)
    raise SystemExit(10)
PYXPRE
  local preflight_rc=$?
  if [[ $preflight_rc -eq 10 ]]; then
    log "Изменение DNS отменено: xrayTemplateConfig отсутствует; БД не изменялась"
    return 1
  elif [[ $preflight_rc -ne 0 ]]; then
    err "Не удалось проверить xrayTemplateConfig — DNS-шаблон не изменён"
    return 1
  fi
  # Перед изменением шаблона сохраняем саму БД: это отдельная rollback-точка,
  # потому что auto_backup_stack может быть вызван не из этого меню.
  local dns_backup=""
  mkdir -p "$BACKUP_DIR" 2>/dev/null || true
  dns_backup="$BACKUP_DIR/x-ui-dns-$(date +%Y%m%d-%H%M%S)-$$.db"
  if ! cp -a "$XUI_DB" "$dns_backup" 2>/dev/null; then
    err "Не удалось создать backup x-ui.db — DNS-шаблон не изменён"
    return 1
  fi
  systemctl stop x-ui >/dev/null 2>&1 || true
  DNS_MODE="$mode" DNS_URL="$doh_url" DNS_HOSTS="$doh_host" DNS_IP="$doh_ip" \
  python3 - "$XUI_DB" <<'PYXDNS'
import json, os, sqlite3, sys
path = sys.argv[1]
mode = os.environ.get("DNS_MODE", "1")
url = os.environ.get("DNS_URL", "")
hosts = os.environ.get("DNS_HOSTS", "").split()
ip = os.environ.get("DNS_IP", "").strip()
def unwrap(cfg):
    # LucX/3x-ui может хранить конфиг как JSON-обёртку с xraySetting.
    # Возвращаем рабочий объект и способ упаковки обратно, не теряя api/rules/outbounds.
    wrappers = []
    for _ in range(8):
        if isinstance(cfg, dict) and "xraySetting" in cfg and not any(k in cfg for k in ("dns", "routing", "outbounds", "inbounds")):
            wrappers.append(cfg)
            inner = cfg["xraySetting"]
            cfg = json.loads(inner) if isinstance(inner, str) else inner
        else:
            return cfg, wrappers
    raise ValueError("слишком много вложенных xraySetting")
con = sqlite3.connect(path, timeout=30)
row = con.execute("SELECT value FROM settings WHERE key='xrayTemplateConfig' ORDER BY id DESC LIMIT 1").fetchone()
if not row or not row[0]:
    print("xrayTemplateConfig отсутствует — безопасно отменено", file=sys.stderr)
    con.close()
    raise SystemExit(10)
try:
    container = json.loads(row[0])
    cfg, wrappers = unwrap(container)
except Exception as exc:
    print("xrayTemplateConfig повреждён или имеет неизвестный формат: %s" % exc, file=sys.stderr)
    con.close()
    raise SystemExit(10)
if not isinstance(cfg, dict):
    print("xrayTemplateConfig не является объектом — безопасно отменено", file=sys.stderr)
    con.close()
    raise SystemExit(10)
if mode == "1":
    # Только отключаем ранее заданный управляемый DNS; остальные поля сохраняем.
    cfg.pop("dns", None)
    routing = cfg.get("routing") if isinstance(cfg.get("routing"), dict) else {}
    routing["domainStrategy"] = "AsIs"
    cfg["routing"] = routing
    cfg["fakedns"] = None
else:
    routing = cfg.get("routing") if isinstance(cfg.get("routing"), dict) else {}
    routing["domainStrategy"] = "IPIfNonMatch"
    cfg["routing"] = routing
    host_map = {}
    for h in hosts:
        host_map[h] = ip
    cfg["dns"] = {
        "tag": "dns_inbound",
        "queryStrategy": "UseIPv4",
        "disableCache": False,
        "disableFallback": True,
        "disableFallbackIfMatch": True,
        "useSystemHosts": False,
        "enableParallelQuery": False,
        "serveStale": False,
        "serveExpiredTTL": 0,
        "hosts": host_map,
        "servers": [{"address": url, "skipFallback": True,
                      "queryStrategy": "UseIPv4", "timeoutMs": 4000}]
    }
    cfg["fakedns"] = None
    for ob in cfg.get("outbounds", []):
        if not isinstance(ob, dict) or ob.get("protocol") != "freedom" or ob.get("tag") != "direct":
            continue
        stream = ob.get("streamSettings") if isinstance(ob.get("streamSettings"), dict) else {}
        sock = stream.get("sockopt") if isinstance(stream.get("sockopt"), dict) else {}
        sock["domainStrategy"] = "ForceIPv4"
        stream["sockopt"] = sock
        ob["streamSettings"] = stream
        break
# Восстанавливаем исходную обёртку LucX/3x-ui, если она была.
# Это важно: при записи внутреннего объекта нельзя терять структуру шаблона.
value_obj = cfg
for wrapper in reversed(wrappers):
    wrapper["xraySetting"] = json.dumps(value_obj, ensure_ascii=False, indent=2) if isinstance(wrapper.get("xraySetting"), str) else value_obj
    value_obj = wrapper
value = json.dumps(value_obj, ensure_ascii=False, indent=2)
con.execute("UPDATE settings SET value=? WHERE key='xrayTemplateConfig'", (value,))
if con.total_changes == 0:
    raise SystemExit("xrayTemplateConfig не обновлён")
con.commit()
try:
    con.execute("PRAGMA wal_checkpoint(TRUNCATE)"); con.commit()
except Exception: pass
con.close()
PYXDNS
  local rc=$?
  systemctl start x-ui >/dev/null 2>&1 || true
  # Код 10 означает штатный безопасный отказ: шаблон отсутствует или
  # имеет неподдерживаемый формат. БД при этом не трогалась, restore не нужен.
  if [[ $rc -eq 10 ]]; then
    log "Изменение DNS отменено: xrayTemplateConfig отсутствует или не поддерживается; backup не восстанавливался"
    return 1
  fi
  if [[ $rc -ne 0 ]]; then
    warn "Не удалось записать xrayTemplateConfig — восстанавливаю backup $dns_backup"
    systemctl stop x-ui >/dev/null 2>&1 || true
    cp -a "$dns_backup" "$XUI_DB" 2>/dev/null || err "Не удалось восстановить $dns_backup"
    systemctl start x-ui >/dev/null 2>&1 || true
    return 1
  fi
  # x-ui генерирует итоговый config.json только после перезапуска; если сервис
  # не поднялся, возвращаем БД, чтобы не оставлять панель в полуобновлённом виде.
  if ! systemctl is-active --quiet x-ui; then
    err "x-ui не запустился после изменения DNS — восстанавливаю backup $dns_backup"
    systemctl stop x-ui >/dev/null 2>&1 || true
    cp -a "$dns_backup" "$XUI_DB" 2>/dev/null || err "Не удалось восстановить $dns_backup"
    systemctl start x-ui >/dev/null 2>&1 || true
    return 1
  fi
  if [[ "$mode" == 1 ]]; then
    log "DNS Xray: системный режим (управляемый DNS удалён), routing=AsIs"
  else
    log "DNS Xray применён: $doh_url · routing=IPIfNonMatch · queryStrategy=UseIPv4"
  fi
}

# Определить внешний домен AdGuard Home по фактической конфигурации.
# При отдельном SNI DoH живёт на adguard.<зона>, а не на домене панели.
xray_adguard_doh_endpoint() {
  local panel="${PANEL_DOMAIN:-}" dom="" block=""
  [[ -n "$panel" ]] || panel=$(xui_get webDomain 2>/dev/null || true)
  [[ "$panel" == "null" ]] && panel=""
  # Приоритет — реальный SNI-map: он показывает, куда nginx отправляет DoH.
  if [[ -f "$SNI_CONF" ]]; then
    dom=$(awk '$2 == "agh_backend;" {print $1; exit}' "$SNI_CONF" 2>/dev/null || true)
  fi
  if [[ -n "$dom" ]]; then
    printf '%s' "$dom"
    return 0
  fi
  # Если отдельного SNI нет, проверяем proxy AdGuard в корневом блоке панели.
  if [[ -f "$STACK_CONF" ]] && grep -q "listen 127.0.0.1:4443" "$STACK_CONF" 2>/dev/null; then
    block=$(sed -n '/listen 127\.0\.0\.1:4443/,/^}/p' "$STACK_CONF" 2>/dev/null || true)
    if grep -q "proxy_pass https://127\.0\.0\.1:" <<< "$block"; then
      printf '%s' "$panel"
      return 0
    fi
  fi
  return 1
}

xray_dns_menu() {
  [[ -n "$XUI_DB" && -f "$XUI_DB" ]] || { err "x-ui.db не найден — сначала установите панель"; return 1; }
  line; echo -e "${B}   DNS В ПАНЕЛИ LUCX/3X-UI${N}"; line
  echo "  1) Системный DNS (убрать управляемый шаблон)"
  echo "  2) DoH Cloudflare (1.1.1.1)"
  echo "  3) DoH Google (8.8.8.8)"
  echo "  4) DoH Quad9 (9.9.9.9)"
  echo "  5) Self-hosted DoH AdGuard (домен из SNI, IP автоматически)"
  echo "  6) Свой DoH (ввести URL, host и IP вручную)"
  local mode="" url="" host="" ip=""
  ask mode "Профиль DNS" "2" '^[1-6]$'
  case "$mode" in
    5)
      ip=$(server_ip4)
      host=$(xray_adguard_doh_endpoint 2>/dev/null || true)
      [[ -n "$host" && -n "$ip" ]] || {
        err "Не найден внешний домен AdGuard Home в SNI/nginx-конфигурации — DNS не изменён"; return 1;
      }
      url="https://${host}/dns-query"
      echo "  Self-hosted AdGuard: $url"; echo "  hosts: $host → $ip" ;;
    6)
      ask url "URL DoH (например https://dns.example/dns-query)" "https://" '^https://[^[:space:]]+$'
      ask host "DoH host для hosts" "" '^[a-zA-Z0-9.-]+$'
      ask ip "IPv4 DoH host" "" '^([0-9]{1,3}\.){3}[0-9]{1,3}$' ;;
  esac
  xray_dns_apply "$mode" "$url" "$host" "$ip"
  pause
}

# =====================================================================
