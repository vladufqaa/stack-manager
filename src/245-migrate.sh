# =====================================================================
# ПЕРЕЕЗД НА ДРУГОЙ СЕРВЕР (полный перенос стека)
#
# Порядок жёсткий и обратный обычному: сначала на НОВОМ сервере скрипт
# ставит платформу (пакеты, nginx, панель) — потом распаковывается архив
# со старого. Так распакованные бинарники/юниты всегда ложатся на готовую
# базу и не конфликтуют с установщиком панели.
#
# Схема:
#   1) старый сервер: migrate_export    → архив + sha256
#   2) новый сервер:  перенос файла (scp/rsync вручную или 8 → 1 на приёмнике)
#   3) новый сервер:  migrate_bootstrap → пакеты, nginx, панель
#   4) новый сервер:  migrate_unpack    → распаковка поверх платформы
#   5) новый сервер:  migrate_dns_check → имена должны указывать на новый IP
#   6) новый сервер:  migrate_certs_reissue → перевыпуск сертов
#   7) новый сервер:  migrate_postcheck → смоук
# =====================================================================
MIGRATE_DIR="/root/stack-backups"
MIGRATE_PREFIX="migrate"
MIGRATE_EXTRA_PATHS=(
  /root/.config/torrserver
  /opt/torrserver
)

# ─── Сбор доменов стека: БД, SNI-map, renewal, CDN-профили, маркеры ──────────
# Печатает по одному домену в строку, без чужих reality-целей и CDN-хостов.
migrate_collect_domains() {
  local d _rt_x skip_reality=false
  {
    [[ -n "$XUI_DB" && -f "$XUI_DB" ]] || true
    if [[ -n "$XUI_DB" && -f "$XUI_DB" ]]; then
      sqlite3 -cmd ".timeout 3000" "$XUI_DB" "SELECT value FROM settings WHERE key='webDomain';" 2>/dev/null || true
      sqlite3 -cmd ".timeout 3000" "$XUI_DB" "SELECT address FROM hosts WHERE address IS NOT NULL AND address<>'';" 2>/dev/null || true
      sqlite3 -cmd ".timeout 3000" "$XUI_DB" "SELECT stream_settings FROM inbounds WHERE stream_settings IS NOT NULL;" 2>/dev/null \
        | grep -oE '"(serverName|sni|hostname|domain)"[[:space:]]*:[[:space:]]*"[A-Za-z0-9.-]+"' \
        | sed -E 's/.*"([A-Za-z0-9.-]+)"$/\1/' || true
      sqlite3 -cmd ".timeout 3000" "$XUI_DB" "SELECT stream_settings FROM inbounds WHERE stream_settings IS NOT NULL;" 2>/dev/null \
        | grep -oE '"(serverNames)"[[:space:]]*:[[:space:]]*\[[^]]*\]' \
        | grep -oE '"[A-Za-z0-9.-]+"' | tr -d '"' || true
    fi
    # SNI-карта: только строки map (левая колонка), upstream-имена не домены
    sed -n 's/^[[:space:]]*\([A-Za-z0-9.-][A-Za-z0-9.-]*\)[[:space:]]\+[A-Za-z0-9_]*;.*/\1/p' "$SNI_CONF" 2>/dev/null || true
    # renewal-конфиги: имена линий и SAN
    if [[ -d /etc/letsencrypt/renewal ]]; then
      local f
      for f in /etc/letsencrypt/renewal/*.conf; do
        [[ -f "$f" ]] || continue
        basename "$f" .conf
        sed -n 's/^domains[[:space:]]*=[[:space:]]*//p' "$f" 2>/dev/null | tr ',' '\n' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'
      done
    fi
    # каждый производитель обязан заканчиваться \n: файлы без перевода строки
    # на конце склеиваются со следующим выводом (пустые строки отфильтрует grep)
    [[ -f "$WILDCARD_STATE" ]] && { head -n 1 "$WILDCARD_STATE" 2>/dev/null; printf '\n'; }
    [[ -f "$CDN_PROFILES" ]] && { cut -d'|' -f3,4 "$CDN_PROFILES" 2>/dev/null | tr '|' '\n'; printf '\n'; }
    [[ -f /etc/letsencrypt/stack-domains.txt ]] && { cat /etc/letsencrypt/stack-domains.txt 2>/dev/null; printf '\n'; }
  } | tr -d '\r' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | sed 's/^\*\.//' \
    | grep -E '^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?\.[A-Za-z]{2,}$' | sort -u \
    | while IFS= read -r d; do
      for _rt_x in "${REALITY_TARGETS[@]}"; do
        [[ "$d" == "$_rt_x" ]] && { skip_reality=true; break; }
        skip_reality=false
      done
      [[ "$skip_reality" == true ]] || printf '%s\n' "$d"
    done
}

# ─── Источники архива (только существующие пути) ────────────────────────────
migrate_sources() {
  local -a cand=(
    etc/x-ui
    etc/nginx
    etc/letsencrypt
    etc/fail2ban
    etc/systemd/system/x-ui.service
    etc/systemd/system/tg-stack-bot.service
    etc/systemd/system/stack-heal.service
    etc/systemd/system/stack-heal.timer
    etc/logrotate.d/stack-decoy
    etc/ufw
    etc/default/ufw
    var/www
    root/stack-manager.sh
    root/panel-credentials.txt
    root/adguard-credentials.txt
    root/.secrets
    root/stack-backups/wildcard-domain
    root/stack-backups/cert-mode
    root/stack-backups/cert-lines.txt
    root/stack-backups/le-email
    root/stack-backups/cdn-profiles.tsv
    root/stack-backups/.stack-configured
    root/stack-backups/cert-line-
  )
  local p
  for p in "${cand[@]}"; do
    if [[ "$p" == "root/stack-backups/cert-line-" ]]; then
      local f
      for f in /root/stack-backups/cert-line-*; do
        [[ -f "$f" ]] && printf '%s\n' "${f#/}"
      done
      continue
    fi
    [[ -e "/$p" ]] && printf '%s\n' "$p"
  done
  if [[ "${MIGRATE_WITH_EXTRA:-false}" == true ]]; then
    for p in "${MIGRATE_EXTRA_PATHS[@]}"; do
      [[ -e "$p" ]] && printf '%s\n' "${p#/}"
    done
  fi
}

# ─── 1. ЭКСПОРТ НА СТАРОМ СЕРВЕРЕ ───────────────────────────────────────────
migrate_export() {
  line; echo -e "${B}   1) ЭКСПОРТ: АРХИВ ДЛЯ ПЕРЕЕЗДА${N}"; line
  [[ -n "$XUI_DB" && -f "$XUI_DB" ]] || { err "x-ui.db не найден — это не источник стека"; pause; return 1; }
  mkdir -p "$MIGRATE_DIR" 2>/dev/null || { err "Не могу создать $MIGRATE_DIR"; pause; return 1; }

  local -a src=()
  mapfile -t src < <(migrate_sources)
  [[ ${#src[@]} -gt 0 ]] || { err "Не нашёл, что архивировать"; pause; return 1; }

  local extra=""
  if [[ "${MIGRATE_WITH_EXTRA:-false}" != true ]]; then
    askyn extra "Включить TorrServer и прочие доп. каталоги, если есть?" "n"
    MIGRATE_WITH_EXTRA="$extra"
    [[ "$extra" == true ]] && mapfile -t src < <(migrate_sources)
  fi

  echo
  echo "  В архив войдёт:"
  printf '    %s\n' "${src[@]}" | head -30
  [[ ${#src[@]} -gt 30 ]] && echo "    … всего ${#src[@]} путей"
  echo
  echo -e "  ${Y}В архиве приватные ключи TLS и БД панели — копировать только по SSH/scp.${N}"

  # Место: сжатие даёт ~1/3, требуем трёхкратный запас
  local need avail
  local -a full=()
  local p
  for p in "${src[@]}"; do full+=("/$p"); done
  need=$(du -sb --total "${full[@]}" 2>/dev/null | awk '/total/{print $1}')
  avail=$(df -B1 --output=avail / 2>/dev/null | tail -1 | tr -d ' ')
  if [[ -n "$need" && -n "$avail" ]] && (( need / 3 > avail )); then
    err "Мало места: нужно ~$((need/3/1048576))МБ, свободно $((avail/1048576))МБ"
    local go=""
    askyn go "Продолжить всё равно?" "n"
    [[ "$go" == true ]] || { pause; return 1; }
  fi

  local go=""
  askyn go "Собрать архив сейчас? Панель и nginx будут кратко остановлены" "y"
  [[ "$go" == true ]] || { pause; return 0; }
  audit "migrate: экспорт стека"

  local ts file
  ts=$(date +%Y%m%d-%H%M%S)
  file="$MIGRATE_DIR/$MIGRATE_PREFIX-$ts.tar.gz"

  log "Остановка x-ui (консистентная БД)…"
  sqlite3 "$XUI_DB" "PRAGMA wal_checkpoint(TRUNCATE);" >/dev/null 2>&1 || true
  systemctl stop x-ui 2>/dev/null || true

  log "Архивирование…"
  local rc=0
  tar czf "$file" -C / --warning=no-file-changed "${src[@]}" 2>/dev/null || rc=$?
  systemctl start x-ui 2>/dev/null || true
  # код 1 = «файл изменился во время чтения», архив при этом валиден
  if [[ $rc -ne 0 && $rc -ne 1 ]]; then
    err "tar завершился с кодом $rc — архив не готов"
    rm -f "$file"
    pause; return 1
  fi
  [[ -s "$file" ]] || { err "Архив пуст"; rm -f "$file"; pause; return 1; }
  chmod 600 "$file" 2>/dev/null || true
  sha256sum "$file" > "$file.sha256" 2>/dev/null || true

  local doms
  doms=$(migrate_collect_domains | tr '\n' ' ')
  {
    echo "Дата:      $(date '+%F %T')"
    echo "Источник:  $(hostname) / $(server_ip4 2>/dev/null || echo '?')"
    echo "Панель:    ${PANEL_FLAVOR:-unknown}"
    echo "Домены:    $doms"
    echo "Путей:     ${#src[@]}"
  } > "$file.INFO.txt" 2>/dev/null || true

  line
  ok "Архив готов: $file"
  ls -lh "$file" 2>/dev/null | sed 's/^/  /'
  echo "  sha256: $(cut -d' ' -f1 "$file.sha256" 2>/dev/null)"
  echo
  echo "  Дальше:"
  echo "   1) скопируй архив и .sha256 на новый сервер:"
  echo "      scp $file* root@НОВЫЙ_IP:/root/stack-backups/"
  echo "   2) на новом сервере: этот раздел → п.2 (установить платформу)"
  echo "   3) в конце — шеф: ни один домен не должен остаться на старом IP"
  line
  pause
}

# ─── 2. ПЛАТФОРМА НА НОВОМ СЕРВЕРЕ ──────────────────────────────────────────
# Сознательно ДО распаковки: распаковка кладёт файлы поверх готовой базы.
migrate_bootstrap() {
  line; echo -e "${B}   2) УСТАНОВКА ПЛАТФОРМЫ НА НОВОМ СЕРВЕРЕ${N}"; line
  echo "  Ставится: пакеты (nginx+certbot+ufw+fail2ban…), каталоги nginx,"
  echo "  сама панель LucX UI, базовая защита UFW (22/443/80)."
  echo "  Данные панели будут заменены при распаковке — это нормально."
  echo
  if [[ -n "$XUI_DB" && -f "$XUI_DB" ]]; then
    local nb
    nb=$(sqlite3 -cmd ".timeout 1000" "$XUI_DB" "SELECT COUNT(*) FROM inbounds;" 2>/dev/null || echo 0)
    warn "Панель уже есть ($nb инбаундов) — установка пропустится, но пакеты обновятся"
  fi
  local go=""
  askyn go "Начать установку платформы?" "y"
  [[ "$go" == true ]] || { pause; return 0; }
  audit "migrate: bootstrap платформы"

  if ! ensure_deps; then err "Зависимости не установились — платформа не готова"; pause; return 1; fi

  mkdir -p /etc/nginx/{sites-available,sites-enabled,streams-available,streams-enabled,snippets,conf.d} \
           /var/www/html /etc/letsencrypt/renewal-hooks/deploy 2>/dev/null || true

  detect_env
  if [[ -z "$XUI_DB" || ! -f "$XUI_DB" ]]; then
    install_lucx_panel || { err "Панель не установилась — распаковывать рано"; pause; return 1; }
    detect_env
  fi
  systemctl enable x-ui >/dev/null 2>&1 || true
  systemctl start x-ui 2>/dev/null || true

  # базовый firewall: SSH + 80 (ACME) + 443 (SNI). Полный набор — после распаковки.
  if command -v ufw >/dev/null 2>&1; then
    ufw allow "$SSH_PORT"/tcp >/dev/null 2>&1 || true
    ufw allow 443/tcp >/dev/null 2>&1 || true
    ufw allow 80/tcp >/dev/null 2>&1 || true
    log "UFW: разрешены $SSH_PORT, 80, 443"
  fi

  line
  ok "Платформа установлена. Дальше — п.3 (распаковка архива)."
  echo "  Панель сейчас на пустой БД: после распаковки её заменит БД со старого сервера."
  line
  pause
}

# ─── 3. РАСПАКОВКА ──────────────────────────────────────────────────────────
migrate_unpack() {
  line; echo -e "${B}   3) РАСПАКОВКА АРХИВА ПЕРЕЕЗДА${N}"; line
  local file=""
  local -a found=()
  local f
  for f in "$MIGRATE_DIR/$MIGRATE_PREFIX"-*.tar.gz; do [[ -f "$f" ]] && found+=("$f"); done
  if [[ ${#found[@]} -gt 0 ]]; then
    echo "  Найденные архивы:"
    local i=1
    for f in "${found[@]}"; do
      printf "  %2d) %-46s %s\n" "$i" "$(basename "$f")" "$(du -h "$f" 2>/dev/null | cut -f1)"
      i=$((i+1))
    done
    echo
    local pick=""
    ask pick "Номер архива (0 — отмена)" "1" '^[0-9]+$'
    [[ "$pick" == "0" ]] && { pause; return 0; }
    file=$(printf '%s\n' "${found[@]}" | sed -n "${pick}p")
  else
    ask file "Путь к архиву" "$MIGRATE_DIR/$MIGRATE_PREFIX.tar.gz" '^/.+'
  fi
  [[ -f "$file" ]] || { err "Архив не найден: $file"; pause; return 1; }

  # целостность: если рядом есть .sha256 — сверяем обязательно
  local sha_file="$file.sha256"
  if [[ -f "$sha_file" ]]; then
    local want got
    want=$(cut -d' ' -f1 "$sha_file" 2>/dev/null)
    got=$(sha256sum "$file" 2>/dev/null | cut -d' ' -f1)
    if [[ "$want" != "$got" ]]; then
      err "sha256 не совпал — архив повреждён или подменён"
      echo "    ожидалось: $want"
      echo "    получено:  $got"
      pause; return 1
    fi
    log "sha256 совпал"
  else
    warn "Файл .sha256 рядом отсутствует — целостность не проверена"
  fi

  # Список берём ЦЕЛИКОМ без пайпа: под глобальным pipefail
  # `tar tzf | head -5` даёт tar SIGPIPE (141) → подстановка «падает»,
  # хотя архив целый (538 записей в тесте). head для показа — уже по herestring.
  local tlist=""
  if ! tlist=$(tar tzf "$file" 2>/dev/null); then
    err "Архив не читается"; pause; return 1
  fi
  log "Содержимое (первые строки):"; head -5 <<<"$tlist" | sed 's/^/    /'

  local go=""
  askyn go "Распаковать в / (текущие панель, nginx и серты будут заменены)?" "y"
  [[ "$go" == true ]] || { pause; return 0; }
  audit "migrate: распаковка $(basename "$file")"

  auto_backup_stack >/dev/null 2>&1 || true
  log "Остановка служб…"
  systemctl stop x-ui 2>/dev/null || true
  systemctl stop nginx 2>/dev/null || true
  systemctl stop tg-stack-bot 2>/dev/null || true
  [[ -n "$ADG_SERVICE" ]] && systemctl stop "$ADG_SERVICE" 2>/dev/null || true

  local _pre_db=""
  if [[ -f "$XUI_DB" ]]; then
    sqlite3 "$XUI_DB" "PRAGMA wal_checkpoint(TRUNCATE);" >/dev/null 2>&1 || true
    rm -f "${XUI_DB}-wal" "${XUI_DB}-shm" 2>/dev/null || true
    _pre_db="$MIGRATE_DIR/pre-unpack-x-ui.db.$(date +%Y%m%d-%H%M%S)"
    cp -a "$XUI_DB" "$_pre_db" 2>/dev/null || _pre_db=""
  fi

  if ! tar xzf "$file" -C / -p 2>/dev/null; then
    err "Распаковка не удалась — службы остаются остановленными, состояние смотри выше"
    pause; return 1
  fi
  log "Файлы распакованы"

  # симлинки nginx: в архиве могли быть, но пересоберём на всякий случай
  mkdir -p "$NGINX_SITES_DIR" "$NGINX_STREAM_DIR" 2>/dev/null || true
  if [[ -f "$STACK_CONF" ]]; then
    ln -sf "$STACK_CONF" "$STACK_LINK" 2>/dev/null || cp -f "$STACK_CONF" "$STACK_LINK" 2>/dev/null || true
  fi
  # дистрибутивный default-сайт конфликтует со stack.conf (оба объявляют
  # default_server на :80): при переустановке пакета nginx symlink «default»
  # возвращается, и nginx -t после распаковки падает. Убираем.
  if [[ -f "$STACK_CONF" && ( -e /etc/nginx/sites-enabled/default || -L /etc/nginx/sites-enabled/default ) ]]; then
    rm -f /etc/nginx/sites-enabled/default
    log "Убран дистрибутивный sites-enabled/default — конфликтовал со stack.conf (default_server :80)"
  fi
  # sni-router: если available-файл есть, а enabled-ссылки нет — восстанавливаем
  if [[ -f /etc/nginx/streams-available/sni-router.conf && ! -e /etc/nginx/streams-enabled/sni-router.conf ]]; then
    ln -sf /etc/nginx/streams-available/sni-router.conf /etc/nginx/streams-enabled/sni-router.conf 2>/dev/null || true
  fi

  # права: приватный ключ и БД только root
  [[ -f "$XUI_DB" ]] && chown root:root "$XUI_DB" 2>/dev/null || true
  chmod 600 "$XUI_DB" 2>/dev/null || true
  chmod -R 600 /etc/letsencrypt/archive /etc/letsencrypt/keys 2>/dev/null || true

  migrate_db_verify "$_pre_db"

  systemctl daemon-reload 2>/dev/null || true
  systemctl enable x-ui >/dev/null 2>&1 || true

  if nginx -t >/dev/null 2>&1; then
    systemctl start nginx && log "nginx запущен"
  else
    err "nginx -t после распаковки не прошёл:"
    nginx -t 2>&1 | tail -6 | sed 's/^/    /'
    warn "  чаще всего это отсутствующий модуль stream: apt-get install -y libnginx-mod-stream"
  fi
  systemctl start x-ui 2>/dev/null || true
  systemctl start fail2ban 2>/dev/null || true
  if [[ -f /etc/systemd/system/tg-stack-bot.service ]]; then
    systemctl enable tg-stack-bot >/dev/null 2>&1 || true
    systemctl start tg-stack-bot 2>/dev/null || true
  fi

  # UFW: архив вернул конфиги (user.rules/ufw.conf), но фильтрацию в ядре
  # включает только явное решение. Включаем безопасно: только если в архиве
  # UFW был включён (ENABLED=yes), он ещё не активен и в правилах есть allow
  # для текущего SSH-порта — иначе предупреждение вместо включения.
  if command -v ufw >/dev/null 2>&1 && grep -qs '^ENABLED=yes' /etc/ufw/ufw.conf; then
    if ufw status 2>/dev/null | grep -q 'Status: active'; then
      log "UFW уже активен"
    else
      local -a _ufw_ports=()
      [[ -n "${SSH_CONNECTION:-}" ]] && _ufw_ports+=("$(awk '{print $4}' <<<"$SSH_CONNECTION")")
      if ((${#_ufw_ports[@]} == 0)); then
        # запущено не по SSH (консоль/VNC) — все внешние сокеты sshd
        # (loopback и X11-форвардинг не считаем: ufw loopback не фильтрует)
        local _up
        while IFS= read -r _up; do
          [[ -n "$_up" ]] || continue
          [[ " ${_ufw_ports[*]-} " == *" $_up "* ]] || _ufw_ports+=("$_up")
        done < <(ss -tlnp 2>/dev/null | awk '/sshd/ && $4 !~ /^(127\.|\[::1\]|::1)/ {n=split($4,a,":"); print a[n]}' | sort -un)
      fi
      local _added="" _ufw_bad=0
      _added=$(ufw show added 2>/dev/null) || _added=""
      for _up in "${_ufw_ports[@]}"; do
        if ! grep -qE "^ufw (allow|limit).*[^0-9:]${_up}(/tcp)?([[:space:]']|$)" <<<"$_added"; then
          warn "  в правилах UFW нет allow для SSH-порта ${_up} — не включаю, чтобы не отрезать сессию"
          warn "  вручную: ufw allow ${_up}/tcp && ufw --force enable"
          _ufw_bad=1
        fi
      done
      if ((${#_ufw_ports[@]} == 0)); then
        warn "  SSH-порт не определён — UFW не включаю (вручную: ufw --force enable)"
      elif ((_ufw_bad == 0)); then
        if ufw --force enable >/dev/null 2>&1; then
          log "UFW включён (правила из архива; SSH-порт проверен)"
        else
          warn "  включить UFW не удалось — вручную: ufw --force enable"
        fi
      fi
    fi
  fi

  stack_mark_configured || true

  sleep 2
  line
  if systemctl is-active --quiet x-ui && systemctl is-active --quiet nginx; then
    ok "Распаковка завершена, панель и nginx подняты"
  else
    warn "Распаковка завершена, но не все службы активны — смотри п.6 (проверка)"
  fi
  echo "  Обязательный следующий шаг: 8 → 4 (DNS) и 8 → 5 (перевыпуск сертов)."
  line
  pause
}

# Проверка x-ui.db после распаковки: целостность (PRAGMA integrity_check) и
# сверка числа инбаундов/клиентов со снимком до распаковки. Только отчёт:
# автоматического восстановления нет — решение за человеком (пути печатаем).
migrate_db_verify() { # $1 — путь к снимку x-ui.db до распаковки (может быть пуст)
  local pre_db="${1:-}"
  [[ -n "$XUI_DB" && -f "$XUI_DB" ]] || return 0
  sqlite3 "$XUI_DB" "PRAGMA wal_checkpoint(TRUNCATE);" >/dev/null 2>&1 || true
  local ic db_in db_cl pre_in="" pre_cl=""
  ic=$(sqlite3 -readonly "$XUI_DB" "PRAGMA integrity_check;" 2>/dev/null) || ic=""
  db_in=$(sqlite3 -readonly "$XUI_DB" "SELECT COUNT(*) FROM inbounds;" 2>/dev/null) || db_in=""
  db_cl=$(sqlite3 -readonly "$XUI_DB" "SELECT COUNT(*) FROM client_traffics;" 2>/dev/null) || db_cl=""
  if [[ -n "$pre_db" && -f "$pre_db" ]]; then
    pre_in=$(sqlite3 -readonly "$pre_db" "SELECT COUNT(*) FROM inbounds;" 2>/dev/null) || pre_in=""
    pre_cl=$(sqlite3 -readonly "$pre_db" "SELECT COUNT(*) FROM client_traffics;" 2>/dev/null) || pre_cl=""
  fi
  if [[ "$ic" == "ok" ]]; then
    log "x-ui.db: целостность OK ($(du -h "$XUI_DB" 2>/dev/null | awk '{print $1}'))"
  else
    err "x-ui.db: integrity_check НЕ прошёл${ic:+: $ic}"
    warn "  снимок до распаковки: ${pre_db:-— нет}; смотри п.8→6 и бэкапы (раздел 5)"
  fi
  if [[ -n "$pre_db" && -f "$pre_db" ]]; then
    log "x-ui.db: инбаундов ${db_in:-?} (до распаковки: ${pre_in:-?}), клиентов ${db_cl:-?} (до: ${pre_cl:-?})"
    if [[ -n "$pre_in" && -n "$db_in" && "$db_in" -lt "$pre_in" ]] \
       || [[ -n "$pre_cl" && -n "$db_cl" && "$db_cl" -lt "$pre_cl" ]]; then
      warn "  распакованная БД содержит МЕНЬШЕ данных, чем было до распаковки — возможно, архив старее состояния"
    fi
  else
    log "x-ui.db: инбаундов ${db_in:-?}, клиентов ${db_cl:-?} (снимка до распаковки нет — сверить не с чем)"
  fi
}

# ─── 4. ПРОВЕРКА DNS ────────────────────────────────────────────────────────
migrate_dns_check() {
  line; echo -e "${B}   4) ПРОВЕРКА ПРИВЯЗКИ ДОМЕНОВ К НОВОМУ IP${N}"; line
  local my_ip=""
  my_ip=$(server_ip4 2>/dev/null || curl -4 -s --max-time 6 ifconfig.me 2>/dev/null | tr -d '[:space:]' || true)
  [[ -n "$my_ip" ]] || { err "Не удалось определить внешний IP этого сервера"; pause; return 1; }
  echo "  Внешний IP этого сервера: ${B}$my_ip${N}"
  echo

  local -a doms=()
  mapfile -t doms < <(migrate_collect_domains)
  [[ ${#doms[@]} -gt 0 ]] || { warn "Домены не найдены (БД пуста? распаковка не сделана?)"; pause; return 1; }

  local d resolved ok_cnt=0 bad=0
  local -a bad_list=()
  printf '  %-40s %s\n' "ДОМЕН" "РЕЗОЛВ"
  for d in "${doms[@]}"; do
    resolved=$(dig +short A "$d" @1.1.1.1 2>/dev/null | grep -E '^[0-9.]+$' | tail -1 || true)
    [[ -z "$resolved" ]] && resolved=$(dig +short A "$d" @8.8.8.8 2>/dev/null | grep -E '^[0-9.]+$' | tail -1 || true)
    if [[ "$resolved" == "$my_ip" ]]; then
      printf '  %-40s %s %s\n' "$d" "${G}✓${N}" "$resolved"
      ok_cnt=$((ok_cnt+1))
    else
      printf '  %-40s %s %s\n' "$d" "${R}✗${N}" "${resolved:-нет A-записи}"
      bad=$((bad+1)); bad_list+=("$d")
    fi
  done
  echo
  if (( bad == 0 )); then
    ok "Все домены (${#doms[@]}) указывают на этот сервер — можно перевыпускать серты"
  else
    warn "Не переключено: $bad из ${#doms[@]}"
    echo "  Пока A-записи не переключены на $my_ip, HTTP-01 не пройдёт и серт не выпустится."
    echo "  Переключи записи в панели DNS домена (TTL минимальный), дождись TTL и повтори."
    echo
    echo "  Не переключены:"; printf '    %s\n' "${bad_list[@]}"
    echo
    echo "  Проверить повторно: 8 → 4. Принудительно (старые серты уже лежат и рабочие)"
    echo "  панель поднимется и так — но обновление сертов будет падать."
  fi
  echo
  echo "  ${Y}Не забыть:${N} старый сервер НЕ выключать до полного переноса клиентов."
  line
  pause
}

# ─── 5. ПЕРЕВЫПУСК СЕРТИФИКАТОВ ─────────────────────────────────────────────
migrate_certs_reissue() {
  line; echo -e "${B}   5) ПЕРЕВЫПУСК СЕРТИФИКАТОВ${N}"; line
  local -a doms=()
  mapfile -t doms < <(migrate_collect_domains)
  [[ ${#doms[@]} -gt 0 ]] || { warn "Домены не найдены"; pause; return 1; }

  local my_ip=""
  my_ip=$(server_ip4 2>/dev/null || true)
  echo "  Домены для сертов: ${#doms[@]}"
  echo "  Лимит Let's Encrypt: 5 сертов на 168 ч — принудительное обновление всех может"
  echo "  упереться в лимит. Ниже выбор."
  echo
  echo "  1) Только отсутствующие/истекающие (certbot решает сам) — безопасно"
  echo "  2) Принудительно ВСЕ (--force-renewal) — нужно при смене IP, но ест лимит"
  echo "  3) Только выбранные домены"
  local mode=""; ask mode "Режим" "1" '^[1-3]$'
  [[ -n "$my_ip" ]] || warn "Внешний IP не определён — DNS-проверка внутри certbot может ложно ругаться"

  local -a targets=()
  case "$mode" in
    1) targets=("${doms[@]}") ;;
    2) targets=("${doms[@]}") ;;
    3)
      local pick=""
      local i=1 d
      for d in "${doms[@]}"; do printf '  %2d) %s\n' "$i" "$d"; i=$((i+1)); done
      ask pick "Номера через пробел" "" '^[0-9 ]+$'
      local n
      for n in $pick; do
        (( n >= 1 && n <= ${#doms[@]} )) && targets+=("${doms[$((n-1))]}")
      done
      ;;
  esac
  [[ ${#targets[@]} -gt 0 ]] || { warn "Ничего не выбрано"; pause; return 0; }

  le_email_load || true
  if [[ -z "$EMAIL" ]] && [[ -t 0 ]]; then
    ask EMAIL "Email для Let's Encrypt" "" '^[^@]+@[^@]+\.[^@]+$'
    le_email_save "$EMAIL" || true
  fi
  [[ -n "$EMAIL" ]] || { err "Email Let's Encrypt не задан"; pause; return 1; }

  local go=""
  askyn go "Запустить перевыпуск для ${#targets[@]} домен(ов)?" "y"
  [[ "$go" == true ]] || { pause; return 0; }
  audit "migrate: перевыпуск сертов (${#targets[@]})"

  local d rc okc=0 failc=0
  local nginx_was=false
  systemctl is-active --quiet nginx 2>/dev/null && nginx_was=true
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
    ufw allow 80/tcp >/dev/null 2>&1 || true
  fi
  mkdir -p /var/www/html 2>/dev/null || true

  for d in "${targets[@]}"; do
    local resolved=""
    resolved=$(dig +short A "$d" @1.1.1.1 2>/dev/null | grep -E '^[0-9.]+$' | tail -1 || true)
    if [[ -n "$my_ip" && "$resolved" != "$my_ip" ]]; then
      err "  $d → ${resolved:-нет A-записи}, а сервер $my_ip — выпуск почти наверняка упадёт"
    fi
    local out=""
    if [[ "$mode" == "2" && -d "/etc/letsencrypt/live/$d" ]]; then
      log "  force-renew: $d"
      out=$(certbot renew --force-renewal --cert-name "$d" --non-interactive 2>&1 || true)
      grep -qE "Congratulations|Successfully renewed|not yet due" <<<"$out" && { okc=$((okc+1)); } || { failc=$((failc+1)); echo "$out" | tail -4 | sed 's/^/    /'; }
      continue
    fi
    if cert_issue "$d"; then
      okc=$((okc+1))
    else
      failc=$((failc+1))
    fi
  done

  [[ "$nginx_was" == true ]] || systemctl start nginx 2>/dev/null || true
  systemctl reload nginx 2>/dev/null || true
  line
  ok "Успешно: $okc   Провалов: $failc"
  [[ $failc -gt 0 ]] && warn "  по провалам смотри причину выше: чаще DNS ещё не переключён или лимит LE"
  [[ -d /etc/letsencrypt/renewal ]] && certbot renew --dry-run 2>&1 | tail -3 | sed 's/^/  dry-run: /'
  line
  pause
}

# ─── 6. ПРОВЕРКА ПОСЛЕ ПЕРЕЕЗДА ─────────────────────────────────────────────
migrate_postcheck() {
  line; echo -e "${B}   6) ПРОВЕРКА ПОСЛЕ ПЕРЕЕЗДА${N}"; line
  local fails=0
  check() {  # $1 = описание, $2 = команда-строка
    if eval "$2" >/dev/null 2>&1; then printf '  %s %s\n' "${G}✓${N}" "$1"
    else printf '  %s %s\n' "${R}✗${N}" "$1"; fails=$((fails+1)); fi
  }
  detect_env
  check "x-ui активен" "systemctl is-active --quiet x-ui"
  check "nginx активен" "systemctl is-active --quiet nginx"
  check "nginx -t проходи��" "nginx -t"
  check "x-ui.db читается" "sqlite3 '$XUI_DB' 'SELECT COUNT(*) FROM inbounds;'"
  check "443 слушает nginx" "ss -tlnH 'sport = :443' | grep -q ."
  check "UFW активен" "ufw status | grep -q 'Status: active'"
  check "fail2ban активен" "systemctl is-active --quiet fail2ban"
  if [[ -f /etc/systemd/system/tg-stack-bot.service ]]; then
    if systemctl is-enabled --quiet tg-stack-bot 2>/dev/null; then
      check "бот активен" "systemctl is-active --quiet tg-stack-bot"
    else
      printf '  %s бот выключен (disabled) — намеренно, не провал\n' "${Y}–${N}"
    fi
  fi

  local d doms ip4
  mapfile -t doms < <(migrate_collect_domains)
  for d in "${doms[@]}"; do
    [[ -f "/etc/letsencrypt/live/$d/fullchain.pem" ]] || continue
    ip4=$(openssl x509 -noout -enddate -in "/etc/letsencrypt/live/$d/fullchain.pem" 2>/dev/null | cut -d= -f2)
    if openssl x509 -noout -checkend 604800 -in "/etc/letsencrypt/live/$d/fullchain.pem" >/dev/null 2>&1; then
      printf '  %s серт %s (до %s)\n' "${G}✓${N}" "$d" "$ip4"
    else
      printf '  %s серт %s ИСТЕКАЕТ/истёк (%s)\n' "${R}✗${N}" "$d" "$ip4"; fails=$((fails+1))
    fi
  done

  # decoy-проверка по каждому домену с сертом: 200 для браузерного UA
  local ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124 Safari/537.36"
  for d in "${doms[@]}"; do
    local code
    code=$(curl -sk --max-time 8 --resolve "$d:443:127.0.0.1" -A "$ua" "https://$d/" -o /dev/null -w '%{http_code}' 2>/dev/null || true)
    if [[ "$code" =~ ^(2|3) ]]; then printf '  %s decoy %s (%s)\n' "${G}✓${N}" "$d" "$code"
    else printf '  %s decoy %s (%s)\n' "${Y}!${N}" "$d" "${code:-нет ответа}"; fi
  done

  line
  if (( fails == 0 )); then ok "Критичных провалов нет"
  else err "Провалов: $fails — смотри строки с ✗ выше"; fi
  echo "  ${Y}Проверки decoy с «!» — не критичны, но посмотри глазами в браузере.${N}"
  line
  pause
}

# ─── 7. ЧЕК-ЛИСТ ────────────────────────────────────────────────────────────
migrate_checklist() {
  line; echo -e "${B}   ЧЕК-ЛИСТ ПЕРЕЕЗДА${N}"; line
  echo "  Порядок обязателен, шаги не переставлять:"
  echo
  echo "   СТАРЫЙ сервер:"
  echo "    1. 8 → 1 — архив. Скопировать архив и .sha256 на новый сервер."
  echo
  echo "   НОВЫЙ сервер (по SSH):"
  echo "    2. 8 → 2 — платформа: пакеты, nginx, панель. До распаковки."
  echo "    3. 8 → 3 — распаковка (sha256 сверяется автоматически)."
  echo "    4. 8 → 4 — DNS: ВСЕ домены обязаны указывать на новый IP."
  echo "    5. 8 → 5 — перевыпуск сертов (после переключения DNS)."
  echo "    6. 8 → 6 — проверка: службы, серты, decoy."
  echo
  echo "  ${Y}Важно:${N}"
  echo "   • домены переключать в панели DNS домена, TTL заранее уменьшить"
  echo "   • старый сервер не выключать, пока клиенты не переедут"
  echo "   • приватные ключи и БД в архиве — копировать только по SSH"
  echo "   • лимит Let's Encrypt 5 сертов/168ч — принудительный перевыпуск всех тратит его"
  echo
  local n=0
  [[ -n "$XUI_DB" && -f "$XUI_DB" ]] && n=$(sqlite3 -cmd ".timeout 1000" "$XUI_DB" "SELECT COUNT(*) FROM inbounds;" 2>/dev/null || echo 0)
  echo "  Состояние: инбаундов в БД: $n | доменов: $(migrate_collect_domains | wc -l) | архивов в $MIGRATE_DIR: $(ls -1 "$MIGRATE_DIR"/$MIGRATE_PREFIX-*.tar.gz 2>/dev/null | wc -l)"
  line
  pause
}

migrate_menu() {
  while :; do
    clear
    line; echo -e "${B}   ПЕРЕЕЗД НА ДРУГОЙ СЕРВЕР${N}"; line
    echo "  1) 📦 Экспорт: собрать архив (на СТАРОМ сервере)"
    echo "  2) 🧱 Платформа: пакеты, nginx, панель (на НОВОМ)"
    echo "  3) 📂 Распаковать архив (на НОВОМ)"
    echo "  4) 🌐 Проверить DNS: домены → IP этого сервера"
    echo "  5) 🔐 Перевыпустить сертификаты"
    echo "  6) 🩺 Проверка после переезда"
    echo "  7) 📋 Чек-лист переезда"
    echo "  0) Назад"
    line
    local c=""
    read -rp "$(echo -e "${Y}👉${N} Выбор: ")" c || c="0"
    case "$c" in
      1) migrate_export ;;
      2) migrate_bootstrap ;;
      3) migrate_unpack ;;
      4) migrate_dns_check ;;
      5) migrate_certs_reissue ;;
      6) migrate_postcheck ;;
      7) migrate_checklist ;;
      0) return 0 ;;
      *) sleep 1 ;;
    esac
  done
}

# =====================================================================
