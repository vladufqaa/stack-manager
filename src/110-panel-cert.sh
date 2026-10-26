# ДОМЕН + СЕРТИФИКАТ ПАНЕЛИ СРАЗУ ПОСЛЕ ЧИСТОЙ УСТАНОВКИ
# =====================================================================
cert_domains_load() {
  CERT_DOMAINS=()
  [[ -f "$CERT_DOMAINS_FILE" ]] || return 0
  local d
  while IFS= read -r d; do
    d="$(printf '%s' "$d" | tr -d '[:space:]')"
    [[ -z "$d" ]] && continue
    [[ " ${CERT_DOMAINS[*]} " == *" $d "* ]] && continue
    CERT_DOMAINS+=("$d")
  done < "$CERT_DOMAINS_FILE"
}
cert_domains_save() {
  mkdir -p "$(dirname "$CERT_DOMAINS_FILE")" 2>/dev/null || true
  if [[ ${#CERT_DOMAINS[@]} -eq 0 ]]; then
    : > "$CERT_DOMAINS_FILE"
    return 0
  fi
  printf '%s\n' "${CERT_DOMAINS[@]}" > "$CERT_DOMAINS_FILE" 2>/dev/null || true
}
cert_domains_add() {
  local d="$1" force="${2:-0}"
  [[ -z "$d" ]] && return 0
  # CDN-фронт — не наш домен: серт выдает CDN, в SAN он не добавляется
  if cdn_front_domain_is "$d"; then
    warn "cert_domains_add: «$d» — домен CDN-фронта, в SAN не добавляется (TLS терминирует CDN)"
    return 0
  fi
  # wildcard в SAN-линии не нужен: HTTP-01 его не выпустит, а покрытие
  # *.база уже даёт серт линии/файл доменов — не портим идемпотентность
  if [[ "$d" == "*."* ]]; then
    warn "cert_domains_add: wildcard «$d» в SAN-список не добавляется (не выпускается по HTTP-01)"
    return 0
  fi
  cert_mode_load >/dev/null 2>&1 || true
  # ── В режиме B добавляем в правильную линию (автоопределение по базе) ──
  if [[ "${CERT_MODE:-A}" == "B" ]]; then
    local _line=""
    _line=$(cert_line_for "$d")
    if [[ -z "$_line" ]]; then
      # домен панели неизвестен — некуда класть, пишем в общий (best effort)
      warn "cert_domains_add: домен панели не определён — «$d» не привязан к линии"
      return 1
    fi
    cert_line_domains_add "$_line" "$d"
    return 0
  fi
  # ── Режим A — без фильтра: одна линия (имя = домен панели) ──
  cert_domains_load
  [[ " ${CERT_DOMAINS[*]} " == *" $d "* ]] && return 0
  CERT_DOMAINS+=("$d")
  cert_domains_save
}
cert_domains_remove() {
  local d="$1"
  [[ -z "$d" ]] && return 0
  cert_mode_load >/dev/null 2>&1 || true
  # панельный домен = имя главной линии, нельзя убрать
  cert_multi_name_resolve >/dev/null 2>&1 || true
  [[ -n "$CERT_MULTI_NAME" && "$d" == "$CERT_MULTI_NAME" ]] && return 0
  # ── В режиме B убираем из той линии, где он лежит ──
  if [[ "${CERT_MODE:-A}" == "B" ]]; then
    local _line=""
    _line=$(cert_line_for "$d")
    [[ -z "$_line" ]] && return 0
    cert_line_domains_remove "$_line" "$d"
    # если линия опустела и она НЕ главная — удалить её
    local pd=""
    pd=$(xui_get webDomain 2>/dev/null || true)
    if [[ -n "$pd" && "$_line" != "$pd" ]]; then
      cert_line_domains_load "$_line"
      if [[ ${#CERT_LINE_DOMAINS[@]} -eq 0 ]]; then
        cert_lines_remove "$_line"
        log "  линия $_line удалена (пустая)"
      fi
    fi
    return 0
  fi
  # ── Режим A ──
  cert_domains_load
  local -a newlist=() x
  for x in "${CERT_DOMAINS[@]}"; do
    [[ "$x" == "$d" ]] && continue
    newlist+=("$x")
  done
  if [[ ${#newlist[@]} -ne ${#CERT_DOMAINS[@]} ]]; then
    CERT_DOMAINS=("${newlist[@]}")
    cert_domains_save
  fi
}

# Выпуск единого мультисерта: stack-multi покрывает ВСЕ домены из
# /etc/letsencrypt/stack-domains.txt. Перевыпуск — только при изменении SAN
# или истечении ≤30 дн. Файл-список — источник истины.
# Универсальный выпуск одной линии: cert_issue_line <line-name>
#   • line = имя линии (в A совпадает с доменом панели; в B может быть all.<base>)
#   • Домены SAN берутся из cert_line_domains_load (A: stack-domains.txt;
#     B: cert-line-<имя>.domains).
#   • Первый -d = CN. Для главной линии (имя == домен панели) CN = имя линии.
#     Для доп. линий CN = первый домен из SAN (имя all.<base> не является доменом).
#   • DNS-фильтр: в TTY при невалидном домене — откат + сообщение + ожидание
#     Enter; в не-TTY — исключение невалидных с warn (для таймеров).
#   • Идемпотентно: если SAN совпадает и срок > 30 дн — выпуск не выполняется.
cert_issue_line() {
  local line="$1"
  [[ -z "$line" ]] && { err "cert_issue_line: пустое имя линии"; return 1; }

  cert_mode_load >/dev/null 2>&1 || true
  cert_line_domains_load "$line"
  [[ ${#CERT_LINE_DOMAINS[@]} -eq 0 ]] && { warn "Линия $line пуста — выпуск не нужен"; return 0; }

  # ── Wildcard-зона: линия базы wildcard выпускается через DNS-01 с *.<зона> ──
  # Мульти-SAN перевыпуск через webroot затирал "*.зона" из SAN (HTTP-01 не умеет
  # wildcard) — линия оставалась БЕЗ покрытия, флаг wildcard при этом жил, и
  # cert_paths раздавал серт, не покрывающий новые поддомены. Теперь линия
  # wildcard-зоны всегда содержит -d "<зона>" -d "*.<зона>" и идёт через
  # dns-cloudflare (если токен сохранён).
  local _wc_fix=false
  if [[ -z "$WILDCARD_DOMAIN" && -f "$WILDCARD_STATE" ]]; then
    WILDCARD_DOMAIN=$(head -n 1 "$WILDCARD_STATE" 2>/dev/null | tr -d '[:space:]' || true)
  fi
  if [[ -n "$WILDCARD_DOMAIN" && "$line" == "$WILDCARD_DOMAIN" && -f "$CF_CREDS" ]] \
     && grep -q 'dns_cloudflare_api_token' "$CF_CREDS" 2>/dev/null; then
    _wc_fix=true
  fi

  # CN
  local cn="" pd=""
  pd=$(xui_get webDomain 2>/dev/null || true)
  [[ -z "$pd" || "$pd" == "null" ]] && pd="${PANEL_DOMAIN:-}"
  if [[ -n "$pd" && "$line" == "$pd" ]]; then
    cn="$pd"
  else
    cn="${CERT_LINE_DOMAINS[0]}"
  fi

  # ── DNS-фильтр ──
  local -a _valid=() _invalid=()
  local _d2 _a4 _a6 _x
  for _d2 in "${CERT_LINE_DOMAINS[@]}"; do
    _a4=$(dig +short A "$_d2" @1.1.1.1 2>/dev/null | grep -E '^[0-9.]+$' | head -1 || true)
    [[ -z "$_a4" ]] && _a4=$(dig +short A "$_d2" @8.8.8.8 2>/dev/null | grep -E '^[0-9.]+$' | head -1 || true)
    _a6=$(dig +short AAAA "$_d2" @1.1.1.1 2>/dev/null | grep ':' | head -1 || true)
    if [[ -n "$_a4" || -n "$_a6" ]]; then
      _valid+=("$_d2")
    else
      _invalid+=("$_d2")
    fi
  done

  if [[ ${#_invalid[@]} -gt 0 ]]; then
    if [[ -t 0 ]]; then
      echo
      err "Линия «$line»: следующие домены НЕ резолвятся (A/AAAA):"
      for _x in "${_invalid[@]}"; do
        err "  - $_x"
      done
      err "Перевыпуск ОТМЕНЁН — исправь DNS и запусти снова."
      read -rp "$(echo -e "${B}Нажмите Enter чтобы продолжить${N}")" _ || true
      return 1
    fi
    warn "Линия «$line»: исключаю невалидные домены (не-TTY):"
    for _x in "${_invalid[@]}"; do warn "  - $_x"; done
    CERT_LINE_DOMAINS=("${_valid[@]}")
    cert_line_domains_save "$line"
  fi
  [[ ${#CERT_LINE_DOMAINS[@]} -eq 0 ]] && { warn "Линия «$line»: все домены исключены"; return 1; }

  # Email LE
  le_email_load || true
  if [[ -z "$EMAIL" ]]; then
    EMAIL=$(certbot show_account 2>/dev/null | grep -iE 'Email' | awk -F: '{print $2}' | tr -d ' ' | head -1 || true)
  fi
  if [[ -z "$EMAIL" && -t 0 ]]; then
    ask EMAIL "Email для Let's Encrypt" "" '^[^@]+@[^@]+\.[^@]+$'
    le_email_save "$EMAIL"
  fi
  if [[ -z "$EMAIL" ]]; then
    err "cert: email Let's Encrypt не задан. Укажи EMAIL или задай его в разделе сертификатов."
    return 1
  fi
  le_email_save "$EMAIL" || true

  # Идемпотентность: если SAN совпадает и срок > 30 дн — не выпускаем
  local ldir="/etc/letsencrypt/live/$line"
  if [[ -f "$ldir/fullchain.pem" ]]; then
    local cur_san want_san left _wc_missing=false _cf_extra=false
    cur_san=$(openssl x509 -noout -ext subjectAltName -in "$ldir/fullchain.pem" 2>/dev/null \
              | grep -oE 'DNS:[^,]+' | sed 's/DNS://g' | tr -d ' ' | sort | tr '\n' ',')
    if [[ "$_wc_fix" == true && "$cur_san" != *"*.$WILDCARD_DOMAIN"* ]]; then
      _wc_missing=true
      warn "Линия «$line»: wildcard *.$WILDCARD_DOMAIN потерян в SAN — перевыплускаю с ним"
    fi
    # CDN-фронт в SAN быть не должно (серт выдан не нами): если остался от
    # прежних версий — перевыпускаем линию без него, иначе он там так и живёт.
    if cert_san_has_cdn_front "$cur_san"; then
      _cf_extra=true
      warn "Линия «$line»: в SAN есть CDN-домен (TLS терминирует CDN) — перевыпускаю без него"
    fi
    want_san=$(printf '%s\n' "${CERT_LINE_DOMAINS[@]}" | sort -u | tr '\n' ',')
    if [[ "$_wc_missing" == false && "$_cf_extra" == false && "${cur_san%,}" == "${want_san%,}" ]]; then
      left=$(( ($(date -d "$(openssl x509 -enddate -noout -in "$ldir/fullchain.pem" 2>/dev/null | cut -d= -f2)" +%s 2>/dev/null || echo 0) - $(date +%s)) / 86400 ))
      if (( left > 30 )); then
        log "Линия «$line» актуальна (${#CERT_LINE_DOMAINS[@]} дм., ~$left дн)"
        return 0
      fi
    elif [[ "$_cf_extra" == false ]] && cert_san_set_covers "$ldir/fullchain.pem" "${CERT_LINE_DOMAINS[@]}"; then
      left=$(( ($(date -d "$(openssl x509 -enddate -noout -in "$ldir/fullchain.pem" 2>/dev/null | cut -d= -f2)" +%s 2>/dev/null || echo 0) - $(date +%s)) / 86400 ))
      if (( left > 30 )); then
        log "Линия «$line» покрыта текущим сертом (wildcard/SAN), ~$left дн — перевыпуск не нужен"
        return 0
      fi
    fi
  fi

  # Аргументы -d: CN первым
  local -a cargs=()
  cargs+=(-d "$cn")
  local d
  for d in "${CERT_LINE_DOMAINS[@]}"; do
    [[ "$d" == "$cn" ]] && continue
    cargs+=(-d "$d")
  done
  if [[ "$_wc_fix" == true ]]; then
    cargs+=(-d "$WILDCARD_DOMAIN" -d "*.$WILDCARD_DOMAIN")
  fi

  log "Выпуск линии «$line» (CN=$cn, ${#CERT_LINE_DOMAINS[@]} дм.)…"
  mkdir -p /var/www/html 2>/dev/null || true
  mkdir -p /var/www/html/.well-known/acme-challenge 2>/dev/null || true
  chown -R www-data:www-data /var/www/html/.well-known 2>/dev/null || true
  chmod 755 /var/www/html /var/www/html/.well-known /var/www/html/.well-known/acme-challenge 2>/dev/null || true

  local ufw_80=false
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
    if ! ufw status 2>/dev/null | grep -qE "^80/tcp[[:space:]]+ALLOW"; then
      ufw allow 80/tcp comment "acme-temp" >/dev/null 2>&1 || true
      ufw_80=true
    fi
  fi

  local out=""
  if [[ "$_wc_fix" == true ]]; then
    # wildcard возможен только через DNS-01 Cloudflare
    out=$(certbot certonly --dns-cloudflare \
          --dns-cloudflare-credentials "$CF_CREDS" \
          --dns-cloudflare-propagation-seconds 30 \
          --non-interactive --agree-tos \
          --email "$EMAIL" --cert-name "$line" --force-renewal \
          "${cargs[@]}" 2>&1 || true)
  else
  out=$(certbot certonly --webroot -w /var/www/html --non-interactive --agree-tos \
        --email "$EMAIL" --cert-name "$line" --force-renewal \
        "${cargs[@]}" 2>&1 || true)
  fi

  if [[ ! -f "$ldir/fullchain.pem" || ! -f "$ldir/privkey.pem" ]]; then
    local nginx_was=""
    if systemctl is-active --quiet nginx 2>/dev/null; then
      nginx_was=1; systemctl stop nginx 2>/dev/null || true
    fi
    if [[ "$_wc_fix" == true ]]; then
      out="$out
$(certbot certonly --dns-cloudflare \
      --dns-cloudflare-credentials "$CF_CREDS" \
      --dns-cloudflare-propagation-seconds 30 \
      --non-interactive --agree-tos --email "$EMAIL" --cert-name "$line" \
      --force-renewal "${cargs[@]}" 2>&1 || true)"
    else
    out="$out
$(certbot certonly --standalone --non-interactive --agree-tos \
        --email "$EMAIL" --cert-name "$line" --force-renewal \
        "${cargs[@]}" 2>&1 || true)"
    fi
    [[ -n "$nginx_was" ]] && systemctl start nginx 2>/dev/null || true
  fi

  [[ "$ufw_80" == true ]] && ufw delete allow 80/tcp >/dev/null 2>&1 || true

  if [[ -f "$ldir/fullchain.pem" && -f "$ldir/privkey.pem" ]]; then
    log "Линия «$line» готова: $ldir"
    return 0
  fi
  err "Линия «$line» НЕ выпущена:"
  echo "$out" | tail -10 | sed 's/^/    /'
  [[ -t 0 ]] && read -rp "$(echo -e "${B}Нажмите Enter${N}")" _ || true
  return 1
}

cert_multi_issue() {
  cert_mode_load >/dev/null 2>&1 || true

  # ── Режим A: одна линия ──
  if [[ "${CERT_MODE:-A}" == "A" ]]; then
    cert_multi_name_resolve || { err "cert_multi_issue: домен панели неизвестен"; return 1; }
    cert_domains_add "$CERT_MULTI_NAME"
    cert_domains_load
    [[ ${#CERT_DOMAINS[@]} -eq 0 ]] && return 0
    local -a _final=("$CERT_MULTI_NAME") _x
    for _x in "${CERT_DOMAINS[@]}"; do
      [[ "$_x" == "$CERT_MULTI_NAME" ]] && continue
      _final+=("$_x")
    done
    CERT_DOMAINS=("${_final[@]}")
    cert_domains_save
    cert_issue_line "$CERT_MULTI_NAME"
    return $?
  fi

  # ── Режим B: обход всех линий ──
  local pd=""
  pd=$(xui_get webDomain 2>/dev/null || true)
  [[ -z "$pd" || "$pd" == "null" ]] && pd="${PANEL_DOMAIN:-}"
  if [[ -n "$pd" ]]; then
    cert_lines_add "$pd"
    cert_line_domains_add "$pd" "$pd"
  fi
  cert_lines_load
  [[ ${#CERT_LINES[@]} -eq 0 ]] && { warn "cert_multi_issue: нет линий"; return 0; }
  local rc=0 ln
  for ln in "${CERT_LINES[@]}"; do
    cert_issue_line "$ln" || rc=1
  done
  return $rc
}

# Идемпотентный выпуск: если SAN мультисерта совпадает с файлом доменов и
# срок > 30 дн — ничего не делает. Безопасно звать в конце любой операции.
# Синхронизация: пройтись по SNI-карте и добавить пропущенные домены
# в stack-domains.txt / в линии. Нужно, если инбаунд был привязан к SNI
# напрямую (минуя cert_domains_add) — тогда домен есть в карте, но не в списке.
# Безопасно: чужие цели (REALITY_TARGETS), panel_backend и agh_backend не трогаем.
cert_domains_sync_from_sni() {
  [[ -f "$SNI_CONF" ]] || return 0
  cert_mode_load >/dev/null 2>&1 || true

  # Собираем домены из map-блока с их backend
  local -a rows=()
  local ln
  while IFS= read -r ln; do
    [[ -z "$ln" ]] && continue
    rows+=("$ln")
  done < <(awk '
    /^map / { inmap=1; next }
    inmap && /^}/ { inmap=0 }
    inmap && /^[[:space:]]/ && NF >= 2 {
      dom = $1; sub(/;$/, "", dom); be = $2; sub(/;$/, "", be)
      if (dom != "" && dom != "default") print dom "|" be
    }
  ' "$SNI_CONF")

  [[ ${#rows[@]} -eq 0 ]] && return 0

  local -a added=()
  local row dom be t skip is_target
  for row in "${rows[@]}"; do
    IFS='|' read -r dom be <<<"$row"
    [[ -z "$dom" ]] && continue
    # пропускаем служебные backend'ы
    case "$be" in
      panel_backend|agh_backend) continue ;;
    esac
    # пропускаем чужие цели reality
    is_target=0
    for t in "${REALITY_TARGETS[@]}"; do
      [[ "$dom" == "$t" ]] && { is_target=1; break; }
    done
    [[ "$is_target" == "1" ]] && continue
    # CDN-фронт (домен, привязанный к внешнему CDN) в SAN не попадает: серт ему
    # не выдаётся, TLS терминирует CDN. ORIGIN тоже в карте (cdn_frontend) и
    # добавляется как обычный домен — он наш.
    cdn_front_domain_is "$dom" && continue
    # уже в списке?
    if [[ "${CERT_MODE:-A}" == "A" ]]; then
      cert_domains_load
      [[ " ${CERT_DOMAINS[*]} " == *" $dom "* ]] && continue
      cert_domains_add "$dom"
    else
      # режим B: проверяем в правильной линии
      local _line=""
      _line=$(cert_line_for "$dom")
      [[ -z "$_line" ]] && continue
      cert_line_domains_load "$_line"
      [[ " ${CERT_LINE_DOMAINS[*]} " == *" $dom "* ]] && continue
      cert_line_domains_add "$_line" "$dom"
    fi
    added+=("$dom")
  done

  if [[ ${#added[@]} -gt 0 ]]; then
    log "cert-domains-sync: добавлены в список: ${added[*]}"
  fi
  return 0
}

# Есть ли в SAN (строка «DNS:a,DNS:b», без пробелов) домен CDN-фронта
cert_san_has_cdn_front() {   # <cur_san>
  local san="${1:-}" d
  [[ -n "$san" ]] || return 1
  while IFS= read -r d; do
    [[ -n "$d" ]] || continue
    case ",$san," in *",$d,"*) return 0 ;; esac
  done < <(cdn_front_domains)
  return 1
}

# Убрать CDN-фронты из списков SAN: они не наши (TLS терминирует CDN), а в серт
# попадали автоматически через SNI-карту.
cert_drop_cdn_fronts() {
  cert_mode_load >/dev/null 2>&1 || true
  local d _line
  while IFS= read -r d; do
    [[ -n "$d" ]] || continue
    if [[ "${CERT_MODE:-A}" == "B" ]]; then
      _line=$(cert_line_for "$d" 2>/dev/null || true)
      [[ -n "$_line" ]] || continue
      cert_line_domains_load "$_line"
      [[ " ${CERT_LINE_DOMAINS[*]} " == *" $d "* ]] || continue
    else
      cert_domains_load
      [[ " ${CERT_DOMAINS[*]} " == *" $d "* ]] || continue
    fi
    cert_domains_remove "$d"
    log "  CDN-домен $d исключён из SAN (серт выдаёт CDN, не мы)"
  done < <(cdn_front_domains)
}

# Идемпотентная пересборка сертов.
#   • Режим A — одна линия (имя = домен панели).
#   • Режим B — обход всех линий (главная + доп. all.<base>).
#   • Если SAN совпадает и срок > 30 дн — перевыпуск не запускается.
#   • Выводит состояние каждой линии.
# Покрывает ли SAN серта ($1) все перечисленные домены — точно или wildcard *.база.
# Защита от перезатирания wildcard-серта SAN-перевыпуском (п.10.9/самолечение).
cert_san_set_covers() {
  local certf="$1"; shift
  local san dom
  [[ -f "$certf" ]] || return 1
  san=$(openssl x509 -noout -ext subjectAltName -in "$certf" 2>/dev/null \
        | grep -oE 'DNS:[^,]+' | sed 's/DNS://g' | tr -d ' ')
  [[ -n "$san" ]] || return 1
  for dom in "$@"; do
    grep -qx "$dom" <<<"$san" && continue
    local base="${dom#*.}"
    if [[ "$dom" == *.* && "$dom" != "$base" ]] && grep -qx "*.$base" <<<"$san"; then
      continue
    fi
    return 1
  done
  return 0
}

cert_batch_flush() {
  cert_mode_load >/dev/null 2>&1 || true
  # Перед перевыпуском — синхронизировать список с SNI-картой (могут быть
  # пропущенные домены, если инбаунд когда-то был привязан к SNI напрямую).
  cert_domains_sync_from_sni >/dev/null 2>&1 || true
  # CDN-фронты (cdn.*) в SAN не нужны: серт на них не выдаётся, TLS терминирует
  # CDN. Если они там остались от прежних версий — выкидываем из списка; если
  # из-за этого SAN изменился, cert_issue_line перевыпустит линию без них.
  cert_drop_cdn_fronts || true

  # ── Режим A ──
  if [[ "${CERT_MODE:-A}" == "A" ]]; then
    cert_multi_name_resolve || { warn "cert_batch_flush: домен панели неизвестен"; return 0; }
    cert_domains_load
    if [[ ${#CERT_DOMAINS[@]} -eq 0 ]]; then
      warn "Список доменов (stack-domains.txt) пуст — перевыпуск не требуется"
      return 0
    fi
    local ldir="/etc/letsencrypt/live/$CERT_MULTI_NAME"
    if [[ -f "$ldir/fullchain.pem" ]]; then
      local cur_san want_san left
      cur_san=$(openssl x509 -noout -ext subjectAltName -in "$ldir/fullchain.pem" 2>/dev/null \
                | grep -oE 'DNS:[^,]+' | sed 's/DNS://g' | tr -d ' ' | sort | tr '\n' ',')
      want_san=$(printf '%s\n' "${CERT_DOMAINS[@]}" | sort -u | tr '\n' ',')
      if [[ "${cur_san%,}" == "${want_san%,}" ]]; then
        left=$(( ($(date -d "$(openssl x509 -enddate -noout -in "$ldir/fullchain.pem" 2>/dev/null | cut -d= -f2)" +%s 2>/dev/null || echo 0) - $(date +%s)) / 86400 ))
        if (( left > 30 )); then
          log "Линия «$CERT_MULTI_NAME» актуальна: ${#CERT_DOMAINS[@]} дом., ~$left дн — перевыпуск не нужен"
          echo "      SAN: ${cur_san%,}"
          return 0
        fi
        warn "Линия «$CERT_MULTI_NAME»: срок ~$left дн (<=30) — обновляю"
      else
        if cert_san_has_cdn_front "$cur_san"; then
          warn "Линия «$CERT_MULTI_NAME»: в SAN есть CDN-домен (TLS терминирует CDN) — перевыпускаю без него"
        elif cert_san_set_covers "$ldir/fullchain.pem" "${CERT_DOMAINS[@]}"; then
          left=$(( ($(date -d "$(openssl x509 -enddate -noout -in "$ldir/fullchain.pem" 2>/dev/null | cut -d= -f2)" +%s 2>/dev/null || echo 0) - $(date +%s)) / 86400 ))
          if (( left > 30 )); then
            log "Линия «$CERT_MULTI_NAME» полностью покрыта текущим сертом (wildcard/SAN), ~$left дн — перевыпуск не нужен"
            echo "      SAN серта: ${cur_san%,}"
            return 0
          fi
        fi
        warn "Линия «$CERT_MULTI_NAME»: SAN изменился"
        echo "      было:  ${cur_san%,}"
        echo "      стало: ${want_san%,}"
      fi
    else
      log "Линия «$CERT_MULTI_NAME»: серта нет — выпускаю"
      echo "      SAN: $(printf '%s\\n' "${CERT_DOMAINS[@]}" | sort -u | tr '\\n' ',')"
    fi
    cert_multi_issue
    return $?
  fi

  # ── Режим B: обход линий ──
  local pd=""
  pd=$(xui_get webDomain 2>/dev/null || true)
  [[ -z "$pd" || "$pd" == "null" ]] && pd="${PANEL_DOMAIN:-}"
  if [[ -n "$pd" ]]; then
    cert_lines_add "$pd"
    cert_line_domains_add "$pd" "$pd"
  fi
  cert_lines_load
  if [[ ${#CERT_LINES[@]} -eq 0 ]]; then
    warn "cert_batch_flush: нет линий (режим B)"
    return 0
  fi
  log "Режим B: линий — ${#CERT_LINES[@]}"
  local rc=0 ln d
  for ln in "${CERT_LINES[@]}"; do
    cert_line_domains_load "$ln"
    if [[ ${#CERT_LINE_DOMAINS[@]} -eq 0 ]]; then
      warn "  Линия «$ln» пуста — пропуск"
      continue
    fi
    cert_issue_line "$ln" || rc=1
  done
  return $rc
}

# Просмотр: список доменов + сведения о сертах
certs_view() {
  cert_mode_load >/dev/null 2>&1 || true
  cert_multi_name_resolve >/dev/null 2>&1 || true
  line; echo -e "${B}   СЕРТИФИКАТЫ — ОБЗОР${N}"; line
  if [[ "${CERT_MODE:-A}" == "B" ]]; then
    echo "  Режим: B — отдельные линии сертификатов по базовым доменам"
    echo -e "${B}▸ Фактические линии и их сертификаты:${N}"
    cert_lines_load >/dev/null 2>&1 || true
    if [[ ${#CERT_LINES[@]} -gt 0 ]]; then
      local _ln _i=1 _d
      for _ln in "${CERT_LINES[@]}"; do
        echo "  Линия $_i: $_ln"
        cert_line_domains_load "$_ln" >/dev/null 2>&1 || true
        if [[ ${#CERT_LINE_DOMAINS[@]} -eq 0 ]]; then
          echo "      (список доменов пуст)"
        else
          for _d in "${CERT_LINE_DOMAINS[@]}"; do
            [[ -n "$_d" ]] && echo "      - $_d"
          done
        fi
        if [[ -f "/etc/letsencrypt/live/$_ln/fullchain.pem" ]]; then
          echo "      Сертификат: установлен"
        else
          echo "      Сертификат: не выпущен"
        fi
        _i=$((_i+1))
      done
    else
      echo "  (линии ещё не сформированы)"
    fi
  else
    echo "  Режим: A — одна SAN-линия"
    echo "  Имя линии (= домен панели): ${CERT_MULTI_NAME:-<домен панели не задан>}"
    echo -e "${B}▸ Домены в SAN-списке ($CERT_DOMAINS_FILE):${N}"
    if [[ -s "$CERT_DOMAINS_FILE" ]]; then
      local i=1 d
      while IFS= read -r d; do
        d="$(printf '%s' "$d" | tr -d '[:space:]')"
        [[ -z "$d" ]] && continue
        printf "  %2d) %s\n" "$i" "$d"; i=$((i+1))
      done < "$CERT_DOMAINS_FILE"
    else
      echo "  (список SAN ещё не создан)"
    fi
  fi
  echo
  local ldir="/etc/letsencrypt/live/$CERT_MULTI_NAME"
  if [[ -f "$ldir/fullchain.pem" ]]; then
    echo -e "${B}▸ Сертификат панели / мультисерт «$CERT_MULTI_NAME»:${N}"
    echo "  Путь:  $ldir"
    local subj end left
    subj=$(openssl x509 -noout -subject -in "$ldir/fullchain.pem" 2>/dev/null | sed 's/^subject= *//')
    end=$(openssl x509 -noout -enddate -in "$ldir/fullchain.pem" 2>/dev/null | cut -d= -f2)
    left=$(( ($(date -d "$end" +%s 2>/dev/null || echo 0) - $(date +%s)) / 86400 ))
    echo "  Subject: $subj"
    echo "  Истекает: $end (~$left дн)"
    echo "  SAN:"
    openssl x509 -noout -ext subjectAltName -in "$ldir/fullchain.pem" 2>/dev/null \
      | tail -n +2 | tr ',' '\n' | sed 's/^ */    /' || true
  else
    echo -e "${B}▸ Мультисерт $CERT_MULTI_NAME:${N}  НЕ выпущен"
  fi
  echo
  echo -e "${B}▸ Все сертификаты в /etc/letsencrypt/live/:${N}"
  certbot certificates 2>/dev/null | sed 's/^/  /' || true
  echo
  le_email_load || true
  echo -e "${B}▸ Email Let's Encrypt:${N} ${EMAIL:-<не задан>}   (файл: $LE_EMAIL_FILE)"
  pause
}

cert_issue() {
  local d="$1"
  # невидимый хвост (пробел/CR из БД или ans-файла) ломает пути live/<домен> —
  # certbot нормализует имя, скрипт ищет файлы по «грязному» пути и не находит
  d="$(printf '%s' "$d" | tr -d '[:space:]')"
  # ЖЁСТКИЙ ЗАПРЕТ: цели чужого reality — НЕ наши домены. Let's Encrypt серт
  # на них не выдаст (HTTP-01/DNS-01 недоступны), а спрашивать пользователя
  # «какой сертификат для www.samsung.com» — баг, какими бы путями домен
  # сюда ни приехал (утёкший serverNames из старой БД и т.п.).
  # Домен, привязанный к внешнему CDN, тоже не наш: TLS для CDN-фронта
  # завершается на стороне CDN, поэтому сертификат Let's Encrypt на него
  # выпускать нельзя. Сертификат нужен только для ORIGIN-домена.
  if cdn_front_domain_is "$d"; then
    warn "cert_issue: «$d» — CDN-домен, TLS завершает CDN; сертификат не выпускается"
    return 1
  fi
  local _rt_x
  for _rt_x in "${REALITY_TARGETS[@]}"; do
    if [[ "$d" == "$_rt_x" ]]; then
      warn "cert_issue: «$d» — цель чужого reality, серт не нужен и невозможен (пропускаю)"
      return 1
    fi
  done

  local dir="/etc/letsencrypt/live/$d" arch="/etc/letsencrypt/archive/$d"

  # self-heal: флаг wildcard мог не загрузиться (source без точки входа)
  if [[ -z "$WILDCARD_DOMAIN" && -f "$WILDCARD_STATE" ]]; then
    WILDCARD_DOMAIN=$(head -n 1 "$WILDCARD_STATE" 2>/dev/null | tr -d '[:space:]' || true)
  fi

  local in_wc_zone=false
  [[ -n "$WILDCARD_DOMAIN" && ( "$d" == "$WILDCARD_DOMAIN" || "$d" == *."$WILDCARD_DOMAIN" ) ]] && in_wc_zone=true

  # email обязателен: пустой --email меняет параметры аккаунта — certbot не
  # переиспользует существующую линию и плодит дубли (-0001, -0002…)
  # ВАЖНО: базу отрезаем только если остаётся ещё точка — иначе для домена
  # вида zone.ru (две метки) получаем admin@ru и отказ ACME-сервера.
  le_email_load || true
  if [[ -z "$EMAIL" && -t 0 ]]; then
    ask EMAIL "Email для Let's Encrypt" "" '^[^@]+@[^@]+\.[^@]+$'
    le_email_save "$EMAIL"
  fi
  [[ -n "$EMAIL" ]] || { err "  cert $d: email Let's Encrypt не задан — укажи EMAIL или задай его в разделе сертификатов"; return 1; }
  le_email_save "$EMAIL" || true

  # --- проверка: сертификат уже установлен → переустанавливать не нужно ---
  if [[ "$in_wc_zone" == true ]]; then
    local wdir="/etc/letsencrypt/live/$WILDCARD_DOMAIN"
    if [[ -f "$wdir/fullchain.pem" && -f "$wdir/privkey.pem" ]]; then
      log "  cert $d: уже есть wildcard *.$WILDCARD_DOMAIN — используется он"
      return 0
    fi
  fi
  # --- авто-поиск установленного сертификата по SAN (работает даже без флага wildcard) ---
  # Делать его ДО проверки персональной линии: wildcard должен иметь приоритет
  # для поддоменов, даже если ранее по ошибке уже выпустили персональный cert.
  local hit wcdir wcbase
  hit=$(find_covering_cert "$d") || hit=""
  if [[ -n "$hit" ]]; then
    wcdir="${hit%%|*}"; wcbase="${hit#*|}"
    log "  cert $d: найден установленный сертификат «$(basename "$wcdir")» — используется он"
    cert_mirror_to_certroot "$wcdir" "$d" >/dev/null 2>&1 || true
    if [[ -n "$wcbase" ]]; then
      echo "$wcbase" > "$WILDCARD_STATE" 2>/dev/null || true
      WILDCARD_DOMAIN="$wcbase"
      log "  флаг wildcard восстановлен: *.$wcbase"
    fi
    return 0
  fi
  if [[ -f "$dir/fullchain.pem" && -f "$dir/privkey.pem" ]]; then
    log "  cert $d уже установлен — переустановка не нужна"
    return 0
  fi

  # --- восстановление из archive/ (если live-ссылки потеряны) ---
  if [[ -d "$arch" ]]; then
    log "  cert $d: восстановление из archive/"
    mkdir -p "$dir" 2>/dev/null || true
    local n=""
    n=$(ls -1 "$arch"/fullchain*.pem 2>/dev/null | sed -E 's/.*fullchain([0-9]+)\.pem/\1/' | sort -n | tail -1 || true)
    if [[ -n "$n" ]]; then
      local f
      for f in cert chain fullchain privkey; do
        [[ -f "$arch/$f$n.pem" ]] && ln -sf "../../archive/$d/$f$n.pem" "$dir/$f.pem"
      done
      chmod 700 "$dir" 2>/dev/null || true
      if [[ -f "$dir/fullchain.pem" && -f "$dir/privkey.pem" ]]; then
        log "  восстановлен (v$n)"
        # пути — live/ (единое место)
        cert_mirror_to_certroot "$dir" "$d" >/dev/null 2>&1 || true
        return 0
      fi
    fi
  fi

  # --- выпуск: выбор типа сертификата ---
  # CERT_MODE_CHOICE — выбор запоминается на сессию (1 вопрос на установку,
  # а не на каждый инбаунд). В ans-автоустановках (stdin не TTY) вопрос
  # не задаётся — режим уже выбран вопросом 2b.
  local mode="personal"
  local wbase="${d#*.}"
  [[ "$wbase" != *.* ]] && wbase="$d"   # d — сам базовый домен
  if [[ -n "${CERT_MODE_CHOICE:-}" ]]; then
    mode="$CERT_MODE_CHOICE"
  elif [[ "$name" == "VLESS XHTTP TLS" ]]; then
          # Явный TLS-пункт: CDN не спрашиваем и security сохраняем как tls.
          security="tls"
          INBOUND_CREATE_MODE="tls"
          _is_cdn=false
        elif [[ -t 0 && "$security" != "tls" ]]; then
    echo "  Какой сертификат выпустить для $d?"
    echo "   1) Wildcard *.$wbase — Cloudflare DNS-01, покроет $wbase и все поддомены"
    echo "   2) Обычный персональный — только $d (HTTP-01)"
    local cm=""
    ask cm "Выбор [1/2]" "2" '^[12]$'
    if [[ "$cm" == "1" ]]; then
      mode="wildcard"
      CERT_MODE_CHOICE="wildcard"
    else
      CERT_MODE_CHOICE="personal"
    fi
  fi

  if [[ "$mode" == "wildcard" ]]; then
    if cert_wildcard_issue "${WILDCARD_DOMAIN:-$wbase}"; then
      log "  cert $d: используется wildcard *.${WILDCARD_DOMAIN:-$wbase}"
      return 0
    fi
    err "  ОШИБКА: wildcard для $d не установлен. Нажмите Enter для продолжения."
    cert_error_pause
    warn "  wildcard НЕ выпущен (токен Cloudflare / DNS-01?) — для $d выпускаю персональный"
    warn "  ВАЖНО: остальные серты этой установки тоже пойдут персональными (фолбэк сессии)."
    warn "  Вернуть wildcard потом: меню сертификатов → Wildcard Cloudflare → включить,"
    warn "  затем перепривязать пути (п.10 — пересборка). Причина отказа выше в выводе."
    CERT_MODE_CHOICE="personal"
  fi

  # DNS-проверка (dual-stack): A-запись сверяется с IPv4 сервера, AAAA — с IPv6.
  # Совпадение ЛЮБОЙ пары = OK (ложный mismatch раньше был из-за IPv6-ответа ifconfig.me).
  local nA nAAAA
  nA=$(dig +short A "$d" @8.8.8.8 2>/dev/null | grep -cE '^[0-9]+(\.[0-9]+){3}$' || true)
  nAAAA=$(dig +short AAAA "$d" @8.8.8.8 2>/dev/null | grep -c ':' || true)
  [[ "${nA:-0}" -eq 0 && "${nAAAA:-0}" -eq 0 ]] && { err "  $d не резолвится"; return 1; }

  local ip4_server="" ip6_server="" dns_ok=false
  ip4_server=$(curl -4 -s --max-time 5 ifconfig.me 2>/dev/null | tr -d '[:space:]' || true)
  ip6_server=$(curl -6 -s --max-time 5 ifconfig.me 2>/dev/null | tr -d '[:space:]' || true)
  if [[ -z "$ip4_server" && -z "$ip6_server" ]]; then
    warn "  не удалось определить IP сервера — DNS-проверка пропущена"
  else
    if [[ -n "$ip4_server" ]] && dig +short A "$d" @8.8.8.8 2>/dev/null | grep -Fqx -- "$ip4_server"; then
      dns_ok=true
    fi
    if [[ "$dns_ok" != true && -n "$ip6_server" ]] && dig +short AAAA "$d" @8.8.8.8 2>/dev/null | grep -Fxi -- "$ip6_server"; then
      dns_ok=true
    fi
    if [[ "$dns_ok" != true ]]; then
      warn "  DNS mismatch: $d"
      warn "    A ($nA):    $(dig +short A "$d" @8.8.8.8 2>/dev/null | tr '\n' ' ')"
      warn "    AAAA:      $(dig +short AAAA "$d" @8.8.8.8 2>/dev/null | tr '\n' ' ')"
      warn "    сервер v4: $ip4_server"
      warn "    сервер v6: $ip6_server"
      local continue_anyway
      askyn continue_anyway "Продолжить выпуск несмотря на DNS?" "n"
      [[ "$continue_anyway" == true ]] || return 1
    fi
  fi

  log "  выпуск cert для $d..."
  local out="" nginx_was_active=false
  systemctl is-active --quiet nginx 2>/dev/null && nginx_was_active=true
  # 80 закрыт UFW (наш принцип) — но ACME-сервер стучится снаружи. Открываем
  # временно и закрываем после выпуска (standalone И webroot оба требуют :80 извне).
  local ufw_80_temp=false
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
    if ! ufw status 2>/dev/null | grep -qE "^80/tcp[[:space:]]+ALLOW"; then
      ufw allow 80/tcp comment "acme-temp" >/dev/null 2>&1 || true
      ufw_80_temp=true
      log "  UFW: 80/tcp временно открыт для ACME"
    fi
  fi
  mkdir -p /var/www/html 2>/dev/null || true

  if [[ "$nginx_was_active" == true ]]; then
    # nginx держит :80 — используем webroot (ACME-сервер :80 в stack.conf отдаёт /.well-known/acme-challenge/)
    # --keep-until-expiring: если валидный серт с этими доменами уже есть —
    # certbot обязан переиспользовать линию, а не создавать копию -0001
    out=$(certbot certonly --webroot -w /var/www/html --non-interactive --agree-tos --keep-until-expiring --email "$EMAIL" --cert-name "$d" -d "$d" 2>&1 || true)
    if [[ ! -f "$dir/fullchain.pem" || ! -f "$dir/privkey.pem" ]]; then
      warn "  webroot не сработал, пробуем standalone (nginx кратко остановим)"
      systemctl stop nginx 2>/dev/null || true
      out="$out
$(certbot certonly --standalone --non-interactive --agree-tos --keep-until-expiring --email "$EMAIL" --cert-name "$d" -d "$d" 2>&1 || true)"
      systemctl start nginx 2>/dev/null || true
    fi
  else
    out=$(certbot certonly --standalone --non-interactive --agree-tos --keep-until-expiring --email "$EMAIL" --cert-name "$d" -d "$d" 2>&1 || true)
  fi
  if [[ "$ufw_80_temp" == true ]]; then
    ufw delete allow 80/tcp >/dev/null 2>&1 || true
    log "  UFW: 80/tcp закрыт обратно"
  fi
  # certbot мог создать линию с суффиксом (-0001…) — подхватываем фактическую
  if [[ ! -f "$dir/fullchain.pem" || ! -f "$dir/privkey.pem" ]]; then
    local alt=""
    alt=$(ls -d /etc/letsencrypt/live/"$d"-* 2>/dev/null | sort | tail -1 || true)
    if [[ -n "$alt" && -f "$alt/fullchain.pem" && -f "$alt/privkey.pem" ]]; then
      dir="$alt"
      warn "  certbot создал линию с суффиксом: $(basename "$alt") — использую её"
    fi
  fi
  # «not yet due for renewal» = серт УЖЕ существует и валиден (certbot сам
  # проверил) — это УСПЕХ, а не отказ: берём фактическую линию и зеркалим.
  if grep -q "not yet due for renewal" <<<"$out"; then
    if [[ ! -f "$dir/fullchain.pem" ]]; then
      local alt2
      alt2=$(ls -d /etc/letsencrypt/live/"$d"-* 2>/dev/null | sort | tail -1 || true)
      [[ -n "$alt2" ]] && dir="$alt2"
    fi
    if [[ -f "$dir/fullchain.pem" && -f "$dir/privkey.pem" ]]; then
      log "  cert $d: уже действует (certbot: not yet due for renewal) — переустановка не нужна"
      local mline0=""
      mline0=$(cert_mirror_to_certroot "$dir" "$d" 2>/dev/null || true)
      [[ -n "$mline0" ]] && log "  OK (live: /etc/letsencrypt/live/$d/)" || log "  OK"
      return 0
    fi
  fi
  [[ -f "$dir/fullchain.pem" && -f "$dir/privkey.pem" ]] || {
    err "  certbot отказал для $d:"
    echo "$out" | tail -8 | sed 's/^/    /'
    local rl
    rl=$(echo "$out" | grep -oE "retry after [0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} UTC" | head -1 || true)
    [[ -n "$rl" ]] && err "  ЛИМИТ LET'S ENCRYPT (5 сертов/168ч): повторить после $rl — это НЕ баг скрипта"
    err "  ИТОГ: серт $d НЕ выпущен — инбаунд с этим доменом не поднимется"
    cert_error_pause
    return 1
  }

  # пути — live/ (единое место)
  local mline=""
  mline=$(cert_mirror_to_certroot "$dir" "$d" 2>/dev/null || true)
  [[ -n "$mline" ]] && log "  OK (live: /etc/letsencrypt/live/$d/)" || log "  OK"
  return 0
}

# =====================================================================
