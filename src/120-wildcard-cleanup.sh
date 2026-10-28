# WILDCART СЕРТИФИКАТ CLOUDFLARE (DNS-01, один на все поддомены)
# =====================================================================
# Поиск УСТАНОВЛЕННОГО сертификата, покрывающего домен, по SAN всех live-сертификатов.
# Не зависит от флага WILDCARD_STATE. Печатает: "<live-dir>|<wcbase>" (wcbase пуст, если совпадение точное).
find_covering_cert() {
  local d="$1" ldir san entry base wcbase
  for ldir in /etc/letsencrypt/live/*/; do
    [[ -f "${ldir}fullchain.pem" && -f "${ldir}privkey.pem" ]] || continue
    san=$(openssl x509 -noout -ext subjectAltName -in "${ldir}cert.pem" 2>/dev/null | tail -n +2 | tr -d ' ' || true)
    [[ "$san" != *DNS:* ]] && continue
    wcbase=""
    while IFS= read -r entry; do
      entry="${entry#DNS:}"
      [[ -z "$entry" ]] && continue
      if [[ "$entry" == "$d" ]]; then
        echo "${ldir%/}|$wcbase"; return 0
      fi
      if [[ "$entry" == \** ]]; then
        base="${entry#\*.}"
        if [[ "$d" == *."$base" || "$d" == "$base" ]]; then
          wcbase="$base"
          echo "${ldir%/}|$wcbase"; return 0
        fi
      fi
    done < <(tr ',\n' '\n\n' <<<"$san")
  done
  return 1
}

# Свежий (>30 дн) установленный сертификат, покрывающий домен, — для пропуска
# избыточных персональных выпусков при живом wildcard/SAN. Печатает hit
# find_covering_cert ("<live-dir>|<wcbase>"); 1 — если ничего свежего нет.
cert_fresh_cover() {
  local d="$1" hit dir
  hit=$(find_covering_cert "$d") || return 1
  dir="${hit%%|*}"
  openssl x509 -noout -checkend 2592000 -in "$dir/cert.pem" >/dev/null 2>&1 || return 1
  printf '%s' "$hit"
  return 0
}

# Печатает "fullchain privkey" для домена: wildcard (если покрывает) → персональный
cert_paths() {
  local d="$1"
  # self-heal: флаг wildcard мог не загрузиться (например, при source без точки входа)
  if [[ -z "$WILDCARD_DOMAIN" && -f "$WILDCARD_STATE" ]]; then
    WILDCARD_DOMAIN=$(head -n 1 "$WILDCARD_STATE" 2>/dev/null | tr -d '[:space:]' || true)
  fi
  if [[ -n "$WILDCARD_DOMAIN" && ( "$d" == "$WILDCARD_DOMAIN" || "$d" == *."$WILDCARD_DOMAIN" ) ]]; then
    local wd="/etc/letsencrypt/live/$WILDCARD_DOMAIN"
    [[ -f "$wd/fullchain.pem" && -f "$wd/privkey.pem" ]] && { echo "$wd/fullchain.pem $wd/privkey.pem"; return 0; }
  fi
  local pd="/etc/letsencrypt/live/$d"
  [[ -f "$pd/fullchain.pem" && -f "$pd/privkey.pem" ]] && { echo "$pd/fullchain.pem $pd/privkey.pem"; return 0; }
  # флаг потерян — ищем покрывающий сертификат по SAN
  local hit wcdir
  hit=$(find_covering_cert "$d") || return 1
  wcdir="${hit%%|*}"
  echo "$wcdir/fullchain.pem $wcdir/privkey.pem"
  return 0
}

# Строгая проверка сертификата и ключа для конкретного hostname.
# Возвращает 0 только если сертификат существует, не истёк, покрывает домен
# и соответствует приватному ключу.
cert_preflight() {
  local d="$1" pair cert key san_end
  [[ "$d" =~ ^[A-Za-z0-9.-]+$ ]] || return 1
  pair=$(cert_paths "$d" 2>/dev/null) || return 1
  cert="${pair%% *}"; key="${pair##* }"
  [[ -s "$cert" && -s "$key" ]] || return 1
  openssl x509 -noout -checkend 86400 -in "$cert" >/dev/null 2>&1 || return 1
  # Не разбираем текст checkhost: в разных версиях OpenSSL успешный вывод
  # отличается ("was found" или "does match"). Код возврата — стабильный API.
  openssl x509 -noout -checkhost "$d" -in "$cert" >/dev/null 2>&1 || return 1
  # Поддерживаем RSA и ECDSA: сравниваем DER публичных ключей, а не modulus.
  local cert_pub key_pub
  cert_pub=$(openssl x509 -in "$cert" -pubkey -noout 2>/dev/null | openssl pkey -pubin -outform DER 2>/dev/null | sha256sum | cut -d' ' -f1)
  key_pub=$(openssl pkey -in "$key" -pubout -outform DER 2>/dev/null | sha256sum | cut -d' ' -f1)
  [[ -n "$cert_pub" && "$cert_pub" != "$(printf '0%.0s' {1..64})" && "$cert_pub" == "$key_pub" ]] || return 1
  printf '%s %s\n' "$cert" "$key"
}

# --- МУЛЬТИСЕРТ (SAN): один серт на несколько доменов (в т.ч. РАЗНЫХ зон) ---
# Сосуществует с wildcard: cert_paths/find_covering_cert сами выберут wildcard
# для его зоны, а для остальных доменов найдут SAN в линии stack-multi.
# cert_issue при виде домена из списка тоже переиспользует SAN (find_covering_cert).
# Добавить домен в мультисписок вручную
certs_domain_add_manual() {
  cert_mode_load >/dev/null 2>&1 || true
  local newd="" _line=""
  ask newd "Домен для добавления" "" '^[a-zA-Z0-9.-]+$'
  [[ -z "$newd" ]] && { warn "Отменено"; return 0; }
  if [[ "${CERT_MODE:-A}" == "B" ]]; then
    _line=$(cert_line_for "$newd") || true
    [[ -z "$_line" ]] && { err "Не удалось определить линию сертификата для $newd"; pause; return 1; }
    cert_line_domains_load "$_line"
    [[ " ${CERT_LINE_DOMAINS[*]} " == *" $newd "* ]] && { log "Домен уже в линии $_line"; return 0; }
    cert_line_domains_add "$_line" "$newd"
    log "Добавлен в линию сертификата $_line: $newd"
  else
    cert_domains_load
    [[ " ${CERT_DOMAINS[*]} " == *" $newd "* ]] && { log "Домен $newd уже в списке"; return 0; }
    cert_domains_add "$newd" 1
    log "Добавлен в мультисписок: $newd"
  fi
  local r=""
  askyn r "Перевыпустить мультисерт сейчас?" "y"
  [[ "$r" == true ]] && { CERT_DEFER=0; cert_batch_flush; }
  pause
}

# Удалить домен из мультисписка вручную
certs_domain_remove_manual() {
  cert_mode_load >/dev/null 2>&1 || true
  if [[ "${CERT_MODE:-A}" == "B" ]]; then
    cert_lines_load
    local _all=() _ln _d
    for _ln in "${CERT_LINES[@]}"; do
      cert_line_domains_load "$_ln"
      for _d in "${CERT_LINE_DOMAINS[@]}"; do _all+=("$_ln|$_d"); done
    done
    [[ ${#_all[@]} -eq 0 ]] && { warn "Линии сертификатов пусты"; pause; return 0; }
    echo; echo "Домены линий сертификатов:"
    local i=1 d
    for d in "${_all[@]}"; do printf "  %2d) %s (линия %s)\n" "$i" "${d#*|}" "${d%%|*}"; i=$((i+1)); done
    local pick=""; ask pick "Номер для удаления (0 — отмена)" "0" '^[0-9]+$'
    [[ "$pick" == "0" ]] && return 0
    (( pick < 1 || pick > ${#_all[@]} )) && { err "Нет такого номера"; pause; return 1; }
    local target="${_all[$((pick-1))]}"; cert_line_domains_remove "${target%%|*}" "${target#*|}"
    log "Удалён из линии ${target%%|*}: ${target#*|}"; pause; return 0
  fi
  cert_domains_load
  cert_multi_name_resolve >/dev/null 2>&1 || true
  [[ ${#CERT_DOMAINS[@]} -eq 0 ]] && { warn "Мультисписок пуст"; pause; return 0; }
  echo
  echo "Домены в мультисписке:"
  local i=1 d
  for d in "${CERT_DOMAINS[@]}"; do
    local mark=""
    [[ -n "$CERT_MULTI_NAME" && "$d" == "$CERT_MULTI_NAME" ]] && mark=" [домен панели — удалять нельзя]"
    printf "  %2d) %s%s\n" "$i" "$d" "$mark"
    i=$((i+1))
  done
  echo
  local pick=""
  ask pick "Номер для удаления (0 — отмена)" "0" '^[0-9]+$'
  [[ "$pick" == "0" ]] && return 0
  (( pick < 1 || pick > ${#CERT_DOMAINS[@]} )) && { err "Нет такого номера"; pause; return 1; }
  local target="${CERT_DOMAINS[$((pick-1))]}"
  if [[ -n "$CERT_MULTI_NAME" && "$target" == "$CERT_MULTI_NAME" ]]; then
    err "Это домен панели (CN серта) — удалить нельзя. Смени домен панели в п.1."
    pause; return 1
  fi
  cert_domains_remove "$target"
  log "Удалён из мультисписка: $target"
  local r=""
  askyn r "Перевыпустить мультисерт сейчас (без удалённого домена)?" "y"
  [[ "$r" == true ]] && { CERT_DEFER=0; cert_batch_flush; }
  pause
}


# =====================================================================
# ОЧИСТКА СИРОТ И ДУБЛЕЙ СЕРТОВ
# =====================================================================

# Возвращает список «известных» линий (для проверки, что линия в live/
# действительно нужна). Печатает по строке.
cert_known_lines() {
  cert_mode_load >/dev/null 2>&1 || true
  # Главная линия (домен панели)
  local pd=""
  pd=$(xui_get webDomain 2>/dev/null || true)
  [[ -z "$pd" || "$pd" == "null" ]] && pd="${PANEL_DOMAIN:-}"
  [[ -n "$pd" ]] && echo "$pd"
  # Линии из cert-lines.txt (режим B)
  if [[ -f "$CERT_LINES_FILE" ]]; then
    local l
    while IFS= read -r l; do
      l="$(printf '%s' "$l" | tr -d '[:space:]')"
      [[ -n "$l" ]] && echo "$l"
    done < "$CERT_LINES_FILE"
  fi
  # Wildcard
  [[ -f "$WILDCARD_STATE" ]] && head -n1 "$WILDCARD_STATE" 2>/dev/null | tr -d '[:space:]'
}

# Проверяет, используется ли имя линии где-нибудь:
#   - в БД x-ui (webCertFile / subCertFile / в настройках инбаундов)
#   - в nginx (stack.conf, adguard-tls)
#   - в списке известных линий (cert_known_lines)
# Возвращает 0 если используется, иначе 1.
cert_line_is_used() {
  local name="$1"
  [[ -z "$name" ]] && return 1
  # Известные линии
  if cert_known_lines | grep -qxF "$name"; then
    return 0
  fi
  # БД x-ui
  if [[ -n "$XUI_DB" && -f "$XUI_DB" ]]; then
    local cnt
    cnt=$(sqlite3 -cmd ".timeout 3000" "$XUI_DB" \
      "SELECT COUNT(*) FROM settings WHERE value LIKE '%/live/$name/%';" 2>/dev/null || echo 0)
    [[ "$cnt" != "0" ]] && return 0
    cnt=$(sqlite3 -cmd ".timeout 3000" "$XUI_DB" \
      "SELECT COUNT(*) FROM inbounds WHERE settings LIKE '%/live/$name/%' OR stream_settings LIKE '%/live/$name/%';" 2>/dev/null || echo 0)
    [[ "$cnt" != "0" ]] && return 0
  fi
  # nginx
  if [[ -f "$STACK_CONF" ]] && grep -q "/live/$name/" "$STACK_CONF" 2>/dev/null; then
    return 0
  fi
  if [[ -f /opt/AdGuardHome/AdGuardHome.yaml ]] && grep -q "/live/$name/" /opt/AdGuardHome/AdGuardHome.yaml 2>/dev/null; then
    return 0
  fi
  return 1
}

# Очистка дублей -0001 / -0002.
# Если есть <base> и <base>-0001:
#   • Если <base> — живая линия (используется) → удаляем <base>-0001.
#   • Если <base> пустая (нет fullchain.pem или его symlink битый) → удаляем
#     <base>, переименовываем <base>-0001 в <base> (через certbot? нет —
#     через mv live/archive + правку renewal.conf).
#   • Если обе живые и не совпадают SAN — показать, не трогать.
cert_dedup_0001() {
  line; echo -e "${B}   ОЧИСТКА ДУБЛЕЙ -0001${N}"; line
  local -a suffix_lines=()
  local ld name base
  for ld in /etc/letsencrypt/live/*/; do
    [[ -d "$ld" ]] || continue
    name=$(basename "$ld")
    [[ "$name" =~ -[0-9]{4}$ ]] && suffix_lines+=("$name")
  done
  if [[ ${#suffix_lines[@]} -eq 0 ]]; then
    log "Дублей -0001 в live/ не найдено"
    pause; return 0
  fi
  echo "Найдены линии с суффиксом:"
  for name in "${suffix_lines[@]}"; do echo "  - $name"; done
  echo
  local did=0
  for name in "${suffix_lines[@]}"; do
    base="${name%-[0-9][0-9][0-9][0-9]}"
    local base_live="/etc/letsencrypt/live/$base"
    local suffix_live="/etc/letsencrypt/live/$name"

    # Случай 1: <base> не существует или пустая → переименовать <base>-NNNN в <base>
    if [[ ! -d "$base_live" ]] || [[ ! -f "$base_live/fullchain.pem" ]]; then
      echo "  ─ $name: базовая линия $base отсутствует → переименовываю"
      local sure=""
      askyn sure "Переименовать $name → $base?" "y"
      if [[ "$sure" == true ]]; then
        # Переименовать live/
        [[ -d "$base_live" ]] && rm -rf "$base_live"
        mv "$suffix_live" "$base_live" 2>/dev/null || true
        # Переименовать archive/
        [[ -d "/etc/letsencrypt/archive/$base" ]] && rm -rf "/etc/letsencrypt/archive/$base"
        [[ -d "/etc/letsencrypt/archive/$name" ]] && mv "/etc/letsencrypt/archive/$name" "/etc/letsencrypt/archive/$base" 2>/dev/null || true
        # Поправить renewal.conf
        local rf="/etc/letsencrypt/renewal/$name.conf"
        if [[ -f "$rf" ]]; then
          sed -i "s|/etc/letsencrypt/live/$name|/etc/letsencrypt/live/$base|g; s|/etc/letsencrypt/archive/$name|/etc/letsencrypt/archive/$base|g; s|cert = $name|cert = $base|; s|^archive_dir = .*$|archive_dir = /etc/letsencrypt/archive/$base|" "$rf" 2>/dev/null || true
          mv "$rf" "/etc/letsencrypt/renewal/$base.conf" 2>/dev/null || true
        fi
        log "    переименовано: $name → $base"
        did=$((did+1))
      fi
      continue
    fi

    # Случай 2: обе линии живые → сравнить SAN
    local san_base san_suffix
    san_base=$(openssl x509 -noout -ext subjectAltName -in "$base_live/fullchain.pem" 2>/dev/null \
               | grep -oE 'DNS:[^,]+' | sed 's/DNS://g' | tr -d ' ' | sort | tr '\n' ',')
    san_suffix=$(openssl x509 -noout -ext subjectAltName -in "$suffix_live/fullchain.pem" 2>/dev/null \
                 | grep -oE 'DNS:[^,]+' | sed 's/DNS://g' | tr -d ' ' | sort | tr '\n' ',')
    echo "  ─ $name"
    echo "      $base        SAN: ${san_base%,}"
    echo "      $name  SAN: ${san_suffix%,}"
    if [[ "${san_base%,}" == "${san_suffix%,}" ]]; then
      local sure=""
      askyn sure "SAN совпадают — удалить дубль $name?" "y"
      if [[ "$sure" == true ]]; then
        certbot delete --cert-name "$name" --non-interactive 2>/dev/null || true
        log "    удалено: $name"
        did=$((did+1))
      fi
    else
      warn "    SAN РАЗНЫЕ — не трогаю (разберись вручную)"
    fi
  done
  [[ $did -eq 0 ]] && log "Ничего не изменено."
  pause
}

# Автоочистка сирот: линии в live/, которые не используются.
# Показывает список, спрашивает по каждой, удаляет по certbot delete.
cert_lines_cleanup() {
  line; echo -e "${B}   ОЧИСТКА СИРОТ (линии, которые нигде не используются)${N}"; line
  [[ -d /etc/letsencrypt/live ]] || { warn "Нет /etc/letsencrypt/live"; pause; return 0; }

  local -a orphans=()
  local ld name
  for ld in /etc/letsencrypt/live/*/; do
    [[ -d "$ld" ]] || continue
    name=$(basename "$ld")
    [[ "$name" =~ -[0-9]{4}$ ]] && continue   # -0001 обрабатывает cert_dedup_0001
    if ! cert_line_is_used "$name"; then
      orphans+=("$name")
    fi
  done

  if [[ ${#orphans[@]} -eq 0 ]]; then
    log "Сирот не найдено — всё используется"
    pause; return 0
  fi

  echo "Найдены сироты (не используются нигде):"
  local n=0
  for name in "${orphans[@]}"; do
    n=$((n+1))
    local fc="/etc/letsencrypt/live/$name/fullchain.pem"
    local san="—" exp="—"
    if [[ -f "$fc" ]]; then
      san=$(openssl x509 -noout -ext subjectAltName -in "$fc" 2>/dev/null \
            | grep -oE 'DNS:[^,]+' | sed 's/DNS://g' | tr -d ' ' | tr '\n' ',' | sed 's/,$//')
      exp=$(openssl x509 -noout -enddate -in "$fc" 2>/dev/null | cut -d= -f2)
    fi
    printf "  %2d) %s\n" "$n" "$name"
    echo "      SAN: $san"
    echo "      Истекает: $exp"
  done
  echo
  echo "  1) Удалить ВСЕ найденные сироты (с подтверждением)"
  echo "  2) Выбрать по одной"
  echo "  0) Отмена"
  line
  local c=""
  read -rp "$(echo -e "${B}Выбор:${N} ")" c || c="0"
  case "$c" in
    1)
      local sure=""
      ask sure "Удалить ВСЕ сироты (${#orphans[@]} шт.)? Введи YES" "" '^YES$'
      [[ "$sure" == "YES" ]] || { log "Отменено"; pause; return 0; }
      for name in "${orphans[@]}"; do
        log "Удаляю $name …"
        certbot delete --cert-name "$name" --non-interactive 2>&1 | tail -2 | sed 's/^/    /'
      done
      log "Готово"
      ;;
    2)
      for name in "${orphans[@]}"; do
        local sure=""
        askyn sure "Удалить «$name»?" "n"
        if [[ "$sure" == true ]]; then
          certbot delete --cert-name "$name" --non-interactive 2>&1 | tail -2 | sed 's/^/    /'
          log "  удалено"
        fi
      done
      ;;
    *) pause; return 0 ;;
  esac
  pause
}

# Расширенный аудит для режима B: показывает все линии + их SAN + использование.
cert_lines_audit() {
  line; echo -e "${B}   АУДИТ ЛИНИЙ СЕРТОВ${N}"; line
  cert_mode_load >/dev/null 2>&1 || true
  echo "  Режим: ${CERT_MODE:-A}"
  echo

  cert_lines_load
  if [[ ${#CERT_LINES[@]} -eq 0 ]]; then
    warn "Линии не найдены"
    pause; return 0
  fi
  local ln d n
  for ln in "${CERT_LINES[@]}"; do
    cert_line_domains_load "$ln"
    n=${#CERT_LINE_DOMAINS[@]}
    echo "  ▸ Линия «$ln» ($n дом.)"
    echo "      Домены SAN:"
    for d in "${CERT_LINE_DOMAINS[@]}"; do echo "        $d"; done
    local ldir="/etc/letsencrypt/live/$ln"
    if [[ -f "$ldir/fullchain.pem" ]]; then
      local end left
      end=$(openssl x509 -noout -enddate -in "$ldir/fullchain.pem" 2>/dev/null | cut -d= -f2)
      left=$(( ($(date -d "$end" +%s 2>/dev/null || echo 0) - $(date +%s)) / 86400 ))
      echo "      Серт: есть (~$left дн, до $end)"
      # Проверка: SAN серта == SAN в файле?
      local cur_san want_san
      cur_san=$(openssl x509 -noout -ext subjectAltName -in "$ldir/fullchain.pem" 2>/dev/null \
                | grep -oE 'DNS:[^,]+' | sed 's/DNS://g' | tr -d ' ' | sort | tr '\n' ',')
      want_san=$(printf '%s\n' "${CERT_LINE_DOMAINS[@]}" | sort -u | tr '\n' ',')
      if [[ "${cur_san%,}" == "${want_san%,}" ]]; then
        echo "      SAN совпадает: ✓"
      else
        warn "      SAN РАСХОДИТСЯ:"
        echo "        серт:  ${cur_san%,}"
        echo "        файл:  ${want_san%,}"
      fi
    else
      warn "      Серт: НЕ выпущен"
    fi
    echo
  done
  pause
}

# Аудит сертификатов: какие линии в live/, где используются, какие сироты.
# Ничего не удаляет — только показывает.
cert_audit() {
  line; echo -e "${B}   АУДИТ СЕРТИФИКАТОВ${N}"; line
  [[ -d /etc/letsencrypt/live ]] || { warn "Нет /etc/letsencrypt/live"; pause; return 0; }

  # 1. Активные домены из 3 источников
  local active_domains=""
  # БД x-ui
  local _wd _sd
  _wd=$(xui_get webDomain 2>/dev/null || true); _sd=$(xui_get subDomain 2>/dev/null || true)
  [[ -n "$_wd" && "$_wd" != "null" ]] && active_domains+=" $_wd"
  [[ -n "$_sd" && "$_sd" != "null" && "$_sd" != "$_wd" ]] && active_domains+=" $_sd"

  # stack-domains.txt
  if [[ -s "$CERT_DOMAINS_FILE" ]]; then
    local d
    while IFS= read -r d; do
      d="$(printf '%s' "$d" | tr -d '[:space:]')"
      [[ -n "$d" ]] && active_domains+=" $d"
    done < "$CERT_DOMAINS_FILE"
  fi

  # SNI-карта: домены из блока map (только первое поле строк ВНУТРИ map)
  if [[ -f "$SNI_CONF" ]]; then
    local sd
    while IFS= read -r sd; do
      [[ -n "$sd" && "$sd" != "default" && "$sd" != "_" ]] && active_domains+=" $sd"
    done < <(awk '
      /^map / { inmap=1; next }
      inmap && /^}/ { inmap=0 }
      inmap && /^[[:space:]]/ && NF >= 2 {
        dom = $1
        sub(/;$/, "", dom)
        if (dom != "" && dom != "default") print dom
      }
    ' "$SNI_CONF" 2>/dev/null | sort -u)
  fi

  # server_name в stack.conf
  if [[ -f "$STACK_CONF" ]]; then
    local sn
    while IFS= read -r sn; do
      [[ -n "$sn" && "$sn" != "_" ]] && active_domains+=" $sn"
    done < <(grep -oE '^\s*server_name\s+[^;]+;' "$STACK_CONF" 2>/dev/null | sed 's/server_name//; s/;//; s/^\s*//; s/\s*$//' | tr ' ' '\n' | sort -u)
  fi

  # Уникализация
  active_domains=$(printf '%s\n' "$active_domains" | tr ' ' '\n' | sed '/^$/d' | sort -u | tr '\n' ' ')
  echo -e "${B}▸ Активные домены стека:${N}"
  echo "  $active_domains"
  echo

  # 2. Все линии в live/
  echo -e "${B}▸ Линии в /etc/letsencrypt/live/:${N}"
  local total=0 orphans=0
  local ld
  for ld in /etc/letsencrypt/live/*/; do
    [[ -d "$ld" ]] || continue
    local name
    name=$(basename "$ld")
    (( total++ ))
    local fc="$ld/fullchain.pem"
    [[ -f "$fc" ]] || { warn "  $name — НЕТ fullchain.pem (битая линия)"; continue; }

    # SAN
    local san=""
    san=$(openssl x509 -noout -ext subjectAltName -in "$fc" 2>/dev/null \
          | grep -oE 'DNS:[^,]+' | sed 's/DNS://g' | tr '\n' ',' | sed 's/,$//')

    # Срок
    local end left
    end=$(openssl x509 -noout -enddate -in "$fc" 2>/dev/null | cut -d= -f2)
    left=$(( ($(date -d "$end" +%s 2>/dev/null || echo 0) - $(date +%s)) / 86400 ))

    # Использование
    local used_in=""
    local in_db=0 in_nginx=0 in_sni=0 in_domains=0

    # в БД? Сертификаты sidecar-инбаундов лежат в JSON settings,
    # поэтому ищем не только в таблице settings панели.
    local refs refs_json
    refs=$(sqlite3 -cmd ".timeout 3000" "$XUI_DB" \
      "SELECT COUNT(*) FROM settings WHERE value LIKE '%/live/$name/%';" 2>/dev/null || echo 0)
    refs_json=$(sqlite3 -cmd ".timeout 3000" "$XUI_DB" \
      "SELECT COUNT(*) FROM inbounds WHERE settings LIKE '%/live/$name/%' OR stream_settings LIKE '%/live/$name/%';" 2>/dev/null || echo 0)
    if [[ "$refs" != "0" || "$refs_json" != "0" ]]; then
      in_db=1; used_in+=" БД"
    fi

    # в nginx?
    if [[ -f "$STACK_CONF" ]] && grep -q "/live/$name/" "$STACK_CONF" 2>/dev/null; then
      in_nginx=1; used_in+=" nginx"
    fi

    # в SNI-карте? (по имени как домен). Для wildcard-пути cert-name
    # может отличаться от SNI-домена, поэтому JSON/БД проверяются отдельно.
    if [[ -f "$SNI_CONF" ]] && grep -qE "^[[:space:]]+${name}[[:space:]]+" "$SNI_CONF" 2>/dev/null; then
      in_sni=1; used_in+=" SNI"
    fi
    if [[ "$in_db" == 1 && "$used_in" != *"SNI"* ]]; then
      : # уже отмечено через settings JSON
    fi

    # в stack-domains.txt?
    if [[ -s "$CERT_DOMAINS_FILE" ]] && grep -qxF "$name" "$CERT_DOMAINS_FILE" 2>/dev/null; then
      in_domains=1; used_in+=" domains.txt"
    fi

    # Сан содержит любой активный домен?
    local covers_active=0
    local ad
    for ad in $active_domains; do
      [[ -z "$ad" ]] && continue
      if grep -qE "(^|,)\s*$ad(\s*,|$)" <<<"$(tr ',' '\n' <<<"$san")" 2>/dev/null; then
        covers_active=1; break
      fi
      # wildcard-проверка
      if grep -qE "(^|,)\s*\*\.${ad#*.}(\s*,|$)" <<<"$(tr ',' '\n' <<<"$san")" 2>/dev/null; then
        covers_active=1; break
      fi
    done

    # Вердикт
    local verdict
    if [[ $((in_db + in_nginx + in_sni + in_domains)) -gt 0 ]]; then
      verdict="${G}✓ используется${N} (${used_in# })"
    elif [[ "$covers_active" == "1" ]]; then
      verdict="${Y}? не привязан, но SAN покрывает активный домен${N}"
    else
      verdict="${R}✗ СИРОТА (не используется нигде)${N}"
      (( orphans++ ))
    fi

    echo "  ─ $name"
    echo "      SAN:     $san"
    echo "      Срок:    $end (~$left дн)"
    echo -e "      Статус:  $verdict"
  done

  echo
  echo "  Всего линий: $total · Сирот: $orphans"
  if [[ $orphans -gt 0 ]]; then
    warn "Удалить сирот можно через п.10 → 12 (или вручную: certbot delete --cert-name <name>)"
  fi
  line
  pause
}

# Интерактивное удаление сертов. Показывает список, даёт выбрать, требует
# подтверждения для используемых. Защищает от случайного удаления.
cert_delete_menu() {
  line; echo -e "${B}   УДАЛЕНИЕ СЕРТА${N}"; line
  [[ -d /etc/letsencrypt/live ]] || { warn "Нет /etc/letsencrypt/live"; pause; return 0; }

  local -a lines=()
  local ld
  for ld in /etc/letsencrypt/live/*/; do
    [[ -d "$ld" ]] || continue
    lines+=("$(basename "$ld")")
  done

  [[ ${#lines[@]} -eq 0 ]] && { warn "Сертов нет"; pause; return 0; }

  echo "Доступные линии:"
  local i=1 name
  for name in "${lines[@]}"; do
    local fc="/etc/letsencrypt/live/$name/fullchain.pem"
    local san="" exp=""
    if [[ -f "$fc" ]]; then
      san=$(openssl x509 -noout -ext subjectAltName -in "$fc" 2>/dev/null | grep -oE 'DNS:[^,]+' | sed 's/DNS://g' | tr '\n' ',' | sed 's/,$//')
      exp=$(openssl x509 -noout -enddate -in "$fc" 2>/dev/null | cut -d= -f2)
    fi

    # Использование
    local used=""
    local refs
    refs=$(sqlite3 -cmd ".timeout 3000" "$XUI_DB" \
      "SELECT COUNT(*) FROM settings WHERE value LIKE '%/live/$name/%';" 2>/dev/null || echo 0)
    [[ "$refs" != "0" ]] && used+=" БД"
    [[ -f "$STACK_CONF" ]] && grep -q "/live/$name/" "$STACK_CONF" 2>/dev/null && used+=" nginx"

    local mark=""
    if [[ -n "$used" ]]; then mark="${R}[ИСПОЛЬЗУЕТСЯ:${used# }]${N}"; else mark="${G}[не используется]${N}"; fi

    printf "  %2d) %-30s %s\n" "$i" "$name" "$mark"
    printf "        SAN: %s\n" "${san:-—}"
    printf "        Срок: %s\n" "${exp:-—}"
    i=$((i+1))
  done
  echo
  local pick=""
  ask pick "Номер линии для удаления (0 — отмена)" "0" '^[0-9]+$'
  [[ "$pick" == "0" ]] && return 0
  (( pick < 1 || pick > ${#lines[@]} )) && { err "Нет такого"; pause; return 1; }
  local target="${lines[$((pick-1))]}"

  # Проверка использования → требует YES
  local in_use=""
  local refs
  refs=$(sqlite3 -cmd ".timeout 3000" "$XUI_DB" \
    "SELECT COUNT(*) FROM settings WHERE value LIKE '%/live/$target/%';" 2>/dev/null || echo 0)
  [[ "$refs" != "0" ]] && in_use+=" БД"
  [[ -f "$STACK_CONF" ]] && grep -q "/live/$target/" "$STACK_CONF" 2>/dev/null && in_use+=" nginx"

  echo
  if [[ -n "$in_use" ]]; then
    warn "⚠ Линия «$target» ИСПОЛЬЗУЕТСЯ: ${in_use# }"
    warn "  Удаление сломает TLS для этих сервисов!"
    local sure=""
    ask sure "Для подтверждения введи YES" "" '^YES$'
    [[ "$sure" == "YES" ]] || { log "Отменено"; pause; return 0; }
  else
    local sure=""
    askyn sure "Удалить «$target»?" "n"
    [[ "$sure" == true ]] || { log "Отменено"; pause; return 0; }
  fi

  log "Удаляю $target …"
  if certbot delete --cert-name "$target" --non-interactive 2>&1 | sed 's/^/    /'; then
    log "Линия «$target» удалена"
  else
    err "certbot delete вернул ошибку"
  fi
  pause
}

# статистика decoy-посещений за 24ч (парсинг decoy_ext через python3)
cert_wildcard_issue() {
  le_email_load || true
  if [[ -z "$EMAIL" ]]; then
    ask EMAIL "Email для Let's Encrypt" "" '^[^@]+@[^@]+\.[^@]+$'
    le_email_save "$EMAIL"
  fi
  local base="${1:-}"
  if [[ -z "$base" ]]; then
    ask base "Базовый домен wildcard (напр. example.com)" "${WILDCARD_DOMAIN:-}" '^[a-zA-Z0-9.-]+$'
  fi
  [[ -z "$base" ]] && return 1

  # --- проверка: wildcard уже установлен → переустанавливать не нужно ---
  local wdir="/etc/letsencrypt/live/$base"
  if [[ -f "$wdir/fullchain.pem" && -f "$wdir/privkey.pem" ]]; then
    local exp="" days_left=-1
    exp=$(openssl x509 -enddate -noout -in "$wdir/fullchain.pem" 2>/dev/null | cut -d= -f2 || true)
    [[ -n "$exp" ]] && days_left=$(( ( $(date -d "$exp" +%s 2>/dev/null || echo 0) - $(date +%s) ) / 86400 ))
    if [[ "$days_left" -gt 30 ]]; then
      echo "$base" > "$WILDCARD_STATE" 2>/dev/null || true
      WILDCARD_DOMAIN="$base"
      log "Wildcard *.$base уже выпущен (истекает через $days_left дн.) — переустановка не нужна"
      return 0
    fi
    warn "Wildcard *.$base истекает через $days_left дн. — обновляю"
  fi

  # плагин DNS-01 для Cloudflare
  if ! certbot plugins 2>/dev/null | grep -q dns-cloudflare; then
    log "Установка плагина python3-certbot-dns-cloudflare..."
    apt-get update -y >/dev/null 2>&1 || true
    apt-get install -y python3-certbot-dns-cloudflare >/dev/null 2>&1 \
      || { err "Не удалось установить python3-certbot-dns-cloudflare"; return 1; }
  fi

  # API Token (сохраняется один раз)
  local need_token=true
  if [[ -f "$CF_CREDS" ]] && grep -q 'dns_cloudflare_api_token' "$CF_CREDS" 2>/dev/null; then
    askyn reuse "Использовать сохранённый Cloudflare API Token ($CF_CREDS)?" "y"
    # shellcheck disable=SC2154 # задаётся askyn выше
    [[ "$reuse" == true ]] && need_token=false
  fi
  if [[ "$need_token" == true ]]; then
    echo "Создайте токен: Cloudflare → My Profile → API Tokens → 'Edit zone DNS'"
    echo "Права: Zone / DNS / Edit для зоны $base"
    local token=""
    ask token "Cloudflare API Token" "" '.+'
    mkdir -p "$(dirname "$CF_CREDS")" 2>/dev/null || true
    cat > "$CF_CREDS" <<EOF
# Cloudflare API Token (Zone:DNS:Edit) — для wildcard-сертификатов
dns_cloudflare_api_token = $token
EOF
    chmod 600 "$CF_CREDS" 2>/dev/null || true
  fi

  log "Выпуск wildcard: $base + *.$base (DNS-01 Cloudflare)..."
  local out=""
  out=$(certbot certonly \
    --dns-cloudflare \
    --dns-cloudflare-credentials "$CF_CREDS" \
    --dns-cloudflare-propagation-seconds 30 \
    --non-interactive --agree-tos --email "$EMAIL" \
    --cert-name "$base" \
    -d "$base" -d "*.$base" 2>&1 || true)

  local wdir="/etc/letsencrypt/live/$base"
  if [[ -f "$wdir/fullchain.pem" && -f "$wdir/privkey.pem" ]]; then
    # хук перезагрузки nginx после автопродления
    mkdir -p /etc/letsencrypt/renewal-hooks-deploy 2>/dev/null || true
    cat > /etc/letsencrypt/renewal-hooks-deploy/reload-nginx.sh <<'HOOK'
#!/bin/sh
systemctl reload nginx 2>/dev/null || true
HOOK
    chmod +x /etc/letsencrypt/renewal-hooks-deploy/reload-nginx.sh 2>/dev/null || true
    echo "$base" > "$WILDCARD_STATE" 2>/dev/null || true
    WILDCARD_DOMAIN="$base"
    log "Wildcard cert готов: $wdir"
    log "  покрывает: $base и *.$base — персональные сертификаты больше не нужны"
    return 0
  fi
  err "  certbot отказал:"
  echo "$out" | tail -12 | sed 's/^/    /'
  err "  ИТОГ: wildcard *.$base НЕ выпущен — дальнейшая настройка остановлена."
  cert_error_pause
  return 1
}

wildcard_toggle() {
  echo
  echo "▸ Wildcard Cloudflare: ${WILDCARD_DOMAIN:-выключен}"
  if [[ -n "$WILDCARD_DOMAIN" ]]; then
    echo "  1) отключить (вернуть приоритет персональным сертификатам)"
    echo "  2) сменить базовый домен / перевыпустить"
    echo "  0) Назад"
    local c=""
    ask c "Выбор" "0" '^[0-9]$'
    case "$c" in
      1) rm -f "$WILDCARD_STATE" 2>/dev/null || true; WILDCARD_DOMAIN=""; log "Wildcard отключён" ;;
      2) cert_wildcard_issue ;;
    esac
  else
    local on=false
    askyn on "Включить wildcard — один cert Cloudflare на все поддомены?" "y"
    [[ "$on" == true ]] && cert_wildcard_issue
  fi
}

# =====================================================================
