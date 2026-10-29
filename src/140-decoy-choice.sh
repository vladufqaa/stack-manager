# DECOY ВЫБОР
# =====================================================================
# ЕДИНЫЙ выбранный шаблон decoy — SELECTED_DECOY_TPL.
# Выбор делается один раз в анкете п.1 (заглушка панели) и/или в вопросах
# CDN/Reality, а применяется ко ВСЕМ доменам стека. Раньше домены, для которых
# шаблон не спрашивали (инбаунды, уже привязанные к SNI), молча получали
# стандартную страницу nginx «Welcome to nginx!» — выбор пользователя
# игнорировался.
# Значение переживает перезапуск скрипта (файл состояния), но применяется
# ТОЛЬКО там, где раньше стоял жёсткий "default": явный выбор в меню главнее.
# Пусто/невалидно → "default" (прежнее поведение, полная совместимость).
DECOY_TPL_STATE="/root/stack-backups/selected-decoy-tpl"
SELECTED_DECOY_TPL="${SELECTED_DECOY_TPL:-}"

# Шаблон реально применим? (файл шаблона существует / папка своего сайта есть)
decoy_tpl_valid() {   # <шаблон>
  local t="${1:-}"
  [[ -z "$t" ]] && return 1
  if [[ "$t" == custom:* ]]; then
    [[ -d "${t#custom:}" ]] && return 0
    return 1
  fi
  [[ "$t" == "redirect" || "$t" == "locked" ]] && return 0
  [[ -f "$DECOY_TPL_DIR/$t.html" || -f "$DECOY_LOGIN_DIR/$t.html" ]] && return 0
  return 1
}

# Запомнить выбор пользователя как общий шаблон для всех доменов.
# Значения-заглушки (stub/adguard/default) общий шаблон не меняют.
decoy_selected_set() {   # <шаблон|значение PDECOY>
  local t="${1:-}"
  case "$t" in
    ""|stub|adguard|adguard-sni|default) return 0 ;;
    tpl:*) t="${t#tpl:}" ;;
  esac
  [[ "$t" == "default" ]] && return 0
  SELECTED_DECOY_TPL="$t"
  mkdir -p "$(dirname "$DECOY_TPL_STATE")" 2>/dev/null || true
  printf '%s\n' "$t" > "$DECOY_TPL_STATE" 2>/dev/null || true
  return 0
}

# Шаблон по умолчанию для домена: выбранный пользователем, иначе "default".
decoy_default_tpl() {
  if [[ -z "${SELECTED_DECOY_TPL:-}" && -s "$DECOY_TPL_STATE" ]]; then
    SELECTED_DECOY_TPL=$(head -n 1 "$DECOY_TPL_STATE" 2>/dev/null | tr -d '[:space:]') || true
  fi
  if decoy_tpl_valid "${SELECTED_DECOY_TPL:-}"; then
    printf '%s' "$SELECTED_DECOY_TPL"
  else
    printf 'default'
  fi
}

# ── Шаблоны decoy ПО ДОМЕНАМ ────────────────────────────────────────────
# Каждому домену можно задать СВОЙ шаблон (каталожный или свой сайт
# custom:/путь) независимо от остальных: домены могут быть настроены одинаково,
# по-разному или на свои сайты. Хранится в файле «домен<TAB>шаблон».
# Приоритет: свой шаблон домена → tpl CDN-профиля (для origin) → общий
# (SELECTED_DECOY_TPL) → "default".
DECOY_TPL_MAP="/root/stack-backups/decoy-templates.tsv"

decoy_tpl_store_get() {   # <domain> → шаблон (пусто, если домену не задан)
  local d="${1:-}"
  [[ -n "$d" && -s "$DECOY_TPL_MAP" ]] || return 1
  awk -F'\t' -v d="$d" '$1==d {print $2; exit}' "$DECOY_TPL_MAP" 2>/dev/null
}

decoy_tpl_store_set() {   # <domain> <шаблон>
  local d="${1:-}" t="${2:-}"
  [[ -n "$d" && -n "$t" ]] || return 1
  mkdir -p "$(dirname "$DECOY_TPL_MAP")" 2>/dev/null || true
  local tmp; tmp=$(mktemp 2>/dev/null) || return 1
  [[ -s "$DECOY_TPL_MAP" ]] && awk -F'\t' -v d="$d" '$1!=d' "$DECOY_TPL_MAP" > "$tmp" 2>/dev/null || true
  printf '%s\t%s\n' "$d" "$t" >> "$tmp"
  mv -f "$tmp" "$DECOY_TPL_MAP" 2>/dev/null || { rm -f "$tmp"; return 1; }
  chmod 600 "$DECOY_TPL_MAP" 2>/dev/null || true
  return 0
}

# Шаблон из действующего decoy-блока домена (маркер: tpl=… root=…)
decoy_tpl_from_block() {   # <domain> → шаблон (custom:/путь для своего сайта)
  local dom="${1:-}" line="" t="" r=""
  [[ -n "$dom" && -f "$STACK_CONF" ]] || return 1
  line=$(grep -m1 -E "# >>> decoy .*domain=${dom//./\\.}([[:space:]]|\$)" "$STACK_CONF" 2>/dev/null || true)
  [[ -n "$line" ]] || return 1
  t=$(grep -oE 'tpl=[^ ]+' <<<"$line" | head -1 | cut -d= -f2-)
  [[ -n "$t" ]] || return 1
  if [[ "$t" == "custom" ]]; then
    r=$(grep -oE 'root=[^ ]+' <<<"$line" | head -1 | cut -d= -f2-)
    [[ -n "$r" ]] && t="custom:$r"
  fi
  printf '%s' "$t"
}

# tpl CDN-ORIGIN из CDN-профиля (поле 6): для origin он главнее общего
cdn_profile_origin_tpl() {   # <domain>
  local d="${1:-}" row f3 f6
  [[ -n "$d" && -s "$CDN_PROFILES" ]] || return 1
  while IFS= read -r row; do
    [[ -n "$row" ]] || continue
    f3=$(printf '%s' "$row" | cut -d'|' -f3)
    [[ "$f3" == "$d" ]] || continue
    f6=$(printf '%s' "$row" | cut -d'|' -f6)
    [[ -n "$f6" ]] && { printf '%s' "$f6"; return 0; }
  done < "$CDN_PROFILES"
  return 1
}

# Итоговый шаблон для домена (используется всеми местами создания decoy).
# Приоритет: сохранённый выбор домена → tpl CDN-профиля (для origin) → шаблон
# действующего decoy-блока (чтобы самолечение не затирало уже настроенный домен
# общим шаблоном) → общий → default.
decoy_tpl_for() {   # <domain>
  local d="${1:-}" t=""
  t=$(decoy_tpl_store_get "$d" 2>/dev/null || true)
  [[ -n "$t" ]] && decoy_tpl_valid "$t" && { printf '%s' "$t"; return 0; }
  t=$(cdn_profile_origin_tpl "$d" 2>/dev/null || true)
  [[ -n "$t" ]] && decoy_tpl_valid "$t" && { printf '%s' "$t"; return 0; }
  t=$(decoy_tpl_from_block "$d" 2>/dev/null || true)
  [[ -n "$t" ]] && decoy_tpl_valid "$t" && { printf '%s' "$t"; return 0; }
  decoy_default_tpl
}

# Что реально стоит на домене сейчас (подсказка по умолчанию в вопросах)
decoy_tpl_current() {   # <domain>
  local d="${1:-}" t=""
  t=$(decoy_tpl_store_get "$d" 2>/dev/null || true)
  [[ -n "$t" ]] && decoy_tpl_valid "$t" && { printf '%s' "$t"; return 0; }
  t=$(decoy_tpl_from_block "$d" 2>/dev/null || true)
  [[ -n "$t" ]] && decoy_tpl_valid "$t" && { printf '%s' "$t"; return 0; }
  decoy_tpl_for "$d"
}

decoy_template_choose_impl() {
  local __result="$1" prompt="${2:-Выберите decoy-шаблон}" default="${3:-default}"
  echo >&2; echo -e "${B}Доступные decoy-шаблоны — страница-ЗАГЛУШКА:${N}" >&2
  echo -e "   (её увидит посторонний, открыв домен в браузере; на работу протокола не влияет)" >&2
  local i=1
  local -a NAMES=()
  local __t
  for __t in "${DECOY_TEMPLATES[@]}"; do
    local __n="${__t%%|*}" __dsc="${__t##*|}"
    printf "  %2d) %-15s %s\n" "$i" "$__n" "$__dsc" >&2
    NAMES+=("$__n"); i=$((i+1))
  done
  local __custom_num=$i
  printf "  %2d) %-15s %s\n" "$__custom_num" "custom" "▶ Свой сайт — папка со статикой (index.html и т.д.)" >&2
  echo >&2
  local __c=""
  while :; do
    if ! ask __c "$prompt" "$default" '^[0-9]+$|^[a-z:_/.-]+$'; then
      # EOF (анс-файл кончился): возвращаем дефолт, но если это не валидное
      # имя шаблона и не custom:* — глобальный дефолтный шаблон, иначе ниже
      # по потоку decoy применит несуществующий шаблон.
      local __eof_default="$default"
      if [[ "$__eof_default" != custom:* ]] && ! decoy_tpl_valid "$__eof_default"; then
        __eof_default="$(decoy_default_tpl)"
        warn "Дефолт «$default» не валиден — использую шаблон «$__eof_default»" >&2
      fi
      printf -v "$__result" '%s' "$__eof_default"
      return 0
    fi
    if [[ "$__c" =~ ^[0-9]+$ ]] && (( __c < 1 || __c > __custom_num )); then
      err "Выбор вне списка. Укажите номер от 1 до $__custom_num."
      continue
    fi
    # Имя шаблона (decoy_tpl_current/дефолт при EOF — всегда ИМЯ, не номер):
    # валидное имя из списка принимаем сразу, иначе ask() на EOF вернёт дефолт-
    # имя, проверка ниже его отвергнет и цикл «EOF → имя → вне списка» станет
    # бесконечным. Заодно чинится Enter на имени-по-умолчанию в интерактиве.
    local __found=""
    local __k
    for __k in "${!NAMES[@]}"; do
      [[ "${NAMES[$__k]}" == "$__c" ]] && { __found=1; break; }
    done
    if [[ -n "$__found" ]]; then
      log "Выбран decoy-шаблон: $__c" >&2
      printf -v "$__result" '%s' "$__c"
      return 0
    fi
    if [[ "$__c" =~ ^[a-z:_/.-]+$ ]] && [[ "$__c" != custom && "$__c" != custom:* ]]; then
      err "Выбор вне списка. Укажите номер шаблона, его имя или custom."
      continue
    fi
    break
  done
  if [[ "$__c" == "custom" || "$__c" == "$__custom_num" || "$__c" == custom:* ]]; then
    local __path=""
    [[ "$__c" == custom:* ]] && __path="${__c#custom:}"
    if [[ -z "$__path" ]]; then
      # Не-TTY: папку выбрать нечем — EOF вернёт дефолт «/var/www/mysite»,
      # которого нет → «Папка не существует → continue» навсегда.
      # Возвращаем безопасный шаблон по умолчанию.
      if [[ ! -t 0 ]]; then
        warn "Не-TTY: custom-путь недоступен — использую шаблон по умолчанию" >&2
        printf -v "$__result" '%s' "$(decoy_default_tpl)"
        return 0
      fi
      local __path_tries=0
      while :; do
        # 3 неудачи подряд (Ctrl+D возвращает тот же дефолт-путь) — не петлим.
        __path_tries=$((__path_tries+1))
        [[ "$__path_tries" -ge 3 ]] && {
          warn "Путь не выбран — использую шаблон по умолчанию" >&2
          printf -v "$__result" '%s' "$(decoy_default_tpl)"
          return 0
        }
        __path=""
        ask __path "Путь к папке сайта (index.html обязателен)" "/var/www/mysite" '^/.+'
        [[ -d "$__path" ]] || { err "Папка $__path не существует"; continue; }
        if [[ ! -f "$__path/index.html" ]]; then
          warn "В $__path нет index.html — nginx отдаст 404"
          local __go=""
          askyn __go "Продолжить всё равно?" "n"
          [[ "$__go" == true ]] || continue
        fi
        break
      done
    fi
    if command -v sudo >/dev/null 2>&1 && ! sudo -u www-data test -r "$__path/index.html" 2>/dev/null; then
      warn "www-data не может читать $__path/index.html — nginx отдаст 403"
      local __fix=""
      askyn __fix "Исправить права (chmod -R o+rX)?" "y"
      if [[ "$__fix" == true ]]; then
        chmod -R o+rX "$__path" 2>/dev/null || true
        log "Права исправлены: $__path"
      fi
    fi
    printf -v "$__result" '%s' "custom:$__path"
    return 0
  fi
  if [[ "$__c" =~ ^[0-9]+$ ]]; then
    if (( __c >= 1 && __c <= ${#NAMES[@]} )); then
      log "Выбран decoy-шаблон: ${NAMES[$((__c-1))]}" >&2
      printf -v "$__result" '%s' "${NAMES[$((__c-1))]}"
    else
      log "Выбор decoy вне списка — используется: $default" >&2
      printf -v "$__result" '%s' "$default"
    fi
  else
    log "Выбран decoy-шаблон: $__c" >&2
    printf -v "$__result" '%s' "$__c"
  fi
}

# Обёртка: любой явный выбор шаблона запоминаем как общий (SELECTED_DECOY_TPL),
# чтобы он применялся и к доменам, для которых вопрос больше не задаётся.
decoy_template_choose() {
  local __var="$1"
  decoy_template_choose_impl "$@"
  decoy_selected_set "${!__var:-}"
}

# =====================================================================
# ЕДИНЫЙ HTTP-КОНФИГ (sites-available/stack.conf)
#   ACME :80 + панель :4443 + все decoy-блоки — в одном файле.
#   Stream-часть (SNI-роутер) обязана жить в streams-enabled/sni-router.conf:
#   в sites-available можно класть только http-контекст.
# =====================================================================
stack_ensure() {
  mkdir -p "$NGINX_SITES_AVAIL" "$NGINX_SITES_DIR" 2>/dev/null || true
  [[ -f "$STACK_CONF" ]] || printf '# stack-manager: единый конфиг (ACME :80, панель :4443, decoy)\n' > "$STACK_CONF"
  # формат лога декоёв: с доменом (host=) — нужен для статистики и бана смотревших
  if ! grep -q "log_format decoy_ext" "$STACK_CONF" 2>/dev/null; then
    sed -i "1i log_format decoy_ext '\$remote_addr [\$time_local] \"\$request\" \$status \"\$http_user_agent\" host=\$host';" "$STACK_CONF"
  fi
  [[ -e "$STACK_LINK" || -L "$STACK_LINK" ]] || ln -sf "$STACK_CONF" "$STACK_LINK"
  return 0
}

# удалить decoy-блок по домену (маркеры # >>> decoy ... domain=X)
stack_del_decoy() {
  local dom="$1"
  [[ -f "$STACK_CONF" ]] || return 0
  local tmp
  tmp=$(mktemp)
  awk -v dom="$dom" '
    !skip && index($0, "# >>> decoy ") == 1 {
      tail = $0
      sub(/^.* domain=/, "", tail)
      if (tail == dom) { skip = 1; next }
    }
    skip && index($0, "# <<< decoy ") == 1 { skip = 0; next }
    !skip { print }
  ' "$STACK_CONF" > "$tmp" 2>/dev/null && mv "$tmp" "$STACK_CONF"
}

# удалить ВСЕ decoy-блоки
stack_del_all_decoy() {
  [[ -f "$STACK_CONF" ]] || return 0
  local tmp
  tmp=$(mktemp)
  awk '
    index($0, "# >>> decoy ") == 1 { skip = 1; next }
    skip && index($0, "# <<< decoy ") == 1 { skip = 0; next }
    !skip { print }
  ' "$STACK_CONF" > "$tmp" 2>/dev/null && mv "$tmp" "$STACK_CONF"
}

# метаданные decoy по домену:  port root cert key
stack_decoy_meta() {
  local dom="$1" line=""
  [[ -f "$STACK_CONF" ]] || return 1
  local esc="${dom//./\\.}"
  line=$(grep -m1 -E "# >>> decoy .*domain=${esc}([[:space:]]|\$)" "$STACK_CONF" 2>/dev/null || true)
  [[ -z "$line" ]] && return 1
  local port root cert key
  port=$(grep -oE 'port=[0-9]+'   <<<"$line" | head -1 | cut -d= -f2)
  root=$(grep -oE 'root=[^ ]+'    <<<"$line" | head -1 | cut -d= -f2-)
  cert=$(grep -oE 'cert=[^ ]+'    <<<"$line" | head -1 | cut -d= -f2-)
  key=$(grep -oE 'key=[^ ]+'      <<<"$line" | head -1 | cut -d= -f2-)
  echo "$port $root $cert $key"
}

mk_decoy() {
  # $1..$6 как раньше; $7 (необязательно) — opts: "ua404=1 redir=https://..."
  local port="$1" dom="$2" cert="$3" key="$4" root="$5"
  local tpl="${6:-default}" opts="${7:-}"
  local opt_ua404=1 opt_redir="" opt_status404=0
  local _o _k _v
  for _o in $opts; do
    _k="${_o%%=*}"; _v="${_o#*=}"
    case "$_k" in
      ua404) opt_ua404="$_v" ;;
      redir) opt_redir="$_v" ;;
      status404) opt_status404="$_v" ;;
    esac
  done
  # custom:<path> — nginx будет служить прямо из указанной папки
  if [[ "$tpl" == custom:* ]]; then
    root="${tpl#custom:}"
    tpl="custom"
  fi
  mkdir -p "$root" 2>/dev/null || true

  # security-заголовки decoy: сниппет должен существовать до nginx -t
  mkdir -p /etc/nginx/snippets 2>/dev/null || true
  [[ -f /etc/nginx/snippets/decoy-headers.conf ]] || cat > /etc/nginx/snippets/decoy-headers.conf <<'EOF'
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "SAMEORIGIN" always;
add_header Referrer-Policy "no-referrer-when-downgrade" always;
EOF

  # index.html: login-реплики из DECOY_LOGIN_DIR, статика из DECOY_TPL_DIR
  if [[ "$tpl" != "custom" ]]; then
    local tpl_src="$DECOY_TPL_DIR/$tpl.html"
    is_login_template "$tpl" && tpl_src="$DECOY_LOGIN_DIR/$tpl.html"
    if [[ -f "$tpl_src" ]]; then
      # Всегда заменяем старую страницу: иначе при смене шаблона
      # старый index.html может остаться незатронутым.
      rm -f "$root/index.html" 2>/dev/null || true
      if ! cp -f "$tpl_src" "$root/index.html" 2>/dev/null; then
        warn "Не удалось применить decoy-шаблон $tpl к $root"
        return 1
      fi
    elif [[ "$tpl" != redirect && "$tpl" != locked ]]; then
      cp -f "$DECOY_TPL_DIR/default.html" "$root/index.html" 2>/dev/null || true
    fi
    chown www-data:www-data "$root/index.html" 2>/dev/null || true
  fi

  # Шаблон отдаётся с HTTP 404 через внутренний переход: прямой
  # server-level return 404 зацикливает error_page и показывает nginx 404.
  local extra=""
  [[ "$opt_status404" == "1" ]] && extra='    error_page 418 =404 @stack_decoy_404;
    return 418;
    location @stack_decoy_404 { try_files /index.html =404; }'
  case "$tpl" in
    redirect)
      [[ -z "$opt_redir" ]] && opt_redir="https://www.google.com/"
      extra="    return 302 $opt_redir;"
      ;;
    locked)
      extra='    add_header WWW-Authenticate "Basic realm=Restricted" always;
    return 401;'
      ;;
  esac

  # UA-свитч: сканерам/ботам — пустая 404 (в лог попадает → банов не миновать)
  local ua_block=""
  if [[ "$opt_ua404" == "1" && "$tpl" != "redirect" && "$tpl" != "locked" ]]; then
    ua_block='    if ($http_user_agent ~* (curl|wget|python|scrapy|httpclient|okhttp|go-http|libwww|zgrab|nikto|dirbuster|gobuster|wfuzz|nuclei|masscan|headless|bot|spider|crawler|scanner)) { return 404; }'
  fi

  # shellcheck disable=SC2154 # \$uri/\$args — переменные nginx, не bash
  local body
  body=$(cat <<EOF
server {
    listen 127.0.0.1:$port ssl;
    server_name $dom;
    ssl_certificate     $cert;
    ssl_certificate_key $key;
    include /etc/nginx/snippets/decoy-headers.conf;
    root $root;
    index index.html;
    access_log $DECOY_LOG_ACCESS decoy_ext;
    error_log  /var/log/nginx/decoy-error.log;
$extra
$ua_block
    location = /robots.txt { return 200 "User-agent: *\nDisallow: /\n"; }
    location ~ ^/(admin|wp-admin|wp-login\.php|\.env|\.git|api/debug|phpmyadmin|configuration\.php|actuator)(/|\$|\?) { return 404; }
    location / { try_files \$uri \$uri/ /index.html; }
    location = /login { limit_except POST { deny all; } return 401; }
}
EOF
)

  stack_ensure
  stack_del_decoy "$dom"   # замена блока того же домена (upsert)
  {
    # ВАЖНО: domain= держим ПОСЛЕДНИМ ключом — парсеры маркера на это рассчитаны
    echo "# >>> decoy port=$port root=$root cert=$cert key=$key tpl=$tpl ua404=$opt_ua404 status404=$opt_status404 domain=$dom"
    echo "$body"
    echo "# <<< decoy port=$port domain=$dom"
  } >> "$STACK_CONF"
}

# Для Xray fallback входящий TLS уже расшифрован, поэтому dest должен быть
# обычным HTTP, а не вторым TLS-соединением. Иначе браузер получает
# ERR_HTTP2_PROTOCOL_ERROR/400. Создаём отдельный plain listener с тем же root.
mk_plain_fallback_decoy() {   # <port> <domain> <root>
  local port="$1" dom="$2" root="$3"
  [[ "$port" =~ ^[0-9]+$ && "$dom" && "$root" ]] || return 1
  stack_ensure
  stack_del_decoy "$dom" "fallback-plain" 2>/dev/null || true
  # shellcheck disable=SC2154 # \\$uri — переменная nginx в heredoc
  {
    echo "# >>> fallback-plain port=$port root=$root domain=$dom"
    cat <<EOF
server {
    listen 127.0.0.1:$port;
    server_name $dom;
    root $root;
    index index.html;
    include /etc/nginx/snippets/decoy-headers.conf;
    access_log $DECOY_LOG_ACCESS decoy_ext;
    error_log /var/log/nginx/decoy-error.log;
    location = /robots.txt { return 200 "User-agent: *\\nDisallow: /\\n"; }
    location / { try_files \\$uri \\$uri/ /index.html; }
}
EOF
    echo "# <<< fallback-plain port=$port domain=$dom"
  } >> "$STACK_CONF"
  nginx_reload
}

# =====================================================================
