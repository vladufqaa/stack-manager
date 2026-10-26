# ФАЙЛЫ ЛИНИЙ СЕРТИФИКАТОВ (для режима B — несколько линий)
# =====================================================================
# В режиме A — одна линия, имя = домен панели, SAN = stack-domains.txt.
# В режиме B — несколько линий: cert-lines.txt (список имён) + файл на каждую.
# Для совместимости: cert_lines_load() в режиме A возвращает одну линию,
# читая домены из stack-domains.txt.

cert_line_file() {   # <line-name> → путь к файлу SAN этой линии
  printf '%s%s.domains' "$CERT_LINE_FILE_PREFIX" "$1"
}

# валидный домен: >=2 метки из [a-z0-9-], без ведущих/хвостовых дефисов.
# Отсекает мусор из файлов линий («0», обрезки), который раньше доезжал до ACME.
cert_domain_valid() {
  local d="$1"
  [[ "$d" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)+$ ]]
}

# валидное имя линии: домен ИЛИ all.<домен>
cert_line_name_valid() {
  local n="$1"
  [[ "$n" == all.* ]] && n="${n#all.}"
  cert_domain_valid "$n"
}

# Загрузка списка линий в массив CERT_LINES
cert_lines_load() {
  CERT_LINES=()
  cert_mode_load >/dev/null 2>&1 || true
  if [[ "${CERT_MODE:-A}" == "A" ]]; then
    # Режим A: одна линия (имя = домен панели) — вычисляем при необходимости
    local nm=""
    nm=$(cert_multi_name_resolve >/dev/null 2>&1; printf '%s' "${CERT_MULTI_NAME:-}")
    [[ -z "$nm" ]] && nm=$(xui_get webDomain 2>/dev/null || true)
    [[ -n "$nm" && "$nm" != "null" ]] && CERT_LINES=("$nm")
    return 0
  fi
  # Режим B: список из файла. Если список линий потерян, восстанавливаем
  # его по cert-line-*.domains и по установленным certbot live-каталогам.
  if [[ ! -f "$CERT_LINES_FILE" ]]; then
    local _lf _ln
    for _lf in "${CERT_LINE_FILE_PREFIX}"*.domains; do
      [[ -f "$_lf" ]] || continue
      _ln="${_lf#${CERT_LINE_FILE_PREFIX}}"; _ln="${_ln%.domains}"
      cert_line_name_valid "$_ln" && CERT_LINES+=("$_ln")
    done
    if [[ ${#CERT_LINES[@]} -gt 0 ]]; then
      cert_lines_save
      return 0
    fi
    # Старые установки режима B могли не иметь служебных файлов линий:
    # восстанавливаем их по существующим certbot live-каталогам. Выбор «4»
    # в мастере означает personal+B, а не номер линии — линией является имя
    # сертификата (например vladufqaa.ru или all.example.net).
    local _lf _ln
    for _lf in /etc/letsencrypt/live/*/; do
      [[ -d "$_lf" ]] || continue
      _ln="$(basename "${_lf%/}")"
      [[ "$_ln" == "README" ]] && continue
      cert_line_name_valid "$_ln" || continue
      [[ " ${CERT_LINES[*]} " == *" $_ln "* ]] && continue
      CERT_LINES+=("$_ln")
      local _df; _df="$(cert_line_file "$_ln")"
      [[ -s "$_df" ]] || printf '%s\n' "$_ln" > "$_df"
    done
    # Также подхватываем старый общий список, если certbot-каталоги были
    # переименованы или очищены после выпуска.
    if [[ -s "$CERT_DOMAINS_FILE" ]]; then
      local _d _line
      while IFS= read -r _d; do
        _d="$(printf '%s' "$_d" | tr -d '[:space:]')"; [[ -z "$_d" ]] && continue
        _line="$_d"
        [[ " ${CERT_LINES[*]} " == *" $_line "* ]] || CERT_LINES+=("$_line")
        local _df2; _df2="$(cert_line_file "$_line")"
        [[ -s "$_df2" ]] || printf '%s\n' "$_d" > "$_df2"
      done < "$CERT_DOMAINS_FILE"
    fi
    [[ ${#CERT_LINES[@]} -gt 0 ]] && cert_lines_save
    return 0
  fi
  local l
  while IFS= read -r l; do
    l="$(printf '%s' "$l" | tr -d '[:space:]')"
    [[ -z "$l" ]] && continue
    if ! cert_line_name_valid "$l"; then
      warn "cert-lines: имя линии «$l» не похоже на домен — пропуск (мусор в $CERT_LINES_FILE)"
      continue
    fi
    [[ " ${CERT_LINES[*]} " == *" $l "* ]] && continue
    CERT_LINES+=("$l")
  done < "$CERT_LINES_FILE"
  return 0
}

cert_lines_save() {
  mkdir -p "$(dirname "$CERT_LINES_FILE")" 2>/dev/null || true
  if [[ ${#CERT_LINES[@]} -eq 0 ]]; then
    : > "$CERT_LINES_FILE"
    return 0
  fi
  printf '%s\n' "${CERT_LINES[@]}" > "$CERT_LINES_FILE" 2>/dev/null || true
  chmod 600 "$CERT_LINES_FILE" 2>/dev/null || true
}

cert_lines_add() {   # <line-name>
  local n="$1"
  [[ -z "$n" ]] && return 0
  cert_lines_load
  [[ " ${CERT_LINES[*]} " == *" $n "* ]] && return 0
  CERT_LINES+=("$n")
  cert_lines_save
}

cert_lines_remove() {   # <line-name>
  local n="$1"
  [[ -z "$n" ]] && return 0
  cert_lines_load
  local -a out=() x
  for x in "${CERT_LINES[@]}"; do
    [[ "$x" == "$n" ]] && continue
    out+=("$x")
  done
  if [[ ${#out[@]} -ne ${#CERT_LINES[@]} ]]; then
    CERT_LINES=("${out[@]}")
    cert_lines_save
  fi
  # Удаляем и файл SAN этой линии
  rm -f "$(cert_line_file "$n")" 2>/dev/null || true
}

# Загрузка SAN линии в массив CERT_LINE_DOMAINS
# В режиме A для главной линии SAN = stack-domains.txt
declare -a CERT_LINE_DOMAINS=()
cert_line_domains_load() {   # <line-name>
  CERT_LINE_DOMAINS=()
  local n="$1"
  [[ -z "$n" ]] && return 0
  local f=""
  # Режим A: главная линия → читаем stack-domains.txt
  if [[ "${CERT_MODE:-A}" == "A" ]]; then
    local pn=""
    pn=$(xui_get webDomain 2>/dev/null || true)
    if [[ -n "$pn" && "$n" == "$pn" && -f "$CERT_DOMAINS_FILE" ]]; then
      f="$CERT_DOMAINS_FILE"
    fi
  fi
  [[ -z "$f" ]] && f=$(cert_line_file "$n")
  [[ -f "$f" ]] || return 0
  local d
  while IFS= read -r d; do
    d="$(printf '%s' "$d" | tr -d '[:space:]')"
    [[ -z "$d" ]] && continue
    if ! cert_domain_valid "$d"; then
      warn "cert-line «$n»: домен «$d» не похож на домен — пропуск (мусор в $f)"
      continue
    fi
    [[ " ${CERT_LINE_DOMAINS[*]} " == *" $d "* ]] && continue
    CERT_LINE_DOMAINS+=("$d")
  done < "$f"
  return 0
}

cert_line_domains_save() {   # <line-name>  (использует CERT_LINE_DOMAINS)
  local n="$1"
  [[ -z "$n" ]] && return 0
  # Режим A: главная линия → сохраняем в stack-domains.txt
  if [[ "${CERT_MODE:-A}" == "A" ]]; then
    local pn=""
    pn=$(xui_get webDomain 2>/dev/null || true)
    if [[ -n "$pn" && "$n" == "$pn" ]]; then
      mkdir -p "$(dirname "$CERT_DOMAINS_FILE")" 2>/dev/null || true
      if [[ ${#CERT_LINE_DOMAINS[@]} -eq 0 ]]; then
        : > "$CERT_DOMAINS_FILE"
      else
        printf '%s\n' "${CERT_LINE_DOMAINS[@]}" > "$CERT_DOMAINS_FILE" 2>/dev/null || true
      fi
      return 0
    fi
  fi
  # Режим B / обычный случай → отдельный файл
  local f; f=$(cert_line_file "$n")
  mkdir -p "$(dirname "$f")" 2>/dev/null || true
  if [[ ${#CERT_LINE_DOMAINS[@]} -eq 0 ]]; then
    : > "$f"
  else
    printf '%s\n' "${CERT_LINE_DOMAINS[@]}" > "$f" 2>/dev/null || true
  fi
  chmod 600 "$f" 2>/dev/null || true
}

cert_line_domains_add() {   # <line-name> <domain>
  local n="$1" d="$2"
  [[ -z "$n" || -z "$d" ]] && return 0
  cert_lines_add "$n"
  cert_line_domains_load "$n"
  [[ " ${CERT_LINE_DOMAINS[*]} " == *" $d "* ]] && return 0
  CERT_LINE_DOMAINS+=("$d")
  cert_line_domains_save "$n"
}

cert_line_domains_remove() {   # <line-name> <domain>
  local n="$1" d="$2"
  [[ -z "$n" || -z "$d" ]] && return 0
  cert_line_domains_load "$n"
  local -a out=() x
  for x in "${CERT_LINE_DOMAINS[@]}"; do
    [[ "$x" == "$d" ]] && continue
    out+=("$x")
  done
  if [[ ${#out[@]} -ne ${#CERT_LINE_DOMAINS[@]} ]]; then
    CERT_LINE_DOMAINS=("${out[@]}")
    cert_line_domains_save "$n"
  fi
}

# Определяет имя линии, которая должна содержать домен $1.
# В режиме A: всегда домен панели (одна линия).
# В режиме B:
#   - если домен в зоне базы панели → имя = домен панели (главная линия);
#   - если домен вне зоны → имя = all.<базовый-домен-домена> (доп. линия);
#     для доменов вида a.b.c.com «база» = b.c.com (последние две метки? нет —
#     база = две последние метки: c.com). Для доменов вида panel.a.com → a.com.
# То есть: главная линия = домен панели; доп. линии именуются all.<base>,
# где base = последние две метки домена (или весь домен, если меток меньше 3).
cert_line_for() {   # <domain> → печатает имя линии
  local d="$1"
  [[ -z "$d" ]] && return 1
  cert_mode_load >/dev/null 2>&1 || true
  local pd=""
  pd=$(xui_get webDomain 2>/dev/null || true)
  [[ -z "$pd" || "$pd" == "null" ]] && pd="${PANEL_DOMAIN:-}"
  if [[ -z "$pd" ]]; then
    # домен панели неизвестен → главной линии нет, вычислим по базе домена
    cert_mode_line_base "$d"
    return 0
  fi
  if [[ "${CERT_MODE:-A}" == "A" ]]; then
    printf '%s' "$pd"
    return 0
  fi
  # Режим B. Если включён wildcard, все домены его зоны должны жить
  # в одной линии wildcard, а не в отдельных линиях поддоменов.
  if [[ -z "${WILDCARD_DOMAIN:-}" && -f "$WILDCARD_STATE" ]]; then
    WILDCARD_DOMAIN=$(head -n 1 "$WILDCARD_STATE" 2>/dev/null | tr -d '[:space:]' || true)
  fi
  if [[ -n "${WILDCARD_DOMAIN:-}" && ( "$d" == "$WILDCARD_DOMAIN" || "$d" == *."$WILDCARD_DOMAIN" ) ]]; then
    printf '%s' "$WILDCARD_DOMAIN"
    return 0
  fi
  local pbase="${pd#*.}"
  [[ "$pbase" != *.* ]] && pbase="$pd"
  # домен панели сам (panel.exemple.xyz) → база exemple.xyz
  # домен в базе панели?
  if [[ "$d" == "$pd" || "$d" == "$pbase" || "$d" == *."$pbase" ]]; then
    printf '%s' "$pd"
    return 0
  fi
  # вне зоны панели → отдельная линия all.<base>
  cert_mode_line_base "$d"
}

# Вычисляет all.<base> для домена (base = последние две метки)
cert_mode_line_base() {   # <domain> → печатает all.<base>
  local d="$1"
  local IFS='.'
  local -a p
  read -r -a p <<<"$d"
  local n=${#p[@]}
  local base=""
  if (( n >= 3 )); then
    base="${p[n-2]}.${p[n-1]}"
  elif (( n == 2 )); then
    base="$d"
  else
    base="$d"
  fi
  printf 'all.%s' "$base"
}

# Миграция: разложить текущий stack-domains.txt по линиям (для B).
# В режиме A — оставляем как есть.

# Показать все линии с их SAN (для аудита/меню)

# =====================================================================
