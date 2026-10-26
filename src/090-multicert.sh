# МУЛЬТИСЕРТ (единый серт на все домены стека) + сохранение email LE
# =====================================================================
le_email_load() {
  [[ "$EMAIL" =~ ^[^@]+@[^@]+\.[^@]+$ ]] && return 0
  EMAIL=""
  [[ -s "$LE_EMAIL_FILE" ]] && EMAIL=$(head -n1 "$LE_EMAIL_FILE" 2>/dev/null | tr -d '[:space:]')
  [[ "$EMAIL" =~ ^[^@]+@[^@]+\.[^@]+$ ]] && return 0
  EMAIL=""
  return 1
}
le_email_save() {
  local e="${1:-$EMAIL}"
  [[ -z "$e" ]] && return 1
  mkdir -p "$(dirname "$LE_EMAIL_FILE")" 2>/dev/null || true
  printf '%s\n' "$e" > "$LE_EMAIL_FILE" 2>/dev/null || return 1
  chmod 600 "$LE_EMAIL_FILE" 2>/dev/null || true
  EMAIL="$e"
  return 0
}
le_email_forget() {
  rm -f "$LE_EMAIL_FILE" 2>/dev/null || true
  EMAIL=""
}

# --- Режим выпуска сертификатов (A/B) -----------------------------------
#   A = одна линия на всё (имя = домен панели, SAN = все домены)
#   B = линия на базовый домен (разные базовые → разные линии all.<база>)
# Обе ветки реализованы: роутинг доменов — cert_line_for/cert_domains_add,
# выпуск — cert_batch_flush (обход линий).
# Совместимость со старым мультисертом (live/stack-multi): домены → stack-domains.txt
cert_multi_compat_migrate() {
  [[ -s "/root/stack-multi-cert-domains.txt" ]] || return 0
  local d
  while IFS= read -r d; do
    d="$(printf '%s' "$d" | tr -d '[:space:]')"
    [[ -z "$d" ]] && continue
    cert_domains_add "$d"
  done < "/root/stack-multi-cert-domains.txt"
  mv "/root/stack-multi-cert-domains.txt" "/root/stack-multi-cert-domains.txt.migrated" 2>/dev/null || true
  log "Старый мультисписок перенесён в $CERT_DOMAINS_FILE (линия live/stack-multi не тронута — уберёт п.10.13)"
}

cert_mode_load() {
  CERT_MODE=""
  if [[ -f "$CERT_MODE_FILE" ]]; then
    CERT_MODE=$(head -n1 "$CERT_MODE_FILE" 2>/dev/null | tr -d '[:space:]')
    if [[ "$CERT_MODE" == "A" || "$CERT_MODE" == "B" ]]; then
      return 0
    fi
    CERT_MODE=""
  fi
  # Автоопределение для существующего стека: есть stack-domains.txt →
  # значит работала одна линия → режим A. Пишем молча.
  if [[ -s "$CERT_DOMAINS_FILE" ]]; then
    CERT_MODE="A"
    mkdir -p "$(dirname "$CERT_MODE_FILE")" 2>/dev/null || true
    printf '%s\n' "$CERT_MODE" > "$CERT_MODE_FILE" 2>/dev/null || true
    chmod 600 "$CERT_MODE_FILE" 2>/dev/null || true
  fi
  cert_multi_compat_migrate
  return 0
}

cert_mode_save() {
  local m="${1:-$CERT_MODE}"
  [[ "$m" != "A" && "$m" != "B" ]] && return 1
  mkdir -p "$(dirname "$CERT_MODE_FILE")" 2>/dev/null || true
  printf '%s\n' "$m" > "$CERT_MODE_FILE" 2>/dev/null || return 1
  chmod 600 "$CERT_MODE_FILE" 2>/dev/null || true
  CERT_MODE="$m"
  return 0
}

# Краткое описание режимов (для меню)
cert_mode_describe() {
  echo
  echo -e "${B}  A) Одна линия на всё${N}"
  echo "     Имя: <домен панели>. SAN: домен панели + ВСЕ домены инбаундов."
  echo -e "     ${G}+${N} Проще: одна линия, один список"
  echo -e "     ${R}-${N} Если один домен не валидируется - ВЕСЬ перевыпуск падает"
  echo -e "     ${R}-${N} Лимит 100 SAN на серт"
  echo -e "     ${R}-${N} Разные DNS-провайдеры (Cloudflare + Route53) - сложнее"
  echo
  echo -e "${B}  B) Линия на базовый домен${N} ${Y}(рекомендуется)${N}"
  echo "     Имя: <домен панели> для доменов той же базы."
  echo "     Домены других баз - отдельные линии (имя = сам домен)."
  echo -e "     ${G}+${N} Устойчиво: битый домен не валит остальные"
  echo -e "     ${G}+${N} Разные DNS-провайдеры - естественно"
  echo -e "     ${G}+${N} Нет риска упереться в лимит SAN"
  echo -e "     ${R}-${N} Сложнее: несколько линий, разные сроки обновления"
  echo
}

# Интерактивный вопрос про режим. В не-TTY сразу выходит.
# $1 == "force" — спрашивать, даже если уже задан.
cert_mode_ask() {
  local force="${1:-}"
  [[ -t 0 ]] || return 0
  cert_mode_load
  if [[ -n "$CERT_MODE" && "$force" != "force" ]]; then
    return 0
  fi
  echo
  echo -e "${B}+- Логика выпуска сертификатов -+${N}"
  cert_mode_describe
  local cur="${CERT_MODE:-B}"
  local m=""
  ask m "Выбор [A/B]" "$cur" '^[ABab]$'
  m="${m^^}"
  cert_mode_save "$m"
  log "Режим: $m"
  if [[ "$m" == "B" ]]; then
    log "Режим B: домены вне базы панели пойдут в отдельные линии all.<база> (пересборка — п.10.9)"
  fi
  return 0
}

# Реальное наличие wildcard, а не только флаг wildcard-domain.
cert_wildcard_valid() {
  local base="${1:-${WILDCARD_DOMAIN:-}}" pem
  [[ -n "$base" ]] || return 1
  pem="/etc/letsencrypt/live/$base/fullchain.pem"
  [[ -f "$pem" ]] || return 1
  openssl x509 -noout -ext subjectAltName -in "$pem" 2>/dev/null \
    | grep -qE "DNS:\*\.${base//./\\.}([,[:space:]]|$)"
}

# Явный тип сертификатов для первоначальной установки/п.1.
# $1 == force — спрашивать заново даже при выборе в текущем shell.
cert_type_ask() {
  local force="${1:-}" cm=""
  [[ -t 0 ]] || { [[ -n "${CERT_MODE_CHOICE:-}" ]] || CERT_MODE_CHOICE="personal"; return 0; }
  if [[ -n "${CERT_MODE_CHOICE:-}" && "$force" != "force" ]]; then return 0; fi
  echo
  echo -e "${B}  Сертификаты: тип выпуска и линии${N}"
  echo "  1) Wildcard Cloudflare DNS-01 + A: одна линия на всё"
  echo "  2) Wildcard Cloudflare DNS-01 + B: линия на базовый домен"
  echo "  3) Персональные HTTP-01 + A: одна линия на всё"
  echo "  4) Персональные HTTP-01 + B: линия на базовый домен"
  if [[ -n "${WILDCARD_DOMAIN:-}" ]]; then
    if cert_wildcard_valid "$WILDCARD_DOMAIN"; then
      echo -e "  ${G}✓ Реальный wildcard *.$WILDCARD_DOMAIN найден${N}"
    else
      echo -e "  ${Y}! Флаг wildcard есть, но реальный cert *.$WILDCARD_DOMAIN не найден${N}"
    fi
  fi
  ask cm "Выбор [1/4]" "2" '^[1-4]$'
  case "$cm" in
    1) CERT_MODE_CHOICE="wildcard"; cert_mode_save A ;;
    2) CERT_MODE_CHOICE="wildcard"; cert_mode_save B ;;
    3) CERT_MODE_CHOICE="personal"; cert_mode_save A ;;
    4) CERT_MODE_CHOICE="personal"; cert_mode_save B ;;
  esac
  if [[ "$CERT_MODE_CHOICE" == "wildcard" ]]; then
    log "Тип сертификатов: wildcard Cloudflare DNS-01 (линии: $CERT_MODE)"
    if [[ -n "${WILDCARD_DOMAIN:-}" ]] && ! cert_wildcard_valid "$WILDCARD_DOMAIN"; then
      warn "Выбран wildcard, но реального сертификата *.$WILDCARD_DOMAIN нет."
      cert_wildcard_issue "$WILDCARD_DOMAIN" || warn "Wildcard не выпущен — причина показана выше; выбор сохранён."
    elif [[ -z "${WILDCARD_DOMAIN:-}" ]]; then
      cert_wildcard_issue || warn "Wildcard не выпущен — причина показана выше; выбор сохранён."
    fi
  else
    log "Тип сертификатов: персональные HTTP-01 (линии: $CERT_MODE)"
  fi
}

cert_mode_menu() {
  cert_mode_load
  line; echo -e "${B}   ЛОГИКА ВЫПУСКА СЕРТИФИКАТОВ${N}"; line
  echo "  Текущий режим: ${CERT_MODE:-<не задан>}"
  cert_mode_ask force
  echo
  echo "  Тип сертификатов выбирается при запуске п.1/первоначальной установке."
  pause
}

cert_multi_name_resolve() {
  [[ -n "$CERT_MULTI_NAME" ]] && return 0
  local pd="${PANEL_DOMAIN:-}"
  [[ -z "$pd" && -n "$XUI_DB" && -f "$XUI_DB" ]] && pd=$(xui_get webDomain 2>/dev/null || true)
  [[ -z "$pd" || "$pd" == "null" ]] && return 1
  CERT_MULTI_NAME="$pd"
  return 0
}


# =====================================================================
