# ─────────────────────────────────────────────────────────────────────────────
# 🤖 TG-БОТ (tg-stack-bot) — ВЫХОД В TELEGRAM
# Меню «TG-выход» из бота убрано: режим ведётся ТОЛЬКО отсюда (SSH).
# State: /root/.tg-stack-bot-out.env — бот читает его на лету (по mtime,
# рестарт бота не нужен). Правки делаются в xrayTemplateConfig (переживают
# пересборку config.json панелью): локальный socks-инбаунд tgbot-in на
# 127.0.0.1:<порт> + правило роутинга на выбранный аутбаунд. Перед каждой
# правкой — бэкап config.json и БД в /root/stack-backups. Включение — только
# после живой проверки (HTTP 204 через локальный socks), иначе полный откат.
# ─────────────────────────────────────────────────────────────────────────────
BOT_OUT_FILE="/root/.tg-stack-bot-out.env"
BOT_SVC="tg-stack-bot"
BOT_SOCKS_IN="tgbot-in"
BOT_SOCKS_OUT="tgbot-out"
BOT_XRAY_CFG="/usr/local/x-ui/bin/config.json"

botout_state_load() { # state бота → BO_MODE/BO_TAG/BO_PORT/BO_SOCKS/BO_OURS
  BO_MODE="direct"; BO_TAG=""; BO_PORT=""; BO_SOCKS=""; BO_OURS=0
  [[ -f "$BOT_OUT_FILE" ]] || return 0
  BO_MODE=$(grep -a '^TG_OUT_MODE=' "$BOT_OUT_FILE" | tail -1 | cut -d= -f2-)
  BO_TAG=$(grep -a '^TG_OUT_TAG=' "$BOT_OUT_FILE" | tail -1 | cut -d= -f2-)
  BO_PORT=$(grep -a '^TG_OUT_PORT=' "$BOT_OUT_FILE" | tail -1 | cut -d= -f2-)
  BO_SOCKS=$(grep -a '^TG_SOCKS_B64=' "$BOT_OUT_FILE" | tail -1 | cut -d= -f2-)
  BO_OURS=$(grep -a '^TG_OURS=' "$BOT_OUT_FILE" | tail -1 | cut -d= -f2-)
  [[ "$BO_MODE" =~ ^(direct|socks|outbound)$ ]] || BO_MODE="direct"
  [[ "$BO_OURS" =~ ^[01]$ ]] || BO_OURS=0
}
botout_state_write() { # атомарно, 600 — бот подхватит по mtime без рестарта
  local tmp="${BOT_OUT_FILE}.tmp"
  printf 'TG_OUT_MODE=%s\nTG_OUT_TAG=%s\nTG_OUT_PORT=%s\nTG_SOCKS_B64=%s\nTG_OURS=%s\n' \
    "$BO_MODE" "$BO_TAG" "$BO_PORT" "$BO_SOCKS" "$BO_OURS" > "$tmp"
  chmod 600 "$tmp" 2>/dev/null || true
  mv "$tmp" "$BOT_OUT_FILE"
}
botout_tpl_get() { # шаблон из БД — ПЕРВАЯ строка ключа (панель читает её через GORM First()); дубликаты ключа игнорируем
  [[ -n "${XUI_DB:-}" && -f "$XUI_DB" ]] || detect_env >/dev/null 2>&1 || true
  [[ -n "${XUI_DB:-}" && -f "$XUI_DB" ]] || { err "БД панели (x-ui.db) не найдена"; return 1; }
  local t v
  t=$(sqlite3 -cmd ".timeout 1000" "$XUI_DB" "SELECT value FROM settings WHERE key='xrayTemplateConfig' ORDER BY id ASC LIMIT 1;" 2>/dev/null)
  if [[ -z "$t" ]]; then
    warn "xrayTemplateConfig отсутствует — создаю из рабочего config.json (инбаунды из БД убираются, api остаётся)"
    t=$(jq -c '.inbounds = [.inbounds[] | select(.tag=="api")]' "$BOT_XRAY_CFG" 2>/dev/null) || { err "не удалось прочитать $BOT_XRAY_CFG"; return 1; }
    [[ -n "$t" ]] || { err "пустой шаблон из config.json"; return 1; }
    v=$(printf '%s' "$t" | sed "s/'/''/g")
    sqlite3 -cmd ".timeout 2000" "$XUI_DB" "INSERT OR REPLACE INTO settings (key,value) VALUES ('xrayTemplateConfig','$v');" 2>/dev/null \
      || { err "не удалось записать созданный шаблон в БД"; return 1; }
    log "xrayTemplateConfig создан из текущего конфига"
  fi
  printf '%s' "$t"
}
botout_backup() { # бэкап конфига и БД перед правкой шаблона
  local ts; ts=$(date +%Y%m%d-%H%M%S)
  mkdir -p "$BACKUP_DIR" 2>/dev/null || true
  cp -a "$BOT_XRAY_CFG" "$BACKUP_DIR/xray-config.pre-botout-$ts.json" || return 1
  [[ -n "${XUI_DB:-}" && -f "$XUI_DB" ]] && cp -a "$XUI_DB" "$BACKUP_DIR/x-ui.pre-botout-$ts.db"
  return 0
}
botout_free_port() { # первый свободный из 10808-10810 → stdout
  local p
  for p in 10808 10809 10810; do
    if ! ss -ltn 2>/dev/null | awk '{print $4}' | grep -qE ":${p}$"; then printf '%s' "$p"; return 0; fi
  done
  return 1
}
botout_apply() { # $1=add|remove $2=tag $3=port(add) $4=ours $5=outboundJSON(""=существующий тег)
  local op=$1 tag=$2 port=$3 ours=${4:-0} objson=${5:-} newc v obArgs=(--argjson ob null)
  botout_backup || { err "не удалось сделать бэкап перед правкой — отменяю"; return 1; }
  [[ -n "$objson" ]] && obArgs=(--argjson ob "$objson")
  if [[ "$op" == "add" ]]; then
    newc=$(botout_tpl_get | jq -c --arg inb "$BOT_SOCKS_IN" --arg out "$tag" --argjson port "$port" "${obArgs[@]}" '
      del(.inbounds[] | select(.tag == $inb))
      | .routing.rules = ((.routing.rules // []) | map(select(((.inboundTag // []) | index($inb)) | not)))
      | if $ob != null then
          .outbounds = (((.outbounds // []) | map(select(.tag != $out))) + [($ob | .tag = $out)])
        else . end
      | .inbounds += [{listen:"127.0.0.1", port:$port, protocol:"socks", tag:$inb, settings:{auth:"noauth", udp:false}}]
      | .routing.rules = ([{type:"field", inboundTag:[$inb], outboundTag:$out}] + .routing.rules)
    ') || { err "jq не смог изменить шаблон"; return 1; }
  else
    if [[ "$ours" == "1" && -n "$tag" ]]; then
      newc=$(botout_tpl_get | jq -c --arg inb "$BOT_SOCKS_IN" --arg out "$tag" '
        del(.inbounds[] | select(.tag == $inb))
        | del(.outbounds[] | select(.tag == $out))
        | .routing.rules = ((.routing.rules // []) | map(select(((.inboundTag // []) | index($inb)) | not)))
      ') || { err "jq не смог изменить шаблон"; return 1; }
    else
      newc=$(botout_tpl_get | jq -c --arg inb "$BOT_SOCKS_IN" '
        del(.inbounds[] | select(.tag == $inb))
        | .routing.rules = ((.routing.rules // []) | map(select(((.inboundTag // []) | index($inb)) | not)))
      ') || { err "jq не смог изменить шаблон"; return 1; }
    fi
  fi
  [[ -n "$newc" ]] || { err "пустой результат после правки шаблона — БД не менял"; return 1; }
  printf '%s\n' "$newc" | jq -e '.inbounds and .outbounds and .routing' >/dev/null 2>&1 \
    || { err "невалидный шаблон после правки — БД не менял"; return 1; }
  v=$(printf '%s' "$newc" | sed "s/'/''/g")
  # Пишем В ПЕРВУЮ строку ключа (её читает панель — GORM First()) и вычищаем
  # дубликаты: старый бот-код делал INSERT OR REPLACE без UNIQUE по key и надувал
  # ключ «склейками» шаблонов; одна строка сходится при любой семантике чтения.
  local chg dup
  chg=$(sqlite3 -cmd ".timeout 2000" "$XUI_DB" \
    "UPDATE settings SET value='$v' WHERE id=(SELECT MIN(id) FROM settings WHERE key='xrayTemplateConfig'); SELECT changes();" 2>/dev/null | tail -1)
  if [[ "$chg" == "0" ]]; then
    sqlite3 -cmd ".timeout 2000" "$XUI_DB" "INSERT INTO settings (key,value) VALUES ('xrayTemplateConfig','$v');" >/dev/null 2>&1 \
      || { err "Не удалось записать шаблон в БД"; return 1; }
  fi
  dup=$(sqlite3 -cmd ".timeout 2000" "$XUI_DB" \
    "DELETE FROM settings WHERE key='xrayTemplateConfig' AND id > (SELECT MIN(id) FROM settings WHERE key='xrayTemplateConfig'); SELECT changes();" 2>/dev/null | tail -1)
  [[ "${dup:-0}" =~ ^[0-9]+$ && "$dup" != "0" ]] && log "Вычищено дубликатов xrayTemplateConfig: $dup (панель работает с одной строкой)"
  log "Перезапускаю x-ui (Xray пересоберёт конфиг из шаблона)…"
  systemctl restart x-ui >/dev/null 2>&1 || true
  sleep 3
  return 0
}
botout_verify() { # $1=port → 0, если socks слушается и через него есть выход (204); до 3 попыток
  local port=$1 code try
  for try in 1 2 3; do
    if ss -ltn 2>/dev/null | awk '{print $4}' | grep -qE ":${port}$"; then
      code=$(curl -sk -m 12 --proxy "socks5h://127.0.0.1:${port}" -o /dev/null -w '%{http_code}' "https://www.google.com/generate_204" 2>/dev/null)
      [[ "$code" == "204" ]] && return 0
    fi
    sleep 3
  done
  return 1
}
botout_bot_note() { # бот забирает state сам (mtime); сообщаем только о нестандартных случаях
  if systemctl is-active --quiet "$BOT_SVC" 2>/dev/null; then
    log "Бот подхватит выход на лету (state $BOT_OUT_FILE), рестарт не нужен"
  else
    warn "Бот ($BOT_SVC) сейчас не запущен — применит режим при старте"
  fi
}
bot_svc_installed() { systemctl cat "$BOT_SVC" >/dev/null 2>&1; }
bot_toggle() { # вкл/выкл самого бота: enable --now / disable --now
  if ! bot_svc_installed; then
    err "Юнит $BOT_SVC.service не найден — бот не установлен"
    return 1
  fi
  local yn="n"
  if systemctl is-active --quiet "$BOT_SVC" 2>/dev/null; then
    askyn yn "Выключить бота? (systemctl disable --now $BOT_SVC — останов сейчас + без автозапуска при ребуте; режим TG-выхода сохранится)" "n"
    [[ "$yn" == "true" ]] || { warn "Отменено — бот продолжает работать"; return 1; }
    if systemctl disable --now "$BOT_SVC" >/dev/null 2>&1; then
      ok "Бот выключен (stop + disable). State $BOT_OUT_FILE не тронут — включишь через этот же пункт"
    else
      err "Не удалось остановить $BOT_SVC — смотри journalctl -u $BOT_SVC"
      return 1
    fi
  else
    askyn yn "Включить бота? (systemctl enable --now $BOT_SVC — старт сейчас + автозапуск при ребуте)" "n"
    [[ "$yn" == "true" ]] || { warn "Отменено — бот остаётся выключенным"; return 1; }
    if ! systemctl enable --now "$BOT_SVC" >/dev/null 2>&1; then
      err "Не удалось запустить $BOT_SVC — последние строки журнала:"
      journalctl -u "$BOT_SVC" -n 10 --no-pager 2>/dev/null | sed 's/^/    /'
      return 1
    fi
    local i
    for i in 1 2 3 4 5; do systemctl is-active --quiet "$BOT_SVC" 2>/dev/null && break; sleep 1; done
    if systemctl is-active --quiet "$BOT_SVC" 2>/dev/null; then
      ok "Бот запущен (start + enable)"
      botout_bot_note
    else
      warn "Юнит стартовал и сразу упал — последние строки журнала:"
      journalctl -u "$BOT_SVC" -n 10 --no-pager 2>/dev/null | sed 's/^/    /'
      return 1
    fi
  fi
}
botout_enable_outbound() { # $1=tag $2=outboundJSON(""=существующий тег) — вкл только после проверки 204
  local tag=$1 ob=${2:-} port
  port=$(botout_free_port) || { err "нет свободного локального порта (10808-10810)"; return 1; }
  botout_apply add "$tag" "$port" 1 "$ob" || { err "правка шаблона не прошла — выход не изменён"; return 1; }
  if botout_verify "$port"; then
    BO_MODE="outbound"; BO_TAG="$tag"; BO_PORT="$port"; BO_SOCKS=""
    [[ "$tag" == "$BOT_SOCKS_OUT" ]] && BO_OURS=1 || BO_OURS=0
    botout_state_write
    ok "TG-выход: аутбаунд «$tag» (локальный socks 127.0.0.1:$port), проверка 204 пройдена"
    botout_bot_note
    return 0
  fi
  warn "Через аутбаунд выхода в интернет нет (проверка 204 не прошла) — откатываю правки"
  botout_apply remove "$tag" "" 1 "" >/dev/null 2>&1 || true
  err "Выход не изменён — бот работает как работал. Проверь аутбаунд: адрес, порт, UUID, TLS/SNI"
  return 1
}
botout_disable() { # убрать наши правки из шаблона (если были) и вернуть прямой
  botout_state_load
  if [[ "$BO_MODE" == "outbound" || "$BO_OURS" == "1" ]]; then
    botout_apply remove "$BO_TAG" "" "$BO_OURS" "" || { err "правки не убраны — state не менял"; return 1; }
  fi
  BO_MODE="direct"; BO_TAG=""; BO_PORT=""; BO_SOCKS=""; BO_OURS=0
  botout_state_write
  ok "TG-выход: прямой (наши правки из Xray убраны)"
  botout_bot_note
}
botout_set_socks() { # свой SOCKS — включается только после живой проверки
  local u="" code
  ask u "URL прокси (socks5h://user:pass@зарубежный-сервер:1080)" "" '^(socks5h?|https?)://[^[:space:]]+$'
  code=$(curl -sk -m 12 --proxy "$u" -o /dev/null -w '%{http_code}' "https://www.google.com/generate_204" 2>/dev/null)
  if [[ "$code" == "204" ]]; then
    BO_MODE="socks"; BO_SOCKS=$(printf '%s' "$u" | base64 -w0 2>/dev/null || printf '%s' "$u" | base64)
    BO_TAG=""; BO_PORT=""; BO_OURS=0
    botout_state_write
    ok "TG-выход: SOCKS $u — проверка 204 пройдена"
    botout_bot_note
  else
    err "Через этот SOCKS выхода нет (код: ${code:-нет ответа}) — режим не изменён"
  fi
}
botout_pick_existing() { # список аутбаундов из шаблона (кроме freedom/blackhole) → OUT_TAG
  local t tag proto i=1
  declare -a _btags=() _bprotos=()
  t=$(botout_tpl_get) || return 1
  echo
  echo -e "${B}Аутбаунды в конфиге Xray:${N}"
  while IFS=$'\t' read -r tag proto; do
    [[ -z "$tag" ]] && continue
    [[ "$proto" == "freedom" || "$proto" == "blackhole" ]] && continue
    _btags+=("$tag"); _bprotos+=("$proto")
    printf '  %2d) %-24s (%s)\n' "$i" "$tag" "$proto"; i=$((i+1))
  done < <(printf '%s' "$t" | jq -r '.outbounds[]? | [(.tag // ""), (.protocol // "")] | @tsv' 2>/dev/null)
  if (( ${#_btags[@]} == 0 )); then
    warn "Подходящих аутбаундов нет (только freedom/blackhole) — добавь свой через п.2"
    return 1
  fi
  local c=""; ask c "Через какой аутбаунд направить бота" "1" '^[0-9]+$'
  (( c >= 1 && c <= ${#_btags[@]} )) || { err "Нет такого пункта"; return 1; }
  OUT_TAG="${_btags[$((c-1))]}"
}
botout_add_json() { # свой аутбаунд из JSON (тег станет tgbot-out)
  local src="" ob="" ojt yn="n"
  echo "Вставь JSON аутбаунда ОДНОЙ строкой или укажи путь к файлу (/root/out.json)."
  ask src "JSON или путь к файлу" "" ''
  [[ -z "$src" ]] && { warn "Пусто — отмена"; return 1; }
  if [[ -f "$src" ]]; then
    ob=$(cat "$src")
    log "Читаю JSON из файла $src"
  else
    ob="$src"
  fi
  printf '%s' "$ob" | jq -e '.tag and .protocol and .settings' >/dev/null 2>&1 \
    || { err "Это не валидный JSON аутбаунда (нужны tag, protocol, settings)"; return 1; }
  ojt=$(printf '%s' "$ob" | jq -r '.tag')
  echo "Тег «$ojt» будет заменён на $BOT_SOCKS_OUT; добавится локальный socks 127.0.0.1:<порт> и правило роутинга."
  askyn yn "Продолжить? (бэкап → правка шаблона → рестарт x-ui → проверка 204)" "n"
  [[ "$yn" == "true" ]] || { warn "Отменено"; return 1; }
  botout_enable_outbound "$BOT_SOCKS_OUT" "$ob"
}
botout_status() { # однострочный статус + состояние сервиса бота
  botout_state_load
  local m
  case "$BO_MODE" in
    outbound) m="📡 аутбаунд «$BO_TAG» · локальный socks 127.0.0.1:$BO_PORT" ;;
    socks)    m="🔌 свой SOCKS $(printf '%s' "$BO_SOCKS" | base64 -d 2>/dev/null)" ;;
    *)        m="✅ прямой (без прокси)" ;;
  esac
  echo "Режим: $m"
  if systemctl is-active --quiet "$BOT_SVC" 2>/dev/null; then
    echo "Бот: 🟢 запущен (правки подхватывает на лету)"
  else
    echo "Бот: 🔴 не запущен"
  fi
}
bot_out_menu() {
  while :; do
    line; echo -e "${B}   🤖 TG-БОТ — ВЫХОД В TELEGRAM${N}"; line
    botout_status
    echo
    echo "  1) Через существующий аутбаунд (список из конфига)"
    echo "  2) Добавить свой аутбаунд (JSON)"
    echo "  3) Свой SOCKS-прокси (URL)"
    echo "  4) Напрямую (убрать правки из Xray)"
    if systemctl is-active --quiet "$BOT_SVC" 2>/dev/null; then
      echo "  5) 🔴 Выключить бота (stop + disable)"
    else
      echo "  5) 🟢 Включить бота (start + enable)"
    fi
    echo "  0) Назад"
    local c=""; ask c "Выбор" "1" '^[0-5]$'
    case "$c" in
      1)
        if botout_pick_existing; then
          local t="$OUT_TAG" yn="n"
          askyn yn "Направить Telegram-трафик бота через «$t»? (бэкап → правка шаблона → рестарт x-ui, кратко; клиенты переподключатся)" "n"
          [[ "$yn" == "true" ]] && botout_enable_outbound "$t" ""
        fi
        pause ;;
      2) botout_add_json; pause ;;
      3) botout_set_socks; pause ;;
      4)
        local yn="n"
        askyn yn "Убрать локальный socks-инбаунд и правки из шаблона Xray, вернуть прямой выход?" "n"
        [[ "$yn" == "true" ]] && botout_disable
        pause ;;
      5) bot_toggle; pause ;;
      0) return 0 ;;
    esac
  done
}

