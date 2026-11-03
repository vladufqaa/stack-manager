# ════════════════════════════════════════════════════════════════════
# 🤖 TG-БОТ — движок, встроенный в stack-manager (режим запуска --bot)
# Отдельного файла tg-stack-bot.sh больше нет: юнит tg-stack-bot.service
# запускает этот же скрипт: ExecStart=/usr/bin/env bash /root/stack-manager.sh --bot
# BOT_TOKEN/ADMIN_CHAT_ID — из EnvironmentFile=/root/.tg-stack-bot.env.
# «TG-выход» — state /root/.tg-stack-bot-out.env (пишет п.7 → 🤖 TG-бот),
# бот подхватывает правки на лету (по mtime), меню в боте нет.
# Переименовано относительно старого tg-stack-bot.sh: log → bot_log,
# fmt_bytes → bot_fmt_bytes (не пересекаться с функциями stack-manager).
# ════════════════════════════════════════════════════════════════════
bot_log() { echo "[$(date '+%F %T')] $*"; } # журнал бота (в старом tg-stack-bot.sh называлось log())
bot_init() { # конфиг, проверки и синглтон — ТОЛЬКО в режиме --bot
BOT_TOKEN="${BOT_TOKEN:-}"
ADMIN_CHAT_ID="${ADMIN_CHAT_ID:-}"
STACK_SCRIPT="$(readlink -f "$0")"  # бот встроен: источник = этот же скрипт
XUI_DB="/etc/x-ui/x-ui.db"
API="https://api.telegram.org/bot${BOT_TOKEN}"
TG_PROXY="${TG_PROXY:-}"   # legacy: статический SOCKS из env (если state не задан — используется он)
TG_PROXY_CUR="${TG_PROXY:-}" # фактический выход бота (state-файл ведёт stack-manager.sh, п.7 → TG-выход)
tgc() { # curl для Telegram API: через TG_PROXY_CUR, если задан; локальные вызовы (панель, nginx) идут напрямую
  if [[ -n "$TG_PROXY_CUR" ]]; then curl --proxy "$TG_PROXY_CUR" "$@"; else curl "$@"; fi
}
PENDING=""; PENDING_TS=0
OFFSET=0
WINDOW_MID=""; CUR_MENU="main"
CARD_FLAG="/run/tg-stack-card.flag"
CARD_PID=""
API_TOKEN_FILE="/root/.tg-api-token"
OUT_FILE="/root/.tg-stack-bot-out.env"   # state «TG-выход»: TG_OUT_MODE/TG_OUT_TAG/TG_OUT_PORT/TG_SOCKS_B64/TG_OURS — пишет stack-manager.sh, бот только читает
TG_OUT_MODE="direct"; TG_OUT_TAG=""; TG_OUT_PORT=""; TG_SOCKS_B64=""; TG_OURS=0
OUT_MTIME="0"                             # mtime state-файла: бот подхватывает правки из SSH-скрипта без рестарта
WIZ_STATE="/run/tg-stack-bot-wiz.env"
WIZ_MID=""; NEW_STEP=""; NEW_IN=""; NEW_GB=-1; NEW_DAYS=0; NEW_EMAIL=""; NEW_SUBID=""
E_EMAIL=""; E_STEP=""; E_IN=""; E_MID=""   # карточка клиента (просмотр/правка)
CL_PAGE=1; CL_PER=10  # пагинация списка клиентов (страница / клиентов на странице)

set -o errtrace
trap '[[ "$BASH_COMMAND" == *jq* ]] && bot_log "DEBUG: jq упал на строке $LINENO: $(awk "NR==$LINENO" "$0" 2>/dev/null | head -c 120)"' ERR
[[ -n "$BOT_TOKEN" ]] || { bot_log "BOT_TOKEN не задан — выходим"; exit 0; }
command -v jq >/dev/null || { bot_log "jq не найден"; exit 1; }
command -v flock >/dev/null || { bot_log "flock не найден (util-linux)"; exit 1; }

# ── отказоустойчивость: один экземпляр + курсор апдейтов ────────────────────
exec 9>/run/tg-stack-bot.lock   # синглтон: два экземпляра ловят 409 Conflict у Telegram
flock -n 9 || { bot_log "бот уже запущен (lock /run/tg-stack-bot.lock) — второй экземпляр не нужен"; exit 0; }
OFFSET_FILE="/run/tg-stack-bot.offset"  # курсор getUpdates переживает рестарт — старые нажатия кнопок не переигрываются
}
offset_save() { printf '%s' "$OFFSET" > "${OFFSET_FILE}.tmp" 2>/dev/null && mv -f "${OFFSET_FILE}.tmp" "$OFFSET_FILE" 2>/dev/null; }

# ── базовая отправка ────────────────────────────────────────────────────────
tg_send() { # $1=chat $2=text — служебное сообщение, всегда с кнопкой «🗑 Скрыть»
  local text="${2:-}" json
  (( ${#text} > 3500 )) && text="…${text: -3500}"
  json=$(jq -n --arg c "$1" --arg t "$text" --argjson kb "$KB_HIDE" \
    '{chat_id:$c,text:$t,reply_markup:{inline_keyboard:$kb}}')
  tgc -s --max-time 40 -X POST "$API/sendMessage" -H 'Content-Type: application/json' -d "$json" >/dev/null
}
tg_send_kb() { # $1=chat $2=text $3=inline_keyboard — возвращает message_id (пусто при ошибке)
  local json resp
  json=$(jq -n --arg c "$1" --arg t "$2" --argjson kb "$3" \
    '{chat_id:$c,text:$t,parse_mode:"HTML",reply_markup:{inline_keyboard:$kb}}')
  resp=$(tgc -s --max-time 40 -X POST "$API/sendMessage" -H 'Content-Type: application/json' -d "$json")
  jq -r '.result.message_id // empty' <<<"$resp" 2>/dev/null
}
tg_edit() { # $1=chat $2=mid $3=text(HTML) $4=inline_keyboard → 0/1 (not modified = успех)
  local json resp desc
  json=$(jq -n --arg c "$1" --arg m "$2" --arg t "$3" --argjson kb "$4" \
    '{chat_id:$c,message_id:($m|tonumber),text:$t,parse_mode:"HTML",reply_markup:{inline_keyboard:$kb}}')
  resp=$(tgc -s --max-time 40 -X POST "$API/editMessageText" -H 'Content-Type: application/json' -d "$json")
  [[ "$(jq -r '.ok // false' <<<"$resp" 2>/dev/null)" == "true" ]] && return 0
  desc=$(jq -r '.description // ""' <<<"$resp" 2>/dev/null)
  [[ "$desc" == *"not modified"* ]]
}
tg_confirm() { # $1=action $2=chat $3=question
  local json
  json=$(jq -n --arg c "$2" --arg t "⚠ $3" \
    '{chat_id:$c,text:$t,reply_markup:{inline_keyboard:[[
      {text:"✅ Подтвердить",callback_data:("confirm:"+$a)},
      {text:"❌ Отмена",callback_data:"cancel"}],
      [{"text":"🗑 Скрыть","callback_data":"hide"}]]}}' --arg a "$1")
  tgc -s --max-time 40 -X POST "$API/sendMessage" -H 'Content-Type: application/json' -d "$json" >/dev/null
}
tg_answer_cb() { tgc -s --max-time 15 "$API/answerCallbackQuery" -d "callback_query_id=$1" >/dev/null; }
tg_del() { tgc -s --max-time 15 "$API/deleteMessage" -d "chat_id=$1" -d "message_id=$2" >/dev/null; }
KB_HIDE='[[{"text":"🗑 Скрыть","callback_data":"hide"}]]'
hesc() { sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' <<<"$1"; }

# ── источник истины: stack-manager ──────────────────────────────────────────
strip_ansi() { sed -r 's/\x1b\[[0-9;]*[A-Za-z]//g; s/\r//g'; } # Telegram не понимает ANSI из stack-manager
run_stack() { timeout 300 bash -c "source '$STACK_SCRIPT'; detect_env; $1" 2>&1 | strip_ansi; }
run_check()  { timeout 300 bash "$STACK_SCRIPT" --check 2>&1 | strip_ansi; }

# ── форматирование ──────────────────────────────────────────────────────────
bot_fmt_bytes() { awk -v b="${1:-0}" 'BEGIN{u=b;s="Б";if(b>=1073741824){u=b/1073741824;s="ГБ"}else if(b>=1048576){u=b/1048576;s="МБ"}else if(b>=1024){u=b/1024;s="КБ"}printf "%.1f %s",u,s}'; }
fmt_age() { local s=${1:-0}
  if (( s < 90 )); then printf '%sс' "$s"
  elif (( s < 5400 )); then printf '%sм' $(( s/60 ))
  elif (( s < 172800 )); then printf '%sч' $(( s/3600 ))
  else printf '%sд' $(( s/86400 )); fi; }

# ── данные ──────────────────────────────────────────────────────────────────
panel_domain() { local d; d=$(sqlite3 "$XUI_DB" "SELECT value FROM settings WHERE key='subDomain';" 2>/dev/null); [[ -z "$d" ]] && d=$(hostname -f 2>/dev/null); printf '%s' "$d"; }
panel_base() { local p; p=$(sqlite3 "$XUI_DB" "SELECT value FROM settings WHERE key='webBasePath';" 2>/dev/null); printf '%s' "${p:-/vladufqa/}"; }
api_call() { # $1=method $2=path $3=json_body → тело ответа
  local tok dom bp url
  tok=$(cat "$API_TOKEN_FILE" 2>/dev/null)
  dom=$(panel_domain); bp=$(panel_base); bp=${bp%/}
  url="https://127.0.0.1:2904$bp$2"
  if [[ -n "${3:-}" ]]; then
    curl -sk --max-time 30 -X "$1" -H "Host: $dom" -H "Authorization: Bearer $tok" -H "Content-Type: application/json" -d "$3" "$url"
  else
    curl -sk --max-time 30 -X "$1" -H "Host: $dom" -H "Authorization: Bearer $tok" "$url"
  fi
}

render_card() {
  local xui="🔴" ngx="🔴" up l1 l2 l3 cores ram_u ram_t ram_p du dt dp conns awg="" ifc hs now age rx tx dom tgp
  systemctl is-active -q x-ui  2>/dev/null && xui="🟢"
  systemctl is-active -q nginx 2>/dev/null && ngx="🟢"
  up=$(uptime -p 2>/dev/null | sed 's/^up //;s/^ *//')
  read -r l1 l2 l3 _ < /proc/loadavg 2>/dev/null
  cores=$(nproc 2>/dev/null); cores=${cores:-1}
  read -r _ ram_t ram_u _ < <(free -m 2>/dev/null | awk '/^Mem:/')
  if [[ "${ram_t:-0}" -gt 0 ]]; then ram_p=$(( ram_u*100/ram_t )); else ram_p=0; fi
  read -r du dt < <(df -BM / 2>/dev/null | awk 'NR==2{gsub(/M/,"",$3);gsub(/M/,"",$2);print $3,$2}')
  if [[ "${dt:-0}" -gt 0 ]]; then dp=$(( du*100/dt )); else dp=0; fi
  conns=$(ss -tnH 'sport = :443' 2>/dev/null | grep -c .); conns=${conns:-0}
  now=$(date +%s)
  while read -r ifc; do
    hs=$(awg show "$ifc" latest-handshakes 2>/dev/null | awk '{print $2}' | sort -nr | head -1)
    if [[ -n "$hs" && "$hs" != "0" ]]; then age=$(( now - hs )); (( age < 0 )) && age=0; awg+="${awg:+ · }<code>$ifc</code>👋$(fmt_age $age)"
    else awg+="${awg:+ · }<code>$ifc</code>👋—"; fi
  done < <(awg show 2>/dev/null | awk '/^interface:/{print $2}')
  [[ -z "$awg" ]] && awg="нет интерфейсов"
  read -r rx tx < <(awk 'NR>2 && $1!~/lo:/ {rx+=$2; tx+=$10} END{print rx+0, tx+0}' /proc/net/dev 2>/dev/null)
  dom=$(hostname -f 2>/dev/null); dom=${dom:-$(hostname)}
  tgp="прямой"; [[ -n "$TG_PROXY_CUR" ]] && tgp="прокси <code>$(hesc "$TG_PROXY_CUR")</code>"
  printf '🖥 <b>%s</b> — сервер\n%s x-ui   %s nginx\n⏱ аптайм: %s\n📊 load: <code>%s %s %s</code> (%s ядер)\n🧠 RAM: <code>%s/%s МБ (%s%%)</code>\n💾 Диск: <code>%sM/%sM (%s%%)</code>\n🌐 443: <code>%s</code> активных соединений\n📡 AWG: %s\n📥 RX: <code>%s</code> · 📤 TX: <code>%s</code> (с загрузки)\n📤 TG-выход: %s\n🔄 %s · автообновление 10с' \
    "$dom" "$xui" "$ngx" "${up:-?}" "${l1:-?}" "${l2:-?}" "${l3:-?}" "$cores" "${ram_u:-?}" "${ram_t:-?}" "$ram_p" "${du:-?}" "${dt:-?}" "$dp" "$conns" "$awg" "$(bot_fmt_bytes "${rx:-0}")" "$(bot_fmt_bytes "${tx:-0}")" "$tgp" "$(date '+%H:%M:%S')"
}

render_main() {
  local xui="🔴" ngx="🔴" nc in_n dom pb
  systemctl is-active -q x-ui  2>/dev/null && xui="🟢"
  systemctl is-active -q nginx 2>/dev/null && ngx="🟢"
  nc=$(sqlite3 "$XUI_DB" 'SELECT count(*) FROM clients;' 2>/dev/null); nc=${nc:-0}
  in_n=$(sqlite3 "$XUI_DB" 'SELECT count(*) FROM inbounds;' 2>/dev/null); in_n=${in_n:-0}
  dom=$(panel_domain); pb=$(panel_base)
  printf '🖥 <b>Панель стека</b> › Главное\n🔗 хост: <a href="https://%s%s">%s</a>\n%s x-ui   %s nginx\n👥 клиентов: %s · 📡 Инбаунды: %s\nВыбери раздел:' "$dom" "$pb" "$dom" "$xui" "$ngx" "$nc" "$in_n"
}

render_clients() { # только заголовок: клиенты — кнопки в клавиатуре (kb_clients)
  local tot pages
  tot=$(sqlite3 "$XUI_DB" 'SELECT count(*) FROM clients;' 2>/dev/null); tot=${tot:-0}
  if (( tot == 0 )); then CL_PAGE=1; printf '👥 <b>Клиенты</b>\nВ панели нет клиентов.'; return 0; fi
  pages=$(( (tot + CL_PER - 1) / CL_PER )); (( pages < 1 )) && pages=1
  (( CL_PAGE > pages )) && CL_PAGE=$pages; (( CL_PAGE < 1 )) && CL_PAGE=1
  printf '👥 <b>Клиенты</b> · всего %s · стр %s/%s\nНажми клиента — откроется карточка (подписка, QR, лимиты, инбаунды).' "$tot" "$CL_PAGE" "$pages"
}

render_traffic() {
  local rows email up down tot out="" dom rx tx sum_u=0 sum_d=0
  read -r rx tx < <(awk 'NR>2 && $1!~/lo:/ {rx+=$2; tx+=$10} END{print rx+0, tx+0}' /proc/net/dev 2>/dev/null)
  rows=$(sqlite3 -separator '|' "$XUI_DB" \
    "SELECT COALESCE(email,''),COALESCE(up,0),COALESCE(down,0),COALESCE(total,0)
     FROM client_traffics ORDER BY id;" 2>/dev/null)
  if [[ -n "$rows" ]]; then
    while IFS='|' read -r email up down tot; do
      sum_u=$((sum_u+up)); sum_d=$((sum_d+down))
      local lim=""
      (( tot > 0 )) && lim=" / лимит $(bot_fmt_bytes "$tot")"
      out="${out}<code>$(hesc "$email")</code> ↑$(bot_fmt_bytes "${up:-0}") ↓$(bot_fmt_bytes "${down:-0}")${lim}"$'\n'
    done <<<"$rows"
    out="${out}"$'\n'"Итого по клиентам: ↑$(bot_fmt_bytes $sum_u) ↓$(bot_fmt_bytes $sum_d)"$'\n'
  fi
  printf '🚦 <b>Трафик</b>\n📥 RX: <code>%s</code> · 📤 TX: <code>%s</code> (с загрузки сервера)\n\n%s' \
    "$(bot_fmt_bytes "${rx:-0}")" "$(bot_fmt_bytes "${tx:-0}")" "${out:-По клиентам данных нет.}"
}

render_maint() {
  printf '🛠 <b>Обслуживание</b>\nДействия выполняются после ✅ подтверждения.\nАудит и инбаунды приходят отдельным сообщением.'
}

render_bksched() {
  local cal next mon ivm
  cal=$(systemctl cat xui-db-backup.timer 2>/dev/null | grep '^OnCalendar=' | head -1 | cut -d= -f2-)
  next=$(systemctl list-timers xui-db-backup.timer --no-pager 2>/dev/null | awk 'NR==2{printf "%s %s",$1,$2}')
  ivm=$(( MON_IV / 60 )); (( ivm < 1 )) && ivm=1
  mon="🔴 выключен"; (( MON_ON == 1 )) && mon="🟢 включён · каждые ${ivm} мин"
  printf '⏰ <b>Расписание</b>\n\n💾 <b>Бэкап БД</b>\nТекущее: <code>%s</code>\nСледующий запуск: %s\nБэкап присылается документом в этот чат.\n\n🕵️ <b>Мониторинг</b>: %s\nАлерты приходят в этот чат.\n✅/❌ на кнопке = событие вкл/выкл (у CPU/RAM повторное нажатие меняет порог):' \
    "${cal:-—}" "${next:-выключен}" "$mon"
}

# ── клавиатуры экранов ──────────────────────────────────────────────────────
kb_main='[[{"text":"🖥 Сервер","callback_data":"nav:server"},{"text":"👥 Клиенты","callback_data":"nav:clients"}],[{"text":"🚦 Трафик","callback_data":"nav:traffic"},{"text":"🛠 Обслуживание","callback_data":"nav:maint"}],[{"text":"🔄 Обновить","callback_data":"refresh"}]]'
kb_server='[[{"text":"🔄 Обновить","callback_data":"refresh"},{"text":"⏯ Авто","callback_data":"auto"}],[{"text":"⬅️ Меню","callback_data":"nav:main"}]]'
kb_traffic='[[{"text":"🔄 Обновить","callback_data":"refresh"}],[{"text":"⬅️ Меню","callback_data":"nav:main"}]]'
kb_maint_fn() { # динамическое меню обслуживания: AdGuard — только если юнит есть; кнопки журналов ошибок
  # запятые ВКЛЮЧЕНЫ в вставки (ведущая у ряда, у кнопки — ведущая), чтобы пустой AdGuard не ломал JSON
  local adg_row="," adg_err=""
  if systemctl cat AdGuardHome.service >/dev/null 2>&1; then
    adg_row=',[{"text":"🔁 Перезагрузить AdGuard","callback_data":"askrestart:AdGuardHome"}]'
    adg_err=',{"text":"📜 adg","callback_data":"err:adg"}'
  fi
  printf '[[{"text":"⚡ Починить","callback_data":"askfix"},{"text":"🔎 Аудит","callback_data":"doaudit"}],[{"text":"🔁 Перезагрузить AWG","callback_data":"askawg"},{"text":"🔁 Перезагрузить X-ui","callback_data":"askrestart:x-ui"}],[{"text":"🔁 Перезагрузить Nginx","callback_data":"askrestart:nginx"},{"text":"🔁 Перезагрузить Xray","callback_data":"askrestart:xray"}]%s[{"text":"📡 Инбаунды","callback_data":"doinb"},{"text":"💾 Бэкап БД","callback_data":"askbackup"}],[{"text":"📜 Ошибки x-ui","callback_data":"err:xui"},{"text":"nginx","callback_data":"err:nginx"},{"text":"f2b","callback_data":"err:f2b"}%s],[{"text":"⏰ Расписание","callback_data":"nav:bksched"}],[{"text":"⬅️ Меню","callback_data":"nav:main"}]]' \
    "$adg_row" "$adg_err"
}
kb_sched() { # динамическая клавиатура расписания (мониторинг: ✅/❌ по состоянию)
  local o ou xr nd nu c r l sw
  (( EV_OUT   == 1 )) && o="✅ "   || o="❌ "
  (( EV_OUTUP == 1 )) && ou="✅ "  || ou="❌ "
  (( EV_XRAY  == 1 )) && xr="✅ "  || xr="❌ "
  (( EV_NODE  == 1 )) && nd="✅ "  || nd="❌ "
  (( EV_NODEUP== 1 )) && nu="✅ "  || nu="❌ "
  (( EV_CPU   == 1 )) && c="✅ "   || c="❌ "
  (( EV_RAM   == 1 )) && r="✅ "   || r="❌ "
  (( EV_LOGIN == 1 )) && l="✅ "   || l="❌ "
  sw="▶️ Включить мониторинг"; (( MON_ON == 1 )) && sw="⏸ Выключить мониторинг"
  local n2="❌ " a2="❌ " d2="❌ " ce="❌ " bf="❌ "
  (( EV_NGINX == 1 )) && n2="✅ "
  (( EV_ADG   == 1 )) && a2="✅ "
  (( EV_DISK  == 1 )) && d2="✅ "
  (( EV_CERT  == 1 )) && ce="✅ "
  (( EV_BKFAIL== 1 )) && bf="✅ "
  printf '[[{"text":"⏰ Бэкап: каждый час","callback_data":"bkset:hourly"},{"text":"Каждые 6ч","callback_data":"bkset:6h"}],[{"text":"Каждые 12ч","callback_data":"bkset:12h"},{"text":"Раз в день (04:00)","callback_data":"bkset:daily"}],[{"text":"⏸ Бэкап выключить","callback_data":"bkset:off"}],[{"text":"%s","callback_data":"mon:sw"}],[{"text":"⏱ 1 мин","callback_data":"moniv:60"},{"text":"⏱ 5 мин","callback_data":"moniv:300"},{"text":"⏱ 15 мин","callback_data":"moniv:900"}],[{"text":"%sИсходящие ⛔","callback_data":"mon:out"},{"text":"%sИсходящие ↩️","callback_data":"mon:outup"}],[{"text":"%sСбой Xray","callback_data":"mon:xray"}],[{"text":"%sУзел недоступен","callback_data":"mon:node"},{"text":"%sУзел ↩️","callback_data":"mon:nodeup"}],[{"text":"%sCPU ≥%s%%","callback_data":"mon:cpu"},{"text":"%sRAM ≥%s%%","callback_data":"mon:ram"}],[{"text":"%sNginx упал","callback_data":"mon:nginx"},{"text":"%sAdGuard упал","callback_data":"mon:adg"}],[{"text":"%sДиск ≥%s%%","callback_data":"mon:disk"},{"text":"%sСерты ≤7д","callback_data":"mon:cert"},{"text":"%sБэкап упал","callback_data":"mon:bkfail"}],[{"text":"%sПопытка входа","callback_data":"mon:login"}],[{"text":"⬅️ Обслуживание","callback_data":"nav:maint"}]]' \
    "$sw" "$o" "$ou" "$xr" "$nd" "$nu" "$c" "$CPU_TH" "$r" "$RAM_TH" "$n2" "$a2" "$d2" "$DISK_TH" "$ce" "$bf" "$l"
}

kb_clients() { # кнопки клиентов ТЕКУЩЕЙ страницы (один клиент — один ряд) + пагинация + действия
  # ВАЖНО: ряды кнопок идут верхним уровнем массива rows — вложенный массив в ряду
  # Telegram не рендерит (была кнопка-«…» на весь ряд).
  local total pages start n email sep="" rows=""
  total=$(sqlite3 "$XUI_DB" 'SELECT count(*) FROM clients;' 2>/dev/null); total=${total:-0}
  if (( total == 0 )); then
    printf '[[{"text":"➕ Создать","callback_data":"new:start"}],[{"text":"⬅️ Меню","callback_data":"nav:main"}]]'
    return 0
  fi
  pages=$(( (total + CL_PER - 1) / CL_PER ))
  (( CL_PAGE > pages )) && CL_PAGE=$pages; (( CL_PAGE < 1 )) && CL_PAGE=1
  start=$(( (CL_PAGE - 1) * CL_PER ))
  n=$start
  while IFS='|' read -r email st; do
    n=$((n+1))
    rows+="${sep}[$(jq -n --arg e "$email" --arg st "$st" --arg n "$n" '{text:($st+" "+$e),callback_data:("copen:"+$n)}')]"; sep=","
  done < <(sqlite3 -separator '|' "$XUI_DB" "SELECT COALESCE(c.email,'клиент'),CASE c.enable WHEN 1 THEN '✅' ELSE '⛔' END FROM clients c ORDER BY c.id LIMIT ${CL_PER} OFFSET ${start};" 2>/dev/null)
  local pg=""
  if (( pages > 1 )); then
    pg="[{\"text\":\"◀️\",\"callback_data\":\"clpage:$((CL_PAGE-1))\"},{\"text\":\"$CL_PAGE / $pages\",\"callback_data\":\"clpage:$CL_PAGE\"},{\"text\":\"▶️\",\"callback_data\":\"clpage:$((CL_PAGE+1))\"}],"
  fi
  # пагинация — ВНИЗУ списка (после клиентов), действия — в самом низу
  printf '[%s%s%s[{"text":"➕ Создать","callback_data":"new:start"},{"text":"📋 Все ссылки","callback_data":"subsall"}],[{"text":"⬅️ Меню","callback_data":"nav:main"}]]' "$rows" "${rows:+,}" "$pg"
}

screen_text() { # $1=menu → текст экрана (HTML)
  case "$1" in
    server)  render_card ;;
    clients) render_clients ;;
    traffic) render_traffic ;;
    maint)   render_maint ;;
    bksched) render_bksched ;;
    client)  client_card_render ;;
    *)       render_main ;;
  esac
}
screen_kb() { # $1=menu → inline_keyboard JSON
  case "$1" in
    server)  printf '%s' "$kb_server" ;;
    clients) kb_clients ;;
    traffic) printf '%s' "$kb_traffic" ;;
    maint)   kb_maint_fn ;;
    bksched) printf '%s' "$(kb_sched)" ;;
    client)  kb_client_card ;;
    *)       printf '%s' "$kb_main" ;;
  esac
}

# ── окно: показать/обновить экран ───────────────────────────────────────────
start_autoloop() { # цикл автообновления, если ещё не живёт
  if ! kill -0 "$CARD_PID" 2>/dev/null; then
    window_loop "$ADMIN_CHAT_ID" "$WINDOW_MID" &
    CARD_PID=$!
  fi
}
show_screen() { # $1=chat $2=menu
  local chat=$1 menu=$2 text kb
  CUR_MENU=$menu
  text=$(screen_text "$menu"); kb=$(screen_kb "$menu")
  if [[ -n "$WINDOW_MID" ]] && tg_edit "$chat" "$WINDOW_MID" "$text" "$kb"; then
    : # окно обновилось на месте
  else
    WINDOW_MID=$(tg_send_kb "$chat" "$text" "$kb")
  fi
  if [[ "$menu" == "server" ]]; then
    printf '%s server' "$WINDOW_MID" > "$CARD_FLAG"; start_autoloop
  else
    rm -f "$CARD_FLAG"
  fi
}

window_loop() { # $1=chat $2=mid — фоном, пока окно=server и жив CARD_FLAG
  local chat=$1 mid=$2 i m
  for (( i=0; i<60; i++ )); do
    sleep 10
    [[ -f "$CARD_FLAG" ]] || return 0
    read -r m menu < "$CARD_FLAG"
    [[ "$m" != "$mid" ]] && return 0
    [[ "${menu:-}" == "server" ]] || continue
    tg_edit "$chat" "$mid" "$(render_card)" "$kb_server" || return 0
  done
  rm -f "$CARD_FLAG"
}

# ── действия ────────────────────────────────────────────────────────────────
cmd_inbounds() {
  sqlite3 -separator ' | ' "$XUI_DB" \
    "SELECT id,COALESCE(remark,''),listen,CASE enable WHEN 1 THEN 'on' ELSE 'OFF' END
     FROM inbounds ORDER BY enable DESC, id;" 2>/dev/null
}
cmd_subs() {
  local dom rows out="" email sid en
  dom=$(panel_domain)
  rows=$(sqlite3 -separator '|' "$XUI_DB" \
    "SELECT COALESCE(email,''),COALESCE(sub_id,''),CASE enable WHEN 1 THEN 'on' ELSE 'OFF' END
     FROM clients ORDER BY id;" 2>/dev/null)
  [[ -z "$rows" ]] && { printf 'Клиентов в панели нет.'; return 0; }
  while IFS='|' read -r email sid en; do
    [[ -z "$sid" ]] && continue
    out="${out}$en $(hesc "$email")"$'\n'"https://${dom}/podpiska/${sid}"$'\n\n'
  done <<<"$rows"
  [[ -z "$out" ]] && out="У клиентов нет sub_id."
  printf '%s' "$out"
}
sub_url_for() { # $1=email_or_n → url
  local dom rows email sid n=0
  dom=$(panel_domain)
  rows=$(sqlite3 -separator '|' "$XUI_DB" \
    "SELECT COALESCE(email,''),COALESCE(sub_id,'') FROM clients ORDER BY id;" 2>/dev/null)
  while IFS='|' read -r email sid; do
    n=$((n+1))
    if [[ "$1" == "$email" || "$1" == "$n" ]]; then
      [[ -z "$sid" ]] && return 1
      printf 'https://%s/podpiska/%s' "$dom" "$sid"; return 0
    fi
  done <<<"$rows"
  return 1
}
send_client_pack() { # $1=chat $2=n — ссылка + QR клиента (обе с кнопкой 🗑)
  local url png="/tmp/tg-stack-qr.png" email
  email=$(sqlite3 "$XUI_DB" "SELECT COALESCE(email,'клиент') FROM clients ORDER BY id LIMIT 1 OFFSET $(( $2 - 1 ));" 2>/dev/null)
  url=$(sub_url_for "$2") || { tg_send "$1" "У клиента ${email} нет sub_id."; return 0; }
  qrencode -o "$png" -s 10 -m 2 "$url" 2>/dev/null
  tgc -s --max-time 40 -F "chat_id=$1" -F "photo=@${png}" -F "reply_markup={\"inline_keyboard\":$KB_HIDE}" "$API/sendPhoto" >/dev/null
  rm -f "$png"
  tg_send_kb "$1" "🔗 ${email}"$'\n'"$url" "$KB_HIDE" >/dev/null
}
cmd_awg_restart() {
  local ifaces if_ out=""
  mapfile -t ifaces < <(awg show 2>/dev/null | grep '^interface:' | awk '{print $2}')
  if (( ${#ifaces[@]} == 0 )); then printf 'AWG интерфейсов нет.'; return 0; fi
  for if_ in "${ifaces[@]}"; do
    awg-quick down "$if_" >/dev/null 2>&1
    if awg-quick up "$if_" >/dev/null 2>&1; then out="${out}$if_: перезапущен ✓"$'\n'
    else out="${out}$if_: ОШИБКА подъёма (awg-quick up)"$'\n'; fi
  done
  printf '%s' "$out"
}
# ── мастер создания клиента (API панели, панель сама генерит креды) ─────────
wiz_reset() { NEW_STEP=""; NEW_IN=""; NEW_GB=-1; NEW_DAYS=0; NEW_EMAIL=""; NEW_SUBID=""; WIZ_MID=""; wiz_save; }
wiz_save() { # сохранить сессию мастера — переживает рестарт бота
  [[ -d /run ]] || return 0
  printf 'WIZ_MID=%s\nNEW_STEP=%s\nNEW_IN=%s\nNEW_GB=%s\nNEW_DAYS=%s\nNEW_EMAIL=%s\nNEW_SUBID=%s\n' \
    "$WIZ_MID" "$NEW_STEP" "$NEW_IN" "$NEW_GB" "$NEW_DAYS" "$NEW_EMAIL" "$NEW_SUBID" \
    > "$WIZ_STATE" 2>/dev/null || true
}
wiz_load() { # восстановить сессию мастера после рестарта
  [[ -s "$WIZ_STATE" ]] || return 0
  local k v
  while IFS='=' read -r k v; do
    case "$k" in
      WIZ_MID) WIZ_MID="$v" ;; NEW_STEP) NEW_STEP="$v" ;; NEW_IN) NEW_IN="$v" ;;
      NEW_GB) NEW_GB="$v" ;; NEW_DAYS) NEW_DAYS="$v" ;;
      NEW_EMAIL) NEW_EMAIL="$v" ;; NEW_SUBID) NEW_SUBID="$v" ;;
    esac
  done < "$WIZ_STATE"
}
wiz_render() {
  local ib iname
  case "$NEW_STEP" in
    wait_in)
      printf '➕ <b>Новый клиент</b> — шаг 1/4\nВыбери инбаунды (можно несколько — повторное нажатие снимает):' ;;
    gb)
      ib=$(sqlite3 "$XUI_DB" "SELECT group_concat(COALESCE(remark,'?'), ', ') FROM inbounds WHERE id IN ($NEW_IN);" 2>/dev/null)
      printf '➕ <b>Новый клиент</b> — шаг 2/4\nИнбаунд: <b>%s</b>\nЛимит трафика:' "$(hesc "$ib")" ;;
    days)
      printf '➕ <b>Новый клиент</b> — шаг 3/4\nТрафик: %s\nСрок действия:' "$([[ $NEW_GB -ge 0 ]] && printf '%s ГБ' "$NEW_GB" || printf '∞ безлимит')" ;;
    email)
      printf '➕ <b>Новый клиент</b> — шаг 4/4\nТрафик: %s · Срок: %s\nИмя клиента (email):' \
        "$([[ $NEW_GB -ge 0 ]] && printf '%s ГБ' "$NEW_GB" || printf '∞')" \
        "$([[ $NEW_DAYS -gt 0 ]] && printf '%s дн' "$NEW_DAYS" || printf '∞')" ;;
    confirm)
      ib=$(sqlite3 "$XUI_DB" "SELECT group_concat(COALESCE(remark,'?'), ', ') FROM inbounds WHERE id IN ($NEW_IN);" 2>/dev/null)
      printf '✅ <b>Подтверди создание</b>\nИмя: <code>%s</code>\nИнбаунд: <b>%s</b>\nТрафик: %s\nСрок: %s' \
        "$(hesc "$NEW_EMAIL")" "$(hesc "$ib")" \
        "$([[ $NEW_GB -ge 0 ]] && printf '%s ГБ' "$NEW_GB" || printf '∞ безлимит')" \
        "$([[ $NEW_DAYS -gt 0 ]] && printf '%s дней' "$NEW_DAYS" || printf '∞ бессрочно')" ;;
    *) printf 'Мастер создания клиента.' ;;
  esac
}
wiz_kb() {
  local btn rows id rem port mark
  case "$NEW_STEP" in
    wait_in)
      rows=""
      while IFS='|' read -r id rem port; do
        [[ ",$NEW_IN," == *",$id,"* ]] && mark="✅ " || mark=""
        rows+="[$(jq -n --arg t "$mark$rem" --arg id "$id" '{text:$t,callback_data:("new:in:"+$id)}')],"
      done < <(sqlite3 -separator '|' "$XUI_DB" \
        "SELECT id,COALESCE(remark,'?'),port FROM inbounds WHERE enable=1 ORDER BY id;" 2>/dev/null)
      if [[ -z "$rows" ]]; then
        printf '[[{"text":"Нет активных инбаундов","callback_data":"noop"}],[{"text":"❌ Отменить","callback_data":"new:abort"}]]'
      elif [[ -n "$NEW_IN" ]]; then
        printf '[%s[{"text":"Далее ➡️","callback_data":"new:indone"},{"text":"❌ Отменить","callback_data":"new:abort"}]]' "$rows"
      else
        printf '[%s[{"text":"❌ Отменить","callback_data":"new:abort"}]]' "$rows"
      fi ;;
    gb)      printf '[[{"text":"∞ безлимит","callback_data":"new:gb:0"},{"text":"10 ГБ","callback_data":"new:gb:10"},{"text":"50 ГБ","callback_data":"new:gb:50"}],[{"text":"100 ГБ","callback_data":"new:gb:100"},{"text":"500 ГБ","callback_data":"new:gb:500"},{"text":"✏️ Свой ГБ","callback_data":"new:gbtxt"}],[{"text":"⬅️ Отменить","callback_data":"new:abort"}]]' ;;
    gb_txt)  printf '[[{"text":"⬅️ Отменить","callback_data":"new:abort"}]]' ;;
    days)    printf '[[{"text":"∞ бессрочно","callback_data":"new:days:0"},{"text":"7 дней","callback_data":"new:days:7"},{"text":"30 дней","callback_data":"new:days:30"}],[{"text":"90 дней","callback_data":"new:days:90"},{"text":"✏️ Свой срок","callback_data":"new:daystxt"}],[{"text":"⬅️ Назад","callback_data":"new:backgb"}]]' ;;
    days_txt) printf '[[{"text":"⬅️ Отменить","callback_data":"new:abort"}]]' ;;
    email)   printf '[[{"text":"🎲 Автоимя","callback_data":"new:emauto"},{"text":"✏️ Ввести имя","callback_data":"new:emtxt"}],[{"text":"⬅️ Назад","callback_data":"new:backdays"}]]' ;;
    email_txt) printf '[[{"text":"⬅️ Отменить","callback_data":"new:abort"}]]' ;;
    confirm) printf '[[{"text":"✅ Создать","callback_data":"new:go"}],[{"text":"❌ Отменить","callback_data":"new:abort"}]]' ;;
    done)    printf '[[{"text":"➕ Ещё клиент","callback_data":"new:start"}],[{"text":"Закрыть","callback_data":"new:close"}]]' ;;
    *)       printf '[[{"text":"⬅️ Меню","callback_data":"nav:main"}]]' ;;
  esac
}
show_wizard() { # $1=chat — создать/обновить карточку мастера
  local chat=$1 text kb json resp
  wiz_save
  text=$(wiz_render); kb=$(wiz_kb)
  json=$(jq -n --arg c "$chat" --arg t "$text" --argjson kb "$kb" \
    '{chat_id:$c,text:$t,parse_mode:"HTML",reply_markup:{inline_keyboard:$kb}}')
  if [[ -n "$WIZ_MID" ]]; then
    json=$(jq -n --arg c "$chat" --arg m "$WIZ_MID" --arg t "$text" --argjson kb "$kb" \
      '{chat_id:$c,message_id:($m|tonumber),text:$t,parse_mode:"HTML",reply_markup:{inline_keyboard:$kb}}')
    resp=$(tgc -s --max-time 40 -X POST "$API/editMessageText" -H 'Content-Type: application/json' -d "$json")
    if jq -re '.ok == true' <<<"$resp" >/dev/null 2>&1 || grep -q "not modified" <<<"$resp"; then return 0; fi
    bot_log "WIZ: edit msg $WIZ_MID не удался: $(head -c 200 <<<"$resp")"
  fi
  resp=$(tgc -s --max-time 40 -X POST "$API/sendMessage" -H 'Content-Type: application/json' -d "$json")
  WIZ_MID=$(jq -r '.result.message_id // empty' <<<"$resp" 2>/dev/null)
  [[ -z "$WIZ_MID" ]] && bot_log "WIZ: sendMessage не удался: $(head -c 200 <<<"$resp")"
  wiz_save
}
wiz_done() { # $1=chat $2=text — завершить мастер
  NEW_STEP="done"
  local text kb json
  wiz_save
  text="$2"; kb=$(wiz_kb)
  json=$(jq -n --arg c "$1" --arg t "$text" --argjson kb "$kb" \
    '{chat_id:$c,text:$t,parse_mode:"HTML",reply_markup:{inline_keyboard:$kb}}')
  if [[ -n "$WIZ_MID" ]]; then
    local j2; j2=$(jq -n --arg c "$1" --arg m "$WIZ_MID" --arg t "$text" --argjson kb "$kb" \
      '{chat_id:$c,message_id:($m|tonumber),text:$t,parse_mode:"HTML",reply_markup:{inline_keyboard:$kb}}')
    tgc -s --max-time 40 -X POST "$API/editMessageText" -H 'Content-Type: application/json' -d "$j2" >/dev/null
  else
    tgc -s --max-time 40 -X POST "$API/sendMessage" -H 'Content-Type: application/json' -d "$json" >/dev/null
  fi
}
api_create_client() { # → "OK" или текст ошибки
  [[ -z "$NEW_IN" || -z "$NEW_EMAIL" ]] && { printf 'сессия мастера потеряна'; return 0; }
  local ms=0 gb=0
  (( NEW_DAYS > 0 )) && ms=$(( ($(date +%s) + NEW_DAYS * 86400) * 1000 ))
  (( NEW_GB > 0 )) && gb=$(( NEW_GB * 1024 * 1024 * 1024 ))
  local payload resp msg
  payload=$(jq -nc --arg e "$NEW_EMAIL" --arg s "$NEW_SUBID" --argjson gb "$gb" --argjson ms "$ms" --argjson in "[$NEW_IN]" \
    '{client:{email:$e,enable:true,limitIp:0,totalGB:$gb,expiryTime:$ms,subId:$s},inboundIds:$in}')
  resp=$(api_call POST /panel/api/clients/add "$payload")
  if jq -re '.success == true' <<<"${resp:-}" >/dev/null 2>&1; then
    printf 'OK'
  else
    msg=$(jq -r '.msg // "ошибка API"' <<<"${resp:-}" 2>/dev/null)
    printf '%s' "$msg"
  fi
}
new_client_send_links() { # $1=chat $2=email $3=subId — ссылка+QR свежесозданного клиента (обе с кнопкой 🗑)
  local dom url png="/tmp/tg-stack-qr.png"
  dom=$(panel_domain)
  url="https://${dom}/podpiska/${3}"
  qrencode -o "$png" -s 10 -m 2 "$url" 2>/dev/null
  tgc -s --max-time 40 -F "chat_id=$1" -F "photo=@${png}" -F "reply_markup={\"inline_keyboard\":$KB_HIDE}" "$API/sendPhoto" >/dev/null
  rm -f "$png"
  tg_send_kb "$1" "🔗 ${2}"$'\n'"$url" "$KB_HIDE" >/dev/null
}

# ── карточка клиента: подписка / QR / инбаунды / лимиты / удаление ──────────
em_ok() { [[ "$1" =~ ^[A-Za-z0-9_.-]{1,40}$ ]]; }
client_exists() { sqlite3 "$XUI_DB" "SELECT 1 FROM clients WHERE email='$1';" 2>/dev/null | grep -q 1; }
client_in_csv() { # $1=email → csv inbound_id клиента
  sqlite3 "$XUI_DB" "SELECT COALESCE(group_concat(ci.inbound_id),'') FROM client_inbounds ci JOIN clients c ON c.id=ci.client_id WHERE c.email='$1';" 2>/dev/null
}
csv_diff() { # $1=A $2=B → элементы A, которых нет в B (csv)
  local out="" x
  [[ -z "$1" ]] && return 0
  while IFS= read -r x; do
    [[ -z "$x" ]] && continue
    [[ ",$2," == *",$x,"* ]] || out="${out}${out:+,}$x"
  done < <(tr ',' '\n' <<<"$1")
  printf '%s' "$out"
}
api_client_get() { # $1=email → JSON клиента (id строкой, allowedIPs массивом) или ""
  local r
  r=$(api_call GET "/panel/api/clients/get/$1")
  jq -re '.success == true' <<<"${r:-}" >/dev/null 2>&1 || { printf ''; return 0; }
  jq -c '.obj.client | .id=(.id|tostring) | .allowedIPs=(if (.allowedIPs|type)=="string" and .allowedIPs!="" then [.allowedIPs] elif (.allowedIPs|type)=="array" then . else [] end)' <<<"$r" 2>/dev/null
}
api_client_update() { # $1=email $2=JSON-изменения (camelCase) → "OK" | текст ошибки
  local c payload resp ch="$2"
  c=$(api_client_get "$1")
  [[ -z "$c" ]] && { printf 'клиент не найден через API'; return 0; }
  payload=$(jq -c '. + $ch' --argjson ch "$ch" <<<"$c" 2>/dev/null)
  [[ -z "$payload" ]] && { printf 'ошибка сборки payload'; return 0; }
  resp=$(api_call POST "/panel/api/clients/update/$1" "$payload")
  if jq -re '.success == true' <<<"${resp:-}" >/dev/null 2>&1; then printf 'OK'
  else jq -r '.msg // "ошибка API"' <<<"${resp:-}" 2>/dev/null | head -c 200; fi
}
api_client_ids() { # $1=email $2=attach|detach $3=csv ids → "OK" | текст ошибки
  local arr payload resp
  arr=$(jq -nc --arg c "$3" '[$c | split(",") | map(select(length>0) | tonumber)]' 2>/dev/null)
  [[ -z "$arr" ]] && { printf 'ошибка списка инбаудов'; return 0; }
  payload=$(jq -nc --argjson i "$arr" '{inboundIds:$i}')
  resp=$(api_call POST "/panel/api/clients/$1/$2" "$payload")
  if jq -re '.success == true' <<<"${resp:-}" >/dev/null 2>&1; then printf 'OK'
  else jq -r '.msg // "ошибка API"' <<<"${resp:-}" 2>/dev/null | head -c 200; fi
}
api_client_del() { # $1=email → "OK" | текст ошибки
  local resp
  resp=$(api_call POST "/panel/api/clients/del/$1")
  if jq -re '.success == true' <<<"${resp:-}" >/dev/null 2>&1; then printf 'OK'
  else jq -r '.msg // "ошибка API"' <<<"${resp:-}" 2>/dev/null | head -c 200; fi
}
send_qr_msg() { # $1=chat $2=url — QR-фото с кнопкой 🗑
  local png="/tmp/tg-stack-qr.png"
  qrencode -o "$png" -s 10 -m 2 "$2" 2>/dev/null
  tgc -s --max-time 40 -F "chat_id=$1" -F "photo=@${png}" -F "reply_markup={\"inline_keyboard\":$KB_HIDE}" "$API/sendPhoto" >/dev/null
  rm -f "$png"
}
client_card_render() { # по E_EMAIL
  local row email sid en lip tgb exp inb used st lim till
  row=$(sqlite3 -separator '|' "$XUI_DB" \
    "SELECT COALESCE(email,''),COALESCE(sub_id,''),enable,COALESCE(limit_ip,0),COALESCE(total_gb,0),COALESCE(expiry_time,0)
     FROM clients WHERE email='$E_EMAIL';" 2>/dev/null)
  [[ -z "$row" ]] && { printf '👤 Клиент не найден (удалён?).'; return 0; }
  IFS='|' read -r email sid en lip tgb exp <<<"$row"
  inb=$(sqlite3 "$XUI_DB" "SELECT COALESCE(group_concat(COALESCE(i.remark,'?'),', '),'') FROM client_inbounds ci JOIN inbounds i ON i.id=ci.inbound_id JOIN clients c ON c.id=ci.client_id WHERE c.email='$E_EMAIL';" 2>/dev/null)
  used=$(sqlite3 "$XUI_DB" "SELECT COALESCE(SUM(up+down),0) FROM client_traffics WHERE email='$E_EMAIL';" 2>/dev/null); used=${used:-0}
  st="🔴 OFF"; [[ "$en" == "1" ]] && st="🟢 on"
  lim="∞ безлимит"; (( tgb > 0 )) && lim="$(bot_fmt_bytes "$tgb")"
  till="∞ бессрочно"
  if (( exp > 0 )); then
    till="до $(date -d "@$(( exp / 1000 ))" '+%d.%m.%Y' 2>/dev/null)"
    (( exp < $(date +%s) * 1000 )) && till+=" (истёк)"
  fi
  printf '👤 <b>%s</b> %s\n📡 Инбаунды: %s\n📊 Трафик: %s из %s\n⏳ Срок: %s\n🔒 IP-лимит: %s' \
    "$(hesc "$email")" "$st" "${inb:-нет}" "$(bot_fmt_bytes "$used")" "$lim" "$till" \
    "$( [[ $lip -gt 0 ]] && printf '%s IP' "$lip" || printf 'нет' )"
}
kb_client_card() {
  local e="$E_EMAIL" en tog
  en=$(sqlite3 "$XUI_DB" "SELECT COALESCE(enable,0) FROM clients WHERE email='$e';" 2>/dev/null); en=${en:-0}
  if [[ "$en" == "1" ]]; then tog='⛔ Выключить'; else tog='✅ Включить'; fi
  printf '[[{"text":"🔗 Подписка","callback_data":"csub:%s"},{"text":"📱 QR","callback_data":"cqr:%s"}],[{"text":"📡 Инбаунды","callback_data":"cin:%s"},{"text":"📊 Лимит ГБ","callback_data":"cgb:%s"}],[{"text":"⏳ Срок","callback_data":"cdays:%s"},{"text":"🗑 Удалить","callback_data":"askdel:%s"}],[{"text":"%s","callback_data":"ctgl:%s"}],[{"text":"⬅️ Клиенты","callback_data":"nav:clients"}]]' \
    "$e" "$e" "$e" "$e" "$e" "$e" "$tog" "$e"
}
ecard_render() {
  case "$E_STEP" in
    in)       printf '📡 <b>Инбаунды клиента %s</b>\nОтметь нужные (✅ = будет привязан), затем «Сохранить».' "$(hesc "$E_EMAIL")" ;;
    gb)       printf '📊 <b>Лимит трафика %s</b>\nВыбери новый лимит:' "$(hesc "$E_EMAIL")" ;;
    days)     printf '⏳ <b>Срок действия %s</b>\nВыбери новый срок (отсчёт с сегодня):' "$(hesc "$E_EMAIL")" ;;
    gb_txt)   printf '📊 Лимит %s: пришли число ГБ (например 200).' "$(hesc "$E_EMAIL")" ;;
    days_txt) printf '⏳ Срок %s: пришли число дней (например 30).' "$(hesc "$E_EMAIL")" ;;
    *)        client_card_render ;;
  esac
}
ecard_kb() {
  local rows id rem port mark
  case "$E_STEP" in
    in)
      rows=""
      while IFS='|' read -r id rem port; do
        [[ ",$E_IN," == *",$id,"* ]] && mark="✅ " || mark="➕ "
        rows+="[$(jq -n --arg t "$mark$rem" --arg e "$E_EMAIL" --arg id "$id" '{text:$t,callback_data:("cinb:"+$e+":"+$id)}')],"
      done < <(sqlite3 -separator '|' "$XUI_DB" \
        "SELECT id,COALESCE(remark,'?'),port FROM inbounds WHERE enable=1 ORDER BY id;" 2>/dev/null)
      if [[ -z "$rows" ]]; then
        printf '[[{"text":"Нет активных инбаудов","callback_data":"noop"}],[{"text":"⬅️ Отмена","callback_data":"cback"}]]'
      else
        printf '[%s[{"text":"💾 Сохранить","callback_data":"cinok:%s"},{"text":"⬅️ Отмена","callback_data":"cback"}]]' "$rows" "$E_EMAIL"
      fi ;;
    gb)    printf '[[{"text":"∞ безлимит","callback_data":"cgbset:%s:0"},{"text":"10 ГБ","callback_data":"cgbset:%s:10"},{"text":"50 ГБ","callback_data":"cgbset:%s:50"}],[{"text":"100 ГБ","callback_data":"cgbset:%s:100"},{"text":"500 ГБ","callback_data":"cgbset:%s:500"},{"text":"✏️ Свой ГБ","callback_data":"cgbtxt:%s"}],[{"text":"⬅️ Отмена","callback_data":"cback"}]]' "$E_EMAIL" "$E_EMAIL" "$E_EMAIL" "$E_EMAIL" "$E_EMAIL" "$E_EMAIL" ;;
    days)  printf '[[{"text":"∞ бессрочно","callback_data":"cdset:%s:0"},{"text":"7 дней","callback_data":"cdset:%s:7"},{"text":"30 дней","callback_data":"cdset:%s:30"}],[{"text":"90 дней","callback_data":"cdset:%s:90"},{"text":"✏️ Свой срок","callback_data":"cdtxt:%s"}],[{"text":"⬅️ Отмена","callback_data":"cback"}]]' "$E_EMAIL" "$E_EMAIL" "$E_EMAIL" "$E_EMAIL" "$E_EMAIL" ;;
    gb_txt|days_txt) printf '[[{"text":"⬅️ Отмена","callback_data":"cback"}]]' ;;
    *)     kb_client_card ;;
  esac
}
show_ecard() { # $1=chat — экран правки клиента (отдельное сообщение E_MID)
  local chat=$1 text kb json resp
  text=$(ecard_render); kb=$(ecard_kb)
  if [[ -n "$E_MID" ]]; then
    json=$(jq -n --arg c "$chat" --arg m "$E_MID" --arg t "$text" --argjson kb "$kb" \
      '{chat_id:$c,message_id:($m|tonumber),text:$t,parse_mode:"HTML",reply_markup:{inline_keyboard:$kb}}')
    resp=$(tgc -s --max-time 40 -X POST "$API/editMessageText" -H 'Content-Type: application/json' -d "$json")
    if jq -re '.ok == true' <<<"$resp" >/dev/null 2>&1 || grep -q "not modified" <<<"$resp"; then return 0; fi
    E_MID=""
  fi
  json=$(jq -n --arg c "$chat" --arg t "$text" --argjson kb "$kb" \
    '{chat_id:$c,text:$t,parse_mode:"HTML",reply_markup:{inline_keyboard:$kb}}')
  resp=$(tgc -s --max-time 40 -X POST "$API/sendMessage" -H 'Content-Type: application/json' -d "$json")
  E_MID=$(jq -r '.result.message_id // empty' <<<"$resp" 2>/dev/null)
}
ecard_close() { # $1=chat — убрать экран правки
  [[ -n "$E_MID" ]] && tg_del "$1" "$E_MID"
  E_MID=""; E_STEP=""
}
ecard_client_view() { # $1=chat — вернуться к карточке клиента в главном окне
  ecard_close "$1"; show_screen "$1" "client"
}

do_confirmed() { # $1=chat $2=action (fix|awg|restart-xui|restart-nginx|restart-adg|restart-xray)
  case "$2" in
    fix)           tg_send "$1" "⚡ Автопочинка запущена (до 5 мин)…"; tg_send_kb "$1" "$(run_stack stack_check_fix | tail -60)" "$KB_HIDE" >/dev/null ;;
    awg)           tg_send "$1" "🔁 Перезапуск AWG…"; tg_send_kb "$1" "$(cmd_awg_restart)" "$KB_HIDE" >/dev/null ;;
    restart-xui)   systemctl restart x-ui && sleep 2 && tg_send "$1" "x-ui: $(systemctl is-active x-ui)" ;;
    restart-nginx) systemctl restart nginx && sleep 2 && tg_send "$1" "nginx: $(systemctl is-active nginx)" ;;
    restart-adg)   systemctl restart AdGuardHome && sleep 2 && tg_send "$1" "AdGuardHome: $(systemctl is-active AdGuardHome 2>/dev/null)" ;;
    restart-xray)
      local res; res=$(api_call POST /panel/api/server/restartXrayService)
      if jq -re '.success == true' <<<"$res" >/dev/null 2>&1; then tg_send "$1" "xray: перезапущен ✓"
      else tg_send "$1" "xray: ошибка — $(jq -r '.msg // "нет ответа панели"' <<<"$res")"; fi ;;
  esac
}

# ── журнал ошибок сервисов (/err и кнопки 📜 в обслуживании) ────────────────
err_unit() { # $1=алиас (xui|nginx|adg|f2b|bot) или имя юнита → имя юнита
  local pair
  for pair in xui:x-ui nginx:nginx adg:AdGuardHome f2b:fail2ban bot:tg-stack-bot; do
    [[ "${pair%%:*}" == "$1" ]] && { printf '%s' "${pair#*:}"; return 0; }
  done
  [[ "$1" =~ ^[A-Za-z0-9_.@-]+$ ]] && { printf '%s' "$1"; return 0; }
  return 1
}
err_tail() { # $1=юнит → последние ошибки журнала (HTML); нет ошибок — просто хвост
  local u=$1 out
  out=$(journalctl -u "$u" -n 200 --no-pager 2>/dev/null | grep -iaE "error|fail|fatal|crit|panic" | tail -10)
  [[ -z "$out" ]] && out=$(journalctl -u "$u" -n 10 --no-pager 2>/dev/null)
  [[ -z "$out" ]] && { printf '📜 <b>%s</b>: журнал пуст или юнит не найден.' "$(hesc "$u")"; return 0; }
  printf '📜 <b>%s</b> — последние ошибки:\n<pre>%s</pre>' "$(hesc "$u")" "$(hesc "$(printf '%s' "$out" | head -c 2800)")"
}

bk_set_schedule() { # $1=пресет → текст результата
  local cal name
  case "$1" in
    hourly) cal='*-*-* *:00:00';        name='каждый час' ;;
    6h)     cal='*-*-* 00,06,12,18:00:00'; name='каждые 6 часов' ;;
    12h)    cal='*-*-* 00,12:00:00';    name='каждые 12 часов' ;;
    daily)  cal='*-*-* 04:00:00';       name='раз в день в 04:00' ;;
    off)
      systemctl disable --now xui-db-backup.timer >/dev/null 2>&1
      printf '⏹ Расписание бэкапа выключено (ручной — кнопкой 💾 Бэкап БД).'; return 0 ;;
    *) printf 'Неизвестный пресет.'; return 0 ;;
  esac
  cat > /etc/systemd/system/xui-db-backup.timer <<EOF
[Unit]
Description=x-ui DB backup schedule
[Timer]
OnCalendar=$cal
Persistent=true
[Install]
WantedBy=timers.target
EOF
  systemctl daemon-reload
  systemctl enable --now xui-db-backup.timer >/dev/null 2>&1
  printf '✅ Бэкап: %s (OnCalendar=%s). Документ будет приходить в этот чат.' "$name" "$cal"
}

# ── мониторинг (Расписание → алерты по событиям панели) ────────────────────
MON_FILE="/root/.tg-stack-bot-mon.env"
MON_ON=1; MON_IV=300
EV_OUT=1; OUT_FAILS=3; EV_OUTUP=0      # Исходящие ⛔ / ↩️ (как в панели)
EV_XRAY=1                              # Сбой Xray
EV_NODE=1; NODE_FAILS=1; EV_NODEUP=0   # Узел ⛔ / ↩️
EV_CPU=0; CPU_TH=90; EV_RAM=0; RAM_TH=90  # Система (в панели по умолчанию выкл)
EV_LOGIN=1                             # Попытка входа
EV_NGINX=1; EV_ADG=1; EV_DISK=0; DISK_TH=85; EV_CERT=1; EV_BKFAIL=1  # nginx/adguard упал, диск, серты ≤7д, бэкап упал
OUT_CNT=0; OUT_BAD=0; XRAY_BAD=0; XRAY_LAST=0
NODE_CNT=0; NODE_BAD=0; NODE_LAST=0
CPU_LAST=0; RAM_LAST=0
NGX_BAD=0; NGX_LAST=0; ADG_BAD=0; ADG_LAST=0; DISK_LAST=0; CERT_LAST=0; CERT_CHK=-3600; BKF_LAST=0
LOG_POS=0; LAST_MON=-1

mon_load() {
  [[ -r "$MON_FILE" ]] || return 0
  local k v
  while IFS='=' read -r k v; do
    [[ "$k" =~ ^[A-Z_]+$ ]] || continue
    case "$k" in
      MON_ON) MON_ON=$v ;; MON_IV) MON_IV=$v ;;
      EV_OUT) EV_OUT=$v ;; OUT_FAILS) OUT_FAILS=$v ;; EV_OUTUP) EV_OUTUP=$v ;;
      EV_XRAY) EV_XRAY=$v ;;
      EV_NODE) EV_NODE=$v ;; NODE_FAILS) NODE_FAILS=$v ;; EV_NODEUP) EV_NODEUP=$v ;;
      EV_CPU) EV_CPU=$v ;; CPU_TH) CPU_TH=$v ;; EV_RAM) EV_RAM=$v ;; RAM_TH) RAM_TH=$v ;;
      EV_LOGIN) EV_LOGIN=$v ;;
      EV_NGINX) EV_NGINX=$v ;; EV_ADG) EV_ADG=$v ;; EV_DISK) EV_DISK=$v ;; DISK_TH) DISK_TH=$v ;;
      EV_CERT) EV_CERT=$v ;; EV_BKFAIL) EV_BKFAIL=$v ;;
      OUT_CNT) OUT_CNT=$v ;; OUT_BAD) OUT_BAD=$v ;; XRAY_BAD) XRAY_BAD=$v ;; XRAY_LAST) XRAY_LAST=$v ;;
      NODE_CNT) NODE_CNT=$v ;; NODE_BAD) NODE_BAD=$v ;; NODE_LAST) NODE_LAST=$v ;;
      CPU_LAST) CPU_LAST=$v ;; RAM_LAST) RAM_LAST=$v ;;
      LOG_POS) LOG_POS=$v ;;
    esac
  done < "$MON_FILE"
}

mon_save() {
  local tmp="$MON_FILE.tmp" um
  um=$(umask); umask 077
  cat > "$tmp" <<EOF
MON_ON=$MON_ON
MON_IV=$MON_IV
EV_OUT=$EV_OUT
OUT_FAILS=$OUT_FAILS
EV_OUTUP=$EV_OUTUP
EV_XRAY=$EV_XRAY
EV_NODE=$EV_NODE
NODE_FAILS=$NODE_FAILS
EV_NODEUP=$EV_NODEUP
EV_CPU=$EV_CPU
CPU_TH=$CPU_TH
EV_RAM=$EV_RAM
RAM_TH=$RAM_TH
EV_LOGIN=$EV_LOGIN
EV_NGINX=$EV_NGINX
EV_ADG=$EV_ADG
EV_DISK=$EV_DISK
DISK_TH=$DISK_TH
EV_CERT=$EV_CERT
EV_BKFAIL=$EV_BKFAIL
NGX_BAD=$NGX_BAD
NGX_LAST=$NGX_LAST
ADG_BAD=$ADG_BAD
ADG_LAST=$ADG_LAST
DISK_LAST=$DISK_LAST
CERT_LAST=$CERT_LAST
CERT_CHK=$CERT_CHK
BKF_LAST=$BKF_LAST
OUT_CNT=$OUT_CNT
OUT_BAD=$OUT_BAD
XRAY_BAD=$XRAY_BAD
XRAY_LAST=$XRAY_LAST
NODE_CNT=$NODE_CNT
NODE_BAD=$NODE_BAD
NODE_LAST=$NODE_LAST
CPU_LAST=$CPU_LAST
RAM_LAST=$RAM_LAST
LOG_POS=$LOG_POS
EOF
  mv "$tmp" "$MON_FILE"
  umask "$um"
}

mon_alert() { # $1=text (HTML) — алерт в чат админа (с кнопкой «🗑 Скрыть») + лог результата в журнал
  [[ -n "${ADMIN_CHAT_ID:-}" ]] || return 0
  local json resp
  json=$(jq -n --arg c "$ADMIN_CHAT_ID" --arg t "$1" --argjson kb "$KB_HIDE" \
    '{chat_id:$c,text:$t,parse_mode:"HTML",reply_markup:{inline_keyboard:$kb}}')
  resp=$(tgc -s --max-time 30 -X POST "$API/sendMessage" -H 'Content-Type: application/json' -d "$json")
  bot_log "мониторинг: ok=$(jq -r '.ok // false' <<<"${resp:-}") $(jq -r '.description // ""' <<<"${resp:-}") :: ${1:0:60}"
}

mon_tick() { # периодическая проверка (вызывается из главного цикла)
  (( MON_ON == 1 )) || return 0
  local now=$SECONDS
  (( LAST_MON >= 0 && now - LAST_MON < MON_IV )) && return 0
  LAST_MON=$now
  local st cpu_pct mem_pct xr code pct bp logf sz endd left bad cf
  bp=$(panel_base)

  # статус панели: CPU / RAM / Xray
  st=$(api_call GET /panel/api/server/status 2>/dev/null)
  if jq -re '.success == true and (.obj != null)' <<<"${st:-}" >/dev/null 2>&1; then
    cpu_pct=$(jq -r '.obj.cpu // 0' <<<"$st")
    mem_pct=$(jq -r '((.obj.mem.current // 0) * 100 / (.obj.mem.total // 1))' <<<"$st" | cut -d. -f1)
    xr=$(jq -r '.obj.xray.state // "?"' <<<"$st")

    if (( EV_XRAY == 1 )) && [[ "$xr" != "running" ]]; then
      if (( now - XRAY_LAST >= 1800 )); then
        mon_alert "☢️ <b>Сбой Xray</b>: состояние <code>$xr</code>"; XRAY_LAST=$now
      fi
      XRAY_BAD=1
    elif [[ "$xr" == "running" ]]; then
      XRAY_BAD=0
    fi

    pct=${cpu_pct%%.*}; [[ -z "$pct" ]] && pct=0
    if (( EV_CPU == 1 && pct >= CPU_TH && now - CPU_LAST >= 900 )); then
      mon_alert "🔥 <b>CPU</b>: ${pct}% (порог ${CPU_TH}%)"; CPU_LAST=$now
    fi
    if (( EV_RAM == 1 && mem_pct >= RAM_TH && now - RAM_LAST >= 900 )); then
      mon_alert "🧠 <b>RAM</b>: ${mem_pct}% (порог ${RAM_TH}%)"; RAM_LAST=$now
    fi
  fi

  # узел: nginx отвечает на 443
  code=$(curl -sk -m 6 -o /dev/null -w '%{http_code}' -H "Host: $(panel_domain)" "https://127.0.0.1${bp}" 2>/dev/null)
  if [[ "$code" =~ ^[1-5][0-9][0-9]$ ]]; then
    NODE_CNT=0
    if (( NODE_BAD == 1 )); then
      NODE_BAD=0
      (( EV_NODEUP == 1 )) && mon_alert "🟢 <b>Узел в сети</b> (443 отвечает)"
    fi
  else
    NODE_CNT=$((NODE_CNT+1))
    if (( EV_NODE == 1 && NODE_CNT >= NODE_FAILS && now - NODE_LAST >= 1800 )); then
      mon_alert "🖥 <b>Узел недоступен</b>: нет ответа на 443 (${NODE_CNT} провер. подряд)"; NODE_LAST=$now
    fi
  fi

  # исходящие: интернет с сервера (через TG-выход, если он задан — это и есть «зарубежный выход»)
  code=$(curl -sk -m 6 ${TG_PROXY_CUR:+--proxy $TG_PROXY_CUR} -o /dev/null -w '%{http_code}' "https://www.google.com/generate_204" 2>/dev/null)
  if [[ "$code" == "204" ]]; then
    OUT_CNT=0
    if (( OUT_BAD == 1 )); then
      OUT_BAD=0
      (( EV_OUTUP == 1 )) && mon_alert "✅ <b>Исходящие снова работают</b>"
    fi
  else
    OUT_CNT=$((OUT_CNT+1))
    if (( EV_OUT == 1 && OUT_CNT >= OUT_FAILS && OUT_BAD == 0 )); then
      mon_alert "⛔ <b>Исходящие недоступны</b>: ${OUT_CNT} неудачных проверок подряд"; OUT_BAD=1
    fi
  fi

  # сервисы: nginx / AdGuardHome
  if (( EV_NGINX == 1 )); then
    st=$(systemctl is-active nginx 2>/dev/null)
    if [[ "$st" == "active" ]]; then
      if (( NGX_BAD == 1 )); then NGX_BAD=0; mon_alert "🟢 <b>nginx снова работает</b>"; fi
    else
      NGX_BAD=1
      if (( now - NGX_LAST >= 1800 )); then
        mon_alert "🌐 <b>nginx не работает</b>: состояние <code>${st:-unknown}</code>"; NGX_LAST=$now
      fi
    fi
  fi
  if (( EV_ADG == 1 )) && systemctl cat AdGuardHome.service >/dev/null 2>&1; then
    st=$(systemctl is-active AdGuardHome 2>/dev/null)
    if [[ "$st" == "active" ]]; then
      if (( ADG_BAD == 1 )); then ADG_BAD=0; mon_alert "🟢 <b>AdGuardHome снова работает</b>"; fi
    else
      ADG_BAD=1
      if (( now - ADG_LAST >= 1800 )); then
        mon_alert "🛡 <b>AdGuardHome не работает</b>: состояние <code>${st:-unknown}</code>"; ADG_LAST=$now
      fi
    fi
  fi

  # диск: занято ≥ DISK_TH% (алерт не чаще раза в 6ч)
  if (( EV_DISK == 1 )); then
    pct=$(df -P / | awk 'NR==2{gsub("%","",$5);print $5+0}')
    if (( pct >= DISK_TH && now - DISK_LAST >= 21600 )); then
      mon_alert "💽 <b>Диск</b>: занято ${pct}% (порог ${DISK_TH}%)"; DISK_LAST=$now
    fi
  fi

  # серты: certificateFile из TLS-инбаундов (проверка раз в час, алерт раз в 12ч)
  if (( EV_CERT == 1 && now - CERT_CHK >= 3600 )); then
    CERT_CHK=$now
    bad=""
    while IFS= read -r cf; do
      [[ -r "$cf" ]] || continue
      endd=$(openssl x509 -in "$cf" -noout -enddate 2>/dev/null | cut -d= -f2)
      [[ -z "$endd" ]] && continue
      left=$(( ( $(date -d "$endd" +%s 2>/dev/null || printf '0') - $(date +%s) ) / 86400 ))
      if (( left <= 7 )); then bad+="• $(basename "$(dirname "$cf")"): осталось ${left} дн"$'\n'; fi
    done < <(sqlite3 "$XUI_DB" "SELECT stream_settings FROM inbounds;" 2>/dev/null \
      | jq -r '.tlsSettings.certificates[]?.certificateFile // empty' 2>/dev/null | sort -u)
    if [[ -n "$bad" ]] && (( now - CERT_LAST >= 43200 )); then
      mon_alert "🔐 <b>Серты истекают (≤7 дн)</b>:
${bad}Перевыпусти через stack-manager › серты."
      CERT_LAST=$now
    fi
  fi

  # бэкап БД упал (алерт не чаще раза в 6ч, пока не починят)
  if (( EV_BKFAIL == 1 )); then
    st=$(systemctl is-failed xui-db-backup.service 2>/dev/null)
    if [[ "$st" == "failed" ]] && (( now - BKF_LAST >= 21600 )); then
      mon_alert "💾 <b>Бэкап БД упал</b> — детали: journalctl -u xui-db-backup"; BKF_LAST=$now
    fi
  fi
  mon_save
}

mon_login_check() { # входы в панель: источник истины — журнал x-ui (200 панель шлёт и на неверный пароль!),
  # фолбэк для старых панелей без этих строк — access.bot_log (как раньше)
  (( MON_ON == 1 )) || return 0
  local cf="/root/.tg-stack-bot-login.cursor" out line res un ip rsn extra jrc
  if [[ ! -s "$cf" ]]; then
    # инициализация: запоминаем «текущую позицию», старую историю не алертим
    journalctl -q -u x-ui -n 1 --cursor-file="$cf" >/dev/null 2>&1
    return 0
  fi
  out=$(journalctl -q -u x-ui -o cat --cursor-file="$cf" 2>/dev/null); jrc=$?
  if (( jrc == 0 )); then
    out=$(grep -aE 'logged in successfully: username=|failed login: username=' <<<"$out" || true)
    [[ -n "$out" ]] || return 0
    while IFS= read -r line; do
      [[ -z "$line" ]] && continue
      if [[ "$line" == *"logged in successfully"* ]]; then res="✅ успех"; else res="❌ неудача"; fi
      un=$(sed -nE 's/.*username="([^"]*)".*/\1/p' <<<"$line")
      ip=$(sed -nE 's/.*IP="([^"]*)".*/\1/p' <<<"$line")
      extra=""
      [[ -n "$un" ]] && extra+=" · ${un}"
      [[ -n "$ip" && "$ip" != "127.0.0.1" ]] && extra+=" · IP ${ip}"
      if [[ "$res" == "❌ неудача" ]]; then
        rsn=$(sed -nE 's/.*reason="([^"]*)".*/\1/p' <<<"$line")
        [[ -z "$rsn" ]] && rsn="неверный логин или пароль"
        extra+=" · ${rsn}"
      fi
      mon_alert "🔑 <b>Вход в панель</b>: ${res}${extra}"
    done <<<"$out"
    return 0
  fi
  local bp logf="/var/bot_log/nginx/access.bot_log" sz
  bp=$(panel_base)
  sz=$(stat -c %s "$logf" 2>/dev/null || printf 0)
  if (( LOG_POS == 0 )); then
    LOG_POS=$sz
  elif (( sz < LOG_POS )); then
    LOG_POS=0
  elif (( sz > LOG_POS )); then
    local newl="" n=0 lastline="" codeL ip res extra
    newl=$(tail -c +"$((LOG_POS+1))" "$logf" 2>/dev/null | grep -F "POST ${bp}login " || true)
    LOG_POS=$sz
    if [[ -n "$newl" && "$EV_LOGIN" == "1" ]]; then
      while IFS= read -r lastline; do
        [[ -n "$lastline" ]] && n=$((n+1))
      done <<<"$newl"
      lastline=$(tail -1 <<<"$newl")
      codeL=$(awk '{print $9}' <<<"$lastline")
      ip=$(awk '{print $1}' <<<"$lastline")
      res="неудача (${codeL:-?})"; [[ "$codeL" == "200" ]] && res="успех"
      extra=""
      [[ "$ip" != "127.0.0.1" && -n "$ip" ]] && extra=" · IP ${ip}"
      (( n > 1 )) && extra+=" · всего попыток: ${n}"
      mon_alert "🔑 <b>Вход в панель</b>: ${res}${extra}"
    fi
  fi
  mon_save
}

# ── TG-выход бота: только ЧТЕНИЕ state (ведёт stack-manager.sh, п.7 → TG-бот) ─
out_load() {
  [[ -f "$OUT_FILE" ]] || return 0
  TG_OUT_MODE=$(grep -a '^TG_OUT_MODE=' "$OUT_FILE" | tail -1 | cut -d= -f2-)
  TG_OUT_TAG=$(grep -a '^TG_OUT_TAG=' "$OUT_FILE" | tail -1 | cut -d= -f2-)
  TG_OUT_PORT=$(grep -a '^TG_OUT_PORT=' "$OUT_FILE" | tail -1 | cut -d= -f2-)
  TG_SOCKS_B64=$(grep -a '^TG_SOCKS_B64=' "$OUT_FILE" | tail -1 | cut -d= -f2-)
  TG_OURS=$(grep -a '^TG_OURS=' "$OUT_FILE" | tail -1 | cut -d= -f2-)
  [[ "$TG_OUT_MODE" =~ ^(direct|socks|outbound)$ ]] || TG_OUT_MODE="direct"
  [[ "$TG_OURS" =~ ^[01]$ ]] || TG_OURS=0
}
tgout_cur_recalc() {
  case "$TG_OUT_MODE" in
    outbound) [[ -n "$TG_OUT_PORT" ]] && TG_PROXY_CUR="socks5h://127.0.0.1:${TG_OUT_PORT}" || TG_PROXY_CUR="" ;;
    socks)    TG_PROXY_CUR=$(printf '%s' "$TG_SOCKS_B64" | base64 -d 2>/dev/null) ;;
    *)        TG_PROXY_CUR="$TG_PROXY" ;;
  esac
}
out_check_reload() { # правки из SSH-скрипта подхватываются на лету (по mtime state-файла)
  local m; m=$(stat -c %Y "$OUT_FILE" 2>/dev/null || printf '0')
  [[ "$m" == "$OUT_MTIME" ]] && return 0
  OUT_MTIME="$m"
  local prev="$TG_OUT_MODE/$TG_OUT_TAG/$TG_OUT_PORT"
  out_load; tgout_cur_recalc
  [[ "$prev" != "$TG_OUT_MODE/$TG_OUT_TAG/$TG_OUT_PORT" ]] && bot_log "tg-выход изменён stack-manager.sh → $TG_OUT_MODE ${TG_OUT_TAG:+($TG_OUT_TAG)}${TG_OUT_PORT:+ :$TG_OUT_PORT}"
}

# ── диспетчер ───────────────────────────────────────────────────────────────
dispatch() { # $1=chat $2=text $3=callback_data $4=cb_id $5=cb_message_id
  local chat="$1" text="$2" cbdata="$3" cbid="$4" cbmid="$5"
  if [[ -n "$cbdata" ]]; then
    tg_answer_cb "$cbid"
    [[ "$chat" != "$ADMIN_CHAT_ID" ]] && return 0
    bot_log "DEBUG: cb=$cbdata (step=$NEW_STEP in=$NEW_IN gb=$NEW_GB days=$NEW_DAYS email=$NEW_EMAIL)"
    case "$cbdata" in
      nav:*) show_screen "$chat" "${cbdata#nav:}" ;;
      clpage:*)
        local p="${cbdata#clpage:}"
        if [[ "$p" =~ ^[0-9]+$ ]]; then CL_PAGE=$((10#$p)); show_screen "$chat" "clients"; fi ;;
      err:*)
        local eu; eu=$(err_unit "${cbdata#err:}") || eu=""
        if [[ -z "$eu" ]]; then tg_send "$chat" "Не знаю такой сервис. Доступны: xui, nginx, adg, f2b, bot."
        else tg_send_kb "$chat" "$(err_tail "$eu")" "$KB_HIDE" >/dev/null; fi ;;
      hide)
        tg_del "$chat" "$cbmid"
        [[ "$cbmid" == "$WINDOW_MID" ]] && WINDOW_MID=""
        if [[ "$cbmid" == "$WIZ_MID" ]]; then WIZ_MID=""; wiz_save; fi
        if [[ "$cbmid" == "$E_MID" ]]; then E_MID=""; E_STEP=""; fi
        rm -f "$CARD_FLAG" ;;
      refresh) show_screen "$chat" "$CUR_MENU" ;;
      auto)
        if [[ -f "$CARD_FLAG" ]]; then rm -f "$CARD_FLAG"; tg_send "$chat" "⏹ Автообновление остановлено."
        else printf '%s server' "$WINDOW_MID" > "$CARD_FLAG"; start_autoloop; tg_send "$chat" "▶️ Автообновление 10с включено."; fi ;;
      client:*) send_client_pack "$chat" "${cbdata#client:}" ;;
      copen:*)
        local n="${cbdata#copen:}" em
        [[ "$n" =~ ^[0-9]+$ ]] || return 0
        em=$(sqlite3 "$XUI_DB" "SELECT COALESCE(email,'') FROM clients ORDER BY id LIMIT 1 OFFSET $(( n - 1 ));" 2>/dev/null)
        # без em_ok: имена клиентов бывают кириллицей/с "+", важен факт существования в БД
        if [[ -n "$em" ]] && client_exists "$em"; then
          E_EMAIL="$em"; ecard_close "$chat"; show_screen "$chat" "client"
        else
          tg_send "$chat" "Клиент не найден (в БД нет строки с этим номером)."
        fi ;;
      csub:*)
        local e="${cbdata#csub:}" url
        if ! client_exists "$e"; then tg_send "$chat" "Клиент не найден."; return 0; fi
        if url=$(sub_url_for "$e"); then
          tg_send_kb "$chat" "🔗 ${e}"$'\n'"$url" "$KB_HIDE" >/dev/null
        else
          tg_send "$chat" "У клиента ${e} нет sub_id."
        fi ;;
      cqr:*)
        local e="${cbdata#cqr:}" url
        if ! client_exists "$e"; then tg_send "$chat" "Клиент не найден."; return 0; fi
        if url=$(sub_url_for "$e"); then
          send_qr_msg "$chat" "$url"
        else
          tg_send "$chat" "У клиента ${e} нет sub_id."
        fi ;;
      cin:*)
        local e="${cbdata#cin:}"
        if ! client_exists "$e"; then tg_send "$chat" "Клиент не найден."; return 0; fi
        E_EMAIL="$e"; NEW_STEP=""; E_STEP="in"; E_IN=$(client_in_csv "$e"); show_ecard "$chat" ;;
      cinb:*)
        local rest="${cbdata#cinb:}" e id
        e="${rest%:*}"; id="${rest##*:}"
        [[ "$id" =~ ^[0-9]+$ && "$e" == "$E_EMAIL" ]] || return 0
        if [[ ",$E_IN," == *",$id,"* ]]; then
          E_IN=$(printf '%s' "$E_IN" | tr ',' '\n' | grep -vx "$id" | paste -sd, -)
        else
          E_IN=$(printf '%s\n%s' "$E_IN" "$id" | sed '/^$/d' | paste -sd, -)
        fi
        E_STEP="in"; show_ecard "$chat" ;;
      cinok:*)
        local e="${cbdata#cinok:}" cur add rem r err=""
        client_exists "$e" || return 0
        if [[ "$e" != "$E_EMAIL" ]]; then tg_send "$chat" "⚠️ Сессия устарела — открой клиента заново."; return 0; fi
        cur=$(client_in_csv "$e")
        add=$(csv_diff "$E_IN" "$cur"); rem=$(csv_diff "$cur" "$E_IN")
        [[ -n "$rem" ]] && { r=$(api_client_ids "$e" detach "$rem"); [[ "$r" == "OK" ]] || err="detach: $r"; }
        [[ -z "$err" && -n "$add" ]] && { r=$(api_client_ids "$e" attach "$add"); [[ "$r" == "OK" ]] || err="attach: $r"; }
        if [[ -z "$err" ]]; then
          ecard_client_view "$chat"
        else
          ecard_close "$chat"; tg_send "$chat" "❌ $err"; show_screen "$chat" "client"
        fi ;;
      cgb:*)
        local e="${cbdata#cgb:}"
        if ! client_exists "$e"; then tg_send "$chat" "Клиент не найден."; return 0; fi
        E_EMAIL="$e"; NEW_STEP=""; E_STEP="gb"; show_ecard "$chat" ;;
      cgbset:*)
        local rest="${cbdata#cgbset:}" e gb ch r
        e="${rest%:*}"; gb="${rest##*:}"
        [[ "$gb" =~ ^[0-9]{1,6}$ && "$e" == "$E_EMAIL" ]] || { tg_send "$chat" "⚠️ Сессия устарела — открой клиента заново."; return 0; }
        ch=$(jq -nc --argjson gb "$(( gb * 1024 * 1024 * 1024 ))" '{totalGB:$gb}')
        r=$(api_client_update "$e" "$ch")
        ecard_client_view "$chat"
        [[ "$r" == "OK" ]] || tg_send "$chat" "❌ $r" ;;
      cgbtxt:*)
        local e="${cbdata#cgbtxt:}"
        if ! client_exists "$e"; then tg_send "$chat" "Клиент не найден."; return 0; fi
        E_EMAIL="$e"; NEW_STEP=""; E_STEP="gb_txt"; show_ecard "$chat" ;;
      cdays:*)
        local e="${cbdata#cdays:}"
        if ! client_exists "$e"; then tg_send "$chat" "Клиент не найден."; return 0; fi
        E_EMAIL="$e"; NEW_STEP=""; E_STEP="days"; show_ecard "$chat" ;;
      cdset:*)
        local rest="${cbdata#cdset:}" e d ms ch r
        e="${rest%:*}"; d="${rest##*:}"
        [[ "$d" =~ ^[0-9]{1,5}$ && "$e" == "$E_EMAIL" ]] || { tg_send "$chat" "⚠️ Сессия устарела — открой клиента заново."; return 0; }
        ms=0; (( d > 0 )) && ms=$(( ($(date +%s) + d * 86400) * 1000 ))
        ch=$(jq -nc --argjson ms "$ms" '{expiryTime:$ms}')
        r=$(api_client_update "$e" "$ch")
        ecard_client_view "$chat"
        [[ "$r" == "OK" ]] || tg_send "$chat" "❌ $r" ;;
      cdtxt:*)
        local e="${cbdata#cdtxt:}"
        if ! client_exists "$e"; then tg_send "$chat" "Клиент не найден."; return 0; fi
        E_EMAIL="$e"; NEW_STEP=""; E_STEP="days_txt"; show_ecard "$chat" ;;
      askdel:*)
        local e="${cbdata#askdel:}"
        if ! client_exists "$e"; then tg_send "$chat" "Клиент не найден."; return 0; fi
        PENDING="cdel:$e"; PENDING_TS=$SECONDS
        tg_confirm "cdel:$e" "$chat" "Удалить клиента ${e}? Подписка и QR перестанут работать." ;;
      ctgl:*)
        local e="${cbdata#ctgl:}" en r
        if ! client_exists "$e"; then tg_send "$chat" "Клиент не найден."; return 0; fi
        en=$(sqlite3 "$XUI_DB" "SELECT COALESCE(enable,0) FROM clients WHERE email='$e';" 2>/dev/null); en=${en:-0}
        if [[ "$en" == "1" ]]; then
          r=$(api_client_update "$e" '{"enable":false}')
        else
          r=$(api_client_update "$e" '{"enable":true}')
        fi
        show_screen "$chat" "client"
        [[ "$r" == "OK" ]] || tg_send "$chat" "❌ $r" ;;
      cback) ecard_client_view "$chat" ;;
      subsall)  tg_send_kb "$chat" "$(cmd_subs)" "$KB_HIDE" >/dev/null ;;
      doaudit)  tg_send_kb "$chat" "$(run_check)" "$KB_HIDE" >/dev/null ;;
      doinb)    tg_send_kb "$chat" "$(cmd_inbounds)" "$KB_HIDE" >/dev/null ;;
      askfix)   PENDING="fix"; PENDING_TS=$SECONDS; tg_confirm "fix" "$chat" "Запустить автопочинку (⚡ проверка и починка)?" ;;
      askawg)   PENDING="awg"; PENDING_TS=$SECONDS; tg_confirm "awg" "$chat" "Перезапустить AWG-интерфейсы (клиенты переподключатся)?" ;;
      askbackup) PENDING="backup"; PENDING_TS=$SECONDS; tg_confirm "backup" "$chat" "Сделать бэкап x-ui.db и прислать сюда документом?" ;;
      bkset:*)   tg_send "$chat" "$(bk_set_schedule "${cbdata#bkset:}")"; show_screen "$chat" "bksched" ;;
      mon:sw)    MON_ON=$(( 1 - MON_ON )); mon_save; show_screen "$chat" "bksched" ;;
      moniv:*)   MON_IV="${cbdata#moniv:}"; mon_save; show_screen "$chat" "bksched" ;;
      mon:*)
        local mk="${cbdata#mon:}"
        case "$mk" in
          out)    EV_OUT=$(( 1 - EV_OUT )); OUT_CNT=0; OUT_BAD=0 ;;
          outup)  EV_OUTUP=$(( 1 - EV_OUTUP )) ;;
          xray)   EV_XRAY=$(( 1 - EV_XRAY )) ;;
          node)   EV_NODE=$(( 1 - EV_NODE )); NODE_CNT=0; NODE_BAD=0 ;;
          nodeup) EV_NODEUP=$(( 1 - EV_NODEUP )) ;;
          login)  EV_LOGIN=$(( 1 - EV_LOGIN )) ;;
          cpu)    if (( EV_CPU == 0 )); then EV_CPU=1; CPU_TH=90
                  elif (( CPU_TH == 90 )); then CPU_TH=95
                  elif (( CPU_TH == 95 )); then CPU_TH=85
                  else EV_CPU=0; CPU_TH=90; fi ;;
          ram)    if (( EV_RAM == 0 )); then EV_RAM=1; RAM_TH=90
                  elif (( RAM_TH == 90 )); then RAM_TH=95
                  elif (( RAM_TH == 95 )); then RAM_TH=85
                  else EV_RAM=0; RAM_TH=90; fi ;;
          nginx)  EV_NGINX=$(( 1 - EV_NGINX )) ;;
          adg)    EV_ADG=$(( 1 - EV_ADG )) ;;
          disk)   if (( EV_DISK == 0 )); then EV_DISK=1; DISK_TH=85
                  elif (( DISK_TH == 85 )); then DISK_TH=90
                  elif (( DISK_TH == 90 )); then DISK_TH=95
                  else EV_DISK=0; DISK_TH=85; fi ;;
          cert)   EV_CERT=$(( 1 - EV_CERT )) ;;
          bkfail) EV_BKFAIL=$(( 1 - EV_BKFAIL )) ;;
        esac
        mon_save; show_screen "$chat" "bksched" ;;
      new:start)
        ecard_close "$chat"; E_EMAIL=""
        wiz_reset; NEW_STEP="wait_in"
        NEW_SUBID=$(tr -dc a-f0-9 </dev/urandom 2>/dev/null | head -c 16)
        show_wizard "$chat" ;;
      new:in:*)
        local iid="${cbdata#new:in:}"
        [[ "$iid" =~ ^[0-9]+$ ]] || return 0
        if sqlite3 "$XUI_DB" "SELECT 1 FROM inbounds WHERE id=$iid AND enable=1;" 2>/dev/null | grep -q 1; then
          if [[ ",$NEW_IN," == *",$iid,"* ]]; then
            NEW_IN=$(printf '%s' "$NEW_IN" | tr ',' '\n' | grep -vx "$iid" | paste -sd, -)
          else
            NEW_IN=$(printf '%s\n%s' "$NEW_IN" "$iid" | sed '/^$/d' | paste -sd, -)
          fi
          NEW_STEP="wait_in"; show_wizard "$chat"
        else
          tg_send "$chat" "⚠️ Инбаунд #$iid недоступен (выключен или удалён) — выбери заново."
          NEW_STEP="wait_in"; show_wizard "$chat"
        fi ;;
      new:indone) NEW_STEP="gb"; show_wizard "$chat" ;;
      new:gb:*)  NEW_GB="${cbdata#new:gb:}"; NEW_STEP="days"; show_wizard "$chat" ;;
      new:gbtxt) NEW_STEP="gb_txt"; show_wizard "$chat" ;;
      new:days:*) NEW_DAYS="${cbdata#new:days:}"; NEW_STEP="email"; show_wizard "$chat" ;;
      new:daystxt) NEW_STEP="days_txt"; show_wizard "$chat" ;;
      new:backgb)  NEW_STEP="wait_in"; show_wizard "$chat" ;;
      new:backdays) NEW_STEP="gb"; show_wizard "$chat" ;;
      new:emauto) NEW_EMAIL="tg-$(tr -dc a-z0-9 </dev/urandom 2>/dev/null | head -c 5)"; NEW_STEP="confirm"; show_wizard "$chat" ;;
      new:emtxt)  NEW_STEP="email_txt"; show_wizard "$chat" ;;
      new:go)
        local res em sub
        if [[ -z "$NEW_IN" || -z "$NEW_EMAIL" || -z "$NEW_SUBID" ]]; then
          # сессия мастера потеряна (рестарт бота / старая карточка) — начать заново
          wiz_reset; WIZ_MID=""; NEW_STEP="wait_in"
          NEW_SUBID=$(tr -dc a-f0-9 </dev/urandom 2>/dev/null | head -c 16)
          show_wizard "$chat"
          tg_send "$chat" "⚠️ Сессия мастера устарела (бот перезапускался). Пройди шаги заново — карточка выше."
        else
          res=$(api_create_client)
          em="$NEW_EMAIL"; sub="$NEW_SUBID"
          NEW_STEP="done"
          if [[ "$res" == "OK" ]]; then
            wiz_done "$chat" "✅ Клиент <b>$(hesc "$em")</b> создан. Подписка и QR ниже."
            new_client_send_links "$chat" "$em" "$sub"
          else
            wiz_done "$chat" "❌ Ошибка создания: $(hesc "$res")"
          fi
          wiz_reset
        fi ;;
      new:close) local wzm=$WIZ_MID; wiz_reset; NEW_STEP=""; [[ -n "$wzm" ]] && tg_del "$chat" "$wzm"; tg_send "$chat" "Мастер закрыт." ;;
      new:abort) local wzm=$WIZ_MID; wiz_reset; [[ -n "$wzm" ]] && tg_del "$chat" "$wzm" ;;
      askrestart:*)
        local svc="${cbdata#askrestart:}"
        case "$svc" in
          x-ui)  PENDING="restart-xui" ;;
          nginx) PENDING="restart-nginx" ;;
          xray)  PENDING="restart-xray" ;;
          AdGuardHome) PENDING="restart-adg" ;;
        esac
        PENDING_TS=$SECONDS; tg_confirm "$PENDING" "$chat" "Рестарт $svc?" ;;
      cancel) PENDING=""; tg_send "$chat" "Отменено." ;;
      confirm:*)
        if [[ "$PENDING" == "cdel:"* && "$cbdata" == "confirm:$PENDING" && $(( SECONDS - PENDING_TS )) -le 300 ]]; then
          local de="${PENDING#cdel:}"; PENDING=""
          local dr; dr=$(api_client_del "$de")
          ecard_close "$chat"
          [[ "$E_EMAIL" == "$de" ]] && E_EMAIL=""
          if [[ "$dr" == "OK" ]]; then
            tg_send "$chat" "🗑 Клиент ${de} удалён."
            show_screen "$chat" "clients"
          else
            tg_send "$chat" "❌ $dr"
            show_screen "$chat" "client"
          fi
        elif [[ "$PENDING" =~ ^(fix|awg|restart-xui|restart-nginx|restart-adg|restart-xray|backup)$ && "$cbdata" == "confirm:$PENDING" && $(( SECONDS - PENDING_TS )) -le 300 ]]; then
          local act="$PENDING"; PENDING=""
          if [[ "$act" == "backup" ]]; then
            tg_send "$chat" "💾 Готовлю бэкап…"
            tg_send "$chat" "$(timeout 180 /usr/local/sbin/xui-db-backup.sh 2>&1 | tail -5)"
          else
            do_confirmed "$chat" "$act"
          fi
        fi ;;
    esac
    return 0
  fi
  [[ "$chat" != "$ADMIN_CHAT_ID" ]] && return 0   # чужие — молча

  # текстовые шаги правки клиента (лимит ГБ / срок)
  if [[ "$E_STEP" == "gb_txt" ]]; then
    if [[ -z "$E_EMAIL" ]] || ! client_exists "$E_EMAIL"; then
      E_STEP=""; tg_send "$chat" "⚠️ Сессия устарела — открой клиента заново."
    elif [[ "$text" =~ ^[0-9]{1,6}$ ]]; then
      local egb r
      egb=$(jq -nc --argjson gb "$(( 10#$text * 1024 * 1024 * 1024 ))" '{totalGB:$gb}')
      r=$(api_client_update "$E_EMAIL" "$egb")
      if [[ "$r" == "OK" ]]; then ecard_client_view "$chat"; else E_STEP=""; tg_send "$chat" "❌ $r"; fi
    else
      tg_send "$chat" "Пришли целое число ГБ (например 200)."
    fi
    return 0
  fi
  if [[ "$E_STEP" == "days_txt" ]]; then
    if [[ -z "$E_EMAIL" ]] || ! client_exists "$E_EMAIL"; then
      E_STEP=""; tg_send "$chat" "⚠️ Сессия устарела — открой клиента заново."
    elif [[ "$text" =~ ^[0-9]{1,5}$ ]]; then
      local ems ed r
      ems=$(( ($(date +%s) + 10#$text * 86400) * 1000 ))
      ed=$(jq -nc --argjson ms "$ems" '{expiryTime:$ms}')
      r=$(api_client_update "$E_EMAIL" "$ed")
      if [[ "$r" == "OK" ]]; then ecard_client_view "$chat"; else E_STEP=""; tg_send "$chat" "❌ $r"; fi
    else
      tg_send "$chat" "Пришли целое число дней (например 30)."
    fi
    return 0
  fi

  # текстовые шаги мастера
  if [[ "$NEW_STEP" == "gb_txt" ]]; then
    if [[ "$text" =~ ^[0-9]{1,5}$ ]]; then NEW_GB=$((10#$text)); NEW_STEP="days"; show_wizard "$chat"
    else tg_send "$chat" "Пришли целое число ГБ (например 200)."; fi
    return 0
  fi
  if [[ "$NEW_STEP" == "days_txt" ]]; then
    if [[ "$text" =~ ^[0-9]{1,4}$ ]]; then NEW_DAYS=$((10#$text)); NEW_STEP="email"; show_wizard "$chat"
    else tg_send "$chat" "Пришли целое число дней (например 30)."; fi
    return 0
  fi
  if [[ "$NEW_STEP" == "email_txt" ]]; then
    local em
    em=$(printf '%s' "$text" | tr -cd 'A-Za-z0-9_.-' | cut -c1-30)
    if [[ ${#em} -ge 3 ]]; then NEW_EMAIL="$em"; NEW_STEP="confirm"; show_wizard "$chat"
    else tg_send "$chat" "Имя: 3-30 символов, латиница/цифры/._-"; fi
    return 0
  fi

  case "$text" in
    /start|/help|/menu)
      # заметка перед окном — обычное сообщение, с кнопкой «🗑 Скрыть»
      tg_send "$chat" "Панель стека. Управление — кнопками в окне ниже."
      WINDOW_MID=""; show_screen "$chat" "main" ;;
    /status)  show_screen "$chat" "server" ;;
    /audit)   tg_send_kb "$chat" "$(run_check)" "$KB_HIDE" >/dev/null ;;
    /subs)    tg_send_kb "$chat" "$(cmd_subs)" "$KB_HIDE" >/dev/null ;;
    /fix)     PENDING="fix"; PENDING_TS=$SECONDS; tg_confirm "fix" "$chat" "Запустить автопочинку (⚡ проверка и починка)?" ;;
    /cancel)  PENDING=""; wiz_reset; tg_send "$chat" "Ок." ;;
    /err*)
      local ea eu
      ea=$(printf '%s' "$text" | awk '{print $2}')
      [[ -z "$ea" ]] && ea="xui"
      eu=$(err_unit "$ea") || eu=""
      if [[ -z "$eu" ]]; then tg_send "$chat" "Не знаю сервис «$(hesc "$ea")». Доступны: xui, nginx, adg, f2b, bot (или /err без аргумента = x-ui)."
      else tg_send_kb "$chat" "$(err_tail "$eu")" "$KB_HIDE" >/dev/null; fi ;;
    *)        tg_send "$chat" "Используй окно панели или /start." ;;
  esac
}

# ── главный цикл (long polling) ─────────────────────────────────────────────
wiz_load
mon_load
out_load; tgout_cur_recalc
OUT_MTIME=$(stat -c %Y "$OUT_FILE" 2>/dev/null || printf '0')
main_loop() {
while :; do
  out_check_reload
  mon_tick
  mon_login_check
  resp=$(tgc -s --retry 2 --retry-delay 2 --max-time 25 "$API/getUpdates?timeout=15&offset=${OFFSET}")
  [[ -z "$resp" ]] && { sleep 3; continue; }   # сеть моргнула — короткая пауза, не горячий цикл
  ok=$(jq -r '.ok // false' <<<"$resp" 2>/dev/null) || ok=false
  if [[ "$ok" != "true" ]]; then
    ec=$(jq -r '.error_code // 0' <<<"$resp" 2>/dev/null)
    if [[ "$ec" == "409" ]]; then
      # 409 = слот getUpdates занят другим поллером: спим 1с и тут же перехватываем окно
      # (долгий сон здесь = бот не получает нажатия, пока соперник держит long-poll)
      (( C409LOG += 1 ))
      (( C409LOG % 10 == 1 )) && bot_log "409 Conflict — слот занят другим поллером, перехватываю (подавл. лог $(( C409LOG - 1 )) шт)"
      sleep 1; continue
    fi
    bot_log "API: $(head -c 200 <<<"$resp")"; sleep 5; continue
  fi
  if (( OFFSET < 0 )); then   # первый успешный опрос после старта: пропускаем накопленное, не спамим старыми карточками
    OFFSET=$(jq -r '[.result[]?.update_id] | if length>0 then (max+1) else 0 end' <<<"$resp" 2>/dev/null)
    [[ "$OFFSET" =~ ^[0-9]+$ ]] || OFFSET=0
    offset_save; continue
  fi
  while IFS= read -r upd; do
    [[ -z "$upd" ]] && continue
    uid=$(jq -r '.update_id' <<<"$upd")
    (( uid >= OFFSET )) && OFFSET=$((uid+1))
    chat=$(jq -r '.message.chat.id // .callback_query.message.chat.id // empty' <<<"$upd")
    text=$(jq -r '.message.text // empty' <<<"$upd")
    cbdata=$(jq -r '.callback_query.data // empty' <<<"$upd")
    cbid=$(jq -r '.callback_query.id // empty' <<<"$upd")
    cbmid=$(jq -r '.callback_query.message.message_id // empty' <<<"$upd")
    [[ -z "$chat" ]] && continue
    if [[ "$chat" != "$ADMIN_CHAT_ID" ]]; then
      if [[ -z "$ADMIN_CHAT_ID" && -n "$text" ]]; then
        bot_log "режим обучения: chat_id=$chat прислал: $text (не отвечаю; впиши id в /root/.tg-stack-bot.env)"
      fi
      continue
    fi
    dispatch "$chat" "$text" "$cbdata" "$cbid" "$cbmid"
  done < <(jq -c '.result[]?' <<<"$resp" 2>/dev/null)
  offset_save
done
}

run_bot() { # точка входа режима --bot: init → курсор апдейтов → супервизор
bot_init   # конфиг, проверки jq/flock, синглтон flock (при отсутствии токена — exit)
OFFSET=$(cat "$OFFSET_FILE" 2>/dev/null || true)
[[ "$OFFSET" =~ ^[0-9]+$ ]] || OFFSET=-1   # -1 = первый опрос: курсор ставим «за последний» апдейт, накопленное не переигрываем
C409LOG=0                                  # счётчик подавленных 409 (лог раз в 10)
bot_log "бот запущен (admin=${ADMIN_CHAT_ID:-НЕ задан — режим обучения}; tg-выход=$( [[ -n "$TG_PROXY_CUR" ]] && printf '%s: %s' "$TG_OUT_MODE" "$TG_PROXY_CUR" || printf 'прямой' ))"
# ── супервизор: внутренний цикл не должен возвращаться; если вернулся — поднимаем ──
while :; do
  main_loop
  bot_log "главный цикл завершился (неожиданно) — перезапуск через 3 с"
  sleep 3
done
}
