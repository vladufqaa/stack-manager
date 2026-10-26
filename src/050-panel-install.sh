# УСТАНОВКА ПАНЕЛИ
# =====================================================================
# СЕРТ, ВПИСАННЫЙ В НАСТРОЙКИ x-ui (в т.ч. выпущенный через меню x-ui: x-ui setting
# -webCert/-webCertKey или acme-модулем панели). Скрипт СЧИТЫВАЕТ его и пользуется им,
# ничего не перевыпуская. Печатает "<cert> <key> [domain]"; код 1 — живого серта нет.
panel_cert_from_db() {
  [[ -z "$XUI_DB" || ! -f "$XUI_DB" ]] && return 1
  local c k d end
  c=$(xui_get webCertFile)
  k=$(xui_get webKeyFile)
  d=$(xui_get webDomain)
  [[ -z "$c" || ! -f "$c" ]] && return 1
  [[ -z "$k" || ! -f "$k" ]] && k=$(xui_get subKeyFile)
  [[ -z "$k" || ! -f "$k" ]] && return 1
  openssl x509 -noout -in "$c" >/dev/null 2>&1 || return 1
  end=$(openssl x509 -noout -enddate -in "$c" 2>/dev/null | cut -d= -f2)
  [[ -z "$end" ]] && return 1
  [[ $(date -d "$end" +%s 2>/dev/null || echo 0) -lt $(date +%s) ]] && return 1
  # домен: webDomain → subDomain → SAN/CN самого серта (x-ui меню могло не вписать домен)
  [[ -z "$d" ]] && d=$(xui_get subDomain)
  if [[ -z "$d" ]]; then
    d=$(openssl x509 -noout -ext subjectAltName -in "$c" 2>/dev/null \
        | grep -oE 'DNS:[^,]+' | head -1 | sed 's/DNS://; s/^\*\.//')
    [[ -z "$d" ]] && d=$(openssl x509 -noout -subject -in "$c" 2>/dev/null \
        | grep -oE 'CN ?= ?[^/,]+' | head -1 | sed 's/.*CN *= *//')
  fi
  echo "$c $k ${d}"
  return 0
}

# Автобэкап состояния стека при каждом старте: x-ui.db + nginx-конфиги.
# Держим последние 5 копий в /root/stack-backups/auto-*
auto_backup_stack() {
  local bd="/root/stack-backups/auto-$(date +%Y%m%d-%H%M%S)"
  local saved=false
  mkdir -p "$bd" 2>/dev/null || return 0
  [[ -f "$XUI_DB" ]] && { cp -a "$XUI_DB" "$bd/" 2>/dev/null && saved=true; }
  for f in /etc/nginx/sites-available/stack.conf /etc/nginx/sites-enabled/stack.conf \
           /etc/nginx/streams-enabled/sni-router.conf /etc/nginx/streams-available/sni-router.conf; do
    [[ -f "$f" ]] && cp -a "$f" "$bd/" 2>/dev/null && saved=true
  done
  # Сохраняем итоговый Xray-конфиг как диагностический снимок. Это не источник
  # восстановления и не заменяет templateSettings: снимок нужен для сравнения
  # тегов api/blackhole и routing после обновлений панели.
  local xf
  for xf in /usr/local/x-ui/bin/config.json /usr/local/x-ui/config.json /etc/x-ui/config.json; do
    if [[ -f "$xf" ]]; then
      cp -a "$xf" "$bd/xray-config.json" 2>/dev/null || true
      sha256sum "$xf" 2>/dev/null | awk '{print $1}' > "$bd/xray-config.sha256" 2>/dev/null || true
      printf '%s\n' "$xf" > "$bd/xray-config.path"
      XRAY_SNAPSHOT_PATH="$xf" XRAY_SNAPSHOT_MANIFEST="$bd/xray-manifest.json" python3 - <<'PYXMAN' 2>/dev/null || true
import json, os, hashlib
from pathlib import Path
p=Path(os.environ['XRAY_SNAPSHOT_PATH']); raw=p.read_bytes(); c=json.loads(raw.decode('utf-8'))
obs=[x.get('tag') for x in c.get('outbounds',[]) if isinstance(x,dict) and isinstance(x.get('tag'),str)]
r=c.get('routing') if isinstance(c.get('routing'),dict) else {}
Path(os.environ['XRAY_SNAPSHOT_MANIFEST']).write_text(json.dumps({
  'schema':1,'source':str(p),'sha256':hashlib.sha256(raw).hexdigest(),
  'outboundTags':obs,'api':'api' in obs,'blackhole':'blackhole' in obs,
  'routingRules':len(r.get('rules',[])) if isinstance(r.get('rules'),list) else 0,
  'hasDns':isinstance(c.get('dns'),dict)
},ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
PYXMAN
      # Канонический manifest используется для сравнения с текущим config.json.
      cp -f "$bd/xray-manifest.json" "$BACKUP_DIR/xray-manifest.json" 2>/dev/null || true
      saved=true
      break
    fi
  done
  [[ "$saved" == true ]] || { rmdir "$bd" 2>/dev/null; return 0; }
  echo "backup-ok" > "$bd/.ok"
  # ретеншен: последние 5
  ls -1dt /root/stack-backups/auto-* 2>/dev/null | tail -n +6 | xargs -r rm -rf 2>/dev/null || true
  return 0
}

# Хелпер выпуска серта ЧЕРЕЗ МЕНЮ x-ui: acme.sh панели работает standalone на :80,
# а :80 у нас занимает nginx. Временно освобождаем ТОЛЬКО 80 (443/SNI-роутер и
# туннели продолжают работать), открываем 80 в UFW, ждём, возвращаем всё обратно
# и подхватываем новый серт панели в nginx.
xui_cert_menu_helper() {
  line; echo -e "${B}   ВЫПУСК СЕРТА ЧЕРЕЗ МЕНЮ x-ui${N}"; line
  echo "  Меню x-ui выпускает серт standalone-режимом на :80, а там висит nginx."
  echo "  Этот пункт временно освобождает :80 (443 не трогается), открывает 80 в UFW,"
  echo "  затем ждёт, пока ты выпустишь серт в панели, и восстанавливает всё обратно."
  echo
  local bak="/root/stack-backups/pre-xuicert-$(date +%Y%m%d-%H%M%S)"
  mkdir -p "$bak" 2>/dev/null || true
  cp -a /etc/nginx/sites-available/stack.conf /etc/nginx/sites-enabled/stack.conf \
        /etc/nginx/streams-enabled/sni-router.conf "$bak/" 2>/dev/null || true
  [[ -f "$XUI_DB" ]] && cp -a "$XUI_DB" "$bak/" 2>/dev/null || true

  # 1) закомментировать listen :80 во всех наших конфигах (маркер ACME80)
  local touched=()
  local f
  for f in /etc/nginx/sites-enabled/*.conf /etc/nginx/streams-enabled/*.conf /etc/nginx/sites-enabled/default; do
    [[ -f "$f" ]] || continue
    if grep -qE '^[[:space:]]*listen[[:space:]]+([^[:space:]]+:)?80[[:space:]]*;' "$f"; then
      sed -i -E 's/^([[:space:]]*listen[[:space:]]+([^[:space:]]+:)?80[[:space:]]*;)/#ACME80 \1/' "$f"
      touched+=("$f")
    fi
  done
  if [[ ${#touched[@]} -gt 0 ]]; then
    if nginx -t >/dev/null 2>&1; then
      nginx_reload || true
      log ":80 освобождён: ${touched[*]}"
    else
      local rf2
      for rf2 in "${touched[@]}"; do
        cp -a "$bak/$(basename "$rf2")" "$rf2" 2>/dev/null || sed -i 's/^#ACME80 //' "$rf2"
      done
      nginx -t >/dev/null 2>&1 && nginx_reload || true
      err "nginx -t не прошёл после правки — откат выполнен"
      return 1
    fi
  else
    log ":80 в nginx-конфигах не найден — освобождать нечего"
  fi

  # 2) UFW: открыть 80 (ACME стучится извне)
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
    ufw allow 80/tcp comment "acme-temp" >/dev/null 2>&1 || true
    log "UFW: 80/tcp открыт"
  fi

  # 3) КТО выпускает: скрипт сам (acme.sh) или пользователь в панели x-ui
  local cert_mode="" cert_dom="" cert_ok=false
  ask cert_mode "Кто выпускает серт?  1) скрипт сам (acme.sh, авто)  2) я сам в панели x-ui" "1" '^[12]$'
  if [[ "$cert_mode" == "1" ]]; then
    local db_dom=""
    db_dom=$(xui_get webDomain 2>/dev/null || true)
    [[ -z "$db_dom" ]] && db_dom=$(xui_get subDomain 2>/dev/null || true)
    ask cert_dom "Домен для сертификата" "${db_dom:-panel.example.com}" '^[a-zA-Z0-9.-]+$'
    [[ -z "$cert_dom" ]] && { err "Домен не указан"; return 1; }
    # acme.sh установлен вместе с x-ui; если нет — ставим
    if [[ ! -x ~/.acme.sh/acme.sh ]]; then
      log "acme.sh не найден — устанавливаю…"
      curl -s https://get.acme.sh | sh >/dev/null 2>&1 || true
      [[ -x ~/.acme.sh/acme.sh ]] || { err "acme.sh не установился"; return 1; }
    fi
    log "Выпуск через acme.sh (standalone, :80): $cert_dom"
    ~/.acme.sh/acme.sh --set-default-ca --server letsencrypt --force >/dev/null 2>&1 || true
    if ~/.acme.sh/acme.sh --issue -d "$cert_dom" --standalone --httpport 80 --force; then
      local cdir="/etc/letsencrypt/live/$cert_dom"
      mkdir -p "$cdir"
      ~/.acme.sh/acme.sh --installcert --force -d "$cert_dom" \
        --key-file "$cdir/privkey.pem" \
        --fullchain-file "$cdir/fullchain.pem" \
        --reloadcmd "true" >/dev/null 2>&1 || true
      if [[ -f "$cdir/fullchain.pem" && -f "$cdir/privkey.pem" ]]; then
        # вписать серт в настройки панели (x-ui прочитает при рестарте)
        xui_set_setting webDomain   "$cert_dom"
        xui_set_setting webCertFile "$cdir/fullchain.pem"
        xui_set_setting webKeyFile  "$cdir/privkey.pem"
        xui_set_setting subCertFile "$cdir/fullchain.pem"
        xui_set_setting subKeyFile  "$cdir/privkey.pem"
        xui_set_setting subDomain   "$cert_dom"
        xui_set_setting subURI      "$(suburi_build "$cert_dom")"
        systemctl restart x-ui 2>/dev/null || true
        cert_ok=true
        log "Серт выпущен и вписан в панель: $cdir"
      else
        err "installcert не создал файлы в $cdir"
      fi
    else
      err "acme.sh не смог выпустить серт (домен резолвится на этот сервер? 80 открыт выше)"
    fi
  else
    warn "СЕЙЧАС: зайди в панель (или CLI x-ui) → SSL-сертификат → получить серт (порт 80)."
    warn "По завершении (успех или ошибка — неважно) вернись сюда и нажми Enter."
    read -rp "  Enter для восстановления :80 … " _r || _r=""
  fi

  # 3) вернуть listen :80
  local rf
  for rf in /etc/nginx/sites-enabled/*.conf /etc/nginx/streams-enabled/*.conf /etc/nginx/sites-enabled/default; do
    [[ -f "$rf" ]] || continue
    grep -q '^#ACME80 ' "$rf" && sed -i 's/^#ACME80 //' "$rf"
  done
  nginx -t >/dev/null 2>&1 && nginx_reload || warn "nginx -t: проверь конфиг вручную"
  # 4) UFW закрыть обратно
  command -v ufw >/dev/null 2>&1 && ufw delete allow 80/tcp >/dev/null 2>&1 || true
  log "UFW: 80/tcp закрыт обратно"
  nginx_reload >/dev/null 2>&1 || true

  # 5) подхватить новый серт панели в nginx (если панель его вписала)
  local pline="" pcert pkey
  pline=$(panel_cert_from_db) || true
  if [[ -n "$pline" && -f /etc/nginx/sites-available/stack.conf ]]; then
    pcert="${pline%% *}"; pkey=$(echo "$pline" | awk '{print $2}')
    local old_cert
    old_cert=$(awk '/# >>> panel/,/# <<< panel/ {if (/ssl_certificate /) print $2}' /etc/nginx/sites-available/stack.conf | head -1)
    if [[ -n "$old_cert" && "$old_cert" != "$pcert" ]]; then
      sed -i "s|$old_cert|$pcert|g; $(echo "$old_cert" | sed 's|fullchain|privkey|')|$pkey|g" /etc/nginx/sites-available/stack.conf
      nginx_reload >/dev/null 2>&1 || true
      log "Новый серт панели вписан в nginx: $pcert"
    else
      log "Серт панели уже актуален в nginx"
    fi
    log "Панель: ${pline##* } → $pcert (действует до: $(openssl x509 -noout -enddate -in "$pcert" 2>/dev/null | cut -d= -f2))"
  else
    warn "Панель не вписала серт в настройки — при следующем п.1 он будет подхвачен автоматически"
  fi
  log "Готово. Бэкап конфигов: $bak"
}

# =====================================================================
# ДОМЕН + СЕРТИФИКАТ ПАНЕЛИ СРАЗУ ПОСЛЕ ЧИСТОЙ УСТАНОВКИ
# =====================================================================
setup_panel_cert_domain() {
  [[ -z "$XUI_DB" || ! -f "$XUI_DB" ]] && { err "x-ui.db не найден"; return 1; }

  # уже настроено — не трогаем, но серт подписок приводим к панельному
  local cur_dom="" cur_cert="" cur_subcert="" cur_key="" cur_end=""
  cur_dom=$(xui_get webDomain); cur_cert=$(xui_get webCertFile); cur_subcert=$(xui_get subCertFile)
  if [[ -n "$cur_cert" && -f "$cur_cert" ]] && openssl x509 -noout -in "$cur_cert" >/dev/null 2>&1; then
    # СЕРТ УЖЕ ЕСТЬ (в т.ч. выпущенный через меню x-ui) — считываем и пользуемся им
    cur_end=$(openssl x509 -noout -enddate -in "$cur_cert" 2>/dev/null | cut -d= -f2)
    if [[ -z "$cur_dom" ]]; then
      # x-ui меню могло вписать серт без домена — восстанавливаем из SAN/CN
      cur_dom=$(openssl x509 -noout -ext subjectAltName -in "$cur_cert" 2>/dev/null \
          | grep -oE 'DNS:[^,]+' | head -1 | sed 's/DNS://; s/^\*\.//')
      [[ -z "$cur_dom" ]] && cur_dom=$(openssl x509 -noout -subject -in "$cur_cert" 2>/dev/null \
          | grep -oE 'CN ?= ?[^/,]+' | head -1 | sed 's/.*CN *= *//')
      if [[ -n "$cur_dom" ]]; then
        xui_set_setting webDomain "$cur_dom"
        xui_set_setting subDomain "$cur_dom"
        xui_set_setting subURI "$(suburi_build "$cur_dom")"
        log "Домен панели восстановлен из серта: $cur_dom (вписан в webDomain/subDomain)"
      fi
    fi
    log "Считан серт панели из настроек x-ui: ${cur_dom:-домен не определён} → $cur_cert"
    [[ -n "$cur_end" ]] && log "  действует до: $cur_end"
    cur_key=$(xui_get webKeyFile)
    # ПАНЕЛЬ: пути серта должны указывать в /etc/letsencrypt/live/ (единое место)
    if [[ "$cur_cert" != /etc/letsencrypt/live/* && -n "$cur_dom" ]]; then
      local mline=""
      mline=$(cert_mirror_to_certroot "$(dirname "$cur_cert")" "$cur_dom" 2>/dev/null || true)
      if [[ -n "$mline" ]]; then
        xui_set_setting webCertFile "${mline%% *}"
        xui_set_setting webKeyFile  "${mline##* }"
        xui_set_setting subCertFile "${mline%% *}"
        xui_set_setting subKeyFile  "${mline##* }"
        systemctl restart x-ui 2>/dev/null || true
        log "Серт панели перепривязан на ${mline%% *} (единое место live/)"
      fi
    fi
    if [[ -z "$cur_subcert" || "$cur_subcert" != "$cur_cert" || ! -f "$cur_subcert" ]]; then
      warn "subCertFile ($cur_subcert) ≠ панельному — заменяю на $cur_cert"
      xui_set_setting subCertFile "$cur_cert"
      xui_set_setting subKeyFile  "$cur_key"
      systemctl restart x-ui 2>/dev/null || true
      log "subCertFile/subKeyFile обновлены: $cur_cert"
    fi
    PANEL_DOMAIN="${PANEL_DOMAIN:-$cur_dom}"
    return 0
  fi

  echo; line; echo -e "${B}   ДОМЕН И СЕРТИФИКАТ ПАНЕЛИ${N}"; line
  local pdomain="${PANEL_DOMAIN:-}"
  if [[ -z "$pdomain" ]]; then
    ask pdomain "Домен панели (A-запись → этот сервер)" "panel.example.com" '^[a-zA-Z0-9.-]+$'
  fi
  [[ -z "$pdomain" ]] && { warn "Домен не указан — панель остаётся на самоподписанном сертификате"; return 1; }

  cert_issue "$pdomain" || { err "Сертификат $pdomain не выпущен"; return 1; }
  local cp_line="" pc="" pk=""
  cp_line=$(cert_paths "$pdomain") || true
  [[ -z "$cp_line" ]] && { err "cert_paths пуст для $pdomain"; return 1; }
  pc="${cp_line%% *}"; pk="${cp_line##* }"
  # пути панели — из /etc/letsencrypt/live/ (единое место)
  local mline=""
  mline=$(cert_mirror_to_certroot "$(dirname "$pc")" "$pdomain" 2>/dev/null || true)
  [[ -n "$mline" ]] && { pc="${mline%% *}"; pk="${mline##* }"; }

  xui_set_setting webDomain   "$pdomain"
  xui_set_setting webCertFile "$pc"
  xui_set_setting webKeyFile  "$pk"
  xui_set_setting subCertFile "$pc"
  xui_set_setting subKeyFile  "$pk"
  xui_set_setting subDomain   "$pdomain"
  # URL обратного прокси для подписок: иначе share-ссылки получают порт панели
  xui_set_setting subURI      "$(suburi_build "$pdomain")"

  systemctl restart x-ui 2>/dev/null || true
  sleep 2
  local chk=""
  chk=$(xui_get webCertFile)
  if [[ "$chk" == "$pc" ]]; then
    log "Панель: домен $pdomain + сертификат вписаны в настройки"
    PANEL_DOMAIN="$pdomain"
    SNI_USED["$pdomain"]="${SNI_USED[$pdomain]:-panel_backend}"
    return 0
  fi
  err "webCertFile не применился (chk='$chk')"
  return 1
}

install_lucx_panel() {
  line; echo -e "${B}   УСТАНОВКА ПАНЕЛИ LUCX UI${N}"; line
  detect_env
  [[ -n "$XUI_DB" && -f "$XUI_DB" ]] && { log "Панель уже установлена: $XUI_DB"; return 0; }
  warn "x-ui.db не найден — устанавливаю LucX UI (вопрос задаётся один раз, в начале скрипта)."

  local tmp_sh rc
  tmp_sh=$(mktemp /tmp/lucx-install.XXXXXX.sh 2>/dev/null) || { err "mktemp failed"; return 1; }
  log "Скачивание установщика LucX UI..."
  if ! curl -fSL --retry 3 "$LUCX_INSTALL_URL" -o "$tmp_sh" || [[ ! -s "$tmp_sh" ]]; then
    rm -f "$tmp_sh"
    err "Не удалось скачать установщик LucX UI ($LUCX_INSTALL_URL)"; return 1
  fi
  # ЖЁСТКИЙ SKIP SSL УСТАНОВЩИКА: панель ставится БЕЗ SSL (reverse proxy = наш nginx).
  # XUI_NONINTERACTIVE=1 обязателен: только в этом режиме установщик читает
  # XUI_SSL_MODE=none и НЕ показывает меню «1..4, default 2» (в интерактиве оно
  # показывается всегда и ведёт к конфликту «порт занят 80»).
  # Все параметры передаём через env — вопросов ноль. Серт панели вписывается
  # сразу после установки (setup_panel_cert_domain) или через СЕРТИФИКАТЫ → 5.
  # пароль панели: заданный при авто-установке (U_PANEL_PASS) → интерактивный
  # вопрос (Enter — случайный) → случайный; логин — U_PANEL_USER (Enter — admin)
  local lucx_user="${U_PANEL_USER:-admin}"
  local lucx_pass="${U_PANEL_PASS:-}"
  if [[ -z "$lucx_pass" ]]; then
    lucx_pass=$(openssl rand -base64 18 2>/dev/null | tr -dc 'a-zA-Z0-9' | head -c 16)
    [[ -z "$lucx_pass" ]] && lucx_pass="LucX$(date +%s)"
    if [[ -t 0 ]]; then
      ask lucx_pass "Пароль панели admin (Enter — случайный)" "$lucx_pass" '^.{6,}$'
    fi
  fi
  lucx_port=$(make_port)
  lucx_wbp=$(gen_random_string 12)
  log "Запуск установщика LucX UI (XUI_NONINTERACTIVE=1 + XUI_SSL_MODE=none — без вопросов и без SSL)..."
  XUI_NONINTERACTIVE=1 XUI_SSL_MODE=none XUI_DB_TYPE=sqlite \
    XUI_USERNAME="$lucx_user" XUI_PASSWORD="$lucx_pass" \
    XUI_PANEL_PORT="$lucx_port" XUI_WEB_BASE_PATH="$lucx_wbp" \
    bash "$tmp_sh"
  rc=$?
  rm -f "$tmp_sh"

  # креды панели — фиксируем (установщик в неинтерактиве берёт их из env)
  {
    echo "LucX UI панель — $(date '+%F %T')"
    echo "  Логин:  $lucx_user"
    echo "  Пароль: $lucx_pass"
  } > /root/panel-credentials.txt 2>/dev/null || true
  chmod 600 /root/panel-credentials.txt 2>/dev/null || true
  # запомнить финальные креды глобально — авто-поток не спрашивает второй раз
  U_PANEL_PASS="$lucx_pass"
  U_PANEL_USER="$lucx_user"

  if [[ $rc -ne 0 ]]; then
    err "Ошибка установки LucX UI"; return 1
  fi
  detect_env
  if [[ -n "$XUI_DB" && -f "$XUI_DB" ]]; then
    log "Панель установлена: $XUI_DB"
    # ЧИСТАЯ установка: старые SNI-записи панели/decoy/AdGuard недействительны
    # (новые порты/пути). Сносим sni-роутер и stack.conf — п.1 создаст заново.
    rm -f /etc/nginx/streams-enabled/sni-router.conf 2>/dev/null || true
    rm -f /etc/nginx/sites-enabled/stack.conf /etc/nginx/sites-available/stack.conf 2>/dev/null || true
    nginx -t >/dev/null 2>&1 && nginx_reload || true
    log "Старые SNI-записи панели/AdGuard очищены (п.1 создаст новые)"
    # nginx ставится зависимостью и может быть без автозапуска — стек обязан подниматься после ребра
    systemctl enable nginx >/dev/null 2>&1 || true
    # СРАЗУ после чистой установки: домен + настоящий сертификат панели
    setup_panel_cert_domain || warn "Домен/сертификат панели можно задать позже (п.1)"
    return 0
  fi
  err "Установка прошла, но x-ui.db не найден"; return 1
}

# =====================================================================
# ГЕНЕРАТОРЫ
# =====================================================================
gen_uuid() { cat /proc/sys/kernel/random/uuid 2>/dev/null || openssl rand -hex 16; }
gen_hex()  { openssl rand -hex "$1" 2>/dev/null || head -c "$1" /dev/urandom | xxd -p | head -c "$(( $1 * 2 ))"; }
gen_b64()  { openssl rand -base64 24 2>/dev/null | tr -d '/+=' | head -c 22; }
sql_escape() { echo "${1//\'/\'\'}"; }

gen_reality_keys() {
  local out="" priv="" pub=""
  if [[ -n "$XRAY_BIN" && -x "$XRAY_BIN" ]]; then
    out=$("$XRAY_BIN" x25519 2>/dev/null || true)
    priv=$(echo "$out" | grep -iE 'private' | awk '{print $NF}' | head -1)
    pub=$(echo "$out"  | grep -iE 'public'  | awk '{print $NF}' | head -1)
  fi
  if [[ -z "$priv" || -z "$pub" ]]; then
    priv=$(openssl rand -base64 32 | tr -d '/+=' | head -c 43)
    pub=$(openssl rand -base64 32 | tr -d '/+=' | head -c 43)
    warn "  xray не найден — Reality-ключи сгенерированы openssl и НЕВАЛИДНЫ! Установите панель (п.14), затем пересоздайте инбаунд."
  fi
  echo "$priv|$pub"
}

# =====================================================================
