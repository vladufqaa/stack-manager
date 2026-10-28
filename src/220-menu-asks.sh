# ГЛАВНОЕ МЕНЮ
# =====================================================================
# =====================================================================
# УДАЛЕНИЕ КОМПОНЕНТОВ
# =====================================================================
# AdGuard Home: остановка, удаление файлов/сервиса, заглушка вместо
# прокси на AdGuard в stack.conf
uninstall_adguard() {
  detect_env
  if [[ "$ADG_PRESENT" != true ]]; then
    warn "AdGuard Home не установлен."
    return 1
  fi
  line; echo -e "${B}   УДАЛЕНИЕ ADGUARD HOME${N}"; line
  echo "  Будут удалены: сервис, /opt/AdGuardHome, конфигурация и статистика."
  echo "  Бэкап конфига: /root/adguard-backup-<дата>.tar.gz"
  local sure=false
  askyn sure "Удалить AdGuard Home?" "n"
  [[ "$sure" == true ]] || { log "Отменено."; return 0; }

  tar -czf "/root/adguard-backup-$(date +%Y%m%d-%H%M%S).tar.gz" \
    -C / opt/AdGuardHome/AdGuardHome.yaml 2>/dev/null || true

  systemctl stop "$ADG_SERVICE" 2>/dev/null || true
  systemctl disable "$ADG_SERVICE" 2>/dev/null || true
  rm -f "/etc/systemd/system/$ADG_SERVICE.service" 2>/dev/null || true
  systemctl daemon-reload 2>/dev/null || true
  rm -rf /opt/AdGuardHome 2>/dev/null || true

  # stack.conf: только полный location / (прокси на удалённый AdGuard)
  # заменяем безопасно: старый awk обрывал вложенный блок и мог оставить
  # stack.conf с незакрытой фигурной скобкой.
  if [[ -f "$STACK_CONF" ]] && grep -q "proxy_pass https\?://127.0.0.1:[0-9]*;" "$STACK_CONF"; then
    local tmp=""
    tmp=$(mktemp) || true
    STACK_CONF_IN="$STACK_CONF" STACK_CONF_OUT="$tmp" python3 - <<'PYADG'
import os, sys
src = open(os.environ['STACK_CONF_IN'], encoding='utf-8').read().splitlines()
out=[]; i=0; replaced=False
while i < len(src):
    if src[i].strip() == 'location / {':
        j=i+1; depth=1
        while j < len(src):
            s=src[j].strip()
            if s.endswith('{'): depth += 1
            if s == '}':
                depth -= 1
                if depth == 0: break
            j += 1
        block='\n'.join(src[i:j+1]) if j < len(src) else ''
        if j < len(src) and 'proxy_pass https://127.0.0.1:' in block:
            out += ['    location / {', '        return 302 /404.html;', '    }']
            i=j+1; replaced=True; continue
    out.append(src[i]); i += 1
if replaced:
    open(os.environ['STACK_CONF_OUT'], 'w', encoding='utf-8').write('\n'.join(out)+'\n')
else:
    sys.exit(2)
PYADG
    if [[ -s "$tmp" ]] && mv "$tmp" "$STACK_CONF"; then
      nginx -t >/dev/null 2>&1 && nginx_reload || warn "nginx конфигурация требует проверки после удаления AdGuard"
    else
      rm -f "$tmp" 2>/dev/null || true
    fi
  fi
  ADG_PRESENT=false
  log "AdGuard Home удалён. Бэкап конфига: /root/adguard-backup-*.tar.gz"
}

# Панель LucX UI (x-ui): остановка, бэкап БД, удаление файлов/сервиса.
# Опционально — конфиги nginx стека (SNI-роутер + stack.conf).
uninstall_panel_lucx() {
  detect_env
  line; echo -e "${B}   УДАЛЕНИЕ ПАНЕЛИ LUCX UI (X-UI)${N}"; line
  if [[ -z "$XUI_DB" || ! -f "$XUI_DB" ]]; then
    warn "Панель не установлена (x-ui.db не найден)."
  else
    echo "  Будут удалены: сервис x-ui, /usr/local/x-ui, /etc/x-ui (БД + инбаунды!), /usr/bin/x-ui."
    echo "  Бэкап: /root/x-ui-backup-<дата>.tar.gz (восстановление распаковкой в /)."
  fi
  local sure=false
  askyn sure "Удалить панель LucX UI?" "n"
  [[ "$sure" == true ]] || { log "Отменено."; return 0; }

  # таймер автопочинки ссылается на скрипт — снимаем вместе с панелью
  uninstall_heal_timer

  if [[ -f "$XUI_DB" ]]; then
    tar -czf "/root/x-ui-backup-$(date +%Y%m%d-%H%M%S).tar.gz" -C / etc/x-ui 2>/dev/null || true
    log "Бэкап БД: /root/x-ui-backup-*.tar.gz"
  fi

  systemctl stop x-ui 2>/dev/null || true
  systemctl disable x-ui 2>/dev/null || true
  rm -f /etc/systemd/system/x-ui.service /etc/systemd/system/multi-user.target.wants/x-ui.service 2>/dev/null || true
  systemctl daemon-reload 2>/dev/null || true
  rm -rf /usr/local/x-ui /etc/x-ui 2>/dev/null || true
  rm -f /usr/bin/x-ui 2>/dev/null || true
  XUI_DB=""

  # конфиги nginx стека: без панели SNI-роутер и stack.conf не имеют смысла
  local drop_nginx=false
  askyn drop_nginx "Удалить и конфиги nginx стека (SNI-роутер, stack.conf)?" "y"
  if [[ "$drop_nginx" == true ]]; then
    rm -f /etc/nginx/streams-enabled/sni-router.conf /etc/nginx/streams-available/sni-router.conf 2>/dev/null || true
    rm -f "$STACK_LINK" "$STACK_CONF" 2>/dev/null || true
    if command -v nginx >/dev/null 2>&1; then
      nginx_reload || warn "Конфиги удалены, но nginx не удалось проверить/перезагрузить"
    else
      log "Конфиги nginx стека удалены; nginx уже не установлен."
    fi
    log "Конфиги nginx стека удалены."
  fi
  log "Панель LucX UI удалена. Бэкап: /root/x-ui-backup-*.tar.gz"

  # Без панели стек мёртв — предлагаем сразу установить панель с инбаундами.
  local redeploy=false
  askyn redeploy "Приступить к установке панели с настройкой инбаундов?" "y"
  if [[ "$redeploy" == true ]]; then
    initial_setup || err "Первоначальная установка завершилась с ошибкой — запусти п.1 вручную"
  else
    log "Выход из скрипта."
    exit 0
  fi
}

# --- Обновление скрипта с GitHub ---------------------------------------------
# Версия хранится в STACK_MANAGER_VERSION и показывается в шапке.
# URL берётся из /root/.stack-src (сохраняется после первого обновления).
version_is_newer() {
  local old="$1" new="$2" oa ob oc na nb nc
  IFS=. read -r oa ob oc <<<"${old#v}"
  IFS=. read -r na nb nc <<<"${new#v}"
  oa=${oa:-0}; ob=${ob:-0}; oc=${oc:-0}; na=${na:-0}; nb=${nb:-0}; nc=${nc:-0}
  (( 10#$na > 10#$oa ||
     (10#$na == 10#$oa && 10#$nb > 10#$ob) ||
     (10#$na == 10#$oa && 10#$nb == 10#$ob && 10#$nc > 10#$oc) ))
}
STACK_SRC_URL="$(cat /root/.stack-src 2>/dev/null || echo 'https://raw.githubusercontent.com/vladufqaa/stack-manager/main/stack-manager.sh')"

update_self() {
  line; echo -e "${B}   ОБНОВЛЕНИЕ СКРИПТА С GITHUB${N}"; line
  # Сравниваем именно запущенный файл, а не безусловно /root/stack-manager.sh:
  # при запуске копии из другого пути старый код ошибочно сообщал «идентичен».
  local cur="${BASH_SOURCE[0]}" src_url="$STACK_SRC_URL" tmp="" lock="" bakdir="" old_sha="" new_sha="" mode="" remote_version=""
  cur=$(readlink -f "$cur" 2>/dev/null || printf '%s' "$cur")
  [[ -f "$cur" && ! -L "$cur" ]] || cur="/root/stack-manager.sh"
  lock="${cur}.update.lock"
  exec 9>"$lock" || { err "Не удалось открыть lock-файл обновления"; return 1; }
  flock -n 9 || { err "Обновление уже выполняется другим процессом"; return 1; }
  tmp=$(mktemp "$(dirname "$cur")/.stack-manager.update.XXXXXX") || { err "Не удалось создать временный файл"; return 1; }
  trap 'rm -f "$tmp" 2>/dev/null || true; flock -u 9 2>/dev/null || true' RETURN
  ask src_url "Raw-URL скрипта (Enter — сохранённый)" "$src_url" '^https?://'
  log "Качаю: $src_url"
  # raw.githubusercontent кэшируется ~5 минут (Fastly): сразу после пуша можно
  # скачать старую версию и получить ложное «обновление не требуется».
  # ?ts=… меняет ключ кэша → всегда свежий файл. В /root/.stack-src пишем
  # чистый URL (без бастера).
  # Обходим кэш raw.githubusercontent независимо от того, есть ли в URL
  # уже query-параметры. Заголовки no-cache дополняют уникальный nonce.
  local sep='?'; [[ "$src_url" == *\?* ]] && sep='&'
  local bust_url="${src_url}${sep}stack_nonce=$(date +%s%N)-$$"
  if ! curl -fsSL -H 'Cache-Control: no-cache, no-store' -H 'Pragma: no-cache' \
      --retry 3 --retry-delay 1 --max-time 45 "$bust_url" -o "$tmp" || [[ ! -s "$tmp" ]]; then
    err "Не удалось скачать (проверь URL/доступность репозитория)"
    rm -f "$tmp"; return 1
  fi
  # GitHub/прокси иногда добавляют CRLF или UTF-8 BOM. Нормализуем
  # загруженный файл ДО bash -n и атомарной установки, иначе Bash увидит
  # shebang с CR и после перезапуска выдаст «/usr/bin/env: No such file».
  sed -i 's/\r$//' "$tmp"
  if [[ "$(LC_ALL=C od -An -t x1 -N3 "$tmp" 2>/dev/null | tr -d ' ')" == "efbbbf" ]]; then
    tail -c +4 "$tmp" > "${tmp}.nobom" && mv -f "${tmp}.nobom" "$tmp"
  fi
  local _shebang=""
  _shebang=$(head -n1 "$tmp")
  # Shebang проверяем мягко: некоторые прокси меняют BOM/пробелы, но
  # главным доказательством остаётся строгий синтаксический bash -n.
  if [[ ! "$_shebang" =~ bash ]]; then
    warn "Первая строка не распознана как shebang Bash — продолжаю, bash -n проверит файл"
  fi
  bash -n "$tmp" || { err "Новый файл не проходит bash -n — обновление отменено"; rm -f "$tmp"; return 1; }
  old_sha=$(sha256sum "$cur" | awk '{print $1}')
  new_sha=$(sha256sum "$tmp" | awk '{print $1}')
  # Если сеть/прокси вернули старую копию GitHub, не объявляем её актуальной:
  # сравниваем содержимое также с коротким commit API (если доступен).
  local remote_sha=""
  remote_version=$(grep -m1 -E '^STACK_MANAGER_VERSION="[^"]+"' "$tmp" | sed -E 's/^STACK_MANAGER_VERSION="([^"]+)"/\1/' || true)
  if [[ -z "$remote_version" ]]; then
    warn "В загруженном файле не найдена STACK_MANAGER_VERSION — обновление отменено"
    rm -f "$tmp"; return 1
  fi
  if [[ "$src_url" == https://raw.githubusercontent.com/*/*/main/* ]]; then
    local api_repo api_file
    api_repo=$(printf '%s' "$src_url" | sed -E 's#https://raw.githubusercontent.com/([^/]+/[^/]+)/main/.*#\1#')
    api_file=$(printf '%s' "$src_url" | sed -E 's#https://raw.githubusercontent.com/[^/]+/[^/]+/main/##')
    remote_sha=$(curl -fsSL -H 'Cache-Control: no-cache' \
      "https://api.github.com/repos/$api_repo/commits?path=$api_file&per_page=1" 2>/dev/null \
      | grep -m1 '"sha"' | sed -E 's/.*"sha"[[:space:]]*:[[:space:]]*"([0-9a-f]+)".*/\1/' || true)
  fi
  if [[ "$remote_version" == "$STACK_MANAGER_VERSION" ]]; then
    log "Обновление не требуется — версия v$STACK_MANAGER_VERSION уже актуальна (sha256: $new_sha)"
    rm -f "$tmp"; return 0
  fi
  if ! version_is_newer "$STACK_MANAGER_VERSION" "$remote_version"; then
    warn "Обновление отменено: удалённая версия v$remote_version не новее локальной v$STACK_MANAGER_VERSION"
    rm -f "$tmp"; return 1
  fi
  echo "  версия: v$STACK_MANAGER_VERSION → v$remote_version"
  echo "  sha256: $old_sha → $new_sha"
  local yn=false
  askyn yn "Сохранить резервную копию и заменить $cur?" "y"
  [[ "$yn" == true ]] || { rm -f "$tmp"; log "Отменено"; return 0; }
  bakdir="$BACKUP_DIR/self-update-$(date +%Y%m%d-%H%M%S)"
  mkdir -p "$bakdir" || { err "Не удалось создать каталог отката"; return 1; }
  mode=$(stat -c '%a' "$cur" 2>/dev/null || echo 700)
  cp -p "$cur" "$bakdir/stack-manager.sh" || { err "Не удалось сохранить старую версию"; return 1; }
  printf 'old_sha=%s\nnew_sha=%s\nsource=%s\n' "$old_sha" "$new_sha" "$src_url" > "$bakdir/metadata"
  sha256sum "$bakdir/stack-manager.sh" > "$bakdir/stack-manager.sh.sha256"; sync
  mv -f "$tmp" "$cur" || { err "Не удалось атомарно заменить скрипт"; return 1; }
  chmod "$mode" "$cur" 2>/dev/null || chmod 700 "$cur"; sync
  # После замены проверяем только сам файл. --check запускает полноценный аудит
  # сервера и закономерно возвращает ненулевой код при удалённой панели/nginx,
  # поэтому его результат нельзя использовать как критерий валидности обновления.
  if ! bash -n "$cur" || [[ "$(sha256sum "$cur" | awk '{print $1}')" != "$new_sha" ]]; then
    err "Проверка нового файла не пройдена — выполняю откат"
    cp -p "$bakdir/stack-manager.sh" "$cur"; chmod "$mode" "$cur" 2>/dev/null || true; sync; return 1
  fi
  printf '%s' "$src_url" > /root/.stack-src && chmod 600 /root/.stack-src
  # Обновление запускается поверх уже существующей системы. Не считаем
  # перезапуск после self-update «первым запуском» и не показываем повторно
  # pre-install-вопрос только из-за отсутствующего старого маркера.
  mkdir -p "$BACKUP_DIR" 2>/dev/null || true
  touch "$BACKUP_DIR/.stack-ever-ran" 2>/dev/null || true
  log "Обновлено атомарно ✓ (backup: $bakdir) — перезапускаюсь…"
  trap - RETURN; flock -u 9 2>/dev/null || true
  exec bash "$cur"
}

# =====================================================================
# ЕДИНЫЕ БЛОКИ ВОПРОСОВ УСТАНОВКИ — общий путь для п.1 (первичная
# настройка), п.17 (переустановка после удаления) и авто-подъёма.
# Порядок ВСЕГДА: панель (пароль+порты) → AdGuard (да/нет+пароль+где) →
# заглушка панели → серты (тип 1/2, уже в cert_issue) → инбаунды.
# =====================================================================
ask_panel_creds() {
  # ПАНЕЛЬ УЖЕ УСТАНОВЛЕНА → берём её текущие значения и НИЧЕГО не спрашиваем:
  # порты/пути остаются как есть, пароль в БД не трогаем (его всё равно
  # нельзя «прочитать» — а спрашивать = предлагать сменить, это ломает вход).
  if [[ -n "$XUI_DB" && -f "$XUI_DB" ]]; then
    local _wp _ws _bp _sp
    _wp=$(xui_get webPort);     _ws=$(xui_get subPort)
    _bp=$(xui_get webBasePath); _sp=$(xui_get subPath)
    if [[ -n "$_wp" && -n "$_bp" && -n "$_sp" && -n "$_ws" ]]; then
      U_PANEL_PASS="${U_PANEL_PASS:-}"   # пароль не спрашиваем и не меняем
      # Если креды/порты уже собраны в этой сессии (спросили ДО установки —
      # единый путь первого запуска) — сохраняем их; иначе берём фактические
      # значения установленной панели (повторный п.1 на живом стеке).
      if [[ -n "${U_PANEL_PORT}${U_PANEL_PATH}${U_SUB_PORT}${U_SUB_PATH}" ]]; then
        log "Панель установлена — порты/пути из анкеты этой сессии сохраняю:"
        log "  панель   : $U_PANEL_PORT $U_PANEL_PATH"
        log "  подписки : $U_SUB_PORT $U_SUB_PATH"
      else
        U_PANEL_PORT="$_wp"; U_PANEL_PATH="$_bp"
        U_SUB_PORT="$_ws";   U_SUB_PATH="$_sp"
        log "Панель уже установлена — беру её настройки без изменений:"
        log "  панель   : $_wp $_bp"
        log "  подписки : $_ws $_sp"
      fi
      return 0
    fi
  fi
  # свежая панель (или п.17 удалил): обычный путь — вопросы.
  # Пароль уже задан (собран раньше в этой сессии) → не перегенерируем.
  if [[ -z "${U_PANEL_PASS:-}" ]]; then
    U_PANEL_USER="${U_PANEL_USER:-admin}"
    U_PANEL_PASS=$(openssl rand -base64 18 2>/dev/null | tr -dc 'a-zA-Z0-9' | head -c 16)
    if [[ -t 0 ]]; then
      ask U_PANEL_USER "Логин панели (Enter — admin)" "$U_PANEL_USER" '^[a-zA-Z0-9._-]{3,32}$'
      ask U_PANEL_PASS "Пароль панели (Enter — случайный)" "$U_PANEL_PASS" '^.{6,}$'
    fi
  fi
  U_PANEL_PORT=""; U_SUB_PORT=""; U_PANEL_PATH=""; U_SUB_PATH=""
  ask U_PANEL_PORT "Порт панели (Enter — случайный)"       "" '^[0-9]*$'
  ask U_PANEL_PATH "Путь панели (Enter — случайный)"       "/$(gen_random_string 12)/" '^[a-zA-Z0-9/_-]*$'
  ask U_SUB_PORT  "Порт подписок (Enter — случайный)"     "" '^[0-9]*$'
  ask U_SUB_PATH  "Путь подписок (Enter — случайный)"     "/$(gen_random_string 10)/" '^[a-zA-Z0-9/_-]*$'
  [[ "$U_PANEL_PATH" != /* ]] && U_PANEL_PATH="/$U_PANEL_PATH"
  [[ "$U_PANEL_PATH" != */ ]] && U_PANEL_PATH="$U_PANEL_PATH/"
  [[ "$U_SUB_PATH"  != /* ]] && U_SUB_PATH="/$U_SUB_PATH"
  [[ "$U_SUB_PATH"  != */ ]] && U_SUB_PATH="$U_SUB_PATH/"
  [[ -n "$U_PANEL_PORT" && ( "$U_PANEL_PORT" -lt 1    || "$U_PANEL_PORT" -gt 65535 ) ]] && { err "Некорректный порт панели"; return 1; }
  [[ -n "$U_SUB_PORT"   && ( "$U_SUB_PORT"   -lt 1    || "$U_SUB_PORT"   -gt 65535 ) ]] && { err "Некорректный порт подписок"; return 1; }
  if [[ -n "$U_PANEL_PORT" && -n "$U_SUB_PORT" && "$U_PANEL_PORT" == "$U_SUB_PORT" ]]; then
    err "Порт панели и порт подписок совпадают ($U_PANEL_PORT) — укажите разные."; return 1
  fi
  if [[ "$U_PANEL_PATH" == "$U_SUB_PATH" ]]; then
    err "Путь панели и путь подписок совпадают ($U_PANEL_PATH) — укажите разные."; return 1
  fi
  return 0
}

ask_adguard_and_decoy() {
  # AdGuard: да/нет → установка → пароль → размещение
  if [[ "$ADG_PRESENT" != true ]]; then
    local adg_install=false
    [[ -t 0 ]] && askyn adg_install "Установить AdGuard Home?" "n"
    if [[ "$adg_install" == true ]]; then
      install_adguard_home || warn "AdGuard не установился — продолжаем без него."
      detect_env
      [[ "$ADG_PRESENT" == true ]] && ADG_JUST_INSTALLED=true
    fi
  fi
  ADG_PLACEMENT=""
  local adg_installed_now=false
  if [[ "$ADG_PRESENT" == true ]]; then
    if [[ -t 0 ]]; then
      if [[ "${ADG_JUST_INSTALLED:-}" == true ]]; then
        # установили ТОЛЬКО ЧТО в этом запуске — креды спрашиваем
        adg_installed_now=true
        if [[ -z "${U_ADG_PASS:-}" ]]; then
          U_ADG_USER="${U_ADG_USER:-admin}"
          U_ADG_PASS=$(openssl rand -base64 18 2>/dev/null | tr -dc 'a-zA-Z0-9' | head -c 16)
          [[ -z "$U_ADG_PASS" ]] && U_ADG_PASS="AdG$(date +%s)"
          ask U_ADG_USER "Логин AdGuard (Enter — admin)" "$U_ADG_USER" '^[a-zA-Z0-9._-]{3,32}$'
          ask U_ADG_PASS "Пароль AdGuard (Enter — случайный)" "$U_ADG_PASS" '^.{6,}$'
        elif [[ -z "${U_ADG_USER_SET:-}" ]]; then
          # пароль уже задан (установкой выше), логин уточняем один раз
          U_ADG_USER="${U_ADG_USER:-admin}"
          ask U_ADG_USER "Логин AdGuard (Enter — admin)" "$U_ADG_USER" '^[a-zA-Z0-9._-]{3,32}$'
          U_ADG_USER_SET=1
        fi
      else
        # был установлен РАНЬШЕ — креды не трогаем и не спрашиваем (как с панелью)
        log "AdGuard Home уже установлен — логин/пароль не трогаю (креды: /root/adguard-credentials.txt или твои)"
      fi
      echo "  AdGuard Home — где показывать веб-интерфейс?"
      echo "   1) За доменом панели   (https://<панель>/, DoH там же)"
      echo "   2) Отдельный SNI-домен (adguard.<база>)"
      echo "   3) Не трогать (только локально)"
      local ap=""
      ask ap "Размещение [1/2/3]" "1" '^[123]$'
      case "$ap" in 2) ADG_PLACEMENT="sni" ;; 3) ADG_PLACEMENT="local" ;; *) ADG_PLACEMENT="panel" ;; esac
    else
      ADG_PLACEMENT="${ADG_PLACEMENT:-panel}"   # не-TTY: сохраняем выбор авто-потока
    fi
  fi
  # заглушка панели — ПОСЛЕ AdGuard (если корень не занят самим AdGuard)
  PDECOY="${PDECOY:-stub}"
  if [[ -t 0 && "$ADG_PLACEMENT" != "panel" ]]; then
    local pdc3=""
    decoy_panel_choose pdc3 "1"
    PDECOY="$pdc3"
  fi
  # выбор пользователя (tpl:ИМЯ / tpl:custom:/путь) — общий шаблон для всех
  # доменов стека, а не только для панели
  decoy_selected_set "$PDECOY"
}

# Проверка UDP-инбаундов против UFW и локального слушателя.
# Не открывает порты молча: только показывает закрытые и спрашивает разрешение.
udp_inbound_firewall_check() {
  [[ -n "$XUI_DB" && -f "$XUI_DB" ]] || return 0
  local id proto port remark rule ask_open listen_state
  local -a closed=()
  while IFS='|' read -r id proto port remark; do
    [[ -n "$id" && -n "$port" && "$port" != 0 ]] || continue
    is_udp_proto "$proto" || continue
    rule=$(ufw status 2>/dev/null | awk -v p="$port" '$0 ~ ("[[:space:]]" p "/udp([[:space:]]|$)") || $0 ~ ("[[:space:]]" p "([[:space:]]|$)") {print; exit}')
    listen_state="нет"
    ss -Hlun "sport = :$port" 2>/dev/null | grep -q . && listen_state="да"
    if [[ -z "$rule" ]]; then
      closed+=("#$id|$proto|$port|$remark|$listen_state")
    else
      ok "UDP #$id $proto/$port: правило UFW есть, слушает: $listen_state"
    fi
  done < <(sqlite3 "$XUI_DB" "SELECT id, protocol, port, COALESCE(remark,'') FROM inbounds WHERE enable=1 AND port>0 ORDER BY id;" 2>/dev/null || true)
  [[ ${#closed[@]} -gt 0 ]] || return 0
  echo
  warn "UDP-инбаунды без разрешения UFW:"
  local row
  for row in "${closed[@]}"; do
    IFS='|' read -r id proto port remark listen_state <<<"$row"
    echo "  #$id ${remark:-$proto} — UDP/$port, слушает: $listen_state"
  done
  if [[ -t 0 ]]; then
    askyn ask_open "Открыть эти UDP-порты в UFW?" "y"
    [[ "$ask_open" == true ]] || return 0
  else
    warn "Неинтерактивный режим: порты не открыты автоматически"
    return 0
  fi
  for row in "${closed[@]}"; do
    IFS='|' read -r id proto port remark listen_state <<<"$row"
    fw_allow "$port" udp "udp-инбаунд #$id"
    log "UDP/$port открыт в UFW для #$id"
  done
  ufw --force enable >/dev/null 2>&1 || true
}

# Единый файрвол: сброс → SSH+443 (TCP) → нужные UDP → DENY панельных портов.
# Вызывается и из авто-подъёма, и из п.1 (при переустановке убивает старые
# правила прошлой установки — «почему открыты TCP-порты» лечится здесь).
firewall_apply() {
  # Снимок «до стека» — один раз, чтобы откат через раздел 5 имел к чему вернуться.
  # save_firewall_state сам защищён от перезаписи: если снимок уже есть — молча выйдет.
  save_firewall_state >/dev/null 2>&1 || true
  log "Файрвол: сброс и только необходимое…"
  ufw --force reset >/dev/null 2>&1 || true
  ufw default deny incoming >/dev/null 2>&1 || true
  ufw default allow outgoing >/dev/null 2>&1 || true
  # SSH: если sshd слушает только loopback («через туннель») — 22 наружу не открываем
  if ! ss -tln 2>/dev/null | grep -qE '127\.0\.0\.1:22([[:space:]]|$)'; then
    fw_allow "${SSH_PORT:-22}" tcp "SSH"
  else
    ufw delete allow "${SSH_PORT:-22}/tcp" >/dev/null 2>&1 || true
  fi
  fw_allow 443 tcp "HTTPS/SNI"
  # UDP — только инбаунды из БД панели (скан-сокеты шумят ephemeral-мусором)
  local up
  for up in $(udp_inbound_ports); do
    fw_port_locked "$up" && continue
    fw_allow "$up" udp "udp-инбаунд"
  done
  # доктрина 443: 11443 наружу никогда (TCP туннеля идёт через nginx:443,
  # UDP — это HTTP/3 caddy). Гасим, если правило когда-то засело.
  ufw delete allow 11443/tcp >/dev/null 2>&1 || true
  ufw delete allow 11443/udp >/dev/null 2>&1 || true
  fw_deny_panel_ports
  ufw --force enable >/dev/null 2>&1 || true
  sleep 1
}

# =====================================================================
# ЗДОРОВЬЕ: UFW-fallback, recidive, живой лог, шаблоны decoy
# ссылок, смена домена инбаунда
# =====================================================================

# Статус UFW с запасным путём: бинарь может не находиться в PATH — тогда
# смотрим сервис (oneshot ufw.service остаётся active после применения правил).
ufw_is_active() {
  local ub
  ub=$(command -v ufw 2>/dev/null || true)
  [[ -z "$ub" && -x /usr/sbin/ufw ]] && ub=/usr/sbin/ufw
  if [[ -n "$ub" ]]; then
    LC_ALL=C "$ub" status 2>/dev/null | head -1 | grep -q "Status: active" && return 0
    return 1
  fi
  systemctl is-active --quiet ufw 2>/dev/null
}

# Jail recidive: рецидивисты (3 бана за сутки) получают бан на неделю,
# который переживает рестарты fail2ban.
f2b_recidive_setup() {
  command -v fail2ban-client >/dev/null 2>&1 || { err "fail2ban не установлен"; return 1; }
  local f=/etc/fail2ban/jail.d/recidive.local
  cat > "$f" <<'EOF'
[recidive]
enabled   = true
filter    = recidive
logpath   = /var/log/fail2ban.log
banaction = iptables-allports
bantime   = 1w
findtime  = 1d
maxretry  = 3
EOF
  systemctl restart fail2ban 2>/dev/null || fail2ban-client reload >/dev/null 2>&1 || true
  sleep 1
  if fail2ban-client status recidive >/dev/null 2>&1; then
    log "recidive включён: 3 бана за сутки → бан на неделю (переживает рестарты)"
    audit "f2b: recidive jail включён"
  else
    err "recidive не поднялся — смотри /var/log/fail2ban.log (возможно, нет banaction iptables-allports)"
    return 1
  fi
}

f2b_tail() {
  local f=/var/log/fail2ban.log
  [[ -f "$f" ]] || { err "$f не найден"; return 1; }
  line; echo -e "${B}   FAIL2BAN — ЖИВОЙ ЛОГ (Ctrl+C — выход)${N}"; line
  tail -n 30 -f "$f"
}

# Смена домена инбаунда без пересоздания: stop панели → правка JSON/hosts/
# SNI-карты → start → nginx reload. Reality: свой decoy перепривязывается
# через reality_set_dest, чужая цель — через замену dest/serverNames.
inbound_change_domain() {
  line; echo -e "${B}   СМЕНА ДОМЕНА ИНБАУНДА (без пересоздания)${N}"; line
  [[ -z "$XUI_DB" || ! -f "$XUI_DB" ]] && { err "x-ui.db не найден"; return 1; }
  db_protect_suspend
  inbounds_live
  local id=""
  ask id "ID инбаунда (0 — отмена)" "0" '^[0-9]+$'
  [[ "$id" == 0 ]] && return 0
  # CDN-инбаунд: домен живёт в CDN-профиле (origin/cdn), в stream его нет —
  # смена домена = перенaстройка профиля (nginx-блок, серт, hosts, путь)
  if [[ -n "$(cdn_profile_get "$id" 2>/dev/null)" ]]; then
    line; echo -e "${B}   СМЕНА ДОМЕНА CDN-ИНБАУНДА #$id${N}"; line
    cdn_change_profile "$id"
    return 0
  fi
  local row
  row=$(python3 - "$XUI_DB" "$id" <<'PYROW' 2>/dev/null
import sqlite3, json, sys
con = sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True, timeout=5)
r = con.execute("SELECT protocol,port,settings,stream_settings FROM inbounds WHERE id=?", (int(sys.argv[2]),)).fetchone()
if not r: sys.exit(1)
proto, port, s1, s2 = r
se = json.loads(s1 or "{}"); st = json.loads(s2 or "{}")
rs = st.get("realitySettings") or {}
dom = se.get("domain") or se.get("hostname") or se.get("sni") \
   or (st.get("tlsSettings") or {}).get("serverName") \
   or (rs.get("serverNames") or [""])[0] or ""
dest = rs.get("dest") or rs.get("target") or ""
cert = se.get("certFile") or ""
if not cert:
    c = (st.get("tlsSettings") or {}).get("certificates") or []
    if c: cert = c[0].get("certificateFile", "")
print(f"{proto}|{port}|{dom}|{(st.get('security') or '').lower()}|{dest}|{cert}")
PYROW
) || { err "Инбаунд #$id не найден"; return 1; }
  local proto port old sec dest cert
  IFS='|' read -r proto port old sec dest cert <<<"$row"
  [[ -z "$old" ]] && { err "У инбаунда не найден текущий домен — меняй вручную"; return 1; }
  echo "  #$id: $proto $port/tcp · домен: $old · security: ${sec:-none} · dest: ${dest:--}"
  local nd=""
  ask nd "Новый домен (A-запись → этот сервер)" "" '^[a-zA-Z0-9.-]+$'
  [[ -z "$nd" ]] && return 0
  [[ "$nd" == "$old" ]] && { warn "Домен не изменился"; return 0; }
  local srv_ip dip
  srv_ip=$(server_ip4)
  dip=$(dig +short A "$nd" 2>/dev/null | tail -1)
  if [[ "$dip" != "$srv_ip" ]]; then
    warn "DNS: $nd → ${dip:-не резолвится}, а сервер: $srv_ip"
    local go=""
    askyn go "Продолжить всё равно (клиенты не подключатся, пока DNS не поправишь)?" "n"
    [[ "$go" == true ]] || return 0
  fi
  if [[ "$sec" == "tls" ]] && ! cert_paths "$nd" >/dev/null 2>&1; then
    if [[ -n "$WILDCARD_DOMAIN" && "$nd" == *."$WILDCARD_DOMAIN" ]]; then
      log "Сёрт: wildcard *.$WILDCARD_DOMAIN покрывает $nd"
    else
      log "Сёрта для $nd нет — выпускаю на месте (certbot)"
      cert_issue "$nd" || warn "Серт для $nd не выпущен — сделай это через п.10 и повтори"
    fi
  fi
  echo "  План: JSON стрима/настроек ($old→$nd), hosts, SNI-карта, reality-dest при необходимости."
  local go=""
  askyn go "Менять? (панель будет остановлена на время правки)" "n"
  [[ "$go" == true ]] || return 0
  auto_backup_stack >/dev/null 2>&1 || true
  local xui_was=""
  if systemctl is-active --quiet x-ui 2>/dev/null; then
    xui_was=1; systemctl stop x-ui >/dev/null 2>&1 || true; sleep 1
  fi
  local pyok=1
  python3 - "$XUI_DB" "$id" "$old" "$nd" <<'PYSET' && pyok=0 || pyok=1
import sqlite3, json, sys
db, iid, old, new = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
def walk(v):
    if isinstance(v, str):
        return new if v == old else v
    if isinstance(v, list):
        return [walk(x) for x in v]
    if isinstance(v, dict):
        return {k: walk(x) for k, x in v.items()}
    return v
con = sqlite3.connect(db, timeout=10)
con.execute("PRAGMA busy_timeout=8000")
s1, s2 = con.execute("SELECT settings,stream_settings FROM inbounds WHERE id=?", (iid,)).fetchone()
se = json.loads(s1 or "{}"); st = json.loads(s2 or "{}")
se = walk(se); st = walk(st)
# reality: dest с чужим доменом → новый:443; локальный decoy (127.*) не трогаем
rs = st.get("realitySettings") or {}
for k in ("dest", "target"):
    d = rs.get(k)
    if isinstance(d, str) and d.startswith(old + ":"):
        rs[k] = new + ":443"
if rs: st["realitySettings"] = rs
# tls: свой серт на новый домен, если выпущен
if (st.get("security") or "").lower() == "tls":
    fc, fk = f"/etc/letsencrypt/live/{new}/fullchain.pem", f"/etc/letsencrypt/live/{new}/privkey.pem"
    import os
    if os.path.isfile(fc) and os.path.isfile(fk):
        for c in (st.get("tlsSettings") or {}).get("certificates") or []:
            if c.get("certificateFile"): c["certificateFile"] = fc
            if c.get("keyFile"):        c["keyFile"] = fk
con.execute("UPDATE inbounds SET settings=?, stream_settings=? WHERE id=?",
            (json.dumps(se, ensure_ascii=False), json.dumps(st, ensure_ascii=False), iid))
con.commit()
print("[+] JSON обновлён")
PYSET
  if [[ "$pyok" != 0 ]]; then
    err "Правка БД не прошла — панель НЕ трогаю дальше"; [[ "$xui_was" == 1 ]] && systemctl start x-ui; return 1
  fi
  hosts_upsert "$id" "$nd"
  # SNI-карта: переносим бэкенд старого домена на новый
  local backend
  backend=$(grep -E "^\s+$old\s+" "$SNI_CONF" 2>/dev/null | awk '{print $2}' | head -1)
  if [[ -n "$backend" ]]; then
    sni_map_remove "$old"; sni_map_add "$nd" "$backend"
    log "  SNI-карта: $old → $nd (бэкенд $backend сохранён)"
  else
    sni_upstream_add "inb_${id}_backend" "$port"
    sni_map_add "$nd" "inb_${id}_backend"
    log "  SNI-карта: $nd → inb_${id}_backend (старой записи не было)"
  fi
  [[ "$xui_was" == 1 ]] && { systemctl start x-ui >/dev/null 2>&1 || true; sleep 2; }
  nginx_reload || true
  audit "inbound: смена домена #$id: $old → $nd"
  echo
  log "Готово: #$id теперь $nd. Проверь таблицу ниже — порт слушается, домен новый."
  inbounds_live
}

# =====================================================================
