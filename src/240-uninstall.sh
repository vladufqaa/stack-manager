# ОТКАТ И ДЕМОНТАЖ СТЕКА
#   Подменю поэтапного возврата к «плоскому» состоянию:
#     1) открыть порты наружу (панель/подписки/инбаунды)
#     2) правила UFW (снимок / по одному / reset+open)
#     3) службы и интеграции стека
#     4) конфиги и каталоги стека
#     5) удаление nginx (пакет + конфиги)
#     6) полный откат (всё выше, тихо, подтверждение YES)
#   AdGuard Home и серты LE НЕ трогаются — у AdGuard свой пункт (п.14),
#   серты не наши, могут использоваться другими сервисами.
# =====================================================================

# Список служб/интеграций, которые создаёт stack-manager
rb_services_list() {
  printf '%s\n' \
    "stack-heal.timer|таймер автопочинки инбаундов (каждые 2 мин)|/etc/systemd/system/stack-heal.timer|systemd" \
    "stack-heal.service|служба автопочинки (oneshot, запускается таймером)|/etc/systemd/system/stack-heal.service|systemd" \
    "fail2ban jail decoy-login|бан за POST /login к decoy-страницам|/etc/fail2ban/jail.d/decoy-login.local|f2b" \
    "fail2ban filter decoy-login|фильтр для jail decoy-login|/etc/fail2ban/filter.d/decoy-login.conf|f2b" \
    "certbot deploy-hook|рестарт x-ui/nginx/AdGuard после renew сертов|/etc/letsencrypt/renewal-hooks/deploy/stack-cert-mirror.sh|file"
}

# Список конфигов и каталогов стека
rb_configs_list() {
  printf '%s\n' \
    "/etc/nginx/sites-available/stack.conf|основной http-конфиг стека (ACME :80 + панель :4443 + decoy)|file" \
    "/etc/nginx/sites-enabled/stack.conf|симлинк основного конфига|link" \
    "/etc/nginx/streams-available/sni-router.conf|SNI-роутер 443 (map + upstream)|file" \
    "/etc/nginx/streams-enabled/sni-router.conf|симлинк SNI-роутера|link" \
    "/etc/nginx/snippets/decoy-headers.conf|security-заголовки decoy|file" \
    "/etc/logrotate.d/stack-decoy|ротация decoy-логов|file" \
    "/var/www/panel-decoy|decoy-заглушка корня домена панели|dir" \
    "/var/www/decoy-templates|шаблоны decoy (corporate, blog, docs…)|dir" \
    "/var/www/decoy-login|login-шаблоны (adguard, portainer, jellyfin…)|dir"
}

# --- 23.1 Открыть порты наружу (панель/подписки/инбаунды) --------------
rb_open_ports() {
  line; echo -e "${B}   ОТКРЫТЬ ПОРТЫ НАРУЖУ${N}"; line
  echo "  Сейчас панель/подписки/инбаунды живут за SNI-роутером (127.0.0.1)."
  echo "  Здесь — открыть их напрямую на 0.0.0.0 (по каждому пункту спрошу)."
  echo
  [[ -f "$XUI_DB" ]] || { err "x-ui.db не найден"; pause; return 1; }
  auto_backup_stack >/dev/null 2>&1 || true

  local wp wl sp sl
  wp=$(xui_get webPort); wl=$(xui_get webListen)
  sp=$(xui_get subPort); sl=$(xui_get subListen)

  local need_restart=0
  systemctl stop x-ui 2>/dev/null || true

  echo "▸ Панель: bind=${wl:-<пусто>} port=${wp:-?}"
  if [[ -n "$wp" && ( "$wl" == "127.0.0.1" || "$wl" == "::1" || -z "$wl" ) ]]; then
    local go=""
    askyn go "  Открыть панель ($wp) наружу (0.0.0.0)?" "n"
    if [[ "$go" == true ]]; then
      xui_set_setting webListen '0.0.0.0'
      log "  webListen → 0.0.0.0 (панель $wp)"; need_restart=1
      audit "rollback: webListen → 0.0.0.0"
    fi
  else
    [[ -n "$wp" ]] && log "  панель уже слушает ${wl:-0.0.0.0}:$wp" || warn "  webPort не найден"
  fi

  echo
  echo "▸ Подписки: bind=${sl:-<пусто>} port=${sp:-?}"
  if [[ -n "$sp" && ( "$sl" == "127.0.0.1" || "$sl" == "::1" || -z "$sl" ) ]]; then
    local go=""
    askyn go "  Открыть подписки ($sp) наружу (0.0.0.0)?" "n"
    if [[ "$go" == true ]]; then
      xui_set_setting subListen '0.0.0.0'
      log "  subListen → 0.0.0.0 (подписки $sp)"; need_restart=1
      audit "rollback: subListen → 0.0.0.0"
    fi
  else
    [[ -n "$sp" ]] && log "  подписки уже слушают ${sl:-0.0.0.0}:$sp" || warn "  subPort не найден"
  fi

  echo
  echo "▸ Инбаунды:"
  # ВАЖНО: сначала собрать строки, потом спрашивать — иначе read внутри
  # while < <(...) съест следующую строку sqlite как ответ на askyn.
  local -a rows=()
  local _l
  while IFS= read -r _l; do rows+=("$_l"); done < <(sqlite3 -cmd ".timeout 3000" "$XUI_DB" \
    "SELECT id, protocol, port, COALESCE(listen,''), COALESCE(json_extract(stream_settings,'\$.security'),'') FROM inbounds ORDER BY id;" 2>/dev/null || true)

  if [[ ${#rows[@]} -eq 0 ]]; then
    warn "  инбаундов в панели нет"
  else
    local row iid iproto iport ilisten isec note go
    for row in "${rows[@]}"; do
      IFS='|' read -r iid iproto iport ilisten isec <<<"$row"
      [[ -z "$iid" ]] && continue
      note=""
      case "$isec" in
        tls)     note=" [TLS — без nginx серт-пути в settings могут стать недостижимы]" ;;
        reality) note=" [Reality — dest указывает на локальный decoy nginx]" ;;
      esac
      echo "  #$iid $iproto :$iport (bind=${ilisten:-0.0.0.0})$note"
      if [[ "$ilisten" == "127.0.0.1" || "$ilisten" == "::1" ]]; then
        askyn go "    Открыть #$iid наружу?" "n"
        if [[ "$go" == true ]]; then
          sqlite3 -cmd ".timeout 3000" "$XUI_DB" "UPDATE inbounds SET listen='0.0.0.0' WHERE id=$iid;" 2>/dev/null || true
          log "    #$iid listen → 0.0.0.0"; need_restart=1
          audit "rollback: inbound #$iid listen → 0.0.0.0"
        fi
      else
        echo "    уже слушает наружу"
      fi
    done
  fi

  systemctl start x-ui 2>/dev/null || true
  [[ "$need_restart" == 1 ]] && log "x-ui перезапущен — новые bind'ы применены"
  pause
}

# --- 23.2 Правила UFW -------------------------------------------------
rb_firewall() {
  line; echo -e "${B}   ПРАВИЛА ФАЙРВОЛА (UFW)${N}"; line
  if ! command -v ufw >/dev/null 2>&1; then
    warn "UFW не установлен — чистить нечего"; pause; return 0
  fi
  echo "  Статус: $(ufw status 2>/dev/null | head -1)"
  echo
  ufw status numbered 2>/dev/null | sed 's/^/    /'
  echo

  if [[ -f "$FW_STATE_DIR/saved" ]]; then
    log "Есть снимок состояния UFW: $FW_STATE_DIR/saved"
    local rs=""
    askyn rs "Восстановить из снимка (отменит все правила, добавленные стеком)?" "y"
    if [[ "$rs" == true ]]; then
      restore_firewall_state
      audit "rollback: UFW восстановлен из снимка"
      return 0
    fi
  fi

  echo "  1) Пройти по каждому правилу (оставить/удалить)"
  echo "  2) Reset UFW (default deny) + открыть всё слушающееся"
  echo "  0) Отмена"
  line
  local c=""
  read -rp "$(echo -e "${B}Выбор:${N} ")" c || c="0"
  case "$c" in
    1)
      # Собираем номера правил, потом спрашиваем — иначе read внутри
      # while < <(...) съест следующую строку ufw как ответ.
      local -a nums=()
      local _n
      while IFS= read -r _n; do nums+=("$_n"); done < <(
        ufw status numbered 2>/dev/null | grep -oE '^\[[[:space:]]*[0-9]+\]' | grep -oE '[0-9]+' | sort -rn
      )
      local -a to_del=()
      local n rule del
      for n in "${nums[@]}"; do
        rule=$(ufw status numbered 2>/dev/null | grep -E "^\[[[:space:]]*$n\]" || true)
        [[ -z "$rule" ]] && continue
        echo "  $rule"
        askyn del "    Удалить это правило?" "n"
        [[ "$del" == true ]] && to_del+=("$n")
      done
      local deleted=0
      for n in "${to_del[@]}"; do
        if ufw --force delete "$n" >/dev/null 2>&1; then
          log "  правило $n удалено"; deleted=$((deleted+1))
        else
          warn "  правило $n не удалилось"
        fi
      done
      [[ "$deleted" -eq 0 ]] && log "Ничего не удалено."
      audit "rollback: UFW удалено правил: $deleted"
      ;;
    2)
      local go=""
      askyn go "Сбросить UFW (default deny + открыть всё слушающееся)?" "n"
      [[ "$go" == true ]] || { pause; return 0; }
      save_firewall_state
      ufw --force reset >/dev/null 2>&1 || true
      ufw default deny incoming >/dev/null 2>&1 || true
      ufw default allow outgoing >/dev/null 2>&1 || true
      fw_allow "${SSH_PORT:-22}" tcp "SSH"
      local p
      for p in $(ss -tln 2>/dev/null | awk 'NR>1 { if ($4 ~ /^127\./ || $4 ~ /^\[::1\]/) next; split($4,a,":"); print a[length(a)] }' | sort -un); do
        [[ -n "$p" && "$p" != "${SSH_PORT:-22}" ]] && fw_allow "$p" tcp "rollback-open"
      done
      for p in $(ss -uln 2>/dev/null | awk 'NR>1 { if ($4 ~ /^127\./ || $4 ~ /^\[::1\]/) next; if ($5 != "*:*") next; split($4,a,":"); print a[length(a)] }' | sort -un); do
        [[ -n "$p" ]] && fw_allow "$p" udp "rollback-open"
      done
      ufw --force enable >/dev/null 2>&1 || true
      log "UFW: reset + открыто всё слушающееся"
      audit "rollback: UFW reset + open listening"
      ;;
    *) pause; return 0 ;;
  esac
  pause
}

# --- 23.3 Службы и интеграции -----------------------------------------
rb_services() {
  line; echo -e "${B}   СЛУЖБЫ И ИНТЕГРАЦИИ СТЕКА${N}"; line
  local -a items=()
  local _l
  while IFS= read -r _l; do items+=("$_l"); done < <(rb_services_list)

  local found=0 name desc path typ exists unit c
  local item
  for item in "${items[@]}"; do
    IFS='|' read -r name desc path typ <<<"$item"
    [[ -z "$name" ]] && continue
    exists=false
    [[ -e "$path" ]] && exists=true
    [[ "$exists" != true ]] && continue
    found=$((found+1))
    echo "  ─ $name"
    echo "    $desc"
    echo "    файл: $path"
    echo "      1) Удалить   2) Отключить (файл оставить)   3) Отмена"
    c=""
    ask c "    Выбор" "3" '^[123]$'
    case "$c" in
      1)
        case "$typ" in
          systemd)
            unit=$(basename "$path")
            systemctl disable --now "$unit" >/dev/null 2>&1 || true
            rm -f "$path" 2>/dev/null || true
            systemctl daemon-reload >/dev/null 2>&1 || true
            ;;
          f2b)
            rm -f "$path" 2>/dev/null || true
            systemctl restart fail2ban >/dev/null 2>&1 || true
            ;;
          file)
            rm -f "$path" 2>/dev/null || true
            ;;
        esac
        log "    удалено"; audit "rollback: удалено — $name"
        ;;
      2)
        case "$typ" in
          systemd)
            unit=$(basename "$path")
            systemctl disable --now "$unit" >/dev/null 2>&1 || true
            ;;
          f2b)
            sed -i -E 's/^enabled[[:space:]]*=.*/enabled  = false/' "$path" 2>/dev/null || true
            systemctl restart fail2ban >/dev/null 2>&1 || true
            ;;
          file)
            chmod -x "$path" 2>/dev/null || true
            ;;
        esac
        log "    отключено (файл на месте)"; audit "rollback: отключено — $name"
        ;;
    esac
  done
  [[ "$found" -eq 0 ]] && log "Служб/интеграций стека не найдено — чистить нечего."
  pause
}

# --- 23.4 Конфиги и каталоги ------------------------------------------
rb_configs() {
  line; echo -e "${B}   КОНФИГИ И КАТАЛОГИ СТЕКА${N}"; line
  local -a items=()
  local _l
  while IFS= read -r _l; do items+=("$_l"); done < <(rb_configs_list)

  local found=0 path desc typ exists go
  local item
  for item in "${items[@]}"; do
    IFS='|' read -r path desc typ <<<"$item"
    [[ -z "$path" ]] && continue
    exists=false
    case "$typ" in
      file|link) [[ -e "$path" ]] && exists=true ;;
      dir)       [[ -d "$path" ]] && exists=true ;;
    esac
    [[ "$exists" != true ]] && continue
    found=$((found+1))
    echo "  ─ $path"
    echo "    $desc"
    askyn go "    Удалить?" "n"
    if [[ "$go" == true ]]; then
      case "$typ" in
        dir) rm -rf "$path" ;;
        *)   rm -f "$path" ;;
      esac
      log "    удалено"; audit "rollback: удалено — $path"
    fi
  done

  # per-inbound decoy-каталоги
  local -a decoy_dirs=()
  local d
  for d in /var/www/decoy-*; do
    [[ -d "$d" ]] && decoy_dirs+=("$d")
  done
  for d in "${decoy_dirs[@]}"; do
    found=$((found+1))
    echo "  ─ $d"
    echo "    decoy-заглушка инбаунда"
    askyn go "    Удалить?" "n"
    if [[ "$go" == true ]]; then
      rm -rf "$d"; log "    удалено"; audit "rollback: удалено — $d"
    fi
  done

  [[ "$found" -eq 0 ]] && log "Конфигов/каталогов стека не найдено."
  nginx -t >/dev/null 2>&1 && nginx_reload >/dev/null 2>&1 || true
  pause
}

# --- 23.5 Удаление nginx ----------------------------------------------
rb_remove_nginx() {
  line; echo -e "${B}   УДАЛЕНИЕ NGINX${N}"; line
  command -v nginx >/dev/null 2>&1 || { warn "nginx не установлен — нечего удалять"; pause; return 0; }
  echo "  ${R}ВНИМАНИЕ:${N} без nginx стек работать НЕ БУДЕТ как SNI-роутер."
  echo "  • Панель/подписки/инбаунды сейчас на 127.0.0.1 — станут недоступны снаружи,"
  echo "    пока не откроешь их через раздел 5 → «Откат и демонтаж стека» → 1 (Открыть порты наружу)."
  echo "  • Серты на :443 перестанут отдаваться; decoy-страницы; DoH AdGuard."
  echo "  • Конфиги /etc/nginx будут удалены пакетом (это же делает apt purge)."
  echo
  local go=""
  askyn go "Удалить nginx (пакет + конфиги + сервис)?" "n"
  [[ "$go" == true ]] || { pause; return 0; }
  local sure=""
  ask sure "Для подтверждения введи YES" "" '^YES$'
  [[ "$sure" == "YES" ]] || { log "Отменено"; pause; return 0; }
  audit "rollback: удаление nginx (purge)"
  systemctl stop nginx 2>/dev/null || true
  systemctl disable nginx 2>/dev/null || true
  DEBIAN_FRONTEND=noninteractive apt-get purge -y nginx nginx-common nginx-full libnginx-mod-stream >/dev/null 2>&1 || true
  apt-get autoremove -y >/dev/null 2>&1 || true
  rm -rf /etc/nginx /var/log/nginx 2>/dev/null || true
  log "nginx удалён (пакет + /etc/nginx + /var/log/nginx)"
  pause
}

# --- 23.6 Полный откат (тихо) -----------------------------------------
stack_preinstall_db() {
  local d=""
  while IFS= read -r d; do
    [[ -z "$d" ]] && continue
    [[ -f "$d/x-ui.db" ]] && { printf '%s\n' "$d/x-ui.db"; return 0; }
  done < <(ls -1dt "$BACKUP_DIR"/pre-install-* 2>/dev/null | grep -v '\.tar\.gz$' || true)
  return 1
}

# Возврат НАСТРОЕК ПАНЕЛИ (settings) к значениям из снимка «до скрипта».
# Трогаются только ключи web*/sub* — инбаунды, пользователи и прочее не читаются
# и не пишутся. Хост не восстанавливаем (машина та же, а чужие webListen/webPort
# сломали бы доступ к панели).
stack_restore_panel_from_snapshot() {
  local snap_db="$1" sdb="$2"
  [[ -z "$snap_db" || ! -f "$snap_db" ]] && { warn "Снимок x-ui.db не найден — настройки панели не восстановлены"; return 1; }
  [[ -z "$sdb" || ! -f "$sdb" ]] && { warn "x-ui.db не найден — настройки панели не восстановлены"; return 1; }
  command -v python3 >/dev/null 2>&1 || { warn "python3 недоступен — настройки панели не восстановлены"; return 1; }
  command -v "$DB_BIN" >/dev/null 2>&1 || { warn "sqlite3 недоступен — настройки панели не восстановлены"; return 1; }
  local res="" res_file=""
  res_file=$(mktemp /tmp/stack-rst.XXXXXX 2>/dev/null) || return 1
  python3 - "$snap_db" "$sdb" > /dev/null 2> "$res_file" <<'PYRST2'
import os, sqlite3, sys
snap_path, live_path = sys.argv[1], sys.argv[2]
KEYS = ("webDomain", "webListen", "webPort", "webBasePath", "subDomain", "subListen",
        "subPort", "subPath", "subURI", "webCertFile", "webKeyFile",
        "subCertFile", "subKeyFile")
def read(path):
    con = sqlite3.connect("file:%s?mode=ro" % path, uri=True, timeout=5)
    rows = dict(con.execute("SELECT key, value FROM settings").fetchall())
    con.close()
    return rows
try:
    snap = read(snap_path)
except Exception:
    sys.exit(0)
try:
    con = sqlite3.connect(live_path, timeout=10)
    cur = con.cursor()
    cur.execute("PRAGMA busy_timeout=5000")
    cur.execute("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)")
    # Настройки, значение которых — путь к СУЩЕСТВУЮЩЕМУ файлу. Если в снимке
    # путь мёртвый, а в панели сейчас рабочий серт — оставляем рабочий: иначе
    # откат снимает HTTPS с панели («панель работает по обычному HTTP»).
    FILE_KEYS = ("webCertFile", "webKeyFile", "subCertFile", "subKeyFile")

    def alive(v):
        if not v or not str(v).startswith("/"):
            return False
        return os.path.isfile(str(v))

    cur_keys = dict(cur.execute("SELECT key, value FROM settings").fetchall())
    applied, kept = [], []
    for k in KEYS:
        if k not in snap:
            continue
        old = snap[k]
        now = cur_keys.get(k)
        if k in FILE_KEYS and not alive(old) and alive(now):
            kept.append(k)            # не ломаем работающий серт панели
            continue
        if now == old and k in cur_keys:
            continue
        if k in cur_keys:
            cur.execute("UPDATE settings SET value=? WHERE key=?", (old, k))
        else:
            cur.execute("INSERT INTO settings (key, value) VALUES (?, ?)", (k, old))
        applied.append(k)
    con.commit()
    con.close()
except Exception:
    sys.exit(1)
sys.stderr.write("RESTORED:%d:%s\nKEPT:%d:%s\n" % (
    len(applied), ",".join(applied) if applied else "-",
    len(kept), ",".join(kept) if kept else "-"))
PYRST2
  res=$(cat "$res_file" 2>/dev/null || true)
  rm -f "$res_file" 2>/dev/null || true
  [[ -z "$res" ]] && { warn "не удалось прочитать снимок — настройки панели не восстановлены"; return 1; }
  local rline="" kline=""
  rline=$(grep -m1 '^RESTORED:' <<<"$res" || true)
  kline=$(grep -m1 '^KEPT:' <<<"$res" || true)
  if [[ -n "$rline" ]]; then
    log "Настройки панели из снимка: восстановлено полей ${rline#RESTORED:} "
  else
    warn "Настройки панели: снимок прочитан, но применять было нечего"
  fi
  if [[ -n "$kline" ]]; then
    local kn="${kline#KEPT:}"
    if [[ "${kn%%:*}" != "0" ]]; then
      # серт панели не тронули: в снимке путь мёртвый, а в панели рабочий
      log "  сохранён рабочий серт панели (в снимке путь нерабочий): ${kn#*:}"
    fi
  fi
  return 0
}

# Восстановить SNI/target Reality из снимка, не заменяя всю строку inbound:
# клиенты, UUID, порты и остальные настройки остаются в текущей БД.
stack_restore_reality_sni_from_snapshot() {
  local snap_db="$1" live_db="$2"
  [[ -f "$snap_db" && -f "$live_db" ]] || return 1
  python3 - "$snap_db" "$live_db" <<'PYREALITY'
import json, sqlite3, sys
snap_path, live_path = sys.argv[1:]
def rows(path):
    con=sqlite3.connect('file:%s?mode=ro' % path, uri=True, timeout=10)
    out={r[0]: (r[1], r[2], r[3]) for r in con.execute(
        "SELECT id, protocol, port, stream_settings FROM inbounds")}
    con.close(); return out
try:
    old=rows(snap_path)
    con=sqlite3.connect(live_path, timeout=10); con.execute('PRAGMA busy_timeout=5000')
    changed=0
    for iid, (op, oport, os) in old.items():
        if not os: continue
        try: oj=json.loads(os)
        except Exception: continue
        ors=oj.get('realitySettings')
        if not isinstance(ors, dict): continue
        cur=con.execute('SELECT protocol, stream_settings FROM inbounds WHERE id=?', (iid,)).fetchone()
        if not cur: continue
        try: cj=json.loads(cur[1] or '')
        except Exception: continue
        crs=cj.get('realitySettings')
        if not isinstance(crs, dict): continue
        copied=False
        for key in ('target','dest','serverNames'):
            if key in ors and ors[key] != crs.get(key):
                crs[key]=ors[key]; copied=True
        if copied:
            cj['realitySettings']=crs
        # CDN-профиль XHTTP+TLS меняет origin SNI, host и path. Возвращаем
        # только transport-объекты из snapshot, не заменяя inbound целиком.
        if (oj.get('network') == 'xhttp' and oj.get('security') == 'tls'):
            for key in ('tlsSettings','xhttpSettings'):
                if key in oj:
                    if cj.get(key) != oj[key]: copied=True
                    cj[key]=oj[key]
        if copied:
            con.execute('UPDATE inbounds SET stream_settings=? WHERE id=?',
                        (json.dumps(cj, ensure_ascii=False, separators=(',',':')), iid))
            changed += 1
    con.commit(); con.close()
    print('REALITY_RESTORED:%d' % changed)
except Exception:
    sys.exit(1)
PYREALITY
}

stack_restore_hosts_from_snapshot() {
  local snap_db="$1" live_db="$2"
  [[ -f "$snap_db" && -f "$live_db" ]] || return 1
  python3 - "$snap_db" "$live_db" <<'PYHOSTS'
import sqlite3, sys
snap_path, live_path = sys.argv[1:]
try:
    so=sqlite3.connect('file:%s?mode=ro' % snap_path, uri=True, timeout=10)
    lo=sqlite3.connect(live_path, timeout=10); lo.execute('PRAGMA busy_timeout=5000')
    st=so.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='hosts'").fetchone()
    lt=lo.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='hosts'").fetchone()
    if not st or not lt: raise SystemExit(0)
    sc=[r[1] for r in so.execute('PRAGMA table_info(hosts)')]
    lc=[r[1] for r in lo.execute('PRAGMA table_info(hosts)')]
    cols=[c for c in sc if c in lc and c != 'id']
    if not cols: raise SystemExit(0)
    q=','.join('"%s"'%c.replace('"','""') for c in cols)
    n=0
    # Если скрипт менял SNI, текущая hosts-строка уже существует, поэтому
    # INSERT OR IGNORE недостаточен. Удаляем только строки, отмеченные нашим
    # реестром владения, затем вставляем snapshot-значение (например google.com).
    owned = lo.execute("SELECT inbound_id,port,address,sni FROM sm_hosts_owned").fetchall() if lo.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='sm_hosts_owned'").fetchone() else []
    # В старых версиях реестр мог быть пустым. Восстановление hosts должно
    # всё равно заменить текущую строку для inbound, если в snapshot есть
    # исходная строка; ручные hosts остальных inbound не затрагиваем.
    snap_keys = {(int(r[0]), int(r[2])) for r in so.execute('SELECT inbound_id, address, port FROM hosts')}
    owned_keys = {(int(a), int(b)) for a,b,_,_ in owned}
    for iid, port, addr, sni in owned:
        lo.execute("DELETE FROM hosts WHERE inbound_id=? AND port=? AND COALESCE(address,'')=? AND COALESCE(sni,'')=?", (iid,port,addr,sni))
    for iid, port in (snap_keys - owned_keys):
        lo.execute("DELETE FROM hosts WHERE inbound_id=? AND port=?", (iid,port))
    for row in so.execute('SELECT %s FROM hosts' % q):
        marks=','.join('?' for _ in cols)
        try:
            cur=lo.execute('INSERT OR IGNORE INTO hosts (%s) VALUES (%s)'%(q,marks), row)
            n += cur.rowcount if cur.rowcount > 0 else 0
        except Exception: pass
    # Реестр должен указывать уже на восстановленный SNI, иначе следующий
    # откат/смена decoy не найдёт строку google.com.
    if owned and all(x in cols for x in ('inbound_id','port','address','sni')):
        keys={(int(a),int(b)) for a,b,_,_ in owned}
        lo.execute('DELETE FROM sm_hosts_owned')
        for row in so.execute('SELECT %s FROM hosts' % q):
            d=dict(zip(cols,row)); k=(int(d['inbound_id']),int(d['port']))
            if k in keys:
                lo.execute('INSERT OR IGNORE INTO sm_hosts_owned(inbound_id,port,address,sni) VALUES(?,?,?,?)', (k[0],k[1],d.get('address') or '',d.get('sni') or ''))
    lo.commit(); so.close(); lo.close(); print('HOSTS_RESTORED:%d'%n)
except SystemExit: pass
except Exception: sys.exit(1)
PYHOSTS
}

# Снять «состояние стека»: маркеры, флаги, триггеры защиты БД, журналы.
#   $1 = prompt — спрашивать по группам с необратимыми данными (1) или тихо (0)
# Сертификаты Let's Encrypt и AdGuard Home НЕ трогаются — это и раньше было явно.
rb_wipe_stack_state() {
  local prompt="${1:-0}" go="" n=0
  # 1) журнал изменений: вернуть то, что скрипт правил в панели (п.2/п.3)
  if panel_journal_started; then
    log "Возврат настроек панели по журналу изменений (п.2/п.3)…"
    panel_journal_apply 1 || warn "  журнал применён частично (файлы смотри в $BACKUP_DIR)"
  fi
  panel_journal_clear

  # 2) точка отсчёта «первого запуска»: без неё скрипт считает стек собранным (п.1)
  local -a wipe=(
    "$BACKUP_DIR/.pre-install-done"
    "$BACKUP_DIR/.stack-ever-ran"
    /root/stack-frozen.txt
    "$CERT_MODE_FILE"
    "$CERT_LINES_FILE"
    "$WILDCARD_STATE"
    /root/panel-credentials.txt
    /root/adguard-credentials.txt
    /root/.stack-src
  )
  local f
  for f in "${wipe[@]}"; do
    rm -f "$f" 2>/dev/null && { n=$((n+1)); log "  снято: $f"; }
  done
  rm -f "$CERT_LINE_FILE_PREFIX"*.domains 2>/dev/null || true

  # Файлы линий сертов: удаляем по префиксу, т.к. имена линий заранее неизвестны
  rm -f "$CERT_LINE_FILE_PREFIX"*.domains 2>/dev/null || true
  # Триггеры, которые ставит ensure_shareonly_triggers: пересоздаются при
  # следующей установке, зато новая установка не получит «УЖЕ СУЩЕСТВУЕТ»
  if [[ -n "$XUI_DB" && -f "$XUI_DB" ]]; then
    local _tg=""
    while IFS= read -r _tg; do
      [[ -n "$_tg" ]] && sqlite3 "$XUI_DB" "DROP TRIGGER IF EXISTS \"$_tg\";" 2>/dev/null || true
    done < <(sqlite3 "$XUI_DB" "SELECT name FROM sqlite_master WHERE type='trigger' AND name LIKE 'lucx_shareonly%';" 2>/dev/null || true)
  fi

  # 4) конфиги и данные прежней установки (только своё)
  local -a data=(
    /etc/fail2ban/jail.d/decoy-login.local
    /etc/fail2ban/filter.d/decoy-login.conf
    /etc/logrotate.d/stack-decoy
  )
  [[ -n "${DECOY_LOG_ACCESS:-}" ]] && data+=("$DECOY_LOG_ACCESS")
  for f in "${data[@]}"; do
    rm -f "$f" 2>/dev/null || true
  done
  [[ -n "${DECOY_LOGIN_DIR:-}" && "$DECOY_LOGIN_DIR" == /var/www/* ]] && rm -rf "$DECOY_LOGIN_DIR" 2>/dev/null || true
  rm -rf /var/www/decoy-[0-9]* 2>/dev/null || true

  # 5) данные, которые мог править пользователь — спрашиваем отдельно
  local cert_domains="/etc/letsencrypt/stack-domains.txt"
  if [[ -f "$cert_domains" ]]; then
    if [[ "$prompt" == "1" && -t 0 ]]; then
      askyn go "Списки доменов сертификатов ($cert_domains и cert-lines*.domains) тоже снять?" "n"
    else
      go=false
    fi
    if [[ "$go" == true ]]; then
      rm -f "$cert_domains" 2>/dev/null || true
      log "  снято: $cert_domains"
    else
      warn "  оставлено: $cert_domains (список доменов сертификатов)"
    fi
  fi
  if [[ -d /root/stack-backups ]]; then
    local old_ans
    old_ans=$(find /root/stack-backups -maxdepth 1 -name 'ans-auto-*.txt' 2>/dev/null | wc -l)
    if [[ "${old_ans:-0}" -gt 0 ]]; then
      if [[ "$prompt" == "1" && -t 0 ]]; then
        askyn go "Удалить сохранённые файлы автоответов установки ($old_ans шт.)?" "y"
      else
        go=true
      fi
      [[ "$go" == true ]] && rm -f /root/stack-backups/ans-auto-*.txt 2>/dev/null || true
    fi
  fi
  rm -f /root/ans-auto-*.txt 2>/dev/null || true
  log "Состояние стека снято (файлов и записей: $n + журнал)"
  return 0
}

# Полный сброс «состояния стека» + возврат настроек панели из снимка.
# $1 = 1 — спрашивать по группам (ручной пункт меню), 0 — тихо (полный откат)
stack_reset_state() {
  local prompt="${1:-1}"
  local snap_db="" sdb=""
  snap_db=$(stack_preinstall_db 2>/dev/null || true)
  sdb="${XUI_DB:-}"
  [[ -f "$sdb" ]] || sdb="/etc/x-ui/x-ui.db"
  if [[ -z "$snap_db" ]]; then
    warn "Снимок «до скрипта» не найден:"
    warn "  • «первичная настройка уже выполнена» больше не появится, маркеры сняты;"
    warn "  • но исходные настройки панели (домен, порты, пути) вернуть не из чего —"
    warn "    задайте их в п.1 или восстановите снимок вручную через раздел 5 → Pre-install snapshot."
  fi
  local xui_was=""
  if systemctl is-active --quiet x-ui 2>/dev/null; then
    xui_was=1; stop_xui_for_edit
  fi
  # 1) маркеры, флаги, журнал изменений и данные прежней установки
  rb_wipe_stack_state "$prompt"
  # 2) исходные настройки панели из снимка «до скрипта»
  if [[ -n "$snap_db" ]]; then
    stack_restore_panel_from_snapshot "$snap_db" "$sdb"
    local _rr=""
    _rr=$(stack_restore_reality_sni_from_snapshot "$snap_db" "$sdb" 2>/dev/null || true)
    [[ -n "$_rr" ]] && log "  $_rr (SNI/target Reality из backup)"
    local _rh=""
    _rh=$(stack_restore_hosts_from_snapshot "$snap_db" "$sdb" 2>/dev/null || true)
    [[ -n "$_rh" ]] && log "  $_rh (hosts из backup)"
  fi
  if [[ -n "$xui_was" ]]; then
    # После восстановления БД panel/xray может держать старую конфигурацию
    # Reality в памяти; именно поэтому ручное вкл/выкл инбаунда «лечит» его.
    systemctl restart x-ui >/dev/null 2>&1 || systemctl start x-ui >/dev/null 2>&1 || true
    sleep 3
  fi
  return 0
}

# --- 23.0 Снять состояние стека (п.1/п.2/п.3 отката, отдельным пунктом) --
rb_reset_state_menu() {
  line; echo -e "${B}   СНЯТЬ СОСТОЯНИЕ СТЕКА${N}"; line
  echo "  Возвращает панель и систему к состоянию «скрипт ещё не запускался»:"
  echo "    • listen инбаундов — как было до правок скрипта (только то, что он менял)"
  echo "    • настройки панели (домен, порты, пути, серты панели) — из снимка «до скрипта»"
  echo "    • маркеры стека: .pre-install-done, заморозка, режим/линии сертов,"
  echo "      wildcard-флаг, креды панели и AdGuard, URL самообновления"
  echo "    • триггеры защиты БД и служебные таблицы (hosts_shadow, sm_pending)"
  echo "    • jail/filter decoy-login, decoy-логи, login-шаблоны"
  echo
  echo -e "  ${G}НЕ трогается:${N} инбаунды и клиенты панели, AdGuard Home,"
  echo "  серты Let's Encrypt, снимки в /root/stack-backups/pre-install-*."
  echo "  Конфиги nginx (stack.conf, sni-router.conf) снимаются пунктами 4–5."
  echo
  local snap_db=""
  snap_db=$(stack_preinstall_db 2>/dev/null || true)
  if [[ -n "$snap_db" ]]; then
    log "Снимок «до скрипта»: $snap_db"
  else
    warn "Снимок «до скрипта» не найден — настройки панели вернуть не из чего."
  fi
  local go=""
  askyn go "Выполнить?" "n"
  [[ "$go" == true ]] || { log "Отменено"; pause; return 0; }
  audit "rollback: снятие состояния стека"
  systemctl stop x-ui 2>/dev/null || true
  stack_reset_state 1
  systemctl start x-ui 2>/dev/null || true
  log "Готово. Панель: настройки и listen возвращены, маркеры стека сняты."
  log "  Проверить: п.1 не должен писать «первичная настройка уже выполнена»."
  pause
}

rb_full_rollback() {
  line; echo -e "${R}   ПОЛНЫЙ ОТКАТ СТЕКА${N}"; line
  echo "  Будет выполнено (без вопросов, по шагам):"
  echo "    1) Бэкап x-ui.db и nginx-конфигов стека"
  echo "    2) Удаление служб и интеграций (stack-heal, decoy-login jail, certbot hook)"
  echo "    3) Удаление конфигов и каталогов стека"
  echo "    4) Полное восстановление x-ui.db из pre-install снимка"
  echo "       Reality, CDN/XHTTP, hosts, SNI-поля, инбаунды и клиенты — как до скрипта"
  echo "    5) Удаление служебных маркеров стека и интеграций"
  echo "    6) UFW: восстановление из снимка (если есть), иначе reset + открытие слушающегося"
  echo "    7) Удаление nginx (пакет + конфиги)"
  echo
  echo -e "  ${G}НЕ трогается:${N} AdGuard Home и серты Let's Encrypt в /etc/letsencrypt/live/."
  echo "  ${Y}ВНИМАНИЕ:${N} текущие инбаунды, клиенты и изменения панели после pre-install снимка будут заменены состоянием из снимка."
  echo
  local sure=""
  ask sure "Для подтверждения введи YES" "" '^YES$'
  [[ "$sure" == "YES" ]] || { log "Отменено"; pause; return 0; }
  audit "rollback: ПОЛНЫЙ ОТКАТ СТЕКА (silent)"

  log "[1/7] Бэкап…"
  auto_backup_stack >/dev/null 2>&1 || true

  log "[2/7] Службы и интеграции…"
  uninstall_heal_timer >/dev/null 2>&1 || true
  rm -f /etc/fail2ban/jail.d/decoy-login.local /etc/fail2ban/filter.d/decoy-login.conf 2>/dev/null || true
  rm -f /etc/letsencrypt/renewal-hooks/deploy/stack-cert-mirror.sh 2>/dev/null || true
  systemctl restart fail2ban >/dev/null 2>&1 || true

  log "[3/7] Конфиги и каталоги стека…"
  rm -f /etc/nginx/sites-enabled/stack.conf /etc/nginx/sites-available/stack.conf 2>/dev/null || true
  rm -f /etc/nginx/streams-enabled/sni-router.conf /etc/nginx/streams-available/sni-router.conf 2>/dev/null || true
  rm -f /etc/nginx/snippets/decoy-headers.conf /etc/logrotate.d/stack-decoy 2>/dev/null || true
  rm -rf /var/www/panel-decoy /var/www/decoy-templates /var/www/decoy-login 2>/dev/null || true
  rm -rf /var/www/decoy-[0-9]* /var/www/decoy-login 2>/dev/null || true

  log "[4/7] Полное восстановление x-ui.db из pre-install snapshot…"
  # В режиме «полный откат» возвращаем БД целиком. Это гарантирует возврат
  # Reality, CDN/XHTTP, hosts, SNI-полей, клиентов и настроек ровно к моменту
  # до вмешательства скрипта. Перед заменой актуальная БД уже сохранена через
  # auto_backup_stack на шаге [1/7].
  systemctl stop x-ui 2>/dev/null || true
  local _full_snap="" _db_restored=false
  _full_snap=$(stack_preinstall_db 2>/dev/null || true)
  if [[ -n "$_full_snap" && -f "$_full_snap" && -n "$XUI_DB" && -f "$XUI_DB" ]]; then
    sqlite3 "$XUI_DB" "PRAGMA wal_checkpoint(TRUNCATE);" >/dev/null 2>&1 || true
    cp -a "$XUI_DB" "${XUI_DB}.pre-full-rollback-$(date +%Y%m%d-%H%M%S)" 2>/dev/null || true
    rm -f "${XUI_DB}-wal" "${XUI_DB}-shm" 2>/dev/null || true
    if cp -a "$_full_snap" "$XUI_DB" 2>/dev/null; then
      _db_restored=true
      log "  x-ui.db полностью восстановлен: $_full_snap"
    else
      warn "  не удалось заменить x-ui.db — применяю безопасный выборочный откат"
    fi
  else
    warn "  pre-install x-ui.db не найден — применяю безопасный выборочный откат"
  fi
  if [[ "$_db_restored" != true ]]; then
    stack_reset_state 0 || warn "  выборочный откат выполнен частично"
  else
    # Снимаем служебные маркеры/интеграции, но не меняем восстановленную БД.
    rb_wipe_stack_state 0 || warn "  служебное состояние стека снято частично"
  fi
  log "[5/7] Открытие портов наружу (значение из восстановленной панели)…"
  if [[ "$_db_restored" != true ]]; then
    xui_set_setting webListen ''
    xui_set_setting subListen ''
    local _lid
    while IFS= read -r _lid; do
      [[ -n "$_lid" ]] && db_set_listen "$_lid" '' direct
    done < <(sqlite3 -cmd ".timeout 3000" "$XUI_DB" \
             "SELECT id FROM inbounds WHERE COALESCE(listen,'') IN ('127.0.0.1','::1');" 2>/dev/null || true)
  fi
  systemctl start x-ui 2>/dev/null || true

  log "[6/7] UFW…"
  # в полном откате действуем тихо: если снимок есть — восстанавливаем его логику
  # без интерактивного запроса (restore_firewall_state спрашивает — обходим)
  if [[ -f "$FW_STATE_DIR/saved" ]]; then
    . "$FW_STATE_DIR/state" 2>/dev/null || true
    [[ -f "$FW_STATE_DIR/iptables.v4" ]] && iptables-restore  < "$FW_STATE_DIR/iptables.v4"  2>/dev/null || true
    [[ -f "$FW_STATE_DIR/iptables.v6" ]] && ip6tables-restore < "$FW_STATE_DIR/iptables.v6"  2>/dev/null || true
    if [[ "${UFW_WAS_INSTALLED:-0}" == "1" && -f "$FW_STATE_DIR/ufw-config.tar" ]]; then
      tar -xpf "$FW_STATE_DIR/ufw-config.tar" -C / 2>/dev/null || true
      if [[ "${UFW_WAS_ACTIVE:-0}" == "1" ]]; then
        ufw --force enable >/dev/null 2>&1 || warn "�� ������� �������� UFW"
      else
        ufw --force disable >/dev/null 2>&1 || warn "�� ������� ��������� UFW"
      fi
    fi
    rm -f "$FW_STATE_DIR/saved"
    log "  восстановлено из снимка $FW_STATE_DIR (тихо)"
  else
    save_firewall_state >/dev/null 2>&1 || true
    ufw --force reset >/dev/null 2>&1 || true
    ufw default deny incoming >/dev/null 2>&1 || true
    ufw default allow outgoing >/dev/null 2>&1 || true
    fw_allow "${SSH_PORT:-22}" tcp "SSH"
    local p
    for p in $(ss -tln 2>/dev/null | awk 'NR>1 { if ($4 ~ /^127\./ || $4 ~ /^\[::1\]/) next; split($4,a,":"); print a[length(a)] }' | sort -un); do
      [[ -n "$p" && "$p" != "${SSH_PORT:-22}" ]] && fw_allow "$p" tcp "rollback-open"
    done
    for p in $(ss -uln 2>/dev/null | awk 'NR>1 { if ($4 ~ /^127\./ || $4 ~ /^\[::1\]/) next; if ($5 != "*:*") next; split($4,a,":"); print a[length(a)] }' | sort -un); do
      [[ -n "$p" ]] && fw_allow "$p" udp "rollback-open"
    done
    ufw --force enable >/dev/null 2>&1 || true
    log "  reset + открыто всё слушающееся"
  fi
  # Полный откат снимает firewall-режим стека независимо от наличия снимка.
  # Иначе восстановленный UFW может оставить deny incoming после удаления nginx.
  if command -v ufw >/dev/null 2>&1; then
    ufw --force disable >/dev/null 2>&1 || true
    log "  UFW отключён после полного отката"
  fi

  log "[7/7] Удаление nginx…"
  systemctl stop nginx 2>/dev/null || true
  systemctl disable nginx 2>/dev/null || true
  DEBIAN_FRONTEND=noninteractive apt-get purge -y nginx nginx-common nginx-full libnginx-mod-stream >/dev/null 2>&1 || true
  apt-get autoremove -y >/dev/null 2>&1 || true
  rm -rf /etc/nginx /var/log/nginx 2>/dev/null || true
  # Финальная страховка: полный откат не должен оставлять маркеры stack/SNI,
  # иначе следующий запуск ошибочно считает первичную настройку выполненной.
  rm -f "$STACK_CONF" "$STACK_LINK" "$SNI_CONF" \
    /etc/nginx/streams-enabled/sni-router.conf \
    /etc/nginx/streams-available/sni-router.conf \
    /etc/nginx/snippets/decoy-headers.conf 2>/dev/null || true
  rm -f "$BACKUP_DIR/.pre-install-done" /root/stack-frozen.txt "$CERT_MODE_FILE" \
    "$CERT_LINES_FILE" "$WILDCARD_STATE" /root/.stack-src 2>/dev/null || true

  line
  log "ПОЛНЫЙ ОТКАТ ЗАВЕРШЁН"
  line
  local wp
  wp=$(xui_get webPort 2>/dev/null || echo '?')
  local _pd _pp _host _scheme _cert
  _pd="${PANEL_DOMAIN:-$(xui_get webDomain 2>/dev/null || true)}"
  _pp="$(xui_get webBasePath 2>/dev/null || true)"
  _pp="/${_pp#/}"
  [[ "$_pp" != */ ]] && _pp="$_pp/"
  _host="${_pd:-$(server_ip4)}"; [[ -z "$_host" ]] && _host="127.0.0.1"
  _scheme="https"; _cert=""
  [[ -n "$_pd" ]] && _cert="/etc/letsencrypt/live/$_pd/fullchain.pem"
  [[ -n "$_cert" && ! -f "$_cert" ]] && _cert=""
  [[ -z "$_cert" ]] && _scheme="http"
  if [[ -n "$_pd" && "$_pd" != "panel.example.com" ]]; then
    echo "  Панель:  ${_scheme}://${_pd}:${wp:-?}${_pp}"
    [[ "$_scheme" == "https" ]] && echo "           (доступ по домену; IP даст ошибку сертификата Common Name)"
  else
    echo "  Панель:  ${_scheme}://${_host}:${wp:-?}${_pp}"
    echo "           домен панели не определён — проверь webDomain в LucX UI"
  fi
  echo "  Серты:   сохранены (/etc/letsencrypt/live/)"
  echo "  AdGuard: не трогался"
  echo "  Инбаунды и клиенты панели: сохранены"
  echo "  Бэкап:   $BACKUP_DIR/auto-*"
  line
  pause
}

# --- Подменю отката ---------------------------------------------------
rollback_menu() {
  while :; do
    clear
    line; echo -e "${B}   ОТКАТ И ДЕМОНТАЖ СТЕКА${N}"; line
    local heal="нет" jail="нет" hook="нет" ngx="нет" sni="нет" snap="нет"
    # Проверяем фактические файлы/состояние, а не только список unit-файлов:
    # после частичного отката unit может остаться disabled, а SNI — в enabled.
    stack_heal_present && heal="да"
    [[ -f /etc/fail2ban/jail.d/decoy-login.local ]] && jail="да"
    [[ -x /etc/letsencrypt/renewal-hooks/deploy/stack-cert-mirror.sh ]] && hook="да"
    nginx_ready && ngx="да"
    sni_router_present && sni="да"
    [[ -f "$FW_STATE_DIR/saved" ]] && snap="да"
    echo "  Текущее состояние стека:"
    printf "    nginx:                 %s\n" "$ngx"
    printf "    SNI-роутер (443):      %s\n" "$sni"
    printf "    stack-heal:            %s\n" "$heal"
    printf "    fail2ban decoy-jail:   %s\n" "$jail"
    printf "    certbot deploy-hook:   %s\n" "$hook"
    printf "    снимок UFW:            %s\n" "$snap"
    echo
    line
    echo "  1) 🌐 Открыть порты наружу (панель / подписки / инбаунды)"
    echo "  2) 🚧 Правила файервола (UFW)"
    echo "  3) 🛠️  Службы и интеграции стека"
    echo "  4) 📁 Конфиги и каталоги стека"
    echo "  5) 🗑️  Удалить nginx (пакет + конфиги)"
    echo "  6) 🧨 Снять состояние стека (настройки панели, listen, маркеры)"
    echo "  7) 💣 ПОЛНЫЙ ОТКАТ (всё выше, тихо, подтверждение YES)"
    echo "  0) Назад"
    line
    local c=""
    read -rp "$(echo -e "${B}Выбор:${N} ")" c || c="0"
    case "$c" in
      1) rb_open_ports ;;
      2) rb_firewall ;;
      3) rb_services ;;
      4) rb_configs ;;
      5) rb_remove_nginx ;;
      6) rb_reset_state_menu ;;
      7) rb_full_rollback ;;
      0) return 0 ;;
      *) sleep 1 ;;
    esac
  done
}


# --- Подменю: pre-install snapshot (раздел 5 → пункт 4) ----------------
preinstall_menu() {
  while :; do
    clear
    line; echo -e "${B}   PRE-INSTALL СНИМОК СОСТОЯНИЯ${N}"; line
    local cnt
    cnt=$(ls -1d "$BACKUP_DIR"/pre-install-* 2>/dev/null | grep -v "\.tar\.gz$" | wc -l)
    echo "  Снимков в $BACKUP_DIR/pre-install-*: $cnt"
    echo
    echo "  Что сохраняется:"
    echo "    x-ui.db, /etc/x-ui, /etc/nginx/*, правила UFW/iptables, /etc/fail2ban,"
    echo "    systemd units стека, /etc/letsencrypt/renewal+hooks, logrotate, AdGuardHome.yaml"
    echo
    line
    echo "  1) 📸 Сделать новый снимок сейчас"
    echo "  2) ♻️  Восстановить из снимка (перезапишет текущее состояние)"
    echo "  3) 🗑️  Удалить старый снимок"
    echo "  0) Назад"
    line
    local c=""
    read -rp "$(echo -e "${B}Выбор:${N} ")" c || c="0"
    case "$c" in
      1) take_pre_install_snapshot; pause ;;
      2) restore_pre_install_snapshot ;;
      3)
        local snaps
        snaps=$(ls -1dt "$BACKUP_DIR"/pre-install-* 2>/dev/null | grep -v "\.tar\.gz$" | head -20)
        [[ -z "$snaps" ]] && { warn "Снимков нет"; pause; continue; }
        local i=1 d
        while IFS= read -r d; do
          [[ -z "$d" ]] && continue
          printf "  %2d) %s\n" "$i" "$(basename "$d")"
          i=$((i+1))
        done <<<"$snaps"
        local pick=""; ask pick "Номер (0 — отмена)" "0" '^[0-9]+$'
        [[ "$pick" == "0" ]] && continue
        local ch
        ch=$(printf '%s\n' "$snaps" | sed -n "${pick}p")
        [[ -z "$ch" ]] && { err "Нет такого"; pause; continue; }
        local sure=""; askyn sure "Удалить $(basename "$ch") и его .tar.gz?" "n"
        [[ "$sure" == true ]] && { rm -rf "$ch" "$ch.tar.gz" 2>/dev/null; log "Удалено"; }
        pause
        ;;
      0) return 0 ;;
      *) sleep 1 ;;
    esac
  done
}

routing_diagnostics_menu() {
  while :; do
    line; echo -e "${B}   МАРШРУТИЗАЦИЯ И ДИАГНОСТИКА${N}"; line
    echo "  1) Диагностика стека"
    echo "  2) Очистить устаревшие SNI-записи"
    echo "  3) Пересобрать SNI из текущей БД"
    echo "  4) Гигиена nginx"
    echo "  5) Проверка/починка CDN-маршрутизации"
    echo "  0) Назад"
    local c=""
    ask c "Выбор" "1" '^[0-5]$'
    case "$c" in
      1)
        echo
        echo "  1) Полный read-only аудит"
        echo "  2) Наблюдение за стеком"
        echo "  3) Стелс-аудит"
        echo "  0) Назад"
        local d=""
        ask d "Диагностика" "1" '^[0-3]$'
        case "$d" in
          1) stack_full_audit; pause ;;
          2) stack_doctor_menu ;;
          3) stealth_audit ;;
        esac
        ;;
      2) sni_cleanup_stale; pause ;;
      3) rebuild_sni_from_db ;;
      4) nginx_hygiene ;;
      5) cdn_repair; pause ;;
      0) return 0 ;;
    esac
  done
}

setup_routing_menu() {
  while :; do
    line; echo -e "${B}   УСТАНОВКА И МАРШРУТИЗАЦИЯ${N}"; line
    echo "  1) Первичная настройка SNI-роутера"
    echo "  2) Инбаунды: проверка, добавление, удаление, домены"
    echo "  0) Назад"
    local c=""; ask c "Выбор" "1" '^[0-2]$'
    case "$c" in
      1)
        : > /tmp/stack-initial-setup.log 2>/dev/null || true
        initial_setup > >(tee -a /tmp/stack-initial-setup.log) 2>&1
        local _setup_rc=$?
        if [[ $_setup_rc -eq 0 ]]; then
          stack_mark_configured || warn "Не удалось сохранить маркер настройки; автоматические исправления останутся отключены."
          echo
          echo -e "${G}Первичная настройка завершена.${N}"
          pause
        else
          echo
          err "Первичная настройка завершилась с ошибкой (код $_setup_rc)."
          echo "Подробный лог: /tmp/stack-initial-setup.log"
          echo "Последние строки лога:"
          tail -30 /tmp/stack-initial-setup.log 2>/dev/null || true
          pause
        fi
        return "$_setup_rc"
        ;;
      2) inbounds_manage_menu ;;
      0) return 0 ;;
    esac
  done
}
decoy_domains_menu() {
  while :; do
    line; echo -e "${B}   DECOY И ДОМЕНЫ${N}"; line
    echo "  1) Сменить decoy"
    echo "  2) Каталог decoy-шаблонов"
    echo "  3) Сменить домен inbound"
    echo "  0) Назад"
    local c=""; ask c "Выбор" "1" '^[0-3]$'
    case "$c" in 1) change_decoy ;; 2) view_decoy_templates ;; 3) inbound_change_domain ;; 0) return 0 ;; esac
  done
}
certificates_menu() { certs_menu; }
security_firewall_menu() {
  while :; do
    line; echo -e "${B}   БЕЗОПАСНОСТЬ И FIREWALL${N}"; line
    echo "  1) Баны, decoy-login, fail2ban"
    echo "  2) Правила firewall"
    echo "  3) Восстановить состояние firewall"
    echo "  0) Назад"
    local c=""; ask c "Выбор" "1" '^[0-3]$'
    case "$c" in 1) security_menu ;; 2) firewall_menu ;; 3) restore_firewall_state ;; 0) return 0 ;; esac
  done
}
backups_rollback_menu() {
  while :; do
    line; echo -e "${B}   БЭКАПЫ И ОТКАТ${N}"; line
    echo "  1) Сделать бэкап"
    echo "  2) Восстановить из бэкапа"
    echo "  3) Откат и демонтаж стека"
    echo "  4) Pre-install snapshot (снимок до изменений)"
    echo "  0) Назад"
    local c=""; ask c "Выбор" "1" '^[0-4]$'
    case "$c" in 1) backup_config ;; 2) restore_config ;; 3) rollback_menu ;; 4) preinstall_menu ;; 0) return 0 ;; esac
  done
}
diagnostics_maintenance_menu() {
  while :; do
    line; echo -e "${B}   ДИАГНОСТИКА И ОБСЛУЖИВАНИЕ${N}"; line
    echo "  1) ⚡ Проверить всё и починить (аудит → автопочинка → контроль)"
    echo "  2) Статус стека"
    echo "  3) Маршрутизация и диагностика"
    echo "  4) Полный read-only аудит стека (вкл. CDN и drift)"
    echo "  5) Сменить пароли LucX UI / AdGuard Home"
    echo "  6) Обновить скрипт"
    echo "  7) AmneziaWG: статус (инбаунды + kernel-интерфейсы)"
    echo "  0) Назад"
    local c=""; ask c "Выбор" "1" '^[0-7]$'
    case "$c" in
      1) stack_check_fix; pause ;;
      2) show_status ;;
      3) routing_diagnostics_menu ;;
      4) stack_full_audit; pause ;;
      5) change_admin_passwords ;;
      6) update_self ;;
      7) awg_status; pause ;;
      0) return 0 ;;
    esac
  done
}
panel_adguard_menu() {
  while :; do
    line; echo -e "${B}   ПАНЕЛЬ И ADGUARD${N}"; line
    echo "  1) Управление LucX/3x-ui"
    echo "  2) Управление AdGuard Home"
    echo "  3) DNS Xray в панели LucX/3x-ui"
    echo "  0) Назад"
    local c=""; ask c "Выбор" "1" '^[0-3]$'
    case "$c" in 1) panel_manage; pause ;; 2) adguard_manage; pause ;; 3) xray_dns_menu ;; 0) return 0 ;; esac
  done
}

# Действие пункта меню — вызывается в ПОД-ОБОЛОЧКЕ: exit 42 внутри (токен «q»
# в любом вопросе) гасит только её, и мы оказываемся назад в меню.
run_menu_action() {
  # Пункты меню доступны всегда. Безопасность обеспечивается внутри
  # конкретных автоматических процедур, а не блокировкой всего меню.
  stack_is_configured && audit "menu:${1:-}"
  case "$1" in
    1) setup_routing_menu ;;
    2) decoy_domains_menu ;;
    3) certificates_menu ;;
    4) security_firewall_menu ;;
    5) backups_rollback_menu ;;
    6) diagnostics_maintenance_menu ;;
    7) panel_adguard_menu ;;
    *) warn "Нет такого пункта"; sleep 1 ;;
  esac
}

print_menu_actions() {
  echo
  echo -e "  ${B} 1)${N} 🧭 Установка и маршрутизация"
  echo -e "  ${B} 2)${N} 🎭 Decoy и домены"
  echo -e "  ${B} 3)${N} 🔒 Сертификаты"
  echo -e "  ${B} 4)${N} 🛡️  Безопасность и firewall"
  echo -e "  ${B} 5)${N} 💾 Бэкапы и откат"
  echo -e "  ${B} 6)${N} 🩺 Диагностика и обслуживание"
  echo -e "  ${B} 7)${N} ⚙️  Панель и AdGuard"
}

fast_menu_header() {
  local nb=0 ufw_state="down" ngx xui adg f2b panel="—" panel_url="" adg_url=""
  local _pd="" _pp="" _pb="" _adg_dom="" _panel_port="" _public_port=""
  _pd="${PANEL_DOMAIN:-$(xui_get webDomain 2>/dev/null || true)}"
  _pp="$(xui_get webBasePath 2>/dev/null || true)"
  _panel_port="$(xui_get webPort 2>/dev/null || true)"
  # После отката nginx/SNI-фронтенд отсутствует, поэтому панель доступна
  # напрямую на webPort. В шапке показываем тот же фактический URL, что и
  # в итоговом сообщении отката; при работающем фронтенде используем 443.
  if [[ -f "$STACK_CONF" ]] && nginx_ready; then
    _public_port=""
  else
    [[ "$_panel_port" =~ ^[0-9]+$ ]] && _public_port="$_panel_port"
  fi
  if [[ -n "$_pd" && "$_pd" != "panel.example.com" ]]; then
    _pp="${_pp#/}"; _pp="${_pp%/}"   # ведущий и хвостовой слеши — добавим ровно один
    if [[ -n "$_public_port" ]]; then
      panel_url="https://$_pd:${_public_port}/"
    else
      panel_url="https://$_pd/"
    fi
    [[ -n "$_pp" ]] && panel_url="${panel_url}${_pp}/"
  fi
  if [[ "$ADG_PRESENT" == true && -n "$ADG_SERVICE" ]] && systemctl is-active --quiet "$ADG_SERVICE" 2>/dev/null; then
    _adg_dom="$(xui_get webDomain 2>/dev/null || true)"
    if [[ "${ADG_PLACEMENT:-}" == separate && -n "${ADG_MODE_SNI_DOM:-}" ]]; then _adg_dom="$ADG_MODE_SNI_DOM"; fi
    [[ -n "$_adg_dom" ]] && adg_url="https://$_adg_dom/"
  fi
  [[ -f "$XUI_DB" ]] && nb=$(sqlite3 -cmd ".timeout 1000" "$XUI_DB" "SELECT COUNT(*) FROM inbounds WHERE enable=1;" 2>/dev/null || echo 0)
  ufw_is_active && ufw_state="active"
  ngx=$(systemctl is-active nginx 2>/dev/null || echo unknown)
  xui=$(systemctl is-active x-ui 2>/dev/null || echo unknown)
  adg="—"; [[ "$ADG_PRESENT" == true && -n "$ADG_SERVICE" ]] && adg=$(systemctl is-active "$ADG_SERVICE" 2>/dev/null || echo unknown)
  f2b=$(systemctl is-active fail2ban 2>/dev/null || echo unknown)
  case "${PANEL_FLAVOR:-$(detect_panel_flavor)}" in
    lucx) panel="LucX UI" ;; 3x-ui) panel="3x-ui" ;; *) panel="не установлена" ;;
  esac
  line
  local panel_line="" adg_line=""
  [[ -n "$panel_url" ]] && panel_line="🔗 Панель: $panel_url"
  [[ -n "$adg_url" ]] && adg_line="🛡 AdGuard: $adg_url"
  printf "  ${B}%-56s${N}\n" "╔═ STACK MANAGER · ПРОКСИ-ОРКЕСТРАТОР ═╗"
  printf "  ${D}%-56s${N}\n" "Версия: v${STACK_MANAGER_VERSION} | Панель: $panel | nginx: 443 | SNI | CDN | decoy"
  # URL нельзя обрезать: длинная ссылка выводится целиком, при необходимости — в несколько строк.
  if [[ -n "$panel_line" ]]; then
    printf '%s\n' "$panel_line" | fold -w 54 | while IFS= read -r _url_line; do
      [[ -n "$_url_line" ]] && printf "  ${G}%s${N}\n" "$_url_line"
    done
  fi
  if [[ -n "$adg_line" ]]; then
    printf '%s\n' "$adg_line" | fold -w 54 | while IFS= read -r _url_line; do
      [[ -n "$_url_line" ]] && printf "  ${G}%s${N}\n" "$_url_line"
    done
  fi
  line
  printf "  %-18s %-12s | %-18s %-12s\n" "nginx" "$ngx" "x-ui" "$xui"
  printf "  %-18s %-12s | %-18s %-12s\n" "AdGuard" "$adg" "fail2ban" "$f2b"
  local inbound_label="—"
  [[ -n "$XUI_DB" && -f "$XUI_DB" ]] && inbound_label="${nb:-0} active"
  printf "  %-18s %-12s | %-18s %-12s\n" "UFW" "$ufw_state" "inbounds" "$inbound_label"
  line
  printf "  ${D}%-56s${N}\n" "Быстрый переход: 1–7 разделы | 0 выход | аудит: разделы 6–7"
  line
}

main_menu() {
  # До явной настройки пользователя — только меню и чтение состояния.
  # Инициализация decoy сама меняет nginx/файлы, поэтому здесь запрещена.
  detect_env >/dev/null 2>&1 || true
  if stack_is_configured; then
    decoy_full_init || true
  else
    warn "Безопасный режим: стек ещё не настроен скриптом; автоматические изменения отключены."
  fi
  while :; do
    clear
    fast_menu_header
    print_menu_actions
    echo
    echo -e "  ${B} 0)${N} 🚪 Выход   ${Y}(q в любом вопросе — выход в меню)${N}"
    line
    local c="" rc
    read -rp "$(echo -e "${Y}👉${N} Ваш выбор: ")" c || c="0"
    case "$c" in
      0) exit 0 ;;
      q|quit|exit|выход) exit 0 ;;
      *) ( run_menu_action "$c" )
         rc=$?
         if [[ $rc -eq 42 ]]; then warn "Возврат в меню"; sleep 1
         elif [[ $rc -ne 0 ]]; then warn "Пункт завершился с ошибкой (код $rc)"; sleep 1; fi ;;
    esac
  done
}

# =====================================================================
