# СЕРТИФИКАТЫ
# =====================================================================
# =====================================================================
# СЕРТЫ ЖИВУТ ТОЛЬКО В /etc/letsencrypt/live/ — дубликатов больше нет
# =====================================================================
# Раньше каждый серт зеркалировался в /root/cert/<домен>/ (папка панели) —
# дублирование. Теперь функция возвращает пути исходной live-линии, все
# вызывающие (панель, decoy, AdGuard) автоматически получают live-пути,
# а cert_dedup_migrate() разово перепривязывает старые ссылки и сносит /root/cert.
cert_mirror_to_certroot() {   # <live-dir> <domain> → echo "<fullchain> <privkey>"
  local src="$1"
  [[ -f "$src/fullchain.pem" && -f "$src/privkey.pem" ]] || return 1
  echo "$src/fullchain.pem $src/privkey.pem"
  return 0
}



# deploy-hook: после каждого certbot renew — рестарт панели/nginx/AdGuard
# (серты живут в live/, зеркало упразднено). Хук перезаписывается при каждом
# запуске скрипта — старая версия с зеркалом не должна выжить.

# Вписывает пути сертификатов в settings инбаундов:
#   naive/anytls/trusttunnel/tproxy → settings.certFile/keyFile
#   hysteria → stream tlsSettings.certificates[0]
# Lineage для домена: точный, иначе wildcard базового домена (если уже выпущен) —
# чтобы в wildcard-режиме не плодить персональные серты на каждый субдомен
cert_lineage_for() {
  local d="$1" wb="${1#*.}" c
  c=$(cert_paths "$d" 2>/dev/null || true)
  [[ -z "$c" && "$wb" == *.* ]] && c=$(cert_paths "$wb" 2>/dev/null || true)
  printf '%s' "$c"
}

# --- tg web proxy (tproxy): hostname + серт + сайт-заглушка + маршрут 443 -----
# Панель создаёт tproxy-инбаунд пустым — без hostname он отключается
# ("tproxy: hostname is required"), без index.html в siteDir не стартует caddy.
# Здесь доводим до рабочего вида: домен tg.<база панели>, серт (точный или
# wildcard базы), enable=1, маршрут SNI-роутера на 11443.
setup_tproxy_web() {
  [[ -z "$XUI_DB" || ! -f "$XUI_DB" ]] && return 0
  local tid
  tid=$(sqlite3 "$XUI_DB" "SELECT id FROM inbounds WHERE protocol='tproxy' ORDER BY id LIMIT 1;" 2>/dev/null || true)
  [[ -z "$tid" ]] && return 0   # tproxy не выбран при установке — нечего настраивать
  db_protect_suspend
  local tdom="${T_PROXY_DOMAIN:-}"
  if [[ -z "$tdom" ]]; then
    # реальный домен — из настроек инбаунда (если не плейсхолдер *.example.com)
    tdom=$(sqlite3 -cmd ".timeout 3000" "$XUI_DB" \
           "SELECT COALESCE(json_extract(settings,'\$.hostname'),'') FROM inbounds WHERE id=$tid;" 2>/dev/null | tr -d '[:space:]')
    [[ "$tdom" =~ \.example\.com$ ]] && tdom=""
  fi
  if [[ -z "$tdom" ]]; then
    local base="${PANEL_DOMAIN#*.}"
    [[ "$base" != *.* ]] && base="$PANEL_DOMAIN"
    tdom="tg.${base:-example.com}"
  fi
  # сайт-заглушка обязательна: без index.html в siteDir caddy tproxy не поднимается
  mkdir -p /var/www/html
  ensure_tproxy_site   # нейтральная blog-заглушка (перезаписывает пустышку/старое)
  # серт: точный → wildcard базового домена → выпуск
  local cline c_cert="" c_key=""
  cline=$(cert_lineage_for "$tdom")
  if [[ -z "$cline" ]]; then
    cert_issue "$tdom" || warn "  tg web proxy: серт $tdom НЕ выпущен (проверь DNS) — запусти скрипт повторно после добавления записи"
    cline=$(cert_lineage_for "$tdom")
  fi
  [[ -n "$cline" ]] && { c_cert="${cline%% *}"; c_key="${cline##* }"; }
  # БД: hostname + пути серта + enable=1 (строго при остановленном x-ui)
  systemctl stop x-ui 2>/dev/null || true
  T_PROXY_ID="$tid" T_PROXY_DOM="$tdom" T_PROXY_CERT="$c_cert" T_PROXY_KEY="$c_key" python3 - "$XUI_DB" <<'PYTP'
import sqlite3, json, os, sys
con = sqlite3.connect(sys.argv[1])
iid, dom = int(os.environ["T_PROXY_ID"]), os.environ["T_PROXY_DOM"]
s = json.loads(con.execute("SELECT settings FROM inbounds WHERE id=?", (iid,)).fetchone()[0] or "{}")
s["hostname"] = dom
if os.environ.get("T_PROXY_CERT"):
    s["certFile"] = os.environ["T_PROXY_CERT"]; s["keyFile"] = os.environ["T_PROXY_KEY"]
s["externalTLS"] = False
con.execute("UPDATE inbounds SET settings=?, enable=1 WHERE id=?", (json.dumps(s), iid))
con.commit()
print(f"  tproxy #{iid}: hostname={dom}, серт {'вписан' if os.environ.get('T_PROXY_CERT') else 'НЕ найден'}, enable=1")
PYTP
  systemctl start x-ui 2>/dev/null || true
  sleep 4
  # маршрут 443 → tproxy. Сначала удаляем ВСЕ старые строки этого домена,
  # затем добавляем ровно одну актуальную запись — это предотвращает conflict
  # parameter при миграции старого svc-*/inb_* маршрута в tg_backend.
  if [[ -f "$SNI_CONF" ]]; then
    if ! grep -q "upstream tg_backend" "$SNI_CONF"; then
      sed -i "1i upstream tg_backend { server 127.0.0.1:11443; }" "$SNI_CONF" 2>/dev/null || true
    fi
    awk -v dom="$tdom" '
      !($1 == dom && $2 != "") { print }
    ' "$SNI_CONF" > "$SNI_CONF.tmp" && mv "$SNI_CONF.tmp" "$SNI_CONF" || {
      rm -f "$SNI_CONF.tmp" 2>/dev/null || true
      warn "tg web proxy: не удалось очистить старые SNI-записи для $tdom"
    }
    sni_map_add "$tdom" "tg_backend" || warn "tg web proxy: не удалось добавить SNI-запись $tdom"
    log "tg web proxy: мап обновлён → $tdom → tg_backend"
  fi
  # доктрина «всё за 443»: 11443 наружу не открываем (и закрываем, если было);
  # UDP-порт здесь — HTTP/3 caddy, наружу не нужен и палится сканерами
  ufw delete allow 11443/tcp >/dev/null 2>&1 || true
  ufw delete allow 11443/udp >/dev/null 2>&1 || true
  nginx -t >/dev/null 2>&1 && nginx_reload || true
  log "tg web proxy: https://$tdom/ — сайт-заглушка + веб-интерфейс прокси (ключи/ссылки в панели)"
}

# --- Смена паролей admin (панель и/или AdGuard) ------------------------------
change_admin_passwords() {
  line; echo -e "${B}   СМЕНИТЬ ПАРОЛИ ADMIN${N}"; line
  detect_env >/dev/null 2>&1 || true
  local what=""
  if [[ "$ADG_PRESENT" == true && -n "$ADG_SERVICE" ]]; then
    ask what "Что меняем? [1] панель, [2] AdGuard, [3] обе" "3" '^[123]$'
  else
    log "AdGuard Home не установлен — меняем только пароль панели."
    what="1"
  fi
  if [[ "$what" == "1" || "$what" == "3" ]]; then
    [[ -z "$XUI_DB" || ! -f "$XUI_DB" ]] && { err "x-ui.db не найден"; return 1; }
    local ppass=""
    ask ppass "Новый пароль ПАНЕЛИ (admin; Enter — случайный)" "" '^$|.{6,}'
    [[ -z "$ppass" ]] && ppass=$(openssl rand -base64 18 2>/dev/null | tr -dc 'a-zA-Z0-9' | head -c 16)
    systemctl stop x-ui 2>/dev/null || true
    PPASS="$ppass" python3 - "$XUI_DB" <<'PYPASS'
import sqlite3, sys, os
try:
    import bcrypt
except Exception:
    print("  нет python3-bcrypt: apt install python3-bcrypt"); sys.exit(1)
h = bcrypt.hashpw(os.environ["PPASS"].encode(), bcrypt.gensalt()).decode()
con = sqlite3.connect(sys.argv[1])
tabs = [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")]
if "users" in tabs:
    cols = [r[1] for r in con.execute("PRAGMA table_info(users)")]
    if "username" in cols and "password" in cols:
        n = con.execute("UPDATE users SET password=? WHERE username='admin'", (h,)).rowcount
        if n == 0:
            con.execute("INSERT INTO users (username, password) VALUES ('admin', ?)", (h,))
        con.commit(); print("  панель: users.password обновлён (bcrypt)")
elif "pass" in [r[0] for r in con.execute("SELECT key FROM settings")]:
    con.execute("UPDATE settings SET value=? WHERE key='pass'", (h,))
    con.commit(); print("  панель: settings.pass обновлён (bcrypt)")
else:
    print("  панель: не нашёл, где хранится пароль — напиши разработчику"); sys.exit(1)
PYPASS
    local rc=$?
    systemctl start x-ui 2>/dev/null || true
    if [[ $rc -eq 0 ]]; then
      {
        echo "LucX UI панель — $(date '+%F %T')"
        echo "  Логин:  admin"
        echo "  Пароль: $ppass"
      } > /root/panel-credentials.txt
      chmod 600 /root/panel-credentials.txt
      log "Пароль панели обновлён ✓ — логин admin, сохранено в /root/panel-credentials.txt"
    else
      err "Пароль панели НЕ изменён"
    fi
  fi
  if [[ "$what" == "2" || "$what" == "3" ]]; then
    local auser="" apass=""
    auser=$(grep -i "логин" /root/adguard-credentials.txt 2>/dev/null | awk '{print $NF}' | head -1)
    [[ -z "$auser" ]] && auser="${U_ADG_USER:-admin}"
    ask auser "Логин ADGUARD (Enter — $auser)" "$auser" '^[a-zA-Z0-9._-]{3,32}$'
    ask apass "Новый пароль ADGUARD (Enter — случайный)" "" '^$|.{6,}'
    [[ -z "$apass" ]] && apass=$(openssl rand -base64 18 2>/dev/null | tr -dc 'a-zA-Z0-9' | head -c 16)
    if adg_set_admin "$auser" "$apass"; then
      local apd
      apd=$(xui_get webDomain 2>/dev/null || true)
      [[ -z "$apd" || "$apd" == "null" ]] && apd="${PANEL_DOMAIN:-}"
      {
        echo "AdGuard Home — $(date '+%F %T')"
        [[ -n "$apd" ]] && { echo "  URL:    https://$apd/"; echo "  DoH:    https://$apd/dns-query"; }
        echo "  Логин:  $auser"
        echo "  Пароль: $apass"
      } > /root/adguard-credentials.txt
      chmod 600 /root/adguard-credentials.txt
      log "Пароль AdGuard обновлён ✓ — сохранено в /root/adguard-credentials.txt"
    else
      err "Пароль AdGuard НЕ изменён"
    fi
  fi
  return 0
}

# Read-only проверка: есть ли вообще, что чинить. Пустой вывод = все серты
# на месте — тогда sync_inbound_certs не останавливает панель и молчит.
sync_inbound_needs() {
  python3 - "$XUI_DB" "${REALITY_TARGETS[@]}" <<'PYNEED' 2>/dev/null
import sqlite3, json, sys, subprocess, re
db = sys.argv[1]
targets = set(a.lower() for a in sys.argv[2:])
SKIP = {"qwdtt","csqdtt","csqtt","wireguard","amnezia","amneziawg","awg","mtproto","tun"}
CDN_IDS = set()
try:
    CDN_IDS = {l.strip().split("|",1)[0] for l in open("/root/stack-backups/cdn-profiles.tsv")
               if l.strip() and "|" in l and l.split("|",1)[0].isdigit()}
except Exception:
    pass
def listening(port):
    try:
        out = subprocess.run(["ss","-tln"],capture_output=True,text=True,timeout=5).stdout
    except Exception:
        return False
    return bool(re.search(rf":{port}(\s|$)", out))
try:
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=5)
    rows = con.execute("SELECT id,protocol,settings,stream_settings FROM inbounds WHERE enable=1 AND port>0").fetchall()
except Exception:
    sys.exit(0)
for iid, proto, s1, s2 in rows:
    p = (proto or "").lower()
    if p in SKIP: continue
    if str(iid) in CDN_IDS: continue            # CDN-режим: TLS у nginx, серт в инбаунде не нужен
    try: se = json.loads(s1 or "{}")
    except Exception: se = {}
    try: st = json.loads(s2 or "{}")
    except Exception: st = {}
    rs = st.get("realitySettings") or {}
    dom = se.get("domain") or se.get("hostname") or se.get("sni") \
       or (st.get("tlsSettings") or {}).get("serverName") \
       or (rs.get("serverNames") or [None])[0] or ""
    dom = str(dom).strip()
    if not dom: continue
    if (st.get("security") or "").lower() == "reality":
        dest = str(rs.get("dest") or rs.get("target") or "")
        if dest and dest.split(":")[0] != "127.0.0.1": continue   # чужой reality
        if dom.lower() in targets: continue                        # домен = цель
        # Порт берём из ФАКТИЧЕСКОГО dest, а не по формуле 4444+id: если decoy
        # уже рабочий, самолечение не должно его «переносить» (иначе вечный цикл
        # починки и расхождение конфига с работающим nginx).
        m = re.search(r'127\.0\.0\.1:(\d+)', dest)
        if m and listening(int(m.group(1))):
            continue                                               # decoy жив
    else:
        cert = se.get("certFile") or ""
        if not cert:
            c = (st.get("tlsSettings") or {}).get("certificates") or []
            if c: cert = c[0].get("certificateFile","")
        if cert.startswith("/etc/letsencrypt/live/"): continue
    print(f"{iid}\x1f{proto}\x1f{dom}\x1f{json.dumps(st, ensure_ascii=False)}")
PYNEED
}

sync_inbound_certs() {
  [[ -z "$XUI_DB" || ! -f "$XUI_DB" ]] && return 1
  # Тихий проход: если самолечению нечего чинить — панель НЕ останавливаем
  # и ничего не печатаем (раньше каждый запуск бил x-ui и сыпал «cert вписан»).
  [[ -z "$(sync_inbound_needs)" ]] && return 0
  db_protect_suspend   # осознанные правки сертов/dest — триггеры вернутся на выходе
  local cnt=0 id proto dom stream line cert key
  # x-ui держит inbounds в памяти и при рестарте сбрасывает её поверх БД —
  # поэтому ВСЕ правки inbounds делаем только при ОСТАНОВЛЕННОМ x-ui
  systemctl stop x-ui 2>/dev/null || true
  # tproxy (caddy) отказывается стартовать без index.html в siteDir — нейтральный blog
  if [[ -d /var/www/html && -n "$DECOY_TPL_DIR" && -f "$DECOY_TPL_DIR/blog.html" ]]; then
    cp -f "$DECOY_TPL_DIR/blog.html" /var/www/html/index.html 2>/dev/null || true
  fi
  # Читаем через python: панель хранит stream/settings pretty-JSON (многострочно),
  # sqlite3|while-read обрезал бы значение на первом переносе — reality-инбаунды
  # молча выпадали из самолечения и не получали серты/decoy.
  while IFS=$'\x1f' read -r id proto dom stream; do
    [[ -z "$id" || -z "$dom" || "$dom" == "null" ]] && continue
    dom="$(printf '%s' "$dom" | tr -d '[:space:]')"   # хвост-пробел/CR ломает пути live/<домен>
    # «аренда» снятия защиты на КАЖДУЮ итерацию: правки сертов/dest этой итерации
    # не должны откатываться триггером (см. db_protect_suspend)
    db_protect_suspend
    # qwdtt/csqtt/wireguard/т.п. — серты и decoy не нужны никогда
    case "$proto" in
      qwdtt|csqdtt|csqtt|wireguard|amnezia|amneziawg|awg|mtproto|tun) continue ;;
    esac

    # --- Reality: серт нужен DECOY-бекенду (dest). Если decoy нет/мёртв — создаём.
    if grep -qi '"security": *"reality"' <<<"$stream" 2>/dev/null; then
      # ЧУЖОЙ реалити (dest = внешняя цель, НЕ 127.0.0.1): серт и decoy НЕ НУЖНЫ —
      # инбаунд спрятан за 443 через SNI-маршрут на имя цели. dom здесь — это
      # serverNames (цель), выпускать на неё серт нельзя и не нужно.
      local rdest="" rt2
      rdest=$(sqlite3 "$XUI_DB" "SELECT COALESCE(json_extract(stream_settings,'\$.realitySettings.dest'),'') FROM inbounds WHERE id=$id;" 2>/dev/null || true)
      rdest="${rdest%%:*}"
      if reality_external_dest "$id"; then
        continue   # внешний Reality — cert/decoy не требуются
      fi
      local cline2 c_cert c_key want_port droot
      cline2=$(cert_lineage_for "$dom")
      if [[ -z "$cline2" ]]; then
        cert_issue "$dom" >/dev/null 2>&1 || warn "  #$id (reality): серт $dom НЕ выпущен. Причина:"
        cline2=$(cert_lineage_for "$dom")
      fi
      if [[ -z "$cline2" ]]; then
        warn "  #$id (reality): без серта decoy не создать — пробивы увидят отказ соединения"
        continue
      fi
      c_cert="${cline2%% *}"; c_key="${cline2##* }"
      # Порт decoy: сначала смотрим, на каком порту домен уже обслуживается
      # (маркер decoy-блока), и только если блока нет — берём канонический
      # 4444+id. Так самолечение никогда не «переносит» уже рабочий decoy и не
      # расходится с п.1/работающим nginx.
      local _dmeta="" want_port=""
      _dmeta=$(stack_decoy_meta "$dom" 2>/dev/null || true)
      want_port="${_dmeta%% *}"
      [[ "$want_port" =~ ^[0-9]+$ ]] || want_port=$(( 4444 + id ))
      # dest уже указывает на живой decoy с этим портом? тогда не трогаем
      if grep -Eq "\"(dest|target)\": ?\"127\.0\.0\.1:$want_port\"" <<<"$stream" && ss -tln 2>/dev/null | grep -q ":$want_port "; then
        continue
      fi
      droot="/var/www/decoy-$id"
      mkdir -p "$droot"
      [[ -f "$droot/index.html" ]] || { cp "$DECOY_TPL_DIR/corporate.html" "$droot/index.html" 2>/dev/null || echo '<html><body><h1>Welcome</h1></body></html>' > "$droot/index.html"; }
      if mk_decoy "$want_port" "$dom" "$c_cert" "$c_key" "$droot" "$(decoy_tpl_for "$dom")" && reality_set_dest "$id" "$want_port" "$dom"; then
        log "  #$id (reality): decoy на $want_port + dest восстановлены (серт $dom)"
        cnt=$((cnt+1))
      else
        warn "  #$id (reality): не удалось создать decoy/dest"
      fi
      continue
    fi

    # --- TLS-инбаунды (naive/anytls/trusttunnel/hysteria) ---
    line=$(cert_lineage_for "$dom")
    if [[ -z "$line" ]]; then
      local ci_out=""
      if ! ci_out=$(cert_issue "$dom" 2>&1); then
        warn "  #$id ($proto): серт $dom НЕ выпущен. Причина:"
        echo "$ci_out" | tail -10 | sed 's/^/    /'
      fi
      line=$(cert_lineage_for "$dom")
    fi
    [[ -z "$line" ]] && { warn "  #$id ($proto): останется БЕЗ серта — порт подниматься не будет"; continue; }
    cert="${line%% *}"; key="${line##* }"
    # ВАЖНО: sidecar-инбаунды (naive) берут серт из settings.certFile,
    # xray-инбаунды (trusttunnel/anytls/hysteria) — из stream_settings.
    # Пишем ОБА места, иначе x-ui пропускает инбаунд и он не слушает порт.
    python3 - "$XUI_DB" "$id" "$proto" "$dom" "$cert" "$key" "$SNI_CONF" <<'PY' && cnt=$((cnt+1))
import sqlite3, json, sys, re
db, i, proto, dom, cert, key, sni_conf = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6], sys.argv[7]
con = sqlite3.connect(db)
def one(sql, *a):
    return con.execute(sql, a).fetchone()
changed = False
if proto == "hysteria":
    st = json.loads((one("SELECT stream_settings FROM inbounds WHERE id=?", i)[0] or "{}"))
    st["network"] = st.get("network") or "udp"
    st["security"] = "tls"
    tls = st.get("tlsSettings") or {}
    tls["serverName"] = dom
    tls["certificates"] = [{"certificateFile": cert, "keyFile": key}]
    st["tlsSettings"] = tls
    con.execute("UPDATE inbounds SET stream_settings=? WHERE id=?", (json.dumps(st), i))
    changed = True
else:
    try:
        s = json.loads((one("SELECT settings FROM inbounds WHERE id=?", i)[0] or "{}"))
    except Exception:
        s = {}
    # БЕЗУСЛОВНО: ключа certFile может не быть (панель перегенерила settings) —
    # создаём. Иначе самолечение зацикливается: sync «вписал», проверка не видит.
    s["certFile"] = cert; s["keyFile"] = key
    con.execute("UPDATE inbounds SET settings=? WHERE id=?", (json.dumps(s), i))
    changed = True
    # Tunnel-класс LucX читает порт из settings.port; если панель его потеряла —
    # сервис не биндится. Восстанавливаем из SNI-маршрута (upstream inb_<id>_backend).
    if proto in ("naive", "naiveproxy", "anytls", "trusttunnel", "trust-tunnel", "tproxy") and not s.get("port"):
        try:
            m = re.search(r"inb_%d_backend\s*\{[^}]*?server[^\d]*127\.0\.0\.1:(\d+)" % i,
                          open(sni_conf, encoding="utf-8", errors="ignore").read(), re.S)
            if m:
                s["port"] = int(m.group(1))
                con.execute("UPDATE inbounds SET settings=? WHERE id=?", (json.dumps(s), i))
                print(f"  #{i} ({proto}): порт восстановлен из SNI-маршрута → {s['port']}")
        except Exception:
            pass
    if proto in ("anytls", "trusttunnel", "trust-tunnel", "vless"):
        st2 = json.loads((one("SELECT stream_settings FROM inbounds WHERE id=?", i)[0] or "{}"))
        if st2.get("security") not in (None, "", "tls"):
            pass   # reality и прочие — stream не трогаем
        else:
            st2["network"] = "tcp"; st2["security"] = "tls"
            st2["tlsSettings"] = {"serverName": dom, "certificates": [{"certificateFile": cert, "keyFile": key}]}
            con.execute("UPDATE inbounds SET stream_settings=? WHERE id=?", (json.dumps(st2), i))
con.commit()
if changed:
    print(f"  #{i} ({proto}): cert вписан ({dom} → {cert})")
    sys.exit(0)
print(f"  #{i} ({proto}): ПРЕДУПРЕЖДЕНИЕ: серт никуда не вписан — структура не распознана")
sys.exit(4)
PY
  done < <(python3 - "$XUI_DB" <<'PYROWS' 2>/dev/null
import sqlite3, json, sys
try:
    con = sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True, timeout=5)
    rows = con.execute("SELECT id, protocol, settings, stream_settings FROM inbounds WHERE enable=1 AND port>0").fetchall()
except Exception:
    sys.exit(0)
for iid, proto, setts_s, stream_s in rows:
    try:    se = json.loads(setts_s or "{}")
    except Exception: se = {}
    try:    st = json.loads(stream_s or "{}")
    except Exception: st = {}
    rs = st.get("realitySettings") or {}
    dom = se.get("domain") or se.get("hostname") or se.get("sni") \
          or (st.get("tlsSettings") or {}).get("serverName") \
          or (rs.get("serverNames") or [None])[0]
    dom = str(dom or "")   # None → пустая строка (bash-фильтр её отбросит)
    # json.dumps — гарантированно ОДНА строка, какими бы кривыми ни были данные в БД
    print(f"{iid}\x1f{proto}\x1f{dom}\x1f{json.dumps(st, ensure_ascii=False)}")
PYROWS
  )
  # hosts: страховка на случай выключенных триггеров — вернём из тени, если
  # строка всё ещё отсутствует (мгновенный возврат делает sm_hosts_del);
  # x-ui ещё остановлен — окно для правок; тень живёт даже при suspend
  if [[ -n "$(sqlite3 "$XUI_DB" "SELECT 1 FROM sqlite_master WHERE type='table' AND name='hosts_shadow' LIMIT 1;" 2>/dev/null)" ]]; then
    local hid haddr hsni
    while IFS='|' read -r hid haddr hsni; do
      [[ -z "$hid" || -z "$haddr" ]] && continue
      hosts_upsert "$hid" "$haddr" "$hsni"
      log "  #$hid: hosts-строка восстановлена из тени → $haddr:443"
    done < <(sqlite3 "$XUI_DB" "SELECT s.inbound_id, s.address, COALESCE(s.sni,'') FROM hosts_shadow s LEFT JOIN hosts h ON h.inbound_id=s.inbound_id AND h.port=s.port JOIN inbounds i ON i.id=s.inbound_id AND i.enable=1 AND i.port>0 WHERE s.port=443 AND h.id IS NULL;" 2>/dev/null || true)
  fi
  if [[ $cnt -gt 0 ]]; then
    systemctl start x-ui 2>/dev/null || true
    sleep 3
    # decoy-блоки и/или SNI-карта могли измениться — nginx обязан подхватить
    # конфиг, иначе его слушатели разойдутся с stack.conf (заглушки «пропадают»,
    # reality-dest смотрит в мёртвый порт).
    nginx_reload || true
    log "Серты вписаны в $cnt инбаунд(ов), x-ui запущен"
  else
    systemctl start x-ui 2>/dev/null || true
  fi
  # дедупликация: серты только в /etc/letsencrypt/live/, зеркала /root/cert нет
  cert_dedup_migrate
  db_protect_resume   # правки закончены — защита БД возвращается
  return 0
}

# --- Дедупликация сертификатов: live/ — единственное место -------------------
# Разово перепривязывает ВСЕ ссылки на зеркало /root/cert/ на
# /etc/letsencrypt/live/ (БД панели — строго при остановленном x-ui, конфиги
# nginx, yaml AdGuard) и удаляет саму папку-дубль. Идемпотентно: без ссылок
# и папки ничего не делает — безопасно звать из таймера самолечения.
cert_dedup_migrate() {
  [[ -z "$XUI_DB" || ! -f "$XUI_DB" ]] && return 0
  local refs=0
  refs=$(sqlite3 "$XUI_DB" "SELECT (SELECT COUNT(*) FROM settings WHERE value LIKE '/root/cert/%') + (SELECT COUNT(*) FROM inbounds WHERE settings LIKE '%/root/cert/%' OR stream_settings LIKE '%/root/cert/%');" 2>/dev/null || echo 0)
  if [[ "${refs:-0}" -gt 0 ]]; then
    systemctl stop x-ui 2>/dev/null || true
    python3 - "$XUI_DB" <<'PYDEDUP'
import sqlite3, sys
con = sqlite3.connect(sys.argv[1])
cur = con.cursor()
n = 0
for k, v in cur.execute("SELECT key, value FROM settings WHERE value LIKE '/root/cert/%'").fetchall():
    cur.execute("UPDATE settings SET value=? WHERE key=?", (v.replace('/root/cert/', '/etc/letsencrypt/live/'), k)); n += 1
for iid, s, st in cur.execute("SELECT id, settings, stream_settings FROM inbounds WHERE settings LIKE '%/root/cert/%' OR stream_settings LIKE '%/root/cert/%'").fetchall():
    cur.execute("UPDATE inbounds SET settings=?, stream_settings=? WHERE id=?",
                ((s or '').replace('/root/cert/', '/etc/letsencrypt/live/'),
                 (st or '').replace('/root/cert/', '/etc/letsencrypt/live/'), iid)); n += 1
con.commit()
print(f"  дедуп: в БД панели перепривязано ссылок: {n}")
PYDEDUP
    systemctl start x-ui 2>/dev/null || true
  fi
  local nf
  nf=$(grep -rl '/root/cert/' /etc/nginx/ 2>/dev/null | head -5)
  if [[ -n "$nf" ]]; then
    grep -rl '/root/cert/' /etc/nginx/ 2>/dev/null | while read -r f; do
      sed -i 's|/root/cert/|/etc/letsencrypt/live/|g' "$f" 2>/dev/null || true
      log "  дедуп: nginx-конфиг переведён на live: $(basename "$f")"
    done
    nginx -t >/dev/null 2>&1 && nginx_reload || true
  fi
  if [[ -f /opt/AdGuardHome/AdGuardHome.yaml ]] && grep -q '/root/cert/' /opt/AdGuardHome/AdGuardHome.yaml 2>/dev/null; then
    sed -i 's|/root/cert/|/etc/letsencrypt/live/|g' /opt/AdGuardHome/AdGuardHome.yaml 2>/dev/null || true
    systemctl restart AdGuardHome 2>/dev/null || systemctl restart adguardhome 2>/dev/null || true
    log "  дедуп: AdGuard переведён на live и перезапущен"
  fi
  # Не удаляем /root/cert: это может быть рабочее хранилище сертификатов,
  # созданное панелью или администратором. Перепривязка ссылок выше безопасна,
  # но уничтожение каталога при откате/самолечении недопустимо.
  if [[ -d /root/cert ]]; then
    log "  дедуп: /root/cert сохранён (удаление отключено; панельные сертификаты не трогаются)"
  fi
  return 0
}

# --- Самолечение по таймеру убрано из архитектуры ----------------------------
# Таймер stack-heal.timer больше не существует: install_heal_timer()/heal_once()
# и проверка inbounds_need_heal() удалены как мёртвый код. При установке и
# переустановке uninstall_heal_timer() дочищает остатки старых юнитов.
# Отклонения чинятся вручную (п.1/п.4).

uninstall_heal_timer() {
  systemctl disable --now stack-heal.timer 2>/dev/null || true
  rm -f /etc/systemd/system/stack-heal.service /etc/systemd/system/stack-heal.timer
  systemctl daemon-reload 2>/dev/null || true
}

# =====================================================================
