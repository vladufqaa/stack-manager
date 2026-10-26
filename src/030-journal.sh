# ПОЛНЫЙ СНИМОК СТРОКИ ПЕРЕД ИЗМЕНЕНИЕМ (для отката «ровно как было»)
#   settings копируется по значениям (panel-journal.tsv), а inbounds/hosts
#   правятся внутри JSON-полей и строк — там снимаем ВСЮ строку целиком и
#   при откате возвращаем её дословно (столбцы читаются из схемы в момент
#   восстановления, поэтому снимок не зависит от версии схемы панели).
# =====================================================================
panel_journal_capture_row() {
  # $1 = inbounds|hosts, $2 = id
  local kind="$1" id="$2" out="" rc=0
  [[ -z "$XUI_DB" || ! -f "$XUI_DB" || -z "$id" ]] && return 0
  [[ -f "$JOURNAL_MARK" ]] || return 0
  case "$kind" in inbounds|hosts) ;; *) return 0 ;; esac
  mkdir -p "$BACKUP_DIR" 2>/dev/null || return 0
  [[ -s "$ROWS_JOURNAL" ]] && grep -q "^${kind}	${id}	" "$ROWS_JOURNAL" 2>/dev/null && return 0
  local has=0
  has=$(sqlite3 -cmd ".timeout 3000" "$XUI_DB" \
        "SELECT COUNT(*) FROM $kind WHERE id=$id;" 2>/dev/null || echo 0)
  if [[ "$has" == "0" ]]; then
    printf '%s\t%s\t0\t{}\t%s\n' "$kind" "$id" "$XUI_DB" >> "$ROWS_JOURNAL" 2>/dev/null || true
    return 0
  fi
  out=$(sqlite3 -cmd ".timeout 3000" "$XUI_DB" \
        "SELECT json_object($(inbounds_json_pairs "$kind" "$id")) FROM $kind WHERE id=$id;")
  rc=$?
  if [[ $rc -ne 0 || -z "$out" ]]; then
    # молча терять снимок нельзя: без него откат не вернёт строку
    warn "journal: не удалось снять снимок строки $kind#$id (код $rc) — откат её не восстановит"
    return 1
  fi
  if ! printf '%s\t%s\t1\t%s\t%s\n' "$kind" "$id" "$out" "$XUI_DB" >> "$ROWS_JOURNAL" 2>/dev/null; then
    warn "journal: не удалось записать снимок $kind#$id"; return 1
  fi
  return 0
}

# "имя", <значение столбца как JSON> для всех столбцов таблицы.
#   json_extract(col,'$') отдаёт значение с сохранением типа (JSON остаётся
#   структурой, а не строкой); для скаляров (id/port) extra-клауза CASE просто
#   отдаёт значение как есть. ВАЖНО: путь именно '$', а не '$.имя' — столбец
#   сам является JSON-документом, а не объектом с ключом-именем столбца.
inbounds_json_pairs() {
  local kind="$1" col parts=""
  while IFS= read -r col; do
    [[ -z "$col" ]] && continue
    [[ -n "$parts" ]] && parts+=","
    parts+="'$col',(CASE WHEN json_valid(\"$col\") THEN json_extract(\"$col\",'\$') ELSE \"$col\" END)"
  done < <(sqlite3 -cmd ".timeout 3000" "$XUI_DB" "PRAGMA table_info($kind);" 2>/dev/null | awk -F'|' '{print $2}')
  [[ -z "$parts" ]] && { printf "'' , NULL"; return 0; }
  printf '%s' "$parts"
}

# Обновление строки inbounds с автоматическим снимком для отката

# Сменить listen инбаунда напрямую в БД, при mode=journal — с записью прежнего
# значения в LISTEN_JOURNAL (формат читателя panel_journal_apply:
# id<TAB>значение_для_отката<TAB>db, спецзначения __NULL__/__EMPTY__).
#   $1 = id, $2 = новое значение ('' | 127.0.0.1 | 0.0.0.0 | что угодно),
#   $3 = journal|direct (по умолчанию journal)
# Первое изменение для id — приоритетное: откат возвращает исходный listen,
# а не промежуточный. Восстановлено самодостаточно: в v1.0.15 функцию удалили
# вместе со старыми journal-хелперами, а вызовы (cdn-профиль, полный откат)
# остались — слушатель молча не переключался, «command not found» гасился || true.
db_set_listen() {
  local id="$1" want="$2" mode="${3:-journal}"
  [[ -z "$XUI_DB" || ! -f "$XUI_DB" || -z "$id" ]] && return 1
  # Значение не ограничиваем списком: в поле может лежать что угодно (в т.ч.
  # вписанное руками), и откат обязан вернуть именно его. Требование одно —
  # без кавычек и переводов строк, иначе ломается SQL-литерал.
  if [[ "$want" == *"'"* || "$want" == *$'\n'* ]]; then
    err "db_set_listen: значение listen содержит кавычку/перевод строки — запись невозможна"
    return 1
  fi
  if [[ "$mode" == "journal" ]]; then
    panel_journal_capture_row inbounds "$id" 2>/dev/null || true
    if ! awk -F'\t' -v i="$id" '$1==i{f=1} END{exit !f}' "$LISTEN_JOURNAL" 2>/dev/null; then
      local old enc
      old=$(sqlite3 -cmd ".timeout 3000" "$XUI_DB" \
            "SELECT CASE WHEN listen IS NULL THEN '__NULL__' WHEN listen='' THEN '__EMPTY__' ELSE listen END FROM inbounds WHERE id=$id;" 2>/dev/null || true)
      enc="${old:-__EMPTY__}"
      mkdir -p "$BACKUP_DIR" 2>/dev/null || true
      printf '%s\t%s\t%s\n' "$id" "$enc" "$XUI_DB" >> "$LISTEN_JOURNAL" 2>/dev/null || true
    fi
  fi
  local sq; sq=$(sql_escape "$want")
  sqlite3 -cmd ".timeout 3000" "$XUI_DB" \
    "UPDATE inbounds SET listen='$sq' WHERE id=$id AND COALESCE(listen,'') <> '$sq';" 2>/dev/null || true
  return 0
}

# Строка hosts/восстановление всей строки — та же логика для таблицы hosts



# Применить журнал в обратном порядке: вернуть старые значения.
# $1 = 1 — тихо (журнал отката, без интерактива)
panel_journal_apply() {
  local quiet="${1:-0}" n_set=0 n_listen=0 n_rows=0 skipped=0
  local key val db id set_clause
  if [[ -s "$PANEL_JOURNAL" ]]; then
    db_protect_off
    while IFS=$'\t' read -r _kind key val db; do
      [[ -z "$key" || -z "$db" || ! -f "$db" ]] && { skipped=$((skipped+1)); continue; }
      case "$val" in
        __NULL__)
          "$DB_BIN" "$db" "DELETE FROM settings WHERE key='$key';" >/dev/null 2>&1 \
            && n_set=$((n_set+1)) || skipped=$((skipped+1)) ;;
        *)
          local sq=""
          if [[ "$val" == "__EMPTY__" ]]; then sq=""; else sq=$(sql_escape "$val"); fi
          "$DB_BIN" "$db" "UPDATE settings SET value='$sq' WHERE key='$key';" >/dev/null 2>&1 \
            && n_set=$((n_set+1)) || skipped=$((skipped+1)) ;;
      esac
    done < "$PANEL_JOURNAL"
  fi
  if [[ -s "$ROWS_JOURNAL" ]]; then
    db_protect_off
    local rf="" rsql=""
    rf=$(mktemp /tmp/stack-rows.XXXXXX 2>/dev/null || true)
    if [[ -n "$rf" ]]; then
      rsql="$rf.sql"
      # Готовим SQL по снимкам строк. Пишем во ФАЙЛ явным utf-8: через
      # sys.stdout нельзя — скрипт выставляет LC_ALL=C, и кириллица в значениях
      # роняет python с UnicodeEncodeError (откат при этом молча ничего не делал).
      # Значения экранируются как JSON-строки, поэтому возврат дословный.
      command -v python3 >/dev/null 2>&1 && python3 - "$ROWS_JOURNAL" "$rsql" >/dev/null 2>"$rf.err" <<'PYROWS'
import json, os, sqlite3, sys

path, outpath = sys.argv[1], sys.argv[2]

def lit(v):
    # В SQL-литерал строку отдаём В ОДИНАРНЫХ кавычках: json.dumps даёт двойные,
    # а SQLite считает "..." идентификатором и падает «unrecognized token».
    # Одинарные кавычки внутри значения удваиваем — так требует SQL.
    if v is None:
        return "NULL"
    if isinstance(v, bool):
        return "1" if v else "0"
    if isinstance(v, (int, float)):
        return json.dumps(v)
    if isinstance(v, (dict, list)):
        # json.loads разобрал JSON-колонку в объект — назад в JSON, а НЕ через
        # str(): str(dict) даёт одинарные кавычки и пишет в БД мусор вместо JSON
        return "'" + json.dumps(v, ensure_ascii=False).replace("'", "''") + "'"
    return "'" + str(v).replace("'", "''") + "'"

stmts = []
with open(path, encoding="utf-8", errors="replace") as fh:
    lines = [l.rstrip("\n") for l in fh if l.strip()]
# обратный порядок: последняя зафиксированная строка восстанавливается первой
for ln in reversed(lines):
    parts = ln.split("\t")
    if len(parts) < 4:
        continue
    kind, rid, existed, js = parts[0], parts[1], parts[2], parts[3]
    db = parts[4] if len(parts) > 4 else ""
    # Инбаунды никогда не откатываем и не удаляем: они должны остаться.
    if kind not in ("hosts",) or not db or not os.path.exists(db):
        continue
    try:
        data = json.loads(js) if js else {}
    except Exception:
        data = {}
    if existed != "1" or not data:
        stmts.append("DELETE FROM %s WHERE id=%s;" % (kind, rid))
        continue
    try:
        con = sqlite3.connect(db, timeout=10)
        cols = [r[1] for r in con.execute("PRAGMA table_info(%s)" % kind).fetchall()]
        con.close()
    except Exception:
        continue
    use = [c for c in cols if c in data]
    if not use:
        continue
    col_sql = ",".join('"%s"' % c.replace('"', '""') for c in use)
    vals = ",".join(lit(data[c]) for c in use)
    stmts.append("INSERT OR REPLACE INTO %s (%s) VALUES (%s);" % (kind, col_sql, vals))
with open(outpath, "w", encoding="utf-8", errors="replace") as fo:
    fo.write("\n".join(stmts) + ("\n" if stmts else ""))
PYROWS
      if [[ -s "$rsql" ]]; then
        # один вызов sqlite3 на все строки: быстрее и не теряет ошибки по одной
        if sqlite3 -cmd ".timeout 3000" "$XUI_DB" < "$rsql" >/dev/null 2>&1; then
          n_rows=$(grep -c . "$rsql" 2>/dev/null || echo 0)
        else
          warn "journal: SQL восстановления строк не выполнился целиком (см. вывод sqlite3 вручную)"
          skipped=$((skipped+1))
        fi
      elif [[ -s "$rf.err" ]]; then
        # молчать нельзя: это ровно тот случай, когда откат «прошёл», а строки не вернулись
        warn "journal: не удалось подготовить восстановление строк inbounds/hosts:"
        head -3 "$rf.err" 2>/dev/null | sed 's/^/    /'
        skipped=$((skipped+1))
      fi
      rm -f "$rf" "$rsql" "$rf.err" 2>/dev/null || true
    fi
  fi
  if [[ -s "$LISTEN_JOURNAL" ]]; then
    db_protect_off
    while IFS=$'\t' read -r id val db; do
      [[ -z "$id" || -z "$db" || ! -f "$db" ]] && { skipped=$((skipped+1)); continue; }
      case "$val" in
        __NULL__)  set_clause="listen=NULL" ;;
        __EMPTY__) set_clause="listen=''" ;;
        *)         set_clause="listen='$(sql_escape "$val")'" ;;
      esac
      "$DB_BIN" "$db" "UPDATE inbounds SET $set_clause WHERE id=$id;" >/dev/null 2>&1 \
        && n_listen=$((n_listen+1)) || skipped=$((skipped+1))
    done < "$LISTEN_JOURNAL"
    unset set_clause
  fi
  if [[ "$quiet" != "1" ]]; then
    log "Журнал отката: настроек панели восстановлено $n_set, listen инбаундов $n_listen, строк inbounds/hosts $n_rows${skipped:+, пропущено: $skipped}"
  fi
  [[ "$n_set" -gt 0 || "$n_listen" -gt 0 || "$n_rows" -gt 0 || "$skipped" -gt 0 ]]
}

panel_journal_clear() {
  rm -f "$PANEL_JOURNAL" "$LISTEN_JOURNAL" "$ROWS_JOURNAL" "$JOURNAL_MARK" 2>/dev/null || true
}

# Панель держит состояние в памяти — настройки пишем только при остановленной
# панели, иначе при рестарте панель перетрёт правку своим состоянием.
stop_xui_for_edit() {
  if systemctl is-active --quiet x-ui 2>/dev/null; then
    systemctl stop x-ui >/dev/null 2>&1 || true
    sleep 1
  fi
}

proto_remark() {
  local proto="$1" stream="${2:-}"
  case "$proto" in
    vless) grep -q '"security": *"reality"' <<<"$stream" && echo "reality" || echo "vless" ;;
    trusttunnel|trust-tunnel) echo "trusttunnel" ;;
    naive|naiveproxy) echo "naive" ;;
    mtproto) echo "mtproto" ;;
    hysteria|hysteria2) echo "hysteria2" ;;
    qwdtt) echo "qwdtt" ;;
    csqtt|csqdtt) echo "csqtt" ;;
    tproxy) echo "webproxy" ;;
    awg|amneziawg|wireguard) echo "awg" ;;
    *) echo "$proto" ;;
  esac
}

# Название инбаунда для remark. Страна определяется один раз по внешнему IPv4
# сервера и кэшируется: это не зависит от SNI/домена и не требует ручного ввода.
# Пример: «🇩🇪 VLESS TCP Reality», «🇩🇪 Naive», «🇩🇪 VLESS TCP Reality №2».
SERVER_COUNTRY_CACHE="/root/stack-backups/server-country-code"
server_country_code() {
  local cc=""
  if [[ -s "$SERVER_COUNTRY_CACHE" ]]; then
    cc=$(tr -d '[:space:]' < "$SERVER_COUNTRY_CACHE" 2>/dev/null || true)
  fi
  if [[ ! "$cc" =~ ^[A-Z]{2}$ ]]; then
    cc=$(curl -4 -fsS --connect-timeout 3 --max-time 6 https://ipapi.co/country/ 2>/dev/null | tr -d '[:space:]' | tr '[:lower:]' '[:upper:]' || true)
    [[ "$cc" =~ ^[A-Z]{2}$ ]] && { mkdir -p "$(dirname "$SERVER_COUNTRY_CACHE")" 2>/dev/null || true; printf '%s\n' "$cc" > "$SERVER_COUNTRY_CACHE" 2>/dev/null || true; }
  fi
  printf '%s' "$cc"
}
country_flag() {
  # Флаг хранится в remark как настоящий Unicode emoji (две regional
  # indicator-буквы), а не как текстовая замена [SE]. Печатаем его через
  # Python, чтобы не зависеть от особенностей printf/локали Bash.
  local cc="${1^^}"
  [[ "$cc" =~ ^[A-Z]{2}$ ]] || return 0
  python3 - "$cc" <<'PYFLAG'
import sys
cc = sys.argv[1].upper()
if len(cc) == 2 and cc.isascii() and cc.isalpha():
    print(''.join(chr(127397 + ord(c)) for c in cc), end='')
PYFLAG
}
inbound_remark_base() {
  local proto="$1" transport="$2" security="$3" label=""
  case "$proto:$transport:$security" in
    vless:tcp:reality) label="VLESS TCP Reality" ;;
    vless:tcp:tls)     label="VLESS TCP TLS" ;;
    vless:xhttp:reality) label="VLESS XHTTP Reality" ;;
    vless:xhttp:tls)   label="VLESS XHTTP TLS" ;;
    vless:xhttp:*)     label="VLESS XHTTP" ;;
    vless:*)           label="VLESS" ;;
    naive:* )          label="Naive" ;;
    trusttunnel:*|trust-tunnel:*) label="TrustTunnel" ;;
    anytls:*)          label="AnyTLS" ;;
    trojan:*)          label="Trojan" ;;
    shadowsocks:*)     label="Shadowsocks" ;;
    hysteria:*|hysteria2:*) label="Hysteria2" ;;
    qwdtt:*)           label="QWDT" ;;
    csqtt:*)           label="CSQTT" ;;
    tproxy:*)          label="TG Web Proxy" ;;
    *)                 label="${proto^}" ;;
  esac
  printf '%s' "$label"
}
# Добавляет флаг страны к уже созданным стандартным именам инбаундов.
# Нужен для миграции: старые записи могли быть созданы, когда geo-API был
# временно недоступен, поэтому у них remark остался без флага.
backfill_country_remarks() {
  [[ -z "$XUI_DB" || ! -f "$XUI_DB" ]] && return 0
  local cc flag id proto stream remark transport security base new suffix
  cc=$(server_country_code)
  flag=$(country_flag "$cc")
  [[ -n "$flag" ]] || return 0
  while IFS='|' read -r id proto stream remark; do
    [[ -n "$id" && -n "$remark" && "$remark" != "$flag"* ]] || continue
    transport=$(grep -oE '"network"[[:space:]]*:[[:space:]]*"[^"]+' <<<"$stream" | head -1 | sed 's/.*"//')
    security=$(grep -oE '"security"[[:space:]]*:[[:space:]]*"[^"]+' <<<"$stream" | head -1 | sed 's/.*"//')
    [[ -n "$transport" ]] || transport="tcp"
    [[ -n "$security" ]] || security="none"
    base=$(inbound_remark_base "$proto" "$transport" "$security")
    if [[ "$remark" == "$base" ]]; then
      new="$flag $remark"
    elif [[ "$remark" =~ ^${base//\/\\}[^0-9]*№[0-9]+$ ]]; then
      suffix="${remark#"$base"}"
      new="$flag $base$suffix"
    elif [[ "$remark" == *"$base"* ]]; then
      # В старых версиях emoji-флаг мог сохраниться как «����».
      # Восстанавливаем имя по протоколу и оставляем возможный №N.
      suffix="${remark#*"$base"}"
      new="$flag $base$suffix"
    else
      continue
    fi
    sqlite3 "$XUI_DB" "UPDATE inbounds SET remark='$(sql_escape "$new")' WHERE id=$id;" 2>/dev/null || true
  done < <(sqlite3 -separator '|' "$XUI_DB" "SELECT id,protocol,COALESCE(stream_settings,''),COALESCE(remark,'') FROM inbounds WHERE enable=1;" 2>/dev/null || true)
}

# Возвращает remark с порядковым номером только при повторе того же типа.
inbound_remark_next() {
  local proto="$1" transport="$2" security="$3" base flag prefix n=1 max=0 r suffix
  base=$(inbound_remark_base "$proto" "$transport" "$security")
  flag=$(country_flag "$(server_country_code)")
  prefix="${flag:+$flag }$base"
  while IFS= read -r r; do
    [[ "$r" == "$prefix" ]] && (( max < 1 )) && max=1
    local re="^${prefix//\/\\} №([0-9]+)$"
    if [[ "$r" =~ $re ]]; then
      n="${BASH_REMATCH[1]}"; (( n > max )) && max=$n
    fi
  done < <(sqlite3 "$XUI_DB" "SELECT COALESCE(remark,'') FROM inbounds WHERE remark IS NOT NULL;" 2>/dev/null || true)
  (( max > 0 )) && printf '%s №%d' "$prefix" "$((max+1))" || printf '%s' "$prefix"
}

# IP сервера (IPv4) — для subHost у tunnel-протоколов
server_ip4() {
  local ip=""
  ip=$(curl -4 -s --connect-timeout 4 --max-time 8 ifconfig.me 2>/dev/null | tr -d '[:space:]')
  [[ -z "$ip" ]] && ip=$(hostname -I 2>/dev/null | awk '{print $1}')
  echo "$ip"
}

# Триггеры синхронизации клиентов qwdtt/csqtt/tproxy (как в lucx-ui-pro):
# клиенты хранятся в clients+client_inbounds, а inbounds.settings[].clients зеркалится
ensure_shareonly_triggers() {
  [[ -z "$XUI_DB" || ! -f "$XUI_DB" ]] && return 0
  sqlite3 "$XUI_DB" <<'SQL' 2>/dev/null || true
UPDATE inbounds
SET settings = json_set(
  CASE WHEN json_valid(settings) THEN settings ELSE '{}' END,
  '$.clients',
  CASE WHEN json_type(json_extract(settings, '$.clients')) = 'array'
       THEN json_extract(settings, '$.clients')
       ELSE json('[]') END
)
WHERE protocol IN ('qwdtt','csqtt','tproxy');
DROP TRIGGER IF EXISTS lucx_shareonly_clients_ins;
DROP TRIGGER IF EXISTS lucx_shareonly_clients_del;
CREATE TRIGGER lucx_shareonly_clients_ins
AFTER INSERT ON client_inbounds
WHEN EXISTS (SELECT 1 FROM inbounds WHERE id = NEW.inbound_id AND protocol IN ('qwdtt','csqtt','tproxy'))
BEGIN
  UPDATE inbounds SET settings = json_insert(
    json_set(
      settings,
      '$.clients',
      CASE WHEN json_type(json_extract(settings, '$.clients')) = 'array'
           THEN json_extract(settings, '$.clients')
           ELSE json('[]') END
    ),
    '$.clients[#]',
    json_object(
      'email', COALESCE((SELECT email FROM clients WHERE id = NEW.client_id), ''),
      'enable', json('true')
    )
  )
  WHERE id = NEW.inbound_id
    AND COALESCE((SELECT email FROM clients WHERE id = NEW.client_id), '') != ''
    AND NOT EXISTS (
      SELECT 1 FROM json_each(
        CASE WHEN json_type(json_extract(inbounds.settings, '$.clients')) = 'array'
             THEN json_extract(inbounds.settings, '$.clients')
             ELSE json('[]') END
      )
      WHERE json_extract(value, '$.email') = (SELECT email FROM clients WHERE id = NEW.client_id)
    );
END;
CREATE TRIGGER lucx_shareonly_clients_del
AFTER DELETE ON client_inbounds
WHEN EXISTS (SELECT 1 FROM inbounds WHERE id = OLD.inbound_id AND protocol IN ('qwdtt','csqtt','tproxy'))
BEGIN
  UPDATE inbounds SET settings = json_set(
    settings,
    '$.clients',
    (
      SELECT json_group_array(json(value))
      FROM json_each(
        CASE WHEN json_type(json_extract(inbounds.settings, '$.clients')) = 'array'
             THEN json_extract(inbounds.settings, '$.clients')
             ELSE json('[]') END
      )
      WHERE json_extract(value, '$.email') != (SELECT email FROM clients WHERE id = OLD.client_id)
         OR (SELECT email FROM clients WHERE id = OLD.client_id) IS NULL
    )
  )
  WHERE id = OLD.inbound_id;
END;
SQL
}

# Камуфляж-сайт для tproxy: НЕЙТРАЛЬНАЯ заглушка (blog), НЕ связанная с Telegram —
# мимикрия под Telegram на tg-домене = прямая подсказка, что за ним tg-прокси.
ensure_tproxy_site() {
  mkdir -p /var/www/html 2>/dev/null || true
  rm -f /var/www/html/telegram.html 2>/dev/null || true   # след прошлой версии
  # перезаписываем ВСЕГДА: пустышка/старый index = белый лист для посторонних
  if [[ -n "$DECOY_TPL_DIR" && -f "$DECOY_TPL_DIR/blog.html" ]]; then
    cp -f "$DECOY_TPL_DIR/blog.html" /var/www/html/index.html 2>/dev/null || true
  elif [[ ! -s /var/www/html/index.html ]]; then
    printf '%s\n' \
      '<!DOCTYPE html><html><head><meta charset="utf-8"><title></title></head><body></body></html>' \
      > /var/www/html/index.html
  fi
  chmod 644 /var/www/html/index.html 2>/dev/null || true
}

# открыть UDP-порты в UFW, если он активен
ufwd_allow_udp() {
  command -v ufw >/dev/null 2>&1 || return 0
  ufw status 2>/dev/null | grep -q "Status: active" || return 0
  local p
  for p in "$@"; do ufw allow "$p/udp" >/dev/null 2>&1 || true; done
}

# =====================================================================
