# САМОДИАГНОСТИКА (read-only health check): сервисы, порты, SNI, серты,
# UFW, DNS. НИЧЕГО не меняет — только показывает проблемы и подсказки.
# =====================================================================
stack_doctor() {
  line; echo -e "${B}   САМОДИАГНОСТИКА СТЕКА${N}"; line
  local problems=0
  ok()   { echo -e "  ${G}[✓]${N} $*"; }
  bad()  { echo -e "  ${R}[x]${N} $*"; problems=$((problems+1)); }
  warn2(){ echo -e "  ${Y}[!]${N} $*"; }
  hint() { echo -e "      ${Y}→${N} $*"; }

  echo -e "${B}— Сервисы —${N}"
  local s
  for s in nginx x-ui; do
    if systemctl is-active --quiet "$s" 2>/dev/null; then ok "$s: активен"; else bad "$s: НЕ активен"; hint "systemctl restart $s"; fi
  done
  if [[ "$ADG_PRESENT" == true && -n "$ADG_SERVICE" ]]; then
    if systemctl is-active --quiet "$ADG_SERVICE" 2>/dev/null; then ok "AdGuard ($ADG_SERVICE): активен"; else bad "AdGuard: НЕ активен"; hint "systemctl restart $ADG_SERVICE"; fi
  else
    warn2 "AdGuard не установлен (необязательно)"
  fi

  echo -e "${B}— Слушающие порты —${N}"
  if ss -tlnH "sport = :443" 2>/dev/null | grep -q .; then ok "443/tcp слушает nginx"; else bad "443/tcp НЕ слушается"; hint "п.1 пересборка стека / systemctl restart nginx"; fi
  if ss -tlnH "sport = :80" 2>/dev/null | grep -q .; then ok "80/tcp слушается (ACME webroot)"; else warn2 "80/tcp не слушается — HTTP-01 выпуска не будет (wildcard DNS-01 не страдает)"; fi
  local wp sp wl sl
  wp=$(xui_get webPort); sp=$(xui_get subPort); wl=$(xui_get webListen); sl=$(xui_get subListen)
  if [[ "$wl" == "127.0.0.1" ]]; then ok "панель слушает 127.0.0.1:$wp (наружу не торчит)"; else bad "панель слушает ${wl:-?}:$wp — доктрина 443 нарушена"; hint "п.1 (запишет 127.0.0.1)"; fi
  if [[ "$sl" == "127.0.0.1" || -z "$sl" ]]; then ok "подписки слушают 127.0.0.1:$sp"; else bad "подписки слушают ${sl:-?}:$sp — наружу торчат"; fi
  # инбаунды: TCP должен слушать 127.0.0.1 (tproxy — 0.0.0.0)
  local iid iproto ilisten iport isec idest
  while IFS='|' read -r iid iproto iport ilisten isec idest; do
    [[ -z "$iid" ]] && continue
    if [[ "$iproto" == "tproxy" ]]; then
      [[ "$ilisten" == "0.0.0.0" || "$ilisten" == "::" ]] && ok "#$iid tproxy на 0.0.0.0:$iport" || warn2 "#$iid tproxy слушает $ilisten — маршруту tg нужен 0.0.0.0"
      continue
    fi
    if is_udp_proto "$iproto"; then continue; fi   # UDP наружу напрямую — не проверяем
    if [[ "$ilisten" != "127.0.0.1" && "$ilisten" != "" ]]; then
      bad "#$iid ($iproto:$iport) слушает $ilisten — должен 127.0.0.1 (за 443)"
      hint "п.4 → Починить инбаунд #$iid"
    fi
  done < <(sqlite3 -cmd ".timeout 3000" "$XUI_DB" \
    "SELECT id, protocol, port, COALESCE(listen,''), COALESCE(json_extract(stream_settings,'\$.security'),''), COALESCE(json_extract(stream_settings,'\$.realitySettings.dest'),'') FROM inbounds WHERE enable=1;" 2>/dev/null || true)

  echo -e "${B}— SNI-маршрут —${N}"
  if [[ -f "$SNI_CONF" ]]; then
    ok "$SNI_CONF на месте ($(grep -c 'upstream ' "$SNI_CONF" 2>/dev/null || echo 0) upstream-ов)"
    grep -qE "panel_backend;" "$SNI_CONF" 2>/dev/null && ok "домен панели замаплен (panel_backend)" || bad "panel_backend не найден в $SNI_CONF"
  else
    bad "$SNI_CONF не найден"; hint "п.1 — первичная настройка"
  fi
  if nginx -t >/dev/null 2>&1; then ok "nginx -t: конфиг валиден"; else bad "nginx -t провален:"; nginx -t 2>&1 | tail -3 | sed 's/^/      /'; fi

  echo -e "${B}— Сертификаты (истекают < 14 дн — [!]) —${N}"
  local ldir crt end_left
  ldir="/etc/letsencrypt/live"
  if [[ -d "$ldir" ]] && ls -1 "$ldir" 2>/dev/null | grep -q .; then
    local d
    for d in "$ldir"/*/; do
      d=$(basename "$d"); crt="$ldir/$d/fullchain.pem"
      [[ -f "$crt" ]] || { warn2 "$d: fullchain.pem нет"; continue; }
      end_left=$(( ($(date -d "$(openssl x509 -enddate -noout -in "$crt" 2>/dev/null | cut -d= -f2)" +%s 2>/dev/null || echo 0) - $(date +%s)) / 86400 ))
      if [[ "$end_left" -ge 14 ]]; then ok "$d: ~${end_left} дн"; elif [[ "$end_left" -ge 0 ]]; then warn2 "$d: истекает через ~${end_left} дн"; hint "п.10 → обновить"; else bad "$d: ПРОСРОЧЕН"; hint "п.10 → обновить"; fi
    done
  else
    warn2 "сертов в /etc/letsencrypt/live нет"
  fi

  echo -e "${B}— UFW —${N}"
  if ufw_is_active; then
    ok "UFW активен"
    ufw status 2>/dev/null | grep -qE "443/tcp\s+ALLOW" && ok "443/tcp разрешён" || bad "443/tcp НЕ разрешён"; hint "п.11"
    ufw status 2>/dev/null | grep -qE "${SSH_PORT:-22}/tcp\s+ALLOW" && ok "SSH (${SSH_PORT:-22}/tcp) разрешён" || warn2 "SSH-порт не помечен ALLOW — проверь, как подключаешься"
    local extra
    extra=$(ufw status 2>/dev/null | grep -E "ALLOW" | grep -E "/tcp" | grep -vE "443/tcp|${SSH_PORT:-22}/tcp" | head -5)
    [[ -n "$extra" ]] && { warn2 "лишние TCP-разрешения:"; echo "$extra" | sed 's/^/        /'; hint "п.11 → сброс (только SSH+443+UDP)"; }
  else
    bad "UFW не активен (или бинарь не найден — проверь: systemctl is-active ufw)"; hint "п.11"
  fi

  echo -e "${B}— fail2ban —${N}"
  if systemctl is-active --quiet fail2ban 2>/dev/null; then
    ok "fail2ban активен"
    fail2ban-client status decoy-login >/dev/null 2>&1 && ok "jail decoy-login работает" || bad "jail decoy-login НЕ работает"; hint "п.1/п.7"
    fail2ban-client status recidive >/dev/null 2>&1 && ok "jail recidive работает (рецидивисты — бан на неделю)" || warn2 "recidive выключен (п.7 → вкл.)"
  else
    bad "fail2ban НЕ активен"; hint "systemctl restart fail2ban"
  fi

  echo -e "${B}— Decoy-страницы (что реально отвечает nginx) —${N}"
  if [[ -f "$STACK_CONF" ]] && grep -q "^# >>> decoy " "$STACK_CONF" 2>/dev/null; then
    local mline mport mdom mroot code body_md5 idx_md5 n_ok=0 n_bad=0
    while IFS= read -r mline; do
      mport=$(grep -oE 'port=[0-9]+'  <<<"$mline" | head -1 | cut -d= -f2)
      mdom=$(grep  -oE 'domain=[^ ]+$' <<<"$mline" | head -1 | cut -d= -f2-)
      mroot=$(grep -oE 'root=[^ ]+'   <<<"$mline" | head -1 | cut -d= -f2-)
      [[ -z "$mdom" || -z "$mport" ]] && continue
      # UA — браузерный: decoy с ua404=1 отдаёт curl'у 404, доктор должен видеть
      # страницу глазами «человека»
      code=$(curl -sk --max-time 5 -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124 Safari/537.36" -o /tmp/.decoy_body -w '%{http_code}' -H "Host: $mdom" "https://127.0.0.1:$mport/" 2>/dev/null || echo 000)
      if [[ "$code" == "200" || "$code" == "302" || "$code" == "401" ]]; then
        if [[ "$code" == "200" && -f "$mroot/index.html" ]]; then
          body_md5=$(md5sum /tmp/.decoy_body 2>/dev/null | awk '{print $1}')
          idx_md5=$(md5sum "$mroot/index.html" 2>/dev/null | awk '{print $1}')
          if [[ "$body_md5" == "$idx_md5" ]]; then ok "$mdom (:$mport): 200, контент = шаблон"; n_ok=$((n_ok+1))
          else bad "$mdom (:$mport): 200, но контент НЕ совпадает с $mroot/index.html"; n_bad=$((n_bad+1)); fi
        else
          ok "$mdom (:$mport): HTTP $code (ожидаемо для redirect/locked)"; n_ok=$((n_ok+1))
        fi
      else
        bad "$mdom (:$mport): ответ $code — decoy НЕ отвечает"; hint "п.4/пересборка decoy, systemctl restart nginx"; n_bad=$((n_bad+1))
      fi
    done < <(grep "^# >>> decoy " "$STACK_CONF")
    rm -f /tmp/.decoy_body 2>/dev/null || true
    [[ "$n_bad" -gt 0 ]] && problems=$((problems+n_bad))
    [[ "$n_ok" -eq 0 && "$n_bad" -eq 0 ]] && warn2 "decoy-блоки не распарсились"
  else
    warn2 "decoy-блоков в stack.conf нет"
  fi

  echo -e "${B}— Порты инбаундов (быстро; подробно — п.19) —${N}"
  if [[ -n "$XUI_DB" && -f "$XUI_DB" ]]; then
    local dead
    dead=$(python3 - "$XUI_DB" <<'PYPORTS' 2>/dev/null
import sqlite3, json, sys, subprocess, re
UDP_PROTOS={"hysteria","hysteria2","qwdtt","csqtt","tuic","wireguard","amnezia","amneziawg","awg"}
try:
    con=sqlite3.connect(f"file:{sys.argv[1]}?mode=ro",uri=True,timeout=5)
    rows=con.execute("SELECT id,protocol,port,COALESCE(listen,''),settings,stream_settings FROM inbounds WHERE enable=1").fetchall()
except Exception: sys.exit(0)
def listening(net,p):
    if net=="tcp":
        out=subprocess.run(["ss","-tln"],capture_output=True,text=True,timeout=5).stdout
        return bool(re.search(rf":{p}(\s|$)",out))
    out=subprocess.run(["ss","-ulan"],capture_output=True,text=True,timeout=5).stdout
    if re.search(rf":{p}(\s|$)",out): return True
    return False
for iid,proto,port,listen,s1,s2 in rows:
    try: se=json.loads(s1 or "{}")
    except Exception: se={}
    try: st=json.loads(s2 or "{}")
    except Exception: st={}
    try: p=int(se.get("port") or port or 0)
    except Exception: p=int(port or 0)
    if p<=0: continue
    net="udp" if proto.lower() in UDP_PROTOS else (st.get("network") or "tcp")
    # xhttp/ws/grpc/httpupgrade — TCP-транспорты: наружу проверяем как tcp,
    # иначе «не слушается» на живом инбаунде (панель при этом права)
    if net!="udp": net="tcp"
    if not listening(net,p): print(f"#{iid} {proto} {p}/{net}")
PYPORTS
)
    if [[ -z "$dead" ]]; then
      ok "все включённые инбаунды слушают свои порты"
    else
      local dl
      while IFS= read -r dl; do [[ -z "$dl" ]] && continue; bad "не слушается: $dl"; done <<<"$dead"
      hint "systemctl restart x-ui; если не помогло — п.19/логи xray"
    fi
  fi

  echo -e "${B}— Ресурсы —${N}"
  local duse
  duse=$(df -Pm / 2>/dev/null | awk 'NR==2{print $5}' | tr -d '%')
  if [[ -n "$duse" ]]; then
    if (( duse >= 90 )); then bad "диск: занято ${duse}% — критично"; hint "почистить /root/stack-backups, /var/log"
    elif (( duse >= 80 )); then warn2 "диск: занято ${duse}%"; else ok "диск: занято ${duse}%"; fi
  fi
  if [[ -n "$XUI_DB" && -f "$XUI_DB" ]]; then
    local dbsize nbak nauto nman fresh
    dbsize=$(du -h "$XUI_DB" 2>/dev/null | awk '{print $1}')
    nauto=$(ls -1dt "$BACKUP_DIR"/auto-* 2>/dev/null | wc -l)              # автобэкап (старт скрипта)
    nman=$(ls -1 "$BACKUP_DIR"/stack-backup-*.tar.gz 2>/dev/null | wc -l)
    local nself npre
    nself=$(ls -1d "$BACKUP_DIR"/self-update-* 2>/dev/null | wc -l)
    npre=$(ls -1d "$BACKUP_DIR"/pre-install-* 2>/dev/null | grep -v '\.tar\.gz$' | wc -l)
    nbak=$((nauto + nman + nself + npre))
    fresh=$(ls -1dt "$BACKUP_DIR"/auto-* "$BACKUP_DIR"/stack-backup-*.tar.gz "$BACKUP_DIR"/self-update-* "$BACKUP_DIR"/pre-install-* 2>/dev/null | head -1 | xargs -r basename)
    ok "x-ui.db: ${dbsize:-?} · бэкапов: $nbak (авто:$nauto/ручные:$nman/self-update:$nself/pre-install:$npre; свежий: $fresh)"
    (( nbak == 0 )) && warn2 "резервных копий нет — раздел 5 → Бэкапы и откат"
  fi
  if [[ -f /var/run/reboot-required ]]; then
    bad "система ждёт ПЕРЕЗАГРУЗКУ (обновлено ядро/библиотеки)"
    hint "reboot в удобное окно: стек поднимется сам (nginx/x-ui/AdGuard/fail2ban — systemd)"
  fi

  echo -e "${B}— DNS / домены стека —${N}"
  local srv_ip
  srv_ip=$(server_ip4)
  local doms pd
  pd="${PANEL_DOMAIN:-$(xui_get webDomain 2>/dev/null || true)}"
  doms=$(python3 - "$XUI_DB" "${REALITY_TARGETS[@]}" <<'PYDOMS' 2>/dev/null
import sqlite3, json, sys
skip=set(a.lower() for a in sys.argv[2:])
seen=set(); out=[]
def add(d):
    d=(d or "").strip().lower()
    if d and d not in skip and d not in seen:
        seen.add(d); out.append(d)
try:
    con=sqlite3.connect(f"file:{sys.argv[1]}?mode=ro",uri=True,timeout=5)
    for setts_s,stream_s in con.execute("SELECT settings,stream_settings FROM inbounds WHERE enable=1 AND port>0"):
        try: se=json.loads(setts_s or "{}")
        except Exception: se={}
        try: st=json.loads(stream_s or "{}")
        except Exception: st={}
        rs=st.get("realitySettings") or {}
        add(se.get("domain")); add(se.get("hostname")); add(se.get("sni"))
        add((st.get("tlsSettings") or {}).get("serverName"))
        add((rs.get("serverNames") or [None])[0])   # чужие цели отсеет skip-список
except Exception:
    pass
print("\n".join(out))
PYDOMS
)
  [[ -n "$pd" ]] && doms="$pd"$'\n'"$doms"
  local d a_ip
  while IFS= read -r d; do
    [[ -z "$d" ]] && continue
    a_ip=$(dig +short A "$d" @1.1.1.1 2>/dev/null | tail -1)
    [[ -z "$a_ip" ]] && a_ip=$(dig +short A "$d" @8.8.8.8 2>/dev/null | tail -1)
    local aaaa_ip
    aaaa_ip=$(dig +short AAAA "$d" @1.1.1.1 2>/dev/null | tail -1)
    if [[ -n "$a_ip" && "$a_ip" == "$srv_ip" ]]; then
      [[ -n "$aaaa_ip" ]] && ok "$d → A $a_ip ✓; AAAA $aaaa_ip (dual-stack)" || ok "$d → A $a_ip ✓"
    elif [[ -z "$a_ip" ]]; then warn2 "$d: A-запись не резолвится"
    else warn2 "$d → $a_ip, а сервер: $srv_ip"; fi
  done <<<"$doms"

  echo
  line
  if [[ "$problems" -eq 0 ]]; then
    echo -e "${G}  Итог: проблем не найдено ✓${N}"
  else
    echo -e "${R}  Итог: проблем — $problems${N} (подсказки [→] выше)"
  fi
  line
  (( problems > 0 )) && return 1
  return 0
}

# Единый read-only аудит для CI/ручной проверки. Не меняет БД, nginx и сервисы.

# Наблюдение за стеком: одиночный прогон или обновление каждые 10 сек
stack_doctor_menu() {
  stack_doctor
  local wm=""
  askyn wm "Наблюдать непрерывно (обновление каждые 10 сек, любая клавиша — выход)?" "n"
  [[ "$wm" == true ]] || return 0
  while :; do
    local k=""
    read -t 10 -n 1 k 2>/dev/null && [[ -n "$k" ]] && break
    clear
    stack_doctor
  done
}

fmt_bytes() {   # <bytes> → человекочитаемо
  local b="${1:-0}"
  [[ -z "$b" || "$b" == "NULL" ]] && b=0
  if   (( b >= 1099511627776 )); then echo "$(( b / 1099511627776 )) ТБ"
  elif (( b >= 1073741824 ));    then echo "$(( b / 1073741824 )) ГБ"
  elif (( b >= 1048576 ));       then echo "$(( b / 1048576 )) МБ"
  elif (( b >= 1024 ));          then echo "$(( b / 1024 )) КБ"
  else echo "${b} Б"; fi
}

# Единый экран диагностики и управления инбаундами.
inbounds_manage_menu() {
  while :; do
    line; echo -e "${B}   ИНБАУНДЫ: ПРОВЕРКА И УПРАВЛЕНИЕ${N}"; line
    echo "  1) Проверить все инбаунды (live-таблица)"
    echo "  2) Добавить / проверить inbound"
    echo "  3) Удалить inbound или только его SNI-привязку"
    echo "  4) Сменить домен inbound"
    echo "  0) Назад"
    local c=""
    ask c "Выбор" "1" '^[0-4]$'
    case "$c" in
      1) inbounds_live; pause ;;
      2) add_inbound; pause ;;
      3) remove_inbound; pause ;;
      4) inbound_change_domain ;;
      0) return 0 ;;
    esac
  done
}

# п.19: live-таблица по всем инбаундам — порт слушает?, серт (дней), клиенты, трафик
inbounds_live() {
  line; echo -e "${B}   ИНБАУНДЫ — LIVE${N}"; line
  [[ -z "$XUI_DB" || ! -f "$XUI_DB" ]] && { err "x-ui.db не найден"; return 1; }

  printf "  %-5s %-11s %-7s %-5s %-8s %-5s %-9s %s\n" "ID" "Прото" "Порт" "Слух" "Серт" "Кл." "Трафик" "Домен"
  echo "  ─────────────────────────────────────────────────────────────────────────────"

  local out
  out=$(python3 - "$XUI_DB" <<'PYLIVE' 2>/dev/null
import sqlite3, json, sys
try:
    con=sqlite3.connect(f"file:{sys.argv[1]}?mode=ro",uri=True,timeout=5)
    # LIVE показывает только включённые инбаунды. Отключённые записи остаются
    # в БД для истории, но не являются работающими сервисами и не должны
    # попадать в таблицу как будто их порт обязан слушаться.
    rows=con.execute("SELECT id,protocol,port,COALESCE(listen,''),settings,stream_settings FROM inbounds WHERE enable=1 ORDER BY id").fetchall()
except Exception:
    sys.exit(0)
for iid,proto,port,listen,setts_s,stream_s in rows:
    try: se=json.loads(setts_s or "{}")
    except Exception: se={}
    try: st=json.loads(stream_s or "{}")
    except Exception: st={}
    rs=st.get("realitySettings") or {}
    dom=(se.get("domain") or se.get("hostname") or se.get("sni")
         or (st.get("tlsSettings") or {}).get("serverName")
         or (rs.get("serverNames") or [None])[0] or "")
    try: p=int(se.get("port") or port or 0)
    except Exception: p=int(port or 0)
    # UDP-протоколы классифицируем ПО ИМЕНИ — поле network в stream_settings
    # бывает испорчено/наследовано (hysteria с network=tcp живёт у LucX)
    UDP_PROTOS={"hysteria","hysteria2","qwdtt","csqtt","tuic","wireguard","amnezia","amneziawg","awg"}
    net="udp" if proto.lower() in UDP_PROTOS else (st.get("network") or "tcp")
    cert=(se.get("certFile") or "")
    if not cert:
        certs=(st.get("tlsSettings") or {}).get("certificates") or []
        if certs: cert=certs[0].get("certificateFile","")
    if (st.get("security") or "").lower()=="reality": cert="REALITY"
    if (st.get("network") or "").lower()=="xhttp" and (st.get("security") or "none").lower() in ("none",""):
        # CDN-режим: TLS терминирует nginx — серт в инбаунде не нужен
        try:
            prof=[l.split("|") for l in open("/root/stack-backups/cdn-profiles.tsv") if l.strip()]
            if any(r[0]==str(iid) for r in prof): cert="CDN"
        except Exception: pass
    try: ncl=len(se.get("clients") or [])
    except Exception: ncl=0
    # трафик: панель может писать его и в client_traffics (по клиентам),
    # и в inbounds.up/down (по инбаунду) — берём максимум из обоих источников
    t1=t2=0
    try:
        r=con.execute("SELECT COALESCE(SUM(up),0)+COALESCE(SUM(down),0) FROM client_traffics WHERE inbound_id=?", (iid,)).fetchone()
        t1=r[0] if r else 0
    except Exception: pass
    try:
        r=con.execute("SELECT COALESCE(up,0)+COALESCE(down,0) FROM inbounds WHERE id=?", (iid,)).fetchone()
        t2=r[0] if r else 0
    except Exception: pass
    tot=max(int(t1 or 0), int(t2 or 0))
    print(f"{iid}\x1f{proto}\x1f{p}\x1f{net}\x1f{cert}\x1f{ncl}\x1f{dom}\x1f{tot}")
PYLIVE
)
  local iid proto p net cert ncl dom tot st_us days traf e
  while IFS=$'\x1f' read -r iid proto p net cert ncl dom tot; do
    [[ -z "$iid" ]] && continue
    if [[ "$net" == "udp" ]]; then
      if ss -ulan 2>/dev/null | grep -qE ":${p}([[:space:]]|\$)"; then
        st_us="✓"
      elif command -v nft >/dev/null 2>&1 && nft list ruleset 2>/dev/null | grep -qw "$p"; then
        st_us="✓*"   # порт открыт NAT-правилом (port hopping) — сокет слушает другой порт
      elif iptables -t nat -S 2>/dev/null | grep -qE "dport[ =]$p([ :]|$)|:$p([ :]|$)"; then
        st_us="✓*"   # то же, но legacy-iptables
      elif grep -qiE ":$(printf '%04X' "$p" 2>/dev/null)([[:space:]]|\$)" /proc/net/udp /proc/net/udp6 2>/dev/null; then
        st_us="✓"    # прямое чтение /proc — работает даже без ss
      else
        st_us="✗"
      fi
    else
      ss -tln 2>/dev/null | grep -qE ":${p}([[:space:]]|\$)" && st_us="✓" || st_us="✗"
    fi
    days="—"
    if [[ "$cert" == "REALITY" ]]; then
      days="RLTY"
    elif [[ "$cert" == "CDN" ]]; then
      days="CDN"
    elif [[ -n "$cert" && -f "$cert" ]]; then
      e=$(openssl x509 -enddate -noout -in "$cert" 2>/dev/null | cut -d= -f2)
      days="$(( ($(date -d "$e" +%s 2>/dev/null || echo 0) - $(date +%s)) / 86400 )) дн"
      [[ "$days" == "-1 дн" || "$days" == "0 дн" ]] && days="ПРОСРОЧЕН"
    fi
    traf=$(fmt_bytes "${tot:-0}")
    printf "  %-5s %-11s %-7s %-5s %-8s %-5s %-9s %s\n" "#$iid" "$proto" "$p" "$st_us" "$days" "$ncl" "$traf" "$dom"
  done <<<"$out"
  echo
  warn "✗ — порт НЕ слушается (инбаунд не работает) · ✓* — UDP открыт через NAT (port hopping) · RLTY — reality: серт у decoy в nginx · CDN — tls у nginx (CDN-режим) · Кл. — число клиентов"
  line
  return 0
}

# Обновление панели до LucX UI с сохранением данных (инбаунды/клиенты/настройки
# живут в x-ui.db — установщик LucX её подхватывает). Бэкап БД делаем до запуска.
panel_upgrade_lucx() {
  [[ -z "$XUI_DB" || ! -f "$XUI_DB" ]] && { err "x-ui.db не найден — обновлять нечего"; return 1; }
  local bak="${XUI_DB}.bak-$(date +%F-%H%M%S)"
  if ! sqlite3 "$XUI_DB" ".backup '$bak'" 2>/dev/null && ! cp -a "$XUI_DB" "$bak"; then
    err "Не удалось забэкапить $XUI_DB — отмена"
    return 1
  fi
  chmod 600 "$bak" 2>/dev/null || true
  log "Бэкап БД: $bak"
  local tmp_sh
  tmp_sh=$(mktemp /tmp/lucx-upgrade.XXXXXX.sh) || { err "mktemp failed"; return 1; }
  log "Скачивание установщика LucX UI..."
  if ! curl -fSL --retry 3 "$LUCX_INSTALL_URL" -o "$tmp_sh" || [[ ! -s "$tmp_sh" ]]; then
    err "Не удалось скачать установщик ($LUCX_INSTALL_URL)"
    rm -f "$tmp_sh"
    return 1
  fi
  warn "Установщик задаст вопросы по панели — существующие значения оставляй как есть (Enter), БД сохранится."
  if ! bash "$tmp_sh"; then
    err "Установщик завершился с ошибкой — проверь состояние панели. Бэкап БД: $bak"
    rm -f "$tmp_sh"
    return 1
  fi
  rm -f "$tmp_sh"
  detect_env
  local nf
  nf=$(detect_panel_flavor)
  if [[ "$nf" == "lucx" ]]; then
    log "Готово: панель обновлена до LucX UI (инбаунды/клиенты на месте)."
    warn "Дальше: прогони п.1 заново — он перестроит SNI/hosts/серты под LucX."
  else
    warn "После установки панель определяется как «$nf» — если это не то, что ожидал, разбирайся вручную (бэкап: $bak)."
  fi
  return 0
}

# Единый пункт п.7: смотрим какая панель стоит и предлагаем действия.
panel_manage() {
  line; echo -e "${B}   ПАНЕЛЬ — УСТАНОВКА / ОБНОВЛЕНИЕ / УДАЛЕНИЕ${N}"; line
  local flavor
  flavor=$(detect_panel_flavor)
  case "$flavor" in
    lucx)
      log "Установлена: LucX UI (найдены schema-маркеры; x-ui.db: ${XUI_DB:-?})"
      ;;
    3x-ui)
      log "Установлена: оригинальный 3x-ui (LucX schema-маркеры не найдены; x-ui.db: ${XUI_DB:-?})"
      warn "Протоколы LucX (qwdtt/csqtt/tproxy/naive/anytls/trusttunnel/hysteria) в ней работать не будут."
      ;;
    *)
      log "Панель не найдена — установка LucX UI."
      install_lucx_panel
      return 0
      ;;
  esac
  echo
  if [[ "$flavor" == "3x-ui" ]]; then
    echo "  1) Мигрировать оригинальный 3x-ui → LucX UI (бэкап БД; инбаунды сохранятся)"
  else
    echo "  1) Переустановить/обновить LucX UI (бэкап БД; инбаунды сохранятся)"
  fi
  echo "  2) Удалить панель со всеми данными"
  echo "  0) Назад"
  local act=""
  ask act "Выбор" "0" '^[0-2]$'
  case "$act" in
    1) panel_upgrade_lucx; pause ;;
    2)
      # Подтверждение выполняется внутри uninstall_panel_lucx после показа
      # точного списка удаляемых файлов и создания бэкапа.
      uninstall_panel_lucx
      pause
      ;;
  esac
  return 0
}

adguard_manage() {
  line; echo -e "${B}   ADGUARD HOME — УСТАНОВКА / УДАЛЕНИЕ${N}"; line
  if [[ "$ADG_PRESENT" == true && -n "$ADG_SERVICE" ]]; then
    log "AdGuard Home уже установлен (service: $ADG_SERVICE)"
    local go=""
    askyn go "Удалить AdGuard Home?" "n"
    [[ "$go" == true ]] && uninstall_adguard
    return 0
  fi
  log "AdGuard Home не найден — установка."
  install_adguard_home
}

# =====================================================================
# Гигиена nginx и логов: server_tokens off, security-заголовки на decoy,
# ротация decoy-логов (если не покрыта системным logrotate).
# =====================================================================
nginx_hygiene() {
  line; echo -e "${B}   ГИГИЕНА NGINX И ЛОГОВ${N}"; line
  mkdir -p "$BACKUP_DIR" 2>/dev/null || true
  local changed=0
  # 1) server_tokens off — не показывать версию nginx
  # (сначала снимаем возможный дубль от прежнего запуска; директива
  #  может уже быть задана в любом регистре — тогда нормализуем к off)
  cp -a /etc/nginx/nginx.conf "$BACKUP_DIR/nginx.conf.bak-$(date +%Y%m%d-%H%M%S)" 2>/dev/null || true
  if grep -q 'server_tokens off; # stack-manager' /etc/nginx/nginx.conf 2>/dev/null; then
    sed -i '/server_tokens off; # stack-manager/d' /etc/nginx/nginx.conf
    log "server_tokens: убран дубль от прошлого запуска"; changed=1
  fi
  if grep -qiE '^[[:space:]]*server_tokens[[:space:]]+' /etc/nginx/nginx.conf 2>/dev/null; then
    sed -i -E 's/^([[:space:]]*server_tokens[[:space:]]+).*/\1off; # stack-manager/I' /etc/nginx/nginx.conf
    log "server_tokens: уже был задан в nginx.conf — приведён к off"
  else
    sed -i 's/^http {/http {\n    server_tokens off; # stack-manager/' /etc/nginx/nginx.conf
    if grep -q 'server_tokens off' /etc/nginx/nginx.conf; then
      log "server_tokens off → включён (версия nginx больше не светится)"
    else
      err "не нашёл 'http {' в nginx.conf — вставь 'server_tokens off;' вручную"
    fi
  fi
  grep -qiE '^[[:space:]]*server_tokens[[:space:]]+off' /etc/nginx/nginx.conf 2>/dev/null && { audit "nginx: server_tokens off"; changed=1; }
  # 2) security-заголовки decoy: сниппет + вживление во все блоки stack.conf
  mkdir -p /etc/nginx/snippets
  cat > /etc/nginx/snippets/decoy-headers.conf <<'EOF'
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "SAMEORIGIN" always;
add_header Referrer-Policy "no-referrer-when-downgrade" always;
EOF
  if grep -q 'snippets/decoy-headers' "$STACK_CONF" 2>/dev/null; then
    log "заголовки decoy: уже подключены"
  elif [[ -f "$STACK_CONF" ]]; then
    cp -a "$STACK_CONF" "$BACKUP_DIR/stack.conf.bak-hygiene-$(date +%Y%m%d-%H%M%S)" 2>/dev/null || true
    sed -i '/^    ssl_certificate_key /a\    include /etc/nginx/snippets/decoy-headers.conf;' "$STACK_CONF"
    log "заголовки decoy: подключены ко всем блокам stack.conf"; audit "nginx: decoy-заголовки (nosniff/SAMEORIGIN/referrer)"; changed=1
  fi
  # 3) ротация decoy-логов (если не покрыта общим logrotate nginx)
  if grep -rqs 'var/log/nginx' /etc/logrotate.d/ 2>/dev/null; then
    log "ротация логов nginx: уже настроена (/etc/logrotate.d)"
  else
    cat > /etc/logrotate.d/stack-decoy <<'EOF'
/var/log/nginx/decoy-access.log /var/log/nginx/decoy-error.log {
    daily
    rotate 14
    size 50M
    missingok
    notifempty
    compress
    delaycompress
    sharedscripts
    postrotate
        [ -f /var/run/nginx.pid ] && kill -USR1 $(cat /var/run/nginx.pid) 2>/dev/null || true
    endscript
}
EOF
    log "ротация decoy-логов: создана (день / 14 копий / сжатие)"; audit "logrotate: stack-decoy создан"; changed=1
  fi
  # 4) проверка и перезагрузка
  if (( changed )); then
    if nginx -t >/dev/null 2>&1; then
      nginx_reload
      log "Гигиена применена ✓"
    else
      err "nginx -t не прошёл — откат: $BACKUP_DIR/*.bak-hygiene-*"
      nginx -t 2>&1 | tail -3
      return 1
    fi
  else
    log "Всё уже в порядке — менять нечего ✓"
  fi
  pause
}

# =====================================================================
# СТЕЛС-АУДИТ: что о сервере увидит Shodan/Censys/crt.sh.
# Только чтение — ничего не меняет.
# =====================================================================
stealth_audit() {
  line; echo -e "${B}   СТЕЛС-АУДИТ (глазами сканера)${N}"; line
  local base="${WILDCARD_DOMAIN:-${PANEL_DOMAIN:-}}"
  # последние два лейбла: *.vladufqaa.online / vladufqaa.online / panel.vladufqaa.online → vladufqaa.online
  local _p
  IFS='.' read -r -a _p <<<"$base"
  local _n=${#_p[@]}
  if (( _n >= 3 )); then base="${_p[_n-2]}.${_p[_n-1]}"; fi

  local ufw_on=0
  ufw_is_active && ufw_on=1
  local allowed=""
  if [[ "$ufw_on" == 1 ]]; then
    allowed=$(LC_ALL=C ufw status 2>/dev/null | awk '/ALLOW/ {print $1}' | sort -u)
  else
    warn "UFW не активен — ВСЕ слушающие порты видны интернету!"
  fi
  stealth_vis() {   # порт/протокол виден миру? (ufw off → виден всё)
    [[ "$ufw_on" == 1 ]] || return 0
    grep -qE "^${1}/${2}([[:space:]]|$)" <<<"$allowed" \
      || grep -qE "^${1}([[:space:]]|$)" <<<"$allowed"
  }

  echo; echo -e "${B}— 1. Слушающие TCP-порты —${N}"
  local p
  for p in $(ss -tln 2>/dev/null | awk 'NR>1 { if ($4 ~ /^127\./ || $4 ~ /^\[::1\]/) next; split($4,a,":"); print a[length(a)] }' | sort -un); do
    if ! stealth_vis "$p" tcp; then
      ok "порт $p — слушается, но закрыт UFW (сканерам невидим)"
    elif [[ "$p" == "443" ]]; then
      ok "порт 443 — SNI-роутер (decoy-доктрина)"
    elif [[ "$p" == "80" ]]; then
      log "порт 80 — HTTP (обычно для ACME); что отдаёт — см. раздел 3"
    elif [[ "$p" == "22" ]]; then
      warn "порт 22 — SSH открыт миру: банер + host key привязывают тебя между IP (см. раздел 5)"
    else
      err "порт $p — нестандартный и ОТКРЫТ: сканеры его индексируют (инбаунд?). Лучше за 443/SNI или reality"
      echo "      (пропустило правило UFW: $(grep -E "^${p}/" <<<"$allowed" | head -1))"
    fi
  done

  echo; echo -e "${B}— 2. Слушающие UDP-порты (QUIC/крауты) —${N}"
  local any_udp=0
  for p in $(ss -uln 2>/dev/null | awk 'NR>1 { if ($4 ~ /^127\./ || $4 ~ /^\[::1\]/) next; if ($5 != "*:*") next; split($4,a,":"); print a[length(a)] }' | sort -un); do
    any_udp=1
    if ! stealth_vis "$p" udp; then
      ok "udp $p — закрыт UFW (невидим)"
    elif [[ "$p" == "53" ]]; then
      warn "udp 53 — DNS; если отвечает наружу — open resolver (см. раздел 5)"
    else
      err "udp $p — открыт (hysteria/tuic?): QUIC-банер фингерпринтится Censys"
      echo "      (пропустило правило UFW: $(grep -E "^${p}/" <<<"$allowed" | head -1))"
    fi
  done
  [[ "$any_udp" == 0 ]] && ok "открытых UDP-слушателей нет"

  echo; echo -e "${B}— 3. Что видит сканер на :443 БЕЗ SNI —${N}"
  local subj
  subj=$(echo | timeout 8 openssl s_client -connect 127.0.0.1:443 -noservername 2>/dev/null | openssl x509 -noout -subject 2>/dev/null)
  if [[ -z "$subj" ]]; then
    warn "сертификат не получен — проверь руками: openssl s_client -connect $(hostname -I 2>/dev/null | awk '{print $1}'):443"
  else
    echo "    $subj"
    if [[ -n "$PANEL_DOMAIN" && "$subj" == *"$PANEL_DOMAIN"* ]]; then
      err "443 отдаёт серт ПАНЕЛИ → Shodan привяжет «$PANEL_DOMAIN» к IP. Смени default-блок (decoy-серт)."
    elif [[ -n "$base" && "$subj" == *"$base"* ]]; then
      ok "свой wildcard/decoy-серт — приемлемо (панель не светится)"
    else
      ok "чужой серт — идеально (выглядишь чужим сайтом)"
    fi
  fi

  echo; echo -e "${B}— 4. HTTP :80 —${N}"
  if ! stealth_vis "80" tcp; then
    ok "80 закрыт UFW — невидим (ACME п.4 временно открывает сам)"
  else
    local code; code=$(curl -s -o /dev/null -w '%{http_code}' -m 6 http://127.0.0.1/ 2>/dev/null)
    case "$code" in
      301|302|308) ok "редирект на HTTPS ($code) — нейтрально" ;;
      000) warn "80 открыт в UFW, но не отвечает — лучше закрыть" ;;
      *) warn "ответ $code — сканер индексирует содержимое; проверь, что там decoy/заглушка, а не служебное" ;;
    esac
  fi

  echo; echo -e "${B}— 5. SSH :22 —${N}"
  if ! stealth_vis "22" tcp; then
    ok "22 закрыт UFW для мира — сканерам невиден"
  else
    warn "22 открыт: host key Shodan связывает все твои IP (переезд не помогает)."
    echo "      Смягчение: UFW только на свой IP, смена порта или knocking (ТОЛЬКО на 22, не на 443!)."
  fi

  echo; echo -e "${B}— 6. DNS :53 наружу —${N}"
  local udp53; udp53=$(ss -uln 2>/dev/null | awk 'NR>1 && $4 ~ /:53$/ && $5 == "*:*" && $4 !~ /^127\./ && $4 !~ /^\[::1\]/ {c++} END {print c+0}')
  if [[ "$udp53" -eq 0 ]]; then
    ok "53 наружу не слушается ✓"
  elif ! stealth_vis "53" udp; then
    ok "53 слушается, но закрыт UFW ✓"
  else
    err "53 открыт миру — open resolver (абьюз + палево)! Закрой в UFW (п.11)."
  fi

  echo; echo -e "${B}— 7. Публичные имена (Certificate Transparency) —${N}"
  if [[ -z "$base" ]]; then
    log "базовый домен не определён — пропуск"
  else
    local ct
    ct=$(curl -s -m 25 --retry 2 --retry-delay 2 "https://crt.sh/?q=%25.${base}&output=json" 2>/dev/null | python3 -c '
import json, sys
try: d = json.load(sys.stdin)
except Exception: sys.exit(0)
names = set()
for r in d if isinstance(d, list) else []:
    for n in str(r.get("name_value", "")).split("\n"):
        n = n.strip().lstrip("*.")
        if n and "=" not in n: names.add(n)
for n in sorted(names)[:20]: print(n)' 2>/dev/null)
    if [[ -z "$ct" ]]; then
      log "crt.sh не ответил — проверь руками: https://crt.sh/?q=%.${base}"
    else
      warn "эти имена уже публичны (каждый выпуск серта = запись в CT-логах):"
      echo "$ct" | sed 's/^/      /'
      echo "      Правило: чувствительным именам не выпускать отдельных сертов — только wildcard."
    fi
  fi

  echo; echo -e "${B}— 8. Опт-аут из поисковиков —${N}"
  echo "      Shodan: аккаунт → shodan.io → «Request IP Removal» для $(server_ip4 2>/dev/null)"
  echo "      Censys: search.censys.io → ваш хост → Opt-Out Host"
  echo "      Сначала закрыть дыры (выше), потом опт-аут — иначе ре-скан всё вернёт."
  echo
  log "Аудит только читал — ничего не менял."
  pause
}

# =====================================================================
