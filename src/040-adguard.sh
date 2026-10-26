# ADGUARD HOME
# =====================================================================
# свободный порт для web-UI AdGuard: 3000, если занят — первый свободный из 3001..3099
adg_pick_port() {
  local p="$ADG_WEB_PORT" i
  if port_in_use "$p"; then
    for i in $(seq 3001 3099); do
      port_in_use "$i" || { p=$i; break; }
    done
  fi
  ADG_WEB_PORT="$p"
}

# bcrypt-хэш для AdGuard (Go bcrypt понимает $2a/$2b/$2y): python3 → htpasswd
adg_bcrypt() {
  local pw="$1" h=""
  if command -v python3 >/dev/null 2>&1; then
    # 1) pip-модуль bcrypt (основной; модуль crypt УДАЛЁН из Python 3.13+)
    h=$(python3 -c 'import sys
try:
    import bcrypt
    sys.stdout.write(bcrypt.hashpw(sys.argv[1].encode(), bcrypt.gensalt(10)).decode())
except Exception:
    sys.exit(1)' "$pw" 2>/dev/null || true)
    [[ "$h" == \$2* ]] && { echo "$h"; return 0; }
    # 2) stdlib crypt (Python < 3.13)
    h=$(python3 -c 'import sys
try:
    import crypt
    sys.stdout.write(crypt.crypt(sys.argv[1], crypt.mksalt(crypt.METHOD_BLOWFISH)))
except Exception:
    sys.exit(1)' "$pw" 2>/dev/null || true)
    [[ "$h" == \$2* ]] && { echo "$h"; return 0; }
  fi
  # 3) htpasswd (ставим apache2-utils при необходимости)
  command -v htpasswd >/dev/null 2>&1 || apt-get install -y apache2-utils >/dev/null 2>&1 || true
  if command -v htpasswd >/dev/null 2>&1; then
    h=$(htpasswd -bnBC 10 "" "$pw" 2>/dev/null | tr -d ':\n' || true)
    [[ "$h" == \$2* ]] && { echo "$h"; return 0; }
  fi
  return 1
}

# записать админа AdGuard (заменяет всех пользователей; пропускает визард первого запуска)
adg_set_admin() {
  local cfg="$ADG_CONFIG" user="$1" pass="$2"
  if [[ -z "$cfg" || ! -f "$cfg" ]]; then
    local c2
    for c2 in /opt/AdGuardHome/AdGuardHome.yaml /root/AdGuardHome/AdGuardHome.yaml \
              /etc/AdGuardHome.yaml /etc/adguardhome/AdGuardHome.yaml; do
      [[ -f "$c2" ]] && { cfg="$c2"; ADG_CONFIG="$c2"; break; }
    done
  fi
  [[ -z "$cfg" || ! -f "$cfg" ]] && { err "adg_set_admin: AdGuardHome.yaml не найден (ADG_CONFIG='$ADG_CONFIG')"; return 1; }
  local hash
  hash=$(adg_bcrypt "$pass") || { err "adg_set_admin: не удалось создать bcrypt-хэш (нет python3-bcrypt и htpasswd)"; return 1; }
  local svc="${ADG_SERVICE:-AdGuardHome}"
  systemctl stop "$svc" 2>/dev/null || true
  if grep -q '^users:' "$cfg"; then
    # заменяем ВЕСЬ блок users (до следующей строки верхнего уровня) — иначе
    # старый вложенный password: остаётся рядом с новым → yaml не парсится
    awk -v n="  - name: $user" -v p="    password: $hash" '
      /^users:/ { print; print n; print p; inu=1; next }
      inu && /^[^ #]/ { inu=0 }
      inu { next }
      { print }
    ' "$cfg" > "$cfg.new" && mv "$cfg.new" "$cfg"
  else
    printf 'users:\n  - name: %s\n    password: %s\n' "$user" "$hash" >> "$cfg"
  fi
  systemctl start "$svc" 2>/dev/null || true
  sleep 1
  return 0
}

# bootstrap конфига AdGuard при ЧИСТОЙ установке: без yaml сервис висит
# в режиме визарда на 0.0.0.0:3000. Конфиг НЕ пишем руками (схема меняется
# между версиями) — проходим официальный визард через его API: AdGuard сам
# генерирует родной AdGuardHome.yaml (web 127.0.0.1, DNS bind 127.0.0.1:53).
adg_bootstrap_config() {
  local admin_pass="$1"
  local cfg="${ADG_CONFIG:-/opt/AdGuardHome/AdGuardHome.yaml}"
  local dir; dir=$(dirname "$cfg")
  mkdir -p "$dir/data" "$dir/filters" 2>/dev/null || true
  systemctl start "$ADG_SERVICE" 2>/dev/null || true
  sleep 2
  local code=""
  code=$(curl -s -o /tmp/.agh-install.json -w '%{http_code}' --max-time 20 \
    -X POST http://127.0.0.1:3000/control/install/configure \
    -H 'Content-Type: application/json' \
    -d "{\"web\":{\"ip\":\"127.0.0.1\",\"port\":$ADG_WEB_PORT},\"dns\":{\"ip\":\"127.0.0.1\",\"port\":53},\"username\":\"admin\",\"password\":\"$admin_pass\"}" 2>/dev/null) || true
  if [[ "$code" != "200" ]]; then
    err "AdGuard wizard API не ответил 200 (got: $code)"
    head -c 300 /tmp/.agh-install.json 2>/dev/null; echo
    return 1
  fi
  # сервис перезапускается сам — ждём новый порт
  local i
  for i in 1 2 3 4 5 6; do
    ss -tlnH "sport = :$ADG_WEB_PORT" 2>/dev/null | grep -q . && break
    sleep 2
  done
  if ! ss -tlnH "sport = :$ADG_WEB_PORT" 2>/dev/null | grep -q .; then
    err "AdGuard не поднялся на 127.0.0.1:$ADG_WEB_PORT после визарда"
    return 1
  fi
  ADG_CONFIG="$cfg"
  # upstream'ы → Cloudflare/Google (дефолт визарда — quad9)
  curl -s -o /dev/null --max-time 10 -u "admin:$admin_pass" \
    -X POST "http://127.0.0.1:$ADG_WEB_PORT/control/dns_config" \
    -H 'Content-Type: application/json' \
    -d '{"upstream_dns":["https://dns.cloudflare.com/dns-query","8.8.8.8"],"bootstrap_dns":["1.1.1.1","8.8.8.8"]}' 2>/dev/null || true
  log "AdGuard: конфиг создан визард-API (web 127.0.0.1:$ADG_WEB_PORT · DNS 127.0.0.1:53 · admin/admin_pass)"
  return 0
}

# фактический web-порт AdGuard: при включённом TLS — tls.port_https (UI+DoH),
# иначе — порт из http.address
adg_config_port() {
  local cfg="$ADG_CONFIG"
  if [[ -z "$cfg" || ! -f "$cfg" ]]; then echo "$ADG_WEB_PORT"; return; fi
  local tls_en="" p=""
  tls_en=$(awk '/^tls:/{f=1;next} /^[^ ]/{f=0} f && /^  enabled:/{print $2; exit}' "$cfg" 2>/dev/null | tr -d '"')
  if [[ "$tls_en" == "true" ]]; then
    p=$(awk '/^tls:/{f=1;next} /^[^ ]/{f=0} f && /^  port_https:/{print $2; exit}' "$cfg" 2>/dev/null)
    if [[ -n "$p" && "$p" != "0" ]]; then echo "$p"; return; fi
  fi
  p=$(awk '/^http:/{f=1;next} /^[^ ]/{f=0} f && /^  address:/{n=split($2,a,":"); print a[n]; exit}' "$cfg" 2>/dev/null | tr -d '"')
  echo "${p:-$ADG_WEB_PORT}"
}

install_adguard_home() {
  line; echo -e "${B}   УСТАНОВКА ADGUARD HOME${N}"; line
  detect_env
  [[ "$ADG_PRESENT" == true ]] && { log "AdGuard Home уже установлен"; return 0; }
  warn "AdGuard Home не найден — устанавливаю (вопрос задаётся один раз, в начале скрипта)."

  log "Запуск установщика AdGuard Home..."
  if ! curl -s -S -L "$ADG_INSTALL_URL" | sh -s -- -v; then
    err "Ошибка установки AdGuard Home"; return 1
  fi
  sleep 3
  detect_env
  [[ "$ADG_PRESENT" != true ]] && { err "AdGuardHome.service не найден"; return 1; }

  log "AdGuard Home установлен: $ADG_SERVICE"
  adg_pick_port
  local adg_user="${U_ADG_USER:-admin}" adg_pass=""
  adg_pass=$(openssl rand -base64 18 2>/dev/null | tr -dc 'a-zA-Z0-9' | head -c 16)
  [[ -z "$adg_pass" ]] && adg_pass="AdG$(date +%s)"
  # чистая установка: конфига нет (режим визарда) → создаём через wizard-API
  if [[ -z "$ADG_CONFIG" || ! -f "$ADG_CONFIG" ]]; then
    adg_bootstrap_config "$adg_pass" || warn "Bootstrap AdGuardHome.yaml не удался — настройте вручную"
  fi
  configure_adguard_local || warn "Настройте bind вручную"

  # автоматические учётные данные админа — визард не нужен
  adg_user="${U_ADG_USER:-admin}" adg_pass=""
  adg_pass=$(openssl rand -base64 18 2>/dev/null | tr -dc 'a-zA-Z0-9' | head -c 16)
  [[ -z "$adg_pass" ]] && adg_pass="AdG$(date +%s)"
  if adg_set_admin "$adg_user" "$adg_pass"; then
    {
      echo "AdGuard Home — $(date '+%F %T')"
      echo "  URL:    https://<домен-панели>/          (после п.1, decoy=adguard)"
      echo "  DoH:    https://<домен-панели>/dns-query"
      echo "  Логин:  $adg_user"
      echo "  Пароль: $adg_pass"
    } > /root/adguard-credentials.txt 2>/dev/null || true
    chmod 600 /root/adguard-credentials.txt 2>/dev/null || true
  fi

  # СЕРТ для AdGuard: приоритет — серт, вписанный в x-ui (в т.ч. из меню x-ui),
  # затем subDomain/wildcard через cert_paths; без всего — самоподписанный fallback.
  local _adg_cert="" _adg_key="" _adg_cp="" _adg_dom="" _adg_pline=""
  _adg_pline=$(panel_cert_from_db) || true
  if [[ -n "$_adg_pline" ]]; then
    _adg_cert="${_adg_pline%% *}"; _adg_key=$(echo "$_adg_pline" | awk '{print $2}')
  else
    _adg_dom=$(xui_get subDomain 2>/dev/null || true)
    [[ -n "$_adg_dom" ]] && _adg_cp=$(cert_paths "$_adg_dom" 2>/dev/null || true)
    if [[ -z "$_adg_cp" && -f "$WILDCARD_STATE" ]]; then
      _adg_dom=$(head -n 1 "$WILDCARD_STATE" 2>/dev/null | tr -d '[:space:]')
      [[ -n "$_adg_dom" ]] && _adg_cp=$(cert_paths "adg.$_adg_dom" 2>/dev/null || true)
    fi
    [[ -n "$_adg_cp" ]] && { _adg_cert="${_adg_cp%% *}"; _adg_key="${_adg_cp##* }"; }
  fi

  configure_adguard_doh "" "$_adg_cert" "$_adg_key" || warn "DoH-настройка AdGuardHome.yaml не применена автоматически"

  echo
  line
  log "AdGuard Home установлен и настроен:"
  echo "   web:     127.0.0.1:$ADG_WEB_PORT (снаружи — только https://<домен-панели>/)"
  echo "   DoH:     https://<домен-панели>/dns-query"
  echo "   логин:   $adg_user"
  echo "   пароль:  $adg_pass"
  echo "   → сохранено в /root/adguard-credentials.txt"
  line

  # SNI-стек уже поднят? Сразу вешаем AdGuard за домен панели — иначе
  # nginx-правила появились бы только после перезапуска п.1 и сайт «не открывался».
  if grep -q "listen 127.0.0.1:4443" "$STACK_CONF" 2>/dev/null; then
    panel_decoy_apply adguard || warn "nginx-локация AdGuard не применилась — перезапусти п.1 «Первичная настройка»"
  fi
}
# AdGuard + DoH за nginx (v0.107.79+): plain DoH (allow_unencrypted_doh) больше
# не поддерживается — включаем в AdGuard РОДНОЙ HTTPS на 127.0.0.1:$ADG_WEB_PORT
# (web UI + /dns-query на одном порту) с wildcard/панельным сертификатом.
# nginx затем проксирует location / → https://127.0.0.1:$ADG_WEB_PORT.
#   dns.bind_hosts → 127.0.0.1 (plain DNS только для самого сервера)
# Аргументы: configure_adguard_doh [admin_pass] [cert] [key]
#   без серта — самоподписанный (nginx всё равно терминирует TLS с verify off)
configure_adguard_doh() {
  local adg_pass="${1:-}" cert="${2:-}" key="${3:-}"
  local cfg="$ADG_CONFIG"
  [[ -z "$cfg" || ! -f "$cfg" ]] && return 1

  # фактический порт из http.address конфига (дефолт ADG_WEB_PORT может врать)
  local cfg_port=""
  cfg_port=$(awk '/^http:/{f=1;next} /^[^ ]/{f=0} f && /^  address:/{n=split($2,a,":"); print a[n]; exit}' "$cfg" 2>/dev/null | tr -d '"')
  [[ -n "$cfg_port" && "$cfg_port" != "null" ]] && ADG_WEB_PORT="$cfg_port"

  # сертификат: панельный/wildcard или самоподписанный fallback
  if [[ -z "$cert" || ! -f "$cert" || -z "$key" || ! -f "$key" ]]; then
    local tdir="/etc/nginx/adguard-tls"
    mkdir -p "$tdir" 2>/dev/null || true
    if [[ ! -f "$tdir/adguard.crt" || ! -f "$tdir/adguard.key" ]]; then
      openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -keyout "$tdir/adguard.key" -out "$tdir/adguard.crt" -days 3650 -nodes \
        -subj "/CN=adguard.local" 2>/dev/null || true
    fi
    [[ -f "$tdir/adguard.crt" ]] && { cert="$tdir/adguard.crt"; key="$tdir/adguard.key"; }
  fi

  systemctl stop "$ADG_SERVICE" 2>/dev/null || true
  sleep 1
  cp "$cfg" "$cfg.bak.$(date +%s)" 2>/dev/null || true

  # dns.bind_hosts → 127.0.0.1
  awk '
    /^dns:/  { in_dns=1; print; next }
    /^[^ ]/ && !/^dns:/ { in_dns=0 }
    in_dns && /^  bind_hosts:/ {
      print "  bind_hosts:"
      print "    - 127.0.0.1"
      skip_list=1
      next
    }
    skip_list && /^    - / { next }
    skip_list && !/^    - / { skip_list=0 }
    { print }
  ' "$cfg" > "$cfg.new" && mv "$cfg.new" "$cfg"

  # plain-http (админка) уводим на соседний порт: дубликат порта с https запрещён
  local plain_port=""
  local cand=$((ADG_WEB_PORT + 1)) j
  for j in 1 2 3 4 5; do
    if ! port_in_use "$cand"; then plain_port=$cand; break; fi
    cand=$((cand + 1))
  done
  [[ -z "$plain_port" ]] && plain_port=$((ADG_WEB_PORT + 1))
  awk -v pp="$plain_port" '
    /^http:/ { f=1; print; next }
    /^[^ ]/ && !/^http:/ { f=0 }
    f && /^  address:/ { print "  address: 127.0.0.1:" pp; next }
    { print }
  ' "$cfg" > "$cfg.new" && mv "$cfg.new" "$cfg"

  # tls: → enabled + порт https = web порт (UI и DoH на одном порту, TLS на AdGuard)
  # ВАЖНО: в новых версиях (schema 34+) пути серта — certificate_path/private_key_path
  # (certificate_chain/private_key — это САМО PEM-содержимое).
  if grep -q "^tls:" "$cfg"; then
    awk -v ph="$ADG_WEB_PORT" -v sn="${ADG_SNI:-$PANEL_DOMAIN}" -v crt="$cert" -v key="$key" '
      /^tls:/ { in_tls=1; print; next }
      /^[^ ]/ && !/^tls:/ { in_tls=0 }
      in_tls && /^  enabled:/               { print "  enabled: true"; next }
      in_tls && /^  server_name:/           { print "  server_name: \"" sn "\""; next }
      in_tls && /^  force_https:/           { print "  force_https: false"; next }
      in_tls && /^  port_https:/            { print "  port_https: " ph; next }
      in_tls && /^  port_dns_over_tls:/     { print "  port_dns_over_tls: 0"; next }
      in_tls && /^  port_dns_over_quic:/    { print "  port_dns_over_quic: 0"; next }
      in_tls && /^  port_privileged_https:/ { print "  port_privileged_https: 0"; next }
      in_tls && /^  port_dnscrypt:/         { print "  port_dnscrypt: 0"; next }
      in_tls && /^  certificate_chain:/     { print "  certificate_chain: \"\""; next }
      in_tls && /^  private_key:/           { print "  private_key: \"\""; next }
      in_tls && /^  certificate_path:/      { print "  certificate_path: " crt; next }
      in_tls && /^  private_key_path:/      { print "  private_key_path: " key; next }
      { print }
    ' "$cfg" > "$cfg.new" && mv "$cfg.new" "$cfg"
    # отсутствующие ключи — вставляем после ^tls:
    local kv k
    for kv in "  enabled: true" "  port_https: $ADG_WEB_PORT" "  port_dns_over_tls: 0" "  port_dns_over_quic: 0" "  port_dnscrypt: 0" "  certificate_path: $cert" "  private_key_path: $key"; do
      k="${kv%%:*}"
      grep -q "^${k}:" "$cfg" || sed -i "s/^tls:/tls:\n${kv}/" "$cfg"
    done
  else
    {
      echo ""
      echo "tls:"
      echo "  enabled: true"
      echo "  server_name: \"${ADG_SNI:-$PANEL_DOMAIN}\""
      echo "  force_https: false"
      echo "  port_https: $ADG_WEB_PORT"
      echo "  port_dns_over_tls: 0"
      echo "  port_dns_over_quic: 0"
      echo "  port_dnscrypt: 0"
      echo "  certificate_path: $cert"
      echo "  private_key_path: $key"
    } >> "$cfg"
  fi

  systemctl start "$ADG_SERVICE" 2>/dev/null || true
  sleep 3
  if ! ss -tlnH "sport = :$ADG_WEB_PORT" 2>/dev/null | grep -q .; then
    warn "AdGuard не поднялся на 127.0.0.1:$ADG_WEB_PORT"
    return 1
  fi
  # DoH должен отвечать по https (403/200/4xx от хендлера, НЕ 404)
  local code=""
  code=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 8 \
    -H "accept: application/dns-message" \
    "https://127.0.0.1:$ADG_WEB_PORT/dns-query?dns=q80BAAABAAAAAAAAA3d3dwZnb29nbGUDY29tAAABAAE" 2>/dev/null) || true
  if [[ "$code" == "404" ]]; then
    warn "DoH /dns-query не отвечает (HTTP $code)"
    return 1
  fi
  log "AdGuard: https://127.0.0.1:$ADG_WEB_PORT (UI+DoH, TLS на AdGuard) · plain http 127.0.0.1:$plain_port · DNS=127.0.0.1:53 · DoH /dns-query: HTTP $code"
  return 0
}

# AdGuard на ОТДЕЛЬНОМ SNI-домене (adguard.<база панели>): серт (точный или
# wildcard), родной TLS AdGuard на 127.0.0.1:3002, маршрут SNI-роутера
# <домен> → agh_backend. UI + DoH живут на своём домене, панель — на своём корне.
adg_setup_sni_domain() {
  local dom="$1"
  [[ -z "$dom" ]] && return 1
  if [[ "$ADG_PRESENT" != true || -z "$ADG_SERVICE" ]]; then
    warn "AdGuard не установлен — отдельный домен $dom пропущен"
    return 1
  fi
  log "AdGuard → отдельный домен $dom: серт + TLS + SNI-маршрут…"
  cert_issue "$dom" || warn "серт $dom НЕ выпущен — проверь DNS; после выпуска перезапусти п.1 (или таймер самолечения доделает)"
  local cline cert="" key=""
  cline=$(cert_lineage_for "$dom")
  if [[ -n "$cline" ]]; then
    cert="${cline%% *}"; key="${cline##* }"
  else
    cert="/etc/letsencrypt/live/$dom/fullchain.pem"; key="/etc/letsencrypt/live/$dom/privkey.pem"
  fi
  ADG_WEB_PORT=3002
  port_in_use "$ADG_WEB_PORT" && ADG_WEB_PORT=13002
  ADG_SNI="$dom"
  configure_adguard_doh "" "$cert" "$key" || warn "TLS AdGuard для $dom не применился (смотри yaml)"
  sni_upstream_add agh_backend "$ADG_WEB_PORT"
  sni_map_add "$dom" "agh_backend"
  SNI_USED["$dom"]="agh_backend"
  nginx -t >/dev/null 2>&1 && nginx_reload || true
  log "AdGuard: https://$dom/ (UI + DoH /dns-query) — через SNI-роутер на 443"
  return 0
}

# Применить decoy/прокси КОРНЯ домена панели к УЖЕ существующему 4443-блоку
# (без перегенерации stack.conf): adguard | stub | tpl:ИМЯ.
# Нужна, чтобы AdGuard, установленный ПОСЛЕ первичной настройки, сразу
# открывался по домену панели — а не «после перезапуска п.1».
panel_decoy_apply() {
  local mode="$1" custom_path="${2:-}"
  [[ -f "$STACK_CONF" ]] || return 1
  grep -q "listen 127.0.0.1:4443" "$STACK_CONF" 2>/dev/null || return 1
  local adg_port="" panel_path="" panel_conf_bak=""
  panel_conf_bak=$(mktemp /tmp/stack-conf.XXXXXX 2>/dev/null || true)
  [[ -n "$panel_conf_bak" ]] && cp -f "$STACK_CONF" "$panel_conf_bak" 2>/dev/null || true
  adg_port=$(adg_config_port 2>/dev/null || true)
  [[ -z "$adg_port" ]] && adg_port="${ADG_WEB_PORT:-3000}"
  panel_path=$(xui_get webBasePath 2>/dev/null || true)
  panel_path="/${panel_path#/}"; panel_path="${panel_path%/}/"
  PD_MODE="$mode" PD_PORT="$adg_port" PD_DIR="$PANEL_DECOY_DIR" PD_CUSTOM="$custom_path" PD_PATH="$panel_path" python3 - "$STACK_CONF" <<'PYPDA'
import sys, os
mode, adg_port, pdir = os.environ["PD_MODE"], os.environ["PD_PORT"], os.environ["PD_DIR"]
custom = os.environ.get("PD_CUSTOM", "")
panel_path = os.environ.get("PD_PATH", "/")
path = sys.argv[1]
src = open(path).read()
if mode == "custom" and custom:
    block = (
        "    location / {\n"
        f"        root {custom};\n"
        "        try_files $uri $uri/ /index.html;\n"
        "    }"
    )
elif mode == "adguard":
    block = (
        "    location / {\n"
        f"        proxy_pass https://127.0.0.1:{adg_port};\n"
        "        proxy_ssl_verify off;\n"
        "        proxy_http_version 1.1;\n"
        "        proxy_set_header Host $host;\n"
        "        proxy_set_header X-Real-IP $remote_addr;\n"
        "        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n"
        "        proxy_set_header X-Forwarded-Proto https;\n"
        "        proxy_set_header Upgrade $http_upgrade;\n"
        '        proxy_set_header Connection "upgrade";\n'
        "        proxy_read_timeout 86400;\n"
        "    }"
    )
else:
    block = (
        "    location / {\n"
        f"        root {pdir};\n"
        "        try_files /index.html =404;\n"
        "    }"
    )
lines = src.split("\n")
out, i, done, in4443 = [], 0, False, False
while i < len(lines):
    l = lines[i]
    if "listen 127.0.0.1:4443" in l:
        in4443 = True
    # Меняем только отдельный корневой location / — никогда не трогаем
    # webBasePath панели и subPath подписки.
    if in4443 and l.strip() == "location / {":
        j = i + 1
        depth = 1
        while j < len(lines):
            s = lines[j].strip()
            if s.endswith("{"): depth += 1
            if s == "}":
                depth -= 1
                if depth == 0: break
            j += 1
        if j >= len(lines):
            sys.exit(2)
        out.append(block)
        done = True
        i = j + 1
        continue
    out.append(l)
    i += 1
if not done:
    sys.exit(1)
open(path, "w").write("\n".join(out))
PYPDA
  local rc=$?
  if [[ $rc -eq 0 ]]; then
    if nginx -t >/dev/null 2>&1; then
      nginx_reload || true
      log "Корень домена панели → $mode (nginx перезагружен)"
    else
      err "nginx -t не прошёл после смены корня панели — откатываю stack.conf"
      if [[ -s "$panel_conf_bak" ]]; then
        cp -f "$panel_conf_bak" "$STACK_CONF" 2>/dev/null || true
        nginx -t 2>&1 | tail -4 | sed 's/^/    /'
      fi
      rc=1
    fi
  elif [[ -s "$panel_conf_bak" ]]; then
    # Python-редактор не должен оставлять частично изменённый конфиг.
    cp -f "$panel_conf_bak" "$STACK_CONF" 2>/dev/null || true
  fi
  rm -f "$panel_conf_bak" 2>/dev/null || true
  return $rc
}

configure_adguard_local() {
  local cfg="$ADG_CONFIG"
  [[ -z "$cfg" || ! -f "$cfg" ]] && return 1
  systemctl stop "$ADG_SERVICE" 2>/dev/null || true
  sleep 1
  cp "$cfg" "$cfg.bak.$(date +%s)" 2>/dev/null || true
  awk -v web="  address: 127.0.0.1:$ADG_WEB_PORT" '
    /^http:/ { in_http=1; print; next }
    /^[^ ]/ && !/^http:/ { in_http=0 }
    in_http && /^  address:/ { print web; next }
    { print }
  ' "$cfg" > "$cfg.new" && mv "$cfg.new" "$cfg"
  systemctl start "$ADG_SERVICE" 2>/dev/null || true
  sleep 2
  ss -tlnH "sport = :$ADG_WEB_PORT" 2>/dev/null | grep -q . && { log "AdGuard слушает 127.0.0.1:$ADG_WEB_PORT"; return 0; }
  warn "AdGuard не поднялся на $ADG_WEB_PORT"
  return 1
}

decoy_panel_choose() {
  local __result="$1"
  local no_adg="${2:-}"   # "1" = вариант adguard недоступен (пользователь отказался от настройки за панелью)
  echo
  echo -e "${B}Decoy для панели (что показывать по корню домена панели):${N}"
  echo "  1) stub     — стандартная заглушка nginx"
  if [[ "$no_adg" != "1" ]]; then
    echo "  2) adguard  — AdGuard Home web UI + DoH через домен панели"
    echo "  3) шаблон   — decoy-заглушка из каталога (corporate, blog, docs, cloudflare, login-страницы...)"
    echo "  4) adguard+ — AdGuard на ОТДЕЛЬНОМ SNI-домене (adguard.<база панели>)"
  else
    echo "  2) шаблон   — decoy-заглушка из каталога (corporate, blog, docs, cloudflare, login-страницы...)"
  fi
  echo
  if [[ "$no_adg" != "1" && "$ADG_PRESENT" != true ]]; then
    warn "AdGuard Home не установлен — варианты 2 и 4 потребуют установки."
  fi
  if [[ "$no_adg" == "1" ]]; then
    warn "Настройка AdGuard за панелью отклонена — доступен stub или шаблон."
  fi
  echo
  local choice=""
  if [[ "$no_adg" == "1" ]]; then
    ask choice "Выбор" "1" '^[12]$'
    [[ "$choice" == "2" ]] && choice=3
  else
    ask choice "Выбор" "1" '^[1234]$'
  fi
  if [[ "$choice" == "2" && "$ADG_PRESENT" != true ]]; then
    askyn do_install "AdGuard Home не установлен. Установить сейчас?" "y"
    # shellcheck disable=SC2154 # задаётся askyn выше
    if [[ "$do_install" == true ]]; then
      install_adguard_home || { warn "Не удалось — падаем на stub"; choice=1; }
    else
      choice=1
    fi
  fi
  if [[ "$choice" == "4" ]]; then
    if [[ "$ADG_PRESENT" != true ]]; then
      askyn do_install4 "AdGuard Home не установлен. Установить сейчас?" "y"
      # shellcheck disable=SC2154 # задаётся askyn выше
      if [[ "$do_install4" == true ]]; then
        install_adguard_home || { warn "Не удалось — падаем на stub"; choice=1; }
      else
        choice=1
      fi
    fi
    if [[ "$choice" == "4" ]]; then
      printf -v "$__result" '%s' "adguard-sni"
      return 0
    fi
  fi
  if [[ "$choice" == "3" ]]; then
    local tpl=""
    decoy_template_choose tpl "Decoy-шаблон для панели" "corporate"
    printf -v "$__result" '%s' "tpl:$tpl"
    return 0
  fi
  [[ "$choice" == "2" ]] && printf -v "$__result" '%s' "adguard" || printf -v "$__result" '%s' "stub"
}

panel_decoy_stub_init() {
  mkdir -p "$PANEL_DECOY_DIR" 2>/dev/null || true
  cat > "$PANEL_DECOY_DIR/index.html" <<'HTML'
<!doctype html><html><head><meta charset="utf-8"><title>Welcome to nginx!</title>
<style>body{font-family:sans-serif;background:#f4f4f4;text-align:center;padding-top:80px;color:#333}
h1{color:#2b6cb0}p{color:#666}</style></head>
<body><h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and working.</p></body></html>
HTML
  chown -R www-data:www-data "$PANEL_DECOY_DIR" 2>/dev/null || true
}

# =====================================================================
