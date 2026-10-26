# DECOY: СТАТИЧЕСКИЕ ШАБЛОНЫ
# =====================================================================
# записать шаблон, только если его ещё нет — повторные запуски ничего не перезаписывают
tpl_write() {
  [[ -s "$1" ]] && return 0
  cat > "$1"
}

decoy_templates_init() {
  mkdir -p "$DECOY_TPL_DIR" 2>/dev/null || true
  local sig_before; sig_before=$(dir_sig "$DECOY_TPL_DIR")

  # honeypot-ссылки: невидимы для человека, но их парсят боты → путь /admin,
  # /wp-login.php, /.env → nginx отдаёт 404 в лог decoy-access → fail2ban банит
  local honey='<a href="/admin" style="position:fixed;left:-9999px;top:-9999px" aria-hidden="true" tabindex="-1">admin</a>
<a href="/wp-login.php" style="position:fixed;left:-9999px;top:-9999px" aria-hidden="true" tabindex="-1">wp login</a>
<a href="/.env" style="position:fixed;left:-9999px;top:-9999px" aria-hidden="true" tabindex="-1">env</a>'

  tpl_write "$DECOY_TPL_DIR/default.html" <<HTML
<!doctype html><html><head><meta charset="utf-8"><title>Welcome to nginx!</title>
<style>body{font-family:sans-serif;background:#f4f4f4;text-align:center;padding-top:80px;color:#333}
h1{color:#2b6cb0}p{color:#666}</style></head>
<body><h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and working.</p>
$honey</body></html>
HTML

  tpl_write "$DECOY_TPL_DIR/blank.html" <<'HTML'
<!doctype html><html><head><meta charset="utf-8"><title> </title></head><body></body></html>
HTML

  # corporate: случайные год основания и слоган — домены не выглядят близнецами
  local cy=$(( 1998 + RANDOM % 20 ))
  local ctg; case $(( RANDOM % 3 )) in
    0) ctg="Building the future of infrastructure." ;;
    1) ctg="Reliable software for ambitious teams." ;;
    2) ctg="Engineering clarity into complex systems." ;;
  esac
  tpl_write "$DECOY_TPL_DIR/corporate.html" <<HTML
<!doctype html><html><head><meta charset="utf-8"><title>Corp — Solutions</title>
<style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:-apple-system,sans-serif;color:#111;line-height:1.6}
nav{padding:20px 40px;border-bottom:1px solid #eee;display:flex;justify-content:space-between}nav a{color:#111;text-decoration:none;margin-left:24px;font-size:14px}
.logo{font-weight:600;font-size:18px}.hero{padding:100px 40px;max-width:1100px;margin:auto}
h1{font-size:52px;font-weight:600;letter-spacing:-1px;margin-bottom:24px}p.lead{font-size:20px;color:#555;max-width:600px}
.btn{display:inline-block;margin-top:32px;padding:14px 28px;background:#111;color:#fff;text-decoration:none;border-radius:6px}
footer{padding:40px;border-top:1px solid #eee;color:#888;font-size:13px;text-align:center}</style></head><body>
<nav><div class="logo">Corp</div><div><a href="#">Product</a><a href="#">Solutions</a><a href="#">Contact</a></div></nav>
<div class="hero"><h1>$ctg</h1>
<p class="lead">We help enterprises scale with confidence.</p><a href="#" class="btn">Learn more</a></div>
<footer>© $cy Corp Inc. All rights reserved.</footer>
$honey</body></html>
HTML

  # blog: случайные даты постов — каждая генерация чуть другая
  local bd1 bd2
  bd1=$(date -d "-$(( RANDOM % 18 + 2 )) days" '+%B %-d, %Y' 2>/dev/null || date '+%B %d, %Y')
  bd2=$(date -d "-$(( RANDOM % 55 + 25 )) days" '+%B %-d, %Y' 2>/dev/null || date -d '-30 days' '+%B %d, %Y')
  tpl_write "$DECOY_TPL_DIR/blog.html" <<HTML
<!doctype html><html><head><meta charset="utf-8"><title>Notes</title>
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:Georgia,serif;max-width:720px;margin:auto;padding:60px 24px;color:#222;line-height:1.7}
h1{font-size:32px;margin-bottom:8px}.sub{color:#888;font-size:14px;margin-bottom:48px}article{margin-bottom:48px}
article h2{font-size:22px;margin-bottom:8px}article .meta{color:#888;font-size:13px;margin-bottom:12px}article p{color:#444}</style></head><body>
<h1>Notes</h1><p class="sub">Thoughts on software, systems, and craft.</p>
<article><h2>On simple systems</h2><div class="meta">$bd1</div>
<p>The best systems are the ones you can hold in your head.</p></article>
<article><h2>The quiet majority</h2><div class="meta">$bd2</div>
<p>Most software does its job silently.</p></article>
$honey</body></html>
HTML

  tpl_write "$DECOY_TPL_DIR/docs.html" <<HTML
<!doctype html><html><head><meta charset="utf-8"><title>Documentation</title>
<style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:-apple-system,sans-serif;display:flex;color:#222}
aside{width:260px;background:#fafafa;border-right:1px solid #eee;padding:24px;min-height:100vh}
aside h2{font-size:14px;text-transform:uppercase;color:#888;margin-bottom:16px;letter-spacing:1px}
aside a{display:block;padding:6px 0;color:#444;text-decoration:none;font-size:14px}
main{padding:60px 80px;max-width:900px}h1{font-size:36px;margin-bottom:24px}
p{margin-bottom:16px;color:#444;line-height:1.7}code{background:#f4f4f4;padding:2px 6px;border-radius:3px;font-size:13px}
pre{background:#1e1e1e;color:#f8f8f8;padding:20px;border-radius:8px;overflow-x:auto;margin:20px 0}</style></head><body>
<aside><h2>Getting Started</h2><a href="#">Introduction</a><a href="#">Installation</a><a href="#">Configuration</a></aside>
<main><h1>Introduction</h1><p>Welcome to the documentation.</p>
<pre>npm install @example/sdk</pre><p>Then call <code>client.connect()</code>.</p></main>
$honey</body></html>
HTML

  tpl_write "$DECOY_TPL_DIR/cloudflare.html" <<HTML
<!doctype html><html><head><meta charset="utf-8"><title>Attention Required! | Cloudflare</title>
<style>body{font-family:sans-serif;background:#f5f5f5;color:#333;margin:0;padding:60px 20px}
.container{max-width:800px;margin:auto;background:#fff;border-radius:6px;padding:60px;box-shadow:0 2px 12px rgba(0,0,0,.06)}
h1{font-size:26px;margin-bottom:24px;color:#111}p{line-height:1.7;color:#555;margin-bottom:16px}
.footer{border-top:1px solid #eee;margin-top:40px;padding-top:20px;color:#888;font-size:13px}</style></head><body>
<div class="container"><h1>Attention Required!</h1>
<p>You are unable to access this site.</p><p>Please enable cookies and JavaScript.</p>
<div class="footer">Cloudflare Ray ID: 8a3f... &nbsp;•&nbsp; Performance &amp; security by Cloudflare</div>
</div>$honey</body></html>
HTML

  # maintenance: правдоподобное «почему не работает» — отбивает желание копать
  local mh
  mh=$(date -d "+$(( RANDOM % 3 + 2 )) hours" '+%H:%M' 2>/dev/null || echo "12:00")
  tpl_write "$DECOY_TPL_DIR/maintenance.html" <<HTML
<!doctype html><html><head><meta charset="utf-8"><title>Scheduled maintenance</title>
<style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:-apple-system,sans-serif;background:#fffde7;color:#333;display:flex;align-items:center;justify-content:center;min-height:100vh}
.card{max-width:520px;text-align:center;padding:40px}
.ic{font-size:44px;margin-bottom:12px}h1{font-size:24px;margin-bottom:14px}p{color:#666;line-height:1.7;margin-bottom:8px}
.t{font-weight:600;color:#a05a00}</style></head><body><div class="card">
<div class="ic">&#128736;</div><h1>Scheduled maintenance</h1>
<p>We are performing planned maintenance on our systems.</p>
<p>Expected back online by <span class="t">$mh</span>. Thank you for your patience.</p></div>
$honey</body></html>
HTML

  # portfolio: тихая фото-визитка, без логина — совсем не палево
  tpl_write "$DECOY_TPL_DIR/portfolio.html" <<HTML
<!doctype html><html><head><meta charset="utf-8"><title>Selected Works — A. Raven</title>
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:Georgia,serif;background:#111;color:#ddd}
header{padding:80px 40px 40px;max-width:900px;margin:auto}h1{font-size:40px;font-weight:400;letter-spacing:1px}
header p{color:#888;margin-top:10px;font-style:italic}
.grid{max-width:900px;margin:auto;padding:0 40px 80px;display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:18px}
.ph{aspect-ratio:4/3;border-radius:4px;position:relative;overflow:hidden}
.ph:nth-child(1){background:linear-gradient(140deg,#23303d,#3d5266)}.ph:nth-child(2){background:linear-gradient(140deg,#3d2f33,#66424a)}
.ph:nth-child(3){background:linear-gradient(140deg,#2d3d33,#48664f)}.ph:nth-child(4){background:linear-gradient(140deg,#38332d,#5f5744)}
.ph span{position:absolute;bottom:10px;left:12px;font-size:13px;color:#cfcfcf;opacity:.75}
footer{padding:30px;text-align:center;color:#666;font-size:13px}</style></head><body>
<header><h1>Anna Raven</h1><p>photographer &mdash; selected works, 2019&ndash;2026</p></header>
<div class="grid">
<div class="ph"><span>Nordkapp, series IV</span></div><div class="ph"><span>Harbor study 12</span></div>
<div class="ph"><span>Forest interval</span></div><div class="ph"><span>Concrete noon</span></div></div>
<footer>contact: studio@raven.example &middot; prints on request</footer>
$honey</body></html>
HTML

  # hosting-panel и shop — интерактивные (трап через $js) → живут в
  # decoy_login_templates_init, где определены $css/$js.

  # tg-домену НЕ даём отдельного шаблона в меню: мимикрия под Telegram — палево
  # (сразу видно, что за доменом tg-прокси). Сайт tproxy получает нейтральный
  # blog (ensure_tproxy_site) — не совпадающий с corporate у reality-декоев.

  [[ "$sig_before" == "$(dir_sig "$DECOY_TPL_DIR")" ]] || log "Статические decoy-шаблоны готовы"
}

# =====================================================================
# DECOY: LOGIN-ШАБЛОНЫ
# =====================================================================
decoy_login_templates_init() {
  mkdir -p "$DECOY_LOGIN_DIR" 2>/dev/null || true
  local sig_before; sig_before=$(dir_sig "$DECOY_LOGIN_DIR")
  # реплики 1:1 (окт 2026): по умолчанию НЕ сносим — шаблоны пишутся один раз
  # (рандомная версия в футере фиксируется при установке; перегенерация при
  # каждом старте только меняла блобы и шумела в логе). Принудительно
  # обновить реплики из скрипта: SMG_FORCE_TPL=1 bash stack-manager.sh
  if [[ "${SMG_FORCE_TPL:-0}" == "1" ]]; then
    rm -f "$DECOY_LOGIN_DIR/adguard.html" "$DECOY_LOGIN_DIR/portainer.html" \
          "$DECOY_LOGIN_DIR/pihole.html" "$DECOY_LOGIN_DIR/omv.html" \
          "$DECOY_LOGIN_DIR/jellyfin.html" "$DECOY_LOGIN_DIR/homeassistant.html" \
          "$DECOY_LOGIN_DIR/uptime-kuma.html" "$DECOY_LOGIN_DIR/hosting-panel.html" \
          "$DECOY_LOGIN_DIR/shop.html" 2>/dev/null || true
  fi

  local agv="0.107.$(( RANDOM % 25 + 40 ))"   # версия в футере — правдоподобная рандомизация

  local css='<style>
*{box-sizing:border-box;margin:0;padding:0}
.msg{padding:12px;border-radius:4px;margin-bottom:16px;text-align:center;font-size:14px;display:none}
.msg.err{display:block;background:#fdecea;color:#b71c1c;border:1px solid #f5c6cb}
.msg.ban{display:block;background:#fff4e5;color:#a05a00;border:1px solid #ffd8a8}
label{display:block;font-size:13px;color:#555;margin-bottom:6px}
input{width:100%;padding:11px;border:1px solid #dcdcdc;border-radius:4px;font-size:14px;margin-bottom:16px}
button{width:100%;padding:12px;border:none;border-radius:4px;font-size:15px;cursor:pointer}
</style>'

  local js='<script>
document.getElementById("form").addEventListener("submit", async e=>{
  e.preventDefault();
  try{
    await fetch("/login",{method:"POST",body:new FormData(e.target)});
    showErr("Invalid credentials");
  }catch(err){showBan();}
});
function showErr(t){const el=document.getElementById("msg");el.className="msg err";el.textContent=t;}
function showBan(){
  const el=document.getElementById("msg");el.className="msg ban";
  el.textContent="Too many failed attempts. Access blocked for 2 hours.";
  document.getElementById("form").style.display="none";
}
</script>'

  tpl_write "$DECOY_LOGIN_DIR/adguard.html" <<HTML
<!doctype html><html><head><meta charset="utf-8"><title>AdGuard Home</title><link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Cpath fill='%2368b279' d='M12 2 4 5v6c0 5 3.4 9.7 8 11 4.6-1.3 8-6 8-11V5z'/%3E%3C/svg%3E">
$css<style>
body{font-family:Roboto,-apple-system,'Segoe UI',sans-serif;background:#fff;color:#3c4043;display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:100vh}
.logo{display:flex;align-items:center;gap:10px;margin-bottom:26px}
.logo svg{width:46px;height:46px}
.logo b{font-size:27px;font-weight:500;color:#3c4043}
.card{width:360px;padding:32px;background:#fff;border:1px solid #e0e0e0;border-radius:8px;box-shadow:0 1px 3px rgba(0,0,0,.08)}
input{border:1px solid #c6c6c6;border-radius:4px;padding:12px}
input:focus{border-color:#68b279;outline:none}
button{background:#68b279;color:#fff;font-weight:500;border-radius:4px}
button:hover{background:#5aa36c}
.foot{margin-top:20px;font-size:12px;color:#9aa0a6;text-align:center}
.foot span{color:#68b279;cursor:pointer}
</style></head><body>
<div class="logo"><svg viewBox="0 0 24 24"><path fill="#68b279" d="M12 2 4 5v6c0 5 3.4 9.7 8 11 4.6-1.3 8-6 8-11V5l-8-3z"/><path fill="#fff" d="M10.6 14.9l-2.9-2.9 1.2-1.2 1.7 1.7 4.5-4.5 1.2 1.2-5.7 5.7z"/></svg><b>AdGuard Home</b></div>
<div class="card">
<div id="msg" class="msg"></div>
<form id="form" method="POST" action="/login">
<label>Username</label><input name="u" required autocomplete="off">
<label>Password</label><input name="p" type="password" required>
<button>Sign in</button>
</form></div>
<div class="foot">AdGuard Home v$agv · <span>Homepage</span> · <span>Report issue</span></div>
$js</body></html>
HTML

  tpl_write "$DECOY_LOGIN_DIR/portainer.html" <<HTML
<!doctype html><html><head><meta charset="utf-8"><title>Portainer</title><link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Crect width='24' height='24' rx='5' fill='%2313bef9'/%3E%3Cpath fill='%23fff' d='M5 8h9v3.5H5V8zm0 5.5h9V17H5v-3.5zm11-5.5h3v3.5h-3V8zm0 5.5h3V17h-3v-3.5z'/%3E%3C/svg%3E">
$css<style>
body{font-family:'Segoe UI',Roboto,-apple-system,sans-serif;background:#eceff1;color:#333;display:flex;align-items:center;justify-content:center;min-height:100vh}
.card{background:#fff;padding:40px 36px;width:400px;border-radius:4px;box-shadow:0 1px 4px rgba(0,0,0,.14)}
.logo{width:56px;height:56px;background:#13bef9;border-radius:12px;display:flex;align-items:center;justify-content:center;margin:0 auto 18px}
.logo svg{width:32px;height:32px}
h1{font-size:24px;font-weight:400;color:#333;text-align:center;margin-bottom:26px}
button{background:#2b7fd4;color:#fff;font-weight:500}
button:hover{background:#246cb4}
</style></head><body><div class="card">
<div class="logo"><svg viewBox="0 0 24 24"><path fill="#fff" d="M4 7h10v4H4V7zm0 6h10v4H4v-4zm12-6h4v4h-4V7zm0 6h4v4h-4v-4z"/></svg></div>
<h1>Portainer</h1>
<div id="msg" class="msg"></div>
<form id="form" method="POST" action="/login">
<label>Username</label><input name="u" required autocomplete="off">
<label>Password</label><input name="p" type="password" required>
<button>Log in</button>
</form></div>$js</body></html>
HTML

  tpl_write "$DECOY_LOGIN_DIR/pihole.html" <<HTML
<!doctype html><html><head><meta charset="utf-8"><title>Pi-hole - Admin Console</title><link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Ccircle cx='12' cy='12' r='10' fill='%23c0392b'/%3E%3Ccircle cx='12' cy='12' r='5' fill='%23fff'/%3E%3Ccircle cx='12' cy='12' r='2' fill='%23c0392b'/%3E%3C/svg%3E">
$css<style>
body{font-family:'Helvetica Neue',Arial,sans-serif;background:#f5f6f7;color:#333;display:flex;align-items:center;justify-content:center;min-height:100vh}
.card{background:#fff;padding:36px 40px;width:400px;border-radius:6px;border:1px solid #e2e4e6;box-shadow:0 1px 4px rgba(0,0,0,.06)}
.logo{display:flex;align-items:center;gap:12px;margin-bottom:24px;justify-content:center}
.logo svg{width:44px;height:44px}
.logo b{font-size:28px;font-weight:600;color:#2b3033}
.logo b i{font-style:normal;color:#c0392b}
input{border:1px solid #ccc;border-radius:3px;padding:10px}
button{background:#3c8dbc;color:#fff;border-radius:3px}
button:hover{background:#3579a8}
</style></head><body><div class="card">
<div class="logo"><svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10" fill="#c0392b"/><circle cx="12" cy="12" r="6" fill="#fff"/><circle cx="12" cy="12" r="2.5" fill="#c0392b"/></svg><b>Pi-<i>hole</i></b></div>
<div id="msg" class="msg"></div>
<form id="form" method="POST" action="/login">
<label>Password</label><input name="p" type="password" required>
<button>Log in</button>
</form></div>$js</body></html>
HTML

  tpl_write "$DECOY_LOGIN_DIR/omv.html" <<HTML
<!doctype html><html><head><meta charset="utf-8"><title>openmediavault - Login</title><link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Crect width='24' height='24' rx='5' fill='%235d7789'/%3E%3Cpath fill='%23fff' d='M7 14a5 5 0 1 1 10 0h-2a3 3 0 1 0-6 0H7z'/%3E%3C/svg%3E">
$css<style>
body{font-family:'Segoe UI',Roboto,sans-serif;background:#262c31;color:#e8eaed;display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:100vh}
.brand{font-size:30px;font-weight:300;color:#fff;margin-bottom:6px;letter-spacing:.5px}
.brand i{font-style:normal;color:#5d9cec}
.sub{font-size:13px;color:#8a939b;margin-bottom:28px}
.card{background:#31373d;width:400px;padding:36px 32px;border-radius:6px;box-shadow:0 4px 18px rgba(0,0,0,.35)}
label{color:#b8bfc6}
input{background:#262c31;border:1px solid #454d54;color:#e8eaed;border-radius:4px}
input:focus{border-color:#5d9cec;outline:none}
button{background:#5d7789;color:#fff;border-radius:4px}
button:hover{background:#4d6575}
</style></head><body>
<div class="brand">openmediavault<i>.</i></div>
<div class="sub">Network Attached Storage Solution</div>
<div class="card">
<div id="msg" class="msg"></div>
<form id="form" method="POST" action="/login">
<label>Username</label><input name="u" required autocomplete="off">
<label>Password</label><input name="p" type="password" required>
<button>Sign in</button>
</form></div>$js</body></html>
HTML

  tpl_write "$DECOY_LOGIN_DIR/jellyfin.html" <<HTML
<!doctype html><html><head><meta charset="utf-8"><title>Jellyfin</title><link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Ccircle cx='12' cy='12' r='10' fill='%23aa5cc3'/%3E%3Ccircle cx='12' cy='12' r='4.5' fill='none' stroke='%23fff' stroke-width='1.5'/%3E%3Ccircle cx='12' cy='12' r='1.5' fill='%23fff'/%3E%3C/svg%3E">
$css<style>
body{font-family:'Segoe UI',Roboto,-apple-system,sans-serif;background:linear-gradient(160deg,#141e2c,#0b1017);color:#fff;display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:100vh}
.logo svg{width:72px;height:72px;margin-bottom:12px}
h1{font-size:30px;font-weight:400;text-align:center;margin-bottom:24px;letter-spacing:.5px}
.card{width:340px}
label{color:#aebac9}
input{background:#1a2431;border:1px solid #2f3d4f;color:#fff;border-radius:4px}
input:focus{border-color:#52b54b;outline:none}
button{background:#52b54b;color:#fff;font-weight:500;border-radius:4px}
button:hover{background:#46a03f}
</style></head><body>
<div class="logo"><svg viewBox="0 0 24 24"><defs><linearGradient id="jg" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#aa5cc3"/><stop offset="1" stop-color="#00a4dc"/></linearGradient></defs><circle cx="12" cy="12" r="11" fill="url(#jg)"/><circle cx="12" cy="12" r="5.5" fill="none" stroke="#fff" stroke-width="1.6"/><circle cx="12" cy="12" r="1.6" fill="#fff"/></svg></div>
<h1>Jellyfin</h1>
<div class="card">
<div id="msg" class="msg"></div>
<form id="form" method="POST" action="/login">
<label>Username</label><input name="u" required autocomplete="off">
<label>Password</label><input name="p" type="password" required>
<button>Sign In</button>
</form></div>$js</body></html>
HTML

  tpl_write "$DECOY_LOGIN_DIR/homeassistant.html" <<HTML
<!doctype html><html><head><meta charset="utf-8"><title>Home Assistant</title><link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Cpath fill='%2341bdf2' d='M12 3 2 12h3v8h5v-5h4v5h5v-8h3L12 3z'/%3E%3C/svg%3E">
$css<style>
body{font-family:Roboto,'Segoe UI',sans-serif;background:#fafafa;color:#212121;display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:100vh}
.logo svg{width:64px;height:64px;margin-bottom:10px}
h1{font-size:28px;font-weight:400;text-align:center;margin-bottom:26px;color:#424242}
.card{width:360px;padding:28px;background:#fff;border:1px solid #e0e0e0;border-radius:8px}
input{border:1px solid #c6c6c6;border-radius:4px;padding:12px}
input:focus{border-color:#41bdf2;outline:none}
button{background:#41bdf2;color:#fff;font-weight:500;border-radius:4px}
button:hover{background:#2cabdf}
</style></head><body>
<div class="logo"><svg viewBox="0 0 24 24"><path fill="#41bdf2" d="M12 3 2 12h3v8h5v-5h4v5h5v-8h3L12 3z"/></svg></div>
<h1>Home Assistant</h1>
<div class="card">
<div id="msg" class="msg"></div>
<form id="form" method="POST" action="/login">
<label>Username</label><input name="u" required autocomplete="off">
<label>Password</label><input name="p" type="password" required>
<button>Connect</button>
</form></div>$js</body></html>
HTML

  tpl_write "$DECOY_LOGIN_DIR/uptime-kuma.html" <<HTML
<!doctype html><html><head><meta charset="utf-8"><title>Uptime Kuma</title><link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Ccircle cx='12' cy='12' r='10' fill='none' stroke='%235cdd8b' stroke-width='2.5'/%3E%3Cpath fill='none' stroke='%235cdd8b' stroke-width='2' d='M6 12h3l2-4 2 8 2-4h3'/%3E%3C/svg%3E">
$css<style>
body{font-family:Roboto,'Segoe UI',sans-serif;background:#1b2637;color:#fff;display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:100vh}
.logo{display:flex;align-items:center;gap:10px;margin-bottom:30px}
.logo svg{width:40px;height:40px}
.logo b{font-size:24px;font-weight:600;color:#fff}
.logo b i{font-style:normal;color:#5cdd8b}
.card{width:360px;padding:32px;background:#243447;border:1px solid #2e4157;border-radius:10px}
label{color:#9fb0c0}
input{background:#1b2637;border:1px solid #33475e;color:#fff;border-radius:6px}
input:focus{border-color:#5cdd8b;outline:none}
button{background:#5cdd8b;color:#1b2637;font-weight:700;border-radius:6px}
button:hover{background:#4bcf7b}
</style></head><body>
<div class="logo"><svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10" fill="none" stroke="#5cdd8b" stroke-width="2"/><path fill="none" stroke="#5cdd8b" stroke-width="2" d="M6 12h3l2-4 2 8 2-4h3"/></svg><b>Uptime <i>Kuma</i></b></div>
<div class="card">
<div id="msg" class="msg"></div>
<form id="form" method="POST" action="/login">
<label>Username</label><input name="u" required autocomplete="off">
<label>Password</label><input name="p" type="password" required>
<button>Login</button>
</form></div>$js</body></html>
HTML

  # hosting-panel: cPanel-стиль, ловит POST /login как остальные реплики
  tpl_write "$DECOY_LOGIN_DIR/hosting-panel.html" <<HTML
<!doctype html><html><head><meta charset="utf-8"><title>Hosting Control Panel — Login</title>
$css<style>
body{font-family:Arial,Helvetica,sans-serif;background:linear-gradient(180deg,#0b2d4d,#123c66);display:flex;align-items:center;justify-content:center;min-height:100vh}
.card{background:#fff;width:400px;border-radius:8px;overflow:hidden;box-shadow:0 10px 30px rgba(0,0,0,.3)}
.head{background:#f5f7f9;padding:26px;text-align:center;border-bottom:1px solid #e3e8ec}
.logo{font-size:22px;font-weight:700;color:#0b5c8c}.logo i{font-style:normal;color:#ff6c2c}
.head small{display:block;color:#8a97a0;font-size:12px;margin-top:4px}
.body{padding:28px}
button{background:#ff6c2c;color:#fff;border-radius:4px;font-weight:600}
button:hover{background:#e85a1c}
label{color:#5a6a75;text-transform:uppercase;font-size:11px;letter-spacing:.5px}
.foot{padding:14px;text-align:center;color:#9aa7b0;font-size:12px;border-top:1px solid #e3e8ec}
</style></head><body><div class="card">
<div class="head"><div class="logo">Hosting<i>Panel</i></div><small>Client Area &middot; cPanel 110.4</small></div>
<div class="body">
<div id="msg" class="msg"></div>
<form id="form" method="POST" action="/login">
<label>Username</label><input name="u" required autocomplete="off">
<label>Password</label><input name="p" type="password" required>
<button>Log in</button>
</form></div>
<div class="foot">&copy; 2019 Hosting Solutions &middot; License v3</div></div>$js</body></html>
HTML

  # shop: «скоро открытие» — форма подписки постит в тот же трап /login
  tpl_write "$DECOY_LOGIN_DIR/shop.html" <<HTML
<!doctype html><html><head><meta charset="utf-8"><title>Ember Goods — coming soon</title>
$css<style>
body{font-family:-apple-system,sans-serif;background:#faf7f4;color:#2b2b2b;display:flex;align-items:center;justify-content:center;min-height:100vh}
.card{max-width:480px;text-align:center;padding:40px}
.logo{font-size:28px;font-weight:700;letter-spacing:3px;color:#b3541e;margin-bottom:8px}
h1{font-size:22px;font-weight:400;margin-bottom:14px}p{color:#777;line-height:1.7;margin-bottom:22px}
input{border:1px solid #ddd;border-radius:4px;padding:12px}
button{background:#b3541e;color:#fff;border-radius:4px}
.small{font-size:12px;color:#aaa;margin-top:16px}
</style></head><body><div class="card">
<div class="logo">EMBER GOODS</div>
<h1>Something warm is coming.</h1>
<p>We are putting the finishing touches on our store.<br>Leave your email to get 15% off at launch.</p>
<div id="msg" class="msg"></div>
<form id="form" method="POST" action="/login">
<input name="u" placeholder="you@example.com" required autocomplete="off">
<button>Notify me</button>
</form>
<p class="small">No spam. Unsubscribe anytime.</p></div>$js</body></html>
HTML

  chown -R www-data:www-data "$DECOY_LOGIN_DIR" 2>/dev/null || true
  [[ "$sig_before" == "$(dir_sig "$DECOY_LOGIN_DIR")" ]] || log "9 login-шаблонов установлены"
}

# =====================================================================
# FAIL2BAN
# =====================================================================
decoy_fail2ban_init() {
  command -v fail2ban-client >/dev/null 2>&1 || {
    apt-get update -y >/dev/null 2>&1 || true
    apt-get install -y fail2ban >/dev/null 2>&1 || true
  }
  touch "$DECOY_LOG_ACCESS" 2>/dev/null || true
  chown www-data:adm "$DECOY_LOG_ACCESS" 2>/dev/null || true
  chmod 640 "$DECOY_LOG_ACCESS" 2>/dev/null || true
  mkdir -p /etc/fail2ban/filter.d /etc/fail2ban/jail.d 2>/dev/null || true

  cat > /etc/fail2ban/filter.d/decoy-login.conf <<'F2B'
[Definition]
# формат decoy_ext: IP [time] "REQUEST" STATUS "UA" host=dom
failregex = ^<HOST> \[[^\]]+\] "POST /login HTTP/[0-9.]+" 401
            ^<HOST> \[[^\]]+\] "(?:GET|POST|HEAD) /(?:admin|wp-admin|wp-login\.php|\.env|\.git|api/debug|phpmyadmin|configuration\.php|actuator)(?:/|\?| )[^\"]*" \d+
ignoreregex =
F2B

  cat > /etc/fail2ban/jail.d/decoy-login.local <<EOF
[decoy-login]
enabled  = true
filter   = decoy-login
logpath  = $DECOY_LOG_ACCESS
maxretry = $DECOY_MAX_FAILS
findtime = 600
bantime  = $DECOY_BAN_SECONDS
action   = iptables-multiport[name=decoy, port="80,443"]
EOF

  systemctl enable fail2ban >/dev/null 2>&1 || true
  systemctl restart fail2ban >/dev/null 2>&1 || true
  sleep 2
  fail2ban-client status decoy-login >/dev/null 2>&1 && log "fail2ban активен" || warn "fail2ban jail не поднялся"
}

decoy_full_init() {
  decoy_templates_init || true
  decoy_login_templates_init || true
  decoy_fail2ban_init || true
  # тихий старт/decoy-init только что рестартовали юниты — дать им дожить
  # до active, иначе первый рендер шапки покажет 🔴 для живых сервисов
  local _u _t
  for _u in nginx x-ui fail2ban; do
    systemctl is-active --quiet "$_u" 2>/dev/null && continue
    for _t in 1 2 3 4 5 6 7 8 9 10; do
      sleep 0.5
      systemctl is-active --quiet "$_u" 2>/dev/null && break
    done
  done
}

# =====================================================================
