<p align="center">
  <img src="assets/stack-manager-logo.svg" alt="Stack Manager" width="420"/>
</p>

<h1 align="center">Stack Manager</h1>

<p align="center">
  <strong>Один сервер. Один порт 443. Полный контроль маршрутизации.</strong><br/>
  <sub>SNI-оркестратор для LucX/x-ui, Xray и nginx — установка, настройка, аудит, обслуживание и откат в одном Bash-файле</sub>
</p>

<p align="center">
  <a href="https://github.com/vladufqaa/stack-manager/releases/latest"><img src="https://img.shields.io/github/v/release/vladufqaa/stack-manager?style=flat-square&label=release" alt="Release"/></a>
  <a href="https://github.com/vladufqaa/stack-manager/actions/workflows/ci.yml"><img src="https://github.com/vladufqaa/stack-manager/actions/workflows/ci.yml/badge.svg" alt="CI"/></a>
  <img src="https://img.shields.io/badge/shellcheck-passed-4EAA25?style=flat-square&logo=gnu-bash&logoColor=white" alt="ShellCheck"/>
  <img src="https://img.shields.io/badge/Ubuntu-22.04%2B-E95420?style=flat-square&logo=ubuntu&logoColor=white" alt="Ubuntu"/>
  <img src="https://img.shields.io/badge/Debian-11%2B-A81D33?style=flat-square&logo=debian&logoColor=white" alt="Debian"/>
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="License"/>
</p>

<p align="center">
  <a href="#-что-это">Что это</a> ·
  <a href="#-как-это-работает">Как работает</a> ·
  <a href="#-возможности">Возможности</a> ·
  <a href="#-быстрый-старт">Установка</a> ·
  <a href="#-меню">Меню</a> ·
  <a href="#-диагностика">Диагностика</a> ·
  <a href="#-расположение-файлов">Файлы</a>
</p>

---

## 🧭 Что это

**Stack Manager** — управляющий слой над панелью LucX/x-ui, Xray и nginx. Он не заменяет панель, а приводит связанные конфигурации к согласованному состоянию: базу SQLite, SNI-карту nginx, CDN-профили, decoy-заглушки, сертификаты и firewall.

> [!TIP]
> Ключевой принцип: **сначала проверка, затем изменение**. Read-only аудит ничего не трогает и показывает рассогласования; любое исправление — только после явного выбора в меню.

## 🏗 Как это работает

<p align="center">
  <img src="assets/architecture-ru.svg" alt="Архитектура Stack Manager" width="100%"/>
</p>

- Все TCP-сервисы мультиплексируются через единый внешний порт **443** по SNI.
- Наружу публикуются только необходимые порты; UDP-протоколы работают напрямую и проверяются отдельно.
- Stack Manager управляет не только входящими соединениями, но и всеми связанными артефактами: SQLite, nginx, SNI-map, CDN-профилями, сертификатами и decoy.

## ✨ Возможности

| | |
|---|---|
| 🎯 **SNI-мультиплексирование** | TCP-сервисы за единым внешним `443` через nginx stream |
| 🛰 **VLESS Reality и TLS** | Внешняя цель или собственный SNI + HTTPS-decoy |
| 🌐 **XHTTP через CDN** | CDN-домен, ORIGIN, path, hosts и nginx-фронтенд — один мастер, всё согласовано |
| 🎭 **Decoy-шаблоны** | Камуфляж для доменов, Reality и TLS-маршрутов + свои `index.html` |
| 🔒 **Сертификаты** | Let's Encrypt, wildcard Cloudflare DNS-01, персональные, линии A/B, аудит и продление |
| 🩺 **Аудит и самопочинка** | Полный read-only health/drift-аудит + «⚡ Проверить всё и починить» с дельтой «было → осталось» |
| 🧭 **DNS Xray** | Системный DNS, Cloudflare/Google/Quad9 DoH, self-hosted, пользовательский — с реальной DoH-проверкой перед применением |
| 🛡 **Безопасность** | UFW, fail2ban, backup, диагностика, полный откат с журналированием |

## 🚀 Быстрый старт

**Требования:** Ubuntu 22.04+ / Debian 11+, root, домен с DNS-записью на сервер, открытые SSH и 443; для wildcard — Cloudflare API Token с правом `Zone:DNS:Edit`.

```bash
curl -4 -fsSL \
  "https://raw.githubusercontent.com/vladufqaa/stack-manager/main/stack-manager.sh?ts=$(date +%s%N)-$$" \
  -o /root/stack-manager.sh
sed -i 's/\r$//' /root/stack-manager.sh
chmod 700 /root/stack-manager.sh
bash -n /root/stack-manager.sh
bash /root/stack-manager.sh
```

Или одной командой:

```bash
curl -4 -fsSL "https://raw.githubusercontent.com/vladufqaa/stack-manager/main/stack-manager.sh?ts=$(date +%s%N)-$$" \
  | tr -d '\r' > /root/stack-manager.sh && chmod 700 /root/stack-manager.sh && \
  bash -n /root/stack-manager.sh && bash /root/stack-manager.sh
```

> [!IMPORTANT]
> GitHub/raw-прокси иногда отдаёт файл с Windows-окончаниями строк `CRLF`. Шаг с `sed -i 's/\r$//'` обязателен, иначе Bash упадёт с `invalid option name` и `syntax error near $'{\r'`. Проверка: `file /root/stack-manager.sh` — в выводе не должно быть `CRLF line terminators`.

> [!NOTE]
> Пункт 1 работает в два этапа: сначала собираются параметры и показывается план, изменения применяются только после подтверждения.

## 📟 Меню

```text
 1) 🧭 Установка и маршрутизация
 2) 🎭 Decoy и домены
 3) 🔒 Сертификаты
 4) 🛡️ Безопасность и firewall
 5) 💾 Бэкапы и откат
 6) 🩺 Диагностика и обслуживание
 7) ⚙️ Панель и AdGuard
 0) Выход
```

<details>
<summary><b>Дерево подменю</b></summary>

```text
1) Установка и маршрутизация
├─ 1) Первичная настройка SNI-роутера
└─ 2) Инбаунды: проверка, добавление, удаление, домены

2) Decoy и домены
├─ 1) Сменить decoy
├─ 2) Каталог decoy-шаблонов
└─ 3) Сменить домен inbound

3) Сертификаты
└─ Let's Encrypt · wildcard DNS-01 · персональные · линии A/B · аудит · продление

4) Безопасность и firewall
├─ 1) Баны, decoy-login, fail2ban
├─ 2) Правила firewall
└─ 3) Восстановить состояние firewall

5) Бэкапы и откат
├─ 1) Сделать бэкап
├─ 2) Восстановить из бэкапа
├─ 3) Откат и демонтаж стека
└─ 4) Pre-install snapshot (снимок до изменений)

6) Диагностика и обслуживание
├─ 1) ⚡ Проверить всё и починить (аудит → автопочинка → контроль)
├─ 2) Статус стека
├─ 3) Маршрутизация и диагностика
├─ 4) Полный read-only аудит стека (вкл. CDN и drift)
├─ 5) Сменить пароли LucX UI / AdGuard Home
└─ 6) Обновить скрипт

7) Панель и AdGuard
├─ 1) Управление LucX/3x-ui
├─ 2) Управление AdGuard Home
└─ 3) DNS Xray в панели LucX/3x-ui
```

</details>

### ⚡ Проверить всё и починить

Один проход из раздела 6: **read-only аудит → безопасная автопочинка найденного → контрольная проверка** с дельтой «было → осталось». Чинит детерминированное: поднимает упавшие nginx/x-ui, синхронизирует серты/decoy инбаундов, чинит CDN-drift, открывает отсутствующие UDP-правила UFW, пересобирает xray-конфиг для мёртвых сокетов. Квоты Let's Encrypt не тратит и битый nginx-конфиг вслепую не правит — только показывает причину. Перед починкой — явное подтверждение.

## 📡 Поддерживаемые инбаунды

| # | Инбаунд | Транспорт | Примечание |
|---|---|---|---|
| 1 | VLESS TCP REALITY | TCP за 443 | `xtls-rprx-vision`, внешняя цель или свой SNI |
| 2 | VLESS TCP TLS | TCP за 443 | с HTTPS-decoy |
| 3 | VLESS XHTTP (через CDN) | TCP за 443 | TLS терминирует nginx, полный CDN-профиль |
| 4 | VLESS XHTTP TLS | TCP за 443 | с HTTPS-decoy |
| 5 | VLESS XHTTP REALITY | TCP за 443 | |
| 6 | NAIVE | TCP за 443 | sidecar панели |
| 7 | TRUSTTUNNEL | TCP за 443 | sidecar панели |
| 8 | ANYTLS | TCP за 443 | sidecar панели |
| 9 | HYSTERIA2 | UDP | напрямую + правило UFW |
| 10 | QWDTT | UDP 56000 | напрямую + правило UFW |
| 11 | CSQTT | UDP 46000 | напрямую + правило UFW |
| 12 | TG WEB-PROXY | 443 → 11443 | проксирует живую цель, decoy не нужен |

TCP-инбаунды маршрутизируются через nginx по SNI; UDP — работают напрямую и проверяются отдельно правилами firewall.

## 🛰 Reality: два режима

**1) Найти внешнюю цель** — домен-кандидат проверяется на TLS 1.3 и HTTP/2 и используется как `serverNames`/`dest`; сертификат не выпускается, локальный decoy не создаётся.

**2) Указать свой SNI-домен** — собственный поддомен, выпуск/выбор сертификата, HTTPS-decoy, запись в SNI-map nginx. Сертификат и decoy можно сменить позже через раздел 2.

## 🌐 VLESS XHTTP через CDN

CDN-режим предназначен для **VLESS XHTTP без TLS внутри Xray**: TLS завершает nginx.

```text
клиент → CDN-домен:443 → CDN → ORIGIN-домен:443
       → nginx SNI → локальный TLS-фронтенд → Xray XHTTP (127.0.0.1:<порт>)
```

Мастер создаёт единый CDN-профиль и согласует: CDN-домен, ORIGIN-домен, XHTTP path, origin SNI/Host, nginx SNI-маршрут и HTTPS-decoy для ORIGIN на остальных путях. Сертификат нужен **только для ORIGIN** — на публичной стороне TLS завершает сам CDN. Провайдер CDN (Beget / Yandex Cloud / другой) выбирается в анкете и хранится в профиле.

<details>
<summary><b>Подробности CDN-схемы: совпадения, сертификаты, диагностика</b></summary>

**Что должно совпадать для рабочего подключения:**

```text
клиент:       address = CDN-домен, port = 443
XHTTP:        host = ORIGIN-домен, path = /ваш/путь
панель hosts: address/sni/host_header = CDN-домен, security = tls
nginx:        ORIGIN и CDN-домен → XHTTP path → локальный Xray-порт
```

**Правила:**

- ORIGIN должен резолвиться на сервер **до** выпуска сертификата;
- CDN-домен не добавляется в SAN сертификата Stack Manager и не используется для выпуска origin-сертификата;
- в инбаунде Xray — обычный XHTTP без `security=tls`/`reality`, без `externalProxy` (иначе трафик обойдёт nginx-маршрут);
- профили хранятся в `/root/stack-backups/cdn-profiles.tsv`; при удалении инбаунда профиль, hosts-запись и nginx-артефакты удаляются как устаревшие.

**Проверка:** `6) Диагностика → 4) Полный read-only аудит стека` проверяет базу панели, XHTTP host/path, `hosts`, SNI-map, nginx-блок, decoy, сертификат ORIGIN и реальные ответы локального фронтенда. `⚡ Проверить всё и починить` возвращает маршрут, `location ^~ <path>/`, hosts-запись и настройки профиля.

**Быстрые ручные проверки:**

```bash
nginx -t
sed -n '1,220p' /etc/nginx/streams-enabled/sni-router.conf
grep -n -A45 -B2 '# >>> cdn' /etc/nginx/sites-enabled/stack.conf
cat /root/stack-backups/cdn-profiles.tsv
```

Если клиент получает HTML decoy или ошибку `unknown version: 60` — сессионный запрос попал в заглушку вместо Xray: проверьте `location ^~ <path>/` и точное совпадение `path` клиента с профилем и `xhttpSettings.path`.

</details>

## 🎭 Decoy

Шаблоны заглушек + пользовательский `index.html`. Decoy применяется только там, где не ломает протокол: собственный Reality, панель, TCP HTTPS-часть Hysteria/Hysteria2, отдельные TCP-маршруты. **Не назначается:** внешний Reality, AnyTLS, naive/trust-tunnel (TLS терминирует sidecar), TG WEB-PROXY, UDP без отдельного TCP-входа. Если корень домена панели занят AdGuard Home, смена корневого decoy блокируется — чтобы не повредить UI и DoH.

## 🧭 DNS Xray и DoH

Настройка: `7) Панель и AdGuard → 3) DNS Xray`. Поддерживаются системный DNS, Cloudflare/Google/Quad9 DoH, self-hosted DoH панели и пользовательский endpoint.

> [!WARNING]
> Профили 5 и 6 проверяются **обязательно**: перед изменением панели скрипт делает реальный DNS-over-HTTPS запрос (HTTP 200, `RCODE=0`, наличие ответа, корректность IPv4/hostname, совпадение host с URL). Если endpoint недоступен — Xray не изменяется, панель даже не останавливается.

<details>
<summary><b>Как применяются настройки DNS</b></summary>

Настройки применяются к глобальному шаблону Xray панели:

```text
/etc/x-ui/x-ui.db
└── settings
    └── xrayTemplateConfig
```

Если `xrayTemplateConfig` отсутствует, Stack Manager безопасно создаёт его из текущего рабочего `/usr/local/x-ui/bin/config.json` — и только после проверки обязательных outbound `direct`/`blocked` и существующих `routing.rules`. Перед изменением — backup; при ошибке записи, перезапуске панели или потере DNS конфигурация откатывается. Минимальный/неполный Xray-конфиг не создаётся никогда.

**Проверка результата:**

```bash
sqlite3 -noheader /etc/x-ui/x-ui.db \
  "SELECT value FROM settings WHERE key='xrayTemplateConfig';" | \
  jq '{dns: .dns, domainStrategy: .routing.domainStrategy}'

jq '{dns: .dns, domainStrategy: .routing.domainStrategy}' \
  /usr/local/x-ui/bin/config.json
```

</details>

## 🩺 Диагностика

Раздел `6) Диагностика и обслуживание`:

```text
1) ⚡ Проверить всё и починить (аудит → автопочинка → контроль)
2) Статус стека
3) Маршрутизация и диагностика
4) Полный read-only аудит стека (вкл. CDN и drift)
5) Сменить пароли LucX UI / AdGuard Home
6) Обновить скрипт
```

Полный аудит проверяет инбаунды, hosts, SNI/nginx, CDN, decoy, сертификаты, systemd и реальные listening-сокеты — и **ничего не исправляет**.

Без меню:

```bash
bash /root/stack-manager.sh --check        # read-only полный аудит
bash /root/stack-manager.sh --self-test    # то же
```

Проверка побайтного совпадения с GitHub:

```bash
curl -4 -fsSL \
  "https://raw.githubusercontent.com/vladufqaa/stack-manager/main/stack-manager.sh?ts=$(date +%s)" \
  -o /tmp/stack-manager.remote.sh
cmp -s /root/stack-manager.sh /tmp/stack-manager.remote.sh && echo 'Файлы совпадают'
```

## 💾 Бэкапы и откат

Перед изменениями скрипт создаёт автоматические бэкапы и pre-install snapshot. Полный откат восстанавливает `x-ui.db` целиком к pre-install snapshot: Reality, CDN/XHTTP, hosts, SNI-поля, настройки панели и клиентов — к моменту снимка.

> [!WARNING]
> Полный откат удаляет изменения, сделанные **после** снимка: новые инбаунды, клиентов, настройки панели. Перед заменой базы создаётся аварийная копия текущего `x-ui.db`.

Не удаляются автоматически: AdGuard Home и сертификаты Let's Encrypt в `/etc/letsencrypt/live/`. Если pre-install snapshot отсутствует — используется выборочное восстановление доступных настроек.

**Сохранность данных:** пользовательские сертификаты и `/root/cert` не удаляются при обычном обслуживании; инбаунды и клиенты не заменяются при выборочном откате; автоматические изменения журналируются в `/root/stack-actions.log`; SQL-правки выполняются с остановкой панели, когда это необходимо; SNI-map проверяется перед добавлением маршрутов; `q` в любом вопросе возвращает в меню.

## 📍 Расположение файлов

| Путь | Назначение |
|---|---|
| `/root/stack-manager.sh` | Основной скрипт |
| `/etc/x-ui/x-ui.db` | База LucX/x-ui |
| `/etc/nginx/streams-enabled/sni-router.conf` | SNI-map и stream-маршрутизация |
| `/etc/nginx/sites-enabled/stack.conf` | HTTP/HTTPS-конфигурация панели и decoy |
| `/var/www/decoy-templates/` | Шаблоны заглушек |
| `/root/stack-backups/` | Автоматические, pre-install бэкапы и CDN-профили |
| `/root/stack-actions.log` | Журнал действий |

<details>
<summary><b>🛟 Устранение типовых проблем</b></summary>

### `Too many levels of symbolic links`

```bash
rm -f /etc/nginx/streams-enabled/sni-router.conf
rm -f /etc/nginx/streams-available/sni-router.conf
nginx -t
```

Скрипт создаст SNI-конфиг заново как обычный файл.

### `invalid number of the map parameters`

Строки внутри `map` должны содержать ровно два значения и `;`:

```nginx
domain.example.com    inb_4_backend;
```

```bash
sed -n '1,160p' /etc/nginx/streams-enabled/sni-router.conf
```

Обновлённый скрипт очищает повреждённые строки перед добавлением нового маршрута.

### ORIGIN не проходит проверку DNS

Добавьте A/AAAA-запись ORIGIN-домена на IP сервера и дождитесь обновления DNS:

```bash
getent ahosts origin.example.com
```

Затем повторите выпуск сертификата в разделе 3.

</details>

## 🧱 Разработка

- Источник истины — модули `src/NNN-имя.sh`; числовой префикс задаёт порядок сборки.
- `./build.sh` склеивает `stack-manager.sh` из модулей; результат обязан совпадать с закоммиченным файлом байт-в-байт — это же проверяет CI.
- Правки вносятся в `src/`, затем `./build.sh`, в коммит уходят обе стороны.
- CI на каждый push/PR: `bash -n`, ShellCheck (пин 0.11.0, исключения в `.shellcheckrc`) и проверка синхронности сборки.
- Релизы: тег `v<версия>` → workflow собирает `tar.gz` и публикует релиз с заметками из [CHANGELOG.md](CHANGELOG.md).
- `stack-manager-update.sh` — вспомогательный скрипт автообновления.

## 🙏 Благодарности

Проект использует и интегрируется: [LucX UI](https://github.com/AlexeyLCP/lucx-ui) · [3x-ui](https://github.com/MHSanaei/3x-ui) · [AdGuard Home](https://github.com/AdguardTeam/AdGuardHome) · [nginx](https://nginx.org/) · [Certbot](https://certbot.eff.org/) · [fail2ban](https://github.com/fail2ban/fail2ban) · [UFW](https://launchpad.net/ufw)

Отдельная благодарность [Mannokia](https://github.com/Mannokia) за идеи и доработки: линии сертификатов A/B, wildcard-выпуск через Cloudflare DNS-01, аудит сертификатов, очистка дублей и TUI-управление firewall.

## 📄 Лицензия

MIT. Используйте программное обеспечение в соответствии с законодательством вашей юрисдикции.
