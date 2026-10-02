<div align="center">

# 🛰️ stack-manager

### SNI-стек «всё за 443» в одном файле

**LucX / x-ui · AdGuard Home · nginx SNI-роутер · Reality · decoy · fail2ban · UFW · Let's Encrypt**

![bash](https://img.shields.io/badge/made%20with-bash-4EAA25?logo=gnu-bash&logoColor=white)
![platform](https://img.shields.io/badge/platform-Ubuntu%20%7C%20Debian-E95420?logo=ubuntu&logoColor=white)
![port](https://img.shields.io/badge/exposed-443%20only-blue)
![license](https://img.shields.io/badge/license-MIT-green)
![deps](https://img.shields.io/badge/deps-zero%20%E2%9C%95%20builds-orange)

*Один bash-скрипт поднимает и обслуживает весь прокси-стек: от установки до починки.*
*Наружу смотрит единственный порт — 443. Всё остальное слушает 127.0.0.1.*

</div>

---

## ✨ Возможности

| | |
|:---|:---|
| 🔐 **«Всё за 443»** | Панель, подписки, DoH и все TCP-инбаунды живут за одним nginx-роутером по SNI. Наружу — только 443 и SSH. |
| 🎭 **Reality × 2** | **Чужой реалити** — маскировка под cloudflare/microsoft/sony/… (серт не нужен). **Свой SNI** — личный поддомен + LE-серт + decoy. |
| 🎯 **«Найти цели»** | Живая проверка кандидатов (TLS 1.3 + ALPN h2) и выбор цели списком — как кнопка в панели. |
| 🛡️ **AdGuard Home** | 3 режима: за корнем панели · отдельный SNI-домен · локально. DoH через 443, нативный TLS в yaml. |
| 🃏 **Decoy-заглушки 2.0** | 19 шаблонов: статика (лендинг, блог, docs, Cloudflare, техработы, портфолио, магазин) + реплики логинов 1:1 (AdGuard Home, Portainer, Pi-hole, OMV, Jellyfin, Home Assistant, Uptime Kuma, cPanel, магазин). Режимы: **redirect 302** и **locked 401**. |
| 🤖 **Анти-бот** | UA-свитч: сканерам (curl/python/nmap/…) — пустая 404, живому браузеру — сайт. Honeypot-ссылки (`/admin`, `/.env`, `/wp-login.php`) — касание = мгновенный бан. robots.txt в комплекте. |
| 📜 **Серты на автопилоте** | certbot + deploy-hook (перезапуск потребителей после renew) + таймер самолечения каждые 2 минуты. Серты только в `live/`. |
| 🚫 **fail2ban + UFW** | Баны по login-декоям и honeypot-путям; наружу открыто только необходимое, панельные порты — в DENY. |
| 🩹 **Самолечение** | hosts-починка, ре-привязка сертов, восстановление потерянных портов инбаундов и tg-маршрута, чистка мёртвых SNI-записей — само, без рук. |
| 🩺 **Диагностика** | п.20 «Доктор»: сервисы, порты, серты, UFW, DNS всех доменов, таймер — разово или непрерывно. п.21 «Инбаунды live»: таблица в реальном времени (слушается/серт/клиенты/трафик). |
| ⌨️ **Удобство** | `q` в любом вопросе → возврат в меню. Порты: запрет 443/80 и проверка занятости. URL подписок без `:443`. Плейсхолдеры `*.example.com` в меню не проходят. |

## 🗺️ Как это устроено

```mermaid
flowchart LR
    C(("🌍 Клиент")) -->|" :443 "| NGINX["nginx · SNI-роутер<br>(единственный открытый порт)"]

    NGINX -->|"SNI: panel.dom"| PANEL["🖥️ x-ui панель<br/>127.0.0.1"]
    NGINX -->|"SNI: panel.dom/sub"| SUBS["📨 Подписки<br/>127.0.0.1"]
    NGINX -->|"SNI: panel.dom"| AGH["🛡️ AdGuard Home + DoH"]
    NGINX -->|"SNI: цель (reality)"| INB1["⚡ VLESS Reality<br/>127.0.0.1"]
    NGINX -->|"SNI: r. / rx. / nn. …"| INB2["🔌 naive · anytls · trusttunnel<br/>127.0.0.1"]
    NGINX -->|"прочие SNI"| DECOY["🃏 Decoy-заглушка"]

    style NGINX fill:#1f6feb,color:#fff
    style C fill:#238636,color:#fff
```

## 🚀 Быстрый старт

```bash
# 1. залить на сервер
scp ./stack-manager.sh root@SERVER:/root/stack-manager.sh

# 2. запустить
ssh root@SERVER
bash /root/stack-manager.sh
```

> [!TIP]
> Нужны: Ubuntu 22.04+/Debian 11+, root, домен с A-записью на сервер, открыты **22** и **443**.
> Дальше — п.1: скрипт сам поставит nginx, certbot, LucX, AdGuard, fail2ban и задаст вопросы по порядку:
> **панель (пароль/порты) → AdGuard (да/нет) → заглушка панели → инбаунды** (у каждого: свой/чужой reality → SNI → порт → своя заглушка).

## 📋 Меню

<details>
<summary><b>Развернуть все 21 пунктов</b></summary>

| Пункт | Действие |
|:---:|---|
| **1** | Первичная настройка SNI-роутера |
| **2** | Добавить / проверить inbound · создать · починить reality-dest |
| **3** | Удалить inbound (список всех, включая UDP; SNI-домены как маркеры) |
| **4** | Сменить decoy: 19 шаблонов + режимы redirect/locked + вопрос «прятать от ботов?» |
| **5** | Каталог decoy-шаблонов · пересборка всех блоков · «проверить как посторонний» (человек vs сканер) |
| **6** | Статус + доступы (URL панели / AdGuard / DoH, логины, пароли) |
| **7** | Безопасность: баны fail2ban, деко-логины, whitelist · статистика decoy-посещений за 24ч · «забанить всех, кто открывал decoy» |
| **8–9** | Бэкап / восстановление конфигурации |
| **10** | Сертификаты: renew, dry-run, wildcard, выпуск через панель |
| **11–12** | Файрвол: только нужные порты / восстановление из снимка |
| **13** | Установить панель LucX UI |
| **14** | Установить AdGuard Home |
| **15** | Очистка SNI от записей без инбаундов (tg-маршрут восстанавливается сам) |
| **16** | Удалить AdGuard Home |
| **17** | Удалить панель → сразу предложить переустановку стека |
| **18** | Сменить пароли admin (панель / AdGuard, с проверкой наличия) |
| **19** | Обновить сам скрипт (raw.githubusercontent с cache-buster) |
| **20** | Доктор: сервисы, порты, серты, UFW, DNS всех доменов, heal-таймер — разово или режим наблюдения |
| **21** | Инбаунды live: таблица (слушается/серт/клиенты/трафик) — UDP по протоколу, port-hopping как `✓*` |
| **0 / q** | Выход · `q` в любом вопросе — выход в меню |

</details>

## 🧠 Принципы

- **Один порт.** Наружу только 443: меньше сигнатур, меньше пробивов.
- **Тишина для сканера.** На чужой SNI — живая заглушка или прокси на настоящую цель, а не «connection refused».
- **Ничего лишнего в памяти.** Панель держит состояние in-memory — поэтому любая правка БД идёт по схеме *stop → edit → start*.
- **Секреты не в git.** Пароли генерируются на сервере: `/root/panel-credentials.txt`, `/root/adguard-credentials.txt` (0600).

## 📦 Установка на сервер одной строкой

```bash
curl -fsSL https://raw.githubusercontent.com/vladufqaa/stack-manager/main/stack-manager.sh -o /root/stack-manager.sh && bash /root/stack-manager.sh
```

---

<div align="center">

**MIT** · сделано для личного сервера · используйте в соответствии с законами вашей юрисдикции

⭐ — если пригодилось

</div>
