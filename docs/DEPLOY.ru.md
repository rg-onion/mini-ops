# Инструкция по деплою Mini-Ops

## Рекомендуемый путь: one-command bootstrap (Ubuntu)

Новый скрипт `scripts/bootstrap_server.sh` автоматизирует:
1. Базовый hardening (`ufw`, `fail2ban`) при `DEPLOY_HARDENING=1`
   (default).
2. Установку Mini-Ops как systemd-сервис. По умолчанию сервис запускается от
   `root`, чтобы сохранить полный функционал VPS-control панели.
3. Установку/проверку Docker (опционально).
4. Локальную сборку и выкладку бинаря.
5. Создание `.env` и systemd unit.
6. Опциональную настройку PAM hook для SSH alerts (`setup_ssh_alerts.sh`).
7. Опциональный plain-HTTP Nginx reverse proxy при `DEPLOY_SETUP_NGINX=1`.
   В `test` mode он включен по умолчанию; в `production` mode выключен, если
   не задан явно.

### Требования
1. SSH-доступ к серверу (`root` или пользователь с `sudo`).
2. Локально: `cargo`, `npm`, `ssh`, `scp`.
3. ОС сервера: Ubuntu/Debian-совместимая (используется `apt`).

### Быстрый запуск (test mode, без SSL)
```bash
DEPLOY_HOST=203.0.113.10 ./scripts/bootstrap_server.sh
```

С default flags приложение слушает `127.0.0.1:3000`, а сгенерированный Nginx
отдает dashboard на `http://203.0.113.10:8090`.

### Важные переменные
```bash
DEPLOY_HOST=203.0.113.10
DEPLOY_SSH_USER=root
DEPLOY_SSH_PORT=22
DEPLOY_TARGET_DIR=/opt/mini-ops
DEPLOY_APP_USER=root               # root|miniops
DEPLOY_MODE=test                   # test|production
DEPLOY_SETUP_NGINX=1               # 1|0 (default: test=1, production=0)
DEPLOY_EXPOSE_HTTP=1               # 1|0 (default: test=1, production=0)
DEPLOY_NGINX_PORT=8090             # external Nginx port when enabled
DEPLOY_APP_PORT=3000               # internal app port
DEPLOY_INSTALL_DOCKER=1            # 1|0
DEPLOY_ENABLE_SSH_ALERTS=1         # 1|0
DEPLOY_RUN_LOCAL_BUILD=1           # 1|0
DEPLOY_HARDENING=1                 # 1|0 (ufw + fail2ban packages/service)
DEPLOY_MINIMAL=0                   # 1|0 (skip user/systemd/.env changes)
DEPLOY_WRITE_ENV=0                 # 1|0 (write .env when DEPLOY_MINIMAL=1)
DEPLOY_SYSTEMD_ONLY=0              # 1|0 (rewrite systemd unit and restart)
AUTH_TOKEN=<strong 32+ char token> # optional; generated if absent/empty
TELEGRAM_BOT_TOKEN=...             # optional
TELEGRAM_CHAT_ID=...               # optional
```

### Режимы сети
`DEPLOY_MODE`, `DEPLOY_SETUP_NGINX` и `DEPLOY_EXPOSE_HTTP` определяют, что
устанавливается и что открывает UFW:

1. Default `DEPLOY_MODE=test`: скрипт пишет plain-HTTP Nginx reverse proxy на
   `DEPLOY_NGINX_PORT`, и UFW разрешает этот порт при `DEPLOY_HARDENING=1`.
   Сгенерированный Nginx config блокирует `/api/internal/*`.
2. Default `DEPLOY_MODE=production`: скрипт не пишет generated Nginx и не
   открывает HTTP dashboard port, если явно не задать `DEPLOY_SETUP_NGINX=1` и
   `DEPLOY_EXPOSE_HTTP=1`.
3. При `DEPLOY_SETUP_NGINX=0 DEPLOY_MODE=test` UFW разрешает `DEPLOY_APP_PORT`
   только при `DEPLOY_HARDENING=1` и `DEPLOY_EXPOSE_HTTP=1`.
4. `DEPLOY_EXPOSE_HTTP=0` не дает скрипту добавить UFW allow rules для
   dashboard, но не заменяет TLS, VPN или external firewall policy.

Скрипт не настраивает TLS certificates. Для production добавьте HTTPS через
свой Nginx/Caddy/Cloudflare Tunnel setup или ограничьте доступ private
network/VPN.

### Reduced mutation mode
```bash
DEPLOY_HOST=203.0.113.10 \
DEPLOY_HARDENING=0 \
DEPLOY_ENABLE_SSH_ALERTS=0 \
./scripts/bootstrap_server.sh
```

Это отключает UFW/Fail2Ban hardening и PAM hook. В test mode при default
`DEPLOY_SETUP_NGINX=1` скрипт всё равно может установить/записать Nginx.
Добавьте `DEPLOY_SETUP_NGINX=0`, чтобы отключить Nginx automation, и
`DEPLOY_INSTALL_DOCKER=0`, чтобы пропустить установку Docker.

### Minimal mode (только выкладка бинаря)
```bash
DEPLOY_HOST=203.0.113.10 \
DEPLOY_MINIMAL=1 \
./scripts/bootstrap_server.sh
```

### Minimal + .env
```bash
DEPLOY_HOST=203.0.113.10 \
DEPLOY_MINIMAL=1 \
DEPLOY_WRITE_ENV=1 \
AUTH_TOKEN="$(openssl rand -hex 32)" \
./scripts/bootstrap_server.sh
```

### Systemd only (пересоздать unit и перезапустить)
```bash
DEPLOY_HOST=203.0.113.10 \
DEPLOY_SYSTEMD_ONLY=1 \
DEPLOY_APP_USER=root \
DEPLOY_TARGET_DIR=/opt/mini-ops \
./scripts/bootstrap_server.sh
```

### Режимы привилегий

Mini-Ops — локальная VPS-control панель. Режим `DEPLOY_APP_USER=root` теперь
является рекомендуемым для полного функционала: управление Docker, чтение и
очистка journal, настройка SSH/PAM alerts, проверка размеров системных
директорий и более полезный security audit. При этом важно держать
`APP_HOST=127.0.0.1`, использовать сильный `AUTH_TOKEN` и отдавать публичный
доступ через TLS-enabled reverse proxy, tunnel, private network или VPN.
Default bootstrap Nginx config работает по plain HTTP.

Режим `DEPLOY_APP_USER=miniops` остаётся как restricted-вариант. В нём некоторые
функции дэшборда могут быть ограничены:

1. **System Logs**: чтение системных логов (`journalctl`) требует членства в группе `systemd-journal` или `root`.
2. **System Cleansing**: очистка системных кэшей (`apt`, `journald`) невозможна без `sudo`.
3. **Frontend Cache**: если папка `node_modules` была создана при сборке от другого юзера, очистка может не сработать (хотя в `bootstrap_server.sh` делается `chown`).
4. **Docker**: работает корректно (пользователь добавляется в группу `docker`).


## Legacy scripts

`scripts/deploy.sh` и `scripts/provision.sh` оставлены для совместимости,  
но для новых установок рекомендуется `scripts/bootstrap_server.sh`.
