# Инструкция по деплою Mini-Ops

## Рекомендуемый путь: one-command bootstrap (Ubuntu)

Новый скрипт `scripts/bootstrap_server.sh` автоматизирует:
1. Базовый hardening (`ufw`, `fail2ban`).
2. Создание non-root пользователя сервиса (`miniops`).
3. Установку/проверку Docker (опционально).
4. Локальную сборку и выкладку бинаря.
5. Создание `.env` и systemd unit.
6. Опциональную настройку PAM hook для SSH alerts (`setup_ssh_alerts.sh`).

### Требования
1. SSH-доступ к серверу (`root` или пользователь с `sudo`).
2. Локально: `cargo`, `npm`, `ssh`, `scp`.
3. ОС сервера: Ubuntu/Debian-совместимая (используется `apt`).

### Быстрый запуск (test mode, без SSL)
```bash
DEPLOY_HOST=203.0.113.10 ./scripts/bootstrap_server.sh
```

### Важные переменные
```bash
DEPLOY_HOST=203.0.113.10
DEPLOY_SSH_USER=root
DEPLOY_SSH_PORT=22
DEPLOY_TARGET_DIR=/opt/mini-ops
DEPLOY_APP_USER=miniops
DEPLOY_MODE=test                 # test|production
DEPLOY_ENABLE_SSH_ALERTS=1       # 1|0
DEPLOY_HARDENING=1               # 1|0 (ufw + fail2ban)
DEPLOY_MINIMAL=0                 # 1|0 (skip user/systemd/.env changes)
DEPLOY_WRITE_ENV=0               # 1|0 (write .env when DEPLOY_MINIMAL=1)
DEPLOY_SYSTEMD_ONLY=0            # 1|0 (rewrite systemd unit and restart)
AUTH_TOKEN=your_strong_token     # optional but recommended
TELEGRAM_BOT_TOKEN=...           # optional
TELEGRAM_CHAT_ID=...             # optional
```

### Режимы сети
1. `DEPLOY_MODE=test`: откроет `8090/tcp` в UFW (для демо/лаба).
2. `DEPLOY_MODE=production`: не открывает `8090/tcp` (ожидается reverse proxy + HTTPS).

### Safe mode (без изменения firewall/пакетов)
```bash
DEPLOY_HOST=203.0.113.10 \
DEPLOY_HARDENING=0 \
DEPLOY_ENABLE_SSH_ALERTS=0 \
./scripts/bootstrap_server.sh
```

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
AUTH_TOKEN=your_strong_token \
./scripts/bootstrap_server.sh
```

### Systemd only (пересоздать unit и перезапустить)
```bash
DEPLOY_HOST=203.0.113.10 \
DEPLOY_SYSTEMD_ONLY=1 \
DEPLOY_APP_USER=miniops \
DEPLOY_TARGET_DIR=/opt/mini-ops \
./scripts/bootstrap_server.sh
```

### Ограничения режима Non-Root
При запуске от пользователя `miniops` некоторые функции дэшборда могут быть ограничены:
1. **System Logs**: чтение системных логов (`journalctl`) требует членства в группе `systemd-journal` или `root`.
2. **System Cleansing**: очистка системных кэшей (`apt`, `journald`) невозможна без `sudo`.
3. **Frontend Cache**: если папка `node_modules` была создана при сборке от другого юзера, очистка может не сработать (хотя в `bootstrap_server.sh` делается `chown`).
4. **Docker**: работает корректно (пользователь добавляется в группу `docker`).

Для полного доступа к системным функциям требуется настройка `sudo` правил или запуск агента от `root` (не рекомендуется).


## Legacy scripts

`scripts/deploy.sh` и `scripts/provision.sh` оставлены для совместимости,  
но для новых установок рекомендуется `scripts/bootstrap_server.sh`.
