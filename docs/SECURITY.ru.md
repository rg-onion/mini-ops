# Security & Alerting (Безопасность и Оповещения)

Mini-Ops включает в себя встроенную систему аудита и мониторинга безопасности сервера.

## 🛡️ Security Audit

Модуль `SecurityAuditor` проверяет критические настройки сервера на соответствие лучшим практикам безопасности.

### Проверки (Checks)

1.  **SSH Root Login**:
    *   **Проверяет**: файл `/etc/ssh/sshd_config`.
    *   **Правило**: `PermitRootLogin` не должен быть `yes`.
    *   **Риск**: Разрешает прямой вход `root` по паролю, что уязвимо для брутфорса.

2.  **Firewall (UFW)**:
    *   **Проверяет**: наличие UFW в стандартных расположениях:
        - `/usr/sbin/ufw`
        - `/usr/bin/ufw`
        - `/sbin/ufw`
        - `/bin/ufw`
    *   **Запускает**: `ufw status` для проверки активности
    *   **PASS**: UFW активен
    *   **FAIL**: UFW установлен, но отключен
    *   **WARN**: UFW не найден или команда не может быть выполнена (например, из-за недостатка прав)

3.  **Docker Socket**:
    *   **Проверяет**: права доступа к `/var/run/docker.sock`.
    *   **Правило**: Не должен быть доступен для записи всем (`o+w`).
    *   **Риск**: Любой пользователь с доступом к сокету получает права root на хосте.

4.  **Disk Encryption**:
    *   **Проверяет**: наличие разделов типа `crypt` через `lsblk`.
    *   **Правило**: Наличие шифрования (LUKS).
    *   **Риск**: Физическая кража дисков.

5.  **Fail2Ban Status**:
    *   **Проверяет**: активность сервиса `fail2ban` через `systemctl`.
    *   **Риск**: Без Fail2Ban сервер уязвим к автоматизированному брутфорсу паролей.
    *   **Не проверяет**: состояние отдельных jail-правил.

6.  **SSH Password Auth**:
    *   **Проверяет**: файл `/etc/ssh/sshd_config`.
    *   **Правило**: `PasswordAuthentication` должен быть установлен в `no`.
    *   **Риск**: Вход по паролю менее безопасен, чем по SSH ключам.

7.  **Listening Ports**:
    *   **Проверяет**: открытые TCP/UDP порты через `ss -H -tuln`.
    *   **Правило**: Только ожидаемые порты `22`, `80`, `443`, `APP_PORT` (`3000` по умолчанию) и `DEPLOY_NGINX_PORT` (`8090` по умолчанию) должны быть открыты.
    *   **Риск**: Лишние открытые порты увеличивают поверхность атаки.

8.  **Docker TCP API**:
    *   **Проверяет**: открытые Docker API порты `2375`/`2376`.
    *   **Риск**: Открытый Docker API может дать контроль над хостом.

9.  **Docker Container Hardening**:
    *   **Проверяет**: container hardening risks, если Docker доступен агенту.
    *   **Риск**: Привилегированные или опасно настроенные контейнеры расширяют blast radius.

## 🔒 SSH Security & Alerts

Mini-Ops обеспечивает мониторинг SSH-подключений через PAM hook. При старте агент генерирует случайный internal token, записывает его в `MINI_OPS_INTERNAL_TOKEN_FILE`, а hook читает этот файл и отправляет localhost request в Mini-Ops API. Повторные уведомления о SSH-входах ограничиваются по source IP. Подробное описание в [SSH_ALERTS.ru.md](SSH_ALERTS.ru.md).

## API Exposure

Mini-Ops не ограничивает частоту запросов ко всем API routes самостоятельно. Если dashboard доступен вне trusted network, используйте reverse proxy, VPN или edge-сервис с TLS и request throttling.

## Web-triggered updates

Endpoint `POST /api/deploy/webhook` остается защищенным через `AUTH_TOKEN`, но
по умолчанию выключен. Включайте `MINI_OPS_ALLOW_WEB_UPDATE=true` только если
этот хост должен принимать обновления из dashboard.

Когда флаг включен, Mini-Ops запускает `scripts/update.sh` из локального git
checkout. Скрипт отказывается работать вне git checkout и при tracked local
changes, использует `git pull --ff-only`, ставит frontend dependencies из
lockfile при наличии и собирает backend через `cargo build --release --locked`.
Одновременно может идти только одно обновление, а `/api/deploy/logs` отдает
последние строки update logs через SSE.

## События безопасности

Mini-Ops сохраняет результаты аудита безопасности как локальные события в SQLite. События создаются, когда проверка возвращает `FAIL` или `WARN`, обновляются пока проблема активна и закрываются, когда проверка снова возвращает `PASS`.

- Активные события отображаются на странице Security.
- Открытое событие можно принять, чтобы снизить шум, но сохранить evidence.
- Закрытые события хранятся `SECURITY_EVENTS_RETENTION_HOURS` часов (`168` по умолчанию).
- Telegram-уведомления отправляются только когда failed-проверка открывается/переоткрывается и когда она закрывается.

## Локальное хранение данных

Mini-Ops ограничивает локальную operational history, чтобы SQLite база не росла
бесконечно на маленьких VPS:

- Метрики старше `METRICS_RETENTION_HOURS` периодически удаляются (`168` часов
  по умолчанию).
- История SSH-входов старше `SSH_LOGINS_RETENTION_DAYS` удаляется при записи
  новых SSH login events (`90` дней по умолчанию).
- Закрытые security events используют `SECURITY_EVENTS_RETENTION_HOURS`, как
  описано выше.

Приложение создает индексы `metrics(timestamp)`, `ssh_logins(timestamp)` и
`ssh_logins(ip, timestamp)` для retention и history queries. Удаление старых
строк не обязано сразу уменьшать размер SQLite-файла; если нужно вернуть место
на диске, запускайте `VACUUM` вручную во время maintenance window.

## Runtime controls для аудита

Работа security audit ограничена локальными runtime-настройками:

- `SECURITY_AUDIT_INTERVAL_SECS` управляет interval фонового monitor
  (`300` секунд по умолчанию, минимум `60`).
- `SECURITY_AUDIT_CACHE_TTL_SECS` кэширует ответы `/api/security/audit` для
  dashboard/API (`30` секунд по умолчанию; `0` отключает cache).
- `SECURITY_AUDIT_DOCKER_TIMEOUT_SECS` ограничивает Docker container inspection
  во время security audit (`10` секунд по умолчанию).

Если Docker inspection превышает timeout, check Docker container hardening
возвращает `WARN` с evidence о timeout вместо блокировки всего audit.

## 🔔 Alerting (Оповещения)

Система работает в фоновом режиме (проверка раз в 60 секунд) и отправляет уведомления в Telegram.

### Логика работы
*   **Инцидент**: Если статус проверки меняется с `PASS` на `FAIL` -> Шлется уведомление 🚨.
*   **Восстановление**: Если статус меняется с `FAIL` на `PASS` -> Шлется уведомление ✅.
*   **Anti-Spam**: Уведомление шлется только при **смене статуса**.

### Настройка Telegram
Для работы уведомлений убедитесь, что в `.env` заданы:
```env
TELEGRAM_BOT_TOKEN=ваш_токен
TELEGRAM_CHAT_ID=ваш_id
```

## 🌐 Безопасность развертывания (Deployment)

### Автоматизированный деплой
Скрипт развертывания (`scripts/bootstrap_server.sh`) сейчас работает так:

1. **Внутренняя привязка**: Mini-Ops по умолчанию слушает `127.0.0.1:3000`. Скрипт добавляет `APP_HOST=127.0.0.1` и `APP_PORT=3000` в deployed `.env`, если они отсутствуют.
2. **Nginx automation**: в `DEPLOY_MODE=test` generated plain-HTTP Nginx включен по умолчанию на `DEPLOY_NGINX_PORT` (`8090` по умолчанию). В `DEPLOY_MODE=production` generated Nginx выключен, если явно не задан `DEPLOY_SETUP_NGINX=1`. Сгенерированный config блокирует `/api/internal/*`.
3. **Firewall automation**: при `DEPLOY_HARDENING=1` (default) UFW разрешает OpenSSH. Dashboard ports открываются только при `DEPLOY_EXPOSE_HTTP=1` для Nginx (`DEPLOY_SETUP_NGINX=1`) или прямого test app access (`DEPLOY_SETUP_NGINX=0 DEPLOY_MODE=test`).
4. **TLS**: bootstrap script не настраивает HTTPS certificates. Для production exposure добавьте TLS через Nginx/Caddy/Cloudflare Tunnel или ограничьте доступ private network/VPN.

### Синхронизация переменных окружения (`.env`)
Скрипт развертывания собирает временный `.env` локально и загружает его на сервер по SCP:

- Если в корне проекта есть `.env`, он используется как source.
- Если `.env` нет, используется `.env.example` как template. Когда `AUTH_TOKEN`
  отсутствует или пустой, bootstrap генерирует сильный токен до загрузки.
- Overrides для `AUTH_TOKEN`, `TELEGRAM_BOT_TOKEN` и `TELEGRAM_CHAT_ID` применяются локально до загрузки, поэтому они не передаются как remote command-line arguments.
- Runtime defaults (`APP_HOST`, `APP_PORT`, `DEPLOY_NGINX_PORT`, `DATABASE_URL`, `MINI_OPS_INTERNAL_TOKEN_FILE`, `RUST_LOG`, `AGENT_LANG`, `SERVER_NAME`) добавляются на сервере только если отсутствуют.
