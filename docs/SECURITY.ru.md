# Security & Alerting (Безопасность и Оповещения)

Mini-Ops включает в себя встроенную систему аудита и мониторинга безопасности сервера.

## 🛡️ Security Audit

Модуль `SecurityAuditor` проверяет критические настройки сервера на соответствие лучшим практикам безопасности.

### Проверки (Checks)

1.  **SSH Root Login**:
    *   **Проверяет**: bounded effective output `sshd -T -C` для отдельного
        root context с remote TEST-NET адресами. Evaluation context сохраняется
        в evidence и не означает перебор всех возможных `Match`-веток.
    *   **Правило**: `PermitRootLogin` не должен быть `yes`.
    *   **Риск**: Разрешает прямой вход `root` по паролю, что уязвимо для брутфорса.
    *   **Fallback**: чтение `/etc/ssh/sshd_config` без разрешения
        `Include`/`Match` может дать только `WARN`, но не `PASS`.

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
    *   **Проверяет**: `/var/run/docker.sock` является реальным final Unix
        socket, а не symlink/другим типом файла, принадлежит root и имеет
        безопасные права доступа.
    *   **Правило**: Не должен быть доступен для записи всем (`o+w`).
    *   **Риск**: Любой пользователь с доступом к сокету получает права root на хосте.

4.  **Disk Encryption**:
    *   **Проверяет**: bounded JSON tree `lsblk` для фактической backing chain
        корневой файловой системы.
    *   **Правило**: `PASS` возможен только если в ancestry root mount есть
        устройство типа `crypt`; отдельный зашифрованный том этого не доказывает.
    *   **Неизвестность**: отсутствующий/неоднозначный root mount или malformed
        output даёт `WARN`.
    *   **Риск**: Физическая кража дисков.

5.  **Fail2Ban Status**:
    *   **Проверяет**: активность сервиса `fail2ban` через `systemctl`.
    *   **Риск**: Без Fail2Ban сервер уязвим к автоматизированному брутфорсу паролей.
    *   **Не проверяет**: состояние отдельных jail-правил.

6.  **SSH Password Auth**:
    *   **Проверяет**: отдельный bounded non-root `sshd -T -C` context.
    *   **Правило**: `PasswordAuthentication` и
        `KbdInteractiveAuthentication` должны быть `no`; effective `UsePAM`
        сохраняется в evidence.
    *   **Риск**: Вход по паролю менее безопасен, чем по SSH ключам.

7.  **Listening Ports**:
    *   **Проверяет**: открытые TCP/UDP порты через `ss -H -tuln`.
    *   **Сохраняет**: protocol, local address и
        loopback/wildcard/non-loopback scope. Unknown или malformed output
        всегда даёт `WARN`.
    *   **Правило**: Только ожидаемые порты `22`, `80`, `443`, `APP_PORT` (`3000` по умолчанию) и `DEPLOY_NGINX_PORT` (`8090` по умолчанию) должны быть открыты.
    *   **Риск**: Лишние открытые порты увеличивают поверхность атаки.

8.  **Docker TCP API**:
    *   **Проверяет**: TCP listeners `2375`/`2376` с учётом address scope.
        Public/wildcard listener даёт `FAIL`, loopback-only — `WARN`, а UDP с
        тем же номером порта не считается Docker TCP API.
    *   **Риск**: Открытый Docker API может дать контроль над хостом.

9.  **Docker Container Hardening**:
    *   **Проверяет**: privileged mode; host network/PID/IPC/UTS/user/cgroup
        namespaces; explicit capabilities и device access; sensitive host bind
        mounts; seccomp, no-new-privileges, unconfined system paths и effective
        AppArmor/SELinux confinement. Только closed built-in/default profile
        facts доказывают confinement. Custom/malformed profiles, incomplete
        inspect data и недоступное SELinux enforcement state остаются `WARN`;
        известный Critical/High остаётся `FAIL`, даже если другие facts
        incomplete.
    *   **Риск**: Привилегированные или опасно настроенные контейнеры расширяют blast radius.

## 🔒 SSH Security & Alerts

Mini-Ops обеспечивает мониторинг SSH-подключений через PAM hook. При старте
агент генерирует случайный internal token; managed mode атомарно записывает его
в `/run/mini-ops/internal.token`, standalone mode по умолчанию использует
`mini-ops-internal.token`. Root-owned hook выполняет bounded no-follow чтение с
правами service account и отправляет bearer только в loopback API с отключённым
proxy/curlrc behavior. Повторные уведомления ограничиваются по source IP.
Подробнее: [SSH_ALERTS.ru.md](SSH_ALERTS.ru.md).

## API Exposure

Mini-Ops не ограничивает частоту запросов ко всем API routes самостоятельно. Если dashboard доступен вне trusted network, используйте reverse proxy, VPN или edge-сервис с TLS и request throttling.

## Экспериментальная web-сборка исходников

Endpoint `POST /api/deploy/webhook` остается защищенным через `AUTH_TOKEN`, но
по умолчанию выключен. Включайте `MINI_OPS_ALLOW_WEB_UPDATE=true` только если
этот хост должен принимать экспериментальные запросы на сборку исходников.

Когда флаг включен, Mini-Ops запускает `scripts/update.sh` из локального git
checkout. Скрипт отказывается работать вне git checkout и при tracked local
changes, использует `git pull --ff-only`, ставит frontend dependencies из
lockfile при наличии и собирает backend через `cargo build --release --locked`.
Одновременно может идти только одно обновление, а `/api/deploy/logs` передаёт
через SSE bounded status events без raw command output. `MINI_OPS_WEB_UPDATE_TIMEOUT_SECS`
ограничивает runtime каждой web-сборки (`1800` секунд по умолчанию). Успешный
terminal state означает только завершение сборки исходников. Установка файла,
перезапуск сервиса, health validation и rollback выполняются вручную; dashboard
не показывает этот endpoint как готовое обновление агента.

## Очистка диска

Dashboard показывает использование диска, но не предлагает действий очистки.
Server-side endpoint выключен, если не задано точное значение
`MINI_OPS_ALLOW_DISK_CLEANUP=true`. Даже при включённом экспериментальном gate
target `docker` всегда возвращает `403 operation_unavailable` и не может
запустить `docker system prune -af`.

## События безопасности

Mini-Ops сохраняет результаты аудита безопасности как локальные события в SQLite. События создаются, когда проверка возвращает `FAIL` или `WARN`, обновляются пока проблема активна и закрываются, когда проверка снова возвращает `PASS`.

- Активные события отображаются на странице Security.
- Открытое событие можно принять, чтобы снизить шум, но сохранить evidence.
- SSH-входы с source IP вне trusted SSH baseline создают события
  `ssh.untrusted_source_ip`; добавление IP в доверенный список закрывает
  соответствующее событие.
- Закрытые события хранятся `SECURITY_EVENTS_RETENTION_HOURS` часов (`168` по умолчанию).
- Alert-worthy transition и строка Telegram delivery фиксируются одной SQLite
  transaction. Retryable ошибки переживают restart; transition считается
  доставленным только после HTTP `2xx` и `ok=true` от Telegram.
- Acknowledge события не отменяет pending delivery. Delivery state использует
  только closed error codes и не хранит bot token, chat ID, request URL или raw
  provider response.
- JSON security event содержит nullable `notification_delivery_status`, число
  попыток, время обновления и закрытый error code. Внутренний transition
  sequence наружу не выдаётся.
- JSON security event сохраняет legacy-поле `evidence_json` и добавляет typed
  envelope `evidence` с полями `schema_version`, `kind`, `data` и `error_code`.
  Для valid v1 row поле `kind` точно совпадает с `event_type`, `data` содержит
  только allowlisted поля соответствующего event kind, а `error_code` равен
  `null`; `evidence_json` является точной JSON serialization этих data.
  Unsupported или invalid stored evidence не возвращается raw: `data` равен
  `null`, `error_code` равен `unsupported_schema_version` или
  `invalid_stored_payload`, а legacy-поле содержит точную строку `{}`.
  Projection не переписывает сохранённую row.

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

Docker audit использует один внутренний deadline и bounded projections: не
более `256` containers; для каждого проверяемого container — по `256`
capabilities, mounts и entries в каждой категории devices плюс `64` security
options; `64` daemon security options; `128` сохранённых глобальных risk rows.
Overflow/timeout даёт
closed incomplete evidence, а не clean result. Риски, найденные до deadline,
сохраняются, поэтому известный `FAIL` не понижается из-за более позднего
timeout. Docker daemon error bodies не копируются в API responses или
application logs.

API, background monitor и optional Cloud Push используют один общий
language-neutral single-flight snapshot аудита. Concurrent refresh-запросы
присоединяются к одному collection, а смена языка API не запускает probes
повторно. Body существующего `/api/security/audit` остаётся массивом; успешный
ответ добавляет headers `X-Security-Collector-Epoch`,
`X-Security-Generation`, `X-Security-Collected-At` и
`X-Security-Collection-Status`. Если в bounded collection window не появился
новый publishable snapshot, route возвращает `503` с кодом
`security_audit_unavailable`, а не устаревший healthy result.

Unknown или incomplete facts остаются видимыми как `WARN` и помечают snapshot
как `degraded`. Cloud Push только читает snapshot и пропускает push, если он
отсутствует, degraded или старше удвоенного audit interval: текущий security
payload не умеет честно представить unknown values без misleading zero/healthy
полей.

## Контроль целостности sensitive files

Polling целостности sensitive files — отдельный opt-in collector. Он включается
через `SECURITY_FILE_INTEGRITY_ENABLED=true`; default — `false`. Collector
обязан работать от непривилегированного service account. Явное включение при
effective UID `0` fail-closed завершает startup с redacted code
`unsupported_runtime_identity` до создания integrity tables, worker task или
чтения файлов. Shipped managed unit работает как `miniops` и сохраняет
`ProtectHome=true`.

Начальный allowlist включает `/etc/passwd`, `/etc/group`, `/etc/sudoers`,
`/etc/ssh/sshd_config`, `/etc/crontab` и direct children каталогов
`/etc/sudoers.d`, `/etc/ssh/sshd_config.d`, `/etc/cron.d`,
`/etc/cron.daily`, `/etc/cron.hourly` и `/etc/cron.weekly`. Collector не делает
recursion, не следует symlink, не читает devices/FIFO/sockets и не обходит
network/FUSE или unclassified filesystems. Permission denial, небезопасный тип
файла, неизвестная файловая система, timeout или превышение лимита дают
`degraded` coverage, но никогда clean result. Authorized keys в home/root
намеренно не входят в эту low-privilege boundary.

Первый допустимый scan создаёт локальный trust-on-first-use baseline. Contents
обычных файлов на каждом scan потоково хешируются SHA-256; 32-byte digest
хранится только в private SQLite integrity tables. Contents, excerpts, digests,
symlink targets и raw OS/SQL errors не возвращаются через API и не попадают в
security-event evidence, Telegram или Cloud Push. Drift metadata или content
создаёт bounded event `file.sensitive_changed`. Acknowledge оставляет incident
активным и никогда не меняет baseline.

Authenticated Security page и API показывают aggregate states `disabled`,
`initializing`, `healthy`, `drift` и `degraded`. Принятие полного current
snapshot — отдельное подтверждаемое whole-snapshot действие с CAS baseline и
observation generations; stale запрос получает `409`. Логическая corruption
baseline требует отдельного подтверждаемого re-enrollment и свежего complete
observation. Оба действия никогда не запускаются автоматически после package
update. Структурная SQLite corruption остаётся restore-from-backup condition.

`SECURITY_FILE_INTEGRITY_INTERVAL_SECS` по умолчанию равен `300` и clamp-ится в
`60..86400`. Каждый single-flight scan ограничен `256` distinct path IDs,
`1 MiB` на файл, `8 MiB` суммарно, streaming buffer `64 KiB` и deadline
`15 секунд`. Current baseline/observation имеют encoded cap `256 KiB` и не
создают per-poll history. Unchanged healthy scan не пишет SQLite. Collector не
добавляет check в общий audit, не меняет security score и не расширяет Cloud
Push schema.

## Baseline listening ports

Mini-Ops показывает listening sockets, которые не входят в локальный baseline
ожидаемых портов. Он различает public/wildcard listeners и loopback-only
listeners, не меняет firewall rules и не закрывает порты.

Встроенный baseline включает:

- public/wildcard: `22`, `80`, `443`, `DEPLOY_NGINX_PORT` (`8090` по умолчанию)
- loopback-only: `APP_PORT` (`3000` по умолчанию)

Добавляйте ожидаемые для конкретного сервера порты отдельно для public и
loopback baseline:

```env
SECURITY_ALLOWED_PUBLIC_PORTS=81,82,86
SECURITY_ALLOWED_LOOPBACK_PORTS=53,5435,9001
```

Некорректные значения переводят port check в `WARN`. Evidence содержит только
closed configuration error code и количество ошибок, но не raw env value.

## 🔔 Alerting (Оповещения)

Система работает в фоновом режиме с interval из `SECURITY_AUDIT_INTERVAL_SECS`
и отправляет уведомления в Telegram.

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

### Deployment boundary

Поддерживаемый managed bootstrap проверяет детерминированный dry run до build
или network activity. Defaults привязывают приложение к loopback, оставляют
code/config root-owned, используют private state/runtime directories и не
меняют firewall, public HTTP, PAM, Docker installation или root-equivalent
Docker-group access. Каждое расширение явно opt-in; UFW option использует
bounded rollback timer и новое SSH connection перед commit. Legacy
`deploy.sh`/`provision.sh` остаются hard-stop. См. [DEPLOY.ru.md](DEPLOY.ru.md).
