# Деплой Mini-Ops

`scripts/bootstrap_server.sh` — поддерживаемый managed installer. Legacy
entrypoints `deploy.sh` и `provision.sh` остаются выключенными и завершаются до
build, network или mutation, указывая оператору на managed bootstrap. Ниже также
сохранена ручная managed-systemd процедура.

## Tagged release archive

Поддерживаемый GitHub release asset содержит prebuilt binary по пути
`target/release/mini-ops`, tracked scripts, примеры конфигурации и публичную
документацию. Проверьте `SHA256SUMS` и GitHub attestation по
[RELEASING.ru.md](RELEASING.ru.md), затем оставьте локальную сборку выключенной:

```bash
DEPLOY_HOST=server.example \
  DEPLOY_DRY_RUN=1 \
  DEPLOY_RUN_LOCAL_BUILD=0 \
  ./scripts/bootstrap_server.sh
```

Dry run остаётся обязательным до указания host или разрешения mutation.

## Managed bootstrap

Начинайте с детерминированного dry run. Validation завершается до build, DNS,
SSH, установки пакетов или remote mutation:

```bash
DEPLOY_HOST=server.example \
  DEPLOY_DRY_RUN=1 \
  ./scripts/bootstrap_server.sh
```

Default plan собирает lockfiles, проверяет architecture артефакта, использует
strict existing-host-key policy, устанавливает non-root сервис `miniops`,
привязывает приложение к `127.0.0.1:3000` и выполняет paired backup/rollback с
проверкой service, API, SQLite path, owner и mode. Он не устанавливает Docker
или Nginx, не публикует HTTP, не меняет UFW, не добавляет Docker group и не
изменяет PAM.

Local-build mode требует Node.js `24.17.x` и npm `12.0.x`; bootstrap
отклоняет другие версии до установки dependencies. Frontend dependencies
устанавливаются со strict allowlist-policy для install scripts.

Для существующей managed installation default сохраняет и нормализует текущий
root-owned `.env`:

```bash
DEPLOY_HOST=server.example ./scripts/bootstrap_server.sh
```

Для fresh installation явно передайте сильный token и разрешите запись private
environment file. Не передавайте token через command arguments и удалите его из
environment после завершения installer:

```bash
AUTH_TOKEN="$(openssl rand -hex 32)"
export AUTH_TOKEN
DEPLOY_HOST=server.example \
  DEPLOY_WRITE_ENV=1 \
  ./scripts/bootstrap_server.sh
unset AUTH_TOKEN
```

Remote account должен быть root либо иметь passwordless `sudo`; SSH работает
non-interactive. Новый host key отклоняется, если явно не выбран
`DEPLOY_ACCEPT_NEW_HOST_KEY=1`; полученный fingerprint нужно проверить отдельно.

Каждая дополнительная mutation включается отдельно:

- `DEPLOY_INSTALL_DOCKER=1` устанавливает/включает Docker;
- `DEPLOY_ENABLE_DOCKER_INTEGRATION=1` выдаёт root-equivalent Docker group;
- `DEPLOY_SETUP_NGINX=1` создаёт loopback listener;
- `DEPLOY_NGINX_EXTRA_LISTEN_IP=172.17.0.1` добавляет один exact non-wildcard
  listener рядом с loopback, например для явно управляемого Docker edge;
  требует `DEPLOY_SETUP_NGINX=1` и несовместим с `DEPLOY_EXPOSE_HTTP=1`;
- `DEPLOY_EXPOSE_HTTP=1` дополнительно разрешает wildcard plain-HTTP listener;
- `DEPLOY_ENABLE_SSH_ALERTS=1` изменяет PAM;
- `DEPLOY_HARDENING=1` изменяет UFW и включает Fail2Ban.

UFW path не поддерживает NAT/port forwarding. Он требует validated фактический
SSH listener port, root-only snapshot, bounded systemd rollback timer, точную
проверку rules и новое независимое SSH connection перед commit. При ошибке
восстанавливаются исходные files/state и повторно проверяется SSH. При default
`DEPLOY_HARDENING=0` firewall остаётся неизменным.

Extra listen IP должен уже существовать на host к моменту запуска Nginx. Если
им владеет Docker-managed bridge, operator также должен упорядочить Nginx после
Docker (например root-owned systemd drop-in). Bootstrap после restart проверяет
exact loopback и extra sockets и отклоняет wildcard или неожиданные listeners.

## Ручная managed-systemd установка

## Локальная сборка

```bash
npm --prefix frontend ci --strict-allow-scripts
npm --prefix frontend run build
cargo build --release --locked
```

## Подготовка сервера

Зафиксируйте локальные checksums, передайте binary, unit и SSH-alert scripts в
непредсказуемый administrator-owned staging-каталог с mode `0700` и повторно
проверьте checksums на сервере:

```bash
sha256sum target/release/mini-ops scripts/mini-ops.service \
  scripts/setup_ssh_alerts.sh scripts/ssh-alert.sh
```

Для передачи используйте обычный authenticated SSH/SCP workflow. В командах
ниже `/path/to/private-upload` означает этот проверенный private staging path;
не используйте общий или предсказуемый каталог.

Создайте service account и immutable-каталог для кода и конфигурации:

```bash
sudo useradd --system --home /var/lib/mini-ops --shell /usr/sbin/nologin miniops
sudo install -d -o root -g root -m 0755 /opt/mini-ops
sudo install -d -o root -g root -m 0755 /opt/mini-ops/scripts
sudo install -o root -g root -m 0755 /path/to/private-upload/mini-ops \
  /opt/mini-ops/mini-ops
sudo install -o root -g root -m 0755 \
  /path/to/private-upload/setup_ssh_alerts.sh \
  /opt/mini-ops/scripts/setup_ssh_alerts.sh
sudo install -o root -g root -m 0755 /path/to/private-upload/ssh-alert.sh \
  /opt/mini-ops/scripts/ssh-alert.sh
```

Создайте `/opt/mini-ops/.env` с владельцем `root:root` и mode `0600`:

```env
AUTH_TOKEN=
APP_HOST=127.0.0.1
APP_PORT=3000
DATABASE_URL=sqlite:///var/lib/mini-ops/mini-ops.db
MINI_OPS_INTERNAL_TOKEN_FILE=/run/mini-ops/internal.token
```

Сгенерируйте `AUTH_TOKEN` командой `openssl rand -hex 32`. Managed startup
завершается ошибкой для отсутствующего, пустого, слабого или placeholder-токена
и никогда не создаёт state `.env`.

```bash
sudo install -o root -g root -m 0600 /path/to/prepared.env /opt/mini-ops/.env
sudo install -o root -g root -m 0644 /path/to/private-upload/mini-ops.service \
  /etc/systemd/system/mini-ops.service
sudo systemctl daemon-reload
sudo systemctl enable --now mini-ops
```

Unit создаёт приватные каталоги `/var/lib/mini-ops` и `/run/mini-ops` с
владельцем `miniops:miniops`. Код и `.env` остаются root-owned. Сервис использует
`UMask=0077`, `ProtectSystem=strict` и `ProtectHome=true`.

Проверяйте состояние без вывода секретов:

```bash
sudo systemctl status mini-ops --no-pager -l
sudo journalctl -u mini-ops --since "10 minutes ago" --no-pager -n 100
sudo stat /opt/mini-ops/mini-ops /opt/mini-ops/.env \
  /var/lib/mini-ops/mini-ops.db /run/mini-ops/internal.token
curl --fail --silent http://127.0.0.1:3000/
```

## Опциональные SSH alerts

Изменение PAM выполняется отдельным явным действием:

```bash
sudo env MINI_OPS_APP_USER=miniops \
  MINI_OPS_INTERNAL_TOKEN_FILE=/run/mini-ops/internal.token \
  DEPLOY_APP_PORT=3000 \
  /opt/mini-ops/scripts/setup_ssh_alerts.sh
```

Setup script не меняет firewall. Подробнее: [SSH_ALERTS.ru.md](SSH_ALERTS.ru.md).

## Сетевые и Docker-границы

По умолчанию сервис слушает loopback. Перед внешней публикацией отдельно
настройте TLS и reverse proxy, VPN или private network. Unit не добавляет
service account в root-equivalent группу Docker. Docker integration требует
явного administrator override и отдельной оценки риска.

Для существующей установки с mutable state под `/opt/mini-ops` нельзя заменять
только binary или unit на этот layout. Сохраните текущий сервис и state до
миграции при остановленном сервисе с проверенным backup и rollback point.

Managed-обновления продолжают сохранять существующий `history.json` как
неактивный legacy state. Работающий агент не разбирает и не дописывает этот
файл; bootstrap только сохраняет его, включает в snapshot и восстанавливает при
rollback. Администратор может отдельно архивировать или удалить его
после окончания rollback window; bootstrap не удаляет его автоматически.
