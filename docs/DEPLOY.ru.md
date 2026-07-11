# Деплой Mini-Ops

Legacy-скрипты автоматического деплоя в этой версии выключены. Они завершаются
до сборки, SSH-подключения, установки пакетов, изменения firewall, настройки PAM
или перезапуска сервисов. Используйте ручную managed-systemd установку ниже.

## Локальная сборка

```bash
npm --prefix frontend ci
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
MINI_OPS_ALLOW_WEB_UPDATE=false
MINI_OPS_ALLOW_DISK_CLEANUP=false
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
