# 🔐 SSH Alerts (Уведомления о входе по SSH)

Mini-Ops фиксирует успешные SSH-входы; уведомления для недоверенных source IP
ставятся в durable Telegram queue с bounded cooldown и retry.

## ⚙️ Как это работает

Система использует стандартный механизм **PAM (Pluggable Authentication Modules)** в Linux для перехвата событий входа.

1.  При успешном входе PAM вызывает скрипт `/usr/local/bin/ssh-alert.sh`.
2.  Скрипт читает runtime-токен авторизации из файла Mini-Ops, в managed
    systemd deployment по умолчанию `/run/mini-ops/internal.token`.
3.  Скрипт отправляет HTTP POST запрос на локальный API Mini-Ops.
    Bearer header передаётся `curl` через bounded stdin configuration, поэтому
    значение токена не попадает в process argv или логи хука. Перед чтением
    токена root hook понижает права до service account, а proxy/curlrc behavior
    для curl отключается.
4.  Backend проверяет:
    *   **Trusted source-IP baseline**: Если IP доверенный, уведомление не отправляется.
    *   **Durable suppression**: Для одного normalized IP новая occurrence
        подавляется 10 секунд либо пока предыдущая delivery остаётся live.
5.  Для недоверенного IP сообщение ставится в durable outbox; worker выполняет
    bounded provider attempt и retry.

## 🚀 Настройка (Setup)

Настройка PAM выполняется отдельной ручной операцией:

```bash
sudo env MINI_OPS_APP_USER=miniops \
  MINI_OPS_INTERNAL_TOKEN_FILE=/run/mini-ops/internal.token \
  DEPLOY_APP_PORT=3000 \
  ./scripts/setup_ssh_alerts.sh
```

### Ручная проверка
Если уведомления не приходят, проверьте логи:
```bash
journalctl -u mini-ops -f
# Также проверьте логи PAM
grep ssh-alert /var/log/syslog
```

## 🛡️ Baseline доверенных SSH source IP

В интерфейсе управления SSH можно добавить доверенные IP-источники. Этот список
является локальным baseline для SSH source IP.

- Подключения с доверенных IP записываются в историю, но Telegram-уведомление не
  отправляется.
- Подключения с недоверенных IP записываются в историю, ставят обычное SSH
  Telegram-уведомление в durable outbox и создают событие безопасности
  `ssh.untrusted_source_ip`. Outbox подавляет повтор того же normalized source
  IP на 10 секунд, а retryable delivery переживает restart.
- Добавление IP в доверенный baseline закрывает активное событие безопасности
  для этого source IP.
- Существующий флаг `notified` в SSH history означает, что occurrence принята в
  durable queue; это не доказательство provider delivery. Redacted delivery
  status хранится в связанном локальном security event.
- IP нормализуются перед сравнением, поэтому эквивалентные записи IPv6
  считаются одним адресом.

## 📊 История входов

Раздел **SSH Security** отображает последние 100 попыток входа, включая:
- Время и дату.
- Пользователя (`root`, `admin` и т.д.).
- IP адрес источника.
- Legacy queue status: occurrence была поставлена в outbox либо была
  suppressed/disabled; фактическую delivery показывает security event.

## ⚠️ Безопасность токена
Внутренний токен (`internal_token`) генерируется случайным образом (UUID v4)
при каждом запуске Mini-Ops. Managed systemd unit создаёт `/run/mini-ops` с
правами `0700`, а агент атомарно ротирует
`/run/mini-ops/internal.token` с правами `0600`.

`setup_ssh_alerts.sh` создаёт root-owned файл
`/etc/mini-ops/ssh-alert.conf` с правами `0600`. В нём находятся только
loopback URL, путь к token file и имя service account; самого bearer value там
нет. Для custom standalone deployment перед запуском setup script задайте
абсолютный `MINI_OPS_INTERNAL_TOKEN_FILE` и `MINI_OPS_APP_USER`, совпадающий с
владельцем процесса Mini-Ops. Не выводите содержимое token file при
диагностике; для проверки используйте только `stat`.
