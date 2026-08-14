# Fleet Observation Push

**Статус:** optional agent-side protocol preview; по умолчанию выключен.

**Получатель:** только origin оператора из `CLOUD_HUB_URL`.

**Hub в этом репозитории:** нет.

Mini-Ops может периодически отправлять минимизированное read-only observation
в Fleet Hub. Standalone dashboard, локальный monitoring, certificate alerts и
security checks от этой возможности не зависят.

Текущий source реализует Observation schema v1. Он заменяет старый
unversioned Cloud Push payload и route, которые передавали container
names/images, SSH login identities/IP, trusted IP, listening ports,
OS/kernel strings и agent ID из body. Эти поля намеренно не входят в v1.

> [!IMPORTANT]
> Observation v1 впервые входит в Mini-Ops v1.2.0; v1.1.0 не содержит этот
> контракт. Репозиторий пока не доказывает end-to-end Hub deployment, поэтому
> начинайте с одного явно авторизованного canary agent.

## Включение

Cloud Push запускается только при точном opt-in и двух обязательных значениях:

```env
CLOUD_PUSH_ENABLED=true
CLOUD_HUB_URL=https://fleet.example.com
CLOUD_AGENT_TOKEN=replace_with_a_show_once_agent_token
# Optional: default 300; strict range 60..86400 seconds.
CLOUD_PUSH_INTERVAL=300
```

`CLOUD_HUB_URL` должен быть HTTPS origin: только scheme, host и optional port;
credentials, path, query и fragment отклоняются. Mini-Ops добавляет:

```text
/api/v1/agent-observations
```

`CLOUD_PUSH_ALLOW_HTTP=true` работает только с `localhost` или loopback IP для
local development. Он не разрешает plaintext delivery на другой VPS.

Если `CLOUD_PUSH_ENABLED` отсутствует, пуст или не равен точной строке `true`,
Fleet HTTP client и push task не создаются. Некорректная явная конфигурация
выключает push task и пишет только закрытый configuration error code.

## Данные Observation v1

| Раздел | Что передаётся | Зачем |
|---|---|---|
| Envelope | schema version, случайный observation UUID, время observation, версия Mini-Ops | Выбор контракта и idempotency |
| `system` | время collection, CPU, RAM/disk counters в bytes, load averages, uptime | Обзор здоровья сервера |
| `security` | availability state; только для свежего complete snapshot — score и PASS/WARN/FAIL counts | Bounded summary security posture |
| `certificates` | состояние collector, interval и до 32 summary настроенных TLS targets | Fleet-wide контроль expiry и ошибок реально обслуживаемых сертификатов |

Для каждого certificate target v1 может передать stable target ID, настроенный
TLS `server_name`, port, freshness, check/success timestamps, reachability,
trust, hostname, expiry, `not_after` и закрытый probe error code. Certificate
данные появляются только при отдельном включении direct-TLS monitor. См.
[SECURITY.ru.md](SECURITY.ru.md#мониторинг-tls-сертификатов).

## Данные, которые намеренно не передаются

Observation v1 не передаёт:

- local dashboard token или Fleet agent token;
- agent/server/workspace ID в body;
- SSH usernames, source IP, trusted IP или SSH history;
- container IDs, names, images, status strings, logs или environment;
- список listening ports, OS name, kernel version или local hostname;
- certificate target labels или connect hosts;
- certificate bytes/chains, SAN lists, subjects, issuers, serials,
  fingerprints, filesystem paths, private keys, PFX или secrets;
- local security evidence, remediation text, event history или Telegram data;
- file-integrity paths, hashes, observations или baselines.

Настроенный certificate `server_name` всё равно может раскрыть infrastructure
metadata. Включайте Fleet Push только для Hub, который вы контролируете или
полностью доверяете.

## Unknown и stale state

Unknown data всегда выражены явно:

- security имеет `missing`, `stale` или `degraded` без score/counts;
- certificates имеют `disabled`, `unavailable` или `enabled`;
- target имеет `pending` до первого observation и `stale` после более чем двух
  настроенных certificate intervals;
- failed target сохраняет bounded status/error fields и никогда не становится
  healthy из-за подстановки нулей вместо неизвестных значений.

Missing/degraded security snapshot больше не подавляет system и certificate
heartbeat.

## Transport behavior

- HTTPS обязателен, кроме loopback-only development override.
- Fleet delivery выполняется напрямую и не наследует process proxy settings.
- Authentication: `Authorization: Bearer <CLOUD_AGENT_TOKEN>`.
- В body нет trusted agent identity. Hub обязан связать token ровно с одной
  agent/server записью.
- `Idempotency-Key` равен UUID из body `observation_id`.
- Serialized request body ограничен 64 KiB.
- HTTP request timeout равен 10 секундам.
- Первый request отложен на один настроенный interval. Пропущенные timer ticks
  пропускаются; после delivery failure новый observation отправляется на
  следующем interval без unbounded retry loop.
- Любой HTTP `2xx` считается успехом. Authentication, rate-limit, contract,
  transport и Hub failures логируются закрытыми codes; response body и raw
  transport errors не логируются.

Точные receiver rules, JSON example, ordering requirements и test checklist:
[FLEET_INTEGRATION.ru.md](FLEET_INTEGRATION.ru.md).

## Отключение

Оставьте `CLOUD_PUSH_ENABLED=false` или удалите все `CLOUD_*` variables.
Mini-Ops остаётся полноценным standalone agent и не отправляет Fleet
observations.
