# Контракт интеграции с Fleet

Это implementation handoff для Hub, принимающего Mini-Ops Fleet Observation
v1. Документ описывает текущее поведение агента, но не утверждает, что Hub уже
существует.

## Готовность

| Surface | Текущее состояние |
|---|---|
| Mini-Ops v1 serializer и outbound client | Реализованы в current source и покрыты локальными Rust tests |
| Standalone Mini-Ops при выключенном Fleet Push | Не изменён; Fleet client/task не создаётся |
| Hub API, storage, UI, agent enrollment, token rotation | Не реализованы в этом репозитории |
| End-to-end agent -> remote Hub test | Пока не выполнялся |
| Production compatibility claim | Не заявляется; начинать нужно с одного disposable/canary agent |

Observation v1 впервые входит в Mini-Ops v1.2.0; v1.1.0 не содержит этот
контракт. До любого production compatibility claim начните с одного
disposable/canary агента v1.2.0.

## Request

```http
POST /api/v1/agent-observations HTTP/1.1
Authorization: Bearer <agent-token>
Idempotency-Key: 7c89b17a-0583-4476-8676-c05c31a02a36
Content-Type: application/json
```

Настроенный `CLOUD_HUB_URL` является origin; Mini-Ops добавляет path. HTTPS
обязателен для любого non-loopback destination. Request timeout равен 10
секундам, serialized body — не более 64 KiB. Client подключается напрямую и не
наследует process proxy settings.

Timestamps — signed Unix seconds в UTC. Byte counters — integer bytes.
Percentages и load averages — finite non-negative JSON numbers или `null`.

## JSON schema v1 example

```json
{
  "schema_version": 1,
  "observation_id": "7c89b17a-0583-4476-8676-c05c31a02a36",
  "observed_at": 1784707200,
  "agent_version": "1.2.0",
  "system": {
    "collected_at": 1784707198,
    "cpu_usage_percent": 12.5,
    "memory_total_bytes": 2147483648,
    "memory_used_bytes": 734003200,
    "disk_total_bytes": 42949672960,
    "disk_used_bytes": 12884901888,
    "load_average_1m": 0.18,
    "load_average_5m": 0.24,
    "load_average_15m": 0.21,
    "uptime_seconds": 864000
  },
  "security": {
    "status": "available",
    "collected_at": 1784707110,
    "score": 82,
    "findings": {
      "pass": 7,
      "warn": 1,
      "fail": 1
    }
  },
  "certificates": {
    "status": "enabled",
    "interval_seconds": 86400,
    "targets": [
      {
        "target_id": "crm-edge",
        "server_name": "crm.example.com",
        "port": 443,
        "freshness": "fresh",
        "checked_at": 1784703600,
        "last_success_at": 1784703600,
        "reachability": "reachable",
        "trust": "valid",
        "hostname": "match",
        "expiry": "warning",
        "not_after": 1787295600,
        "error_code": null
      }
    ]
  }
}
```

## Закрытые enum values

| Field | Values |
|---|---|
| `security.status` | `available`, `missing`, `stale`, `degraded` |
| `certificates.status` | `disabled`, `enabled`, `unavailable` |
| target `freshness` | `pending`, `fresh`, `stale` |
| target `reachability` | `reachable`, `unknown` или `null` для pending |
| target `trust` | `valid`, `invalid`, `unknown` или `null` для pending |
| target `hostname` | `match`, `mismatch`, `unknown` или `null` для pending |
| target `expiry` | `healthy`, `warning`, `critical`, `expired`, `not_yet_valid`, `unknown` или `null` для pending |
| target `error_code` | `dns_timeout`, `dns_failed`, `connect_timeout`, `connect_refused`, `connect_failed`, `tls_timeout`, `tls_handshake_failed`, `certificate_missing`, `certificate_parse_failed`, `unsupported_protocol`, `cancelled`, `internal_error` или `null` |

Правила:

- `security.score` и `security.findings` non-null только при status
  `available`. Hub не должен превращать null в zero или healthy.
- `certificates.targets` пуст для `disabled` и `unavailable`.
- Pending certificate target имеет `freshness=pending`; все observation fields
  после `freshness` равны null.
- `freshness=stale` означает, что последняя проверка старше двух настроенных
  certificate intervals или её timestamp более чем на пять минут впереди
  observation.
- Failed checks могут иметь `expiry=unknown`, `not_after=null` и non-null error
  code. Сохраняйте `last_success_at` как historical evidence, но не показывайте
  target как currently healthy.
- `target_id` стабилен внутри одной agent configuration, но не globally unique.
  Hub key: `(token-bound agent, target_id)`.
- `server_name` — TLS SNI/expected hostname, а не authorization или server
  identity field.

## Authentication и tenancy boundary

В request body намеренно нет `agent_id`, `server_id`, `workspace_id` или tenant
field. Hub обязан:

1. при agent enrollment генерировать high-entropy show-once token;
2. хранить только подходящий token hash и token metadata;
3. в server-side state связать token ровно с одним server/agent и workspace;
4. получать ownership только из authenticated token, никогда не из JSON;
5. поддерживать rotation и immediate revocation;
6. не логировать Authorization header или token.

Нельзя повторно использовать browser session token как agent token. Agent
token должен уметь только создавать observations для собственной binding; он
не должен читать fleet data или менять agent/server configuration.

## Receiver validation и idempotency

Первый Hub slice должен обеспечить:

- request body limit не выше 64 KiB до JSON parsing;
- HTTPS на edge и redaction Authorization headers в proxy/app logs;
- точный `schema_version=1`; unsupported versions получают `422`;
- valid UUID `observation_id` и точное равенство `Idempotency-Key`;
- strict object/enum decoding и не более 32 certificate targets;
- finite numeric values, non-negative byte counters, percentages в заданном
  receiver plausible range и `used <= total`, если total не равен zero;
- bounded target ID/hostname lengths и valid port range;
- допустимый clock-skew window для нового `observed_at`; observation за его
  пределами считается unknown/stale, но не healthy;
- unique constraint `(agent_binding_id, observation_id)`;
- duplicate delivery того же observation как idempotent success;
- transactional persistence observation и latest-state projection;
- ordering по `observed_at` с deterministic tie-breaker, чтобы поздний старый
  request не перезаписал более новый latest state;
- bounded history/retention и проверенные backup/restore до production.

Любой HTTP `2xx` означает для Mini-Ops, что observation принят. Рекомендуемые
responses: `202 Accepted` для нового observation и `200 OK` или `204 No
Content` для уже принятого duplicate. Используйте `401`/`403` для invalid или
revoked token, `413` для body limit, `422` для schema validation, `429` для
rate limit и `5xx` только для retryable server failure. Mini-Ops игнорирует
response body и никогда его не логирует.

Mini-Ops сейчас создаёт один новый observation на interval. Durable outbound
queue отсутствует; пропущенные historical points после restart/outage не
replay-ятся. Поэтому Fleet UI обязан показывать agent last-seen age и никогда
не считать отсутствие observations healthy-состоянием.

## Certificate boundary

Fleet Push не обнаруживает сертификаты. Оператор отдельно включает Mini-Ops
direct-TLS collector и устанавливает root-owned static targets file; см.
[SECURITY.ru.md](SECURITY.ru.md#мониторинг-tls-сертификатов). Для Mini-CRM host
настройте public CRM hostname и отдельно обслуживаемый Mini-Ops hostname как
независимые TLS targets. Если оба endpoints отдают один certificate, Hub позже
может сгруппировать их, но обязан сохранить per-endpoint reachability,
hostname, trust и freshness.

Не добавляйте recursive scans `/etc`, ACME trees, Docker volumes, home или
application directories ради Fleet ingestion. Не читайте `privkey.pem`,
`server.key`, PFX, Kubernetes Secrets или container env. Served endpoint
остаётся масштабируемым source of truth, потому что проверяет и expiry, и
фактический deployment/reload.

Local public-certificate metadata может появиться только как отдельный future
collector с fixed root-owned source IDs, bounded metadata-only output и
независимым threat review. В Observation v1 его нет.

## Capacity и polling

- Fleet push interval: default 300 seconds, strict `60..86400` range.
- Certificate probe interval: independent default 21600 seconds, strict
  `300..86400`; once daily (`86400`) — разумный low-cost default для Mini-CRM.
- Certificate targets: 1..32 на enabled agent; probe concurrency 1..8.
- Fleet serialization: максимум 32 current target rows и request 64 KiB.
- Каждый Fleet push добавляет один bounded current-state SQLite read при
  включенном certificate monitoring; projection timeout равен двум секундам,
  TLS probe не запускается.
- При default Fleet interval пять минут 100 постоянно подключенных agents дают
  в среднем около 0,33 request/second и 28 800 requests/day без retries.

Existing disposable evidence для direct-TLS collector при 32 targets:
примерно +1,5 MiB RSS, +2 threads и +48 KiB SQLite относительно disabled
fixture. Эти цифры относятся к local certificate collector, а не remote Hub
или end-to-end deployment. На canary измерьте final build повторно.

## Явные non-goals v1

- inbound Hub-to-agent connections;
- remote shell, command execution, deploy, restart, firewall или config change;
- certificate issuance, renewal, file replacement или service reload;
- Hub-managed certificate target CRUD;
- filesystem/key/secret discovery;
- SSH activity, trusted IP, open-port, Docker inventory или log export;
- full security findings/evidence или local event history;
- guaranteed historical delivery при недоступном Hub/network/agent.

## Первый end-to-end gate

До широкой Fleet UI докажите один vertical slice:

1. Реализуйте token enrollment и strict v1 receiver.
2. Разверните Hub за HTTPS на отдельном test VPS. Не используйте HTTP override
   между hosts.
3. Подключите один disposable/canary Mini-Ops agent с interval 300 seconds.
4. Проверьте accepted payload size, token redaction, idempotent duplicate,
   ordering старого observation, revoke/rotate и agent last-seen.
5. Включите один-два explicit TLS targets и проверьте healthy, failure,
   pending/stale, renewal и same-certificate/two-endpoint cases.
6. Остановите Hub/network и убедитесь, что Mini-Ops standalone monitoring и
   Telegram transitions продолжают работать локально.
7. Восстановите Hub database из backup и докажите tenant/server ownership и
   latest-state reconstruction до добавления следующих серверов.

Первый Hub должен давать только read-only visibility. Любые mutations и remote
operations остаются вне этого протокола.
