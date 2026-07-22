# Fleet Integration Contract

This document is the implementation handoff for a Hub that receives Mini-Ops
Fleet Observation v1. It describes current agent behavior, not a promise that a
Hub already exists.

## Readiness

| Surface | Current state |
|---|---|
| Mini-Ops v1 serializer and outbound client | Implemented in current source and covered by local Rust tests |
| Standalone Mini-Ops behavior when Fleet Push is off | Unchanged; no Fleet client/task is created |
| Hub API, storage, UI, agent enrollment, token rotation | Not implemented in this repository |
| End-to-end agent -> remote Hub test | Not performed yet |
| Production compatibility claim | Not made; start with one disposable/canary agent |

Observation v1 is not in the published Mini-Ops v1.1.0 release. Test a source
build or a later release that explicitly includes this contract.

## Request

```http
POST /api/v1/agent-observations HTTP/1.1
Authorization: Bearer <agent-token>
Idempotency-Key: 7c89b17a-0583-4476-8676-c05c31a02a36
Content-Type: application/json
```

The configured `CLOUD_HUB_URL` is an origin; Mini-Ops appends the path. HTTPS is
required for every non-loopback destination. The request timeout is 10 seconds
and the serialized body is at most 64 KiB. The client connects directly and
does not inherit process proxy settings.

Timestamps are signed Unix seconds in UTC. Byte counters are integer bytes.
Percentages and load averages are finite non-negative JSON numbers or `null`.

## JSON schema v1 example

```json
{
  "schema_version": 1,
  "observation_id": "7c89b17a-0583-4476-8676-c05c31a02a36",
  "observed_at": 1784707200,
  "agent_version": "1.1.0",
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

## Closed enum values

| Field | Values |
|---|---|
| `security.status` | `available`, `missing`, `stale`, `degraded` |
| `certificates.status` | `disabled`, `enabled`, `unavailable` |
| target `freshness` | `pending`, `fresh`, `stale` |
| target `reachability` | `reachable`, `unknown`, or `null` while pending |
| target `trust` | `valid`, `invalid`, `unknown`, or `null` while pending |
| target `hostname` | `match`, `mismatch`, `unknown`, or `null` while pending |
| target `expiry` | `healthy`, `warning`, `critical`, `expired`, `not_yet_valid`, `unknown`, or `null` while pending |
| target `error_code` | `dns_timeout`, `dns_failed`, `connect_timeout`, `connect_refused`, `connect_failed`, `tls_timeout`, `tls_handshake_failed`, `certificate_missing`, `certificate_parse_failed`, `unsupported_protocol`, `cancelled`, `internal_error`, or `null` |

Rules:

- `security.score` and `security.findings` are non-null only when status is
  `available`. A Hub must not turn null into zero or healthy.
- `certificates.targets` is empty for `disabled` and `unavailable`.
- A pending certificate target has `freshness=pending`; every observation field
  after `freshness` is null.
- `freshness=stale` means the last check is older than twice the configured
  certificate interval, or its timestamp is more than five minutes in the
  future relative to the observation.
- Failed checks can have `expiry=unknown`, `not_after=null`, and a non-null
  error code. Keep `last_success_at` as historical evidence; do not present the
  target as currently healthy.
- `target_id` is stable within one agent configuration, not globally unique.
  A Hub key is `(token-bound agent, target_id)`.
- `server_name` is the TLS SNI/expected hostname. It is not an authorization or
  server identity field.

## Authentication and tenancy boundary

The request body intentionally has no `agent_id`, `server_id`, `workspace_id`,
or tenant field. The Hub must:

1. generate a high-entropy, show-once token during agent enrollment;
2. store only a suitable token hash and token metadata;
3. bind that token to exactly one server/agent and workspace in server-side
   state;
4. derive all ownership from the authenticated token, never from JSON fields;
5. support rotation and immediate revocation;
6. avoid logging the Authorization header or token.

No browser session token should be reused as an agent token. Agent tokens need
only permission to create observations for their own binding; they must not
read fleet data or mutate agent/server configuration.

## Receiver validation and idempotency

The first Hub slice should enforce:

- request body limit at or below 64 KiB before JSON parsing;
- HTTPS at the edge and redaction of Authorization headers in proxy/app logs;
- exact `schema_version=1`; reject unsupported versions with `422`;
- a valid UUID `observation_id` and exact equality with `Idempotency-Key`;
- strict object/enum decoding and at most 32 certificate targets;
- finite numeric values, non-negative byte counters, percentages in a
  receiver-defined plausible range, and `used <= total` when total is nonzero;
- bounded target ID/hostname lengths and valid port range;
- an acceptable `observed_at` clock-skew window for new data, while treating
  an out-of-window observation as unknown/stale rather than healthy;
- a unique constraint on `(agent_binding_id, observation_id)`;
- duplicate delivery of the same observation as idempotent success;
- transactional persistence of observation and latest-state projection;
- ordering by `observed_at` plus a deterministic tie-breaker so a late older
  request cannot overwrite newer latest state;
- bounded history/retention and tested backup/restore before production use.

Any HTTP `2xx` tells Mini-Ops the observation was accepted. Recommended Hub
responses are `202 Accepted` for a new observation and `200 OK` or `204 No
Content` for an already accepted duplicate. Use `401`/`403` for invalid or
revoked tokens, `413` for body limits, `422` for schema validation, `429` for
rate limits, and `5xx` only for retryable server failure. Mini-Ops ignores the
response body and never logs it.

Mini-Ops currently creates one new observation per interval. It does not keep a
durable outbound queue and does not replay missed historical points after a
restart/outage. Fleet UI must therefore show agent last-seen age and must never
interpret missing observations as healthy.

## Certificate boundary

Fleet Push does not discover certificates. The operator must separately enable
the Mini-Ops direct-TLS collector and install a root-owned static target file;
see [SECURITY.md](SECURITY.md#tls-certificate-monitoring). For a Mini-CRM host,
configure the public CRM hostname and any separately served Mini-Ops hostname
as independent TLS targets. If both endpoints serve the same certificate, the
Hub may group them later, but it must retain per-endpoint reachability,
hostname, trust, and freshness.

Do not add recursive scans of `/etc`, ACME trees, Docker volumes, home
directories, or application directories to make Fleet ingestion work. Do not
read `privkey.pem`, `server.key`, PFX, Kubernetes Secrets, or container env.
The served endpoint remains the scalable source of truth because it verifies
both expiry and actual deployment/reload.

Local public-certificate metadata may be added only as a separate future
collector with fixed root-owned source IDs, bounded metadata-only output, and
an independent threat review. It is not part of Observation v1.

## Capacity and polling

- Fleet push interval: default 300 seconds, strict `60..86400` range.
- Certificate probe interval: independent default 21600 seconds, strict
  `300..86400`; once daily (`86400`) is a reasonable low-cost Mini-CRM default.
- Certificate targets: 1..32 per enabled agent; probe concurrency 1..8.
- Fleet serialization: at most 32 current target rows and a 64 KiB request.
- Each Fleet push adds one bounded current-state SQLite read when certificate
  monitoring is enabled; the read has a two-second projection timeout and does
  not trigger a TLS probe.
- At the default five-minute Fleet interval, 100 continuously connected agents
  average about 0.33 requests/second and 28,800 requests/day before retries.

Existing disposable evidence for the direct-TLS collector at 32 targets was
approximately +1.5 MiB RSS, +2 threads, and +48 KiB SQLite versus the disabled
fixture. Those figures cover the local certificate collector, not a remote Hub
or end-to-end deployment. Measure the canary again with the final build.

## Explicit non-goals for v1

- inbound Hub-to-agent connections;
- remote shell, command execution, deploy, restart, firewall, or config change;
- certificate issuance, renewal, file replacement, or service reload;
- Hub-managed certificate target CRUD;
- filesystem/key/secret discovery;
- SSH activity, trusted IP, open-port, Docker inventory, or log export;
- full security findings/evidence or local event history;
- guaranteed historical delivery while the Hub/network/agent is unavailable.

## First end-to-end gate

Before building broad Fleet UI, prove one vertical slice:

1. Implement token enrollment and the strict v1 receiver.
2. Deploy the Hub behind HTTPS on the separate test VPS. Do not use the HTTP
   override across hosts.
3. Connect one disposable/canary Mini-Ops agent at a 300-second interval.
4. Verify accepted payload size, token redaction, idempotent duplicate handling,
   older-observation ordering, revoke/rotate, and agent last-seen behavior.
5. Enable one or two explicit TLS targets and verify healthy, failure,
   pending/stale, renewal, and same-certificate/two-endpoint cases.
6. Interrupt Hub/network service and confirm Mini-Ops standalone monitoring and
   Telegram transitions continue locally.
7. Restore the Hub database from backup and prove tenant/server ownership and
   latest-state reconstruction before adding more servers.

The Hub should initially be read-only visibility. Keep every mutation or remote
operation outside this protocol.
