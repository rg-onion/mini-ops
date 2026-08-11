# Fleet Observation Push

**Status:** optional agent-side protocol preview; disabled by default.

**Destination:** only the operator-controlled origin in `CLOUD_HUB_URL`.

**Hub included here:** no.

Mini-Ops can periodically send a minimized, read-only observation to a Fleet
Hub. The standalone dashboard, local monitoring, certificate alerts, and
security checks do not depend on this feature.

The current source implements Observation schema v1. It replaces the older
unversioned Cloud Push payload and route that exposed container names/images,
SSH login identities/IPs, trusted IPs, listening ports, OS/kernel strings, and
a body-provided agent ID. Those fields are intentionally not part of v1.

> [!IMPORTANT]
> Mini-Ops v1.1.0 did not ship Observation v1. Until a later release containing
> this code is published, a source build is required for integration testing.
> No end-to-end Hub deployment is proven by this repository yet.

## Activation

Cloud Push starts only when the exact opt-in and both required values are set:

```env
CLOUD_PUSH_ENABLED=true
CLOUD_HUB_URL=https://fleet.example.com
CLOUD_AGENT_TOKEN=replace_with_a_show_once_agent_token
# Optional: default 300; strict range 60..86400 seconds.
CLOUD_PUSH_INTERVAL=300
```

`CLOUD_HUB_URL` must be an HTTPS origin: scheme, host, and optional port only;
credentials, paths, queries, and fragments are rejected. Mini-Ops appends:

```text
/api/v1/agent-observations
```

`CLOUD_PUSH_ALLOW_HTTP=true` works only with `localhost` or a loopback IP for
local development. It cannot enable plaintext delivery to another VPS.

If `CLOUD_PUSH_ENABLED` is absent, empty, or not exactly `true`, no Fleet HTTP
client or push task is created. Invalid explicit configuration disables the
push task and emits only a closed configuration error code.

## Data sent by Observation v1

| Section | Sent | Purpose |
|---|---|---|
| Envelope | schema version, random observation UUID, observation time, Mini-Ops version | Contract selection and idempotency |
| `system` | collection time, CPU, RAM and disk byte counters, load averages, uptime | Server health overview |
| `security` | availability state; only for a fresh complete snapshot: score and PASS/WARN/FAIL counts | Bounded security posture summary |
| `certificates` | collector state, interval, and up to 32 configured TLS target summaries | Fleet-wide served-certificate expiry and failure visibility |

For each configured certificate target, v1 may send its stable target ID,
configured TLS `server_name`, port, freshness, check/success timestamps,
reachability, trust, hostname, expiry, `not_after`, and a closed probe error
code. Certificate data is present only when the separate direct-TLS monitor is
enabled. See [SECURITY.md](SECURITY.md#tls-certificate-monitoring).

## Data intentionally not sent

Observation v1 does not send:

- the local dashboard token or Fleet agent token;
- an agent/server/workspace ID in the body;
- SSH usernames, source IPs, trusted IPs, or SSH history;
- container IDs, names, images, status strings, logs, or environment;
- listening-port lists, OS name, kernel version, or local hostname;
- certificate target labels or connect hosts;
- certificate bytes/chains, SAN lists, subjects, issuers, serials,
  fingerprints, filesystem paths, private keys, PFX, or secrets;
- local security evidence, remediation text, event history, or Telegram data;
- file-integrity paths, hashes, observations, or baselines.

The configured certificate `server_name` can still reveal infrastructure
metadata. Enable Fleet Push only for a Hub you control or fully trust.

## Unknown and stale state

Unknown data is explicit:

- security is `missing`, `stale`, or `degraded` without a score/counts;
- certificates are `disabled`, `unavailable`, or `enabled`;
- a target is `pending` before its first observation and `stale` after more
  than twice the configured certificate interval;
- a failed target keeps bounded status/error fields and never becomes healthy
  by defaulting missing values to zero.

A missing/degraded security snapshot no longer suppresses the system and
certificate heartbeat.

## Transport behavior

- HTTPS is required except for the loopback-only development override.
- Fleet delivery is direct and does not inherit process proxy settings.
- Authentication is `Authorization: Bearer <CLOUD_AGENT_TOKEN>`.
- The body contains no trusted agent identity. The Hub must bind the token to
  exactly one agent/server record.
- `Idempotency-Key` equals the body `observation_id` UUID.
- Serialized request bodies are capped at 64 KiB.
- The HTTP request timeout is 10 seconds.
- The first request is delayed by one configured interval. Missed timer ticks
  are skipped; a failed delivery is tried again with a new observation on the
  next interval, not in an unbounded retry loop.
- Any HTTP `2xx` is success. Authentication, rate-limit, contract, transport,
  and Hub failures are logged as closed codes; response bodies and raw
  transport errors are not logged.

The exact receiver rules, JSON example, ordering requirements, and test
checklist are in [FLEET_INTEGRATION.md](FLEET_INTEGRATION.md).

## Opting out

Leave `CLOUD_PUSH_ENABLED=false` or remove all `CLOUD_*` variables. Mini-Ops
remains a complete standalone agent and sends no Fleet observations.
