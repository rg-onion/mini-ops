# Cloud Push - Transparency Document

**Feature status:** Optional, opt-in client. Disabled by default.
**Data destination:** The HTTPS endpoint configured in `CLOUD_HUB_URL`.

Mini-Ops does not send Cloud Push traffic unless the operator explicitly enables
it and provides a destination URL, agent id, and agent token.

---

## What is Cloud Push?

Cloud Push is an optional background task that periodically sends server metrics
from a Mini-Ops agent to the configured API endpoint:

```text
{CLOUD_HUB_URL}/api/v1/agents/push
```

The module is compiled into the open-source binary, but it is completely dormant
by default.

---

## Activation

Cloud Push activates only when all four settings are present in `.env`:

```env
CLOUD_PUSH_ENABLED=true
CLOUD_HUB_URL=https://your-hub.example.com
CLOUD_AGENT_ID=your_agent_id_here
CLOUD_AGENT_TOKEN=your_agent_token_here
```

If `CLOUD_PUSH_ENABLED` is absent, empty, or set to anything other than the exact
string `"true"`, no HTTP client is created, no background task is spawned, and no
data leaves the server.

---

## What data is sent?

Each push is a JSON payload containing:

| Field | Contents | Why |
|-------|----------|-----|
| `system` | CPU %, RAM, disk usage, load average, OS/kernel version, uptime | Core server health metrics |
| `docker` | Container names, images, running/stopped state | Container fleet overview |
| `security.ssh_hardening_score` | Severity-aware local security score, 0-100 | Security posture summary |
| `security.fail2ban_active` | bool | `systemctl is-active fail2ban` result summarized as a boolean |
| `security.ufw_enabled` | bool | Firewall status |
| `security.open_ports` | List of local listening TCP ports detected by the security audit | Exposure overview |
| `security.last_ssh_login` | Username + source IP + timestamp + `is_trusted` flag | Login activity across servers |
| `security.trusted_ips` | List of IPs the operator marked as trusted | Needed to suppress false-positive alerts on the Hub |
| `agent_id`, `agent_version`, `server_name`, `hostname` | Server identity | Route data to the correct server on the Hub |

### Sensitive fields note

`last_ssh_login.ip`, `trusted_ips`, `hostname`, `server_name`, and `open_ports`
can reveal operational details about your infrastructure. Only point
`CLOUD_HUB_URL` at an endpoint you control or fully trust.

---

## Transport security

- HTTPS is required by default. Attempts to use a plain `http://` URL fail at
  startup with an error logged to the console.
- For local development/testing only, you can override this:
  ```env
  CLOUD_PUSH_ALLOW_HTTP=true   # never set in production
  ```
  A `WARN` log is emitted every time this override is active.

---

## Authentication

Each push includes a bearer token in the `Authorization` header:

```http
Authorization: Bearer <CLOUD_AGENT_TOKEN>
```

The token is never embedded in the URL or the JSON body.

---

## How to verify nothing is sent without opt-in

Search the source:

```bash
grep -n "CLOUD_PUSH_ENABLED" src/main.rs
```

The push loop starts only inside that guard. If the condition is false, the
module stays inert.

---

## Opting out completely

Do not set `CLOUD_PUSH_ENABLED=true`. You can also remove or comment out all
`CLOUD_*` lines from your `.env`; the application will not reference them.

---

## Current Behavior

- Cloud Push is compiled in but inactive unless `CLOUD_PUSH_ENABLED=true`.
- If any required Cloud Push setting is missing, the push loop does not start.
- No data is sent to any Mini-Ops-operated service by default.
- Payloads are sent only to the configured `CLOUD_HUB_URL`.
- HTTPS is required by default; `CLOUD_PUSH_ALLOW_HTTP=true` is only for local
  testing.
