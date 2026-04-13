# Cloud Push — Transparency Document

**Feature status:** Optional, opt-in only.
**Data destination:** A Mini-Ops Hub instance (self-hosted or the commercial cloud service).

---

## What is Cloud Push?

Cloud Push is an optional module that periodically sends server metrics from your
Mini-Ops agent to a central **Hub** — enabling a single dashboard to aggregate
data from multiple servers at once.

This is the foundation of the **commercial multi-server edition** of Mini-Ops,
where a Hub collects readings from N agents and provides a unified view of your
entire infrastructure.

The open-source, single-server version ships with this module in the binary, but
it is **completely dormant** by default.

---

## Activation

Cloud Push activates **only** when all three of the following are set in `.env`:

```env
CLOUD_PUSH_ENABLED=true
CLOUD_HUB_URL=https://your-hub.example.com
CLOUD_AGENT_TOKEN=your_agent_token_here
```

If `CLOUD_PUSH_ENABLED` is absent, empty, or set to anything other than the
exact string `"true"` — no HTTP client is created, no background task is
spawned, and **no data leaves the server**.

---

## What data is sent?

Each push is a JSON payload containing:

| Field | Contents | Why |
|-------|----------|-----|
| `system` | CPU %, RAM, disk usage, load average, OS/kernel version, uptime | Core server health metrics |
| `docker` | Container names, images, running/stopped state | Container fleet overview |
| `security.ssh_hardening_score` | Score 0–100 based on local SSH config checks | Security posture summary |
| `security.fail2ban_active` | bool | Intrusion prevention status |
| `security.ufw_enabled` | bool | Firewall status |
| `security.last_ssh_login` | Username + source IP + timestamp + is\_trusted flag | Login activity across servers |
| `security.trusted_ips` | List of IPs the operator marked as trusted | Needed to suppress false-positive alerts on the Hub |
| `agent_id`, `agent_version`, `server_name`, `hostname` | Server identity | Route data to the correct server on the Hub |

### Sensitive fields note

`last_ssh_login.ip` and `trusted_ips` reveal network topology (who accesses
the server from where). This is intentional for the multi-server use case
(the Hub needs this to correlate events), but it means your Hub must be
trustworthy. **Only point `CLOUD_HUB_URL` at a Hub you control or fully trust.**

---

## Transport security

- HTTPS is **required** by default. Attempts to use a plain `http://` URL will
  fail at startup with an error logged to the console.
- For local development/testing only, you can override this:
  ```env
  CLOUD_PUSH_ALLOW_HTTP=true   # never set in production
  ```
  A prominent `WARN` log is emitted every time this override is active.

---

## Authentication

Each push includes a `Bearer` token in the `Authorization` header:

```
Authorization: Bearer <CLOUD_AGENT_TOKEN>
```

The token is never embedded in the URL or the JSON body.

---

## How to verify nothing is sent without opt-in

Search the source:

```bash
grep -n "CLOUD_PUSH_ENABLED" src/main.rs
```

You will find a single `if` guard. The `tokio::spawn` that starts the push loop
is inside that guard — if the condition is false, the entire module stays inert.

---

## Opting out completely

Simply do not set `CLOUD_PUSH_ENABLED=true`. You can also remove or comment out
all `CLOUD_*` lines from your `.env` — the application will not reference them.

---

## Commercial vs. open-source

| | Open-source (this repo) | Commercial Hub |
|-|-------------------------|----------------|
| Cloud Push module present | Yes (dormant) | Yes (active) |
| Data leaves server | **Never without opt-in** | Only to your own Hub |
| Multi-server dashboard | No | Yes |
| Hub source code | Not published | — |

The commercial Hub is a separate product. The agent code in this repository is
the same binary used with the commercial Hub — there is no hidden version.
