# Upgrading Mini-Ops

## v1.1.0 to v1.2.0

Mini-Ops v1.2.0 preserves the standalone, non-root deployment model and does
not intentionally delete existing SQLite state. Always create a verified
online database backup and retain the previous binary before upgrading. A
rollback must restore the matching binary and database backup together.

### Retired experimental surfaces

The following dormant or misleading surfaces were removed:

- the web source-build updater, `/api/deploy/*`, `scripts/update.sh`, and
  `MINI_OPS_ALLOW_WEB_UPDATE`;
- the deploy-history page and `/api/history`;
- Disk Analyzer/cleanup, `/api/disk/*`, and
  `MINI_OPS_ALLOW_DISK_CLEANUP`.

Removed and unknown `/api/*` paths return a typed JSON `404`. Existing
`history.json` is inert legacy state: the running agent does not parse or append
to it, while bootstrap preserves it for rollback compatibility.

### New and changed behavior

- Dashboard resource history uses `/api/stats/history` with bounded
  `1h`, `6h`, `24h`, and `7d` windows.
- Security results distinguish confirmed findings, recommendations, and
  unverified or partial coverage.
- Direct-TLS endpoint monitoring is opt-in through
  `SECURITY_CERTIFICATE_MONITOR_ENABLED` and a root-owned targets file.
- Fleet Observation v1 first ships in v1.2.0 and remains strictly opt-in;
  standalone monitoring never depends on a Hub.

Review `.env.example`, `METRICS_HISTORY.md`, `SECURITY.md`, `CLOUD_PUSH.md`, and
`FLEET_INTEGRATION.md` before enabling new collectors or outbound delivery.
Start with the zero-mutation deploy plan from `DEPLOY.md`, then verify the
installed checksum, service state, database quick check, local/public routes,
and rollback point after the authorized upgrade.
