# Disk & Cache Management

The Disk Analyzer reports the current size of Rust build artifacts, frontend
dependencies, Docker data, and system logs when each source is readable within
the three-second command budget. Unavailable or timed-out values are shown as
`Unknown`. The dashboard view is read-only and does not expose cleanup buttons.

## Destructive operations

Disk cleanup is disabled on the server by default. The experimental
authenticated server-side API is available only when
`MINI_OPS_ALLOW_DISK_CLEANUP=true` is set exactly. When enabled, it is limited
to requests for Rust
`target/`, `frontend/node_modules/`, and journald cleanup.

Docker cleanup is unavailable in this release, even when the experimental gate
is enabled. `/api/disk/clean` returns `403 operation_unavailable` for the
`docker` target and cannot invoke `docker system prune -af`.

The dashboard remains read-only even when the experimental server gate is
enabled.
