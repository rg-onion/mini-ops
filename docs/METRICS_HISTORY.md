# Metrics History

Mini-Ops records one local CPU, memory, and disk-capacity sample approximately
once per minute. `METRICS_RETENTION_HOURS` controls how long those SQLite rows
are retained (`168` hours by default). History queries reuse the stored rows;
they do not add a collector or extra periodic writes.

The current disk values are used, total, and free capacity, where free is
`total - used`. Collection reads filesystem capacity metadata only. It does not
traverse directory trees, inspect source caches, Docker data, or journals, run
privileged filesystem commands, or change host state.

All endpoints below require the same bearer authentication as the dashboard:

```http
Authorization: Bearer <AUTH_TOKEN>
```

Timestamps are Unix seconds in UTC. Byte totals in the legacy response are
JSON numbers.

## Legacy last-60 response

A request without query parameters keeps the original contract:

```text
GET /api/stats/history
```

It returns a JSON array containing at most the 60 newest raw samples, ordered
newest first. Each item has the same shape as `/api/stats`:

```json
{
  "cpu_usage": 4.2,
  "memory_used": 811597824,
  "memory_total": 2076262400,
  "disk_used": 17200000000,
  "disk_total": 22530000000,
  "timestamp": 1786435200
}
```

## Bounded window response

Pass a supported `window` to use the versioned, peak-preserving response:

```text
GET /api/stats/history?window=1h|6h|24h|7d&resolution=auto|raw|5m|1h
```

`resolution` is optional and defaults to `auto`. The response reports the
effective `raw`, `5m`, or `1h` resolution; it never reports `auto` as the
effective value. Coarser points preserve both average and maximum percentages
so a short peak is not hidden by its bucket average. Every successful response
contains at most 1500 points in chronological order.

With the normal one-minute sampling interval, `auto` selects `raw` for `1h`,
`6h`, and `24h`, and `1h` buckets for `7d`. It can select a coarser resolution
when the actual row count would otherwise exceed the response bound.

```json
{
  "schema_version": 1,
  "window": "24h",
  "resolution": "5m",
  "requested_start": 1786348800,
  "oldest_timestamp": 1786348860,
  "newest_timestamp": 1786435200,
  "partial": false,
  "points": [
    {
      "timestamp": 1786349100,
      "sample_count": 5,
      "cpu_percent": { "avg": 12.4, "max": 48.1 },
      "memory_percent": { "avg": 39.2, "max": 39.6 },
      "disk_percent": { "avg": 76.3, "max": 76.4 }
    }
  ]
}
```

- `requested_start` is the lower time boundary calculated for the request.
- `oldest_timestamp` and `newest_timestamp` describe the stored samples that
  contributed to the response. Both are `null` when no samples are available.
- `partial` is `true` when retained data starts more than one nominal
  60-second sampling interval after the requested boundary; consumers should
  not imply that the full selected window is available.
- `timestamp` identifies a raw sample or aggregate bucket, and `sample_count`
  reports how many stored samples contributed to that point. An aggregate
  timestamp is the UTC-aligned start of its bucket. For `raw` points,
  `sample_count` is `1` and `avg` equals `max`.
- For a raw point, `memory_percent` or `disk_percent` is `null` when its stored
  used/total pair cannot produce a valid percentage. Aggregate buckets use the
  valid percentages they contain and return `null` if none are valid. Invalid
  totals are never presented as zero.
- An empty history is a successful response with `points: []` and null oldest
  and newest timestamps plus `partial: false`; it is not a database error.

The server rejects an explicit resolution that is too fine to preserve the
1500-point bound for the selected window. In particular, `7d` rejects explicit
`raw` and `5m`; its supported explicit resolution is `1h`. Use
`resolution=auto` unless a stable bucket size is required by an API consumer.

## Errors

Errors use the common JSON envelope, for example:

```json
{ "error": { "code": "invalid_history_query" } }
```

- `400 invalid_history_query`: any query string without `window`, an
  unsupported `window` or `resolution`, or an unknown or duplicate query
  parameter. A request with no query string remains the valid legacy request
  described above.
- `400 history_resolution_too_fine`: the explicit resolution cannot satisfy
  the response bound for the selected window.
- `503 metrics_history_unavailable`: SQLite could not serve the history
  request, stored CPU data is invalid, or a hard source-row bound was exceeded.

Authentication failures use the normal protected-API response and are not
reported as an empty history.
