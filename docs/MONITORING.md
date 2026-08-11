# Monitoring & Alerts

Mini-Ops provides a simple interface for monitoring server and container status.

## 📊 Dashboard
Available on the main page at `/`.
Displays:
- **CPU**: Processor load (%).
- **RAM**: Used / Total memory.
- **Disk**: Used / Free / Total capacity.

The CPU, RAM, and disk graphs offer bounded **1h**, **6h**, **24h**, and **7d**
windows. The dashboard distinguishes loading, empty, unavailable, and partial
history instead of filling missing data with zero. See
[Metrics History](METRICS_HISTORY.md) for retention, resolution, and API details.

## 🐳 Docker Logs
You can view Docker container logs in real-time:
1. Go to **Docker Containers**.
2. Click the 📄 (**View Logs**) icon in the row of the desired container.
3. A window with the log stream will open.

> [!NOTE]
> Logs are streamed via SSE (`text/event-stream`) and protected by the same `Authorization: Bearer <AUTH_TOKEN>` as the main API.

## 🛎 Notifications (Telegram)
The system automatically sends a Telegram message when critical thresholds are reached:
- **CPU > 95%**
- **Disk Usage > 90%**

### Configuration
To enable notifications, add to `.env`:
```env
TELEGRAM_BOT_TOKEN=your_bot_token
TELEGRAM_CHAT_ID=your_chat_id
```

Both values must be non-blank. If either value is missing or whitespace-only,
Telegram delivery is disabled. A blank `SERVER_NAME` falls back to the host
name.

Operational and security alerts use a durable SQLite outbox. Failed retryable
deliveries survive restart and retry up to five attempts with bounded backoff.
The queue is capped at 1000 live and 200 terminal rows; capacity pressure is
shown as a local `notification.delivery_degraded` security event. Metric alerts
use stable CPU/disk keys with a 30-minute cooldown rather than changing metric
text as their identity. Provider response bodies, request URLs, tokens, and raw
transport errors are not stored or logged.

### Testing
You can manually test notification delivery:
```bash
curl --include --request POST http://127.0.0.1:3000/api/test-notification \
  -H "Authorization: Bearer YOUR_AUTH_TOKEN"
```

This test is an immediate, non-durable attempt: HTTP `200` means Telegram
actually returned a successful response. Disabled configuration and delivery
failure return typed non-2xx responses and are not queued for retry.
