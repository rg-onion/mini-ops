# Monitoring & Alerts

Mini-Ops provides a simple interface for monitoring server and container status.

## 📊 Dashboard
Available on the main page at `/`.
Displays:
- **CPU**: Processor load (%).
- **RAM**: Used / Total memory.
- **Disk**: Used / Total space.

Graphs store history for the last **60 minutes**.

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

### Testing
You can manually test notification delivery:
```bash
curl -X POST http://YOUR_SERVER_IP:3000/api/test-notification \
  -H "Authorization: Bearer YOUR_AUTH_TOKEN"
```
If settings are correct, the bot will send a test message.
