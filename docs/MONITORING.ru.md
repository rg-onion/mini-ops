# Мониторинг и Уведомления

Mini-Ops предоставляет простой интерфейс для наблюдения за состоянием сервера и контейнеров.

## 📊 Дашборд
Доступен на главной странице по адресу `/`.
Отображает:
- **CPU**: Загрузка процессора (%).
- **RAM**: Использованная / Всего памяти.
- **Disk**: Занятое / Всего пространства.

Графики хранят историю за последние **60 минут**.

## 🐳 Логи Контейнеров
Вы можете просматривать логи Docker контейнеров в реальном времени:
1. Перейдите в раздел **Docker Containers**.
2. Нажмите на иконку 📄 (**View Logs**) в строке нужного контейнера.
3. Откроется окно с потоком логов.

> [!NOTE]
> Логи передаются через SSE (`text/event-stream`) и защищены тем же `Authorization: Bearer <AUTH_TOKEN>`, что и основной API.

## 🛎 Уведомления (Telegram)
Система автоматически отправляет сообщение в Telegram при достижении критических порогов:
- **CPU > 95%**
- **Disk Usage > 90%**

### Настройка
Для включения уведомлений добавьте в `.env`:
```env
TELEGRAM_BOT_TOKEN=your_bot_token
TELEGRAM_CHAT_ID=your_chat_id
```

Оба значения должны быть непустыми. Если хотя бы одно отсутствует или содержит
только пробелы, Telegram delivery выключена. Пустой `SERVER_NAME` заменяется
именем хоста.

Operational и security alerts используют durable SQLite outbox. Retryable
ошибки переживают restart и повторяются не более пяти раз с bounded backoff.
Очередь ограничена 1000 live и 200 terminal rows; переполнение отображается как
локальное security event `notification.delivery_degraded`. Metric alerts
используют стабильные CPU/disk keys с cooldown 30 минут, а не меняющийся текст
метрики как identity. Provider response body, request URL, token и raw transport
error не сохраняются и не пишутся в log.

### Тестирование
Вы можете проверить отправку уведомлений вручную:
```bash
curl --include --request POST http://127.0.0.1:3000/api/test-notification \
  -H "Authorization: Bearer YOUR_AUTH_TOKEN"
```

Это immediate non-durable attempt: HTTP `200` означает, что Telegram реально
вернул успешный ответ. Disabled config и delivery failure возвращают typed
non-2xx response и не ставятся в retry queue.
