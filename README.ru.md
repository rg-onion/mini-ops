# 🚀 Mini-Ops

![Rust](https://img.shields.io/badge/backend-Rust-orange?style=for-the-badge&logo=rust)
![React](https://img.shields.io/badge/frontend-React-blue?style=for-the-badge&logo=react)
![License](https://img.shields.io/badge/license-MIT-green?style=for-the-badge)
![Docker](https://img.shields.io/badge/docker-ready-2496ED?style=for-the-badge&logo=docker)

**Mini-Ops** — это легковесная панель управления (self-hosted) для VPS серверов.
Backend: **Rust** (Axum), Frontend: **React** (Vite, вшит в бинарный файл при сборке).

> "Ваш личный DevOps инженер, который помещается в один бинарный файл."

---

## ✨ Возможности

- **📦 Одиночный бинарный файл**: один файл содержит и API, и фронтенд.
- **🐳 Управление Docker**: список, старт/стоп/рестарт контейнеров, стриминг логов.
- **🛡️ Аудит безопасности**:
  - **SSH Мониторинг**: Telegram уведомления при входе (PAM хук).
  - **Проверки Hardening**: Аудит конфига SSH, статуса Fail2Ban, UFW фаервола и открытых портов.
  - **Целостность sensitive files**: opt-in low-privilege обнаружение drift с локальным private baseline.
  - **Доверенные IP**: Управление белым списком для безопасного доступа.
- **📊 Системный мониторинг**: Загрузка CPU/RAM/Disk + история метрик.
- **🔔 Уведомления**: Telegram алерты при превышении порогов CPU и диска + изменения статуса безопасности.
- **💾 Анализ диска**: просмотр использования диска сборками, зависимостями, Docker и journald в режиме только для чтения.
- **🌍 Локализация**: Полная поддержка Русского и Английского языков.

---

## 🚀 Быстрый старт

### 1. Установка

Используйте managed bootstrap только после zero-mutation dry run:

```bash
DEPLOY_HOST=server.example DEPLOY_DRY_RUN=1 ./scripts/bootstrap_server.sh
```

Defaults оставляют приложение на loopback и не меняют Docker, Nginx, UFW,
public HTTP, Docker-group access или PAM. Legacy entrypoints `deploy.sh` и
`provision.sh` остаются hard-stop. Actual invocation, explicit mutation flags,
rollback boundaries и ручная альтернатива описаны в
[docs/DEPLOY.ru.md](docs/DEPLOY.ru.md).

### 2. Конфигурация (`.env`)

Создайте `.env` из шаблона:
```bash
cp .env.example .env
```

Минимально необходимые переменные:
```env
AUTH_TOKEN=
```

Standalone local mode может сгенерировать токен для пустого значения. Managed
systemd mode требует заранее заданный сильный токен и иначе завершает startup.
Сгенерируйте токен и вставьте его в `.env`:
```bash
openssl rand -hex 32
```

Опционально:
```env
TELEGRAM_BOT_TOKEN=your_bot_token
TELEGRAM_CHAT_ID=your_chat_id
# Override только для standalone; не задавайте его для managed systemd service.
# DATABASE_URL=sqlite:mini-ops.db
SERVER_NAME=My-VPS-1
RUST_LOG=info
```

### 3. Запуск как managed service

Shipped unit оставляет код и конфигурацию root-owned, хранит mutable state в
`/var/lib/mini-ops`, ротирует PAM token в `/run/mini-ops` и применяет
`UMask=0077`, `ProtectSystem=strict`, `ProtectHome=true`. Exact команды
установки и проверки находятся в [docs/DEPLOY.ru.md](docs/DEPLOY.ru.md).

---

## 🌐 Сетевые режимы

- **По умолчанию**: приложение слушает `127.0.0.1:3000`.
- **Внешний доступ**: отдельно настройте TLS и reverse proxy, VPN, tunnel или
  private network. Не публикуйте `3000` напрямую.

---

## 🛠 Разработка

### Требования
- **Rust** (последний stable)
- **Node.js** (v20+)
- **Docker**

### Локальный запуск

1. **Клон и установка Frontend**:
   ```bash
   git clone https://github.com/rg-onion/mini-ops.git
   cd mini-ops/frontend
   npm install
   npm run build
   ```

2. **Запуск Backend**:
   ```bash
   cd ..
   cargo run
   ```

---

## 🔒 Безопасность

Mini-Ops разработан с учетом безопасности:
- **Внутренний PAM-токен**: SSH alerts используют случайный токен,
  сгенерированный при старте и прочитанный localhost PAM hook.
- **Throttling SSH alerts**: повторные уведомления о SSH-входах ограничиваются
  по source IP.
- **Защищенный API**: все публичные ручки требуют `AUTH_TOKEN`.

Рекомендации для продакшена:
- Используйте HTTPS reverse proxy.
- Не открывайте порты `3000` или `8090` публично без TLS/сетевого ограничения.
- Запускайте сервис от отдельного пользователя (non-root).
- Держите экспериментальную web-сборку исходников выключенной, если она явно
  не нужна (`MINI_OPS_ALLOW_WEB_UPDATE=false` по умолчанию). Она не устанавливает
  собранный файл и не перезапускает работающий сервис.
- Очистка диска по умолчанию выключена и недоступна в dashboard. Очистку Docker
  нельзя включить в этой версии.

Подробнее: [docs/SECURITY.ru.md](docs/SECURITY.ru.md).

Индекс документации: [docs/README.md](docs/README.md).

---

## 🤝 Вклад в проект (Contributing)

Мы рады любым вкладам! См. [CONTRIBUTING.ru.md](CONTRIBUTING.ru.md).

## 📄 Лицензия

Этот проект распространяется под лицензией [MIT License](LICENSE).
