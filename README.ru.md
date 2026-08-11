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
  - **Честный posture**: Подтверждённые findings и рекомендации отделены от неполного покрытия аудита.
  - **Целостность sensitive files**: opt-in low-privilege обнаружение drift с локальным private baseline.
  - **Мониторинг TLS-сертификатов**: opt-in проверки до 32 явно заданных обслуживаемых endpoints без поиска по filesystem и чтения private keys.
  - **Доверенные IP**: Управление белым списком для безопасного доступа.
- **📊 Системный мониторинг**: текущие CPU, RAM и ёмкость диска плюс
  [ограниченная история метрик](docs/METRICS_HISTORY.ru.md) от часа до семи дней.
- **🔔 Уведомления**: Telegram алерты при превышении порогов CPU и диска + изменения статуса безопасности.
- **☁️ Fleet Observation Push**: optional outbound-only v1 projection минимизированного system, security и certificate state в Hub оператора.
- **🌍 Локализация**: Полная поддержка Русского и Английского языков.

---

## 🚀 Быстрый старт

### 1. Установка

Для tagged OSS releases скачивайте binary archive, `SHA256SUMS` и SBOM из
одного GitHub Release и проверяйте их перед использованием. Подробнее:
[docs/RELEASING.ru.md](docs/RELEASING.ru.md).

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
- **Rust** (`1.93.0`)
- **Node.js** (`24.17.0`) и **npm** (`12.0.1`)
- **Docker**

### Локальный запуск

1. **Клон и установка Frontend**:
   ```bash
   git clone https://github.com/rg-onion/mini-ops.git
   cd mini-ops/frontend
   npm ci --strict-allow-scripts
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
- Выполняйте обновления через документированный host deployment workflow с
  проверенным артефактом, backup, rollback point и проверками после изменения.

Подробнее: [docs/SECURITY.ru.md](docs/SECURITY.ru.md).

В репозитории реализован opt-in agent-side протокол Fleet observations, но нет
hosted Hub или встроенного Fleet server. Текущий implementation status, privacy
boundary и контракт receiver описаны в
[docs/CLOUD_PUSH.ru.md](docs/CLOUD_PUSH.ru.md) и
[docs/FLEET_INTEGRATION.ru.md](docs/FLEET_INTEGRATION.ru.md).

Индекс документации: [docs/README.md](docs/README.md).

---

## 🤝 Вклад в проект (Contributing)

Мы рады любым вкладам! См. [CONTRIBUTING.ru.md](CONTRIBUTING.ru.md).

## 📄 Лицензия

Этот проект распространяется под лицензией [MIT License](LICENSE).
