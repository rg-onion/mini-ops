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
  - **Доверенные IP**: Управление белым списком для безопасного доступа.
- **📊 Системный мониторинг**: Загрузка CPU/RAM/Disk + история метрик.
- **🔔 Уведомления**: Telegram алерты при превышении порогов CPU и диска + изменения статуса безопасности.
- **🧹 Очистка диска**: очистка `target`, `node_modules`, Docker кэша и старых логов journald.
- **🌍 Локализация**: Полная поддержка Русского и Английского языков.

---

## 🚀 Быстрый старт

### 1. Установка

Mini-Ops собирается из исходного кода или развертывается с помощью автоматического скрипта.

#### Вариант А: Автоматическая установка (Ubuntu, рекомендуется)
Этот скрипт соберет приложение локально и развернет его на сервере:
```bash
DEPLOY_HOST=your-server-ip ./scripts/bootstrap_server.sh
```

#### Вариант Б: Ручная сборка
См. раздел [Разработка](#-разработка) ниже для сборки бинарного файла из исходников.

### 2. Конфигурация (`.env`)

Создайте `.env` из шаблона:
```bash
cp .env.example .env
```

Минимально необходимые переменные:
```env
AUTH_TOKEN=
```

Оставьте значение пустым, чтобы Mini-Ops/bootstrap сгенерировал сильный токен,
или сгенерируйте токен в shell и вставьте готовое значение в `.env`:
```bash
openssl rand -hex 32
```

Опционально:
```env
TELEGRAM_BOT_TOKEN=your_bot_token
TELEGRAM_CHAT_ID=your_chat_id
DATABASE_URL=sqlite:mini-ops.db
SERVER_NAME=My-VPS-1
RUST_LOG=info
```

### 3. Запуск как сервис

```bash
# Создать systemd сервис
sudo tee /etc/systemd/system/mini-ops.service <<EOF
[Unit]
Description=Mini-Ops Agent
After=network.target docker.service

[Service]
ExecStart=/usr/local/bin/mini-ops
Restart=always
EnvironmentFile=/path/to/.env

[Install]
WantedBy=multi-user.target
EOF

# Запустить
sudo systemctl enable --now mini-ops
```

В этом ручном примере Mini-Ops по умолчанию слушает
**http://127.0.0.1:3000**. Перед внешней публикацией настройте reverse proxy
или явно задайте `APP_HOST`/`APP_PORT`.

**Автоматическая установка (Ubuntu, рекомендуется):**
```bash
DEPLOY_HOST=your-server-ip ./scripts/bootstrap_server.sh
```
Доступ при bootstrap-настройках по умолчанию:
**http://your-server-ip:8090** через сгенерированный plain-HTTP Nginx reverse
proxy.

Подробнее см. [docs/DEPLOY.ru.md](docs/DEPLOY.ru.md).

---

## 🌐 Сетевые режимы

- **Bootstrap test access по умолчанию**: `http://server-ip:8090` через
  сгенерированный Nginx config. Это plain HTTP для lab/internal тестов.
- **Production mode**: `DEPLOY_MODE=production` не включает сгенерированный
  plain-HTTP Nginx proxy, если явно не задать `DEPLOY_SETUP_NGINX=1`.
- **Production exposure**: добавьте TLS через Nginx/Caddy/Cloudflare Tunnel
  или ограничьте доступ private network/VPN. Не публикуйте `3000` напрямую.

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
- Держите update из dashboard выключенным, если он явно не нужен
  (`MINI_OPS_ALLOW_WEB_UPDATE=false` по умолчанию).

Подробнее: [docs/SECURITY.ru.md](docs/SECURITY.ru.md).

Индекс документации: [docs/README.md](docs/README.md).

---

## 🤝 Вклад в проект (Contributing)

Мы рады любым вкладам! См. [CONTRIBUTING.ru.md](CONTRIBUTING.ru.md).

## 📄 Лицензия

Этот проект распространяется под лицензией [MIT License](LICENSE).
