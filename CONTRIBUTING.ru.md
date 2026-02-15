# Вклад в развитие Mini-Ops

Спасибо за ваш интерес к проекту Mini-Ops! Мы приветствуем любые вклады.

## С чего начать

1.  **Сделайте Fork репозитория** на GitHub.
2.  **Склонируйте ваш fork** локально:
    ```bash
    git clone https://github.com/rg-onion/mini-ops.git
    cd mini-ops
    ```
3.  **Установите зависимости**:
    - Rust (последний stable)
    - Node.js (v20+)

## Рабочий процесс (Workflow)

### Backend (Rust)
Бэкенд — это монолитный сервис на Axum.
```bash
cargo run
```

### Frontend (React)
Фронтенд — это приложение на Vite + React в папке `frontend/`.
```bash
cd frontend
npm install
npm run dev
```

## Процесс Pull Request

1.  Создайте новую ветку для вашей фичи или исправления:
    ```bash
    git checkout -b feature/cool-new-thing
    ```
2.  Внесите изменения и сделайте коммит с понятным описанием.
3.  Запушьте ветку в ваш fork.
4.  Создайте Pull Request в ветку `main` оригинального репозитория.

## Стандарты кода

- **Rust**: Используйте `cargo fmt` и `cargo clippy` перед отправкой.
- **Frontend**: Используйте `eslint` и `prettier`.
- **Коммиты**: Используйте convention commits (например, `feat: add new widget`, `fix: resolve crash on startup`).

## Лицензия

Внося вклад, вы соглашаетесь с тем, что ваш код будет лицензирован под MIT License.
