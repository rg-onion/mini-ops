# Управление дисковым пространством

Disk Analyzer показывает текущий размер Rust build artifacts, frontend
dependencies, данных Docker и системных логов, когда источник доступен в рамках
трёхсекундного command budget. Для недоступного или превысившего timeout
источника показывается `Unknown`. Экран панели работает только на чтение и не
содержит кнопок очистки.

## Destructive operations

Серверная очистка диска по умолчанию выключена. Экспериментальный
аутентифицированный server-side API доступен только при точном значении
`MINI_OPS_ALLOW_DISK_CLEANUP=true`. После включения он принимает только
аутентифицированные запросы для Rust `target/`, `frontend/node_modules/` и
очистки journald.

Очистка Docker недоступна в этой версии даже при включённом экспериментальном
gate. Для target `docker` маршрут `/api/disk/clean` возвращает
`403 operation_unavailable` и не может запустить `docker system prune -af`.

Dashboard остаётся только для чтения даже при включённом экспериментальном
server gate.
