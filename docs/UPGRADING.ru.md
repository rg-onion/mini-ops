# Обновление Mini-Ops

## С v1.1.0 на v1.2.0

Mini-Ops v1.2.0 сохраняет standalone non-root deployment model и намеренно не
удаляет существующее SQLite state. Перед обновлением обязательно создайте
проверенный online backup базы и сохраните предыдущий binary. При rollback
восстанавливайте совместимые binary и database backup вместе.

### Удалённые experimental surfaces

Удалены неработающие или вводившие в заблуждение поверхности:

- web source-build updater, `/api/deploy/*`, `scripts/update.sh` и
  `MINI_OPS_ALLOW_WEB_UPDATE`;
- страница истории деплоев и `/api/history`;
- Disk Analyzer/cleanup, `/api/disk/*` и
  `MINI_OPS_ALLOW_DISK_CLEANUP`.

Удалённые и неизвестные `/api/*` paths возвращают typed JSON `404`.
Существующий `history.json` остаётся inert legacy state: работающий агент его
не читает и не дополняет, а bootstrap сохраняет файл для rollback compatibility.

### Новое и изменённое поведение

- История ресурсов dashboard использует `/api/stats/history` с bounded окнами
  `1h`, `6h`, `24h` и `7d`.
- Security results разделяют подтверждённые findings, recommendations и
  unverified или partial coverage.
- Мониторинг direct-TLS endpoints включается отдельно через
  `SECURITY_CERTIFICATE_MONITOR_ENABLED` и root-owned targets file.
- Fleet Observation v1 впервые входит в v1.2.0 и остаётся строго opt-in;
  standalone monitoring никогда не зависит от Hub.

Перед включением новых collectors или outbound delivery прочитайте
`.env.example`, `METRICS_HISTORY.ru.md`, `SECURITY.ru.md`, `CLOUD_PUSH.ru.md` и
`FLEET_INTEGRATION.ru.md`. Начните с zero-mutation deploy plan из
`DEPLOY.ru.md`, затем после разрешённого обновления проверьте installed
checksum, service state, database quick check, local/public routes и rollback
point.
