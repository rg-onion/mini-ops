# Выпуск Mini-Ops

Mini-Ops распространяется как GitHub source/binary release. Rust crate и
embedded frontend не публикуются отдельно в crates.io или npm, потому что
поддерживаемая единица поставки также включает scripts, systemd unit, примеры
конфигурации и эксплуатационную документацию.

## Release contract

- Rust `1.93.0`, Node.js `24.17.0` и npm `12.0.1` зафиксированы в репозитории
  и CI.
- Версии в `Cargo.toml`, `frontend/package.json` и tag `vX.Y.Z` должны
  совпадать.
- CI должен пройти Rust tests/fmt/clippy/audit, frontend lint/build/audit и
  shell contract fixtures.
- Tag workflow собирает release на Ubuntu 22.04 и публикует Linux x86-64
  archive, `SHA256SUMS`, SPDX JSON SBOM, build provenance и SBOM attestation.
- Release archive создаётся только из tracked files и проверенного binary.
  Локальные planning-файлы, environment files, tokens, databases и другое
  untracked state в него никогда не попадают.

## Подготовка release

1. Завершите release audit и устраните все blockers.
2. В отдельной version-задаче одновременно обновите Rust и frontend versions.
3. Проверьте exact diff и выполните локальные CI-equivalent checks.
4. Закоммитьте, проверьте и смержите release-ready tree без создания tag;
   post-merge CI default branch должен пройти.
5. Разверните этот exact default-branch commit на test VPS с rollback point и проведите
   непрерывный 72-часовой soak. Требуются `NRestarts=0`, RSS ниже 50 MiB,
   успешный SQLite quick check, отсутствие новых warning/error patterns и хотя
   бы один плановый certificate cycle при включённом collector. Любое изменение
   source создаёт нового кандидата и перезапускает soak.
6. Создайте и отправьте соответствующий signed или annotated tag `vX.Y.Z` на
   exact commit, прошедший soak.

Push tag запускает `.github/workflows/release.yml`. Не заменяйте вручную assets
существующего tag. По возможности включите immutable GitHub Releases в
настройках репозитория.

После публикации скачайте официальный archive и проверьте checksum и
attestations до финального smoke на test VPS. Локально собранный candidate
является soak evidence, но не заменяет проверку опубликованного artifact.

Если workflow, запущенный tag, завершился до публикации release, исправьте его
в default branch и повторите через `workflow_dispatch`, передав существующий
неизменяемый tag во входе `tag`. Повторный запуск checkout-ит и проверяет именно
этот tag; не перемещайте и не пересоздавайте его.

## Проверка скачанного release

Скачайте archive, SPDX SBOM и `SHA256SUMS` из одного GitHub Release:

```bash
sha256sum --check --ignore-missing SHA256SUMS
gh attestation verify mini-ops-vX.Y.Z-linux-x86_64.tar.gz \
  --repo rg-onion/mini-ops
```

Распакуйте archive и сначала выполните non-mutating deploy plan:

```bash
tar -xzf mini-ops-vX.Y.Z-linux-x86_64.tar.gz
cd mini-ops-vX.Y.Z-linux-x86_64
DEPLOY_HOST=server.example \
  DEPLOY_DRY_RUN=1 \
  DEPLOY_RUN_LOCAL_BUILD=0 \
  ./scripts/bootstrap_server.sh
```

Перед разрешением remote mutation прочитайте `docs/DEPLOY.ru.md`.
