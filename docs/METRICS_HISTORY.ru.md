# История метрик

Mini-Ops примерно раз в минуту сохраняет в SQLite локальный срез метрик CPU,
памяти и ёмкости диска. `METRICS_RETENTION_HOURS` задаёт срок хранения этих
строк (`168` часов по умолчанию). Запросы истории переиспользуют
сохранённые строки и не добавляют новый collector или periodic writes.

Текущие значения диска показывают занятую, общую и свободную ёмкость,
где свободно = `total - used`. Collector читает только метаданные о ёмкости
файловой системы. Он не обходит деревья каталогов, не изучает source caches, данные
Docker или journals, не запускает привилегированные команды и не меняет состояние host.

Все описанные ниже endpoints требуют той же bearer-аутентификации, что и
dashboard:

```http
Authorization: Bearer <AUTH_TOKEN>
```

Временные метки — Unix seconds в UTC. Количество bytes в legacy response
передаётся как JSON-числа.

## Legacy-ответ с последними 60 samples

Запрос без query parameters сохраняет исходный контракт:

```text
GET /api/stats/history
```

Он возвращает JSON-массив не более чем из 60 самых новых raw samples в порядке
от новых к старым. Каждый элемент имеет ту же форму, что `/api/stats`:

```json
{
  "cpu_usage": 4.2,
  "memory_used": 811597824,
  "memory_total": 2076262400,
  "disk_used": 17200000000,
  "disk_total": 22530000000,
  "timestamp": 1786435200
}
```

## Ограниченный ответ за окно

Передайте поддерживаемый `window`, чтобы получить версионированный response с
сохранением пиков:

```text
GET /api/stats/history?window=1h|6h|24h|7d&resolution=auto|raw|5m|1h
```

`resolution` необязателен и по умолчанию равен `auto`. Response сообщает
фактическое resolution `raw`, `5m` или `1h`; значение `auto` не бывает фактическим.
Более крупные points сохраняют и средний, и максимальный процент, поэтому короткий
пик не скрывается в среднем значении bucket. Любой успешный response содержит не более
1500 points в хронологическом порядке.

При обычном минутном интервале сбора `auto` выбирает `raw` для `1h`, `6h` и
`24h`, а для `7d` — buckets `1h`. Он может выбрать более грубое resolution,
если фактическое количество строк иначе превысит лимит response.

```json
{
  "schema_version": 1,
  "window": "24h",
  "resolution": "5m",
  "requested_start": 1786348800,
  "oldest_timestamp": 1786348860,
  "newest_timestamp": 1786435200,
  "partial": false,
  "points": [
    {
      "timestamp": 1786349100,
      "sample_count": 5,
      "cpu_percent": { "avg": 12.4, "max": 48.1 },
      "memory_percent": { "avg": 39.2, "max": 39.6 },
      "disk_percent": { "avg": 76.3, "max": 76.4 }
    }
  ]
}
```

- `requested_start` — нижняя граница времени, рассчитанная для запроса.
- `oldest_timestamp` и `newest_timestamp` описывают сохранённые samples, которые
  вошли в response. Оба поля равны `null`, если samples нет.
- `partial` равен `true`, если retained data начинаются более чем через один
  номинальный 60-секундный интервал сбора после requested boundary; consumer не
  должен создавать впечатление, что доступно всё выбранное окно.
- `timestamp` обозначает raw sample или aggregate bucket, а `sample_count`
  сообщает, сколько stored samples вошло в point. Timestamp агрегированного
  point — выровненное по UTC начало bucket. Для `raw` point значение
  `sample_count` равно `1`, а `avg` равно `max`.
- Для raw point `memory_percent` или `disk_percent` равен `null`, если из
  сохранённой пары used/total нельзя получить корректный процент. Aggregate
  bucket использует содержащиеся в нём корректные проценты и возвращает `null`,
  если корректных значений нет. Invalid totals никогда не выдаются за ноль.
- Пустая history — успешный response с `points: []` и null в oldest/newest
  timestamps, а также `partial: false`, а не database error.

Сервер отклоняет explicit resolution, если он слишком мелкий для соблюдения
лимита 1500 points в выбранном окне. В частности, `7d` отклоняет explicit
`raw` и `5m`; поддерживаемое explicit resolution для него — `1h`. Используйте
`resolution=auto`, если API consumer не требует stable bucket size.

## Ошибки

Ошибки используют общий JSON envelope, например:

```json
{ "error": { "code": "invalid_history_query" } }
```

- `400 invalid_history_query`: любая query string без `window`,
  неподдерживаемый `window` или `resolution`, неизвестный либо повторяющийся
  query parameter. Запрос без query string остаётся валидным legacy-запросом,
  описанным выше.
- `400 history_resolution_too_fine`: explicit resolution не может соблюсти response
  bound для выбранного window.
- `503 metrics_history_unavailable`: SQLite не смогла обслужить history
  request, сохранённые CPU data некорректны или превышен жёсткий лимит исходных
  строк.

Ошибка аутентификации использует обычный protected-API response и не
возвращается как пустая history.
