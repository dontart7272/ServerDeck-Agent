# Машиночитаемые контракты v1

12 октября 2026 года. JSON Schema draft-07. Файлы self-contained, внешние `$ref` отсутствуют. `$id` — идентификатор, не сетевой endpoint. Root API/IPC/UI принимает семейство сообщений; реализация обязана выбрать конкретное определение по endpoint/направлению/pending RPC, а не считать любой root-valid тип разрешённым на любом маршруте.

| Файл | Что проверяет |
|---|---|
| [api.schema.json](api.schema.json) | Pair/queries/responses/prepare/operations/errors/WSS, typed records/metrics/history |
| [module.schema.json](module.schema.json) | Манифест/зависимости/запуск/declarations/запрошенные ресурсы |
| [ipc.schema.json](ipc.schema.json) | JSON-RPC payload, typed methods/handshake/reports; framing проверяется отдельно |
| [ui.schema.json](ui.schema.json) | Manifest/UI tree/signature envelope; ZIP/подпись/trust проверяются отдельно |
| [config.schema.json](config.schema.json) | Bootstrap/seed defaults; runtime import имеет отдельный type в API |
| [release.schema.json](release.schema.json) | Release compatibility/digests; не TUF-проверка |

Примеры: [конфигурация](examples/config.json), [query](examples/query.json), [operation](examples/operation.json), [module](examples/module.json), [IPC](examples/ipc.json), [UI](examples/ui.json), [release](examples/release.json), [каталог query/action/method](examples/catalog.json). Все UUID/digests/планы в примерах синтетические, не рабочие секреты/подписанный выпуск. `release.json` демонстрирует форму, не подтверждённые glibc/dependencies.

Проверяемые ответы: [snapshot с сохранённым нулём и текущим отказом прав](examples/snapshot-response.json), [неопределённый результат операции](examples/operation-state.json), [отказ аудита до действия](examples/error.json), [ответ IPC](examples/ipc-response.json). Схемы не превращают синтетический ответ в испытание приложения.

Семантические требования сверх схем: U64<=максимума, календарная корректность timestamp, decoded path-component/no links/mounts/alias/races, freshness/value cross-fields, from<to, unknown operation semantics, plan/versions/authorization/audit ordering, суммарные byte/depth/cardinality quotas, IPC pending-result schema, schema subset/depth запреты remote refs/recursive declarations, dependencies, UI node uniqueness/type-specific bindings/layout, signature inventory/pixel/ZIP bounds и trust. Dynamic `JsonValue` допускается только в envelope объявленного и отдельно проверяемого module/read/action результата; не разрешает произвольную команду. Конечный JSON parser проверяет bytes/depth/duplicate keys до JSON Schema.

Документационный генератор [build-contracts.py](../tools/build-contracts.py) хранит определения без приложения, `python .../build-contracts.py` обновляет шесть JSON и примеры. [check-docs.ps1](../tools/check-docs.ps1) на PowerShell7 проверяет локальные ссылки/AFR/ASEC/строки журнала, refs и примеры через Test-Json, отрицательные fields/лимиты/действие, согласованные defaults. Это проверка документов, не конформанс готового Agent; полный V-CONTRACT выполняется после E01.

E01: кодеки, типы и finite subset validation реализованы в agent/internal/contracts; команды и фактические ограничения — [BUILD](<../../../agent/BUILD.md>). Семантические проверки прав, доверия IPC, подписей, архивов и системных эффектов остаются задачами зависимых этапов. Ошибки кодека INVALID_INPUT/LIMIT_EXCEEDED/SCHEMA_MISMATCH пока локальные; преобразование в сетевой ErrorEnvelope выполняется в E03.
