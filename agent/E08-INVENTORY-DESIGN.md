# Актуализация inventory —15 октября2026

Следующий текст — исторический проект и evidence schema4/floor3. Текущая реализация добавляет migration005: critical schema5 и floor5. Миграции001–004 сохранены. Старый writer несовместим с schema5. Текущая реализация/проверки описаны в FILES.md; нижний проект сохранён как история.

`serverdeckctl state-inventory-confirm STATE INPUT_JSON OPERATION_ID --confirm` выполняется offline с эксклюзивным state lock через общий audited service `storage.inventory.confirm`. Вход: `{"known_regions":[],"absent_operation_ids":[],"artifact_bindings":[]}`; optional bindings связывают immutable artifact_id с region_path после остановленного обслуживания, не удаляя receipt и старый hint; оператор обязан включить известные внешние собственные копии, которые не представлены durable receipts. Все существующие receipts сверяются автоматически. Непустые `absent_operation_ids` отклоняются: отсутствие по пути не доказывает исчезновение копии. Локальный оператор утверждает полноту учёта; автоматического обнаружения произвольных копий или защиты от злонамеренного того же UID/root не обещается.

Подтверждение сохраняет generation и boot/dev/inode/type proofs проверенных областей; лимит32 областей, документ≤16000 bytes. Runtime допускает доступ только при точном соответствии текущего floor опубликованному authenticated floor и generation attestation текущему inventory. Backup/restore создаёт новый receipt до destination write и инвалидирует старое подтверждение. Перезагрузка, смена identity, перемещение собственного дерева или потеря proof закрывают допуск. Bootstrap state/config/key/code и runtime paths закрепляются отдельно. Текущая attestation и file journal сохраняются вместе с текущей authority при restore старого backup.

Модель обслуживания/дескрипторов и защиты предков уточнена прямым согласованием пользователя; актуальный текст — [FILES.md](FILES.md). Исторические утверждения ниже «команды complete нет» и «production всегда закрыт» относятся к снимку до migration005 и больше не задают текущее поведение.

---

# E08: owned-artifact inventory — решение и доступная реализация

**Подход согласован пользователем 15 октября 2026: «Делай как принято в стандартах разработки». Реализована консервативная часть; полнота inventory и baseline-процедура ещё не реализованы.** Причина — реальный TestE08UnregisteredRestoredStateNeverExposesKey: E02 restore создаёт request.key вне active state, а прежний state FD/params_hmac не дают полного постоянного учёта. [FILES](FILES.md) описывает текущий fail-closed gate. Без решения production чтение не включается.

## Рекомендация

Сохранить строгую защиту, добавить critical migration4 и security-floor3 с полным durable inventory собственных объектов/копий. Для существующей схемы3 baseline=unknown: отсутствие записи не считать отсутствием архива. Разрешить переход к подтверждённой legacy baseline только отдельной локальной CLI-процедурой с явным административным подтверждением учёта известных копий/восстановленных деревьев и сохранением непроверенных областей как запрещённых. Не делать silent filesystem scan/автоматическое «копий нет». Пользователь разрешил рекомендованный подход. До доказанной идентификации собственных объектов команда подтверждения полноты не предоставляется.

Новый floor/schema несовместимы с прежним writer: старый Agent обязан отказаться открывать обновлённое состояние; update/rollback не должен подсовывать старый binary. Новая версия читает старые backups, overlays текущую защиту и оставляет baseline unknown, где нет доказательства. Это отдельное совместимое чтение старых данных, а не обещание обратной записи старым Agent.

## Проект данных и транзакций

| Область | Предлагаемый контракт |
|---|---|
| critical.db migration4 | inventory_meta: format/generation/baseline unknown-or-complete; owned_artifacts: opaque id, kind, producing operation, planned/active/unknown/retired, trusted location hints/identity evidence, protected region; без secret bytes |
| security-floor3 | Monotonic inventory generation и сохраняемые запреты/неопределённые owned regions вместе с текущими отзывами/политикой. Restore объединяет protection, не выбирает более удобную старую копию |
| Fresh authority | Complete только после регистрации всех bootstrap/state/runtime/code/TLS/registry/release roots и проверенного создания новой authority. Не переносить эту презумпцию на legacy data |
| Backup/restore | Durable planned owned footprint + floor receipt до первой записи секретных данных. Target actual FD связывается с receipt; ошибка публикации floor блокирует дальнейшую запись. Directory creation/частичный результат отражаются существующей операцией |
| Crash | Planned/unknown footprint остаётся защищённым до сверки; повтор не создаёт новый секретный объект. Не удалять запись ради rotation/dedup quota |
| Restore/rollback | Старый backup не удаляет текущие protections; восстановленный request.key также зарегистрирован. Restore marker не публикуется раньше current security receipt |
| Identity | Path/dev number сами по себе не доказательство при rename/remount/reboot. Держать живые descriptors, проверять aliases/mount namespace; при невозможности привязать прежнюю область fail-closed. Формат evidence должен быть уточнён до кода |
| Limits | Размер/число inventory входят в critical physical budget. При исчерпании новые owned copies отказываются до побочных эффектов, неизвестные footprints не вытесняются. Точное число/профиль подтвердить вместе со спецификацией |
| CLI baseline | Показывает отсутствие доказательства и список учтённых/неизвестных областей; отдельное явное подтверждение, аудит, snapshot before/after и запрет автоматического enable. Кто вправе утверждать полноту и что делать с неизвестной областью — явная доверительная граница |

## Проверки до включения чтения

1. Реальные backup/restore на другой ФС: ключи/DB/служебные объекты не читаются под исходным, изменённым и bind/hardlink alias именем.
2. Отказ DB/floor до секретного write: новых key bytes нет; отказ после write/crash: footprint protected/unknown, retry без второго эффекта.
3. Legacy schema3/старые backups/потерянная metadata: никакого автоматического complete. Новая авторизация и старый writer не обходят gate.
4. Restore старой копии, raw rollback, несовпадающий security floor, смена boot/mount/identity: защита не ослабляется, Current revocations сохранены.
5. Rotation/retention/quota не удаляют единственное доказательство собственного объекта; завершённый operation expiry не означает исчезновение копии.
6. Локальная baseline-процедура проверяется отдельно; подписанное/доверенное подтверждение оператора не подменяет kernel path safety.

## Что этот проект не решает

Даже принятый inventory не закрывает BLOCK-FS/stat+rename и general shared-FS protected ancestry. Он не разрешает write/upload/trash/PURGE и не доказывает безопасность обычного home на общей ФС. Полный E08 всё ещё требует доказанного mutation profile либо отдельного решения о модели writers/maintenance. E09 не начинается.

## Фактическая реализация 15 октября 2026

Версия floor2 уже использована E03 для credential verifiers; inventory получает **floor3**, critical schema4. Миграции001–003 не изменены. 004.sql добавляет inventory_meta(generation, baseline) и owned_artifacts(id операции, backup/restore, location_hint, state). Единственные разрешённые baseline/state — unknown. Это намеренно ограниченный формат: complete/active/retired ещё не доказаны и не принимаются writer.

Максимум32 записей, hint≤1024 bytes, сериализованный inventory≤32000 bytes; весь sealed floor по-прежнему ограничен65536 bytes. Квота отказывает до destination effect; записи не удаляются ротацией операций. Путь — приватная подсказка для сверки, не kernel identity и не разрешение чтения. Secret bytes в inventory отсутствуют.

Maintenance service сохраняет audit intent, проверяет действующий security floor и admission/WAL границы, затем transaction inventory + security_generation, затем sync/rename/fsync и повторную проверку sealed floor. Только после успешной публикации разрешены создание destination и запись DB/request.key. При ошибке публикации неизвестная запись остаётся, destination не создаётся; SecurityFloorAvailable=false. Receipt неизвестен и после успеха: отсутствие immutable FD/identity proof не позволяет объявить иначе. Restore сначала проверяет, что current inventory содержит все receipts старой копии; расходящаяся ветка отклоняется до target writes. Это консервативный отказ вместо потери запретов. Restore копирует текущие inventory/meta вместе с authority tables и публикует current floor до complete marker. Проверка startup запрещает потерю записей из обязательного floor даже при большем security_generation. Raw rollback со старым floor одновременно остаётся общей границей доверия E02/E11, не новым решением против злонамеренного root.

Fresh и legacy authority обе начинают с unknown: учёт bootstrap/runtime/code/реальных aliases ещё не завершён. `serverdeckctl state-inventory /absolute/state` выводит приватные metadata локальному оператору при эксклюзивном offline открытии хранилища; это открытие, как и state-status, может выполнить миграцию/startup recovery. Нет команды complete, публичного endpoint или автоматического enable. Migration4 делает данные несовместимыми со старым writer; новый writer читает backups schema1–4.

Проверки: TestE08InventoryDatabaseFailurePreventsDestination, TestE08DivergentBackupInventoryRefusedBeforeRestore, TestE08InventoryReceiptFailurePreventsDestination, TestE08InventoryRestoreRetainsCurrentFootprints, TestE08InventoryQuotaNeverEvictsUnknown, TestE08LegacyInventoryMigrationNeverInfersCompleteness и прежние backup/revoke/raw rollback tests. Точные результаты — evidence E08. Baseline accounting, identity после rename/remount/reboot и безопасный допуск production чтения остаются **не реализованы**, поэтому TECH-FS-INVENTORY ещё открыт.

Будущий допуск чтения обязан привязываться к текущему inventory generation и живым proofs, а не только к флагу при старте. Новый backup/restore, неизвестный receipt или потеря identity должны закрывать допуск и активные tickets до сверки. Текущий production флаг всегда false; этот будущий протокол инвалидации ещё не реализован. Test-only true не является готовым протоколом.
