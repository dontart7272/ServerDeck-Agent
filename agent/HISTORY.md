# E05: история, события и догрузка

14 октября 2026. Реализация `internal/history`, `internal/events`, telemetry SQLite и защищённые application queries/operations. E01–E04 не заменены. Проверки и ограничения: [evidence](evidence/E05-wsl-2026-10-14/README.md), команды: [BUILD](BUILD.md). Статус итоговых проверок берётся из evidence, не из наличия пакетов.

## Компоненты и хранение

Общий E04 collector продолжает работать без телефонов. Runtime читает его immutable snapshots каждую секунду; одинаковое measured_at повторно не учитывается. Пакеты истории и вычисление правил запускаются каждые5с. Нет отдельного сбора на HTTP-запрос. CPU/system LA/PSI/network имеют15с→1м→5м уровни с целями1ч/24ч/7суток. RAM/filesystems используются для правил, обязательная история этих блоков не введена. NVML/GPU и распознанные native SSH adapters остаются E06; отсутствие адаптера явно сообщается agent.info.

`history.db` и `events.db` имеют самостоятельную миграцию1/checksum/user_version/agent_id/quick_check, WAL/FULL, incremental vacuum; private0600 files и pinned directory используют E02 owner lock. Неизвестная/повреждённая схема не пересоздаётся. `records(kind,id,series,segment,level,start,stop,revision,data)` хранит discriminated series/bucket/problem/offset; `changes(seq,kind,id,at,data)` — ограниченный event/problem журнал, unique event ID. Meta содержит epoch/revision/retention floor. Это физическое представление логических таблиц архитектуры; нет общей транзакции с critical.db или между telemetry DB.

Critical migration3 добавляет rules и rule_versions; правило получает opaque epoch:sequence, лимит256 правил/4096bytes на документ. Delete/recreate и restore сменяют версию, предотвращая ABA. Migration1/2 upgrade сохраняет auth/security floor E02/E03. Изменения rules.put/delete и config.set используют общий prepare/operation/version/intent-audit-before-effect. Для config.set сейчас разрешены группы history/events/audit; другие группы ожидают соответствующие этапы. Потеря результата после commit означает unknown/partial, а не failed/none. Снижение лимитов требует подтверждённого плана; незавершённая очистка не объявляется успешной. CLI и HTTP используют тот же service.

## Агрегация и границы времени

Gauge использует value*монотонную валидную длительность и веса coverage; LA — last, температура — max, throttling — observed_true. Ни NaN/Infinity, ни переполнение, ни сброс счётчика не превращаются в ноль. Boot/run/resource/reset/clock change разрывают baseline/segment. Разрыв более3 периодов или расхождение UTC/монотонного времени >1с не соединяется. Нет интерполяции отсутствующих данных.

Уточнение границы окон согласовано пользователем14 октября: точный uint64 counter delta целиком принадлежит окну завершения измерения (при точном завершении на границе — предшествующему окну). Распределение байтов внутри измеренного интервала не угадывается. `covered_ms` — валидное покрытие внутри UTC-окна, а `counter_covered_ms` — полная длительность интервалов, чьи приращения принадлежат окну. Counter mean=`sum/(counter_covered_ms/1000)`, max — наблюдённая скорость исходного интервала. При несовпадении длительностей окно неполное; rollup суммирует обе длительности отдельно и может устранить внутреннюю граничную неоднозначность. В запросе на край диапазона приращение нельзя трактовать как точное распределение трафика по секундам. Gauge сохраняет взвешенное наблюдение валидного интервала с обрезкой coverage у границ.

Bucket ID связывает UTC start/series/segment/step; revision возрастает при дополнении. Клиент заменяет старую точку по bucket_id только большей revision, не добавляет дубль. Persisted sufficient statistics, а не округлённые wire means, образуют старшие уровни. До4096 baselines,8192 cached buckets,4096 входов/rollup; превышение явно деградирует coverage. Чтение не удаляет историю другого телефона.

## Квоты и отказ

History budget по умолчанию256000000bytes включает allocated DB/WAL/SHM и резерв min(8МБ,10% budget). WAL admission≤8МБ; events WAL≤4МБ. Events journal default32000000bytes, активные проблемы отдельно≤10000/8000000bytes; общий физический events budget включает дополнительный active allowance8МБ. Индексы и резерв также расходуют физический бюджет; достижение физического предела может сократить журнал раньше номинального срока. Changes дополнительно ограничены100000; нет обещания удержать все7суток при любом потоке.

Один DB connection, transaction/read timeout1с, history flush общий deadline4с, batches32 records, individual JSON≤64000bytes, aggregate read≤3500000bytes. Pre-admission учитывает худшую запись страниц, остаток WAL и свободное место; max_page_count не считается ограничением WAL. Длинный reader не разрешает неограниченный WAL. Capacity reclaim удаляет старые bucket rows по порядку поступления, сохраняя последний уровень каждого ряда; events reclaim удаляет changes, не active problems/offsets/credentials. Вакуум ограничен128pages и действительно проходит SQLite statement до DONE. После скачка часов календарное истечение замораживается до нового run; физический budget продолжает действовать. При отказе history/events мониторинг и critical identity продолжают жить; независимый RAM health не требует записи журнала.

## События и источники

Начальные правила RAM<10%120с/восстановление>15%120с, FS/inodes<10%300с/>15%300с; CPU/GPU disabled; GPU device threshold не угадывается безE06. Source stale использует поддерживаемые поля и freshness, отсутствие optional поля не делает весь источник неисправным. Потеря источника/политики переводит active в source_unknown, не recovery; выдержка после перезапуска не продолжается по UTC. Begin/repeat/recovery различаются, repeat≥1ч. Нет автоматического управления сервером.

State+event+source offset атомарны только внутри events.db. Event ID и payload заморожены до подтверждённой записи: потерянный commit acknowledgment не создаёт второй begin/recovery. Восстановление загружает active state независимо от ротации begin; события не подменяют текущее состояние. Пропуск записи виден через health и последующий coverage gap marker.

Typed SSH fixtures проверяют5 failures одного нормализованного IP за5мин, отдельные адреса, физические поколения источника/positions, rotation/dedup, непрерывное quiet recovery и потерянные commit replies. Встроенный ssh_window редактируется как ssh.failures; произвольный log text не принимается. Настоящий journal/file adapter не реализуется вE05: это E06. Source offsets не доказывают полноту нераспознанного источника, неудачи не названы атакой.

## Transport и клиентские fixtures

history.series(metric_key?,logical_key?,cursor?,limit≤100) находит текущие и сохранённые поколения. history.get принимает≤32 series IDs, range≤7d,≤2000points/series/page≤4МБ; страницы идут по одному ряду, продолжение явное, unit сохраняется в registry. Covered/gaps/step/complete возвращаются отдельно от requested range. HMAC cursor привязан к actor/query/run/epoch, TTL15мин; retention epoch change даёт CURSOR_GAP, клиент начинает свежий диапазон. Ни заявленный body device_id, ни чужой cursor не авторизуют чтение.

events.list/problems.list/rules.list сохраняют предел100. WSS events/problems используют durable changes+ACK и resume; recovery передаёт problem tombstone `{problem_id,removed:true,observed_at}`. Retention gap содержит earliest_cursor/latest_cursor и текущие active_problems (первые100 + more), клиент запрашивает оставшиеся. WSS≤16subs/4МБ pending, ACK timeout30с/1013, отзыв credentials закрывает соединение. Fixtures history-response/history-response-updated и wss-problem-removed проверяются runtime codec и docs validator; это контракт Android cache, не реализация Kotlin cache128МБ/WorkManager.

## Проверка и границы готовности

Реальные SQLite: atomic rollback, SIGKILL во время записей, read-only, corruption/schema mismatch, busy/checkpoint/deadline, retention/active state, lost commit reply; physical ENOSPC только private16МБ ext4 image. Реальные TLS/WSS loopback: unauthorized/cross-actor, versioned rules/config и audit intent, resume/removal/gap/slow client. gofmt/vet/test/race/fuzz, cgo amd64/arm64 build/ELF, compiled CLI smoke — точные результаты в evidence. Native ARM, настоящий VPS/systemd, NVML/native SSH/Docker, модули и Android runtime остаются зависимым этапам; E06 автоматически не запускается.

Официальные основания SQLite: [WAL/checkpoints/readers](https://www.sqlite.org/wal.html), [max_page_count/auto_vacuum/incremental_vacuum](https://www.sqlite.org/pragma.html). Эти документы объясняют ограничения, но не заменяют фактический pinned-runtime тест.


Уточнение завершения15 октября2026 (прогоны именованы по UTC14 октября): config.set при незавершённом уменьшении budget/retention возвращает новую version и cleanup_operation_id, равный ID текущей операции, со статусом unknown/partial/CLEANUP_PENDING. Это та же наблюдаемая операция применения политики и очистки, а не потерянное фоновое действие. До подтверждения результата сохранённый intent/lock не удаляется; повтор не запускает очистку заново. По правилам E02 требуется сверка и штатное административное resolve после проверки остатка/health; неизвестный исход автоматически не объявляется успехом. При пустом журнале уменьшение срока завершается succeeded и cleanup_operation_id=null. Calendar cleanup не обходит консервативные clock guards. Это ограничение доступности при неопределённости, не ложный failed/none и не откат принятой политики.
