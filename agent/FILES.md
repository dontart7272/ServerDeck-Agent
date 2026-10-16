# Файловый доступ E08

16 октября 2026. E08 закрыт в согласованных границах и Ubuntu WSL2 amd64; результаты проверок — [итоговый evidence](evidence/E08-final-wsl-2026-10-16/README.md). Полная матрица выпуска остаётся E12.

## Реализованные компоненты

`internal/fileaccess` — Linux descriptor guard, native filesystem operations и приватные области. `internal/app/files*` — queries, ограниченные потоки, tickets, общий HTTP/Unix transport, обработчики application service, cleanup и CLI. `internal/operations/files_recovery.go` — аудируемая offline сверка; `internal/storage/files.go` — journal/attestation/retention. Все изменяющие операции и штатный CLI используют durable intent/аудит/operation ID до первого эффекта. Повтор не повторяет effect; неизвестный исход сохраняется, original operation lock снимается только отдельным явным resolve.

Реализованы roots/list/stat/text/download/tail, create/rename, upload/edit begin→PUT→commit, move на одной ФС и между ФС, trash.list/restore/PURGE. Restore между ФС также выполняется copy→verify→publish→source cleanup, с честным partial/unknown после публикации. Rename/restore между разными configured roots на одной ФС разрешены с теми же guards. Занятое имя сохраняется, пока нет отдельного explicit replace и версии; прежняя версия переносится в приватную корзину. Отмена допустима до фазы effect; остановка ожидания/передачи после effect не доказывает отмену изменения.

## Права и собственные объекты

Production использует shared-root профиль: обычный home может находиться на общей ФС с Agent. Openat2 BENEATH/NO_SYMLINKS/NO_MAGICLINKS/NO_XDEV и проверки inode/dev/типов защищают root boundaries. Traversal, symlink dereference, magic links, hard links, subtree bind mounts и собственные объекты/опасные предки отклоняются, также при root. Вложенный configured root внутри собственного каталога не обходит запрет. Целая ФС, представленная bind alias, проверяется по тем же inode. Приватное имя `.serverdeck-<agent-id>` и зарегистрированные private identities закрыты для API; собственные объекты запрещены и внутри staging/trash перед публикацией, восстановлением и удалением.

Bootstrap config, state, keys, runtime, executable/releases закреплены отдельно. `filesReady` проверяет опубликованный authenticated floor, generation, boot/dev/inode/type и live bindings перед запросом и во время потоков. Отказ не отключает мониторинг. `files`/read capabilities остаются независимыми от отказа аудита, изменяющие capabilities выключаются. Per-entry actions учитывают тип, права ОС, защищённые предки и состояние безопасности; access check является подсказкой, реальные syscall повторно проверяют права.

Профиль native adapter: ext4/tmpfs/XFS/Btrfs с mount root `/`; subtree mounts/subvolumes отвергаются. Фактические E08 испытания относятся к ext4/tmpfs в Ubuntu WSL2; остальные host/filesystem combinations проверяются в E12. Недоступный syscall/FS/права возвращает отказ, а не ослабленный fallback.

## Потоки и лимиты

Два общих transfer slots учитывают persisted pending transfers и активные read tickets. Public chunks≤64000 bytes, idle TTL300с, maximum lifetime3600с, размеры — runtime config. PUT требует octet-stream, точный Content-Length, независимую проверку фактических bytes и SHA-256. Ready receipt: `schema_version=1.0`, transfer_id, received_bytes (integer), sha256, ready=true. Брошенная/ошибочная загрузка не меняет target. Повтор failed ticket в пределах TTL сохраняет новый audit intent, заново резервирует и проверяет staging; повтор ready возвращает сохранённый receipt. Owner, revoke, runtime revision и deadline проверяются в потоке. Local Unix socket использует доверенный SO_PEERCRED; client device_id не доказывает личность.

Commit требует ready/owner/revision/size/hash. Для edit/explicit replace ticket.file_version означает версию исходного target; для нового имени — родителя. После загрузки нового файла можно передать свежую parent version без повторной загрузки. До публикации проверяются target, права, место и quota; затем durable unknown с recovery operation ID, сохранение предыдущей версии и atomic publication. Потеря результата не превращается в «не выполнено».

Деревья≤10000 узлов/глубина256; registry private identities≤65536; journal≤2048 записей с document≤8192 bytes. Перед copy/replacement неподдерживаемые special mode bits/xattrs/ACL/capabilities отклоняются; обычные uid/gid/mode/atime/mtime сохраняются. Symlink копируется как literal object без чтения target. Staging0600/private area0700, O_EXCL/NOFOLLOW, fallocate, fsync file/directory. Trash budget учитывает actual tree bytes и journal по ФС; свежие данные не удаляются ради нового запроса.

## Очистка и восстановление

Внутренний system:files service каждые30с проверяет истечение trash/staging и выполняет отдельные audited операции, не доступные через public prepare/execute. После рестарта истечение устанавливается консервативно: процесс должен отработать полный исходный retention interval; скачок wall clock сам по себе не разрешает удаление. Неизвестная публикация автоматически не повторяется и не очищается. Завершённые published/restored/purged metadata удаляются bounded пачками≤256 после семи дней и только при trustworthy clock; unfinished/unknown state не вытесняется. Отказ аудита блокирует cleanup и виден через storage health независимо от записи нового audit.

При остановленном Agent:

```text
serverdeckctl state-files STATE
serverdeckctl state-file-reconcile STATE CONFIG INPUT_JSON OPERATION_ID --confirm
serverdeckctl state-resolve STATE ORIGINAL_OPERATION_ID applied|none --confirm
```

Reconcile сверяет expected_version SHA-256 всей записи и реальные private/target identity proofs; варианты trashed/published/restored/purged только фиксируют наблюдаемое состояние. `discard` дополнительно требует observed_proof и полный guard из реальной bootstrap CONFIG, TLS/state/runtime/code и актуального inventory. State-only сервис не имеет разрушительного recovery пути. Reconcile не снимает блокировку исходной unknown operation; resolve — отдельное осознанное локальное решение, не автоматический вывод по отсутствию пути. Содержимое файлов/секреты в audit и evidence не записываются.

## Inventory и совместимость

Critical schema5, authenticated security floor5. Миграции001–005 сохраняются; floor5 закрывает доступ writer, не знающему artifact bindings и новые состояния journal. Explicit offline `state-inventory-confirm STATE INPUT_JSON ID --confirm` утверждает полноту учёта собственных копий доверенным оператором. Формат: known_regions, пустой absent_operation_ids, optional artifact_bindings=[{artifact_id,region_path}]. Binding нужен после перемещения собственной копии при остановленном Agent: оператор явно связывает immutable receipt с проверяемой областью, receipt/старый hint не удаляются. Отсутствие по старому пути не доказывает исчезновения копии. Автоматического обнаружения всех произвольных копий/защиты от злонамеренного того же UID/root нет.

Лимиты:32 receipts,32000 bytes inventory,32 regions/bindings,16000 bytes attestation. Backup/restore создают receipt до записи destination и инвалидируют подтверждение. Перезагрузка/перемещение/новая копия требуют нового локального подтверждения. При исчерпании лимита новые копии отклоняются, receipts не вытесняются. Restore старого backup сохраняет текущие отзывы, policy floor, inventory и file journal; независимые БД не объявляются общей транзакцией.

## Проверки и границы готовности

[Финальные команды и evidence](evidence/E08-final-wsl-2026-10-16/README.md) фиксируют конкретный снимок. Реальные SQLite/файловые effects: intent/result failure, subprocess crash в разных фазах, replay/конкуренция, version conflicts, cross-FS failpoints, restored-key/bind protection, private object promotion, revoke/длины/hash/UTF-8, audited expiry/retention, bounded ENOSPC и read-only. Последние два — только временные16МБ tmpfs в отдельном mount/PID namespace; host disk не заполняется.

Ограничения выпуска: native ARM, вся матрица Linux/ФС/ядра, production systemd и Android UX остаются E10–E12. Cross-build не является native ARM тестом. E09 автоматически не начинается. Старые [read-only](evidence/E08-wsl-2026-10-15/README.md) и [частичные completion](evidence/E08-completion-wsl-2026-10-15/README.md) снимки сохранены и не доказывают текущий код.

Технические основания: [Linux rename](https://man7.org/linux/man-pages/man2/rename.2.html), [faccessat2](https://man7.org/linux/man-pages/man2/access.2.html). Faccessat2 требует Linux≥5.8; наличие прав перед вызовом не заменяет проверку самим изменяющим syscall.

## E08: согласованная модель внешних writers —15 октября2026

Пользователь прямо согласовал рекомендованную модель: «Согласовать рекомендованную модель». Это заменяет прежнюю строгую гарантию BLOCK-FS для конфликтов версий, а не требования защиты собственных объектов Agent.

AFR-040/043/046/049 и ASEC-017 применяются так: Agent сериализует свои конфликтующие операции, проверяет ожидаемую идентичность/версию непосредственно перед публикацией и при обнаруженном конфликте отказывает без замены. Готовый результат публикуется атомарно в пределах одной ФС; перед заменой сохраняется предыдущая проверенная версия для восстановления. Между последней проверкой и публикацией остаётся гонка с внешней записью/rename через SSH, включая ранее открытый writable FD. Универсальный compare-and-swap содержимого Linux не обещается; сохранённая копия не объявляется точной версией, записанной внешним writer в этот промежуток.

Существующее имя не заменяется без отдельной политики/подтверждения. Cross-FS остаётся copy/verify/отдельный trash источника с честным partial/unknown. При неопределённости побочный эффект автоматически не повторяется. Аудит до effect, сохранность исходника при ENOSPC, запреты secrets/own objects/ancestors, права ОС, traversal/aliases/mount guards и отдельный PURGE не ослаблены. Технические gates безопасного пути/inventory остаются отдельными; эту новую модель нельзя использовать как разрешение обходить их.

BLOCK-FS как продуктовая развилка решён данным согласованием. Реализация проверяется в указанном ниже окружении; прежний контрпример stat+rename теперь проверяет объявленное ограничение, а не выдуманную гарантию отсутствия внешней гонки.

## E08: согласованная модель обслуживания и дескрипторов —15 октября2026

Пользователь прямо согласовал рекомендованную модель для AFR-042/043 и ASEC-014/015. Собственные корни, конфигурацию, ключи, БД и рабочие каталоги Agent администратор перемещает/перестраивает через SSH только после остановки Agent и его выполняющихся файловых действий. Обычные пользовательские файлы можно изменять параллельно, с ранее согласованным остаточным окном внешнего конфликта.

Разрешённый объект привязывается к проверенному дескриптору после openat2 BENEATH/NO_SYMLINKS/NO_MAGICLINKS/NO_XDEV. Перенос уже разрешённого пользовательского каталога внешним администратором может привести к неопределённому результату; непрерывное нахождение этого объекта под строковым именем корня не гарантируется. Это не разрешение клиенту обходить root policy: операции Agent сериализуются с изменением политики, относительные компоненты проверяются один раз, возвращаемые объекты повторно открываются под разрешённым root; при потере привязки — unknown, без слепого повторения.

API по-прежнему запрещает собственные объекты Agent, их aliases и разрушительные операции над необходимыми предками, также при root. Собственные каталоги защищены inode-идентичностями, каталогами-предками и private namespaces; обычные hard links и вложенные/поддеревные bind mounts не разрешаются обходом. Проверки закреплённых bootstrap paths/живых identities и опубликованного inventory сохраняются. Смена/потеря доказательства закрывает допуск. Эта модель заменяет прежнее требование устойчивости к произвольному одновременному административному переносу собственных рабочих деревьев; нарушение процедуры обслуживания не объявляется поддержанным сценарием.

TECH-FS-READ/мутации на общей ФС теперь реализуются в этих согласованных условиях. Успешные проверки старого строгого FS-deny профиля не заменяют новые V-FILE tests. Результаты текущего полного прогона фиксируются отдельно от исторического evidence.
