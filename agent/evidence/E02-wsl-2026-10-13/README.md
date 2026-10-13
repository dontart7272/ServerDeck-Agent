# E02 Ubuntu WSL2 evidence, 13 октября 2026

Среда: установленный `Ubuntu-22.04`, Ubuntu22.04.5 LTS, WSL2 x86_64, kernel6.6.87.2-microsoft-standard-WSL2, обычный UID1000 dontart7272. Go1.27.2, cgo=1, `/usr/bin/gcc-11`11.4.0-1ubuntu1~22.04.3, glibc2.35-0ubuntu3.15. Зависимости прежние; точные 31 package/4372 toolchain file hashes сверены с [E01 lock](../E01-wsl-2026-10-13/linux-toolchain.lock.json). SQLite3.53.4/source ID/compile options фиксируются в linux-checks.txt.

Из корня проекта в PowerShell, без изменения Windows/VPS:

```powershell
wsl -d Ubuntu-22.04 -- bash /mnt/d/Projects/ServerDeck/agent/tools/wsl-e02.sh sync
wsl -d Ubuntu-22.04 -- bash /mnt/d/Projects/ServerDeck/agent/tools/wsl-e02.sh fault-binary
wsl -d Ubuntu-22.04 -u root -- unshare --mount -- bash /mnt/d/Projects/ServerDeck/agent/tools/e02-full-filesystem.sh
wsl -d Ubuntu-22.04 -- bash /mnt/d/Projects/ServerDeck/agent/tools/wsl-e02.sh check
wsl -d Ubuntu-22.04 -- bash /mnt/d/Projects/ServerDeck/agent/tools/wsl-e02-export.sh
pwsh -NoProfile -File 'Документация ServerDeck/Документация ServerDeck Agent/tools/check-docs.ps1'
```

`sync` создаёт новый mktemp каталог внутри ext4 `/home/dontart7272/serverdeck-e02-2026-10-13`; исходники/contract fixtures побайтово сравниваются с основным проектом. Go из E01 используется после проверки версии; build cache/tmp/SQLite tests находятся на Linux-ФС. Никакие Linux app-source файлы не переносились обратно: исправления сделаны в основном проекте и заново скопированы. `export` проверяет неизменность compiled/tested/tooling inputs, затем переносит только evidence и четыре соответствующих бинарника. При несовпадении input hash экспорт прекращается.

Фактические результаты финального прогона: [Linux команды/окружение/тесты](linux-checks.txt), [реальный ENOSPC](physical-enospc.txt), [исходная копия](source-copy.json), [сверка build inputs](build-inputs.json), [SHA256 бинарников](binaries.sha256), [документация](docs-check.txt), [сохранение прежнего кода](preserved-inputs.txt). JSON snapshots/compiled schemas и security fixes E01 не регенерировались.

V-STORE/V-AUDIT проверены на реальных временных SQLite: intent/result abort, read-only, SQLITE_FULL, фактический ENOSPC, corruption/permissions/migration mismatch, process-crash до intent/после intent/перед effect/после effect/после result, concurrent repeat/actor mismatch, CAS, явная отмена, disconnect-after-intent, quota/rotation/cursor gap, busy/checkpoint/долгое чтение, backup/restore/revocations/policy floor/raw rollback/lost floor/current operation dedup overlay/new settings revision/new audit epoch/old cursor rejection, отсутствие исходных секретных параметров в аудите/ошибках. Физический ENOSPC helper в обычном `go test` явно SKIP и отдельно реально выполнен на ext4 образе16МБ; это не пропуск сценария итогового прогона.

Native amd64 build/smoke/CLI/vet/test/race и arm64 cgo cross-build/ELF фиксируются отдельно. Native ARM не запускался (перенесён в E12); QEMU за нативные проверки не выдаётся. Общая матрица ОС/ФС, systemd, GPU, power-loss и реальные resource mutation adapters не проверялись. Иногда WSL предупреждает о systemd user session; этот offline-прогон не подтверждает работу службы.

Во время разработки исправлены: общий checkpoint по TEMP вместо main; преждевременная неявная отмена при request disconnect; rotation accounting и fairness для третьего инициатора; восстановление текущих operation IDs/unknown-состояний поверх старого snapshot и исключение ABA settings. Финальные логи относятся к повторному прогону после исправлений. Предварительная ручная race-команда без CC не собралась; финальный runbook явно закрепляет CC. Один предварительный runbook изменили во время чтения bash, что дало EOF после проверок; финальный прогон использует неизменённые tools и проверенный exit code, а не этот предварительный вывод.

Границы и консервативная ёмкость WAL — [STORAGE](../../STORAGE.md). Наличие этого отчёта не закрывает полные AFR/ASEC будущих этапов.
