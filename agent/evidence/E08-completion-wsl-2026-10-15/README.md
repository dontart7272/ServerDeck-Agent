# E08 — Ubuntu WSL2, новый снимок15 октября2026

E08 **остаётся открытым**. Это проверенный снимок реализованной части после прямого согласования модели external writers и обслуживания. Предыдущий E08 evidence не изменён. Границы и оставшаяся работа — [FILES.md](../../FILES.md).

## Окружение и исходники

Ubuntu-22.04 WSL2 Ubuntu22.04.5 amd64, kernel6.6.87.2-microsoft-standard-WSL2, Go1.27.2, CGO_ENABLED=1, GCC11.4.0, glibc2.35.4372 toolchain files совпали с E01 lock. Новых зависимостей нет; `go mod verify` PASS. SQLite3.53.4 фактически получен из обоих amd64 бинарных файлов. NVML headers дают прежние compiler deprecation warnings; это не runtime GPU test. WSL временами сообщал об отказе пользовательской systemd session; foreground команды завершились успешно, deploy/systemd readiness этим не подтверждены.

Новая ext4 копия: `~/serverdeck-e08-completion-2026-10-15/source.XXXXXX`; caches/tmp/DB/binaries также внутри этой Linux области. `source-copy.json` фиксирует254 первоначальных файла; `build-inputs.json` подтверждает233 окончательных executable/test/tooling inputs, совпадающих с основным проектом. Markdown обновлялся после проверок и отдельно фиксируется docs-snapshot. Сборка не выполнялась на /mnt/d, Windows dist и несвязанные изменения не перезаписывались.

## Команды и результаты

Из PowerShell в корне проекта:

```powershell
wsl -d Ubuntu-22.04 -- bash /mnt/d/Projects/ServerDeck/agent/tools/wsl-e08-completion.sh
wsl -d Ubuntu-22.04 -u root -- bash /mnt/d/Projects/ServerDeck/agent/tools/wsl-e08-completion-root.sh
wsl -d Ubuntu-22.04 -- bash /mnt/d/Projects/ServerDeck/agent/tools/wsl-e08-completion-export.sh
wsl -d Ubuntu-22.04 -- bash /mnt/d/Projects/ServerDeck/agent/evidence/E08-completion-wsl-2026-10-15/inventory-confirm-cli.sh
```

Все четыре команды exit0. `linux-checks.txt`: PASS gofmt/mod verify/vet, все unit/integration tests, `go test -race -count=1 ./...`, FuzzWeightedRollup215908 executions и FuzzE08Location46599 executions (10s nominal,2workers); cgo build обоих команд amd64/arm64; amd64 version/sqlite-info/ldd, compiled CLI/TLS shutdown/port conflict, offline state backup/replay/restore/resolve; isolated numeric PID reuse regression. Root-only tests в обычном go test пропускаются и выполнены отдельно.

`separate-filesystem.txt`: PASS native create/replay/rename; device-owned TLS PUT и отдельный commit; trash/list; occupied-name refusal без потери чужого файла; restore; отдельный PURGE; copy/verify/cross-FS source trash с directory/regular/symlink fixture. PASS защита собственного state/восстановленной копии и bind crossing. Два tmpfs по16000000 bytes создаются только внутри отдельного mount/PID namespace, затем снимаются; никаких Windows/VPS mounts не менялось. Строка fixture log «rejects own FS» — старое название: фактически проверяется отказ на собственном pinned directory; production shared filesystem теперь допускается согласно новой модели.

Дополнительно `separate-filesystem-race.txt`: те же реальные native cases PASS на `app-race.test`. Recipe сборки: в указанной копии после подключения E01 env, с GOCACHE/GOTMPDIR/TMPDIR из base и CC=gcc-11 выполнить `go test -race -c -o "$base/app-race.test" ./internal/app`, затем из PowerShell `wsl -d Ubuntu-22.04 -u root -- bash /mnt/d/Projects/ServerDeck/agent/evidence/E08-completion-wsl-2026-10-15/wsl-e08-race-root.sh`. SHA256 test binary — private-race-test.sha256.

Новые `TestE08SharedRootProtectsOwnObjectsAndAncestors` и `TestE08SharedRootsRenameAcrossUsesDestinationRoot`: обычная ext4 ФС, общий root, отказ собственному state/key и опасному предку, зарезервированное имя, обнаружение запрещённого live переноса собственных объектов, правильный destination root и отсутствие перезаписи занятого имени. Выполнены в обычном test и race.

`inventory-confirm-cli.txt`: реальный compiled serverdeckctl подтверждает attestation; replay возвращает ту же revision; новый backup инвалидирует прежнюю generation. В первом диагностическом вызове обнаружен неверный пример поля `absent` в документации: строгий decoder вернул INVALID_REQUEST. Пример исправлен на `absent_operation_ids`, повтор PASS; защиты не ослаблялись.

Бинарные SHA256 — binaries.sha256; ELF/динамические зависимости — elf-amd64.json/elf-arm64.json. ELF64 с cgo, needed libc.so.6, максимальный символ GLIBC2.34 на build host glibc2.35. ARM64 — только cross-build/ELF, никакого native ARM runtime результата нет.

## Статус требований

Согласовано: модели external writers/maintenance, explicit local inventory trust boundary. Реализовано: schema5/floor4, актуальный floor/proof/generation gate, перечисленные file handlers и conservative unknown до publication. Проверено: только названные WSL сценарии. AFR-019/040/042–050 и ASEC-014–017/027/031 целиком не закрыты.

Не выполнены: полный domain recovery/reconciliation, audited expiry/staging cleanup/rotation, завершение binary CLI и capabilities, окончательная синхронизация transfer semantics, полный V-FILE crash/ENOSPC/read-only/concurrency/retention/security suite, native ARM/host matrix. Незавершённое не выдаётся за blocked согласование. E09 не начат; stage completion не объявляется по PASS общих тестов.

Финальные документы и evidence связаны seal.py / docs-snapshot.json / artifacts.json. После новых изменений verify должен честно обнаружить drift.
