# E08 — итоговый снимок16 октября2026

Статус: **E08 закрыт** в согласованных границах и указанном Ubuntu WSL2 окружении. Этот каталог не заменяет исторические evidence15 октября. [Реализация и границы](../../FILES.md), [команды](../../BUILD.md).

Ubuntu-22.04 WSL2, Ubuntu22.04.5 amd64, kernel6.6.87.2-microsoft-standard-WSL2, Go1.27.2, CGO_ENABLED=1, GCC11.4.0, glibc2.35. Отдельная Linux ext4 копия ~/serverdeck-e08-final-2026-10-16/source.XXXXXX; все кэши, временные данные, SQLite и бинарные файлы внутри Linux. Source-copy/build-inputs фиксируют SHA-256; export не перезаписывает исходники основного проекта.

Команды из PowerShell в D:\Projects\ServerDeck:

```powershell
wsl -d Ubuntu-22.04 -- bash /mnt/d/Projects/ServerDeck/agent/tools/wsl-e08-final.sh
wsl -d Ubuntu-22.04 -u root -- bash /mnt/d/Projects/ServerDeck/agent/tools/wsl-e08-final-root.sh
wsl -d Ubuntu-22.04 -- bash /mnt/d/Projects/ServerDeck/agent/tools/wsl-e08-final-export.sh
pwsh -NoProfile -File "Документация ServerDeck/Документация ServerDeck Agent/tools/check-docs.ps1"
python agent/evidence/E08-final-wsl-2026-10-16/seal.py --verify
```

Первый незавершённый прогон остановлен I/O error при ~45МБ свободного C:. Повтор начат после удаления только воспроизводимых cache/tmp прежних ServerDeck сборок в Ubuntu. Исходники/evidence/toolchain сохранены; перенос/resize WSL, настройки Windows/VPS не выполнялись. Отдельный warning systemd user session учитывается как ограничение lifecycle, не результат foreground тестов.

Не выполнены: native ARM (E12), вся host/kernel/FS matrix и production systemd (E11/E12), Android UX (E10). Arm64 cross-build не означает native testing. Остаточная SSH writer race и stopped-own-tree maintenance — прямо согласованные модели, не скрытая абсолютная гарантия. E09 не начинается.

## Фактические результаты

Основной/root/export scripts exit0. Полный linux-checks содержит gofmt/mod verify/vet, go test -v -count=1 ./..., go test -race -count=1 ./..., history/location fuzz10s с2workers (214723/66876 executions), обе cgo сборки и ELF, amd64 обе команды version/sqlite-info/ldd, compiled CLI HTTPS/IPv6/Unix download/upload/commit/shutdown/port conflict, state init/backup/replay/restore/resolve, isolated PID reuse. Source-copy:270 initial files, build-inputs:249 final executable/test/tooling inputs. Оба совпали с основным проектом; Markdown отдельно фиксируется docs-snapshot.

4372 native/cross toolchain files и exact package revisions совпали с E01 lock. Dependencies прежние: go-sqlite3 v1.14.52, jsonschema/v5 v5.3.1, coder/websocket v1.8.15, NVIDIA/go-nvml v0.13.4-1; go mod verify PASS, лицензии/происхождение — THIRD_PARTY_NOTICES и ранее закреплённые данные. Новых dependencies нет. SQLite3.53.4/source_id из обоих amd64 binaries; ELF64 amd64/AArch64, dynamic libc.so.6, max required GLIBC2.34≤builder2.35. Бинарные SHA-256 — binaries.sha256/elf-*.json. NVML compiler deprecation warnings не означают runtime GPU test.

separate-filesystem.txt и separate-filesystem-race.txt: все3 E08 mount tests PASS, реальные same/cross-FS effects/restore/PURGE, copy/verify/publish/source_trash failpoints и recovery; full/read-only original-preservation; unregistered/restored own-key/hardlink/whole-FS bind protection. root-guards[-race].txt: private own-object promotion denied, shared root/ancestor/nested root protection PASS. Два16МБ tmpfs только private mount/PID namespace, propagation меняется только там, trap удаляет свои mounts/temp data. Test code проверяет объём≤16004096 bytes; Windows/WSL host disk не заполняется.

Supplemental команды (все exit0):

```powershell
wsl -d Ubuntu-22.04 -- bash /mnt/d/Projects/ServerDeck/agent/evidence/E08-final-wsl-2026-10-16/extra-linux.sh
wsl -d Ubuntu-22.04 -u root -- bash /mnt/d/Projects/ServerDeck/agent/evidence/E08-final-wsl-2026-10-16/root-race.sh
wsl -d Ubuntu-22.04 -- bash /mnt/d/Projects/ServerDeck/agent/evidence/E08-final-wsl-2026-10-16/inventory-confirm-cli.sh
wsl -d Ubuntu-22.04 -- bash /mnt/d/Projects/ServerDeck/agent/evidence/E08-final-wsl-2026-10-16/cli-reconcile.sh
wsl -d Ubuntu-22.04 -u root -- bash /mnt/d/Projects/ServerDeck/agent/evidence/E08-final-wsl-2026-10-16/foreign-peer.sh
```

extra-linux: compiled codecs принимают internal Operation read views, отвергают internal actions в public prepare/execute и malformed receipt bounds. Inventory CLI: durable confirmation/replay, backup invalidation PASS. Reconcile CLI: temporary real SQLite BLOB journal fixture, real config/runtime/TLS-path/code guards (pin-only fixture, service не запускается), state-files→audited reconciliation→replay PASS; исходная операция не создаётся/не разрешается автоматически. Два первоначальных fixture failures (число SQL columns и TEXT вместо штатного BLOB) исправлены в тестовом script; код Agent не ослаблялся. Foreign-peer: actual SO_PEERCRED чужого UID rejected под race; первоначальный запуск из неверного cwd исправлен явным Linux fixture cwd/pipefail.

Default root/mount SKIPs не засчитаны за PASS; соответствующие E08 случаи исполнены отдельными scripts. CrashEffectChild — subprocess helper, реальные фазы запущены TestE08CrashNeverAutomaticallyRepeatsFileEffect. Старые physical DB/telemetry ENOSPC, foreign process/ping procedures не заявлены как повторно исполненные: их собственные stage evidence сохранены. Это не незакрытые E08 file критерии.

Контракты/документация: штатный check-docs, затем seal.py и seal.py --verify. docs-check.txt хранит actual результат; build-inputs/docs-snapshot/artifacts фиксируют проверяемую целостность. Старые evidence seals сравнивают прежние исходники и ожидаемо обнаруживают drift текущего кода, сами прежние artifacts не переписаны.

Незакрытых критериев реализации E08 нет. Для выпуска остаются перечисленные native ARM/host/systemd/Android проверки будущих этапов. E09 не начат.

После завершения всех Linux проверок, export, check-docs и seal отдельный read-only Get-PSDrive C,D показал C: free=0 bytes, D: free≈153611235328 bytes. Причина дальнейшего расхода C: этим замером не установлена; удаление Linux build cache освобождает ext4 blocks, но не гарантирует уменьшение Windows VHDX. Новых сборок после замера не запускали. Это проблема ёмкости окружения перед последующим этапом, не основание выдумывать неуспех уже завершившихся E08 проверок. Чужие файлы/Windows settings/WSL resize/compact не изменялись.
