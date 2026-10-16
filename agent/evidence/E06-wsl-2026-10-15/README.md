# E06: фактические проверки Ubuntu WSL2

15 октября 2026, Europe/Moscow; последний полный прогон начался 14 октября 23:03:47 UTC. Итог доступных проверок — PASS. Этап E06 целиком **не закрыт**: V-GPU и реальная V-ADAPTER matrix остаются открыты.

## Окружение и соответствие исходникам

Использована именно Ubuntu-22.04 WSL2: Ubuntu22.04.5, x86_64, kernel6.6.87.2-microsoft-standard-WSL2, UID1000. docker-desktop остановлен и не использовался. [Inventory](wsl-distributions.txt) — вывод `wsl.exe --list --verbose`, преобразованный в UTF-8 без NUL padding.

Go1.27.2, CGO_ENABLED=1, GOTOOLCHAIN=local, GCC11.4.0, builder glibc2.35. E01 package/toolchain lock совпал по 4372 файлам. SQLite runtime3.53.4 и полный source ID/compile options записаны в [linux-checks](linux-checks.txt). Системная SQLite не подменяла embedded amalgamation.

Свежая ext4-копия: `/home/dontart7272/serverdeck-e06-final-2026-10-15/source.Gr2bio`; caches/tmp/test DB под Linux-ФС. [source-copy.json](source-copy.json) содержит SHA256198 файлов при копировании; [build-inputs.json](build-inputs.json) подтверждает совпадение181 фактически проверенного/собранного input с основным проектом после проверок. Markdown обновлялся отдельно; его финальный снимок — docs-snapshot.json. [binaries.sha256](binaries.sha256) — четыре binaries из этой копии. Export переносил только evidence, без перезаписи источников и Windows dist.

## Команды и результаты

Из корня проекта:

```powershell
wsl.exe -d Ubuntu-22.04 -- bash /mnt/d/Projects/ServerDeck/agent/tools/wsl-e06.sh
wsl.exe -d Ubuntu-22.04 -- bash /mnt/d/Projects/ServerDeck/agent/evidence/E06-wsl-2026-10-15/extra-commands.sh
wsl.exe -d Ubuntu-22.04 -- bash /mnt/d/Projects/ServerDeck/agent/tools/wsl-e06-export.sh
pwsh -NoProfile -File "Документация ServerDeck/Документация ServerDeck Agent/tools/check-docs.ps1"
```

Основной script печатает точные Linux команды и окружение в linux-checks.txt; дополнительные read-only команды сохранены в [extra-commands.sh](extra-commands.sh). Исторический pre-final-checks.txt относится к предыдущему source snapshot и не заменяет итоговый прогон.

| Проверка | Фактический результат |
|---|---|
| gofmt, go mod verify, go vet ./... | PASS |
| go test -v -count=1 ./... | PASS; три отдельные процедуры SKIP перечислены ниже |
| go test -race -count=1 ./... | PASS всех девяти пакетов с тестами |
| FuzzWeightedRollup / FuzzSSHProfile, 10s, parallel2 | PASS; реальные числа запусков в Linux log |
| Linux amd64 cgo, обе команды | PASS version/sqlite-info, compiled CLI/TLS/Unix/start/stop/port-conflict smoke |
| Critical state smoke | PASS init/status/backup/replay/restore/resolve на private временных БД |
| Linux arm64 cgo cross-build | PASS обе команды; выполнение ARM не проводилось |
| ELF/динамические зависимости | ELF64 x86-64/AArch64; max GLIBC2.34 у четырёх binaries; подробности [elf.txt](elf.txt), amd64 ldd в log; RPATH/RUNPATH не обнаружены |
| Штатный docs validator | PASS: [docs-check.txt](docs-check.txt), 72AFR/31ASEC,103ledger rows,6schemas,178types,16positive/18negative fixtures |
| Source identity / export inventory | PASS198 initial copies и181 final build inputs |

В процессе исправлены равнодлинная перезапись auth.log, длина временного Unix socket, сохранение неполного health/working-set состояния, недопустимые категории security records, монотонное старение nested metrics и классификация NVML handle/UUID permission. Успешный итог относится к последнему snapshot, не к промежуточным binaries.

## Что именно подтверждают новые тесты

- TestSMIProfileUnitsUnsupportedIdentityAndMalformed / TestNVMLIdentityPermissionIsNotGenericError: units, nil/unsupported, malformed/duplicate/NaN/negative, SDK return classification; fixtures **не являются настоящим GPU**.
- TestGPUHistoryPersistsMaxMeanAndSeparatesSource / TestGPUDeviceThresholdRequiresFreshSameResourceThreshold: реальные SQLite, source identity, mean/max и device-derived threshold без выдуманного default.
- TestDockerUnixNegotiationWorkingSetAndReadOnly / TestDockerVersionBoundaries: реальный Unix socket, peer/inode checks, fixed GET, API negotiation, working set, отсечение секретных полей,403/redirect/oversized body. HTTP fixture **не является Docker daemon**.
- TestAuthFileRotationCopyTruncateAndLostCursorAck: реальные временные файлы, rename/copytruncate, durable generation, потеря ACK и отсутствие второго эффекта. TestSecurityHooksPersistCursorAndDeduplicateInfoOnRealSQLite отдельно подтверждает cursor/HMAC/info dedup на настоящей SQLite.
- TestFail2banUnknownOrIncompleteListCannotClaimCoverage / TestJournalRecoveryProbeRequiresTrustedMetadata: неизвестный/неполный формат и trusted metadata. Реальный vacuum journal не проводился.
- TestSecurityObservationsMatchExistingContract плюс Snapshot validation в GPU/Docker fixtures: результаты соответствуют действующему контракту без новых enum categories.
- TestNestedMetricUsesMonotonicAgeAndSourceFailure / TestSnapshotAgesNestedMetricsAndMarksPartial: nested values становятся stale/partial по monotonic time, даже при обратном переводе wall clock; последнее значение сохраняется.

## Непроведённые проверки и границы готовности

[adapters-environment.txt](adapters-environment.txt): отсутствуют NVML/nvidia-smi, /dev/nvidiactl, Docker Unix socket и fail2ban-client. /dev/dxg сам по себе не подтверждает NVIDIA. В PATH есть Windows Docker CLI, он не использовался. journalctl249.11 поддерживает фактически применённые --system/--after-cursor/--no-tail/--output-fields/--since; наличие flags не подтверждает всю journal/OS matrix.

Открыты: реальный NVIDIA GPU/driver/UUID/unsupported/permission и native crash/hang в изоляции; настоящие Docker rootless/rootful/version scenarios; Ubuntu/Debian auth/journal/vacuum/firewall/Fail2ban matrix. nft tables-only профиль сознательно всегда partial; сведения о видимости не доказывают эффективность firewall. Native ARM, обычные Linux-серверы, Android и release soak не проверялись. NVML native fault остаётся риском общего процесса, описанным в [INTEGRATIONS](../../INTEGRATIONS.md).

В общем test run отдельно SKIP: TestForeignUIDAdminPeerIsRejected (требует изолированной root процедуры), TestPhysicalFullFilesystem и TestTelemetryPhysicalFullFilesystem (требуют bounded ext4 процедуры). E03/E05 исторические результаты сохранены, но эти процедуры не объявляются повторно выполненными для E06. SQLite quota/read-only/corruption/busy/long-reader тесты в общем прогоне выполнены.

Новых публичных служб, changing HTTP/IPC, системной установки, смены групп, драйверов, firewall или VPS не было. E07 не начинался. Детали реализации и ограничений: [INTEGRATIONS](../../INTEGRATIONS.md), [BUILD](../../BUILD.md). Лицензия NVML и provenance: [modules.json](modules.json) (Go JSON stream), [nvml-provenance.json](nvml-provenance.json), [runtime-packages.txt](runtime-packages.txt), THIRD_PARTY_NOTICES в agent/.

Отдельный NVML header13.4.92 notice сохранён в agent/licenses/NVML-header-NVIDIA-notice.md вместе с SHA256 исходного header. Apache-2.0 относится к Go bindings; header notice и лицензия существующего driver учитываются отдельно. Эта документационная поправка не меняет181 проверенный build input.

Повторная проверка соответствия основному проекту и целостности evidence: `python -X utf8 agent/evidence/E06-wsl-2026-10-15/seal.py --verify` из корня. Сверяются build input inventory/SHA256, финальные документы и artifacts.json; это проверка целостности, а не повторное выполнение Linux-тестов.
