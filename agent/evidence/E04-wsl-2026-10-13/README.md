# E04 Ubuntu WSL evidence

13 октября 2026. Основной проект `D:\Projects\ServerDeck`; дистрибутив явно `Ubuntu-22.04`, WSL2, Ubuntu22.04.5 x86_64, kernel6.6.87.2-microsoft-standard-WSL2. Go1.27.2/cgo1, GCC11.4.0-1ubuntu1~22.04.3, glibc2.35-0ubuntu3.15; предыдущий package/content lock проверяется повторно. Новых Go modules/native packages нет; sysconf/statfs/proc/sysfs используют уже закреплённую libc/Linux ABI. Никакой VPS, host settings или публичный listener не изменялся; TLS/WSS/native service тестируются на IPv4/IPv6 loopback, SQLite/permission fixtures — в Linux temp.

Воспроизведение из PowerShell корня проекта:

```powershell
wsl --list --verbose
wsl -d Ubuntu-22.04 -- bash /mnt/d/Projects/ServerDeck/agent/tools/wsl-e04.sh sync
wsl -d Ubuntu-22.04 -- bash /mnt/d/Projects/ServerDeck/agent/tools/wsl-e04.sh check
wsl -d Ubuntu-22.04 -u root -- bash /mnt/d/Projects/ServerDeck/agent/tools/e04-root-tests.sh
wsl -d Ubuntu-22.04 -- bash /mnt/d/Projects/ServerDeck/agent/tools/wsl-e04-export.sh
pwsh -NoProfile -File 'Документация ServerDeck/Документация ServerDeck Agent/tools/check-docs.ps1'
```

`sync` создаёт новый ext4 snapshot, сравнивает каждый файл с оригиналом по SHA256, исключает dist/evidence; path/manifest сохраняются в source-copy.json. `check` использует именно этот snapshot, Linux cache/tmp, выполняет gofmt/mod verify/vet/test/race, native amd64 build+обе команды+runtime SQLite, compiled loopback/local smoke, state smoke, arm64 cgo cross-build/ELF/glibc inspection и SHA256 четырёх файлов. `export` проверяет, что с момента тестирования compiled/test/tooling inputs и их полный inventory не изменились, затем копирует только evidence и binaries; app-код из WSL назад не копируется.

## Фактические результаты

- PASS: gofmt clean, go mod verify, go vet ./..., go test -v -count=1 ./..., go test -race -count=1 ./...; [полный лог](linux-checks.txt). Sources/cache/temp только ext4, [начальный SHA256 manifest](source-copy.json) и [финальные124 tested/build/tooling inputs](build-inputs.json). Содержимое Markdown позднее синхронизировано отдельно в documents.sha256; code/test inputs проверены непосредственно export guard.
- PASS: два Linux amd64 cgo binaries, обе version/sqlite-info (SQLite3.53.4), compiled service/local CLI/TLS dual-loopback smoke, state smoke. Артефакты [SHA256](binaries.sha256). ELF64/CGO/NEEDED/interpreter/max GLIBC2.34≤2.35 проверены для amd64/arm64; arm64 — cross-build/inspection, не native execution.
- PASS: [root acceptance](root-checks.txt): UID0 temp state, protected local CLI/UID65534 rejection, metrics native/read-only contracts и fixtures. Race выполнен UID1000; root compiled tests без race. Реальный Linux ordinary user файл с mode0000 дал permission denied; root тот же fixture читает, что отражено явно.
- PASS: V-METRIC known samples/reset/hotplug/PID reuse, nonzero/zero/missing/unsupported различия; clock segment/last-good/stale; exact scheduler2/5/15/60 и lease10с→process5с; один сбор без клиентов/20 readers; bounded hung source/statfs4 calls с проверкой реального FD/mount identity; filters/sort/page100/TTL30/trusted actor и32 retained generations; WSS no ACK/revocation1008; реальный SQLite audit abort не отключает monitoring.
- PASS: source-code review по [OWASP scope и ограничениям](SECURITY-REVIEW.md), 26 прежних safety inputs не изменены: [manifest](safety-baseline.json). Dependencies/toolchain pins не менялись,31 package revisions/4372 native toolchain files совпали с E01 lock.
- Документы проверены штатным validator: [финальный лог](docs-checks.txt); это отдельная проверка, не runtime proof.

После дополнительной ABI-проверки исправлен system-level CPU PSI full: kernel compatibility zero теперь null/unsupported, some сохраняет avg10. TestSystemCPUFullPSIZeroIsUndefinedNotAvailable входит в итоговые test/race/root; [предыдущий прогон](pre-psi-checks.txt) сохранён только как исторический, до этого уточнения.

## Граница готовности

E04 закрыт в границах текущих read-only collectors/adapters и указанных V-METRIC проверок в Ubuntu WSL2. Полные AFR/ASEC не закрыты одним этапом. Не выполнены native ARM, физическая thermal/throttle/NIC/OS matrix, real NFS hang, длительный resource soak, production systemd/watchdog и CVE scan (govulncheck отсутствует). Hardware profiles проверены positive/negative fixtures; WSL hardware absence не является проверкой физических датчиков. Windows и QEMU не подменяли этот прогон. Native ARM остаётся ранее согласованным E12 gate.

Иногда WSL печатает предупреждение о systemd user session dontart7272; сборка/loopback/root tests прошли, настройки systemd/Windows не исправлялись, production unit этим не подтверждён. Физический isolated ENOSPC E02/E03 не повторялся: storage/migrations unchanged; SQLite full/read-only/corruption/busy regression suite прошёл. E05 не реализован и автоматически не начат.

Первичный docs validator обнаружил ссылку на ещё не экспортированный pre-psi-checks.txt; [исходный FAIL](docs-initial.txt) сохранён, после экспорта полный финальный validator повторён. Это ошибка порядка переноса evidence, не ошибка схем/runtime.
