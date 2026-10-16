# E07: фактические проверки Ubuntu WSL2

15 октября2026, Europe/Moscow. Итог доступных V-PROCESS/V-ICMP проверок — PASS; E07 закрыт в границах реализованных adapters на этом WSL-стенде. Это не завершение всех AFR/ASEC и не готовность выпуска. [Техническая реализация](../../PROCESS-DIAGNOSTICS.md).

## Окружение и источники

Ubuntu-22.04 WSL2, Ubuntu22.04.5, x86_64, kernel6.6.87.2-microsoft-standard-WSL2, UID1000 и отдельная isolated-root процедура. docker-desktop не использовался. [WSL inventory](wsl-distributions.txt). WSL иногда сообщал об отказе запуска user systemd session; systemd-unit/install этим прогоном не проверялись и настройки ради этого не менялись.

Go1.27.2, CGO_ENABLED=1, GOTOOLCHAIN=local, GCC11.4.0, builder glibc2.35. E01 pinned native/cross lock совпал по4372файлам. SQLite runtime3.53.4; полный source ID и compile options — [Linux log](linux-checks.txt). Новых Go modules/native Agent link libraries нет. Штатный iputils20211215/package3:20211215-1ubuntu0.1: [provenance/filecap/checksum/ldd](ping-provenance.txt), [copyright BSD/GPL](iputils-copyright.txt), [runtime dependency versions/checks](runtime-dependencies.txt). Его cap_net_raw уже существовал; Agent/tests не выдавали его. External ping использует системные libcap/libidn2/libunistring/libc; они не bundled и не linked в Agent.

Свежая Linux ext4-копия `/home/dontart7272/serverdeck-e07-final-2026-10-15/source.aFcNRN`. [source-copy.json](source-copy.json):214 первоначальных byte-identical файлов. [build-inputs.json](build-inputs.json):195 окончательных Go/SQL/contracts/tooling inputs, совпавших с главным проектом после проверок. Кэши/tmp/тестовые БД — Linux-ФС; foreign-UID binary fixture временно размещался в отдельном0755 каталоге `/tmp/serverdeck-e07.*` на ext4 и удалялся, без chmod home. Export переносил только evidence, не sources/Windows dist. SHA256 четырёх приложений — [binaries.sha256](binaries.sha256); test binary checksums — root/runtime logs. Markdown после проверок отдельно закреплён docs-snapshot.json.

## Точные команды

Из корня Windows-проекта:

```powershell
wsl.exe -d Ubuntu-22.04 -- bash /mnt/d/Projects/ServerDeck/agent/tools/wsl-e07.sh
wsl.exe -d Ubuntu-22.04 -u root -- bash /mnt/d/Projects/ServerDeck/agent/tools/wsl-e07-root.sh
wsl.exe -d Ubuntu-22.04 -- bash /mnt/d/Projects/ServerDeck/agent/evidence/E07-wsl-2026-10-15/extra-commands.sh
wsl.exe -d Ubuntu-22.04 -- bash /mnt/d/Projects/ServerDeck/agent/tools/wsl-e07-export.sh
pwsh -NoProfile -File "Документация ServerDeck/Документация ServerDeck Agent/tools/check-docs.ps1"
python -X utf8 agent/evidence/E07-wsl-2026-10-15/seal.py --verify
```

Последний полный прогон начался15 октября08:53:08 UTC. Точные вложенные команды и результаты сохранены в Linux log, root процедура — [foreign-uid.txt](foreign-uid.txt). seal.py без --verify формирует manifest после обновления документации; --verify проверяет неизменность input inventory/docs/evidence. Это проверка контрольных сумм, не новый runtime test.

| Проверка | Фактический результат |
|---|---|
| gofmt / go mod verify / go vet ./... | PASS |
| go test -v -count=1 ./... | PASS, default opt-in SKIP отдельно ниже |
| go test -race -count=1 ./... | PASS11пакетов с тестами |
| FuzzWeightedRollup / FuzzPingSummary,10s/parallel2 | PASS209734/211826executions соответственно |
| amd64 cgo обе команды | PASS version/sqlite-info/ldd; compiled CLI/TLS/Unix/start/stop/port-conflict smoke; E02 private state smoke |
| arm64 cgo cross-build обе команды | PASS ELF/AArch64; выполнение/native ARM не проводились |
| ELF/GLIBC/dependencies | ELF64, maxGLIBC2.34 у четырёх binaries; dynamic libc/loader, не fully static; [amd64](elf-amd64.json), [arm64](elf-arm64.json), полные build-amd64/arm64.txt |
| Реальные pidfd/PID reuse/TERM/KILL | PASS ordinary UID и isolated root/PID1; новый процесс с принудительно тем же PID8 не затронут старым ref/fd |
| Отказ прав | PASS настоящие UID0/65534 и ping с capability-drop только внутри дочернего namespace; привилегии хоста не менялись |
| Audit/order/replay | PASS настоящие SQLite/сигнал/ping: intent failure без эффекта, result failure после эффекта, retry без второго эффекта, reopen→unknown; TERМ plan не разрешает KILL |
| ICMP | PASS реальный IPv4/IPv6 loopback по5пакетов; DNS selection/failures/limits, stale/version, concurrent/rate/cancel и parser negative fixtures; ошибка не меняет online |
| Фон и аудит | PASS explicit enable, мониторинг при audit failure без audit/operation flood и без скрытия degraded health |
| Документы | PASS штатный validator, [docs-check.txt](docs-check.txt); документы не заменяют runtime checks |
| Source inventory | PASS214 initial/195 final inputs, прежние E01–E06 evidence не заменены |

Исправлены: zombie/dead refusal, numeric U64 identity comparison, PID1 Agent child protection, известные typed preflight errors, корректные success results и подтверждения новых actions. Дополнительно устранён отказ явного запроса уже зарегистрированных GPU/Docker/security snapshot blocks; это не подтверждает аппаратную готовность E06. Исторические preflight/pre-final logs сохранены: fmt/version expectation, ошибочные permission fixtures и snapshot до последнего PID1 исправления. Их FAIL не скрыты и не заменяют окончательный PASS.

## Статусы и непроведённые проверки

Согласовано: полный E07/AFR-041/062 и ASEC-009/018/029. Специфицировано: PROCESS-DIAGNOSTICS/API/config. Реализовано: named process handlers, pidfd controller, shared ICMP manager, audited manual actions/config и explicit periodic monitoring. Проверено: только вышеуказанные процедуры Ubuntu WSL2; полная продуктовая матрица не закрыта.

Default suite пропустил TestIsolatedFastPIDReuse, TestIsolatedForeignUID, TestIsolatedPingPermissionDenied; они отдельно действительно выполнены и прошли. Старые TestForeignUIDAdminPeerIsRejected, TestPhysicalFullFilesystem, TestTelemetryPhysicalFullFilesystem в E07 отдельно не повторялись; их прежнее E03/E05 evidence не выдаётся за новый PASS. В полном suite заново прошли SQLite full/read-only/corruption/busy/backup/security-floor tests. Хостовый диск не заполнялся.

Не проверены: native ARM (ранее перенесён в E12), обычная distro/kernel/security-policy matrix, настоящие kernel threads на физическом host, IPv4/IPv6/VPN/NAT/внешний firewall маршрут с Android-телефона, системный DNS/маршрут при смене upstream resolver, длительный soak и production systemd. DNS и недоступные sources дополняются направленными fixtures, не полноценным network/host испытанием. E09 managed lifecycle/переподчинение модулей и E11 firewall/install/update ещё отсутствуют; внутренний Protect hook не считается их реализацией. E06 real GPU/Docker/security gates сохраняются. BLOCK-FS/E08 не ослаблен. E08 не начат.
