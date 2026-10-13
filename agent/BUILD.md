# Сборка и проверка E01

Актуальный E04 runbook — в конце файла; предыдущие разделы сохраняют исторические E01/E02/E03 проверки и не описывают весь текущий runtime.

Текущий код включает E02 critical storage/operations; разделы E01 ниже сохраняют исходный build baseline. Актуальный E02 runbook и границы — в конце файла и [STORAGE](STORAGE.md).

12–13 октября 2026. Module path `serverdeck.local/agent` подтверждён пользователем; это локальное имя, адрес удалённого репозитория отсутствует. E01 реализует конечные offline-команды. Запуск без аргументов/`serve` завершается кодом 2; HTTP/WSS/Unix listeners, systemd-install, изменение ОС/БД/файлов через операции отсутствуют. `sqlite-info` открывает только новую in-memory SQLite для проверки зависимости, не создаёт E02-хранилище.

## Закрепление и происхождение

Go 1.27.2 зафиксирован директивой `go` и проверками scripts при `GOTOOLCHAIN=local`; автоматическое скачивание другой версии отключено. SHA256 официальных архивов — [toolchains.json](toolchains.json), источник [официальные метаданные Go](https://go.dev/dl/?mode=json). `go.mod`/`go.sum` закрепляют только два реально импортируемых модуля. Загрузка выполнялась через `proxy.golang.org` с `sum.golang.org`, `go mod verify` прошёл. Лицензии и native зависимости — [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

Windows-проверки: переносимый Go в `../.tools/go`, существующий MSYS2 UCRT64 GCC 16.1.0 Rev5. Нет системной установки Go/изменения PATH профиля. Для нового окружения `pwsh -NoProfile -File tools/bootstrap-go.ps1` из `agent/` скачивает архив в корневой `.tools`, сверяет digest и распаковывает только в отсутствующий Go-каталог. Нужен разрешённый сетевой доступ. GCC этим скриптом не устанавливается.

Linux baseline — Ubuntu22.04/glibc2.35, GCC11.4.0 с патчами Ubuntu. 13 октября проверена Ubuntu-22.04 WSL2 amd64: exact package revisions и 4372 toolchain/sysroot file hashes закреплены в [lock](evidence/E01-wsl-2026-10-13/linux-toolchain.lock.json). Native amd64 и cross arm64 cgo binaries побайтово совпали после повторной сборки в другом source path с пустым кэшем. Это воспроизводимость текущего E01-снимка в зафиксированном builder, не проверенная production release delivery. [GCC upstream](https://gcc.gnu.org/gcc-11/) больше не поддерживает ветку 11; проверенный GCC-пакет получен из Ubuntu jammy-updates/jammy-security; его точная ревизия и происхождение сохранены. Новые security updates требуют обновления lock и повторных проверок, а не автоматического latest. Не собирать релиз непроверенным системным GCC только ради успешной команды.

## Проверки на текущей Windows

Из корня проекта, PowerShell 7:

```powershell
$env:GOTOOLCHAIN = 'local'
$env:GOPATH = 'D:/Projects/ServerDeck/.tools/gopath'
$env:GOCACHE = 'D:/Projects/ServerDeck/.tools/gocache'
$env:CGO_ENABLED = '1'
& ./agent/tools/verify.ps1 -Go 'D:/Projects/ServerDeck/.tools/go/bin/go.exe' -Gofmt 'D:/Projects/ServerDeck/.tools/go/bin/gofmt.exe'
pwsh -NoProfile -File 'Документация ServerDeck/Документация ServerDeck Agent/tools/check-docs.ps1'
```

`verify.ps1`: gofmt без изменений → mod verify → vet → test -count=1 → оба Windows build с trimpath/buildvcs=false/mod=readonly → version → sqlite-info. Артефакты в игнорируемом dist; фактические логи в [evidence](evidence/E01-windows-checks.txt). Windows-сборки нужны для offline-проверки контрактов и не поставляются как Agent для Windows.

Из `agent/` для отдельных команд:

```powershell
./dist/windows-amd64/serverdeckctl.exe validate-config '../Документация ServerDeck/Документация ServerDeck Agent/contracts/examples/config.json'
./dist/windows-amd64/serverdeckctl.exe check-contract api QueryRequest '../Документация ServerDeck/Документация ServerDeck Agent/contracts/examples/query.json'
./dist/windows-amd64/serverdeck-agent.exe version
```

Успех `validate-config` означает JSON/schema и чистые семантические проверки. Существование пользователя/файлов, владельцы, symlink, сертификаты, syscalls и DB seed/import не проверены. До будущего listen нужен Linux preflight. CLI не печатает входные данные/пути и возвращает ограниченные ошибки.

## Linux amd64/arm64 с cgo

На изолированном Linux builder подготовить официальный Go 1.27.2, сверив SHA256 с toolchains.json; GCC 11.4.0 и glibc 2.35 sysroot **нужной** архитектуры, readelf, sha256sum, bash. Это предварительные условия, не команды установки на пользовательский сервер. На arm64 native builder используется arm64 GCC; на amd64 cross-builder нужен aarch64-linux-gnu-gcc с arm64 sysroot. Windows UCRT GCC не подходит.

Из `agent/`:

```bash
CC=/usr/bin/gcc-11 bash tools/build-linux.sh amd64
# Отдельный builder либо проверенный cross-toolchain:
CC=/usr/bin/aarch64-linux-gnu-gcc-11 bash tools/build-linux.sh arm64
# На каждом соответствующем Linux host после сборки:
CC=/usr/bin/gcc-11 bash tools/smoke-linux.sh
```

Основная команда recipe: `CGO_ENABLED=1 GOOS=linux GOARCH=<arch> GOTOOLCHAIN=local CC=<target-gcc> go build -mod=readonly -trimpath -buildvcs=false -o dist/linux-<arch>/<command> ./cmd/<command>`. `CGO_ENABLED=0` и `-tags libsqlite3` не являются допустимой релизной заменой. SQLite компилируется из amalgamation драйвера; NVML в E01 не подключён. Компилятор нужен builder, не серверу. Полностью статическая сборка не обещается.

Сохранить `build-evidence.txt`, exact OS/kernel/package revisions/sysroot/image digest, `ldd`, ELF GLIBC requirements, `go version -m`, SHA256 binaries, runtime SQLite version/source ID/compile options. Проверить отсутствие GLIBC требований выше 2.35. Smoke выполняет vet/test/race, обе конечные команды, actual SQLite и динамические зависимости; не устанавливает service. systemd/права/NVIDIA/подписанная доставка проверяются на своих этапах. Эти команды исполнены в указанной Ubuntu WSL2 на amd64; native ARM smoke/race не исполнены. ELF64/Machine/PT_INTERP/NEEDED/CGO/max GLIBC автоматически проверяет tools/inspect-linux.py (Python3 нужен builder, не Agent).

## Фактический WSL-прогон

Фактический WSL-прогон, pins, hashes и границы: [E01 Ubuntu evidence](evidence/E01-wsl-2026-10-13/README.md). Имя дистрибутива всегда передаётся явно; default `docker-desktop` не используется. Основная работа шла в Linux ext4-копии `/home/dontart7272/serverdeck-e01-2026-10-13/source.J1hfMJ`; кеши/tmp также Linux. Бинарники затем скопированы в основной ignored dist и сверены по SHA256. Linux-копия не перезаписывала основной app-код.

Подготовка/повтор проверки из PowerShell:

```powershell
wsl -d Ubuntu-22.04 -- bash /mnt/d/Projects/ServerDeck/agent/tools/wsl-inventory.sh
wsl -d Ubuntu-22.04 -u root -- bash /mnt/d/Projects/ServerDeck/agent/tools/wsl-install-deps.sh
wsl -d Ubuntu-22.04 -- bash /mnt/d/Projects/ServerDeck/agent/tools/wsl-prepare.sh
wsl -d Ubuntu-22.04 -- bash /mnt/d/Projects/ServerDeck/agent/tools/wsl-run-checks.sh
wsl -d Ubuntu-22.04 -- bash /mnt/d/Projects/ServerDeck/agent/tools/wsl-finish-checks.sh
```

Перед повторным build проверить существующий lock через `tools/verify-linux-toolchain.py`; `capture-linux-toolchain.py` фиксирует фактическое окружение и не разрешает молча заменить сохранённый lock новым. Полная последовательность capture/verification/export — в evidence README. GCC/cross GCC вызываются явными gcc-11 путями: автоматический системный alias `gcc` не создавался. Installer root-часть ограничена Ubuntu apt; сборки/тесты идут обычным пользователем. Повтор pinned установки проверен: 0 upgrades, 0 installs/removals. Go архив/каталог безопасно переиспользуются после SHA/version checks, а source копия каждый раз создаётся отдельно.

`wsl-run-checks.sh` выполняет native amd64 smoke, arm64 cross-build и явно маркированные QEMU-команды. `wsl-finish-checks.sh` повторно компилирует обе архитектуры из новой копии с пустым GOCACHE и сравнивает четыре binaries. `wsl-export-evidence.sh` переносит только evidence/бинарники, проверяет generator/bash syntax/toolchain lock/ELF и не переносит application source. Для native ARM тестов потребуется отдельный ARM64 Linux-стенд и собственный native builder lock; amd64 package lock нельзя назвать ARM builder.

Сохранённые snapshot/hash/metadata обеспечивают проверку воспроизводимости данного снимка. Доступность старых .deb/go proxy/архивов в будущем не гарантируется; исчезнувший package pin нельзя заменить latest без проверки. В WSL наблюдалось предупреждение о systemd user session; службу Agent не устанавливали и host systemd support этим прогоном не подтверждали. ENOSPC/corrupt persistent-storage испытания не проводились: E02 storage ещё отсутствует.

## Контракты и генерация

Первичный источник схем — Agent `tools/build-contracts.py`. `tools/sync-contracts.ps1` копирует шесть схем в embedded snapshots; Go-test проверяет побайтовое совпадение с документацией. После изменения схем:

```powershell
# Из agent/, после обновления документального генератора:
pwsh -NoProfile -File tools/sync-contracts.ps1
python tools/generate-types.py
gofmt -w internal/contracts/wire_generated.go
go test ./internal/contracts ./internal/config
```

Python нужен только для регенерации; приложение его не вызывает. Generated wire types покрывают records и discriminator-specific request/operation/node варианты. Союзы и отдельно объявленные module data остаются RawMessage и допускаются только через Decode/Validate с выбранным definition. Копирование схем не заменяет семантические ограничения.

Тесты: все 178 определений компилируются offline; 13 positive examples (включая направленные WSS) + неизвестные поля; 75 request branches (22 query, 21 prepare, 21 execute, 11 IPC) и неизвестные nested params; UTF-8/UTF-16 escapes/duplicates/trailing JSON/NUL/size/depth/arrays, U64/calendar/path bytes, framing/partial writes, configuration cross-fields, ограниченные data schemas и UI IDs. Это не полная функциональная приёмка всех ответов/модулей/операций. ReadResponse проверяет id локально ожидаемого RPC и выбранный приложением тип результата; управление таблицей pending/authenticated session ещё отсутствует. Подписи, archive validation, auth, audit и системные эффекты ожидают свои этапы. Encode проверяет ограниченность дерева до выделения JSON-буфера и не исполняет произвольные MarshalJSON; затем проверяется точный размер.

JSON numbers принимаются в конечном диапазоне float64 с экспонентой -324..324, ненулевой underflow отклоняется до точной арифметики схем. Лимит 4096 применяется также к числу object members; проверка деклараций ограничена 10000 посещений schema nodes (защита от раздувания DAG ссылок). Данные не расширяются/не загружаются из сети. Эти детали дополнены в технические спецификации.

## Исправление API-контрактов 13 октября 2026

API-R01/R02: WssClientMessage/WssServerMessage, типизированные subscriptions/changes и unique ID; aggregate WssMessage не принимается codec. Общие RuntimeConfig semantics и ApplyRuntimeChanges проверяют конфигурацию/patch/merged result без OS-effects. Команда из корня `python agent/evidence/api-audit-2026-10-13/reproduce.py` проверяет отказы и положительные сообщения; [результат](evidence/api-audit-2026-10-13/results-fixed.txt), [отчёт](API-SECURITY-AUDIT-2026-10-13.md). Schema/generator/embedded snapshots/wire types/examples синхронизированы; действующего выпущенного API/client нет. Version guard, trusted sessions/ack/revocation, audit ordering и OS preflight этим codec не реализуются.

## Состояние E01

13 октября 2026 исправлен SD-SEC-001: обход вложенных data schemas через const/enum/oneOf. В `contracts` добавлены TestDataSchemaSiblingGuards/Depth; положительные ограниченные схемы сохраняются, опасные соседние properties/items/additionalProperties отклоняются до компиляции. Проверка свежего CLI: из корня `python agent/evidence/security-audit-2026-10-13/reproduce.py`; пять негативных манифестов должны дать exit1/SCHEMA_MISMATCH. Исходные и новые результаты, hashes и Windows race log — [evidence](evidence/security-audit-2026-10-13/results-fixed.txt), детали и ограничения — [отчёт](SECURITY-AUDIT-2026-10-13.md). Формат wire/schema и defaults не менялись; генераторы и embedded snapshots не требуют регенерации.

Windows-часть и Linux amd64 WSL2 build/smoke/vet/test/race выполнены. Linux arm64 cgo cross-build, ELF и QEMU version/SQLite/config выполнены; native ARM smoke/tests/race **не выполнены**, ARM-стенда нет. Builder lock и byte-identical rebuild четырёх binaries получены.

По решению пользователя 13 октября 2026 нативные ARM-проверки перенесены из E01 в E12, до объявления проверенной поддержки ARM64. **E01 закрыт по уточнённым критериям**: native amd64 WSL проверки и arm64 cgo cross-build/ELF/repro выполнены. Эмуляция не заменяет нативные испытания. До native ARM Linux smoke, `go vet ./...`, `go test -count=1 ./...`, `go test -race -count=1 ./...` с собственной закреплённой cgo-цепочкой ARM64 остаётся экспериментальной сборкой. Если стенд не появится к E12, критерий остаётся открытым; ARM не исключается из согласованного объёма продукта.

Исходный [WSL evidence](evidence/E01-wsl-2026-10-13/README.md) и его hashes сохранены без изменения: его вывод «E01 не закрыт» относится к моменту до этого решения. Актуальный статус и основание переноса — [журнал, раздел10](<../Документация ServerDeck/Документация ServerDeck Agent/11. Журнал проверки требований.md>). На момент этой исторической записи E02 ещё не был начат; актуальный E02 описан ниже. Полные AFR/ASEC и матрица обычных Linux-серверов не объявляются проверенными.

## E02: critical SQLite, аудит и операции

13 октября 2026: добавлены storage/operations и конечный offline CLI обслуживания своего private state. Публичной службы/изменяющих HTTP/IPC/пользовательских файловых и process actions нет. [Реализация и ограничения](STORAGE.md), [новые evidence](evidence/E02-wsl-2026-10-13/README.md). Исторические результаты E01 не менялись.

Из корня в PowerShell:

```powershell
wsl -d Ubuntu-22.04 -- bash /mnt/d/Projects/ServerDeck/agent/tools/wsl-e02.sh sync
wsl -d Ubuntu-22.04 -- bash /mnt/d/Projects/ServerDeck/agent/tools/wsl-e02.sh fault-binary
wsl -d Ubuntu-22.04 -u root -- unshare --mount -- bash /mnt/d/Projects/ServerDeck/agent/tools/e02-full-filesystem.sh
wsl -d Ubuntu-22.04 -- bash /mnt/d/Projects/ServerDeck/agent/tools/wsl-e02.sh check
wsl -d Ubuntu-22.04 -- bash /mnt/d/Projects/ServerDeck/agent/tools/wsl-e02-export.sh
pwsh -NoProfile -File 'Документация ServerDeck/Документация ServerDeck Agent/tools/check-docs.ps1'
```

`sync`: новая Linux ext4-копия, byte equality, форматирование уже отформатированных файлов и targeted tests. `check`: точные env/команды в linux-checks.txt; gofmt clean, mod verify, vet, test -v -count=1, race -count=1, оба amd64 cgo binaries и offline smoke, state CLI smoke, arm64 cgo cross-build и ELF/GLIBC checks. Go1.27.2/cgo1/CC=/usr/bin/gcc-11 заданы явно; caches/tmp/тестовые БД в Linux-ФС. Старый toolchain lock сверяется, не заменяется. Новые зависимости не добавлены.

Physical ENOSPC отдельно: root только создаёт приватный mount namespace и ext4 образ16000000 bytes; тест идёт UID1000 и отказывается от root/не-ext4/FS>32000000 bytes. Образ ограничен, чужой/WSL/Windows диск не заполняется; mount автоматически снимается. Тест реально выполнен, обычный `go test` помечает этот opt-in helper SKIP; этот SKIP не заменяет отдельный PASS. Для повторения нужны уже доступные unshare/mkfs.ext4/mount/runuser; служба и пакеты хоста не изменяются.

`export` прекращается при изменении Go/SQL/schema/module/tooling inputs в основном проекте; переносит только evidence и соответствующие бинарники, никогда app-source из Linux-копии. Не редактировать выполняемый bash-script во время прогона. SHA исходной копии, финальных compiled inputs и бинарников фиксируются отдельно от поздних Markdown-изменений. E02 не заявляет повторную byte-identical reproducibility после E01: текущие binaries имеют свои hashes, текущая release delivery ещё E11.

Offline CLI (Linux, от владельца private state; существующая служба должна быть остановлена, flock откажет второму владельцу):

```text
serverdeckctl state-init STATE CONFIG
serverdeckctl state-status STATE
serverdeckctl state-operation STATE OPERATION_ID
serverdeckctl state-backup STATE NEW_BACKUP_DIR OPERATION_ID --confirm
serverdeckctl state-restore STATE BACKUP_DIR NEW_STATE_DIR OPERATION_ID --confirm
serverdeckctl state-resolve STATE OPERATION_ID applied|none --confirm
```

CONFIG проходит прежний валидатор; runtime_user должен совпасть с текущим user, paths.state — с STATE. Initial seed не заменяет существующие settings. Backup/restore проходят общий Prepare/Execute/audit guard; `--confirm` — явное локальное подтверждение private maintenance. Restore не переключает службу и не заменяет исходный каталог; переносит текущие operation IDs/unknown/dedup/audit и повышает settings revision, а не возвращает их к старому snapshot. Resolve означает подтверждённое оператором наблюдение, пишет audit gap; `none` нельзя выбирать по одному отсутствию ответа. JSON CLI описывает внутреннюю запись E02, не является HTTP Operation wire envelope. Изменяющий config.set CLI не открыт до полного OS/policy preflight и E03 local transport.

Подтверждённая среда ограничена указанной Ubuntu WSL2 amd64. Native ARM tests/race/smoke остаются E12, systemd/обычные hosts/GPU/power-loss/полная матрица — не проверены. Полные AFR/ASEC не закрываются фактом прохождения offline E02. E03 автоматически не начинается.

Итог E02 / 13 октября 2026: offline V-STORE/V-AUDIT и обязательные Ubuntu WSL2 amd64 проверки пройдены, E02 закрыт в этих границах. На момент завершения E02 E03 не был начат; последующее поручение и актуальные результаты E03 приведены ниже.

## E03: Auth/TLS/transport / 13 октября 2026

[Реализованное поведение и структура](AUTH-TRANSPORT.md), [evidence](evidence/E03-wsl-2026-10-13/README.md). E03 закрыт в границах работающих auth/transport adapters. E04 не начат. Нельзя объявлять полные AFR/ASEC, Android-интеграцию, готовность выпуска или поддержку всей Linux matrix.

Из корня PowerShell, существующая Ubuntu-22.04 WSL2:

```powershell
wsl -d Ubuntu-22.04 -- bash /mnt/d/Projects/ServerDeck/agent/tools/wsl-e03.sh sync
wsl -d Ubuntu-22.04 -- bash /mnt/d/Projects/ServerDeck/agent/tools/wsl-e03.sh provenance
wsl -d Ubuntu-22.04 -- bash /mnt/d/Projects/ServerDeck/agent/tools/wsl-e03.sh check
wsl -d Ubuntu-22.04 -u root -- bash /mnt/d/Projects/ServerDeck/agent/tools/e03-root-tests.sh
wsl -d Ubuntu-22.04 -- bash /mnt/d/Projects/ServerDeck/agent/tools/wsl-e03.sh fault-binary
wsl -d Ubuntu-22.04 -- bash -lc 'sed s/serverdeck-e02/serverdeck-e03/g /mnt/d/Projects/ServerDeck/agent/tools/e02-full-filesystem.sh > /home/dontart7272/serverdeck-e03-2026-10-13/evidence/full-filesystem-run.sh'
wsl -d Ubuntu-22.04 -u root -- unshare --mount -- bash /home/dontart7272/serverdeck-e03-2026-10-13/evidence/full-filesystem-run.sh
wsl -d Ubuntu-22.04 -- bash /mnt/d/Projects/ServerDeck/agent/tools/wsl-e03-export.sh
pwsh -NoProfile -File 'Документация ServerDeck/Документация ServerDeck Agent/tools/check-docs.ps1'
```

`sync` создаёт новую копию в `/home/dontart7272/serverdeck-e03-2026-10-13/source.XXXXXX`, проверяет все исходные bytes и запускает tests. В фактическом полном прогоне copy=`source.ojWbNj`,126 первоначальных файлов. Go1.27.2, CGO_ENABLED1/GOTOOLCHAINlocal, CC=/usr/bin/gcc-11. GOCACHE=`.../serverdeck-e03-2026-10-13/cache`, GOTMPDIR/TMPDIR=`.../tmp`; GOPATH/toolchain повторно используются из Linux task E01. Загрузка модулей/кэши/тестовые SQLite не размещаются в Windows mount. Source-copy manifest фиксирует исходный снимок до поздних Markdown-обновлений; export заново сверяет Go/SQL/schema/module/tooling/license `.txt` inputs с главным проектом. Linux-копия не переносит app-source обратно и не перезаписывает несвязанные изменения.

`check`: gofmt clean, mod verify, vet, test -v -count=1, test -race -count=1; amd64 cgo build, version/sqlite-info/ldd обеих команд; **свежие скомпилированные binaries** проходят отдельный TestNativeServeCLIShutdownAndPortConflict с env SERVERDECK_E03_AGENT_BINARY/SERVERDECK_E03_CTL_BINARY. Это private loopback startup/TLS/pair/query/local CLI/SIGTERM, не публичный сервис/systemd install. E02 state smoke сохранён. Arm64 cgo cross-build, ELF/loader/GLIBC inspection обеих архитектур и bash syntax checks проходят отдельно. E03 не заявляет новый native ARM runtime/race или повтор E01 byte-identical rebuild.

`provenance`: go mod download -json/go mod graph, origin/checksum database для трёх Go modules; ISC license нового coder/websocket v1.8.15 скопирован из pinned источника. Новых native libraries нет. Старый lock31 packages/4372 files сверяется без перезаписи: GCC11.4.0, glibc2.35, arm64 sysroot/cross compiler. ELF max required GLIBC2.34, SQLite runtime3.53.4 с source ID/compile options в логе, системная libsqlite3 не подменяет amalgamation. Это не CVE-аудит.

Root-процедура использует уже собранный app.test, root-owned temp state и subprocess UID65534 для настоящего отрицательного SO_PEERCRED теста. Не создаёт пользователей/units/служебные настройки. Physical ENOSPC — прежняя проверенная E02-процедура с единственной подстановкой task directory на E03, **новый E03 operations.test** и private mount namespace/ext4 image16000000 bytes; не заполняет WSL/Windows disk. Его отдельный PASS не заменяется обычным opt-in SKIP. Иногда WSL сообщает отказ systemd user session; эти испытания не запускают systemd, предупреждение сохранено в evidence без попытки изменить настройки хоста.

Новые команды и требования к подготовленным directories/config/TLS — AUTH-TRANSPORT. Offline E02 maintenance требует остановленной службы. File stream execution/revocation, сбор/история/events/modules/Android, installer/cert issuance/rotation/systemd/update, нагрузочная host matrix и native ARM остаются E04–E12. При отсутствующем адаптере API возвращает недоступность, а не фиктивный успех. Публичного deploy и изменений VPS/Windows не было.

## E04: снимки и общий Linux-сбор

[Реализация и численные ограничения](METRICS.md), [точные команды/evidence](evidence/E04-wsl-2026-10-13/README.md). Выполнять из корня: `wsl -d Ubuntu-22.04 -- bash /mnt/d/Projects/ServerDeck/agent/tools/wsl-e04.sh sync`, затем тот же script с `check`; root-процедура — `wsl -d Ubuntu-22.04 -u root -- bash /mnt/d/Projects/ServerDeck/agent/tools/e04-root-tests.sh`; экспорт только проверенных artifacts — `wsl -d Ubuntu-22.04 -- bash /mnt/d/Projects/ServerDeck/agent/tools/wsl-e04-export.sh`. Sources/cache/tmp находятся в `~/serverdeck-e04-2026-10-13`, исходники копируются в новый ext4 source.XXXXXX, не собираются на /mnt/d. Version теперь development E04/API1, runtime info0.4.0-e04.

Go modules, toolchains и cgo baseline E03 не изменены. Direct cgo sysconf(_SC_CLK_TCK) использует glibc; Go не предполагает частоту100Hz. Воспроизводимые recipes amd64/arm64 остаются tools/build-linux.sh. Перед экспортом source hashes сравниваются с главным проектом, чужие изменения не перезаписываются. Обновление схем выполняется только tools/build-contracts.py → копии api/ipc в internal/contracts/schemas → tools/generate-types.py → gofmt → contract/docs validation; это авторинг, не runtime генерация.

Пример локального запроса в защищённый *тестовый* runtime: JSON `{"schema_version":"1.0","request_id":"11111111-1111-4111-8111-111111111111","query":"snapshot.get","params":{"view":"summary","blocks":["cpu","memory"]}}`; `serverdeckctl local --config CONFIG query QUERY_FILE`. Команда не собирает данные отдельно, читает общий snapshot. Служба/пользователь/права не устанавливаются ради теста.
