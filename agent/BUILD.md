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

## E05: первая часть — агрегация

14 октября 2026. [Границы реализации](HISTORY.md), [команды и фактические результаты](evidence/E05-aggregation-2026-10-14/README.md). Из корня: `wsl -d Ubuntu-22.04 -- bash /mnt/d/Projects/ServerDeck/agent/tools/wsl-e05-aggregation.sh`. Script сам создаёт отдельную ext4-копию, caches/tmp; не собирает на Windows mount. В текущем прогоне копия `~/serverdeck-e05-aggregation-2026-10-14/source.ig0ZrT`,142 исходных файлов, версия Go1.27.2/GCC11.4.0/cgo1 и прежний package/toolchain lock E01 без изменений. Экспорт результатов: `wsl -d Ubuntu-22.04 -- bash -lc 'rsync -a "$HOME/serverdeck-e05-aggregation-2026-10-14/evidence/" /mnt/d/Projects/ServerDeck/agent/evidence/E05-aggregation-2026-10-14/'`.

PASS gofmt, mod verify, vet, test, race всех пакетов; 10s fuzz `FuzzWeightedRollup` с двумя workers —866139 executions; amd64 cgo build/version/sqlite-info/ldd обеих commands, ELF/glibc, compiled CLI/TLS smoke и E02 state smoke на временных данных. PASS arm64 cgo cross-build/ELF; native ARM не выполнялся. Фактическая SQLite3.53.4. Бинарники находятся только в Linux-копии; `binaries.sha256` относится к ней, старые `agent/dist/` в Windows не перезаписаны.

Новый `internal/history` ещё не вызывается runtime; compiled version остаётся development E04, API/capabilities не расширены. Тесты непосредственно вызывают новый код. E05 целиком открыт: history.db, WAL/quotas/retention, ingestion/registry/revision writer, API/cursors, rules/events и WSS resume требуют следующих частей. Старые root/private-mount ENOSPC opt-in procedures не повторялись; их SKIP не считается PASS. Docs validator запускается отдельно, результат — `docs-checks.txt`.


## E05: полный блок истории и событий

Актуальное [HISTORY](HISTORY.md) заменяет ограничения исторического E05-A выше. Точные команды/версии/контрольные суммы и фактический результат — [E05 evidence](evidence/E05-wsl-2026-10-14/README.md). Из корня выполняются wsl-e05.sh → отдельная e05-full-filesystem.sh в private unshare namespace → wsl-e05-export.sh → штатный check-docs.ps1. Полные команды приведены в evidence. Все build/test/caches/DB остаются в Ubuntu ext4. Новых зависимостей нет; Go/cgo/native pins прежние. Version development E05/runtime0.5.0-e05, critical schema3, telemetry schema1.

Первый script запускает gofmt/modverify/vet/test -v/race/fuzz10s, cgo amd64/arm64 recipes с ELF/glibc inspection, version/sqlite-info/ldd обеих amd64 commands и compiled CLI/TLS/state smoke. storage.test собирается для отдельного isolated physical ENOSPC. Export сверяет весь build input inventory с основным проектом и не перезаписывает чужие sources/binaries. Пример source-copy.json — снимок до последующего Markdown отчёта, build-inputs.json — проверенные исполняемые inputs. Native ARM не выдаётся за cross build.


Уточнение завершения15 октября2026 (прогоны именованы по UTC14 октября): config.set при незавершённом уменьшении budget/retention возвращает новую version и cleanup_operation_id, равный ID текущей операции, со статусом unknown/partial/CLEANUP_PENDING. Это та же наблюдаемая операция применения политики и очистки, а не потерянное фоновое действие. До подтверждения результата сохранённый intent/lock не удаляется; повтор не запускает очистку заново. По правилам E02 требуется сверка и штатное административное resolve после проверки остатка/health; неизвестный исход автоматически не объявляется успехом. При пустом журнале уменьшение срока завершается succeeded и cleanup_operation_id=null. Calendar cleanup не обходит консервативные clock guards. Это ограничение доступности при неопределённости, не ложный failed/none и не откат принятой политики.

## E06: воспроизводимые доступные проверки

Из корня Windows: `wsl.exe -d Ubuntu-22.04 -- bash /mnt/d/Projects/ServerDeck/agent/tools/wsl-e06.sh`. Скрипт создаёт новую ext4-копию в `~/serverdeck-e06-final-2026-10-15/source.XXXXXX`, сверяет SHA256 с основным проектом, использует E01 pinned environment, Linux cache/tmp и GCC11. Выполняет fmt/mod verify/vet/test/race/fuzz, cgo amd64/arm64 build, ELF/ldd и compiled CLI smoke. После успешного окончания: `wsl.exe -d Ubuntu-22.04 -- bash /mnt/d/Projects/ServerDeck/agent/tools/wsl-e06-export.sh`. Export проверяет неизменность build inputs и переносит только evidence. [Ограничения адаптеров](INTEGRATIONS.md), [фактические результаты](evidence/E06-wsl-2026-10-15/README.md). Настоящие NVIDIA/Docker/Fail2ban тесты этим скриптом не подменяются. E06 открыт.

Дополнительные read-only команды E06 для provenance, реальной доступности источников и ELF записаны в `agent/evidence/E06-wsl-2026-10-15/extra-commands.sh`; после основного прогона: `wsl.exe -d Ubuntu-22.04 -- bash /mnt/d/Projects/ServerDeck/agent/evidence/E06-wsl-2026-10-15/extra-commands.sh`, затем повторный export. Они читают binaries именно из последней Linux-копии, не запускают ARM на amd64. Таблицы nft сами по себе дают только partial security coverage; complete host coverage не заявляется.

## E07: процессы и ICMP

Свежая ext4-копия и весь доступный Linux-прогон:

```powershell
wsl.exe -d Ubuntu-22.04 -- bash /mnt/d/Projects/ServerDeck/agent/tools/wsl-e07.sh
wsl.exe -d Ubuntu-22.04 -u root -- bash /mnt/d/Projects/ServerDeck/agent/tools/wsl-e07-root.sh
wsl.exe -d Ubuntu-22.04 -- bash /mnt/d/Projects/ServerDeck/agent/tools/wsl-e07-export.sh
pwsh -NoProfile -File "Документация ServerDeck/Документация ServerDeck Agent/tools/check-docs.ps1"
```

Первый script использует прежние pinned Go1.27.2/GCC11.4.0/CGO_ENABLED=1/glibc2.35, отдельные source/cache/tmp на ext4, полный suite/race, FuzzPingSummary, amd64/arm64 cgo build/ELF, compiled CLI/TLS/state smoke. Дополнительно компилирует test binaries: user/PID namespace forced reuse меняет ns_last_pid исключительно внутри проверенного нового namespace; Root script дополнительно проверяет отказ ICMP с capability-drop в дочернем namespace и создаёт отдельный PID/mount namespace и временные процессы UID0/65534, не меняет пользователей, sysctl, capabilities, firewall или службы хоста. Требуется уже доступный unshare/setpriv; автоматического изменения sysctl для разрешения namespaces нет.

Export сверяет inputs/inventory, переносит только evidence. Предыдущие evidence E01–E06 не перезаписываются. Новых Go dependencies/native link libraries нет. Штатный Ubuntu iputils-ping3:20211215-1ubuntu0.1 проверяется как внешняя программа; provenance, file capabilities и license записаны в evidence. Прогон не выполняет setcap, установку пакетов или изменение sysctl хоста; ns_last_pid меняется исключительно внутри проверенного нового PID namespace. Version development E07/API0.7.0-e07, critical schema3 без новой миграции. [Результаты и ограничения](evidence/E07-wsl-2026-10-15/README.md).

## Исторический E08: частичный read-only профиль15 октября

```powershell
wsl.exe -d Ubuntu-22.04 -- bash /mnt/d/Projects/ServerDeck/agent/tools/wsl-e08.sh
wsl.exe -d Ubuntu-22.04 -u root -- bash /mnt/d/Projects/ServerDeck/agent/tools/wsl-e08-root.sh
wsl.exe -d Ubuntu-22.04 -- bash /mnt/d/Projects/ServerDeck/agent/tools/wsl-e08-export.sh
pwsh -NoProfile -File "Документация ServerDeck/Документация ServerDeck Agent/tools/check-docs.ps1"
```

Fresh ext4 copy/cache/tmp, pinned E01 Go1.27.2/GCC11.4/CGO1/glibc2.35 и прежние dependencies. Script fmt/modverify/vet/test/race/fuzz/fileaccess, cgo amd64/arm64/ELF и compiled CLI/TLS/state smoke. Root script только в private mount/PID namespace делает propagation private, монтирует16МБ tmpfs, проверяет actual protection/bind/TLS download и удаляет свои временные данные. Системные настройки/mounts Windows/VPS и исходники не меняются. Export проверяет input inventory и переносит только evidence. Новых Go/native link dependencies нет; Linux UAPI openat2 из того же sysroot. Stage E08/read версия0.8.0-e08-read, critical schema4/floor3; E08 не закрыт. [Границы](FILES.md), [фактические результаты](evidence/E08-wsl-2026-10-15/README.md).

E08 inventory: `serverdeckctl state-inventory /absolute/state` — offline status, при открытии выполняются применимые миграции/recovery. Schema4/floor3 несовместимы с предыдущим binary: не открывать state старой версией. Legacy baseline остаётся unknown. Backup/restore ограничены32 persistent unknown receipts и32000 bytes inventory; при исчерпании требуется отдельная безопасная сверка, автоматического удаления/complete нет. [Подробности](E08-INVENTORY-DESIGN.md).

Итог E08 доступной части15 октября2026: полный wsl-e08.sh exit0, отдельный private root script exit0, export подтвердил213 исполняемых inputs. PASS vet/test/race/fuzz/cgo amd64+arm64 cross/ELF, amd64 CLI/TLS/state/inventory smoke. Проверки/контрольные суммы — [E08 evidence](evidence/E08-wsl-2026-10-15/README.md). E08 открыт; production reads и mutations не включены. Native ARM/full V-FILE/host matrix не проверены.


## Исторический E08: промежуточный снимок15 октября2026

Согласованные внешние гонки и модель обслуживания — [FILES.md](FILES.md). Текущее хранилище critical schema5 / floor4, migration005. Старые пункты выше schema4/floor3 и production always-off описывают предыдущий evidence, не текущую реализацию. Новых Go/native link dependencies нет. Перед использованием старой версии на state5 остановитесь: writer несовместим.

Offline подтверждение полного учёта собственных копий: `serverdeckctl state-inventory-confirm /absolute/state /absolute/confirmation.json OPERATION_ID --confirm`. Вход `{"known_regions":[],"absent_operation_ids":[]}`; известные внешние собственные области включают в known_regions. Существующие backup/restore receipts проверяются автоматически; absence assertions запрещены. Operator completeness — явная доверительная граница, а не автоматическое сканирование. Выполнять при остановленной службе; после изменения inventory/boot/identity требуется повторная сверка.

Новый воспроизводимый набор:

```powershell
wsl -d Ubuntu-22.04 -- bash /mnt/d/Projects/ServerDeck/agent/tools/wsl-e08-completion.sh
wsl -d Ubuntu-22.04 -u root -- bash /mnt/d/Projects/ServerDeck/agent/tools/wsl-e08-completion-root.sh
wsl -d Ubuntu-22.04 -- bash /mnt/d/Projects/ServerDeck/agent/tools/wsl-e08-completion-export.sh
pwsh -NoProfile -File "Документация ServerDeck/Документация ServerDeck Agent/tools/check-docs.ps1"
```

Новая Linux ext4 копия и cache/tmp: `~/serverdeck-e08-completion-2026-10-15`. Root test создаёт только два16000000 bytes tmpfs в отдельном mount/PID namespace. Обычный полный go test пропускает требующие этого namespace случаи; root script запускается отдельно. [Новый evidence](evidence/E08-completion-wsl-2026-10-15/README.md) хранится отдельно; прежние артефакты не изменены. Полный E08 остаётся открытым до перечисленных в FILES.md реализации и V-FILE; ARM native gate остаётся E12.


Фактический новый прогон: completion script/root/export exit0,233 executable inputs подтверждены; все Go test/race/vet, fuzz, amd64 smoke и cgo arm64 cross-build PASS. Compiled state-inventory-confirm/replay/backup invalidation и отдельный native root race PASS. Точные результаты и SHA256 — новый completion evidence. Полный E08 по-прежнему открыт по перечисленным критериям FILES.md; это не отсутствие согласования пользователя.

## E08: финальные проверки16 октября2026

Текущий код: critical schema5/floor5, migration005; старые schema4/floor3 и schema5/floor4 записи выше относятся к сохранённым историческим evidence. Новых Go/link dependencies нет. Linux syscalls/cgo используют закреплённый sysroot; faccessat2 требует kernel≥5.8. [FILES](FILES.md) содержит actual behavior, CLI recovery, ограничения и maintenance/inventory процедуру.

Из корня проекта в PowerShell:

```powershell
wsl -d Ubuntu-22.04 -- bash /mnt/d/Projects/ServerDeck/agent/tools/wsl-e08-final.sh
wsl -d Ubuntu-22.04 -u root -- bash /mnt/d/Projects/ServerDeck/agent/tools/wsl-e08-final-root.sh
wsl -d Ubuntu-22.04 -- bash /mnt/d/Projects/ServerDeck/agent/tools/wsl-e08-final-export.sh
pwsh -NoProfile -File "Документация ServerDeck/Документация ServerDeck Agent/tools/check-docs.ps1"
python agent/evidence/E08-final-wsl-2026-10-16/seal.py --verify
```

Final script создаёт новую byte-identical Linux ext4 копию в ~/serverdeck-e08-final-2026-10-16, отдельные cache/tmp/test DB/dist. Выполняет gofmt/mod verify/vet, все tests/race, два fuzz targets, amd64 cgo build/ELF/ldd/sqlite-info, compiled CLI/TLS/local transfer smoke, offline state smoke, arm64 cgo cross-build/ELF. Root script работает только в отдельном mount/PID namespace с двумя tmpfs по16000000 bytes и проверяет cross-FS/restore/full/read-only/own-key/aliases/private guards. Export сверяет executable/test/tool inputs с основным проектом, переносит только evidence. Native ARM не выполняется (E12), Windows build не заменяет Linux evidence. Фактические результаты и SHA — [итоговый evidence](evidence/E08-final-wsl-2026-10-16/README.md).

16 октября первоначальный прогон остановился с I/O error при почти заполненном C: (~45МБ). Перед повтором удалены только воспроизводимые cache/tmp наших предыдущих ServerDeck сборок внутри Ubuntu; исходники/toolchain/evidence сохранены. Свободные ext4 blocks повторно используются без переноса/resize WSL и изменений Windows. Неуспешный прогон не считается PASS. WSL warning пользовательской systemd session не доказывает lifecycle readiness; foreground checks учитываются отдельно.

Фактический итог16 октября: final/root/export и supplemental root-race/compiled codec/inventory/reconcile/foreign-peer checks exit0.270 первоначальных файлов,249 executable inputs,4 binaries SHA-256;4372 toolchain files matched. Linux fmt/vet/test/race/fuzz/build/amd64 smoke PASS, документация и seal проверены отдельно. E08 закрыт в согласованных границах; native ARM/full host matrix не заявлены. Бинарные файлы находятся в Linux копии, export сохраняет только evidence.
