# E01: Ubuntu 22.04 WSL 2, 13 октября 2026

Проверены существующие Go-исходники, включая SD-SEC-001 и API-R01/R02. Application-код, API/schema/defaults не менялись. E02, HTTP/WSS/IPC listeners и systemd-install не добавлены. Установлены только инструменты внутри явно выбранной Ubuntu; Windows settings/VPS/docker-desktop не менялись.

## Окружение и границы

Дистрибутив `Ubuntu-22.04`, Ubuntu22.04.5 LTS, WSL2 / WSL2.6.1.0; ядро6.6.87.2-microsoft-standard-WSL2, x86_64. Сборка/тесты от существующего UID1000 `dontart7272`; root применялся только для apt подготовки. [WSL host](wsl-host.txt), [инвентарь до установки](inventory-before.txt), [kernel](kernel.txt), [Linux filesystem](linux-filesystem.txt).

Рабочая копия: `/home/dontart7272/serverdeck-e01-2026-10-13/source.J1hfMJ`. Вторая копия для повторной сборки: `.../rebuild.jEYLnC`. Go/toolchain, GOPATH, GOCACHE, GOTMPDIR и TMPDIR находятся внутри `/home/dontart7272/serverdeck-e01-2026-10-13` на Linux ext4. SQLite probe использует новую БД в памяти; файловых пользовательских БД нет. [Исходная копия: 72 файла](source-copy.json); [50 фактически компилируемых/тестируемых inputs](build-inputs.json) побайтово совпали с основным проектом. Исходный manifest отражает момент до дополнения tooling; build-inputs фиксирует код и контракты после сборки. Поздние изменения BUILD/журнала не являются входом бинарников.

При некоторых стартах WSL выводилось `Failed to start the systemd user session`. Это сохранено в исходных логах; offline builds/tests завершились успешно. Исправление systemd session и испытание Agent-unit здесь не выполнялись. Успех WSL не подтверждает обычный VPS/systemd/права хоста или полную матрицу AFR-001.

## Происхождение и pins

- Go1.27.2 из официального HTTPS-архива go.dev; SHA256 `ecbadb99091a3f46e31f5f934b068b1864eafa7995211b39eaddf76996045fe5` проверен **до** распаковки, [лог подготовки](prepare.txt).
- GCC11.4.0: `gcc-11=11.4.0-1ubuntu1~22.04.3`; cross GCC `gcc-11-aarch64-linux-gnu=11.4.0-1ubuntu1~22.04.3cross1`.
- Native glibc `2.35-0ubuntu3.15`; ARM sysroot `libc6-dev-arm64-cross=2.35-0ubuntu1cross3`; binutils `2.38-4ubuntu2.12`; QEMU user `1:6.2+dfsg-2ubuntu6.31`.
- [APT установка/происхождение](dependencies-install.txt), [повтор с точными pins: 0 upgrades/install/removal](dependencies-replay-pinned.txt), [31 package lock](linux-toolchain.lock.json), [4372 file hashes](toolchain-files.json), [проверка lock](toolchain-verification.txt), [полный installed inventory](ubuntu-packages.tsv), [metadata с SHA256 пакетов](ubuntu-package-metadata.txt). InRelease четырёх официальных Ubuntu suites сохранены рядом; trust bypass не применялся.
- Go-модули закреплены существующими go.mod/go.sum: go-sqlite3 v1.14.52 и jsonschema/v5 v5.3.1, транзитивных Go-модулей нет. `go mod download`, `go mod verify` прошли с checksum database. [Модули](go-modules.json), [hashes module archives](go-module-archives.sha256), [go.mod/go.sum hashes](go-module-files.sha256).
- [glibc copyright](glibc-copyright.txt) и [GCC copyright](gcc-copyright.txt) взяты из установленных Ubuntu-пакетов; историческое название версии в license text не заменяет dpkg/getconf. Compiler/QEMU/sysroot не включены в Agent distribution. Image digest отсутствует: контейнерный image не применялся; builder фиксируется package/content lock.

## Точные команды

Из PowerShell в основном проекте, всегда с явным дистрибутивом:

```powershell
wsl -d Ubuntu-22.04 -- bash /mnt/d/Projects/ServerDeck/agent/tools/wsl-inventory.sh
wsl -d Ubuntu-22.04 -u root -- bash /mnt/d/Projects/ServerDeck/agent/tools/wsl-install-deps.sh
wsl -d Ubuntu-22.04 -- bash /mnt/d/Projects/ServerDeck/agent/tools/wsl-prepare.sh
wsl -d Ubuntu-22.04 -- python3 /mnt/d/Projects/ServerDeck/agent/tools/capture-linux-toolchain.py /home/dontart7272/serverdeck-e01-2026-10-13/evidence
wsl -d Ubuntu-22.04 -- bash /mnt/d/Projects/ServerDeck/agent/tools/wsl-run-checks.sh
wsl -d Ubuntu-22.04 -- bash /mnt/d/Projects/ServerDeck/agent/tools/wsl-finish-checks.sh
wsl -d Ubuntu-22.04 -- bash /mnt/d/Projects/ServerDeck/agent/tools/wsl-export-evidence.sh
```

Capture создаёт snapshot существующего builder и отказывается перезаписывать имеющийся lock. В повторном прогоне capture нужно пропустить, проверить **сохранённый** lock этой записи; новый snapshot сам себя не подтверждает. `verify-linux-toolchain.py` проверяет exact versions и содержимое файлов; смена packages/sysroot требует нового осознанного прогона. Export сравнивает Linux snapshot с сохранённым project lock перед переносом. Подготовка создаёт новую source-копию, не очищает прежние данные. Scripts, env и полные build flags доступны в основном `agent/tools/` и [manifest tooling](tooling.sha256).

В Linux-копии с Go PATH/GOPATH/GOCACHE/GOTMPDIR/TMPDIR из env.sh, GOTOOLCHAIN=local, CGO_ENABLED=1:

```bash
CC=/usr/bin/gcc-11 bash tools/build-linux.sh amd64
CC=/usr/bin/gcc-11 bash tools/smoke-linux.sh
CC=/usr/bin/aarch64-linux-gnu-gcc-11 bash tools/build-linux.sh arm64
```

Smoke реально выполнил `go vet ./...`, `go test -count=1 ./...`, `go test -race -count=1 ./...`, version/sqlite-info для обоих native amd64 binaries, ldd, validate-config, отказ default service startup с exit2. Gofmt clean и mod verify проверены перед сборкой. ELF inspector проверяет ELF64, Machine, PT_INTERP, NEEDED, Go CGO/OS/arch settings и max GLIBC<=2.35. [Основной лог/exit0](linux-checks.txt), [ELF amd64](elf-amd64.json), [ELF arm64](elf-arm64.json), [полный readelf amd64](build-amd64.txt), [полный readelf arm64](build-arm64.txt).

ARM64 emulation: `timeout 60s qemu-aarch64 -L /usr/aarch64-linux-gnu <binary> version|sqlite-info`, дополнительно ctl validate-config. Эти команды прошли; полный arm64 native smoke/tests/race не выполнялся. QEMU не считается нативным ARM.

Вторая сборка обоих command для обеих архитектур выполнена с теми же cgo/build flags, другой source directory и новым пустым GOCACHE. Все четыре `cmp` успешны: [rebuild log/exit0](linux-extra-checks.txt). Python3 generation+gofmt воспроизвели wire_generated.go без изменений; новые scripts прошли bash -n; экспортированные binaries совпали с Linux-копией: [tooling/export log](final-tooling-check.txt).

## Результаты и оставшийся gate

| Цель | Build / ELF / reproducibility | Выполнение |
|---|---|---|
| Linux amd64 cgo | PASS; ELF64 x86-64, interpreter /lib64/ld-linux-x86-64.so.2, NEEDED libc.so.6, max GLIBC2.34; byte-identical rebuild | PASS в указанной Ubuntu WSL2: vet/test/race/offline smoke |
| Linux arm64 cgo | PASS; ELF64 AArch64, interpreter /lib/ld-linux-aarch64.so.1, NEEDED libc.so.6 и loader, max GLIBC2.34; byte-identical rebuild | PASS только QEMU version/SQLite/config; **native ARM NOT RUN** |

SQLite runtime у обеих команд/архитектур: 3.53.4, source ID `2026-07-24 19:02:57 bf7c7f30031888f4e796e429ab3978879485813aaca6f641c7b33e4e09459bcc`, compile options записаны в linux-checks. Системная libsqlite3/NVML не требуются полученным E01-бинарникам. Fully static сборка не заявляется.

[SHA256 четырёх binaries](binaries.sha256); копии артефактов — основной `agent/dist/linux-amd64/` и `agent/dist/linux-arm64/` (ignored). Подписанного production release нет.

Финальные проверки: [origin/binary SHA256 и UTF-8 paths](source-and-binary-verification.txt), [ожидаемый отказ перезаписи lock](capture-guard.txt), [штатный document validator](docs-check.txt). Document validation отдельно от Linux runtime.

**E01 частично закрыт: остаётся согласованный native ARM smoke/tests/race gate.** Нужен реальный ARM64 Linux-стенд с собственной проверенной native cgo цепочкой. WSL amd64 проверен, ARM cross-build доказан; это не повод закрыть нативный критерий или объявить всю матрицу поддержки. E02 не начат. Хранилище/аудит/rollback/full-disk/corruption tests относятся к будущим блокам; здесь такие испытания не выполнялись и пользовательские данные не изменялись.
