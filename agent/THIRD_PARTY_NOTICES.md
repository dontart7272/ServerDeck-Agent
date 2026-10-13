# Реально используемые компоненты E01–E03

Снимок 13 октября 2026. Собственный код `agent/` — Apache-2.0, [LICENSE](LICENSE).

| Компонент | Закрепление / происхождение | Лицензия / native |
|---|---|---|
| Go toolchain/standard library | 1.27.2, официальный go.dev, SHA256 в toolchains.json | [BSD-3-Clause](licenses/Go-BSD-3-Clause.txt); GCC нужен для cgo при сборке |
| github.com/santhosh-tekuri/jsonschema/v5 | v5.3.1, [исходный тег](https://github.com/santhosh-tekuri/jsonschema/tree/v5.3.1), go.sum и checksum database | [Apache-2.0](licenses/jsonschema-Apache-2.0.txt); чистый Go, без транзитивных Go-зависимостей |
| github.com/mattn/go-sqlite3 | v1.14.52, [исходный тег](https://github.com/mattn/go-sqlite3/tree/v1.14.52), go.sum и checksum database | [MIT](licenses/go-sqlite3-MIT.txt), Copyright 2014 Yasuhiro Matsumoto; cgo/GCC, встроенная SQLite |
| github.com/coder/websocket | v1.8.15, [исходный тег](https://github.com/coder/websocket/tree/v1.8.15), commit9c8faadccd1b679e811a79ce506f8a10237251ad; go.sum и [provenance](evidence/E03-wsl-2026-10-13/modules.json) | [ISC](licenses/websocket-ISC.txt), Copyright2025 Coder; pure Go, без дополнительных native libraries/транзитивных Go-модулей |
| SQLite amalgamation внутри драйвера | 3.53.4, sqlite3-binding.c/h из закреплённого тега; runtime source ID в evidence | [Public domain](https://sqlite.org/copyright.html); уведомление об отказе от copyright сохранено в исходном amalgamation, системная libsqlite3 не используется |

`go mod verify` проверяет соответствие загруженного дерева checksum; это не доказательство отсутствия уязвимостей. Оригинальные исходники доступны через `go mod download`, module zip hashes — в `go.sum`; Go snapshot hashes — в toolchains.json. В тегах проверены LICENSE и отсутствие отдельного NOTICE; Go LICENSE включён отдельно.

Websocket подключён в E03. x/sys/NVML/TUF из архитектуры пока не импортируются и не входят в go.mod или этот состав поставки. Их pins остаются кандидатами для соответствующих этапов; зависимости не подключаются ради списка. CUDA Toolkit, драйвер NVIDIA и системная SQLite для E01 не требуются. Linux ELF64/loader/native dependencies измерены: amd64 — libc.so.6, interpreter /lib64/ld-linux-x86-64.so.2; arm64 — libc.so.6 и ld-linux-aarch64.so.1, interpreter /lib/ld-linux-aarch64.so.1. Max GLIBC requirement2.34 у всех четырёх binaries, builder glibc2.35. Native runtime glibc имеет собственные LGPL-2.1-or-later условия; [copyright установленного Ubuntu-пакета](evidence/E01-wsl-2026-10-13/glibc-copyright.txt) и [GCC copyright](evidence/E01-wsl-2026-10-13/gcc-copyright.txt) сохранены. Native libraries/compiler/QEMU/sysroot не включены в Agent archive; app archive ещё не создавался. ARM выполнение проверено только в QEMU, не нативно.
