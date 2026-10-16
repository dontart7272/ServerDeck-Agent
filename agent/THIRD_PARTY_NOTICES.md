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

Websocket подключён в E03. x/sys/TUF из архитектуры пока не импортируются и не входят в go.mod или этот состав поставки. Их pins остаются кандидатами для соответствующих этапов; зависимости не подключаются ради списка. CUDA Toolkit, драйвер NVIDIA и системная SQLite для E01 не требуются. Linux ELF64/loader/native dependencies измерены: amd64 — libc.so.6, interpreter /lib64/ld-linux-x86-64.so.2; arm64 — libc.so.6 и ld-linux-aarch64.so.1, interpreter /lib/ld-linux-aarch64.so.1. Max GLIBC requirement2.34 у всех четырёх binaries, builder glibc2.35. Native runtime glibc имеет собственные LGPL-2.1-or-later условия; [copyright установленного Ubuntu-пакета](evidence/E01-wsl-2026-10-13/glibc-copyright.txt) и [GCC copyright](evidence/E01-wsl-2026-10-13/gcc-copyright.txt) сохранены. Native libraries/compiler/QEMU/sysroot не включены в Agent archive; app archive ещё не создавался. ARM выполнение проверено только в QEMU, не нативно.

## Дополнение E06

NVIDIA/go-nvml v0.13.4-1 реально импортируется Linux+cgo collector. Commit `1a1e86da474d340d7cf58274588f4a4afc8772e7`, module hash `h1:2E7RdOLBxHGSXq8sUw+c5Y0aWmFT7Cj+ZdjYulgUH18=`, [upstream](https://github.com/NVIDIA/go-nvml/tree/v0.13.4-1), [Apache-2.0 license](licenses/go-nvml-Apache-2.0.txt). Нужен cgo; NVML загружается динамически из существующего NVIDIA driver, не поставляется с Agent. CUDA Toolkit не требуется. Native GPU runtime и лицензия установленного NVIDIA driver проверяются отдельно на целевом стенде. Дополнительные зависимости upstream тестов не объявляются runtime-зависимостями Agent. Фактический module graph и ELF dependencies сохраняются в E06 evidence.

### Отдельное уведомление NVML header

`pkg/nvml/nvml.h` в этом теге — header13.4.92, Copyright1993–2026 NVIDIA Corporation. Он содержит собственный NVIDIA notice, а не Apache-2.0. Полный исходный текст сохранён в [NVML-header-NVIDIA-notice.md](licenses/NVML-header-NVIDIA-notice.md), включая Disclaimer и U.S. Government End Users Notice. Оригинальные internal comments сохраняются в неизменённом header закреплённой зависимости. Header SHA256 `c5de65a896402f4770b14e12128016ff974104b569ac08b4ba2aee8e66f5d9bf`. При поставке эти уведомления должны входить в пользовательскую документацию; binary archive E11 пока не создавался. Лицензия собственного кода Agent остаётся Apache-2.0.

## E07 external system utility

ICMP invokes the separately installed Ubuntu iputils ping; it is neither linked nor bundled in Agent binaries. Tested package3:20211215-1ubuntu0.1 (upstream20211215), Ubuntu jammy-updates/main and jammy-security/main. Installed copyright identifies BSD-3-Clause portions and GPL-2.0-or-later other portions; preserve the distribution's full notice when distributing that program. Runtime provenance/checksum/full copyright are in E07 evidence. No new Go modules or native link libraries are introduced. Installation/provisioning does not silently grant CAP_NET_RAW or alter ping_group_range.
