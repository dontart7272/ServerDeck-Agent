# ServerDeck Agent — E01–E07

Один Go-модуль `serverdeck.local/agent`, два cmd. E02 добавил critical SQLite, аудит/операции/offline maintenance. E03 добавил HTTPS/WSS, pairing/devices/revoke, local admin socket/CLI и повторную авторизацию общего application service. E04 добавил общий Linux-сбор и read-only snapshots/process pages через защищённые транспорты. Публичная установка не выполнялась. E05 добавил history/events; E06 — доступные read-only integrations с открытыми аппаратными gates. E07 добавил pidfd process control и ICMP. Файловые эффекты и module IPC ещё не реализованы.

- [Сборка, команды и фактические ограничения](BUILD.md)
- [Критическое хранилище и операции](STORAGE.md), [E02 evidence](evidence/E02-wsl-2026-10-13/README.md)
- [Доверие и транспорт E03](AUTH-TRANSPORT.md), [E03 evidence](evidence/E03-wsl-2026-10-13/README.md)
- [Метрики и снимки E04](METRICS.md), [E04 evidence](evidence/E04-wsl-2026-10-13/README.md)
- [Apache-2.0](LICENSE) и [лицензии зависимостей](THIRD_PARTY_NOTICES.md)
- [План полного продукта](<../Документация ServerDeck/Документация ServerDeck Agent/9. План реализации.md>) и [журнал проверок](<../Документация ServerDeck/Документация ServerDeck Agent/11. Журнал проверки требований.md>)

E01 закрыт по уточнённым критериям; E02 закрыт в offline-границах. E03 проверен в Ubuntu22.04 WSL2 amd64: vet/test/race, реальные SQLite/TLS/WSS/Unix peers, ordinary/root и изолированный ENOSPC; четыре amd64/arm64 cgo binaries собраны. ARM64 экспериментален, native ARM остаётся E12. E03 закрыт в границах реализованного auth/transport, полные AFR/ASEC и матрица выпуска не закрыты. E04 реализован и проверен для текущих Linux read-only adapters в Ubuntu WSL2; матрица физических серверов/датчиков и native ARM остаётся E12. E05 автоматически не начинается; точные результаты и ограничения — BUILD/журнал.

Исторический снимок E05-A (заменён полной реализацией E05 ниже): [математическая агрегация истории](HISTORY.md) и [Linux evidence](evidence/E05-aggregation-2026-10-14/README.md). В том снимке подключения к scheduler/SQLite/API ещё не было. Текущее состояние E05/E06 описано ниже.


E05: [history/events/rules и границы](HISTORY.md), [Ubuntu evidence](evidence/E05-wsl-2026-10-14/README.md). Это текущая реализация; прежний math-only E05-A остаётся историческим снимком. Новые capabilities объявляются только при доступности соответствующего storage. Реальные GPU/security adaptersE06 и Android/runtime release matrix не подменяются fixtures.

E06: доступные read-only адаптеры GPU/Docker/security — [INTEGRATIONS](INTEGRATIONS.md). Этап открыт до перечисленных проверок hardware/daemon/OS и recovery cases.

E07: [процессы и ICMP](PROCESS-DIAGNOSTICS.md), [Ubuntu evidence](evidence/E07-wsl-2026-10-15/README.md). Нет fallback kill(pid), shell/произвольных флагов, выдачи capabilities или автоматического TERM→KILL. E08 не начат.

E08: [файлы, потоки, корзины и recovery](FILES.md), [итоговые проверки](evidence/E08-final-wsl-2026-10-16/README.md). Предыдущие read-only ограничения заменены согласованной моделью shared roots, descriptor bindings и явного inventory; статус этапа фиксируется в итоговом evidence. E09 не начинается автоматически.
