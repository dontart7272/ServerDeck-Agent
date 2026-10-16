# E05: проверка первой части — агрегация

14 октября 2026. Только `internal/history`: pure CPU gauge/network delta aggregation и rollup; AFR-027/028 частично, ASEC-028/030 частично. Это не storage/API/events integration и не закрытие E05. [Границы реализации](../../HISTORY.md).

Основная команда из PowerShell в корне проекта:

```powershell
wsl -d Ubuntu-22.04 -- bash /mnt/d/Projects/ServerDeck/agent/tools/wsl-e05-aggregation.sh
```

Script создаёт новую ext4-копию под `~/serverdeck-e05-aggregation-2026-10-14/source.XXXXXX`, сверяет исходные bytes, использует закреплённый env E01, отдельные cache/tmp и повторно сравнивает основной проект в конце. Обратной синхронизации app-source нет. Экспорт evidence после успешного прогона:

```powershell
wsl -d Ubuntu-22.04 -- bash -lc 'rsync -a "$HOME/serverdeck-e05-aggregation-2026-10-14/evidence/" /mnt/d/Projects/ServerDeck/agent/evidence/E05-aggregation-2026-10-14/'
pwsh -NoProfile -File "Документация ServerDeck/Документация ServerDeck Agent/tools/check-docs.ps1"
```

Окружение: Ubuntu22.04.5 WSL2 x86_64, kernel6.6.87.2-microsoft-standard-WSL2, UID1000, Go1.27.2/cgo1/GOTOOLCHAINlocal, GCC11.4.0-1ubuntu1~22.04.3, glibc2.35-0ubuntu3.15. 31 закреплённый пакет/4372 файла native+cross chain проверяются прежним lock E01. SQLite3.53.4 проверяется обеими compiled commands. Новых Go/native dependencies нет.

Артефакты: `linux-checks.txt` — команды и вывод; `source-copy.json` — первоначальные bytes Linux-копии; `build-inputs.json` — повторная сверка окончательных non-Markdown входов с основным проектом; `binaries.sha256` — четыре cgo-бинарника; `docs-checks.txt` — штатный validator; `evidence.sha256` — целостность остальных файлов evidence. Markdown и карта источников дополняются после тестов; исторический source-copy не заменяется вымышленным новым снимком.

Проверяются gofmt, mod verify, vet, test -v -count=1, test -race -count=1, отдельный 10s fuzz с двумя workers, amd64 build/ELF/glibc/ldd/version/sqlite-info обеих commands, compiled CLI/TLS smoke, state smoke, arm64 cgo cross-build/ELF. Это выполнение в указанном WSL, а не вся серверная матрица; cross-build не является native ARM проверкой.

Не выполняются в этом блоке: новая history.db/WAL/retention/quota/ENOSPC; rules/events/active state/resume/Android; root/foreign-peer и отдельный private-mount ENOSPC E02/E03; native ARM/hardware/host systemd/soak/CVE scan. Старые opt-in root/physical ENOSPC tests могут иметь SKIP в общем suite; это не PASS этих процедур. E01–E04 storage/auth code не менялся. Результаты новой агрегации не переносятся на ещё отсутствующее хранилище истории.

Итог: PASS всех перечисленных проверок; fuzz866139 executions. Штатная docs-проверка:38 документов/605 local links/72AFR/31ASEC/103 ledger rows/6schemas/178types/13valid/15negative/12defaults/22queries/21actions. Финальные133 non-Markdown inputs совпадают с протестированной копией. Целостность: `pwsh -NoProfile -File agent/evidence/E05-aggregation-2026-10-14/verify.ps1` из корня. `documents.sha256` фиксирует обновлённые после тестов документы; старые E04 manifests не переписаны. При экспорте WSL выдал предупреждение о systemd user session; тесты systemd не запускали и настройки не меняли.
