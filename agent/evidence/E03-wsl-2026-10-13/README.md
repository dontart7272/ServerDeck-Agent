# E03 — Ubuntu22.04 WSL2 / 13 октября 2026

Проверены существующий module `serverdeck.local/agent` и новые auth/transport adapters, без публичной установки. E03 закрыт в заявленных границах; E04 не начат. Полная реализация AFR/ASEC и release readiness этим результатом не объявляются.

## Среда и копия

Ubuntu-22.04, Ubuntu22.04.5, WSL2, kernel6.6.87.2-microsoft-standard-WSL2, amd64. Обычные build/tests UID1000 dontart7272, Go1.27.2/cgo1/GOTOOLCHAINlocal, GCC11.4.0-1ubuntu1~22.04.3, glibc2.35-0ubuntu3.15. Старый package/content lock31 packages/4372 hashes прошёл без изменения. Никакого docker-desktop, VPS, изменения Windows/configuration systemd.

Источник `/mnt/d/Projects/ServerDeck`, копия Linux ext4 `/home/dontart7272/serverdeck-e03-2026-10-13/source.ojWbNj`. [126 первоначальных файлов](source-copy.json), [финальные compiled/tested/tooling inputs](build-inputs.json). Поздние Markdown changes не являются tested app-source; итог документации проверяется отдельно. Export сравнивает текущий основной проект, переносит только evidence/соответствующие binaries, не application sources.

## Что выполнено

| Проверка | Фактический результат |
|---|---|
| Formatting/mod/vet/test/race | PASS, все Go packages; [полный лог с командами](linux-checks.txt) |
| TLS/HTTP | Настоящие loopback TLS sockets: wrong pin/SAN/expiry/TLS<1.2 отказ, positive IPv4/IPv6, strict typed queries/errors, invalid/spoofed/oversize input, no unauth metrics/file/UI/operations, no shell |
| Pairing | Real SQLite, atomic code/device, five attempts/TTL/rates, consumed replay/потерянный response, concurrent requests single winner, restart сохраняет issued token и инвалидирует code, нет секретов в audit/Operation result |
| Revoke/operations | Равноправный второй телефон отзывает первый; WSS1008 и HTTP401; plan/version/ID/HMAC guards; audited cancellation до effect/typed too_late после; audit failure до изменения исключает эффект |
| Floor/recovery | Actual v1->v2 migration и v1 backup restore; текущие credentials/identity/policy не подменяются backup; revoked access не возвращается; bounded retired registry; floor write failure после commit даёт unknown/partial и отдельный health flag, повтор не создаёт эффект |
| WSS | Реальный upgrade/subprotocol/text typed pages, max2/device, Origin refusal, duplicate subscriptions, foreign-session ACK rejection, cursor scope/tamper/registry gap |
| CLI/startup | Свежие amd64 agent/ctl binaries: private native startup, Unix bootstrap, HTTPS pair/query, local CLI query, occupied port refusal, SIGTERM socket cleanup; E02 init/status/backup/replay/restore/resolve smoke |
| Root/foreign peer | [Отдельный PASS](root-checks.txt): root-owned temp state/CLI/native startup и настоящий UID65534 peer отказ. Обычный прогон корректно показывает root-only SKIP |
| Storage regressions | Actual SQLite FULL/read-only/corruption/busy/long reader/crash/retention/backup tests; отдельно [physical ENOSPC PASS](physical-enospc.txt) на private16000000-byte ext4, [точная воспроизведённая процедура](full-filesystem-run.sh) |
| cgo builds/ELF | Оба cmd для amd64 и arm64 собраны; NEEDED amd64 libc.so.6, arm64 libc.so.6/ld-linux-aarch64.so.1; max required GLIBC2.34. [SHA256 binaries](binaries.sha256). ARM только cross-build/ELF, не native execution |
| Dependencies | [Module provenance](modules.json), [graph](module-graph.txt), [websocket zip/license SHA](websocket-files.sha256), [ISC](../../licenses/websocket-ISC.txt). Pins прежних двух modules сохранены; native libs не добавлены |
| Documentation | Штатный check-docs.ps1; [фактический лог](docs-checks.txt), не runtime proof |

E03-PAIR-01 исправлен до финального прогона: pending request ID нельзя перезаписать другим code ID. [До/после](pairing-collision.txt), [ожидаемый отказ прежнего поведения](pairing-before.txt), [reproducer](reproduce-pairing-collision.sh). Прежнее поведение восстанавливается только в новой private Linux-копии; основной проект не меняется. Fixed regression дополнительно проходит трижды и в общем race-прогоне. Первый документальный запуск показал только отсутствующую ссылку на ещё не созданный собственный docs-checks.txt; [исходный вывод](docs-initial.txt), итоговый validator PASS после создания log artifact. Это не runtime failure.

Точные команды запуска — [BUILD, E03](../../BUILD.md). check log содержит date/env, lock verification, все команды Go/build/ELF и opt-in SKIP; root/ENOSPC PASS сохранены отдельно. Полный source-ID SQLite3.53.4 и compile options находятся в linux-checks.txt. Сценарии провоцируют отказы только в собственных временных state/DB/controlled effects, секреты не выводятся.

## Не выполнено

Native ARM smoke/tests/race — нет стенда, согласованный E12 gate сохраняется. Обычные Linux hosts/systemd/Android SSH/trust/secure storage/первый snapshot/file byte streams/module IPC/installer/firewall/TLS365-day issuance и rotation/signed update/power-loss/CVE audit/полная нагрузочная матрица — не проверены и не заявлены. File/UI APIs пока только отвергают доступ без токена и возвращают недоступность авторизованному клиенту; их реальные continuations/revocation проверяются E08/E10. WSS operations/storage не заменяют будущие snapshot/events/problems collectors.

Некоторые WSL вызовы сообщают отказ systemd user session; ядро/Ubuntu/команды работают, настройки systemd ради тестов не менялись. E01/E02 historical evidence не переписаны. [Итоговая трассировка](<../../../Документация ServerDeck/Документация ServerDeck Agent/11. Журнал проверки требований.md>) различает согласовано/специфицировано/частично реализовано/частично проверено.
