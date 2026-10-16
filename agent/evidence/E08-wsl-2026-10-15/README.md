# E08: доступная основа и открытые гарантии

**E08 не завершён.** [FILES](../../FILES.md), [inventory decision/реализация](../../E08-INVENTORY-DESIGN.md). Production stat/list/text/download/stream отключены: baseline unknown. Положительные файловые tests используют явно ограниченные fixtures; они не подтверждают готовность общего файлового менеджера.

## Воспроизведение

Из Windows корня проекта:

```powershell
wsl.exe -d Ubuntu-22.04 -- bash /mnt/d/Projects/ServerDeck/agent/tools/wsl-e08.sh
wsl.exe -d Ubuntu-22.04 -u root -- bash /mnt/d/Projects/ServerDeck/agent/tools/wsl-e08-root.sh
wsl.exe -d Ubuntu-22.04 -- bash /mnt/d/Projects/ServerDeck/agent/tools/wsl-e08-export.sh
pwsh -NoProfile -File "Документация ServerDeck/Документация ServerDeck Agent/tools/check-docs.ps1"
python -X utf8 agent/evidence/E08-wsl-2026-10-15/seal.py
python -X utf8 agent/evidence/E08-wsl-2026-10-15/seal.py --verify
```

Full checks выполняются в новой ext4 copy `/home/dontart7272/serverdeck-e08-final-2026-10-15/source.*`; точный путь — source-copy.json/build-inputs.json. source-copy.json — исходный снимок перед отчётом; build-inputs.json связывает окончательные исполняемые inputs с проверенной копией, docs-snapshot.json фиксирует финальный Markdown. Кэши, tmp, DB и binary остаются в Linux-ФС. Export сравнивает весь inventory исполняемых inputs и переносит только evidence. Root procedure монтирует16МБ tmpfs исключительно в новом private mount/PID namespace; не меняет mounts/настройки Windows/VPS или пользовательские файлы. Обычные тесты идут UID1000, отдельные isolation tests — root только в дочернем namespace.

## Окружение и проверки

Ubuntu-22.04 WSL2 Ubuntu22.04.5 x86_64; kernel6.6.87.2-microsoft-standard-WSL2; Go1.27.2, GOTOOLCHAIN=local, CGO_ENABLED=1; GCC11.4.0 amd64 и aarch64 cross; glibc2.35. E01 lock проверяет31 native packages/4372 files; go mod verify подтверждает реальные зависимости, новых нет. Фактическая SQLite3.53.4. Подробности команд/времени/stdout — linux-checks.txt; точные binary hashes — binaries.sha256, ELF/ABI — elf-amd64.json/elf-arm64.json.

**PASS окончательного прогона15 октября2026** (начало14:58:58 UTC): gofmt/vet/test всех пакетов/race, два fuzz10s/2workers, обе amd64 commands/version/sqlite-info/ldd, arm64 cgo cross-build/ELF, compiled TLS/CLI/state smoke; state-inventory smoke проверяет сохранение обоих unknown receipts после restore. Private root tests проверяют live/bootstrap pins, tmpfs/bind/TLS и реальный backup/restore с ключом на другой ФС: high-level чтение отказывает, key bytes не возвращаются/не логируются. Low-level O_PATH metadata counterexample намеренно показывает, почему paths/FD live state не дают полного inventory.

**PASS storage inventory tests:** отказ SQLite и отказ floor publication до destination effect; unknown receipts после restore; divergent backup refusal; legacy migration без automatic complete; quota без eviction; raw rollback/lost floor/revoked credentials и существующие E02 failures. Migration4/floor3: старый writer несовместим, новый читает old backup1–4. Floor2 уже принадлежит E03.

## Что не подтверждено

BLOCK-FS (expected-version mutation при произвольном внешнем writer), TECH-FS-READ (защищённые ancestors на общей ФС), полная идентичность owned objects после rename/remount/reboot, bootstrap inventory accounting и CLI baseline complete. Нет write/upload/staging/rename/move/trash/PURGE/cross-FS implementation, полной CLI binary transfer и полного V-FILE/ENOSPC/crash набора. Отказные gates не закрывают AFR-046–050/ASEC-017. Native ARM и обычная Linux host/kernel/FS matrix не выполнялись; ARM cross-build не заменяет их. NVIDIA/daemon/Android gates прошлых этапов этим не закрыты. E09 не начат.

pre-final-* — диагностические предыдущие snapshots; их PASS не заменяет окончательный linux-checks.txt и source identity. artifacts.json/docs-snapshot.json создаются последними. После изменения исходников seal --verify должен отказать: это честное обнаружение дрейфа, не основание переписать старое evidence.

## Итоговая фиксация

Full script exit0; source identity234 первоначальных files, export подтвердил213 окончательных build/test/tooling inputs. gofmt/mod verify/vet/test/race — PASS для всех пакетов. FuzzWeightedRollup126490 executions, FuzzE08Location82977 executions, nominal10s/2workers каждый — PASS. amd64/arm64 binaries — cgo ELF64, максимальный требуемый символ GLIBC2.34 при сборке на glibc2.35; amd64 version/sqlite-info/ldd/compiled CLI/TLS/state/inventory smoke — PASS. Arm64 только cross-build/ELF. Оба private root tests — PASS на финальной app.test; числовое повторное использование PID в отдельном user/PID namespace также PASS.

Штатный docs validator: PASS38 documents,683 local links,72 AFR+31 ASEC,103 ledger rows,6 schemas,178 compiled types,16 valid examples,18 negative fixtures,12 defaults,23 queries,21 actions. Seal/verify связывают проверенные inputs, финальные документы и evidence; команды выше. WSL иногда сообщал о неуспешном запуске пользовательской systemd session; foreground build/test/isolated namespace процедуры завершились успешно. Это не подтверждение systemd deployment/обычной host matrix.

В ранних полных прогонах найдены устаревшие fixtures schema3/фиксированных поколений и credential insertion без advance security_generation. Fixtures исправлены с сохранением checks migration/checksum/rollback; защиты не отключались. Предыдущие прогоны с изменённым исходным snapshot закономерно отказали на source identity; они сохранены только как diagnostic pre-final logs.

E08 **остаётся открытым**. Согласовано: строгие AFR/ASEC и fail-closed inventory подход. Специфицировано: FILES/inventory/schema4/floor3. Реализовано: read components за gate, metadata/config, ограниченные unknown receipts и local status. Проверено: перечисленные WSL tests; полнота inventory, production filesystem operations и release matrix не подтверждены. Перед продолжением полного E08 нужны identity/accounting/invalidation protocol и решение BLOCK-FS без молчаливого ослабления guarantees; другого Exx для устранения этих технических препятствий само по себе недостаточно.
