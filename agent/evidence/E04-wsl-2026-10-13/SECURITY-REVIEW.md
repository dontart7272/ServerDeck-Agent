# E04: проверка новых read-only путей по OWASP

13 октября 2026. Scope: новые `internal/metrics`, app metrics query/WSS/native lifecycle и изменения wire schemas. Применён [owasp-audit](<../../../.agents/skills/owasp-audit/SKILL.md>). Это проверка E04, а не повторное объявление всего Agent безопасным. E01–E03 remediation сохранены;26 auth/storage/operations/semantic-validator inputs сверены с E03 по SHA256 в safety-baseline.json. Новых dependencies нет. Runtime evidence — [Linux](linux-checks.txt), [root](root-checks.txt).

Проверено без новых открытых находок в указанном scope: авторизация до metadata, trusted cursor owner, изменение sort, отзыв активного snapshot WSS; source callbacks не получают клиентские пути/команды; нет argv/env, shell, исходящего HTTP/DNS lookup или изменения сервера. JSON остаётся данными; Android/UI render вне scope. Пределы входа/страниц/cache/native calls и безопасные reason проверены кодом и тестами. Непроверенные hardware/CVE/release гарантии перечислены ниже.

| Категория | Состояние и проверенный путь |
|---|---|
| A01 Broken Access Control | Clean для E04: HTTP/Unix guards до metricQuery, owner из credential/peer, scope HMAC includes trusted owner+filter/sort, WSS auth перед отправкой. TestMetricsHTTPSPagesScopeWSSAndRevocation, root foreign UID rejection |
| A02 Cryptographic Failures | Clean для новых references: SHA256 только identity, не password hash/token auth; cursor HMAC использует прежний protected Store; UUID crypto/rand. TLS/credentials E03 не заменены |
| A03 Injection | N/A новых SQL/HTML/command execution sinks нет. `rg` и чтение collectors проверили отсутствие os/exec, shell, write syscalls, cmdline/environ; маршруты/cgroup — bounded data |
| A04 Insecure Design | Findings исправлены до итогового прогона: непредельное ожидание statfs и удержание поколений процессов, см. ниже. Engine не размножает зависший native source; leases/pages имеют bounds/TTL |
| A05 Security Misconfiguration | Clean в E04: никаких установок/users/groups/firewall изменений; live tests только loopback. Native boot-source failure выключает collectors, не auth guards. Нет debug/raw error output |
| A06 Vulnerable Components | N/A новых modules/packages нет; go.mod/go.sum, три прежних modules и package/sysroot lock повторно проверены. Свежий CVE scan НЕ выполнен: govulncheck отсутствует. Нельзя читать этот статус как отсутствие CVE; release scan остаётся E12 |
| A07 Authentication Failures | Clean для новых adapters: existing authenticated service, WSS revocation1008 и отказ чужому Unix peer подтверждены. Pairing/token implementation не переписаны |
| A08 Data Integrity | Findings исправлены до прогона: старый segment не должен попадать в новый, общие snapshots не должны мутироваться при выдаче. Source copy/final input/artifact SHA256, last-good и monotonic stale проверены |
| A09 Logging/Monitoring Failures | Clean для новых диагностик: source health/availability видны в памяти, error text не включает raw OS errors/secret content; SQLite audit failure test сохраняет authenticated RAM monitoring и degraded flag. Полные events/alerts E05 ещё не реализованы |
| A10 SSRF | N/A E04: пользователь не задаёт URL/путь источника, сетевые данные читаются локально proc/sys/netlink; внешних HTTP/DNS/доступность запросов нет |

## Исправления при разработке E04

**[Medium] A04 / CWE-400: зависший statfs.** Первоначально последовательный syscall мог задержать весь filesystem block. Исправлено в `internal/metrics/linux.go`: максимум4 actual calls, один pending на observed mount, timeout10мс не освобождает slot; per-mount reason и root-first. TestHungStatfsDoesNotMultiplyOrHideOtherMounts + TestFilesystemNativeSlotLimit проверяют отсутствие повторного вызова и отказ пятому вызову. Это контролируемый test effect, не намеренно зависший host/NFS mount. При4 действительно зависших calls другие ФС получают SOURCE_BUSY; другие источники продолжаются.

**[Medium] A04 / CWE-400: retained process generations.** Кроме2 revisions/owner/30с введены64 owners/32 разных revisions глобально, одна collection≤4МБ encoded. Новая allocation при лимите отклоняется, старые страницы не подменяются. TestTwoProcessSnapshotsPerOwnerAndGlobalRetentionBound и page/lease tests. Число encoded bytes не выдано за предел Go RSS; soak ещё требуется.

**[Medium] A08 / CWE-362: время и общие views.** Stale/TTL рассчитываются по monotonic, wall jump создаёт новый segment, old in-flight source result отбрасывается. FS pending native results очищаются при смене segment; занятые4 slots сохраняются до завершения реальных calls. Выдача копирует изменяемые metrics/raw records, сохраняя timestamps общего снимка. TestLastGoodPermissionFailureStaleAndClockSegment, TestStaleThresholdUsesMonotonicAndReadDoesNotRefresh, общий race suite.

**[Low] A09 / CWE-200: mount source с userinfo.** Источник с `@` заменяется REDACTED_SOURCE; raw source failure/stack/процессные argv/env не выводятся. Это не универсальный DLP для произвольного текста, записанного доверенным администратором в имена/cgroup/mount paths; сервер возвращает только предусмотренные metadata fields.

## Второй проход и ограничения

Повторный adversarial проход проверил quota bypass через разные owners/revisions, signed cursor reuse у другого телефона, WSS без ACK, revocation, PID reuse между stat reads, cached metadata timestamps, clock change при pending native syscall и отличие Tctl/Tdie. Дополнены positive coretemp fixture и прямая проверка пятого statfs slot. Внешний независимый аудитор/модель не использовались. Открытых обнаруженных security defects E04 после исправлений не оставлено; это не доказательство отсутствия неизвестных уязвимостей.

Не выполнены: свежий CVE scan, native ARM runtime/race, physical CPU thermal/throttling/NIC matrix, real NFS hang, длительный CPU/RAM/FD soak, production systemd watchdog/installer и Android end-to-end. Они не заменены Windows-проверками или mock-успехом. E05/history/events и последующие эффекты этим аудитом не разрешаются автоматически.

CPU PSI уточнение: [официальный Linux6.6 PSI ABI](https://www.kernel.org/doc/html/v6.6/accounting/psi.html) определяет system-level CPU full как undefined; compatibility zero не выдаётся как измеренный процент. `psi_full_percent` возвращает null/unsupported/SYSTEM_CPU_FULL_UNDEFINED, `psi_some_percent` использует avg10. TestSystemCPUFullPSIZeroIsUndefinedNotAvailable проверяет обе ветви. Это исправление семантики AFR-013/022, а не изменение продуктовой гарантии.

**[Low] A04 / CWE-20: неизвестный block selector.** HTTP/WSS проверяют membership в зарегистрированных E04 sources. Отсутствующий adapter возвращает SOURCE_UNAVAILABLE, вместо ложного complete empty snapshot; mixed-source partial failure среди зарегистрированных источников сохраняет остальные blocks. TestMetricsHTTPSPagesScopeWSSAndRevocation содержит отрицательную HTTP-проверку; единый metricBlocks guard используется WSS.

Дополнительная проверка last-good: process/source failure и native timeout сохраняют measurement time, но показывают timestamp последней попытки источника; Reason не разделяет изменяемый указатель с вызывающим кодом. TestProcessFailureUpdatesAttemptWithoutRefreshingMeasurement проверяет отказ прав и защиту общего состояния.

Quota уточнение: global retained generations32 (encoded≤128МБ) допускают обычные shared2с/TTL30с страницы разных телефонов; меньший первоначальный bound8 мог преждевременно отклонять нормальные запросы. TestPageRetentionDoesNotThrottleNormalThirtySecondWindow воспроизводит эту границу, тест32 generations отдельно проверяет отказ следующей allocation. RSS/soak ещё не измерены.

**[Medium] A08 / CWE-367: mount identity при overmount/path race.** Capacity привязана к O_PATH FD и фактическому fdinfo.mnt_id перед Fstatfs. Неверный/скрытый mount не получает чужие значения; дополнительный mountinfo recheck сохранён. TestNativeFilesystemDescriptorBindsExpectedMount использует реальные Linux FD/FS и неправильный expected ID; host mount namespace не изменяется.
