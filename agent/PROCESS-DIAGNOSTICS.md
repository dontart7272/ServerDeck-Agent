# E07: процессы и ICMP

## Границы

AFR-041/062, ASEC-009/018/029; общие гарантии AFR-036/038–040, ASEC-010/011/030 наследуются от application service E02/E03. Одна реализация обслуживает HTTPS и доверенный local socket/CLI. Новых маршрутов, shell API, sudo/helper, firewall effects, capabilities или sysctl установки нет. E08 не реализуется.

## Экземпляр процесса и сигналы

`internal/processcontrol` сопоставляет E04 process_ref с boot_id, PID, start_ticks и inode PID namespace. process_ref — первые16bytes SHA256 от разделённых NUL boot/PID/start/namespace, тот же формат E04. Запрос содержит только process_ref, не произвольный PID или номер сигнала. expected_version, если передан, должен совпасть с process_ref.

Подготовка плана проверяет доступность pidfd, идентичность и права. После durable intent и непосредственно перед сигналом проверки повторяются: read → pidfd_open(flags=0) → read/сравнение → pidfd_send_signal(0) → фиксированный SIGTERM либо SIGKILL. Нет fallback kill(pid). Недоступный syscall, неподходящий procfs namespace, нечитаемые данные или слишком длинная цепочка родителей означают SAFETY_UNAVAILABLE. PID1, PF_KTHREAD, собственный процесс, потомки Agent и зарегистрированные managed refs защищены. Регистрация managed refs — только внутренний lifecycle hook, максимум256; E09 должен регистрировать refs также для переподчинённых модулей. Zombie/dead отклоняется как NOT_FOUND. При root сохраняется та же защита.

TERM/KILL имеют отдельные планы, подтверждения, fingerprints и action. Успех означает принятие сигнала ядром. До1000ms poll по этому же pidfd наблюдает завершение; signal_sent=true и exit_observed=false допустимы. Нет автоматического KILL/повтора при таймауте. Два действия над одним ref сериализуются E02. Внешнее изменение по SSH не блокируется внутренним lock: идентичность повторно проверяется ядром. Защита managed lifecycle не даёт прав управлять внешним процессом.

Результат: `{process_ref, signal_sent, exit_observed, observed_at}`. PROTECTED_OBJECT/PERMISSION_DENIED →403, OBJECT_CHANGED/VERSION_CONFLICT →409, NOT_FOUND →404, SAFETY_UNAVAILABLE →422. Если сигнал ещё не отправлен, отказ операции rejected/none. После успешной отправки невозможность наблюдать выход не превращается в failed/none. Потеря durable result сохраняет result_pending; рестарт переводит незавершённое состояние в unknown/reconcile_required, без повторной отправки.

В processes.get/list и snapshot/WSS выдаются process.term/kill actions с live advisory availability, reason и version=process_ref. Эти данные не авторизуют выполнение; guards повторяются в application service. Страницы и snapshots ограничены существующими лимитами E04.

## Общая ICMP-цель

config.set поддерживает группу icmp через существующий CAS runtime revision и аудит. target=null по умолчанию; background_enabled=true требует target. Разрешены отдельный IPv4/IPv6 без zone и ASCII DNS, включая private/VPN адреса; не URL, порт, параметры или shell. Unspecified/multicast запрещены. Никаких произвольных флагов.

`diagnostics.icmp` возвращает общую конфигурацию и последний результат. target_version — opaque `agent_run_id:runtime_revision:icmp_hash`; даже возврат к прежней строке или изменение другой runtime-группы инвалидирует прежний план/кэш. Рестарт создаёт новую идентичность локального кэша; durable manual operation results остаются в E02. Схема critical DB остаётся3, новая миграция не нужна.

Manual diagnostics.icmp.run проходит prepare/execute, авторизацию, policy, intent/audit до DNS/запуска. Общие locks diagnostics.icmp + settings.runtime сериализуют manual probe и config.set. Один Manager на Agent: одна попытка одновременно и минимум15s между началами, включая неуспешный DNS. BUSY/RATE_LIMITED не создают второй probe. Совместный бюджет распространяется на фон.

Фоновый мониторинг запускается раз в60s только после явно включённой аудируемой настройки. Это периодическое наблюдение, а не новое изменение сервера каждую минуту: AFR-038 исключает метрики из аудита, ASEC-011 сохраняет мониторинг при отказе аудита. Фон не расходует критическую квоту operation IDs; читает текущую policy и не запускается при запрете diagnostics.icmp.run или недоступности settings/policy. Ошибка отдельной пробы не меняет online Agent. При смене version результат старого probe не выдаётся для новой цели.

DNS через Go resolver входит в общий10s timeout; выбирается ровно один детерминированный валидный адрес из максимум128 (IPv4 первым), нет сканирования или перебора адресов. Дальше numeric IP передаётся отдельным аргументом штатному ping: `-4|-6 -n -c 5 -w 10 -W 1 ADDRESS`. Максимум5пакетов/10s по первому пределу; после cancellation допускается до250ms на уборку дочернего процесса. PATH lookup отсутствует: /usr/bin/ping или /bin/ping, root-owned executable и все предки без group/other write; чистый LANG=C environment, без унаследованных loader variables. Stdout≤65536bytes, stderr≤4096bytes; сырые выводы не попадают в API/аудит/diagnostics.

Профиль вывода: iputils C-locale packet summary и rtt min/avg/max/mdev; неизвестный/неполный формат →source_error. exit1 с валидной summary и100%loss — доступное измерение, не OFFLINE. Нулевые счётчики при source_error/permission_denied не являются подтверждением отсутствия отправленных пакетов: полной summary нет. resolved_ip и observed_at связаны с конкретной version. Последний результат становится stale через180s по monotonic clock; новый target имеет отдельный результат. Manual results хранятся с E02 завершёнными операциями; общий monitoring cache только в памяти, отдельная ICMP history series контрактом не задана.

## Зависимости и проверка

Новых Go-зависимостей нет. pidfd — cgo syscall/Linux libc с существующей GCC11.4/glibc2.35 цепочкой. ping — отдельная системная программа, не bundled/linked: проверяемый профиль Ubuntu22.04 iputils20211215, package3:20211215-1ubuntu0.1. Лицензии штатного пакета: BSD-3-Clause и GPL-2.0-or-later по /usr/share/doc/iputils-ping/copyright; полная notice сохраняется в evidence. Agent не присваивает этому пакету Apache и не устанавливает capabilities. Отсутствие программы/прав отключает только диагностику.

Проверки и ограничения: [E07 evidence](evidence/E07-wsl-2026-10-15/README.md). WSL не подтверждает обычную серверную matrix, native ARM или IPv4/IPv6/NAT/firewall маршрут с телефона — это отдельные E12 проверки. Реальные процессы/SQLite и loopback дополняют ограниченные fault fixtures.

## Первичные источники

- [pidfd_open](https://man7.org/linux/man-pages/man2/pidfd_open.2.html), [pidfd_send_signal](https://man7.org/linux/man-pages/man2/pidfd_send_signal.2.html): pinned FD, permission checks, poll/exit.
- [proc_pid_status](https://man7.org/linux/man-pages/man5/proc_pid_status.5.html), [PID namespaces](https://man7.org/linux/man-pages/man7/pid_namespaces.7.html): procfs/NSpid mapping.
- [kernel ns_last_pid](https://www.kernel.org/doc/html/v6.6/admin-guide/sysctl/kernel.html#ns-last-pid): forced reuse test меняет только проверенный отдельный PID namespace, никогда host pid_max/ns_last_pid.
- [iputils ping](https://man7.org/linux/man-pages/man8/ping.8.html), [upstream](https://github.com/iputils/iputils): count/deadline/permissions; фактическая Ubuntu-версия и checksum — evidence.
