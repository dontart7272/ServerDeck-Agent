# E03: доверие и транспорт

Актуальное дополнение E04: snapshot.get/processes.list/get и WSS snapshots реализованы поверх описанных здесь auth guards; [METRICS](METRICS.md) заменяет историческое отсутствие collectors ниже. Права, pairing, audit ordering и отзыв E03 сохранены.

13 октября 2026. Один процесс Agent обслуживает HTTPS/WSS и private Unix admin socket через общий application service E02. Публичная установка не выполнялась: сетевые испытания используют временные БД/ключи и loopback Ubuntu WSL2. Этот этап не добавляет collectors, файловые эффекты, process control, module IPC или установщик.

## Состав реализации

| Файлы | Ответственность |
|---|---|
| `internal/storage/migrations/002.sql`, `auth.go` | Схема2, постоянный agent_id, bounded devices/pairing, проверочные значения, атомарное потребление кода и создание устройства, отзыв и версии |
| `internal/auth/auth.go` | CSPRNG, SHA256/constant-time, одноразовые коды, monotonic TTL, bounded sessions, отмена действующих сессий, наблюдение last_seen не чаще минуты |
| `internal/auth/tls.go`, `files_linux.go` | TLS>=1.2, pin одновременно со стандартными SAN/expiry checks; no-follow чтение конфигурации/сертификата/ключа; SO_PEERCRED |
| `internal/app/gateway.go`, `cancel.go` | Общие audited handlers pairing.issue/devices.pair/devices.revoke/operations.cancel, policy guard, доверенный initiator |
| `internal/app/http.go`, `limiter.go` | HTTPS routes, strict bounded codecs, safe errors, rate/connection guards, отсутствие CORS/URL/cookie credentials |
| `internal/app/websocket.go` | WSS serverdeck.v1, bounded subscriptions/pages, точный ACK, ping/pong, закрытие после отзыва, проверка перед каждым сегментом записи <=64000 bytes |
| `internal/app/query.go`, `internal/storage/transport.go` | Typed info/devices/config/operations/audit, HMAC cursor, scope/epoch/expiry, cursor gap при restore/rotation, snapshot-bound device pagination |
| `internal/app/local.go`, `native_linux.go` | Native startup/preflight, CIDR filtering, private admin socket, CLI adapter, остановка по SIGTERM/SIGINT |
| `internal/storage/cancellation.go`, `internal/operations/service.go` | Повторная авторизация перед intent/running, durable cancellation authority, сериализация/идемпотентность E02 |

Машиночитаемые схемы, embedded snapshots и wire types синхронизированы. В read-only Operation добавлены `pairing.issue`, `storage.backup`, `storage.restore`; этих имён **нет** в разрешённых HTTP PrepareRequest/OperationRequest. В их результатах нет кодов, токенов, путей резервных копий или исходных параметров.

## Pairing и отзыв

CLI выдаёт pairing только владельцу Agent или root, проверенному ОС. Код —16 случайных bytes/base64url22, TTL300с с monotonic deadline и дополнительным UTC запретом, пять неверных попыток. Выдача <=3/min, одновременно <=3 кода. В durable БД только SHA256; исходный код существует в bounded RAM и явно запрошенном SSH/local stdout.

`POST /api/v1/pair` — единственное исключение без bearer. Потребление кода и добавление устройства проходят одну FULL-транзакцию после durable intent/running; token32bytes/base64url43 возвращается после сохранения результата. Утрата ответа требует нового SSH-кода; повтор не возвращает прежний токен и не создаёт второе устройство. Ни исходный токен, ни pairing secret не входят в Operation/audit. До32 активных устройств, последние32 отозванные записи; last_seen — наблюдение, его отказ не превращается в публичный обход авторизации.

Все устройства имеют одинаковые права. Device-инициатор создаётся только из непрозрачного Credential, полученного после проверки bearer; заявленный device_id не является доказательством личности. Отзыв требует плана/expected_version и текущей авторизации перед intent и effect. Commit отзыва предшествует успеху; действующие Session contexts отменяются, WSS закрывается с1008 при доступном close handshake. Разрыв TCP может не доставить close frame. Отзыв не отменяет уже начавшийся необратимый эффект. Повторы прежнего operation_id сверяют инициатора/action/параметры E02.

E03-PAIR-01: concurrent разные pairing-коды с одним request_id не могут заменять pending proof друг друга. Резервируются и code ID, и request ID; возвращённый token соответствует committed device_id. [Детерминированный regression до/после](evidence/E03-wsl-2026-10-13/pairing-collision.txt) использует только отдельную Linux-копию и временную SQLite.

`operations.cancel` также требует собственных plan, intent и running. Контрольная операция может выиграть CAS только до effect; возвращает typed `cancelled`, `too_late` или `unknown`. После начала эффекта отключение клиента/запрос отмены не изображают остановку native работы. Чужой operation_id без durable control authority не открывает внутренний Cancel hook.

## Миграция и восстановление

Миграция001 не изменялась. Миграция002 проверяется checksum и фактическим SQL layout. E02 не выдавал настоящих credentials: старые fixture-записи при миграции деактивируются, не становятся действующими телефонами. Agent identity хранится отдельно от installation_id, IP, hostname, run_id и сертификата. Bootstrap installation_id проверяется против существующего state.

Security floor v2 содержит текущий полный ограниченный реестр проверочных значений активных устройств, agent_id, generation, ограничения политики и ограниченную retired metadata. Это private rollback authority, не публичный API. Restore заменяет registry текущим реестром целиком: удаление старой revoked metadata не разрешает resurrect токен из backup. Копия v1 проверяется и мигрируется в v2 до overlay. Текущие operations/audit/dedup и более строгая политика сохраняются; epoch меняется. Утрата/подмена обязательной authority запрещает запуск/restore.

Pair/revoke обновляют защищённый floor после registry commit, до успеха. Это последовательные durable шаги, не атомарность SQLite и отдельного файла. Если экспорт отказал после commit: `unknown/partial/SAFETY_UNAVAILABLE`, единственное состояние/lock не удаляется, эффект не повторяется; raw token не выдаётся, committed revoke продолжает запрещать доступ. `Health.security_floor_available=false` независимо от возможности записать аудит результата. При старте экспорт обновляется только из проверенной живой authority. Нельзя восстановить всю старую папку безопасности вслепую; installer/update/recovery E11 ещё отсутствует.

Наблюдательная запись last_seen/неудачной попытки не сбрасывает признак отказа аудита. Audit availability восстанавливается успешным commit, действительно содержащим новую запись аудита. После старта WAL принудительно приводится к чистой границе: migration frames не должны блокировать первый intent при долгом reader.

## Транспортные границы

| Параметр | Реализация default-v1 |
|---|---|
| HTTP | HTTPS `/api/v1/`; один настроенный TCP port для JSON/WSS; без TLS нет данных |
| Доверие | TLS1.2 минимум, обычный Go TLS1.3 negotiation; pin SHA256 DER **и** SAN/expiry; нет InsecureSkipVerify |
| Вход | strict UTF8 JSON<=1000000 bytes, existing depth32/4096 members bounds, без compression, unknown fields/duplicate keys отклоняются |
| Заголовки/URI | <=16000 bytes /2048 bytes; Go1.27.2 parser slop4096 учтён MaxHeaderBytes11904, дополнительно проверяется parsed size |
| Тайм-ауты | header5с, HTTP read/write10с, idle60с; WSS write10с, ping30с/pong10с, неподтверждённая страница30с |
| Соединения | <=64 общий Agent, <=8/device; WSS<=16 Agent, <=2/device |
| Частота | device20/s burst40; unauth IP2/s burst5; pairing Agent1/s burst3 и IP1/5s burst3; <=1024 IP identities, expiry10min |
| WSS | Только `serverdeck.v1`, text frames<=1МБ, compression off; <=16 активных subscriptions/connection, <=1 pending page/subscription, суммарно<=4МБ pending; медленный клиент1013 |
| Cursor | HMAC domain separation, Agent/kind/filter/epoch/position/expiry15min, случайный nonce; ACK только точному pending cursor данной subscription/session |
| Origin | По умолчанию непустой Origin отвергается, CORS отсутствует; Android/native empty Origin разрешён |

Реализованные queries: agent.info, config.get, devices.list, operations.list, audit.list. Реализованные WSS topics: operations/storage. Snapshot/events/problems требуют E04/E05 и возвращают SOURCE_UNAVAILABLE; file/UI routes защищены авторизацией и не обслуживают данные до E08/E10. Большие replies не обходят codec bounds. Для audit после ротации coverage.complete=false, неизвестные временные границы не выдумываются. Объявление IPC compatibility в info не является запущенным модульным IPC.

CIDR берётся из bootstrap config и фактического RemoteAddr, не X-Forwarded-For. localhost/LAN-VPN/external не меняют firewall. Создание TLS365-day certificates/ручная rotation, SSH install plan, внешний доступ с предупреждением и systemd lifecycle завершаются в E11; E03 использует уже подготовленные защищённые файлы. Не выдаёт отсутствие collectors за готовый первый снимок/готовую запись телефона.

Каждый listen address открывается явно через tcp4/tcp6: IPv6 listener не добавляет неуказанный IPv4 bind. Native smoke проверяет IPv4 и IPv6 loopback на одном настроенном порту; wildcard/public listening во время испытаний не выполняется.

## Локальные команды

```text
serverdeck-agent serve --config /absolute/bootstrap.json
serverdeckctl pairing-issue --config /absolute/bootstrap.json
serverdeckctl local --config /absolute/bootstrap.json query /absolute/query.json
serverdeckctl local --config /absolute/bootstrap.json prepare /absolute/prepare.json
serverdeckctl local --config /absolute/bootstrap.json execute /absolute/operation.json
```

`serve` не является установщиком: нужны ранее инициализированный private state, runtime directory0700, доступный сертификат/SAN и key0600, соответствующий runtime_user. Публичный запуск во время разработки не выполняется. Занятый порт выдаёт PORT_IN_USE до обслуживания запросов; отсутствие безопасного пути/прав — ограниченный отказ. Существующие settings не заменяются runtime_initial.

`admin.sock`0600 внутри удерживаемого directory FD0700; доверие серверного и клиентского peer проверяется отдельно SO_PEERCRED. Сервер принимает только runtime UID/root. Root может использовать защищённую конфигурацию владельца Agent, если её фактический owner соответствует runtime_user; произвольный SSH-login такого права не получает. Общий UID/root не считаются sandbox-границей. Stale socket удаляется только после owner/type/mode, ECONNREFUSED и повторной проверки inode. Чужой/активный socket не удаляется.

Offline state-init/status/backup/restore/resolve E02 сохраняются, требуют остановленной службы/owner-lock. Нет сетевого raw SQL, shell, emergency audit bypass, backup/restore или TLS private key endpoint. Штатный CLI query/prepare/execute идёт через работающий local service; pairing secret выводится только по явному pairing-issue, не в argv/log/evidence.

## Проверка и ограничения

Команды и фактический результат — [BUILD](BUILD.md), [E03 evidence](evidence/E03-wsl-2026-10-13/README.md), трассировка — [журнал](<../Документация ServerDeck/Документация ServerDeck Agent/11. Журнал проверки требований.md>). Полные AFR/ASEC остаются частично выполненными: Android trust/storage/SSH UX, реальные файловые потоки, collectors, modules, install/update/systemd, обычная host matrix и native ARM — следующие этапы. E04 автоматически не запускается.

Первичные технические источники проверены13 октября: [Go TLS Config](https://pkg.go.dev/crypto/tls#Config), [Go HTTP Server](https://pkg.go.dev/net/http#Server), [закреплённый websocket API](https://pkg.go.dev/github.com/coder/websocket@v1.8.15), [Linux unix/SO_PEERCRED](https://man7.org/linux/man-pages/man7/unix.7.html). Reader context WSS отделён от HTTP request/session cancellation, чтобы дать close handshake; это не отменяет проверки Session перед отправкой. Новая Go-зависимость websocket v1.8.15/ISC, origin/commit/checksums и полный license сохранены; cgo/native libraries прежние. Проверка происхождения не является CVE-аудитом.
