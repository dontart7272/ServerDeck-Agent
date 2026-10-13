# Проверка API ServerDeck Agent

13 октября 2026 года. Навык `api-audit`, методика [OWASP API Security Top 10 (2023)](https://api-security.owasp.org/editions/2023/en/0x11-t10/). Проверены текущие API/IPC-схемы и генератор, codec, конфигурационный валидатор, entry points и требования ASEC-004–012/014/021/022/028/029.

**Итог после исправления: API-R01 и API-R02 закрыты в существующем offline codec/контрактах и проверены на Windows 13 октября 2026 года.** Исходные потенциальные риски имели среднюю серьёзность для будущей службы, информационную для E01. Подтверждённых эксплуатируемых сетевых уязвимостей не установлено. Рабочих HTTP/WSS/IPC listeners и обработчиков нет: отсутствие авторизации в offline codec не означает публичный обход авторизации. Это аудит существующей подготовки API, не пентест работающего сервера.

Модель доступа: один Agent/сервер, все сопряжённые телефоны равноправны; отдельные отзываемые bearer tokens. Чтение безопасного результата операции другого телефона предусмотрено требованиями и само по себе не является BOLA. Transfer ticket, инициатор операции, разрешённые файловые корни и политика модулей требуют собственных проверок поверх токена.

## API-R01 — WSS-контракт не разделяет направления и часть типов

**API3/API4/API10; CWE-20. Статус: Fixed для контрактов и stateless codec.** Раздел ниже описывает исходное состояние; сетевого обработчика и stateful session guards ещё нет.

Поверхность: `GET /api/v1/stream`, сообщения `subscribe`/`changes`. Источники: [генератор:309](../Документация%20ServerDeck/Документация%20ServerDeck%20Agent/tools/build-contracts.py#L309), [embedded schema:14715](internal/contracts/schemas/api.schema.json#L14715), [Validate:96](internal/contracts/schema.go#L96).

До исправления `WssMessage` объединяла сообщения клиента и сервера; `subscriptions[].params` — любой ограниченный JsonValue, а `changes.data[]` выбирает тип независимо от `topic`. Нет семантической проверки уникальности subscription ID. Через CLI воспроизведены четыре принятия: `snapshot` с `params:true`; две подписки с одинаковым `id`; серверный `heartbeat` той же схемой; запись storage при `topic:"events"`. Само принятие серверного сообщения общей схемой корректно для union, но эта схема не защищает входное направление соединения.

Минимальный вход, принимавшийся `check-contract api WssMessage` до исправления:

```json
{"schema_version":"1.0","request_id":"11111111-1111-4111-8111-111111111111","type":"subscribe","subscriptions":[{"id":"s","topic":"snapshot","params":true}]}
```

**Риск:** если будущий dispatcher сочтёт эту проверку достаточной, возможны путаница состояний/типов, замена подписок или ошибки обработки. Падение службы, утечка и обход полномочий не доказаны. Размер/глубина/число подписок уже ограничены; речь не об отсутствии этих лимитов.

**Рекомендация:** отдельные client/server definitions; параметры по discriminant `topic`, уникальные ID; `changes` с типом data, связанным с topic. В обработчике — проверка принадлежности подписки соединению, соответствия ack реально отправленной странице и действующей авторизации. Это согласуется с [OWASP WebSocket Security](https://cheatsheetseries.owasp.org/cheatsheets/WebSocket_Security_Cheat_Sheet.html), требующим проверки сообщений и полномочий сверх handshake.

**Проверка исправления:** невалидные params/повтор ID/несоответствие topic-data должны отклоняться codec; server-only type на входе клиента — транспортом или выбранной client-схемой. Чужой/неотправленный ack не должен менять состояние. Сетевые сценарии сейчас NOT RUN.

## API-R02 — `config.set` проходит только структурную проверку

**API4/API8; CWE-20. Статус: Fixed для общей pure semantics и merge helper.** Раздел ниже описывает исходное состояние; application guard версии/прав/аудита остаётся обязательным до запуска изменяющего API. Изменение сервера не выполнялось.

Поверхность: `POST /api/v1/prepare`, `POST /api/v1/operations`, action `config.set`. Текущая реализация: [Validate](internal/contracts/schema.go), [общий Runtime validator](internal/contracts/runtime.go), [локальная конфигурация](internal/config/config.go).

До исправления API codec не вызывал проверку Runtime-конфигурации. JSON Schema сама по себе пропускает `changes.icmp={"target":"-c","background_enabled":true}` и в PrepareRequest, и в OperationRequest; тот же фрагмент в bootstrap отклоняется `validate-config` как `INVALID_INPUT`. CLI честно сообщает, что проверяет форму, поэтому это доказанная разница валидаторов, а не подтверждённая уязвимость исполняющего API.

**Риск:** применение прошедшего только schema-check patch без объединения с текущими настройками и семантической проверки позволит сохранить недопустимую конфигурацию. При небезопасном будущем запуске ping значение с `-` может интерпретироваться как опция; существующего запуска ping, shell-инъекции или SSRF в коде нет. Частные IP разрешены требованиями и не должны запрещаться автоматически.

**Рекомендация:** общий semantic validator для HTTP/CLI/import; patch объединять с актуальной revision и проверять итог целиком при prepare и повторно перед guarded commit. Проверять цель ICMP, clean absolute roots/дубликаты, edit≤full_text, background без target. OS-права/путь/защита собственных объектов проверяются отдельно. Ping — без shell, с безопасной передачей аргументов.

**Проверка исправления:** невалидные цели и конфликтующие поля отклоняются до intent/effect; устаревшая revision даёт конфликт, корректные IP/домены принимаются. Offline-пример — [prepare-icmp-flag.json](evidence/api-audit-2026-10-13/prepare-icmp-flag.json). Заглушечный plan_id в execute-пробе не проверяет подлинность плана.

## Инвентаризация маршрутов

У всех строк статус **N/A для runtime-аудита: handler отсутствует**; ниже результат проверки контракта, а не заключение «endpoint безопасен».

| Маршрут | Проверенный контракт / оставшаяся проверка реализации |
|---|---|
| POST `/api/v1/pair` | Единственное исключение без токена; 128-bit code, TTL/попытки, атомарное потребление; replay/race ещё не испытаны |
| POST `/api/v1/query` | 22 именованных чтения, discriminator/unknown fields; авторизация, root policy и HMAC cursors ещё не реализованы |
| POST `/api/v1/prepare` | 21 action; API-R02; будущий plan должен связывать инициатора, operation_id, смысл/версии и TTL |
| POST `/api/v1/operations` | 21 action; API-R02; audit-before-effect, dedup/locks/revocation ещё не испытаны |
| GET `/api/v1/operations/{operation_id}` | Токен обязателен; равноправное чтение безопасного результата предусмотрено, не исполнение чужого ID |
| PUT `/api/v1/transfers/{transfer_id}/content` | Device-bound ticket, длина/digest/quota; повтор PUT, отзыв и гонки требуют runtime-проверки |
| GET `/api/v1/transfers/{transfer_id}/content` | Ticket и версия, авторизация порциями; чужой ticket/изменение файла не испытаны |
| GET `/api/v1/ui/{package_digest}` | Только объявленный пакет; токен и stream bounds; отдельное доверие подписи на клиенте |
| GET `/api/v1/stream` | API-R01; TLS/token/Origin до upgrade, отзыв и квоты сообщений требуют реализации |

Полный список 22 queries, 21 actions, 11 IPC methods и 8 WSS types — [inventory.json](evidence/api-audit-2026-10-13/inventory.json). IPC: `hello`, `collect`, `read`, `operation.prepare`, `operation.execute`, `operation.report`, `operation.reconcile`, `operation.cancel`, `event.publish`, `heartbeat`, `shutdown` — для каждого **N/A runtime**, проверены discriminated формы; handshake/регистрация/разрешённое направление и capabilities не реализованы. `ReadResponse` связывает ID и локально выбранный тип результата, но не заменяет доверие peer. GraphQL, webhooks, REST install/shell/sudo, старые live API major не обнаружены.

## Покрытие OWASP API Top 10

| Категория | Итог |
|---|---|
| API1 BOLA | Проверены требования к ticket/root/object/operation; runtime N/A, эксплуатация не доказана |
| API2 Authentication | Секреты не в URL/cookie/subprotocol, token hash/отзыв заданы; реализация и активные потоки не испытаны |
| API3 Property authorization | Unknown fields/runtime-only patch ограничены схемой; API-R01, проверки DTO/redaction в handlers отсутствуют |
| API4 Resource consumption | JSON/frame/depth/page bounds есть; API-R01/R02, реальные rate limits/slow-client/fragmented WSS не испытаны |
| API5 Function authorization | Список actions закрыт, локальные install/register/system actions не разрешены HTTP schema; dispatcher N/A |
| API6 Sensitive flows | Pairing/prepare/revoke/purge: лимиты и подтверждение заданы; атомарность/race/replay не испытаны |
| API7 SSRF | Runtime HTTP fetch отсутствует; внешний LoadURL запрещён. ICMP ограничен отдельным соглашением, API-R02 |
| API8 Misconfiguration | API-R02; CORS выключен по умолчанию, TLS/Content-Type/deadlines только специфицированы |
| API9 Inventory | 9 маршрутов сверены, полный machine inventory сохранён; скрытых runtime routes не найдено |
| API10 Unsafe consumption | API-R01; IPC result ID/type проверяются, schema/peer/policy модульных данных требуют E09 |

## Воспроизводимость и границы

Первичный аудит сохранил [восемь исходных проб](evidence/api-audit-2026-10-13/results.txt): шесть допусков формы и два контрольных отказа. Текущая команда из корня `python agent/evidence/api-audit-2026-10-13/reproduce.py` выполняет уже десять проб исправленного CLI; результаты и ожидаемое поведение приведены ниже. Сетевые запросы не выполняются.

Из `agent/` с окружением из BUILD.md: `../.tools/go/bin/go.exe test ./internal/contracts ./internal/config ./internal/app -count=1` — PASS на Windows/cgo. Тесты включают предыдущий SD-SEC-001 fix. Повторный проход не нашёл оснований объявлять подтверждёнными BOLA, SSRF, command injection или массовое назначение прав. Первичный аудит не менял рабочий код. Последующее исправление по прямому запросу пользователя синхронизировало код, генератор, схемы, Go-типы, примеры и нормативные уточнения; исходные evidence сохранены.

Остаётся: реализовать и испытать session/auth/version/audit guards в своих этапах, затем провести авторизованные тесты реальных HTTP/WSS/IPC на изолированном Linux. Отдельные открытые gates — BLOCK-FS, Linux/cgo, CVE/native dependencies, подписи и восстановление. Этот отчёт не закрывает их.


## Выполненное исправление и фактические проверки

- `WssClientMessage` принимает только subscribe/ack, `WssServerMessage` — только сообщения сервера. Aggregate `WssMessage` запрещена как target Go Validate/Decode/Encode. Параметры подписки типизированы по topic, ID уникальны в сообщении; snapshot не принимает after. `changes.data` связан с topic. Точные params и оставшиеся session checks описаны в разделе 7 API.
- `RuntimeConfig.Validate` общий для bootstrap, Runtime, ConfigChanges и config.set prepare/execute. Проверяются ICMP, фон без цели, clean absolute roots/дубликаты и edit≤full_text. `ApplyRuntimeChanges` проверяет полный текущий snapshot, patch и merged result; исходный snapshot не изменяется, OS preflight/commit не выполняются.
- Добавлены `TestWssDirectionAndTopics`, `TestRuntimeAPISharedSemantics`, `TestApplyRuntimeChanges`, два WSS documentation examples. Положительные проверки включают каждую тему changes, допустимые IP/домены и сохранение незатронутых групп; негативные — направления, params/ID/темы, 17 подписок, неверные цели/корни и неполные группы.
- [После исправления](evidence/api-audit-2026-10-13/results-fixed.txt): восемь опасных/контрольных входов отклонены, два корректных WSS сообщения приняты. [Исходные результаты](evidence/api-audit-2026-10-13/results.txt) не перезаписаны. Скрипт reproduce.py теперь проверяет ожидаемое исправленное поведение, inventory-fixed.json содержит текущую карту.
- Windows/cgo: mod verify, vet, полные обычные и race-тесты прошли; [tests](evidence/api-audit-2026-10-13/tests-fixed.txt), [race](evidence/api-audit-2026-10-13/race-fixed.txt). Документальная проверка: 6 schemas, 178 definitions, 13 valid examples, 15 negative fixtures; это не runtime evidence службы.

Повторный разбор: новая направленная схема не заменяет session ownership/ack/revocation; merge helper не заменяет проверку актуальной revision и intent-before-effect. Эти механизмы ещё не реализованы, их безопасность не объявляется проверенной. Linux gate и CVE-check остаются открытыми.

## Дополнение: Linux-проверки после исходного аудита

13 октября 2026 исправления API-R01/API-R02 вошли без изменений в успешные vet/test/race на Ubuntu22.04.5 WSL2 amd64 с Go1.27.2/cgo1/GCC11.4.0. [Linux evidence](evidence/E01-wsl-2026-10-13/README.md), [основной test/race лог](evidence/E01-wsl-2026-10-13/linux-checks.txt). Windows audit evidence выше остаётся историческим. Проверены существующие codec/pure semantics; работающие HTTP/WSS endpoints, session ownership/revocation, audit ordering и native ARM этим дополнением не подтверждаются.
