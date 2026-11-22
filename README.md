# Outgate SDK: начало реализации

Самостоятельный модуль `github.com/solodyagin/outgate-sdk`: [solodyagin/outgate-sdk](https://github.com/solodyagin/outgate-sdk). QUIC adapter включает bootstrap, stream 0 carrier и обычный streaming HTTP/3. Прикладной `client`, WebSocket/Hijacker, полный lifecycle, WSS adapter и versioned release ещё отсутствуют.

`protocol/v1` предоставляет:

- `U64`: JSON decimal string с проверкой канонической записи и overflow.
- QUIC bootstrap `Outgate1` и length-prefixed control frames с ограничениями до выделения буфера.
- Encode/decode WSS binary chunks с 16-byte header и непрозрачным payload.
- `ValidateControlJSON`: ограниченный JSON object, UTF-8, глубина, duplicate keys, surrogate pairs.
- `DecodeRegister`: обязательные/неизвестные/null поля, wire- и семантические ограничения регистрации.
- Строгие `DecodeRegisterAck`/`DecodeRegisterNack`, semantic validation и сверку ack с исходным register.
- Строгие `DecodeRequestStart`/`DecodeResponseStart`: ordered headers, HTTP tokens, escaped URI, Host, Content-Length и запрет ordinary hop-by-hop полей.
- Строгие `DecodeRequestEnd`/`DecodeResponseEnd`, `DecodeWindowUpdate`, `DecodeCancel`/`DecodeCancelAck`: поля EOF, credit и отмены без проверки stream state.
- Строгие `DecodeWebSocketOpen`/`DecodeWebSocketOpenAck`/`DecodeWebSocketEnd`: metadata с сохранением handshake headers, initial credit и directional EOF без channel state.
- Строгие `DecodeInstanceStatus`, `DecodeDrain`/`DecodeDrainAck`, `DecodeUnregister`/`DecodeUnregisterAck`, `DecodeReconnect`: readiness fields, command IDs/deadlines и acknowledgement без session state.
- Negotiation capabilities, нормализацию registration prefixes, однократное декодирование route path и segment matching.

`ReadControl`/`WriteControl` проверяют только framing и общий JSON, а не schema всех сообщений. Все 19 control messages имеют типизированные codecs и Validate: register/ack/nack; request/response start/end; window_update; cancel/ack; websocket_open/open_ack/end; instance_status; drain/ack; unregister/ack; reconnect. Вызывающий слой выбирает codec по type и отвечает за направления, session state, лимиты памяти/credit, mTLS/grants/permissions и deadlines. Stream codecs не проверяют накопление/overflow credit, резервирование budget, соответствие bytes_sent chunks/Content-Length, монотонность cancel IDs, соответствие ack ledger или порядок EOF/cancel. Чтение credentials не является аутентификацией.

`DecodeChunk` возвращает payload, ссылающийся на исходный message buffer. WSS adapter обязан ограничить assembled message до allocation и не переиспользовать buffer до consumption. Wire-лимит chunk не заменяет выданный receiver credit.

Пакеты `protocol/v1`, `wssstate`, `sessionstate` и `httpsig` не открывают sockets и не содержат SQL, registry, RBAC или gateway dependencies.

Session codecs проверяют положительные u64 sequence/command_id, observed_at 0…253402300799, boolean ready, закрытый status code enum, deadline_ms 1…30000 и формат command code. Они не проверяют рост sequence, freshness/security readiness, уникальность command_id, соответствие ack, starts fence или действующий deadline; для этого нужна session state machine. Команды не выполняют I/O и не запускают reconnect.

## HTTP/WebSocket state machine WSS

Отдельный пакет [`wssstate`](wssstate/README.md) проверяет HTTP и WebSocket channel start/body/end с общими ID/budget, отказом до open_ack, credit и локальные receive reservations, Content-Length, HEAD/204/304, ранний ответ, независимые EOF с handshake bytes и cancel/ack races. Inner HTTP handshake и его metadata проверяет будущий adapter. Пакет `protocol/v1` остаётся stateless. State machine применяется после регистрации и не является transport adapter.

`New(Config)` принимает роль, согласованные limits, cancel-ack deadline и предел ledger. `Apply(sender, message, now)` принимает значения wire messages/chunks; `Consume` отмечает фактическую downstream-доставку. `CheckTimeout` вызывается таймером даже без входящих frames. `Effect` задаёт discard, остановку scope, ack и освобождение stream. Все вызовы сериализует один владелец.

Отдельная [`sessionstate`](sessionstate/README.md) связывает регистрацию, readiness/status freshness, callback thresholds и один outstanding callback, drain/ack fences, unregister и bounded reconnect с HTTP/WS state. Время и проверенную security readiness передаёт вызывающий слой; модель не выполняет I/O, callbacks или durable registration. Транспортные очереди, фактический cleanup и thread-safe прикладной `client` ещё не реализованы. Fixed charges внутреннего состояния не заменяют измерение памяти будущего адаптера.

Для QUIC режим `NativeStreams` учитывает concurrency непрозрачными leases, без WSS credit/framing. Завершение обоих направлений сообщает `quichttp.RoundTripWithCompletion`; cleanup и повторное Begin блокируются до возврата старых leases. Сериализацию native starts относительно control drain/fence должен обеспечить adapter отдельно.

Wire minor 1 добавляет optional required-by-negotiation capability `quic_quiescent_fence`: frozen logical request-ID watermark передаётся только после остановки G admission и completion обоих направлений. `Gateway.Pause`/`Service.Quiesce` обеспечивают HTTP admission/cleanup primitives; sessionstate проверяет marker/negotiation/quiescence. Minor-0 fixtures/ALPN/bootstrap bytes сохраняются. Service-side control driver/прикладной Client остаётся отдельной интеграцией.

## HTTP signatures и replay interface

Пакет [`httpsig`](httpsig/README.md) реализует фиксированный Outgate RFC 9421 HMAC-SHA256 профиль: два legs, exact component coverage/order, bounded Structured Fields/HTTP metadata/context, nonce generation и временное окно. Все 4 существующих signature vectors проверяются на Go без изменения corpus. Scheme задаётся явно; authority нормализуется по RFC, исходный публичный URI и query сохраняются. Body API не принимает и не читает.

Production включён по умолчанию. Sign возвращает signature headers; Verify подтверждает только profile/HMAC/time и не создаёт trusted user context. После внешних transport/grant/JWT/route/delegation/revision/instance checks отдельный Verified.Reserve атомарно резервирует nonce через ReplayStore перед dispatch. Durable SQL backend/recovery, JWT/context semantic equality, HTTP adapters и production security integration ещё не реализованы; volatile fallback отсутствует.

## QUIC bootstrap

[`transport/quiccontrol`](transport/quiccontrol/README.md) выполняет register/ack на stream 0 существующего quic-go connection с verified TLS 1.3, production mTLS, явным development mode и ограниченными deadlines. Gateway authorization/durable commit передаются обязательным callback. Carrier сериализует записи, ограничивает read-ahead, проверяет schema/направления session messages и закрывает connection при FIN/reset/ошибке. `ClaimHTTP3` однократно передаёт connection транспортному слою с проверкой роли.

[`transport/quichttp`](transport/quichttp/README.md) подключает ordinary reverse HTTP/3: single-session RoundTripper и service server, transport request IDs, bounded admission, streaming/SSE, независимые EOF и cancellation. Native `ClientConn.RoundTrip` используется без автоматических retry/dial/redirect. Authorization/signature middleware предоставляет вызывающий слой. Listener/dialer, WebSocket/Hijacker, sessionstate/registry integration и прикладной Client остаются в работе.

## Проверка

Нужны Go 1.27.4 и Python 3.12+. QUIC carrier добавляет закреплённые [dependencies, лицензии и SBOM](docs/dependencies.md). Первичная загрузка требует сети; после заполнения module cache можно задать `GOPROXY=off`. Четыре пакета без transport сохраняют standard-library-only граф. Gateway checkout не нужен: тесты используют локальные schema/fixtures ([происхождение snapshot](docs/contract-snapshot.md)).

Из корня SDK, Linux:

```bash
python3 tests/fixtures/protocol/v1/verify.py
GOWORK=off go test -race ./...
GOWORK=off go vet ./...
python3 -B tests/verify_sbom.py
```

Windows PowerShell:

```powershell
python tests/fixtures/protocol/v1/verify.py
$env:GOWORK = 'off'
go test ./...
go vet ./...
python -B tests/verify_sbom.py
```

Фаззинг из корня SDK:

```bash
GOWORK=off GOPROXY=off go test ./protocol/v1 -run='^$' -fuzz=FuzzDecodeChunk -fuzztime=10s
GOWORK=off GOPROXY=off go test ./protocol/v1 -run='^$' -fuzz=FuzzControlJSON -fuzztime=10s
```

CI выполняет Go tests/vet и fixture verifier на Linux/Windows, race на Linux. Наличие workflow не означает выполненную platform acceptance.
