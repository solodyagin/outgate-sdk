# Outgate SDK: начало реализации

Самостоятельный модуль `github.com/solodyagin/outgate-sdk`: [solodyagin/outgate-sdk](https://github.com/solodyagin/outgate-sdk). Прикладной `outgateclient`, transport adapters и versioned release ещё отсутствуют.

`protocol/v1` предоставляет:

- `U64`: JSON decimal string с проверкой канонической записи и overflow.
- QUIC bootstrap `Outgate1` и length-prefixed control frames с ограничениями до выделения буфера.
- Encode/decode WSS binary chunks с 16-byte header и непрозрачным payload.
- `ValidateControlJSON`: ограниченный JSON object, UTF-8, глубина, duplicate keys, surrogate pairs.
- `DecodeRegister`: обязательные/неизвестные/null поля, wire- и семантические ограничения регистрации.
- Строгие `DecodeRegisterAck`/`DecodeRegisterNack`, semantic validation и сверку ack с исходным register.
- Строгие `DecodeRequestStart`/`DecodeResponseStart`: ordered headers, HTTP tokens, escaped URI, Host, Content-Length и запрет ordinary hop-by-hop полей.
- Строгие `DecodeRequestEnd`/`DecodeResponseEnd`, `DecodeWindowUpdate`, `DecodeCancel`/`DecodeCancelAck`: поля EOF, credit и отмены без проверки stream state.
- Negotiation capabilities, нормализацию registration prefixes, однократное декодирование route path и segment matching.

`ReadControl`/`WriteControl` проверяют только framing и общий JSON, а не schema всех сообщений. Из 19 control messages типизированы 10: `register`, `register_ack`, `register_nack`, `request_start`, `response_start`, `request_end`, `response_end`, `window_update`, `cancel` и `cancel_ack`. Вызывающий слой отвечает за schema остальных сообщений, направления, session state, лимиты памяти/credit, mTLS/grants/permissions и deadlines. Stream codecs не проверяют накопление/overflow credit, резервирование budget, соответствие bytes_sent chunks/Content-Length, монотонность cancel IDs, соответствие ack ledger или порядок EOF/cancel. Чтение credentials не является аутентификацией.

`DecodeChunk` возвращает payload, ссылающийся на исходный message buffer. WSS adapter обязан ограничить assembled message до allocation и не переиспользовать buffer до consumption. Wire-лимит chunk не заменяет выданный receiver credit.

Пакеты не открывают sockets и не содержат SQL, registry, RBAC или gateway dependencies.

## HTTP state machine WSS

Отдельный пакет [`wssstate`](wssstate/README.md) проверяет ordinary HTTP start/body/end, credit и локальные receive reservations, Content-Length, HEAD/204/304, ранний ответ и cancel/ack races. Пакет `protocol/v1` остаётся stateless. State machine применяется после регистрации и не является transport adapter.

`New(Config)` принимает роль, согласованные limits, cancel-ack deadline и предел ledger. `Apply(sender, message, now)` принимает значения wire messages/chunks; `Consume` отмечает фактическую downstream-доставку. `CheckTimeout` вызывается таймером даже без входящих frames. `Effect` задаёт discard, остановку scope, ack и освобождение stream. Все вызовы сериализует один владелец.

Пока поддерживаются только HTTP streams: WebSocket channels, общая session state machine (registration/readiness/drain/reconnect), транспортные очереди и callbacks ещё не реализованы. На mixed HTTP/WebSocket session helper применять нельзя до общего watermark/budget. Fixed charges внутреннего состояния не заменяют измерение памяти будущего адаптера.


## Проверка

Нужны Go 1.27.4 и Python 3.12+. Внешних Go dependencies нет; `go.sum` не требуется. Gateway checkout не нужен: тесты используют локальные schema/fixtures ([происхождение snapshot](docs/contract-snapshot.md)).

Из корня SDK, Linux:

```bash
python3 tests/fixtures/protocol/v1/verify.py
GOWORK=off GOPROXY=off go test -race ./...
GOWORK=off GOPROXY=off go vet ./...
```

Windows PowerShell:

```powershell
python tests/fixtures/protocol/v1/verify.py
$env:GOWORK = 'off'
$env:GOPROXY = 'off'
go test ./...
go vet ./...
```

Фаззинг из корня SDK:

```bash
GOWORK=off GOPROXY=off go test ./protocol/v1 -run='^$' -fuzz=FuzzDecodeChunk -fuzztime=10s
GOWORK=off GOPROXY=off go test ./protocol/v1 -run='^$' -fuzz=FuzzControlJSON -fuzztime=10s
```

CI выполняет Go tests/vet и fixture verifier на Linux/Windows, race на Linux. Наличие workflow не означает выполненную platform acceptance.
