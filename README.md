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
- Negotiation capabilities, нормализацию registration prefixes, однократное декодирование route path и segment matching.

`ReadControl`/`WriteControl` проверяют только framing и общий JSON, а не schema всех сообщений. Из control messages типизированы `register`, `register_ack`, `register_nack`, `request_start` и `response_start`. Вызывающий слой отвечает за schema остальных сообщений, направления, session state, лимиты памяти/credit, mTLS/grants/permissions и deadlines. Чтение credentials не является аутентификацией.

`DecodeChunk` возвращает payload, ссылающийся на исходный message buffer. WSS adapter обязан ограничить assembled message до allocation и не переиспользовать buffer до consumption. Wire-лимит chunk не заменяет выданный receiver credit.

Пакет не открывает sockets и не содержит SQL, registry, RBAC или gateway dependencies. Статус реализации и точка продолжения — в [docs/implementation-status.md](docs/implementation-status.md).


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
