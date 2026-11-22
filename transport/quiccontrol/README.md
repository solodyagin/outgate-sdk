# QUIC stream 0 carrier

`quiccontrol` — bootstrap/control часть QUIC adapter на закреплённой `quic-go v0.65.0`. Пакет принимает существующее соединение, выполняет bootstrap/register/ack и удерживает stream 0 для session control. `ClaimHTTP3` передаёт connection для HTTP/3 однократно и с проверкой роли; ordinary HTTP реализован отдельно в [`quichttp`](../quichttp/README.md). Sockets/listener/dial, прикладной `client`, реестр и production authorization интеграция ещё не реализованы. `protocol/v1` сохраняет независимость от транспортных зависимостей.

`Open(ctx, conn, options, credential, register)` вызывается на исходящем service connection; `Accept(ctx, conn, options, authorize)` — на gateway до подключения HTTP/3. Оба вызова требуют завершённого TLS 1.3 handshake с `outgate-tunnel/1`, без 0-RTT. Service всегда требует verified server chain; gateway по умолчанию требует verified client chain. Только явный `Options.Development` разрешает bearer и отсутствие client certificate на gateway. Production grant не подтверждается одним TLS handshake: это обязанность `Authorize`.

Gateway callback получает проверенное TLS state, ограниченный credential и decoded register. Он обязан соблюдать `ctx`, проверить identity/grant/permissions/revocation, конфликты и durable commit до возврата ack. `*Rejection` возвращает проверенный nack; прочие ошибки превращаются в безопасный `state_unavailable`. Credential очищается после callback. Nack предваряет connection close; сеть не гарантирует его получение. При неудаче ack вызывающий gateway исключает session из выбора, сохраняя durable ownership.

Bootstrap ограничен десятью секундами, `RegisterTimeout` может сократить этот срок. Отмена контекста прерывает stream I/O; callback сам отвечает за соблюдение контекста. Контекст регистрации не управляет временем жизни принятой session. После успешного ack вызывающий слой запускает reverse HTTP/3 на том же connection: stream 0 уже потреблён gateway и не попадает в HTTP/3. Service больше не открывает bidirectional streams. Настройки QUIC listener/dialer, включая запрет 0-RTT, keepalive 15s, idle 45s и transport memory budgets, задаёт будущий adapter.

`Carrier.Send` сериализует concurrent writes и применяет меньший из настроенного и согласованного write deadline. В очереди пакета нет накопления сообщений: ожидающие отправители сохраняют данные у себя, поэтому вызывающий слой ограничивает число отправителей и общий budget. `Receive` возвращает типизированные `v1` session messages; у чтения один владелец. Reader удерживает максимум один ограниченный frame до его consumption, далее действует native QUIC flow control. После ack применяется согласованный `max_control_bytes`; сам ack использует исходный wire limit.

Пакет проверяет schema и направления status/drain/ack/unregister/reconnect, запрещает повторную регистрацию и HTTP/WSS messages на carrier. FIN/reset, invalid frame, потеря connection и прерванная запись закрывают всю session, без half-close или retry. `Done` сигнализирует вызывающему слою об исключении session и cleanup; `Close` идемпотентно закрывает connection и дожидается reader. `Err` сохраняет исходную ошибку для диагностики; произвольный текст remote QUIC errors не предназначен для публичного ответа или логирования без redaction.

`Registration()` возвращает независимые копии actual register/ack и bootstrap development profile без credential bytes. `Abort`/`Revoke` закрывают carrier с protocol/security code. Service-side session state/command ledger, readiness callbacks, expiry/recovery и HTTP cleanup подключает отдельный `transport/quicsession`; cleanup реестра остаётся у gateway. Принятый ack не означает готовность или публикацию маршрута. Этот пакет не заявляет завершение этапа 2 или production security.

Проверка из корня SDK:

```bash
GOWORK=off go test -race ./...
GOWORK=off go vet ./...
python3 -B tests/verify_sbom.py
```

Loopback tests используют реальные verified TLS и production mTLS; проверяют reverse HTTP/3 одновременно со status/drain, FIN/reset, bounded backpressure, truncation/overflow, неверные направление/первое сообщение/credential kind, ack negotiation, отказ, concurrent frames и deadlines. Это проверка carrier с тестовыми authorization callbacks, без durable backend. Нативный Windows запуск новых тестов остаётся отдельной проверкой CI.
