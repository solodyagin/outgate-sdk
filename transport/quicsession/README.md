# Service-side QUIC lifecycle

`NewService(carrier, handler, Options)` запускает control reader/writer, reverse HTTP/3 server и readiness timer на уже зарегистрированном service-side carrier. Он использует независимые копии **фактических** register/ack из bootstrap, включая expiry, barrier, limits и development profile. Caller не передаёт подменяемый ack. Требуется negotiated minor-1 `quic_quiescent_fence`; отсутствие capability возвращает ошибку без fallback.

Это transport driver; public `client.Client` подключает Run/WaitReady/Close и sequential reconnect через explicit Connect callback. Встроенные dial/credential acquisition, WebSocket/Hijacker и service-to-service HTTP client остаются в работе. `NewService` сразу запускает goroutines; его контракт отличается от будущего `client.New`. Carrier/control reader и HTTP attachment передаются одному владельцу.

`SecurityReady` по умолчанию false. Проверенную локальную security readiness устанавливают options или `SetSecurity`; абсолютный deadline может только сокращаться. Handler должен включать настоящие signature/authorization checks. Driver не проверяет grant/revocation stores и не создаёт identity. До первого ready status и при security recovery handler не вызывается; отклонённый запрос получает 503 без retry. Уже назначенные G запросы при временной потере callback readiness допускаются согласно sessionstate, пока нет security failure/fence.

`ReadinessCheck` должен точно соответствовать `readiness_check_configured` исходной регистрации. Callback выполняется вне mutex с согласованным timeout и success/failure thresholds. Timeout немедленно снимает ready; зависший callback удерживает единственный слот, новые goroutines не накапливаются. Panic считается неуспешной пробой, его текст не публикуется. Late success не превращает timed-out sample в успешную проверку. Status отправляется сразу после запуска, периодически и при изменении ready; sequence и expiry/barrier контролируются sessionstate.

`Drain(ctx)` — окончательный graceful shutdown: S отправляет drain, G прекращает назначения и возвращает quiescent fence. Для G-origin drain сначала отправляется drain_ack. Reader продолжает обрабатывать встречные команды, пока реальные handlers завершаются. Перед unregister driver ждёт fence, оба drain acknowledgements, отсутствие active handlers/native leases и фактический выход readiness callback. Unregister — последний S frame: ожидание terminal ack не запускает новых periodic status writes, которые могли бы прерваться при закрытии. После корректного unregister_ack соединение закрывается Outgate normal. Deadlines не продлеваются; expiry/revoke имеют приоритет.

`Close(ctx)` немедленно отменяет соединение. `Done` закрывается после выхода reader/writer/timer/HTTP server, callbacks и actual handlers. Если пользовательский код игнорирует cancellation, bounded Close возвращает ctx.Err, а Done остаётся открытым до реального освобождения ресурсов. `Snapshot` потокобезопасен; это состояние транспорта, не обещание готовности production runtime. `Err` предназначен для внутренней диагностики: произвольный текст remote QUIC errors требует redaction перед публичным ответом/логированием.

`ReconnectRequested()` становится true только после validated rotation unregister_ack и полного cleanup. Это hint владельцу на создание новой сессии, без автоматического dial и без переноса business requests. Drain/Close/Revoke подавляют reconnect, в том числе после terminal ack.

Из корня SDK:

```bash
GOWORK=off go test -race ./...
GOWORK=off go test -race ./transport/quicsession -count=20
GOWORK=off go vet ./...
```

Loopback tests используют verified mTLS и native QUIC/HTTP3: fail-closed readiness, immutable bootstrap snapshots, G/S/crossed drain, rotation/final intent, callback timeout/panic/thresholds, late success, cancellation-ignoring callback/handler, expiry и invalid command ledger/fences. Тестовые authorization callbacks не подтверждают production admission.

`PeerShutdownRequested()` сохраняет validated final gateway drain (code кроме credential_rotation), в том числе после actual cleanup. Владелец, подготовивший локальную credential rotation, проверяет этот final intent перед новым dial; crossed peer shutdown не превращается в reconnect. Public Client использует этот сигнал для приоритета gateway shutdown над proactive renewal.
