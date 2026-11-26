# Client lifecycle

`New(Config)` проверяет конфигурацию без I/O и goroutines. `Run(ctx)` разрешён один раз; повторный запуск возвращает `ErrAlreadyStarted`, после Close — `ErrClientClosed`. `Status()` и `WaitReady(ctx)` доступны до Run. Status содержит lifecycle state, connected, connected/ready timestamps, transport и безопасный LastErrorCode. WaitReady не запускает соединение и не гарантирует сохранение ready после возврата.

[`Config.QUIC`](quic.md) задаёт встроенные verified dial/registration и credential source; альтернативный `Config.Connect` — явная граница собственного подключения: callback получает deadline, приобретает актуальные credentials, устанавливает verified QUIC connection и выполняет `quiccontrol.Open`. Он возвращает зарегистрированный Carrier и `quicsession.Options` с проверенной security readiness. Callback обязан учитывать ctx и освобождать ресурсы при ошибке; nonnil carrier передаётся Client даже вместе с ошибкой. Вызов только один, вне mutex. Timeout/Close не создают новый вызов, пока старый фактически не вернулся. Panic становится безопасной terminal error без публикации текста.

Production включён по умолчанию. Client требует совпадения actual carrier development profile с Config.Development; fallback отсутствует. При reconnect register должен совпадать после canonical JSON serialization, включая identity/paths/options; разрешено только неизменное либо возрастающее credential_generation. Новая версия/registration требует нового Client; credential bytes в эту проверку не входят. Повтор предыдущего session ID запрещён. Security readiness по умолчанию false; `SetSecurity` меняет проверенный gate/deadline текущей session, `Revoke` немедленно прекращает работу и подавляет reconnect, в том числе при Connect/cleanup/backoff.

После регистрации Client запускает `quicsession.Service`. Handler должен включать authorization/signature middleware. Readiness/barrier/expiry и actual cleanup принадлежат service driver. Client отслеживает состояние с интервалом 10ms; Status дополнительно читает актуальный snapshot. Callback/handler не является дочерним контекстом Run: отмена Run сначала запрашивает graceful drain.

`Close(ctx)` объединяет concurrent shutdown, самый ранний deadline ограничивает процедуру, без deadline применяется 30s. Close до Run сразу закрывает Client. Повторные Close не продлевают drain. Истечение ожидания отменяет transport; Done остаётся открытым до actual handler/callback/connector cleanup. Run при штатном final drain возвращает nil, при принудительном shutdown — typed error с code shutdown_timeout, совместимую с errors.Is(context.DeadlineExceeded). Errors показывают только code; Unwrap предназначен для внутренней диагностики, поскольку underlying error может содержать secrets/peer text.

Reconnect выполняется только после полного cleanup старой session. Validated rotation hint и ограниченный набор временных connection errors допускают новую попытку. Unknown errors, protocol/security failures, отказ аутентификации и неподдерживаемый протокол terminal; retryable nack обрабатывается только для duplicate_instance/state_unavailable/server_shutdown/quota_exceeded. Exponential backoff с equal jitter по умолчанию 250ms…30s, сбрасывается после наблюдавшегося ready. Переподключение никогда не переносит и не повторяет business requests. Production `Config.QUIC` подключает [proactive credential renewal](quic.md): локально проверяет новую пару во время работы старой, затем выполняет bounded drain/actual cleanup и регистрацию закреплённого нового поколения. Ошибка/timeout provider сохраняет рабочую пару до expiry, final local/peer shutdown и revoke подавляют rotation.

Это первый public lifecycle API, не завершённый прикладной SDK. Встроенный QUIC dialer и static/callback/file credential source реализованы; входящий user middleware/JWKS loader, HTTP panic middleware, internal CONNECT/WebSocket/Hijacker и production durable security integration остаются в работе. Connect — внешняя реализация этих admission/transport checks, не фиктивная identity и не production backend.

Обычный фоновый [`ServiceHTTPClient`](service_http.md) подписывает HTTPS calls с mTLS/accepted credentials, readiness gate, streaming и без business replay. Логический [NewServiceRequest/discovery](discovery.md) добавляет bounded mount cache и signed route revision. User delegation и Upgrade ещё не подключены.

Проверки из корня SDK:

```bash
GOWORK=off go test -race ./...
GOWORK=off go test -race ./client -count=20
GOWORK=off go vet ./...
```

Tests используют actual verified mTLS/QUIC carriers: single Run, WaitReady, concurrent/earliest-deadline Close, отмена Run, connector ownership, rotation и transport reconnect, cleanup старого callback, fresh session IDs, immutable registration identity, development downgrade и security recovery/revoke. Admission callbacks синтетические.

Исходящие пользовательские вызовы через WithUserContext/WithUserAssertion и обязательный security callback описаны в [user.md](user.md). Проверенный user-call lease ограничен 30s без продления; это ограниченный профиль, не полный revocation runtime.
