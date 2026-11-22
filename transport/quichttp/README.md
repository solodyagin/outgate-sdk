# Ordinary reverse HTTP/3

`quichttp` подключает обычный HTTP к уже зарегистрированному `quiccontrol.Carrier`. `NewGateway` создаёт single-session `http.RoundTripper`, `NewService` — reverse HTTP/3 server с `Serve`/`Close`. Направление сверяется с ролью carrier, а право подключить HTTP/3 выдаётся один раз через `ClaimHTTP3`. Listener/dialer, маршрутизация, readiness, авторизация и прикладной `client` находятся вне этого пакета. Успешный ack не разрешает автоматически направлять запросы.

Gateway принимает request с абсолютным HTTPS URL, сохраняет прикладной Host и исходные escaped path/query. Входящие `x-tunnel-request-id` удаляются без учёта регистра; перед отправкой назначается новый монотонный positive u64. Service проверяет единственность/канонический формат и отсутствие reuse, удаляет ID до verifier/handler. Signed/user headers не создаются этим пакетом: переданный Handler должен включать настоящую authorization/signature middleware. Публичный request ID не является identity.

Существующие metadata helpers `protocol/v1` проверяют ordinary HTTP fields без JSON carrier/serialization overhead. Дополнительно действуют согласованные URI/header/inflight limits; размер expanded HTTP/3 field section включает pseudo headers, transport ID и 32 bytes overhead на field. Header names и повторяемые значения сохраняют HTTP-семантику и порядок значений. Gzip negotiation/decompression отключены. Library `net/http` URL у принимающего handler остаётся origin-form. Request trailers пока отклоняются; CONNECT/application WebSocket/Hijacker ещё не реализованы.

Пакет использует напрямую `http3.ClientConn.RoundTrip`, не `http3.Transport.RoundTrip`: автоматического dial/retry/переназначения нет. Redirect возвращается вызывающему слою без перехода. `GetBody` и `Idempotency-Key` не разрешают повтор после reset или GOAWAY. Вызывающий код также не должен повторять уже начатый business request и не должен включать автоматические redirects/retries поверх adapter.

Request/response bodies потоковые; полная буферизация отсутствует. Request context отменяет QUIC stream и закрывает upload reader. Gateway slot удерживается до окончания обоих направлений; ранний response EOF не освобождает продолжающийся upload. `Response.Body.Close` отменяет остаток exchange. Для body действует контракт net/http: concurrent Close должен разблокировать Read. Handler slots ограничены отдельно на service, в том числе против peer, обходящего gateway admission. Запрос сверх лимита возвращает 503 без вызова handler; автоматического retry нет.

Session-long request IDs хранятся в отсортированных непересекающихся диапазонах: последовательные и reordered contiguous IDs сливаются, завершённые IDs не переиспользуются. Число диапазонов фиксировано при старте и ограничено `min(max_inflight+1, buffer_bytes/64)`, минимум 1. Чрезмерно разреженные IDs исчерпывают этот ledger и закрывают session с quota_exceeded. Это явный bounded resource limit; контролируемое graceful reconnect до исчерпания предстоит реализовать в Client. Native QUIC/HTTP3 buffers, middleware и handlers требуют отдельного общего transport budget; предел ledger не заменяет его измерение.

Stream reset изолирован от других запросов; потеря carrier/connection закрывает все операции. Sessionstate command fences, freshness/security expiry, route selection и durable registration пока не интегрированы. `Service.Close` закрывает connection; handler обязан завершаться при отмене request context. Полноценная приёмка этапа 2, WebSocket и production security этим шагом не заявляются.

Из корня SDK:

```bash
GOWORK=off go test -race ./...
GOWORK=off go vet ./...
GOWORK=off go test ./transport/quichttp -count=30
python3 -B tests/verify_sbom.py
```

Loopback tests используют verified mTLS и реальные HTTP/3 streams: SSE до EOF upload, carrier progress, exact Host/escaped URI/repeated fields, half-close, context cancellation, bounded admission с двух сторон, duplicate/malformed IDs, concurrent requests, reset без повторов GET/HEAD/OPTIONS/POST и отсутствие redirect follow. Authorization callback в этих тестах синтетический.
