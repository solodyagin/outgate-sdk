# Логический адрес сервиса

`Client.NewServiceRequest(ctx, gatewayURL, method, targetService, mountID, localRequestURI, body)` разрешает activated mount через service-listener discovery и возвращает обычный `*http.Request`. Helper не читает body, не вызывает business handler и не повторяет бизнес-операции. Отправка — отдельный `ServiceHTTPClient.Do`.

```go
serviceHTTP, err := c.ServiceHTTPClient(gatewayOrigin)
req, err := c.NewServiceRequest(ctx, gatewayOrigin, "POST",
    "reports-service", "api", "/reports?format=csv", streamingBody)
// Обработайте err; только затем явно отправьте req.
resp, err := serviceHTTP.Do(req)
```

Настройка Config.ServiceHTTP/Config.QUIC, explicit HTTPS roots/signing key и Ready gate совпадают с [обычным client](service_http.md). Constructor не делает discovery I/O; NewServiceRequest делает GET только при cache miss. Target/mount/method/local URI проверяются до сети. Local URI — origin-form от `/`, без fragment, dot segments, decoded separators или `//`. Prefix добавляется один раз, без path.Clean/повторного path decode, query не сортируется/не пересериализуется. Root mount не добавляет slash; `/api` + `/` даёт `/api/`. Escaped Unicode и признак пустого query сохраняются. Префикс с Unicode безопасно экранируется при построении публичного URL. Результат получает WithTargetService и X-Outgate-Expected-Route-Revision, покрываемый outgatecall при отправке.

Discovery v1 использует `GET /outgate/discovery/services/{service_id}` с production mTLS certificate + публичным X-Outgate-Deployment-Grant-ID без secret. В development — service bearer принятого QUIC snapshot в Authorization и verified HTTPS без client certificate. HMAC/outgatecall/user context в служебный GET не включаются: discovery проверяет отдельное право caller→target, а не background business policy. Authorization/route/replay production runtime gateway ещё отсутствует; TLS test harness не заменяет этот backend.

Ответ — закрытый JSON `{service_id, route_revision, mounts}`, где каждый mount содержит normalized `path` и `path_mode` preserve/strip. [Нормативная schema](../docs/discovery.schema.json) и [fixtures](../tests/fixtures/discovery/v1/responses.json) взяты из gateway. Codec protocol/v1 проверяет exact names, duplicate keys, UTF-8/surrogates, positive uint64 и нормализованные prefixes. Helper требует service_id точной цели, application/json без content encoding, body ≤64 KiB; oversized/невалидные/status/redirect ответы не кешируются. Полный lookup ограничен DiscoveryTimeout (default/max 5s), caller/security/shutdown deadlines; response body всегда закрывается. Redirect/retry/fallback отсутствуют. HTTP/parse/timeout errors возвращают discovery_unavailable, cancel/deadline cause сохраняется для transport cancellation.

Cache — максимум 256 origin/target/mount entries, LRU, TTL 30s с ограничением credential/security expiry. Он привязан к accepted session/credential snapshot: даже reconnect той же пары требует нового authenticated lookup. Из authenticated 200 кешируется только запрошенный mount; его отсутствие даёт negative entry с тем же TTL и mount_not_found. HTTP errors не являются negative cache. Просроченные/непроверенные entries не используются при недоступном discovery. Expiry и quota проверены на фиксированных timestamps; mutex не удерживается во время I/O.

Для helper-built request любой 409 консервативно удаляет target cache, не читая/не буферизуя response body и не меняя прикладной ответ. Business request никогда не повторяется; приложение явно вызывает NewServiceRequest ещё раз. Invalidation увеличивает bounded global epoch, чтобы in-flight lookup не восстановил старую revision; конкурентный lookup может безопасно вернуть discovery_unavailable и потребовать нового явного вызова helper. Глобальный epoch может также отклонить параллельный lookup другого target вместо принятия сомнительного снимка. Построенный запрос сохраняет private binding к accepted session и target; при смене session до отправки он локально отклоняется и должен быть построен заново. При работе с результатом сохраняйте его context/private binding.

Server endpoint/discovery permission checks, устойчивый route_revision и согласованность mounts при rollout принадлежат будущему gateway runtime. SDK helper не подтверждает право вызова: при Do gateway заново проверяет grant, HMAC, policy, expected revision и durable nonce reservation. User JWT delegation, inherited hop context и WebSocket Upgrade пока не подключены. Этот контракт добавляет отдельный service API response, не меняя tunnel minor/ALPN/существующие control bytes.
