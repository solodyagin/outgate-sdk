# Фоновые межсервисные HTTPS-вызовы

`Config.ServiceHTTP` вместе с `Config.QUIC` включает обычные background-вызовы по ТЗ 3.14/3.21/3.25 и профилю protocol §9. Это отдельный HTTPS listener gateway, не HTTP внутри исходящего QUIC tunnel. Production включён по умолчанию; SDK использует certificate и публичный grant ID из принятой gateway пары. Opaque grant secret в HTTPS headers не передаётся. HMAC signing key задаётся отдельно от TLS private key/grant и копируется при New.

```go
c, err := client.New(client.Config{
    QUIC: tunnelConfig,
    Handler: authorizedHandler,
    ServiceHTTP: &client.ServiceHTTPConfig{
        ServerRoots: serviceListenerCAs,
        SigningKey: client.HMACKey{ID: signingKeyID, Secret: signingSecret},
    },
})
// Обработайте err. Run и внешне проверенный security gate настраиваются
// по client lifecycle; default SecurityReady=false не меняется.
serviceHTTP, err := c.ServiceHTTPClient("https://gateway.example.com:9443")
ctx := client.WithTargetService(requestContext, "reports-service")
req, err := http.NewRequestWithContext(ctx, "POST",
    "https://gateway.example.com:9443/api/reports?format=csv", streamingBody)
resp, err := serviceHTTP.Do(req)
// Обработайте err; успешный resp.Body нужно прочитать/закрыть.
```

Переменные в примере принадлежат приложению; это API sketch, не production bootstrap. New и ServiceHTTPClient не вызывают source, не открывают sockets и не запускают workers. Конструктор проверяет и копирует явные CA/signing key. ServerRoots задаёт trust HTTPS listener отдельно от QUIC ServerRoots/ClientRoots. HTTPS origin не содержит userinfo/query/fragment/прикладного пути; завершающий `/` допустим. Каждый request обязан использовать тот же origin и context с WithTargetService. Host override, меняющий origin, отклоняется. Отсутствие настройки/ключа, неверный target/URI/framing или supplied trusted headers дают локальный отказ до сети. Custom Config.Connect без builtin Config.QUIC пока не поддерживает этот API.

Каждый вызов проходит актуальный Ready gate. До готовности возвращается client_not_ready, после final Close/revoke — client_closed. Вызов клонирует request/headers, формирует caller/target, background manifest `[]`, production hop-limit `8` и публичный grant ID, затем подписывает exact escaped path/query профилем outgatecall. Caller, TLS certificate и grant ID берутся из одного accepted поколения. Явный `X-Outgate-Expected-Route-Revision` допускается только при валидном single-valued decimal значении и всегда покрывается подписью; discovery/cache helper описан в [discovery.md](discovery.md). Lower-case names и повторения application headers сохраняются в canonical Header representation. Authorization/Cookie передаются только если приложение явно включило их в данный Request; из других context/запросов они не извлекаются. Body заранее не читается и не буферизуется. TLS 1.3, hostname verification, mTLS в production, явные roots, без ambient proxy/system trust fallback.

Для гарантии отсутствия прозрачных business retries этот первый transport использует только HTTP/1.1 с новым connection на каждый request, DisableKeepAlives и отключённым GetBody у wire-копии. Встроенный HTTP/2 и повторное использование соединений выключены явно; автоматического выбора другого транспорта нет. Go Transport не повторяет ошибки нового HTTP/1.1 connection, включая GET и запросы с Idempotency-Key. Redirect отключён через http.ErrUseLastResponse; исходный ответ возвращается приложению. Прикладные статусы/тела, включая 409, не переупаковываются и не повторяются. Keep-alive pool с отдельной гарантией no-replay остаётся будущей оптимизацией.

Параллелизм ограничен MaxConcurrent (default 100, максимум 1000) на Client, включая незавершённые response bodies. Превышение даёт quota_exceeded локально. Dial/TLS defaults/max — по 5s, response headers и body idle defaults/max — по 60s; положительные меньшие значения допустимы. URI ограничен 8192 bytes, headers/выходная подпись — 32 KiB с bounded field count, response header limit — 32 KiB. Total timeout не навязывается: действует minimum caller/security/shutdown deadline. Idle upload timer начинает отсчёт при первом чтении producer, response idle timer — с headers; успешные body reads продвигают соответствующий таймер. Нулевые reads не продлевают idle. Body должен соблюдать стандартный net/http контракт: Close разблокирует конкурентный Read.

Новая HTTPS доставка использует только текущие credentials после новой readiness. При ротации новый TLS certificate/grant ID применяется к новым connections, старый accepted HTTPS stream может продолжаться до своего captured old security/credential deadline. Revoke отменяет все поколения немедленно; сокращение security deadline и final Close ограничивают активные вызовы. Close запрещает новые calls, ждёт accepted responses в пределах общего earliest shutdown deadline и затем отменяет оставшиеся; Done/Run ждут освобождения SDK call slots. После transport failure/local rejection request body закрывается без чтения для повтора. EOF/Close/cancellation освобождают quota; пустой response body освобождает её сразу.

Error.Error() RoundTripper содержит только безопасный code, typed Error доступен через errors.As; errors.Is сохраняет cancellation/deadline cause. Стандартный http.Client.Do дополнительно оборачивает ошибки в url.Error с исходным URL: публичные diagnostics должны использовать code, а не печатать полный URL/Unwrap с query/peer text. Body Read/Close сохраняет обычные streaming I/O errors. Это не проверка HMAC на стороне gateway, replay reservation, route policy или JWT; production listener и durable security backend ещё не реализованы.

Пока поддерживаются только обычные фоновые calls. UserContext/issuer JWT delegation, inherited hop context и WebSocket Upgrade/Hijacker остаются в работе. NewServiceRequest/discovery/cache invalidation реализованы отдельно. User/Outgate/Tunnel headers, supplied signatures и Upgrade отклоняются; локальный user context не превращается в подтверждённые claims. Request trailers и явный TransferEncoding пока не принимаются. Этот шаг не завершает весь контракт прикладного SDK.

Проверки используют отдельные actual mTLS HTTPS и QUIC listeners с synthetic admission: проверка HMAC по actual wire URI, immutable headers/key snapshots, streaming upload/response, TLS rejection, readiness/origin/header guards, отсутствие redirects/replay GET/POST, quota/cancellation/idle/Close/revoke/security deadline и смена certificate/grant поколения при сохранении старого accepted stream. Это client integration tests, не production gateway admission/replay acceptance.
