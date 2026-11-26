# Исходящие пользовательские вызовы

`WithUserContext(ctx, UserContext)` сохраняет проверенную по форме owned копию локальных данных. `UserContextFromContext` возвращает копию только этих локальных данных. Эти helpers не подтверждают входящую identity. Invalid context сохраняется как явный отказ, а не превращается в background call.

В production `WithUserAssertion(ctx, issuerJWT)` обязателен для пользовательского `ServiceHTTPClient` request. JWT проверяется при отправке по actual caller и target из `WithTargetService`. При assertion без local context user headers выводятся из claims; если задан и local context, ID, порядок ролей и attributes должны точно совпасть. SDK не выпускает новый assertion и не переносит полномочия на другого actor/audience автоматически.

```go
verifier, err := delegation.New(delegation.Config{
    Issuer: "https://issuer.example.com",
    Claims: delegation.ClaimMap{
        UserID: "sub", Roles: "roles", SessionID: "sid",
        Attributes: map[string]string{"tenant_id": "tenant_id"},
    },
    Keys: authenticatedKeySnapshot,
})
// Обработайте err; параметры встроенного QUIC client задаются отдельно.
serviceHTTPConfig := client.ServiceHTTPConfig{
    ServerRoots: serviceListenerCAs,
    SigningKey: client.HMACKey{ID: signingKeyID, Secret: signingSecret},
    AttributeHeaders: map[string]string{"tenant_id": "x-user-tenant-id"},
    Delegation: &client.DelegationConfig{
        Verifier: verifier,
        SecurityCheck: checkUserSecurity,
    },
}
ctx := client.WithUserAssertion(
    client.WithTargetService(requestContext, "reports-service"), issuerJWT)
// Передайте ctx в http.NewRequestWithContext / NewServiceRequest.
```

Это API sketch: все внешние значения принадлежат приложению. Поддерживаемый [JWT профиль](../delegation/README.md) — RS256 с явно опубликованными trusted key snapshots. `SecurityCheck(context.Context, delegation.Identity) (time.Time, error)` обязателен: он проверяет актуальное user/session security state через доверенный источник и возвращает срок действия результата. Пример не содержит фиктивной реализации production backend. Без verifier/callback пользовательская отправка запрещена; default SecurityReady=false сохраняется.

Callback вызывается вне SDK mutex, с deadline не более 5s и только одним outstanding вызовом на Client. Он обязан учитывать cancellation. Slot удерживается до фактического возврата даже после timeout; Close отменяет transport, но Done/Run ждут actual callback cleanup. Panic превращается в callback_failed, ошибка — в безопасный отказ без текста callback. После callback SDK повторяет JWT verification и перед dispatch проверяет readiness и accepted credential epoch; задержанный callback не отправит запрос со старой парой после ротации.

User call ограничен минимумом caller/security/credential/shutdown deadlines, JWT expiry и returned lease, дополнительно capped at 30s от начала security callback. В этой версии lease не продлевается: даже допустимый длинный response stream отменяется не позднее этого срока. JWT clock skew не продлевает исходящий stream за фактический exp. Это ограничение доступности первого адаптера; continuous revocation sync и stream lease renewal ещё нужны для полного контракта.

`AttributeHeaders` — явный копируемый map logical attribute → разрешённый HTTP header, максимум 16. Зарезервированные/дублирующиеся header names отклоняются. Неотображённый attribute запрещает отправку. User ID и plain attribute values сейчас должны быть printable ASCII без окружающих пробелов; SDK не придумывает wire encoding для Unicode ID. Unicode roles передаются JSON `\u` escapes с сохранением значения, включая surrogate pairs. Manifest сортируется; HMAC покрывает user context, assertion, caller/target, hop и grant. Полный сериализованный context ограничен 8 KiB профилем `httpsig`.

Явный development mode допускает local UserContext без JWT и не принимает WithUserAssertion; production fallback отсутствует. Supplied User/Outgate headers по-прежнему запрещены. Discovery request не получает user context/assertion. Исходящий hop пока начинается с 8: trusted inbound hop inheritance и BindUserSession не реализованы. Проверочный пакет [delivery](../delivery/README.md) объединяет входящие HMAC/JWT/context equality; его middleware integration, JWKS loader, durable revocation backend и production gateway listener остаются отдельной работой.

Интеграционные тесты используют actual mTLS HTTPS и QUIC с synthetic admission/security callback: signed user headers, Unicode roles, semantic mismatch, actor/audience rejection до сети, callback panic/error/expiry, Close cleanup и credential rotation. Это не production security backend acceptance.
