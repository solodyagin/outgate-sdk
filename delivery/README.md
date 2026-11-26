# Проверка подписанной доставки

`delivery` объединяет production `httpsig` и `delegation` на исходных публичных metadata запроса. Поддерживаются оба leg: outgatecall на service listener gateway и outgategateway на стороне получателя. Пакет не принимает body и не выполняет I/O, strip/rewrite, dispatch или установку trusted context в handler. Это проверочная часть будущего middleware, а не готовый HTTP security adapter.

`New(Config)` фиксирует leg, копирует logical attribute → header mapping и принимает общий thread-safe JWT verifier. Указанные headers проходят тот же allowlist, что `httpsig`; имена нормализуются в lower-case, aliases/reserved names запрещены. JWT может отсутствовать только для background-only verifier: user delivery в таком случае отклоняется. Development fallback отсутствует.

`Verify(request, key, expectedBinding, now)` сначала выполняет bounded profile/HMAC/time verification, затем проверяет ожидаемые caller, target и deployment grant ID. `Key` должен быть заранее выбран по доверенному leg/caller configuration после transport identity/grant checks. Expected binding берётся из аутентифицированного состояния, а не из самих HTTP headers.

Для outgategateway дополнительно обязательны точные зарегистрированные instance/version/normalized mount prefix. Проверяется segment match исходного публичного path с prefix; root `/` допустим. Проверка выполняется до strip, без изменения path/query или повторной JSON canonicalization подписанных значений. Outgatecall не принимает gateway tuple в expected binding. Route permissions/revision/canary/active instance state проверяет вызывающий runtime отдельно.

У user delivery issuer JWT проверяется независимо: actual caller/target, claims и время. Raw user ID и attributes должны точно совпасть с mapped claims; roles сравниваются как декодированный массив с сохранением порядка. JSON Unicode escapes не меняют семантику роли, но их подписанные bytes сохраняются. Отсутствующий/лишний mapped attribute и claim без header mapping отклоняются. Поля/manifest/размеры сначала проверяет `httpsig`, поэтому частичная подпись или неполный user context не могут превратиться в background mode. Новая user delivery после фактического JWT exp запрещена, даже если криптографический verifier допускает clock skew.

Успешный `Verified` содержит owned user context и identity без raw JWT; getters не возвращают mutable внутренние slices/maps. Background возвращает `User()/Identity()` с false и не создаёт пользователя `system`. `Binding()` возвращает ожидаемую проверенную tuple; `HopLimit()` — аутентифицированное входящее значение 1…8. API ещё не переносит hop в исходящий client context автоматически.

`Signature()` возвращает cryptographic proof для существующего `httpsig.Verified.Reserve`. Verify сам не резервирует nonce: transport/caller/grant, route/delegation/revision и актуальные user/session/revocation checks должны успешно завершиться до durable reserve, а reserve — до dispatch. Если проверки заняли время, повторите Verify с текущим временем и security gates перед Reserve. Нулевой Verified не может зарезервировать nonce. Replay store не должен удалять reservation после downstream failure; production требует SQL durability, capacity transaction и recovery barrier. In-memory store в тесте проверяет порядок/duplicate rejection и не является production backend.

```go
verifier, err := delivery.New(delivery.Config{
    Leg: httpsig.Gateway,
    AttributeHeaders: map[string]string{"tenant_id": "x-user-tenant-id"},
    JWT: issuerVerifier,
})
// Обработайте err. Сначала проверьте transport identity/grants и выберите key.
verified, err := verifier.Verify(originalPublicMetadata, trustedGatewayKey,
    authenticatedExpectedBinding, time.Now())
// После успешных route/revision/revocation checks и актуализации времени:
err = verified.Signature().Reserve(ctx, durableReplayStore, verifierNamespace, time.Now())
// Только после успешного reserve разрешён handler dispatch.
```

Это sketch порядка вызовов, не готовый listener: без выполнения внешних проверок результат не разрешает dispatch. HTTP extraction/duplicate preservation, transport/grant state, rate limits, incoming trusted context/mount installation, inherited hop, BindUserSession и stream revocation lifecycle ещё требуют интеграции в middleware.

Тесты используют actual HMAC/RS256 signatures для обоих legs: background/user, Unicode roles, semantically forged signed claims/headers, binding/strip/mount mismatch, exact attribute representation, config/result ownership и отдельный replay reserve. `FuzzDeliveryUserEquality` проверяет, что корректный HMAC не позволяет изменить user claims.
