# QUIC dialer и credential source

`Config.QUIC` подключает встроенный dialer к public Client; `Config.Connect` остаётся альтернативой для собственного adapter. Одновременное задание обоих запрещено. `NewQUICConnector(QUICConfig)` возвращает тот же Connect для самостоятельной интеграции. Конструкторы копируют registration/trust config и не выполняют I/O или callbacks.

`QUICConfig` задаёт `Address` в форме host:port, отдельный `ServerName`, `ServerRoots`, production `ClientRoots` и `TrustDomain`, `Register`, `Credentials` и `Session` options. TLS 1.3, явные CA, hostname verification и production client certificate обязательны. InsecureSkipVerify/custom TLS callbacks, system-root fallback, 0-RTT и переключение транспорта отсутствуют. DNS разрешается с context deadline; в quic-go передаётся literal IP, при этом TLS проверяет исходный ServerName. Используется первый разрешённый IP, без автоматического перебора адресов внутри попытки.

`CredentialSource(ctx)` возвращает цельный immutable `CredentialSnapshot`: Certificate, Credential и Generation. Production Credential — уже выданный opaque deployment grant `grant_id.secret`, Generation > 0. SDK добавляет существующую capability credential_generation в offered/required и заполняет register из snapshot; source не выдаёт grant самостоятельно. Grant должен быть заранее связан issuer с этим поколением, SPKI и registration. Development включается явно и в Client Config, и в QUICConfig; он использует bearer без certificate и с Generation=0.

`StaticCredentials(snapshot)` создаёт источник с собственными копиями и возвращает отдельную копию при каждом вызове. Поддерживаются software private keys RSA 2048…8192, ECDSA P-256/P-384/P-521 и Ed25519; hardware signers пока не поддержаны. Цепочка ограничена восемью certificates и 64 KiB DER суммарно, credential — wire limit 4096 bytes. Production grant дополнительно проверяется на canonical base64url и нормативные размеры частей. SDK не меняет исходные maps/slices/ключи; provider обязан не менять опубликованную пару во время чтения. Временный PKCS#8 buffer очищается, полной zeroization Go/TLS памяти API не обещает.

Перед dial проверяются client certificate chain/EKU/time, соответствие private key SPKI и единственный точный URI SAN `spiffe://<trust_domain>/service/<service_id>/instance/<instance_id>`. Caller-supplied Leaf игнорируется: certificate разбирается из DER. Permissions, opaque grant binding/revocation и durable admission независимо проверяет gateway до ack. После ack SDK не принимает expiry позже leaf.NotAfter, а local security deadline дополнительно ограничивается сроками verified chain и Session.SecurityDeadline. Истечение во время connect/register тоже закрывает session.

Источник вызывается под отдельным deadline default/max 5s. Один slot сохраняется до фактического возврата callback, даже после timeout; новые source goroutines не накапливаются. Panic скрывает текст и становится callback_failed. Временный source failure/timeout повторяет только получение credentials через Client backoff; до валидного snapshot UDP session не открывается. Security/protocol errors не становятся retryable из-за source wrapper. Generation не уменьшается; изменение certificate/grant в уже наблюдённом поколении отвергается. Ledger живёт в connector, durable rollback protection между процессами остаётся у защищённого provider/deployment state.

Dial default 5s, максимум 10s, registration default/max 10s; все этапы делят оставшийся parent Connect deadline (Client default 10s, допустимо явно до 30s). QUIC keepalive/idle — 15s/45s, handshake idle — 5s. TLS verification/crypto failures terminal. Секреты не входят в Error()/status; underlying errors через Unwrap предназначены только для внутренних diagnostics с redaction.

При reconnect Client сохраняет registration identity, разрешая только неизменное либо возрастающее credential_generation. Новый источник вызывается после actual cleanup старой session. Сейчас snapshots загружаются при startup/reconnect: файловый manifest provider и упреждающее получение новой пары во время активной session с её последующим rotation drain ещё не реализованы. Действующий tunnel не опрашивает source в фоне. SecurityReady остаётся false по умолчанию; локальная проверка TLS/сертификата не заменяет revocation/replay/recovery checks приложения. Session options и SetSecurity передают только внешне проверенный gate.

Схема использования после загрузки **настоящей** выданной пары и trust configuration:

```go
source, err := client.StaticCredentials(client.CredentialSnapshot{
    Certificate: certificate, Credential: deploymentGrant, Generation: generation,
})
// Обработайте err; не логируйте snapshot или secret.
c, err := client.New(client.Config{
    Handler: authorizedHandler,
    QUIC: &client.QUICConfig{
        Address: "gateway.example.com:443", ServerName: "gateway.example.com",
        ServerRoots: gatewayCAs, ClientRoots: identityCAs, TrustDomain: "example.com",
        Register: registration, Credentials: source,
    },
})
// Run/SetSecurity/WaitReady/Close — client lifecycle; проверенный security gate
// устанавливается приложением после его обязательных security checks.
```

Это API sketch с переменными приложения, не самостоятельный production bootstrap. Файловый формат источника и binding определены в [нормативном контракте credentials](https://github.com/solodyagin/outgate/blob/main/docs/credentials.md).
