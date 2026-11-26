# QUIC dialer и credential source

`Config.QUIC` подключает встроенный dialer к public Client; `Config.Connect` остаётся альтернативой для собственного adapter. Одновременное задание обоих запрещено. `NewQUICConnector(QUICConfig)` возвращает тот же Connect для самостоятельной интеграции. Конструкторы копируют registration/trust config и не выполняют I/O или callbacks.

`QUICConfig` задаёт `Address` в форме host:port, отдельный `ServerName`, `ServerRoots`, production `ClientRoots` и `TrustDomain`, `Register`, `Credentials` и `Session` options. TLS 1.3, явные CA, hostname verification и production client certificate обязательны. InsecureSkipVerify/custom TLS callbacks, system-root fallback, 0-RTT и переключение транспорта отсутствуют. DNS разрешается с context deadline; в quic-go передаётся literal IP, при этом TLS проверяет исходный ServerName. Используется первый разрешённый IP, без автоматического перебора адресов внутри попытки.

`CredentialSource(ctx)` возвращает цельный immutable `CredentialSnapshot`: Certificate, Credential и Generation. Production Credential — уже выданный opaque deployment grant `grant_id.secret`, Generation > 0. SDK добавляет существующую capability credential_generation в offered/required и заполняет register из snapshot; source не выдаёт grant самостоятельно. Grant должен быть заранее связан issuer с этим поколением, SPKI и registration. Development включается явно и в Client Config, и в QUICConfig; он использует bearer без certificate и с Generation=0.

`StaticCredentials(snapshot)` создаёт источник с собственными копиями и возвращает отдельную копию при каждом вызове. Поддерживаются software private keys RSA 2048…8192, ECDSA P-256/P-384/P-521 и Ed25519; hardware signers пока не поддержаны. Цепочка ограничена восемью certificates и 64 KiB DER суммарно, credential — wire limit 4096 bytes. Production grant дополнительно проверяется на canonical base64url и нормативные размеры частей. SDK не меняет исходные maps/slices/ключи; provider обязан не менять опубликованную пару во время чтения. Временный PKCS#8 buffer очищается, полной zeroization Go/TLS памяти API не обещает.

Перед dial проверяются client certificate chain/EKU/time, соответствие private key SPKI и единственный точный URI SAN `spiffe://<trust_domain>/service/<service_id>/instance/<instance_id>`. Caller-supplied Leaf игнорируется: certificate разбирается из DER. Permissions, opaque grant binding/revocation и durable admission независимо проверяет gateway до ack. После ack SDK не принимает expiry позже leaf.NotAfter, а local security deadline дополнительно ограничивается сроками verified chain и Session.SecurityDeadline. Истечение во время connect/register тоже закрывает session.

Источник вызывается под отдельным deadline default/max 5s. Один slot сохраняется до фактического возврата callback, даже после timeout; новые source goroutines не накапливаются. Panic скрывает текст и становится callback_failed. Временный source failure/timeout повторяет только получение credentials через Client backoff; до валидного snapshot UDP session не открывается. Security/protocol errors не становятся retryable из-за source wrapper. Generation не уменьшается; изменение certificate/grant в уже наблюдённом поколении отвергается. Ledger живёт в connector, durable rollback protection между процессами остаётся у защищённого provider/deployment state.

Dial default 5s, максимум 10s, registration default/max 10s; все этапы делят оставшийся parent Connect deadline (Client default 10s, допустимо явно до 30s). QUIC keepalive/idle — 15s/45s, handshake idle — 5s. TLS verification/crypto failures terminal. Секреты не входят в Error()/status; underlying errors через Unwrap предназначены только для внутренних diagnostics с redaction.

При reconnect Client сохраняет registration identity, разрешая только неизменное либо возрастающее credential_generation. `Config.QUIC` в production также получает новую пару во время активной session: acquisition начинается за min(5m, 20% фактического остаточного срока при принятии) до более раннего confirmed ACK expiry, verified chain expiry и первоначального Session.SecurityDeadline. Opaque grant не разбирается как доверенные claims. Development не опрашивает source в фоне. Самостоятельный `NewQUICConnector` и пользовательский `Config.Connect` предоставляют только acquisition/dial/register при вызове; proactive lifecycle подключает именно `Config.QUIC`.

Refresh сохраняет один callback slot до фактического возврата, включая timeout/Close/revoke. Callback выполняется под deadline default/max 5s и оставшимся сроком старой пары; expiry/revoke обслуживаются независимо и не ждут callback, но final Done/следующий Connect ждут его actual cleanup. Unchanged generation, неверная новая пара, source failure и panic сохраняют working session до её срока. Retry использует exponential cap 1…30s и jitter в диапазоне [1s, cap]; после expiry повторов нет. Неверная пара не меняет generation ledger текущей session.

Только owned snapshot с новым поколением, прошедший CA/SAN/time/key/формат grant проверки, запускает graceful Drain старой session. Drain ограничен 30s, negotiated drain deadline и текущим security/credential deadline; истечение/revoke имеют приоритет. Новый dial/register выполняется после фактического cleanup старого transport/handlers/readiness callback. Candidate закрепляется до переключения и повторно проверяется перед dial; source не вызывается заново между успешным refresh и registration. Временная ошибка dial сохраняет candidate для следующей попытки. Bounded drain timeout допускает переключение после actual cleanup, если старый security deadline ещё не достигнут; protocol/security failures останавливают Client. Final Close/отмена Run и validated final gateway drain подавляют rotation, включая crossed commands. Grant binding/permissions/revocations нового поколения gateway проверяет до нового ACK; SDK не может подтвердить opaque binding до остановки старого туннеля.

Старые business requests завершаются или отменяются в рамках старого drain, не повторяются и не переносятся в новую session. При статическом source повторное получение той же пары не начинает drain, а истечение закрывает tunnel. SecurityReady остаётся false по умолчанию; локальная проверка TLS/сертификата не заменяет revocation/replay/recovery checks приложения. Session options и SetSecurity передают только внешне проверенный gate. Прикладной HTTPS connection pool ещё отсутствует, его переключение credentials потребует отдельной интеграции.


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

## Файловый источник

`FileCredentials(root, manifest)` возвращает `CredentialSource` без I/O в конструкторе. Например, `client.FileCredentials("/run/outgate/credentials", "current.json")` можно передать в `QUICConfig.Credentials`. Относительный manifest и все относительные ссылки внутри него разрешаются от явно заданного root; абсолютные ссылки тоже разрешены. Root фиксируется как абсолютный путь при создании source и не меняется при смене working directory. Это правило разрешения путей, а не filesystem sandbox.

Manifest соответствует [credential-provider.schema.json](https://github.com/solodyagin/outgate/blob/main/docs/credential-provider.schema.json): только `generation`, `certificate_file`, `private_key_file`, `deployment_grant_file`, все обязательны. Generation — положительная decimal uint64 string. Duplicate keys, unknown/case-alias fields, null, invalid UTF-8/surrogates, control characters в путях и превышение лимитов отклоняются. Manifest ограничен 64 KiB, certificate PEM — 96 KiB (до восьми certificates и 64 KiB DER), key PEM — 32 KiB. Принимаются незашифрованные PKCS#8, PKCS#1 RSA и SEC1 EC software keys из существующего списка поддерживаемых ключей. Grant file содержит точный canonical `grant_id.secret` до 385 bytes, без завершающего newline. Лишние PEM blocks/посторонний текст и несовпадающие certificate/key отклоняются.

Deployment сначала пишет защищённые файлы нового поколения, затем атомарно заменяет manifest. Опубликованные файлы остаются неизменными на время чтения; provider читает один manifest и возвращает только целый snapshot с собственными копиями. Проверка CA/SAN/срока и monotonic generation выполняется connector перед dial; grant binding проверяет gateway. Source не хранит durable generation ledger. Права доступа/ACL, symlinks и доверенные пути обеспечивает deployment на Linux/Windows. Provider проверяет regular-file type перед open и на открытом descriptor, но эти проверки не защищают от подмены файлов злоумышленником с правами записи в credential directory.

Неполные/некорректные файлы дают retryable `credential_unavailable` без путей, parser text или содержимого даже в Unwrap; следующая acquisition заново читает manifest. Context проверяется между ограниченными чтениями, но не прерывает системную filesystem operation. Connector сохраняет единственный source slot до фактического возврата. Filesystem watcher отсутствует: при `Config.QUIC` файлы перечитываются при startup/reconnect и запланированных proactive acquisition/retry; standalone source не запускает фоновой работы. Native Windows runtime-приёмку provider следует выполнять отдельно от cross-compile.
