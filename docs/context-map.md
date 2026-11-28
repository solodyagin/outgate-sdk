# Карта контекста SDK

Начните с актуальной «Точки продолжения» в `../../project-notes/implementation-status.md`, если она доступна, и строки таблицы ниже. Сверяйте статус с кодом/Git. Исторические отчёты нужны только для конкретных проверок; README описывают API, а не доказательство production-готовности.

Нормативные [ТЗ](https://github.com/solodyagin/outgate/blob/main/docs/requirements.md) и [protocol](https://github.com/solodyagin/outgate/blob/main/docs/protocol.md) принадлежат gateway. При соседнем checkout читайте локальные `../outgate/docs/requirements.md` и `../outgate/docs/protocol.md` от корня SDK; иначе используйте repository sources. Schema/fixtures SDK автономны: [происхождение snapshot](contract-snapshot.md). Карта не заменяет контракт.

| Задача | Разделы ТЗ / protocol | Начальные файлы и целевая проверка |
|---|---|---|
| Wire messages, paths, discovery codec | ТЗ 3.2–3.3, 3.22, 4; protocol 2–7, 10–12 | `protocol/v1`, нужные definitions в `docs/*schema.json`, соответствующие fixtures; `package ./protocol/v1`, `contracts` |
| WSS HTTP/WS state и budgets | ТЗ 3.7, 3.11, 4.3–4.5; protocol 4, 6–7, 11–12 | [wssstate](../wssstate/README.md), `wssstate/state.go`, тесты; `package ./wssstate` |
| Session readiness / security lease renewal / drain / fence | ТЗ 3.7, 3.21, 5.6; protocol 8 | [sessionstate](../sessionstate/README.md), `sessionstate`, [quicsession](../transport/quicsession/README.md); `package ./sessionstate ./transport/quicsession` |
| QUIC bootstrap / streaming HTTP/3 | ТЗ 4.2, 5.6; protocol 3, 5, 8, 11–12 | [quiccontrol](../transport/quiccontrol/README.md), [quichttp](../transport/quichttp/README.md), их код/тесты; `package ./transport/...`; gateway interoperability отдельно |
| Public lifecycle / reconnect | ТЗ 3.10, 3.21, 5.6; protocol 8 | [client](../client/README.md), `client/client.go`, тесты; `package ./client` |
| Credential snapshots / dial / renewal | ТЗ 3.25, 6.5; gateway `docs/credentials.md` | [QUIC client](../client/quic.md), `client/quic.go`, `credentials*.go`, `renewal.go`, тесты; `package ./client` |
| Signed background HTTPS / discovery | ТЗ 3.14, 3.16, 3.22; protocol 9–10 | [service HTTP](../client/service_http.md), [discovery](../client/discovery.md), соответствующие `.go`/tests; `package ./client ./protocol/v1` |
| HMAC profile / replay proof | ТЗ 3.15, 4.6, 5.5.2; protocol 9 | [httpsig](../httpsig/README.md), `httpsig`, signature fixtures; `package ./httpsig` |
| SQLite replay storage / recovery | ТЗ 5.5.2, 6.4 и 8.8, protocol 9.3 | [replay](../replay/README.md), `replay/sqlite.go`, `replay/schema.go`, `package ./replay ./httpsig` |
| JWT / исходящий user context | ТЗ 3.12, 3.14–3.15, 5.5.4, 5.6; protocol 9.2–9.3 | [delegation](../delegation/README.md), [user API](../client/user.md), `delegation`, `client/user.go`; `package ./delegation ./client` |
| Incoming delivery binding | ТЗ 3.12, 3.14–3.16, 5.5.1–5.5.5; protocol 9 | [delivery](../delivery/README.md), `delivery/verifier.go`, тесты и вызываемые `httpsig`/`delegation`; `package ./delivery ./httpsig ./delegation` |
| Dependencies / snapshot / платформы | ТЗ 2.3, 4.7, 5.4, 5.5.7, 10.3 | [dependencies](dependencies.md), [snapshot](contract-snapshot.md), `go.mod`, SBOM, CI; `full` и отдельный Windows compile |

## Порядок работы

- Сначала заголовки нужного документа и поиск symbols (`rg -n`), затем соответствующие разделы/definitions с `$ref`, реализация, вызывающие места и тесты. Не читайте целиком ТЗ, schema, архив статуса или все README по умолчанию. При изменении контракта/границ расширьте чтение и включите критерии приёмки из ТЗ 8.
- `package`, `contracts`, `full` в таблице — аргументы `python3 -B tests/check.py`; подробнее в [checks.md](checks.md). Целевые проверки ускоряют разработку; обязательные итоговые проверки остаются в `AGENTS.md`.
- Формулируйте задачу через конкретное поведение, связанные разделы, сохраняемые инварианты и проверяемый критерий завершения. Не объявляйте primitives полноценными middleware/adapters.
