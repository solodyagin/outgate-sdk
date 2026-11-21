# Статус реализации SDK

Обновлено: 2026-11-21. Начат этап 1 «Контракты и основа». Ни один этап ТЗ целиком не принят. Общий статус проекта — в [gateway repository](https://github.com/solodyagin/outgate/blob/main/docs/implementation-status.md).

## Точка продолжения

- **Текущая задача:** SDK выделен в самостоятельный repository; следующая задача — модели `request_start`/`response_start` с проверками headers/URI.
- **Завершённые шаги:** Go-код, README и AGENTS перенесены из gateway; module path — `github.com/solodyagin/outgate-sdk`. Добавлены автономный Linux/Windows CI и локальный snapshot schema/fixtures; тесты используют только этот checkout. Production Go-файлы не менялись. Wire-контракт и golden bytes сохранены.
- **Незавершённая работа:** Перенос ещё не отправлен в remote. Остальные 16 control messages, headers/URI, state machines, Go signatures/replay, transport adapters и `outgateclient` отсутствуют; versioned release не выпущен. Codecs/unit tests не означают готовность adapter или завершённую приёмку.
- **Проверки текущей сессии (2026-11-21):** локальный fixture verifier — PASS; `go test -race ./...`, `go vet ./...`, `go list -m all` при `GOWORK=off GOPROXY=off GOCACHE=/tmp/outgate-go-cache` — PASS, module graph содержит только SDK. Windows amd64 build и compile тестов `protocol/v1` — PASS с теми же flags и `GOOS=windows GOARCH=amd64` (cross-compile, без native runtime). Snapshot schema/fixtures побайтово совпадает с gateway и указанной в `contract-snapshot.md` revision. Формат Go, относительные Markdown links и `git diff --check` — PASS. Remote CI и native Windows runtime в этой сессии не проверялись; прежние fuzz/coverage результаты записаны в gateway status и не повторялись.
- **Блокеры:** для следующих control messages не выявлены. QUIC adapter заблокирован до обязательного собственного quic-go spike с reverse HTTP/3, stream 0 exclusion, streaming/cancel, internal CONNECT и native Linux/Windows.
- **Следующее действие:** прочитать относящиеся разделы ТЗ/protocol в gateway, локальные schema/fixtures и реализовать `request_start`/`response_start` с semantic validation, негативными/граничными и golden tests. Изменения wire-контракта согласовывать в обоих repositories.

## Реализовано

`protocol/v1` содержит U64 decimal strings, bounded JSON с UTF-8/depth/duplicate-key проверками, QUIC bootstrap/control framing, WSS chunks, register/ack/nack codecs и semantic validation, сверку ack с register, нормализацию prefixes и однократное декодирование route path. Пакет использует только standard library и не содержит gateway logic, sockets, SQL или RBAC. Проверки credentials, session state, budget, routing atomicity, сетевой совместимости и production security не реализованы.

Go 1.27.4; wire major 1 / minor 0. Minimum Go/backward compatibility и SDK/gateway N/previous-minor integration ещё не исследованы. Transport/storage dependencies и release SBOM ещё не выбраны/сформированы.
