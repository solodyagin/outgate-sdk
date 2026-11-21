# Статус реализации SDK

Обновлено: 2026-11-21. Начат этап 1 «Контракты и основа». Ни один этап ТЗ целиком не принят. Общий статус проекта — в [gateway repository](https://github.com/solodyagin/outgate/blob/main/docs/implementation-status.md).

## Точка продолжения

- **Текущая задача:** правила публикации локальных путей и автономная CI-проверка распространены на SDK; следующая задача — модели `request_start`/`response_start` с проверками headers/URI.
- **Завершённые шаги:** добавлены правила публикации путей в AGENTS.md, автономный Python scanner и его тесты, шаги Linux/Windows CI. Конкретный временный путь в отчёте заменён описанием назначения каталога. История Git сохранена. Ранее Go-код, README и AGENTS перенесены из gateway; module path — `github.com/solodyagin/outgate-sdk`. Добавлены автономный Linux/Windows CI и локальный snapshot schema/fixtures; тесты используют только этот checkout. Production Go-файлы не менялись. Wire-контракт и golden bytes сохранены.
- **Незавершённая работа:** удалённый запуск новой проверки и её native Windows runtime ещё не подтверждены. Перенос ещё не отправлен в remote. Остальные 16 control messages, headers/URI, state machines, Go signatures/replay, transport adapters и `outgateclient` отсутствуют; versioned release не выпущен. Codecs/unit tests не означают готовность adapter или завершённую приёмку.
- **Проверки текущей сессии (2026-11-21):** При подготовке коммита повторно прошли 5 unit tests, fixture verifier и `git diff --check`. Проверка домашних путей в отслеживаемых файлах и отдельно в новых Python-файлах, 5 unit tests, fixture verifier в SDK/gateway и `git diff --check` — PASS на Linux. `GOWORK=off GOPROXY=off go test -race ./...` и `go vet ./...` с отдельным временным GOCACHE — PASS. Scanner и его тесты побайтово совпадают с gateway; schema/fixtures также побайтово сверены с gateway — PASS. Go-код и wire-контракт не менялись. Удалённый CI, Windows compile и native Windows runtime в этой сессии не выполнялись. Предыдущие результаты выделены ниже.
- **Блокеры:** для следующих control messages не выявлены. QUIC adapter заблокирован до обязательного собственного quic-go spike с reverse HTTP/3, stream 0 exclusion, streaming/cancel, internal CONNECT и native Linux/Windows.
- **Следующее действие:** прочитать относящиеся разделы ТЗ/protocol в gateway, локальные schema/fixtures и реализовать `request_start`/`response_start` с semantic validation, негативными/граничными и golden tests. Изменения wire-контракта согласовывать в обоих repositories.

## Реализовано

`protocol/v1` содержит U64 decimal strings, bounded JSON с UTF-8/depth/duplicate-key проверками, QUIC bootstrap/control framing, WSS chunks, register/ack/nack codecs и semantic validation, сверку ack с register, нормализацию prefixes и однократное декодирование route path. Пакет использует только standard library и не содержит gateway logic, sockets, SQL или RBAC. Проверки credentials, session state, budget, routing atomicity, сетевой совместимости и production security не реализованы.

Go 1.27.4; wire major 1 / minor 0. Minimum Go/backward compatibility и SDK/gateway N/previous-minor integration ещё не исследованы. Transport/storage dependencies и release SBOM ещё не выбраны/сформированы.

## Проверки выделения SDK

Предыдущая сессия 2026-11-21: локальный fixture verifier — PASS; `go test -race ./...`, `go vet ./...`, `go list -m all` при `GOWORK=off GOPROXY=off` и отдельном временном GOCACHE — PASS, module graph содержит только SDK. Windows amd64 build и compile тестов `protocol/v1` — PASS с теми же flags и `GOOS=windows GOARCH=amd64` (cross-compile, без native runtime). Snapshot schema/fixtures побайтово совпадает с gateway и указанной в `contract-snapshot.md` revision. Формат Go, относительные Markdown links и `git diff --check` — PASS. Remote CI и native Windows runtime в этой сессии не проверялись; прежние fuzz/coverage результаты записаны в gateway status и не повторялись.
