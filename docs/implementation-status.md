# Статус реализации SDK

Обновлено: 2026-11-21. Начат этап 1 «Контракты и основа». Ни один этап ТЗ целиком не принят. Общий статус проекта — в [gateway repository](https://github.com/solodyagin/outgate/blob/main/docs/implementation-status.md).

## Точка продолжения

- **Текущая задача:** завершён проверяемый шаг этапа 1 — SDK codecs `request_start`/`response_start` и проверки HTTP-метаданных; следующий шаг — завершение stream control messages.
- **Завершённые шаги:** в отдельном SDK добавлены wire models, строгий decode обязательных/неизвестных/null/case полей, точная форма header pairs, сохранение повторений, HTTP token/value validation, Host и escaped URI без повторной сериализации, запрет ordinary hop-by-hop полей и неоднозначных Content-Length. Добавлены golden round trips, негативные/граничные тесты и два fuzz targets. Нормативные schema/fixtures и их SDK snapshot не изменены. Ранее реализованы register/ack/nack, выделен SDK и добавлена CI-проверка локальных путей.
- **Незавершённая работа:** остальные 14 control messages, session state machines, negotiated limits/budget и полный размер сериализованного HTTP header block, body/Content-Length accounting, Go signatures/replay, transport adapters и `outgateclient`. Versioned SDK release и boilerplate в отдельном template repository отсутствуют. Remote CI и native Windows runtime не подтверждены. Codecs не означают завершённую приёмку этапа.
- **Проверки текущей сессии (2026-11-21):** см. раздел «Проверки HTTP start» ниже; предыдущие результаты других шагов остаются в существующих разделах.
- **Блокеры:** для следующих control messages не выявлены. До QUIC adapter требуется собственный сквозной quic-go spike по ТЗ 2.3 с native Linux/Windows. Template tunnel integration требует `outgateclient` и SDK release.
- **Следующее действие:** сопоставить нормативные protocol/schema/fixtures и реализовать `request_end`/`response_end`, `window_update`, `cancel`/`cancel_ack`; затем добавить проверяемую stream state machine с credit overflow, ранним ответом, независимыми EOF и cancel races. Не подменять session/budget проверки codecs.

## Реализовано

`protocol/v1` содержит U64 decimal strings, bounded JSON с UTF-8/depth/duplicate-key проверками, QUIC bootstrap/control framing, WSS chunks, register/ack/nack и request_start/response_start codecs и semantic validation, сверку ack с register, нормализацию prefixes и однократное декодирование route path. Пакет использует только standard library и не содержит gateway logic, sockets, SQL или RBAC. Проверки credentials, session state, budget, routing atomicity, сетевой совместимости и production security не реализованы.

Go 1.27.4; wire major 1 / minor 0. Minimum Go/backward compatibility и SDK/gateway N/previous-minor integration ещё не исследованы. Transport/storage dependencies и release SBOM ещё не выбраны/сформированы.

## Проверки HTTP start

Текущая сессия 2026-11-21, Linux amd64 / Go 1.27.4:

- SDK: `GOWORK=off GOPROXY=off go test ./...`, `go test -race ./...` и `go vet ./...` с теми же flags и отдельным временным GOCACHE — PASS. Внешние dependencies не добавлены.
- Golden request_start/response_start сохраняют все поля и порядок headers; negative fixture ordinary_101 отклоняется. Проверены missing/null/type/case/unknown fields, точные пары headers, JSON/extensions, stream ID/u64, method/Host/URI, HTTP token/CTL/hop-by-hop, Content-Length, byte/count/status границы. Оба новых decoder fuzz targets по 5 секунд — PASS; это короткий smoke fuzz, не release acceptance.
- Windows amd64: `go build ./...` и `go test -c` для `protocol/v1` с `GOWORK=off GOPROXY=off GOOS=windows GOARCH=amd64` — PASS. Native Windows runtime и remote CI не запускались.
- Fixture verifier в gateway и SDK, побайтовая сверка schema/fixtures — PASS. Wire-контракт и нормативные golden bytes не менялись. Verifier не заменяет полную JSON Schema validation.
- Проверка локальных путей и её 5 unit tests в каждом repository, отдельная проверка новых Go-файлов и `git diff --check` — PASS. При подготовке коммитов новые Go-файлы добавлены в индекс; tracked-files scanner повторно охватил их — PASS.

Codecs проверяют wire/HTTP metadata, но не authentication/authorization, production Host allowlist, negotiated limits/buffer reservations, полный размер сериализованного HTTP header block, body eligibility для HEAD/204/304, EOF/Content-Length соответствие или session transitions. Эти проверки остаются у будущих adapters/state machines; транспортная приёмка не выполнена.

## Проверки выделения SDK

Предыдущая сессия 2026-11-21: локальный fixture verifier — PASS; `go test -race ./...`, `go vet ./...`, `go list -m all` при `GOWORK=off GOPROXY=off` и отдельном временном GOCACHE — PASS, module graph содержит только SDK. Windows amd64 build и compile тестов `protocol/v1` — PASS с теми же flags и `GOOS=windows GOARCH=amd64` (cross-compile, без native runtime). Snapshot schema/fixtures побайтово совпадает с gateway и указанной в `contract-snapshot.md` revision. Формат Go, относительные Markdown links и `git diff --check` — PASS. Remote CI и native Windows runtime в этой сессии не проверялись; прежние fuzz/coverage результаты записаны в gateway status и не повторялись.
