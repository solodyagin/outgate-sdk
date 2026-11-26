# Зависимости SDK

`protocol/v1`, `wssstate`, `sessionstate` и `httpsig` используют только Go standard library. `transport/quiccontrol` использует `github.com/quic-go/quic-go v0.65.0`, закреплённую после reverse HTTP/3 spike gateway. HTTP/3 включён в интеграционные тесты carrier. Минимальная версия Go пока не исследована; текущая проверяемая версия — 1.27.4.

| Модуль | Версия | Лицензия |
| --- | --- | --- |
| github.com/quic-go/quic-go | v0.65.0 | MIT |
| github.com/quic-go/qpack | v0.6.0 | MIT |
| golang.org/x/crypto | v0.59.0 | BSD-3-Clause |
| golang.org/x/net | v0.63.0 | BSD-3-Clause |
| golang.org/x/sys | v0.50.0 | BSD-3-Clause |
| golang.org/x/text | v0.44.0 | BSD-3-Clause |
| modernc.org/sqlite | v1.62.0 | BSD-3-Clause, вложенные уведомления в `third-party/` |
| modernc.org/libc | v1.80.1 | BSD-3-Clause, вложенные уведомления в `third-party/` |

Пакет [`replay`](../replay/README.md) использует pure-Go SQLite с движком 3.54.1. Драйвер и libc совпадают с версиями, закреплёнными в проверках gateway. Собранные модули и соответствующие лицензии Linux/Windows перечислены в SBOM. [SQLite 3.54.1](https://sqlite.org/releaselog/3_54_1.html)

Версии `x/net` и `x/crypto` сохраняют security pins gateway, превышающие минимумы quic-go. Module graph не содержит reverst, gateway или локальных replace. [go.sum](../go.sum) фиксирует checksum, [CycloneDX SBOM](sbom.cdx.json) — объединённый compiled test inventory Linux/Windows amd64 и Go standard library. Это inventory SDK tests, не SBOM будущего release binary. Лицензии модулей и Go сохранены в `third-party/`; runtime binary потребует отдельной проверки своего графа и вложенных уведомлений Go/зависимостей.

Первая загрузка dependencies и vulnerability database требует сети. После заполнения module cache проверки можно выполнять с `GOPROXY=off`. Standard-library пакеты сохраняют offline-проверку без загрузки transport modules:

```bash
GOWORK=off GOPROXY=off go test ./protocol/v1 ./wssstate ./sessionstate ./httpsig
```

Проверка полного SDK:

```bash
GOWORK=off go mod verify
GOWORK=off go test -race ./...
GOWORK=off go vet ./...
python3 -B tests/verify_sbom.py
GOWORK=off go run golang.org/x/vuln/cmd/govulncheck@v1.10.0 -test ./...
```

На Windows используются те же commands без POSIX assignments: задайте `$env:GOWORK = 'off'`. SBOM verifier сверяет native compiled test modules с pinned inventory и checksums; при обновлении зависимостей inventory и лицензии пересматриваются явно. Cross-compile не заменяет native platform acceptance.
