# Локальные проверки с кратким выводом

Из корня checkout (Python 3.12+, Go из `go.mod`):

```bash
python3 -B tests/check.py package ./delivery ./httpsig ./delegation
python3 -B tests/check.py contracts
python3 -B tests/check.py full
python3 -B tests/check.py full --plan
```

В Windows используйте `python` вместо `python3`. Скрипт работает и при запуске из другого каталога: команды выполняются от корня его repository. Он использует только Python standard library, всегда задаёт `GOWORK=off` и возвращает ненулевой exit code при первой неуспешной команде. Новых dependencies нет. CI по-прежнему выполняет существующие проверки; Python unit tests объединены в discovery `test_*.py`, включая тесты нового runner.

| Режим | Область |
|---|---|
| `package ./path [./other]` | Go tests и vet только явно перечисленных пакетов; на Linux tests с `-race` |
| `contracts` | Локальные protocol/discovery fixture verifiers; sanity checks, не полная schema validation |
| `full` | Contracts, все Python unit tests, tracked-path check, module integrity, SBOM, все Go tests/vet |
| `--plan` | Показать точные команды и рабочие каталоги без выполнения и создания логов |

На Linux `full` запускает race tests; на других ОС — обычные tests. Race detector требует подходящего C toolchain. При заполненном module cache можно задать `GOPROXY=off`; скрипт сохраняет это окружение. Первичная загрузка модулей может потребовать сеть.

Каждая команда пишет полный stdout/stderr в отдельный файл нового системного временного каталога. В консоли — начало и PASS/FAIL; при ошибке — последние до 20 строк из последних 8 КБ лога и его путь. Логи сохраняются после завершения: при необходимости найдите в них конкретный test/error через `rg`, не выводя всё содержимое. Временные каталоги удаляются вручную или системной очисткой; в публикуемых отчётах указывайте назначение лога без персональных путей.

## Что остаётся обязательным

- Во время реализации используйте целевой режим; перед завершением выполните обязательный набор из `AGENTS.md`. `package` не заменяет итоговые проверки, `full` не означает production/release acceptance.
- Для parser/wire изменений — негативные и граничные тесты, golden bytes, при необходимости fuzz; синхронизация контракта gateway/SDK остаётся отдельным шагом.
- Windows build и test compile выполняются отдельно с `GOWORK=off GOOS=windows GOARCH=amd64`, `go build ./...` и `go test -c` для затронутых пакетов с выводом в системный временный каталог. Native Windows runtime acceptance требует реального Windows запуска. Все платформенные статусы привязывайте к проверенному revision.
- Privacy scanner читает tracked файлы. Новые файлы отдельно просмотрите до добавления в Git; `full` сам не добавляет их в index. После staging scanner охватывает и их. Он ищет распространённые домашние пути, а не все персональные данные.
- Успешный прогон не нужно повторять без новых изменений, failures или неразрешённой неопределённости. В ответе достаточно области, результата и существенных ограничений; полные логи остаются для диагностики.

## Обязательные правила и прямые команды

- Проверки из корня SDK: `python3 tests/fixtures/protocol/v1/verify.py`, `GOWORK=off go mod verify`, `python3 -B tests/verify_sbom.py`, `GOWORK=off go test -race ./...`, `GOWORK=off go vet ./...`. Для parser изменений нужны негативные/граничные тесты, golden bytes и при необходимости fuzz targets.
- Проверка домашних путей в отслеживаемых текстовых файлах: `python3 -B tests/check_local_paths.py`; её тесты: `python3 -B -m unittest discover -s tests -p 'test_check_local_paths.py'`. Проверка выполняется в CI на Linux/Windows, читает рабочие версии файлов из `git ls-files` и сообщает только файл/строку. Новые файлы охватываются после добавления в Git. Это проверка распространённых форм домашних путей, не универсальный поиск персональных данных или проверка истории Git; прочие персональные и временные пути проверяйте при review.
- Windows compile проверяйте отдельно: `GOWORK=off GOOS=windows GOARCH=amd64 go build ./...`, для тестов `go test -c` с теми же flags и выводом в `/tmp`. Cross-compile не означает native Windows runtime-приёмку.
