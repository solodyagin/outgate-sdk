# Snapshot контракта

Нормативный источник — gateway repository [solodyagin/outgate](https://github.com/solodyagin/outgate), [ТЗ](https://github.com/solodyagin/outgate/blob/main/docs/requirements.md) и [протокол](https://github.com/solodyagin/outgate/blob/main/docs/protocol.md).

Начальный snapshot от 2026-11-21: gateway revision `5d3635cf1f0e64ee0af9dd5d504877a35b8f276c`. `docs/protocol.schema.json` и весь `tests/fixtures/protocol/v1/` (включая verifier) скопированы побайтово из этой ревизии; wire-контракт при выделении SDK не менялся. Это тестовые данные и schema, а не dependency на gateway.

При изменении контракта сначала согласуйте ТЗ, protocol/schema и golden corpus в gateway. Затем скопируйте schema и весь corpus в те же пути SDK, обновите source revision здесь и выполните verifier в обоих repositories, SDK race/vet и отдельный Windows compile. Нормативные fixtures нельзя менять только ради прохождения SDK tests.

Для соседних checkout выполните из корня gateway:

```bash
cmp docs/protocol.schema.json ../outgate-sdk/docs/protocol.schema.json
diff -r tests/fixtures/protocol/v1 ../outgate-sdk/tests/fixtures/protocol/v1
```

SDK tests используют только локальный snapshot; parent checkout, сеть, локальные replace и go.work не требуются. Python verifier выполняет sanity checks, а не полную JSON Schema validation или adapter integration.
