# Snapshot контракта

Нормативный источник — gateway repository [solodyagin/outgate](https://github.com/solodyagin/outgate), [ТЗ](https://github.com/solodyagin/outgate/blob/main/docs/requirements.md) и [протокол](https://github.com/solodyagin/outgate/blob/main/docs/protocol.md).

Обновлённый snapshot от 2026-11-22: gateway revision `fb4d1986457375184a5469877568b07b074d9ace`. Schema и весь corpus скопированы побайтово; minor 1 добавляет negotiated QUIC quiescent fence, сохраняя прежние minor-0 bootstrap/control bytes. Это тестовые данные и schema, а не dependency на gateway.

При изменении контракта сначала согласуйте ТЗ, protocol/schema и golden corpus в gateway. Затем скопируйте schema и весь corpus в те же пути SDK, обновите source revision здесь и выполните verifier в обоих repositories, SDK race/vet и отдельный Windows compile. Нормативные fixtures нельзя менять только ради прохождения SDK tests.

Для соседних checkout выполните из корня gateway:

```bash
cmp docs/protocol.schema.json ../outgate-sdk/docs/protocol.schema.json
diff -r tests/fixtures/protocol/v1 ../outgate-sdk/tests/fixtures/protocol/v1
```

SDK tests используют только локальный snapshot; parent checkout, сеть, локальные replace и go.work не требуются. Python verifier выполняет sanity checks, а не полную JSON Schema validation или adapter integration.
