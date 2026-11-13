# Исправление O02-F002

Документация `ChannelColor` теперь описывает red как неподтверждённое утверждение, а `anchor` — как тест свойства, тест ограничения или причину отсутствия проверки. Это соответствует red Crypto с выполненным тестом ограничения и red System с невыполненной проверкой. Код и схема не изменены.

`cargo +1.95.0 fmt --all -- --check` прошёл. `cargo +1.95.0 test --locked --offline -p vmkek --lib obf::hard::` — 7 passed. `git diff --check` прошёл.

SHA-256 `src/obf/hard.rs`: `1cfd0f4b1f59ab2463fb87d5bf74d1e650cb702eda2b1f376c772cadf66a1ae2`.
