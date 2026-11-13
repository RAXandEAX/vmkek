# Исправление O02-F001

В `src/obf/hard.rs` исправлены фрагмент «Hardness of the computation uses», описание ширины и документация поля `assumption`. Поле сохраняет прежнюю форму и теперь описано как текст об предпосылке или ограничении. Семантика кода и формат данных не изменены.

`cargo +1.95.0 test --locked --offline -p vmkek --lib obf::hard::` — 7 passed. `cargo +1.95.0 fmt --all -- --check` и `git diff --check` прошли.

## Исходный контроль нормализации

В `normalization-fixture.c` отдельно выписаны операции `hard::trunc_hash(PREIMAGE)`, тождество XOR с переменным ключом и умножение на 3 и его обратный множитель по модулю 2⁶⁴. Команда `clang-18 -O1 -S -emit-llvm normalization-fixture.c -o normalization-fixture.ll` на Ubuntu Clang 18.1.3 свела эти функции соответственно к `ret i64 65117` (0xfe5d), `ret i64 %0` и `ret i64 %0`.

Это контроль вручную переписанных беззнаковых выражений уровня C/LLVM с одной конкретной парой множителей. Он не проверяет сохранение flags, полноценный IR vmkek, выход PE/ELF или восстановление бинарника. Исходник и LLVM IR сохранены рядом. Диапазон остальных множителей и флагов покрывается отдельными тестами проекта, а не данным контролем.

SHA-256: hard.rs `492054be5eecc49abf4aecded2f20ac17d9a63d59b01fe0219f7b3d6d59dd538`; fixture C `80f6972483fd022042268ffa6fe8174915f02077dc536e6b31009d5c5ac9c9af`; LLVM IR `3547fcff3d5516d4d757b8433a3df1f5af7d28691d257adf61c1af2595858de0`.
