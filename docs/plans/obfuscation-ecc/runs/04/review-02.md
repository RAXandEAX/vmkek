# ECC Rust review 02 — этап 04

**COMPLETE + REJECT** для измеренного offset-кандидата. Оба замечания закрыты. Новых замечаний в трёх файлах этапа нет.

- **O04-F001 · CLOSED.** Декларация `multiply_runtime` соответствует переменному `a` в C. `multiply_const` отклоняется тестом. Декларация ограничивает постановку эксперимента. Реальная оценка liveness Rust IR в этот контроль не входит.
- **O04-F002 · CLOSED.** Пустая версия, ошибочный выход версии, отсутствующий или повреждённый LLVM дают структурированный `error` и решение `INCONCLUSIVE`. Четыре адресных теста независимо прошли. Сверен отдельный фактический результат без доступного Clang, где записано `unavailable` и `INCONCLUSIVE`.

## Проверенное измерение

В `/home/rax/.cache/codex-evaluation/ecc-04/normalization-fix01-final/` проверены SHA-256 исходника C, скрипта и LLVM IR. SHA-256 `result.json`: `0f4699bbf19769b7acc30c1988dff97655881a8f9b7ab6df311b6b3248e24cf9`. Независимый запуск Clang 18.1.3 воспроизвёл `normalized.ll` побайтно. Три тела совпадают: wrapping add, mul и return. Три C-реализации дали одинаковый результат на 1625 наборах операндов по независимому oracle.

Результат отклоняет эту конкретную композицию на уровне C/LLVM. Флаги, память, production lowering, несколько выходов региона и стойкость PE/ELF остаются за пределами измеренной серии.

## SHA-256 проверенных файлов

```text
5c0ae222db87f5650e574e5bd5a182ea5aed1c22e95aaffbb8a219c61072c6e0 evaluation/research_data_encoding.py
d51291161d97832a91228ad67c07bd62dd8c8a6277526b2bf194950846a00eec evaluation/research_data_encoding.c
d308cdcff76c3764f41d981489e5eea59a3044e13d107e8ac923cdac81840dab evaluation/test_research_data_encoding.py
```

