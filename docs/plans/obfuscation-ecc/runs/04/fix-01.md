# Исправления O04-F001 и O04-F002

O04-F001: декларация `supported_region` теперь принимает `multiply_runtime` вместе с `add`, соответствуя C-фикстуре с переменным аргументом a. `multiply_const` явно отклоняется. Эта проверка декларации не выполняет анализ liveness Rust IR.

O04-F002: версия Clang проверяется на успешный код и непустую строку. Отсутствующий либо некорректный LLVM-файл, ошибка запуска и тайм-аут дают JSON с `error` и `INCONCLUSIVE`, ненулевой exit. При отсутствии исполняемого Clang статус `unavailable`. Разбор проверяет имена, завершённость и непустые тела трёх функций. Регрессия до исправления воспроизвела отсутствующий LLVM, неправильный заголовок, пустую версию и ошибку её получения.

Прошли 60 Python-тестов с user bus, включая 4 адресных. Строки mock error в stdout не являются результатами измерения. Отдельная проверка с `PATH=/nonexistent` вернула exit 1, unavailable и INCONCLUSIVE. `git diff --check` прошёл.

Новый эксперимент `/home/rax/.cache/codex-evaluation/ecc-04/normalization-fix01-final/result.json` вернул REJECT и all_equal=true для одной C-фикстуры на Clang 18.1.3. Он не оценивает native PE/ELF или поведение флагов.

SHA-256 script `5c0ae222db87f5650e574e5bd5a182ea5aed1c22e95aaffbb8a219c61072c6e0`, C `d51291161d97832a91228ad67c07bd62dd8c8a6277526b2bf194950846a00eec`, тестов `d308cdcff76c3764f41d981489e5eea59a3044e13d107e8ac923cdac81840dab`. Исторический implementation.md содержит прежнее имя декларации multiply_const, фактическое исправление описано здесь.
