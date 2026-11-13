# ECC Rust review 05

Полное review снимка этапа 01 относительно `4cd330d0ba73b6a912506c3c83c2ee1331af262d` завершено. Для согласованной ограниченной опорной серии новых замечаний нет. Все семь findings закрыты.

## Закрытие замечаний

- **O01-F001 и O01-F002 · CLOSED.** Новый per-cell путь сохраняет статусы отдельных строк, а манифест привязан к Git HEAD, Python и фактическому генератору. Ошибочная legacy ветка удалена.
- **O01-F003, O01-F005 и O01-F006 · CLOSED.** Семантические тесты не требуют systemd, фактический код runner хэшируется и рабочий каталог дочернего процесса проверяется интеграционным тестом.
- **O01-F004 · CLOSED.** Независимо проверен CLI `evaluate.py build --affine-probe`. Завершился с кодом 2, перенаправил к per-cell измерению и не создал выходную директорию. Старые batch peak и lifecycle удалены из актуального пути. README описывает отдельные ресурсы fit и scorer.
- **O01-F007 · CLOSED.** Отсутствующий и неверно сформированный SHA-256 наблюдений отклоняются при разборе ответа worker. Проверка подтверждает отдельный `error` без запуска scoring.

## Проверки

- `python3 -B -m unittest discover -s evaluation` с рабочей user bus: 46 тестов, код выхода 0, без пропусков. `git diff --check` прошёл. Rust-файлы не изменены. Сохранены результаты Rust CI и нативного Windows контроля.
- `/home/rax/.cache/codex-evaluation/ecc-01/cells-fix04-{60,600,3600}.json` проверены против `all-fixtures/baseline.json`, фактических target/donor ELF, pack и четырёх файлов реализации. В каждой серии исходный контроль, 10 fresh и 10 transfer дали `hypothesis_match`. У transfer 0 target queries. Максимум наблюдаемого времени строки по трём сериям — 0,2673 секунды.
- `coverage-fix04.json` соответствует текущим исходным SHA-256 и генератору. В плановой матрице 4320 строк `not_run` общего восстановления. Эти записи сосуществуют с отдельными выполненными affine receipts.

## Область принятия

Ограниченная опорная серия пригодна для последующих сравнений с тем же oracle, зафиксированной affine-гипотезой и проверенным периметром. 24 исходных и 240 защищённых ELF подтверждают функциональную корректность на выбранном корпусе. Нативный PE T4 проверяет исполнение и SEH. Поддерживаемая ELF affine серия использует три настроенных лимита и отдельно измеренные ресурсы служб. Родительский orchestration исключён из пиков памяти служб. Произвольное восстановление, PE recovery и общие бинарные адаптеры остаются непокрытыми. Эти ограничения сопровождают дальнейшее использование измерений.

## SHA-256 проверенного снимка

```text
2b346ab4c033b3de9ddb9d9c19aa837483f617ef44f48e3e7f9d54c91b0a7b8c  evaluation/README.md
08af19fd2a85a300faa64e18dd263bde88b8de9667d9306004609c445b56ac99  evaluation/affine_candidate.py
d06edb83dcfd86d5f024cc9fd8315bf52142826ff08aa791c9bd4ad8ece43fd8  evaluation/affine_cells.py
70f0a9baa7fdb32ba9d5bcbf2cb3dae60b9bbf5e44a7ffba8ae1c9ca9f3df147  evaluation/coverage_manifest.py
ce2e5f2415ba54111849ce3c9f462e71136b425177c01e2fe57c85aa60b19190  evaluation/evaluate.py
48871230ccb7cd0c8cefce372dbb916f88bf1cfc817e40f37a236e4a335c7571  evaluation/owned_scope.py
a1757b8f11408dd4f366e0a8c0ad4d6e1e437c5f79edc35d6789ec47b2026b57  evaluation/test_affine_cells.py
e47974a423a6979322bb31017e53e3a541f32f0a7f82bb8ecc2c2a99fd9026cc  evaluation/test_coverage_manifest.py
c133f41f31b774c32c2956d33fdd15b1bad9025dd81a7f5231f13b6e227821f9  evaluation/test_evaluate.py
ef06624abb6b6eff0df9dfa1f7e984acf703644dcc82b159a7404962fedd63cf  evaluation/test_owned_scope.py
```

