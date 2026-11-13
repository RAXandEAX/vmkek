# Исправление review 01

Base `4cd330d0ba73b6a912506c3c83c2ee1331af262d`. Candidate — рабочее дерево `/home/rax/vmkek-obfuscation-ecc`.

## O01-F001

В transfer исключения score_affine завершали всю серию до записи receipt. Добавлена классификация отдельной строки `timeout` или `error` с сохранением donor, target, числа запросов и elapsed. Выполнение следующих строк продолжается. Ответ кандидата, не являющийся массивом объектов, отклоняется с `ValueError` и учитывается как error.

Регрессионные тесты воспроизвели две ошибки transfer `TimeoutExpired` и `ValueError`, а также `TypeError` на JSON `null`. До патча все соответствующие проверки завершились ошибкой, после патча проходят. Проверяется сохранение всех строк и следующего результата.

## O01-F002

Manifest записывает Git HEAD либо `null`, версию Python и SHA-256 генератора. README поясняет, что HEAD не описывает незакоммиченные изменения. Проверка сравнивает digest с фактическим файлом и моделирует отсутствие Git. До исправления проверка завершалась `KeyError`.

## Проверки

`TMPDIR=/home/rax/.cache/codex-research/obfuscation-ecc-rust/tmp python3 -B -m unittest discover -s evaluation` — 34 passed. Печатаемые внутри тестов статусы error являются mock-сценариями. `git diff --check` прошёл.

Изменение измерительного кода требует нового эксперимента. Под systemd scope 60 секунд/8 ГиБ построен `/home/rax/.cache/codex-evaluation/ecc-01/affine-probe-fix01/`. Original и 10 protected baseline прошли, в fresh и transfer по 10 `hypothesis_match`, peak 22298624 bytes. Ограничения прежнего эксперимента по изоляции и классу модели сохраняются. Новый план `coverage-fix01.json` соответствует изменённому генератору.

Покрытие этапа остаётся частичным, как указано в review. Для закрытия findings и дальнейшего движения требуется отдельное полное review.

## SHA-256 candidate

```text
fa065c8287e730738e8cf1dce2cbec6121a56b5da79183137d9697a43f1f18af  evaluation/evaluate.py
7eebe44bb33076a86185f5d0c629604d0b094fecb319e4a00ff3ef7ed08b9520  evaluation/test_evaluate.py
3275ec00bb222016ab1bcde8d24ec79024f3dbbb68430dedbcc6ff3a80f0d129  evaluation/coverage_manifest.py
fdc7f624e38535f629376659addc3b4fc1ce4d762be6756c7f1ee0dc10ee7b9b  evaluation/test_coverage_manifest.py
6a7f69f4e4da9d460edeaa9fc77f5a368cae95ce14db5ca1ee998979177dd100  evaluation/README.md
08af19fd2a85a300faa64e18dd263bde88b8de9667d9306004609c445b56ac99  evaluation/affine_candidate.py
```
