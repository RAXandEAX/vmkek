# Этап 08. Квалификация выбранных путей Windows и Linux

Снимок базируется на коммите `4cd330d0ba73b6a912506c3c83c2ee1331af262d`. Точное Git-дерево `270ce09eeb1dd7e4046424ce04d4eac0e9a9cf54` и SHA-256 26 изменённых исходных и исследовательских файлов зафиксированы в [accepted-source-tree.json](accepted-source-tree.json) и [source-manifest.json](source-manifest.json). Production CLI собран в WSL2 с Rust 1.95.0. Его SHA-256 `3687a7f15308a4a57d56389cbe0f2e7ffdeb05d783658f6201598923c1e8ebf5`, trusted ELF helper `6e4d0c851a268c4e0a6bee4fff190c54dedc50098f86b07fc3e555f48015e01d`.

## Платформенная матрица

| Профиль и проверка | Результат | Предел |
| --- | --- | --- |
| Windows x64, native PE, T4 SEH | PASS | Исходный, защищённый leaf-контроль и защищённая целевая функция, seed 7 |
| Windows x64, native PE, T5 | PASS | Потоки и фактически активные ACG/CFG/CET на данном хосте |
| Windows x64, native PE, T5-Reentry | PASS | Четыре потока и callback повторно входят в виртуализированную функцию |
| Windows x64, native PE, T5-CFG | PASS | Релокация и реальная CFG-политика на зафиксированных фикстурах |
| Windows native `vmkek-protocol` и `vmkek-runtime` | 37 PASS, 12 ignored | Ignored сценарии требуют отдельных стендов, см. `ecc-stage08-windows-rust.log` |
| Linux ELF authenticated Lab | 2 PASS | Два ignored-by-default интеграционных теста с абсолютным путём доверенного helper, `elf-auth-retry.log` |
| Linux workspace | 657 PASS, 33 ignored | 60 групп, полный вывод `cargo-test.log` |
| Python evaluation | 60 PASS | Для доступного user systemd bus, детали в `python-tests.log` |
| Linux LLVM/solver/DFSan source controls | Проходили на этапе 01 | Результаты выполнялись на фиксированных исходных фикстурах |

Нативные PE собраны MSVC 14.44.35207 и исполнены в Windows 11 build 26300. Генерация выполнялась CLI в WSL2. Отчёт `windows.json` содержит SHA-256, размеры и размещение всех артефактов и журналы `ecc-stage08.log`, `ecc-stage08-windows-rust.log`. Проверка флагов ACG/CFG/CET проводилась для активного процесса, состояния других хостов не выводятся из неё. Собственная нативная сборка CLI под Windows на исходной версии оказалась недоступна из-за Unix API в `src/agent/serve.rs`, квалификация PE использует WSL CLI и нативное выполнение Windows fixture.

`cargo fmt --all -- --check`, `cargo check --workspace --all-targets --locked --offline` и `cargo clippy --workspace --all-targets --locked --offline -- -D warnings` завершились успешно. Rust tests запущены с `CARGO_BUILD_JOBS=4`, Rust 1.95.0, отдельным постоянным TMPDIR и Cargo target.

Предыдущий вызов ignored ELF тестов указал некорректный путь helper и завершился ошибкой. Лог `elf-auth.log` оставлен для трассировки. Следующий вызов использовал абсолютный путь и оба теста прошли, см. `elf-auth-retry.log`.

## Принятые решения этапов

- 01 — ограниченный независимый baseline. Состояние и область зафиксированы в `../01/review-05.md`.
- 02 — функциональные IR-абляции и нативная ELF серия двух функций. Изменение порядка расхода RNG и OS entropy ограничивает причинный вывод, см. `../02/review-04.md`.
- 03 — `REJECT` для исследованной арифметической композиции, нормализованной Clang. `../03/review-02.md`.
- 04 — `REJECT` для одной C-фикстуры кодирования. `../04/review-02.md`.
- 05 — `INCONCLUSIVE` для отдельной модели обработчиков. `../05/review-01.md`.
- 06 — `NOT_APPLICABLE` для композиции новых кандидатов, так как нет решения ADOPT. `../06/review-01.md`.
- 07 — `INCONCLUSIVE` для влияния уровней на стойкость. `../07/review-01.md`.

## Незакрытые области

Общая успешность независимого восстановления защищённых PE и ELF вне проверенной affine-гипотезы остаётся неизвестной. Оригинальная серия stage 01 выполнена на CLI с другим SHA и приводится как историческая. Финальная ELF-серия с текущим CLI содержит 24 исходных контроля и 240/240 защищённых функций с совпадением oracle. На этой же версии по каждому бюджету 60, 600 и 3600 секунд narrow affine fresh и transfer дали 10/10 совпадений. Файлы `elf-final-summary.json` и `cells-final-*.json` содержат хэши артефактов и результаты. Не измерены native recovery/transfer по всем семействам, PE recovery, физический Linux вне WSL, полная latency функций и пик памяти защищённых процессов. Результаты и решения отдельных исследований нельзя экстраполировать на произвольные программы.

Этот отчёт фиксирует ограниченное покрытие. Для полной квалификации всех заявленных в плане сценариев необходимо закрыть оставшиеся клетки либо явно ограничить область поддержки. Решение о финальном статусе принимает независимое review.

Все команды, коды завершения и хэши журналов сведены в [checks.json](checks.json).
