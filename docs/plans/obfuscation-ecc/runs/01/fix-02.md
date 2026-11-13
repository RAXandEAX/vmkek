# Исправление review 03

O01-F003: семантический тест запускает настоящий affine_candidate.py через контролируемую замену вызова runner. Реальный runner остаётся fail-closed при недоступности systemd и проверяется отдельными интеграционными тестами. Добавлена проверка ScopeFailure при unsupported. До исправления test_declared_affine_hypothesis завершался ScopeFailure без user bus.

O01-F005: manifest и успешный receipt scoring содержат SHA-256 owned_scope.py. Регрессионные проверки ранее падали с KeyError. Новый coverage-fix02.json привязан к текущему runner и существующему baseline.

O01-F006: child вызывает os.chdir(root) до применения Landlock. Контроль cwd внутри реального systemd-run ранее показал /home/rax, после изменения — временный каталог vmkek-scope-*. Интеграционная проверка Landlock продолжает проходить.

Проверки: с рабочей user bus `python3 -B -m unittest discover -s evaluation` завершён успешно, 42 теста. При заведомо недоступной bus тот же набор из 42 тестов завершился с 9 пропущенными интеграционными subtests. Mock-сценарии печатают error внутри успешных unittest. `git diff --check` прошёл.

O01-F004 остаётся открытым и передан отдельно. Реальный affine experiment после изменения runner не переиздавался из-за известного расхождения batch scope; старые результаты сохраняют свои исходные условия.
