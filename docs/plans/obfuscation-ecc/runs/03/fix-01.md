# Исправления O03-F001–F003

O03-F001: исследовательский `research_arithmetic_solver.py` получает сырые ответы Z3 и выдаёт нейтральный JSON с версией и списком ответов. `research_arithmetic.py` принимает только полный объект с точными ответами `unsat, unsat, sat` и кодом 0, затем называет их соответственно general equivalence, alias equivalence и negative control. Неполный или лишний ответ, unknown и ошибка не допускают правило. Production R06 checker не изменён.

O03-F002: тесты Clang и libz3 пропускаются при отсутствии соответствующих инструментов. Отсутствие Clang в эксперименте сохраняет C-файл и JSON с `normalization_status=unavailable`, `decision=INCONCLUSIVE` и ненулевым кодом выхода. Ошибки и тайм-ауты обозначаются отдельно как error. Подменённые сценарии отсутствия Clang и неполного ответа воспроизвели проблему до исправления.

O03-F003: seed-разбиение названо group_a/group_b; в JSON прямо указано, что обе группы относятся к одной формуле и не являются независимыми функциями или transfer.

Проверки: 7 профильных тестов прошли с Clang/libz3. При `PATH=/nonexistent` профильные тесты завершились с одним skip Clang, остальные прошли. Полный набор `python3 -B -m unittest discover -s evaluation` — 56 passed с доступной user bus. `git diff --check` прошёл.

Повторный эксперимент `/home/rax/.cache/codex-evaluation/ecc-03/arithmetic-fix01/result.json` проверил 20 seed и получил REJECT, `all_match_baseline=true`. Это результат для одной исследовательской композиции на уровне исходных выражений, не результат на PE/ELF. Старое описание `implementation.md` и предыдущие артефакты относятся к историческому runner и должны читаться вместе с этим исправлением.

SHA-256: research_arithmetic.py `6442a6efebd0354449c9427bb7092c63f387e490333be8701c2ea1727448f8a0`; research_arithmetic_solver.py `b00098fde0006adc2a78437ed399329636c7e313a2e9e74a92cf69e82cda8cc5`; test_research_arithmetic.py `02042d5584c0288a55af08cd7751f642ec6458774d55a0b5e0ed17cb527002a7`.
