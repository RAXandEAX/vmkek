# ECC Rust review 03

Вердикт **FIX_REQUIRED**. Полный diff этапа 01 проверен относительно `4cd330d0ba73b6a912506c3c83c2ee1331af262d`. В него входят восемь файлов `evaluation/` и ноль Rust-файлов. O01-F001 и O01-F002 остаются закрытыми по отношению к своим исходным критериям.

## Проверки

- Обычный `python3 -B -m unittest discover -s evaluation` в WSL без адреса пользовательской шины завершился с одной ошибкой и восемью пропусками. С `XDG_RUNTIME_DIR=/run/user/1000` и `DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus` все 40 тестов прошли. Это включает малые контрольные timeout и OOM с потомками, проверку cgroup и Landlock.
- `git diff --check` прошёл. Результаты Rust CI сохранены оркестратором в `rust-gates.json`. Windows PE T4 и 37 native unit tests подтверждены в предыдущем раунде.
- Прочитан исходный `all-fixtures/baseline.json`. В нём 24 исходных контроля и 240 защищённых строк `pass`.
- Проверены 21 совпадение `hypothesis_match`, SHA-256 кандидата, donor и target ELF в `/home/rax/.cache/codex-evaluation/ecc-01/affine-probe-isolated/`. Все transfer указали ноль запросов к целевой сборке.

## Открытые замечания

### O01-F003 HIGH · Обычные тесты теперь зависят от пользовательской шины systemd

`evaluation/test_evaluate.py:355`, `evaluation/evaluate.py:478`. Семантический тест вызывает настоящий runner и падает с `ScopeFailure: Failed to connect to bus`, если стандартный WSL или CI запуск не предоставляет пользовательскую шину. Соседние интеграционные тесты при таком ограничении пропускаются. До runner тот же семантический тест работал в обычном окружении. Проверить чистый запуск без `DBUS_SESSION_BUS_ADDRESS` и `XDG_RUNTIME_DIR`. Проверку oracle и классификации сделать независимой от systemd, сохранить интеграционный тест для поддерживаемой среды. Производственный scoring должен оставаться fail-closed.

### O01-F004 HIGH · Batch scope не включает кандидата и его потребление ресурсов

`evaluation/owned_scope.py:52–56`, `evaluation/evaluate.py:469–473` и `affine_probe`. `systemd-run --user` создаёт service в `app.slice` рядом с внешним scope серии. Контрольный Python-процесс распечатал свой `/proc/self/cgroup` из внешнего scope и из runner. Результаты оканчиваются на `app.slice/run-….scope` и `app.slice/vmkek-eval-….service` соответственно. Пик внешнего scope исключает процессы scoring, хотя receipt называет его batch peak. Остановка внешнего scope не включает sibling service. В его собственном unit работают отдельные лимиты.

Критерий закрытия — либо запускать scoring внутри реально общего ограничителя с проверкой родства cgroup и остановки, либо поменять протокол так, чтобы лимиты и измерения относились к фактической области, и не оставлять отдельный scoring после истечения общего срока. Сумма раздельных пиков не заменяет измеренный агрегат. Обновить доказательства после изменения протокола.

### O01-F005 MEDIUM · Evidence не фиксирует код нового runner

`evaluation/coverage_manifest.py:38–39` и receipt из `evaluation/evaluate.py:487–492`. Хэширование входов включает evaluate и кандидата, но исключает `owned_scope.py`, определяющий наблюдаемые лимиты и правила изоляции. Незакоммиченная замена этого файла при том же HEAD и хэшах остальных входов не меняет привязку инструмента. Критерий закрытия — записать SHA-256 фактического runner в manifest и receipt изоляции. Проверить хэш по файлу и обновить evidence.

### O01-F006 LOW · Runner не меняет рабочий каталог, хотя README обещает свежий

`evaluation/owned_scope.py:52–56`, `evaluation/README.md:94–95`. Отдельный временный каталог используется для stdin/stdout/stderr. `WorkingDirectory` или `chdir` отсутствует. Контроль `import os; print(os.getcwd())` внутри runner вернул `/home/rax`. Критерий закрытия — действительно задать временный cwd либо явно описать фактический рабочий каталог и ограничения. При изменении поведения добавить адресный контроль cwd.

## Границы результата

Текущая бинарная серия оценивает одну заранее заданную арифметическую модель на ELF при бюджете 60 секунд. Синтез, taint и slicing широкого корпуса, PE recovery и фактические эксперименты 600/3600 остаются за пределами выполненного покрытия. 24×10 подтверждает корректность native ELF относительно oracle. PE T4 проверяет совместимость исполнения. Код runner принимает три предусмотренных бюджета и интеграционные тесты проверили их конфигурацию. Выполненная серия не измеряет результаты трёх долгих экспериментов. Необеспеченная широкая матрица остаётся явно помеченной в плане.

## SHA-256 проверенных файлов

```text
ec5409117151d06ad3bb1f6d6e79f1339e51b8edfec2970370922ae9ddc7794a evaluation/README.md
08af19fd2a85a300faa64e18dd263bde88b8de9667d9306004609c445b56ac99 evaluation/affine_candidate.py
3275ec00bb222016ab1bcde8d24ec79024f3dbbb68430dedbcc6ff3a80f0d129 evaluation/coverage_manifest.py
58f9705d4fb44e0dad248de7348b7ccd5d8984d7433ef247a33640bc644d699d evaluation/evaluate.py
b8dfe709b475820cc62c982f69f6613874dafa74a7cf5aeb0f11ea22f82bc830 evaluation/owned_scope.py
fdc7f624e38535f629376659addc3b4fc1ce4d762be6756c7f1ee0dc10ee7b9b evaluation/test_coverage_manifest.py
7a2afd82bea03960e55fa97cb8ae6bb292a5f16bab5a0d0bb7b408a203f92bfe evaluation/test_evaluate.py
e73009532aad8565ab87e36cecf427e4581e1fc1382e9291dad19e99e669dc3c evaluation/test_owned_scope.py
```
