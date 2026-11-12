# Contributing

[Русский](#русский)

Describe the format, architecture, profile, and expected behavior before proposing a change to the binary pipeline. A small synthetic input and its expected output are usually enough to reproduce a problem. Keep private samples, keys, and memory dumps out of public issues and pull requests.

For Rust changes, run formatting, all-target checks, Clippy, and the workspace tests with Rust 1.95.0. Add the native test command and the observed result if the change affects a live platform. The [architecture notes](docs/architecture.md#evidence) explain the evidence labels.

For contributed code that vmkek will offer under both licensing options, the maintainer must obtain a separate written grant covering both options before merging. Include any existing third-party notices with a contribution.

## Русский

В отчёте об ошибке укажи формат, архитектуру, профиль и ожидаемое поведение. Для воспроизведения лучше приложить небольшой синтетический пример и ожидаемый результат. Приватные бинарники, ключи и дампы памяти храни отдельно от публичных обсуждений.

Для изменений Rust запусти форматирование, проверку всех целей, Clippy и тесты workspace на Rust 1.95.0. Для изменений нативного пути приложи команду и фактический результат прогона. [Как оформляем результаты](docs/architecture.ru.md#evidence)

Для вклада, который vmkek будет распространять на обоих условиях, до слияния нужно письменное разрешение на оба варианта. Приложи к вкладу уведомления о лицензиях стороннего кода, если он есть.
