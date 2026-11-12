use crate::action::App;
use vmkek::i18n::Lang;

/// Draw the shell. Buttons call [`App::protect`], [`App::inspect`], and [`App::run`].
pub fn view(ui: &mut egui::Ui, app: &mut App) {
    let lang = app.lang;
    ui.heading("vmkek");
    language(ui, app);
    line(ui, text(lang, "input"), &mut app.input);
    line(ui, text(lang, "output"), &mut app.output);
    line(ui, text(lang, "seed"), &mut app.seed);
    block(ui, text(lang, "virtualize"), &mut app.virtualize);
    block(ui, text(lang, "mutate"), &mut app.mutate);
    ui.checkbox(&mut app.virtualize_all, text(lang, "virtualize-all"));
    ui.checkbox(&mut app.mutate_all, text(lang, "mutate-all"));
    line(ui, text(lang, "key"), &mut app.public_key);
    ui.horizontal(|ui| {
        if ui.button(text(lang, "protect")).clicked() {
            app.protect();
            ui.ctx().request_repaint();
        }
        if ui.button(text(lang, "inspect")).clicked() {
            app.inspect();
            ui.ctx().request_repaint();
        }
        if ui.button(text(lang, "open-report")).clicked() {
            app.open_report();
            ui.ctx().request_repaint();
        }
        if ui.button(text(lang, "run")).clicked() {
            app.run();
            ui.ctx().request_repaint();
        }
    });
    if !app.status.is_empty() {
        ui.label(app.status.as_str());
    }
    let name = ui.label(text(lang, "report"));
    ui.add(
        egui::TextEdit::multiline(&mut app.report)
            .interactive(false)
            .desired_rows(12)
            .desired_width(f32::INFINITY),
    )
    .labelled_by(name.id);
}

fn language(ui: &mut egui::Ui, app: &mut App) {
    egui::ComboBox::from_label(text(app.lang, "language"))
        .selected_text(match app.lang {
            Lang::En => "English",
            Lang::Ru => "Русский",
        })
        .show_ui(ui, |ui| {
            ui.selectable_value(&mut app.lang, Lang::En, "English");
            ui.selectable_value(&mut app.lang, Lang::Ru, "Русский");
        });
}

fn line(ui: &mut egui::Ui, caption: &str, text: &mut String) {
    let name = ui.label(caption);
    ui.add(egui::TextEdit::singleline(text).desired_width(f32::INFINITY))
        .labelled_by(name.id);
}

fn block(ui: &mut egui::Ui, caption: &str, text: &mut String) {
    let name = ui.label(caption);
    ui.add(
        egui::TextEdit::multiline(text)
            .desired_rows(3)
            .desired_width(f32::INFINITY),
    )
    .labelled_by(name.id);
}

fn text(lang: Lang, key: &str) -> &'static str {
    match (lang, key) {
        (Lang::Ru, "language") => "Язык",
        (Lang::Ru, "input") => "Вход",
        (Lang::Ru, "output") => "Выход",
        (Lang::Ru, "seed") => "Seed",
        (Lang::Ru, "virtualize") => "Виртуализация",
        (Lang::Ru, "mutate") => "Мутация",
        (Lang::Ru, "virtualize-all") => "Виртуализировать всё",
        (Lang::Ru, "mutate-all") => "Мутировать всё",
        (Lang::Ru, "key") => "Публичный ключ",
        (Lang::Ru, "protect") => "Защитить",
        (Lang::Ru, "inspect") => "Проверить",
        (Lang::Ru, "run") => "Запуск",
        (Lang::Ru, "open-report") => "Открыть отчёт",
        (Lang::Ru, "report") => "Отчёт",
        (Lang::En, "language") => "Language",
        (Lang::En, "input") => "Input",
        (Lang::En, "output") => "Output",
        (Lang::En, "seed") => "Seed",
        (Lang::En, "virtualize") => "Virtualize",
        (Lang::En, "mutate") => "Mutate",
        (Lang::En, "virtualize-all") => "Virtualize all",
        (Lang::En, "mutate-all") => "Mutate all",
        (Lang::En, "key") => "Public key",
        (Lang::En, "protect") => "Protect",
        (Lang::En, "inspect") => "Inspect",
        (Lang::En, "run") => "Run",
        (Lang::En, "open-report") => "Open report",
        (Lang::En, "report") => "Report",
        _ => "",
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use egui_kittest::kittest::Queryable;
    use egui_kittest::Harness;
    use vmkek::i18n::Lang;

    use super::view;
    use crate::App;

    struct TempPath(PathBuf);

    impl TempPath {
        fn new(name: &str) -> Self {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos();
            Self(
                std::env::temp_dir()
                    .join(format!("vmkek-g1-{name}-{}-{nanos}", std::process::id())),
            )
        }

        fn arg(&self) -> String {
            self.0.display().to_string()
        }

        fn report_json(&self) -> PathBuf {
            PathBuf::from(format!("{}.report.json", self.arg()))
        }
    }

    impl Drop for TempPath {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
        }
    }

    fn fill(harness: &mut Harness<'_, App>, label: &str, text: &str) {
        harness.get_by_label(label).click();
        harness.step();
        harness.get_by_label(label).type_text(text);
        harness.step();
        let value = harness.get_by_label(label).value().unwrap_or_default();
        assert_eq!(value, text, "{label}");
    }

    #[test]
    fn protect_sample_shows_report_and_matches_library() {
        let built = vmkek::sample::build().expect("sample");
        let input = TempPath::new("in");
        let output = TempPath::new("out");
        fs::write(&input.0, &built.bytes).expect("write sample");

        let mut harness = Harness::builder()
            .with_size(egui::vec2(960.0, 1400.0))
            .build_ui_state(view, App::default());
        fill(&mut harness, "Input", &input.arg());
        fill(&mut harness, "Output", &output.arg());
        fill(&mut harness, "Seed", "1");
        fill(&mut harness, "Virtualize", "compute");
        fill(&mut harness, "Mutate", "mix");

        harness.get_by_label("Protect").click();
        harness.run();

        let status = harness.state().status.clone();
        assert!(
            status.contains("protected image written"),
            "{status}\n{}",
            harness.state().report
        );
        let direct = vmkek::protect::protect(
            &built.bytes,
            &vmkek::protect::Options {
                virtualize: ["compute".to_string()].into(),
                mutate: ["mix".to_string()].into(),
                virtualize_all: false,
                mutate_all: false,
                seed: 1,
                random_key: false,
                debug_seed: false,
            },
        )
        .expect("direct protect");
        let written = fs::read(&output.0).expect("protected file");
        assert_eq!(written, direct.bytes);
        let pretty = serde_json::to_string_pretty(&direct.report).expect("json");
        assert_eq!(
            fs::read(output.report_json()).expect("report file"),
            pretty.as_bytes()
        );
        let shown = harness.get_by_label("Report").value().unwrap_or_default();
        assert_eq!(shown, pretty);
        assert!(shown.contains(&direct.report.public_key));
        assert!(shown.contains("compute"));
        let _ = fs::remove_file(output.report_json());
    }

    #[test]
    fn open_report_displays_legacy_without_legacy_strength_labels() {
        let report = TempPath::new("legacy-report");
        fs::write(&report.0, r#"{"claims":[{"pass":"mba","claim":"Proven"}]}"#).unwrap();
        let mut harness = Harness::builder()
            .with_size(egui::vec2(960.0, 1400.0))
            .build_ui_state(view, App::default());
        fill(&mut harness, "Input", &report.arg());
        harness.get_by_label("Open report").click();
        harness.run();
        let shown = harness.get_by_label("Report").value().unwrap_or_default();
        let json: serde_json::Value = serde_json::from_str(&shown).unwrap();
        assert_eq!(json["profile"], "legacy");
        assert_eq!(json["claims"][0]["pass"], "mba");
        assert_eq!(json["claims"][0]["status"], "pending");
        assert!(!shown.contains("Proven"));
        assert_eq!(
            fs::read_to_string(&report.0).unwrap(),
            r#"{"claims":[{"pass":"mba","claim":"Proven"}]}"#
        );
    }

    #[test]
    fn russian_labels_follow_the_language_field() {
        let mut harness = Harness::builder()
            .with_size(egui::vec2(960.0, 1400.0))
            .build_ui_state(view, App::default());
        harness.state_mut().lang = Lang::Ru;
        harness.run();
        harness.get_by_label("Защитить");
        harness.get_by_label("Проверить");
        harness.get_by_label("Запуск");
        harness.get_by_label("Отчёт");
        assert!(harness.query_by_label("Protect").is_none());
        assert!(harness.query_by_label_contains("Math").is_none());
        assert!(harness.query_by_label_contains("Crypto").is_none());
    }
}
