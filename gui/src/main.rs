fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([760.0, 720.0]),
        ..Default::default()
    };
    eframe::run_native(
        "vmkek",
        options,
        Box::new(|_cc| Ok(Box::new(Shell::default()))),
    )
}

#[derive(Default)]
struct Shell(vmkek_gui::App);

impl eframe::App for Shell {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ui, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| {
                vmkek_gui::view(ui, &mut self.0);
            });
        });
    }
}
