#[allow(dead_code)]
#[path = "../tests/common/mod.rs"]
mod common;
#[allow(dead_code)]
#[path = "../tests/common/r08.rs"]
mod r08;

use vmkek_protocol::lab::ScalarType;
use vmkek_protocol::Budgets;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let directory = std::env::args_os()
        .nth(1)
        .ok_or("expected an output directory")?;
    let directory = std::path::PathBuf::from(directory);
    let program = r08::addition(ScalarType::U64, false).encode()?;
    let budgets = Budgets {
        fuel: 64,
        ..Budgets::default()
    };
    std::fs::create_dir_all(&directory)?;
    for depth in [2, 3, 4] {
        let descriptor = r08::descriptor(&program, depth, budgets, false).encode()?;
        std::fs::write(directory.join(format!("r08_depth{depth}.bin")), descriptor)?;
    }
    std::fs::write(directory.join("r08_module.bin"), program)?;
    Ok(())
}
