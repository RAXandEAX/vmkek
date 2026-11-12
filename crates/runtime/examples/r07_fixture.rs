#[allow(dead_code)]
#[path = "../tests/common/mod.rs"]
mod common;
#[path = "../tests/common/r07.rs"]
mod r07;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let directory = std::env::args_os()
        .nth(1)
        .ok_or("expected an output directory")?;
    let directory = std::path::PathBuf::from(directory);
    let program = r07::module().encode()?;
    std::fs::create_dir_all(&directory)?;
    for form in r07::Form::ALL {
        let descriptor = form.descriptor(&program, Default::default(), 17).encode()?;
        std::fs::write(
            directory.join(format!("r07_{}.bin", form.name())),
            descriptor,
        )?;
    }
    std::fs::write(directory.join("r07_module.bin"), program)?;
    Ok(())
}
