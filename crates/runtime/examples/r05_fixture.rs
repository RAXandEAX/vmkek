#[path = "../tests/common/mod.rs"]
mod common;

use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args_os().skip(1);
    let directory = args.next().ok_or("expected an output directory")?;
    if args.next().is_some() {
        return Err("expected exactly one output directory".into());
    }
    let directory = PathBuf::from(directory);
    let program = common::sample_program().encode()?;
    let descriptor = common::descriptor(&program, Default::default(), true).encode()?;
    std::fs::create_dir_all(&directory)?;
    std::fs::write(directory.join("r05_descriptor.bin"), descriptor)?;
    std::fs::write(directory.join("r05_program.bin"), program)?;
    Ok(())
}
