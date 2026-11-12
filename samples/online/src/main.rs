#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod linux;

#[cfg(all(any(windows, target_os = "linux"), target_arch = "x86_64"))]
#[path = "windows.rs"]
mod native;

fn main() -> std::process::ExitCode {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    if std::env::args_os()
        .skip(1)
        .eq([std::ffi::OsStr::new("--observe-tracer")])
    {
        println!(
            "r21 tracer={:?}",
            vmkek_runtime::observations::linux::tracer_attachment()
        );
        return std::process::ExitCode::SUCCESS;
    }

    #[cfg(all(any(windows, target_os = "linux"), target_arch = "x86_64"))]
    return native::run();

    #[cfg(not(all(any(windows, target_os = "linux"), target_arch = "x86_64")))]
    {
        eprintln!("The Online sample client requires Windows or Linux x64.");
        std::process::ExitCode::from(2)
    }
}
