#[cfg(unix)]
#[path = "../fixture/mod.rs"]
mod fixture;

#[cfg(unix)]
#[tokio::main(flavor = "current_thread")]
async fn main() -> std::process::ExitCode {
    match fixture::run().await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("r18-fixture: {error}");
            std::process::ExitCode::from(1)
        }
    }
}

#[cfg(not(unix))]
fn main() -> std::process::ExitCode {
    eprintln!("The R18 fixture requires Unix and a private PostgreSQL socket.");
    std::process::ExitCode::from(2)
}
