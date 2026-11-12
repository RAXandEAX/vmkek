fn main() {
    #[cfg(not(kani))]
    {
        let code = vmkek::cli::execute_from_env();
        std::process::exit(code);
    }
}
