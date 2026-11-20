// Purpose-built interactive credential-check binary.
#![allow(unused_crate_dependencies)]
#![expect(
    clippy::print_stderr,
    reason = "a binary must report a startup failure before returning an exit code"
)]

fn main() -> anyhow::Result<std::process::ExitCode> {
    // The native GUI owns a multi-thread tokio runtime and must be created before this
    // process enters an async context.
    if let Some(code) = ironrdp_agent::swastik::run_gui()? {
        return Ok(std::process::ExitCode::from(code));
    }
    run_cli()
}

#[tokio::main]
async fn run_cli() -> anyhow::Result<std::process::ExitCode> {
    match ironrdp_agent::swastik::run_cli().await {
        Ok(code) => Ok(std::process::ExitCode::from(code)),
        Err(error) => {
            eprintln!("swastik-rdp: {error:#}");
            Ok(std::process::ExitCode::from(2))
        }
    }
}
