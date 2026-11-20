// Purpose-built interactive credential-check binary.
#![allow(unused_crate_dependencies)]
#![expect(
    clippy::print_stderr,
    reason = "a binary must report a startup failure before returning an exit code"
)]

#[tokio::main]
async fn main() -> anyhow::Result<std::process::ExitCode> {
    match ironrdp_agent::swastik::run_cli().await {
        Ok(code) => Ok(std::process::ExitCode::from(code)),
        Err(error) => {
            eprintln!("swastik-rdp: {error:#}");
            Ok(std::process::ExitCode::from(2))
        }
    }
}
