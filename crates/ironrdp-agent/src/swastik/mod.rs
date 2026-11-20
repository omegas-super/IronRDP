//! `swastik-rdp`: an authorized credential-audit front end with terminal prompts and a
//! built-in loopback GUI, both backed by the shared `auth-check` engine.
//!
//! Both front ends produce the same [`RunConfig`], run the same scheduler, and write the same
//! structured reports. Credentials are read from operator-supplied files; there is no
//! wordlist, no password generation, and no cross-product of users and passwords.

#![allow(
    clippy::print_stderr,
    reason = "this binary reports operator-facing progress on stderr"
)]

pub(crate) mod config;
pub(crate) mod gui;
pub(crate) mod report;
pub(crate) mod run;

use clap::Parser as _;

use self::config::Cli;
use self::run::{execute, exit_code};

/// Entry point used by `src/swastik-rdp.rs`.
pub async fn run_cli() -> anyhow::Result<u8> {
    let cli = Cli::parse();
    if cli.gui() {
        gui::serve().await?;
        return Ok(0);
    }
    let config = cli.into_config()?;
    let (summary, _) = execute(config, None).await?;
    Ok(exit_code(&summary))
}
