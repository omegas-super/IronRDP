//! `swastik-rdp`: an authorized credential-audit front end with a terminal mode and a
//! native Windows GUI, both backed by the shared `auth-check` engine.
//!
//! Both front ends produce the same [`RunConfig`], run the same scheduler, and write the same
//! structured reports. Credentials are read from operator-supplied files; there is no
//! wordlist, no password generation, and no cross-product of users and passwords.

#![allow(
    clippy::print_stderr,
    reason = "this binary reports operator-facing progress on stderr"
)]

pub(crate) mod config;
pub(crate) mod report;
pub(crate) mod run;

#[cfg(windows)]
mod native_gui;

use clap::Parser as _;
use core::cell::RefCell;
use std::io::IsTerminal as _;

use self::config::Cli;

thread_local! {
    static CLI: RefCell<Option<Cli>> = const { RefCell::new(None) };
}

fn cli() -> Cli {
    CLI.with(|slot| slot.borrow_mut().take().unwrap_or_else(Cli::parse))
}
use self::run::{cancellation_channel, execute, exit_code};

/// Handles the native GUI before a tokio runtime exists. The GUI owns its own runtime, so it
/// must not be created or dropped inside an async context.
pub fn run_gui() -> anyhow::Result<bool> {
    let cli = cli();
    let choose = !cli.gui() && !cli.no_gui() && !cli.has_mode_flags() && std::io::stdin().is_terminal();
    let open_gui = cli.gui() || (choose && launcher_choice()? == 1);
    CLI.with(|slot| *slot.borrow_mut() = Some(cli));
    if !open_gui {
        return Ok(false);
    }
    #[cfg(windows)]
    {
        native_gui::run()?;
        Ok(true)
    }
    #[cfg(not(windows))]
    {
        anyhow::bail!("the native GUI is available on Windows only")
    }
}

/// Entry point used by `src/swastik-rdp.rs` after GUI mode has been ruled out.
pub async fn run_cli() -> anyhow::Result<u8> {
    let config = cli().into_config()?;
    let (_controller, stop_rx) = cancellation_channel();
    let (summary, _) = execute(config, None, stop_rx).await?;
    Ok(exit_code(&summary))
}

/// Asks for the front end before any audit-specific prompts. `0` enters the terminal flow,
/// `1` opens the native window. A bare non-interactive invocation stays in terminal mode so
/// scripted use is unchanged.
fn launcher_choice() -> anyhow::Result<u8> {
    eprintln!("swastik-rdp:\n  0) CLI - terminal prompts\n  1) GUI - native window");
    use std::io::{IsTerminal as _, Write as _};
    let mut line = String::new();
    eprint!("choose 0 or 1 [0]: ");
    std::io::stderr().flush()?;
    if !std::io::stdin().is_terminal() {
        return Ok(0);
    }
    std::io::stdin().read_line(&mut line)?;
    match line.trim() {
        "" | "0" => Ok(0),
        "1" => Ok(1),
        other => anyhow::bail!("invalid launcher choice {other:?}; choose 0 or 1"),
    }
}
