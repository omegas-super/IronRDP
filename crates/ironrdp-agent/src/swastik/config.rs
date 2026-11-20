//! Startup configuration for `swastik-rdp`: CLI flags, interactive prompts and the
//! shared performance profile contract used by both the terminal and browser front ends.

use std::io::{IsTerminal as _, Write as _};
use std::path::{Path, PathBuf};

use anyhow::{Context as _, bail};
use clap::{Parser, ValueEnum};

use crate::auth_check::{controller, input};
use crate::performance;

/// Terminal/browser selection for how hard the checker pushes the machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum PerformanceProfile {
    /// Push every safe concurrency limit to the machine-derived ceiling.
    Max,
    /// Minimal load, for fragile links or small machines.
    Conservative,
    /// Spec-derived adaptive concurrency, starting conservatively.
    Balanced,
    /// Higher starting concurrency and per-host parallelism.
    Aggressive,
    /// Operator-specified limits and timeouts.
    Custom,
}

impl PerformanceProfile {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Max => "max",
            Self::Conservative => "conservative",
            Self::Balanced => "balanced",
            Self::Aggressive => "aggressive",
            Self::Custom => "custom",
        }
    }

    pub(crate) const fn menu() -> &'static str {
        "  0) MAX - push to the spec-derived ceiling\n  1) conservative - minimal load\n  2) balanced - adaptive, safe start\n  3) aggressive - higher concurrency\n  4) custom - exact limits"
    }

    /// Maps the menu number used by both front ends. `0` is MAX.
    pub(crate) fn from_menu(value: &str) -> anyhow::Result<Self> {
        match value.trim() {
            "0" | "max" => Ok(Self::Max),
            "1" | "conservative" => Ok(Self::Conservative),
            "2" | "balanced" => Ok(Self::Balanced),
            "3" | "aggressive" => Ok(Self::Aggressive),
            "4" | "custom" => Ok(Self::Custom),
            other => bail!("invalid performance choice {other:?}; choose 0-4"),
        }
    }

    /// Converts a profile into concrete scheduler limits. Every ceiling remains bounded by
    /// the machine profile; MAX does not disable resource limits or certificate validation.
    pub(crate) fn limits(
        self,
        system: performance::SystemProfile,
        unique_hosts: usize,
        custom: &CustomLimits,
    ) -> SchedulerLimits {
        let (adaptive_start, adaptive_max) = controller::plan_limits(
            system.logical_cpus,
            system.physical_cores,
            system.total_memory_mb,
            unique_hosts,
            custom.per_host,
        );
        match self {
            Self::Conservative => SchedulerLimits {
                start: 8.min(adaptive_max),
                max: 8.min(adaptive_max),
                per_host: 2.min(custom.per_host),
                pinned: true,
                worker_threads: usize::try_from(system.logical_cpus.clamp(1, 4)).unwrap_or(4),
            },
            Self::Balanced => SchedulerLimits {
                start: adaptive_start,
                max: adaptive_max,
                per_host: custom.per_host,
                pinned: false,
                worker_threads: worker_threads(system),
            },
            Self::Aggressive => SchedulerLimits {
                start: adaptive_max.min(64).max(adaptive_start),
                max: adaptive_max,
                per_host: custom.per_host.max(4),
                pinned: false,
                worker_threads: worker_threads(system),
            },
            Self::Max => SchedulerLimits {
                start: adaptive_max,
                max: adaptive_max,
                per_host: custom.per_host.max(8),
                pinned: false,
                worker_threads: worker_threads(system),
            },
            Self::Custom => SchedulerLimits {
                start: custom.concurrency.unwrap_or(adaptive_start),
                max: custom.concurrency.unwrap_or(adaptive_max),
                per_host: custom.per_host,
                pinned: custom.concurrency.is_some(),
                worker_threads: worker_threads(system),
            },
        }
    }
}

fn worker_threads(system: performance::SystemProfile) -> usize {
    usize::try_from(system.logical_cpus).unwrap_or(4).clamp(1, 16)
}

/// Concrete limits handed to the scheduler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SchedulerLimits {
    pub(crate) start: usize,
    pub(crate) max: usize,
    pub(crate) per_host: usize,
    pub(crate) pinned: bool,
    pub(crate) worker_threads: usize,
}

/// Values only meaningful for the custom profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CustomLimits {
    pub(crate) concurrency: Option<usize>,
    pub(crate) per_host: usize,
    pub(crate) timeout_ms: u64,
    pub(crate) connect_timeout_ms: u64,
    pub(crate) retries: u32,
}

impl Default for CustomLimits {
    fn default() -> Self {
        Self {
            concurrency: None,
            per_host: 8,
            timeout_ms: 10_000,
            connect_timeout_ms: 5_000,
            retries: 0,
        }
    }
}

/// One run, fully specified. Both the CLI and the browser UI produce this type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RunConfig {
    pub(crate) hosts: PathBuf,
    pub(crate) users: PathBuf,
    pub(crate) passwords: PathBuf,
    pub(crate) domains: Option<PathBuf>,
    pub(crate) output_dir: PathBuf,
    pub(crate) profile: PerformanceProfile,
    pub(crate) custom: CustomLimits,
    pub(crate) skip_certificate_check: bool,
    pub(crate) allow_multiple_passwords: bool,
    pub(crate) no_shuffle: bool,
    pub(crate) tune_system: bool,
    pub(crate) seed: Option<u64>,
}

impl RunConfig {
    pub(crate) fn validate(&self) -> anyhow::Result<()> {
        for (label, path) in [
            ("hosts", &self.hosts),
            ("users", &self.users),
            ("passwords", &self.passwords),
        ] {
            if path.as_os_str().is_empty() {
                bail!("{label} file must be provided");
            }
        }
        if self.output_dir.as_os_str().is_empty() {
            bail!("output directory must be provided");
        }
        if self.custom.retries > 2 {
            bail!("retries must be 0, 1, or 2 (pre-authentication failures only)");
        }
        if self.custom.concurrency.is_some_and(|limit| limit == 0) {
            bail!("concurrency must be positive");
        }
        if self.custom.per_host == 0 {
            bail!("per-host limit must be positive");
        }
        if self.custom.timeout_ms == 0 || self.custom.connect_timeout_ms == 0 {
            bail!("timeouts must be positive");
        }
        validate_output_dir(&self.output_dir)
    }
}

/// Reuses the same output contract for the terminal and browser paths: reports are never
/// overwritten by a later run, because silent overwrite can destroy the only good result.
pub(crate) fn validate_output_dir(dir: &Path) -> anyhow::Result<()> {
    if dir.exists() && !dir.is_dir() {
        bail!("{} is not a directory", dir.display());
    }
    for name in crate::swastik::report::FILE_NAMES {
        let path = dir.join(name);
        if path.exists() {
            bail!(
                "report already exists: {}; choose an empty output directory",
                path.display()
            );
        }
    }
    Ok(())
}

#[derive(Debug, Parser)]
#[command(
    name = "swastik-rdp",
    version,
    about = "Interactive RDP credential checker with a built-in local GUI"
)]
pub(crate) struct Cli {
    /// Start the built-in browser interface instead of terminal prompts.
    #[arg(long)]
    gui: bool,
    /// Host/IP list, one `ip[:port]` per line.
    #[arg(long, value_name = "FILE")]
    hosts: Option<PathBuf>,
    /// Usernames, one per line; paired line-wise with passwords.
    #[arg(long, value_name = "FILE")]
    users: Option<PathBuf>,
    /// Passwords, one per line; paired line-wise with usernames.
    #[arg(long, value_name = "FILE")]
    passwords: Option<PathBuf>,
    /// Optional domains, one per line; blank means no domain.
    #[arg(long, value_name = "FILE")]
    domains: Option<PathBuf>,
    /// Directory for goods.txt, bad.txt, errors.txt and summary.ndjson.
    #[arg(long, value_name = "DIR", default_value = "swastik-results")]
    output_dir: PathBuf,
    /// Performance profile: 0|max, 1|conservative, 2|balanced, 3|aggressive, 4|custom.
    #[arg(long, value_name = "PROFILE")]
    profile: Option<String>,
    /// Fixed global concurrency for custom runs; 0 keeps adaptive sizing.
    #[arg(long, default_value_t = 0)]
    concurrency: usize,
    /// Maximum simultaneous checks per host (default 8).
    #[arg(long, default_value_t = 8)]
    per_host: usize,
    /// Whole-check timeout in milliseconds.
    #[arg(long, default_value_t = 10_000)]
    timeout_ms: u64,
    /// TCP connect timeout in milliseconds.
    #[arg(long, default_value_t = 5_000)]
    connect_timeout_ms: u64,
    /// Retries for pre-authentication connectivity failures (0-2).
    #[arg(long, default_value_t = 0)]
    retries: u32,
    /// Accept invalid certificates; authorized test endpoints only.
    #[arg(long)]
    skip_certificate_check: bool,
    /// Allow multiple passwords for the same account (audit mode rejects them).
    #[arg(long)]
    allow_multiple_passwords: bool,
    /// Keep input order instead of a randomized execution order.
    #[arg(long)]
    no_shuffle: bool,
    /// Disable Windows ephemeral-port tuning even when elevated.
    #[arg(long)]
    no_tune_system: bool,
    /// Fixed shuffle seed for reproducible execution order.
    #[arg(long)]
    seed: Option<u64>,
}

impl Cli {
    pub(crate) fn gui(&self) -> bool {
        self.gui
    }

    /// Resolves flags first; missing items are only prompted for on an interactive terminal.
    pub(crate) fn into_config(self) -> anyhow::Result<RunConfig> {
        let profile = self.profile.as_deref().map(PerformanceProfile::from_menu).transpose()?;
        let mut config = RunConfig {
            hosts: self.hosts.unwrap_or_default(),
            users: self.users.unwrap_or_default(),
            passwords: self.passwords.unwrap_or_default(),
            domains: self.domains,
            output_dir: self.output_dir,
            profile: profile.unwrap_or(PerformanceProfile::Balanced),
            custom: CustomLimits {
                concurrency: (self.concurrency > 0).then_some(self.concurrency),
                per_host: self.per_host,
                timeout_ms: self.timeout_ms,
                connect_timeout_ms: self.connect_timeout_ms,
                retries: self.retries,
            },
            skip_certificate_check: self.skip_certificate_check,
            allow_multiple_passwords: self.allow_multiple_passwords,
            no_shuffle: self.no_shuffle,
            tune_system: !self.no_tune_system,
            seed: self.seed,
        };
        if std::io::stdin().is_terminal() && std::io::stderr().is_terminal() {
            prompt_missing(&mut config).with_context(|| "interactive configuration")?;
        }
        config.validate()?;
        Ok(config)
    }
}

fn prompt_missing(config: &mut RunConfig) -> anyhow::Result<()> {
    eprintln!("swastik-rdp: authorized credential audit (credentials you already hold)");
    config.hosts = prompt_file("hosts file (ip[:port] per line)", &config.hosts)?;
    config.users = prompt_file("users file (one per line)", &config.users)?;
    config.passwords = prompt_file("passwords file (one per line)", &config.passwords)?;
    if config.domains.is_none() {
        let answer = prompt_line("domains file (blank for none): ")?;
        config.domains = (!answer.is_empty()).then(|| PathBuf::from(answer));
    }
    eprintln!("performance profile:\n{}", PerformanceProfile::menu());
    let answer = prompt_line("choose 0-4 (blank keeps the current profile): ")?;
    if !answer.is_empty() {
        config.profile = PerformanceProfile::from_menu(&answer)?;
    }
    if config.profile == PerformanceProfile::Custom {
        config.custom.concurrency = prompt_optional_usize("global concurrency (blank = adaptive): ")?;
        config.custom.per_host = prompt_usize("per-host limit [8]: ", 8)?;
        config.custom.timeout_ms = prompt_u64("check timeout in ms [10000]: ", 10_000)?;
        config.custom.connect_timeout_ms = prompt_u64("connect timeout in ms [5000]: ", 5_000)?;
        config.custom.retries = prompt_u32("pre-auth retries 0-2 [0]: ", 0)?;
    }
    if config.output_dir.as_os_str().is_empty() {
        config.output_dir = PathBuf::from(prompt_line("output directory [swastik-results]: ")?);
    }
    Ok(())
}

fn prompt_file(label: &str, current: &Path) -> anyhow::Result<PathBuf> {
    if !current.as_os_str().is_empty() {
        return Ok(current.to_path_buf());
    }
    let answer = prompt_line(&format!("{label}: "))?;
    if answer.is_empty() {
        bail!("{label} is required");
    }
    Ok(PathBuf::from(answer))
}

fn prompt_line(label: &str) -> anyhow::Result<String> {
    eprint!("{label}");
    std::io::stderr().flush()?;
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .with_context(|| "read a line from standard input")?;
    if line.is_empty() {
        bail!("standard input closed before all options were provided");
    }
    Ok(line.trim_end_matches(['\r', '\n']).trim().to_owned())
}

fn prompt_optional_usize(label: &str) -> anyhow::Result<Option<usize>> {
    let answer = prompt_line(label)?;
    if answer.is_empty() {
        return Ok(None);
    }
    let value = answer.parse().with_context(|| format!("{answer:?} is not a number"))?;
    Ok((value > 0).then_some(value))
}

fn prompt_usize(label: &str, default: usize) -> anyhow::Result<usize> {
    let answer = prompt_line(label)?;
    if answer.is_empty() {
        return Ok(default);
    }
    answer.parse().with_context(|| format!("{answer:?} is not a number"))
}

fn prompt_u64(label: &str, default: u64) -> anyhow::Result<u64> {
    let answer = prompt_line(label)?;
    if answer.is_empty() {
        return Ok(default);
    }
    answer.parse().with_context(|| format!("{answer:?} is not a number"))
}

fn prompt_u32(label: &str, default: u32) -> anyhow::Result<u32> {
    let answer = prompt_line(label)?;
    if answer.is_empty() {
        return Ok(default);
    }
    answer.parse().with_context(|| format!("{answer:?} is not a number"))
}

/// Loads all four input files with the shared decoder (UTF-8, UTF-16, BOM).
pub(crate) fn load_inputs(config: &RunConfig) -> anyhow::Result<Vec<input::CheckTarget>> {
    let hosts = input::read_text(&config.hosts)?;
    let users = input::read_text(&config.users)?;
    let passwords = input::read_text(&config.passwords)?;
    let domains = config.domains.as_deref().map(input::read_text).transpose()?;
    input::parse_lists(&hosts, &users, &passwords, domains.as_deref())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> RunConfig {
        RunConfig {
            hosts: "hosts.txt".into(),
            users: "users.txt".into(),
            passwords: "passwords.txt".into(),
            domains: None,
            output_dir: "results".into(),
            profile: PerformanceProfile::Balanced,
            custom: CustomLimits::default(),
            skip_certificate_check: false,
            allow_multiple_passwords: false,
            no_shuffle: false,
            tune_system: true,
            seed: None,
        }
    }

    #[test]
    fn menu_accepts_zero_for_max() {
        assert_eq!(PerformanceProfile::from_menu("0").unwrap(), PerformanceProfile::Max);
        assert_eq!(PerformanceProfile::from_menu("max").unwrap(), PerformanceProfile::Max);
        assert_eq!(PerformanceProfile::from_menu("4").unwrap(), PerformanceProfile::Custom);
        assert!(PerformanceProfile::from_menu("5").is_err());
    }

    #[test]
    fn max_uses_the_machine_ceiling_without_unbounded_workers() {
        let system = performance::SystemProfile {
            logical_cpus: 64,
            physical_cores: 32,
            total_memory_mb: 65_536,
            elevated: true,
        };
        let limits = PerformanceProfile::Max.limits(system, 4, &CustomLimits::default());
        // 4 hosts × 8 per-host is the binding term; MAX never exceeds the fleet bound.
        assert_eq!(limits.start, 32);
        assert_eq!(limits.max, limits.start);
        assert!(limits.per_host >= 8);
        assert!(limits.worker_threads <= 16);
        assert!(!limits.pinned);
    }

    #[test]
    fn conservative_limits_are_lower_than_aggressive() {
        let system = performance::SystemProfile {
            logical_cpus: 8,
            physical_cores: 4,
            total_memory_mb: 16_384,
            elevated: false,
        };
        let conservative = PerformanceProfile::Conservative.limits(system, 100, &CustomLimits::default());
        let aggressive = PerformanceProfile::Aggressive.limits(system, 100, &CustomLimits::default());
        assert!(conservative.max < aggressive.max);
        assert!(conservative.per_host < aggressive.per_host);
    }

    #[test]
    fn custom_pins_explicit_concurrency() {
        let system = performance::SystemProfile {
            logical_cpus: 4,
            physical_cores: 2,
            total_memory_mb: 8_192,
            elevated: false,
        };
        let custom = CustomLimits {
            concurrency: Some(6),
            ..CustomLimits::default()
        };
        let limits = PerformanceProfile::Custom.limits(system, 100, &custom);
        assert_eq!(limits.start, 6);
        assert_eq!(limits.max, 6);
        assert!(limits.pinned);
    }

    #[test]
    fn validate_rejects_bad_retries() {
        let mut value = config();
        value.custom.retries = 3;
        assert!(value.validate().is_err());
    }
}
