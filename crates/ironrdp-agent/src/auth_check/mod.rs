//! Credential-only authentication checks (`auth-check`), single or bulk.
//!
//! Four input modes, mutually exclusive:
//! 1. single: `--server H[:port] -u U -p P [-d D]`;
//! 2. records: `--input FILE [--input-format txt|csv|jsonl]` (`-` reads standard input);
//! 3. lists: `--hosts FILE --users FILE --passwords FILE` (users and passwords pair line-wise);
//! 4. JSONL stream: `--input - --input-format jsonl`.
//!
//! Bulk runs shuffle the targets, size concurrency from the machine profile, adapt it
//! while running, and emit either human lines or a typed ndjson stream (the contract a
//! UI consumes). Exit codes: 0 all valid, 1 any rejected credentials, 2 any check or
//! input error (130 when interrupted).

#![allow(clippy::print_stdout, clippy::print_stderr)]

pub(crate) mod controller;
pub(crate) mod input;
pub(crate) mod output;
pub(crate) mod scheduler;

use core::net::SocketAddr;
use core::time::Duration;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;

use anyhow::bail;
use ironrdp_tls::{CertificateValidation, CertificateValidationCallback};

use crate::cli::{AuthCheckArgs, InputFormat, OutputFormat};
use crate::performance;

use self::input::{CheckTarget, PreparedInput};
use self::output::{Emitter, SummaryOptions};
use self::scheduler::{RunOutcome, SchedulerConfig};

/// Runs the `auth-check` subcommand.
pub(crate) async fn run_auth_check(args: AuthCheckArgs) -> anyhow::Result<()> {
    let raw = build_targets(&args).unwrap_or_else(|error| fatal(format!("{error:#}")));
    let single = raw.single;

    if args.format == OutputFormat::Json && !single {
        fatal("--format json is only available for single checks; use --format ndjson for bulk output");
    }

    let mut prepared =
        input::dedupe(raw.targets, args.allow_multiple_passwords).unwrap_or_else(|error| fatal(format!("{error:#}")));
    let mut targets = core::mem::take(&mut prepared.targets);
    if targets.is_empty() {
        fatal("input contains no checks");
    }

    for (position, target) in targets.iter_mut().enumerate() {
        target.input_index = position;
    }

    let seed = if single || args.no_shuffle {
        None
    } else {
        Some(args.seed.unwrap_or_else(input::entropy_seed))
    };
    // Shuffle the execution order, not the targets: result `index` stays the input-order
    // position even when the checks run in a randomized order.
    let mut order: Vec<usize> = (0..targets.len()).collect();
    if let Some(seed) = seed {
        input::shuffle(&mut order, seed);
    }
    let execution_plan: Vec<_> = order.iter().map(|&i| targets[i].clone()).collect();

    let system = performance::profile();
    if args.dry_run {
        let mut writer: Box<dyn std::io::Write> = match args.output.as_deref() {
            Some(path) => Box::new(
                std::fs::File::create(path)
                    .unwrap_or_else(|error| fatal(format!("create {}: {error}", path.display()))),
            ),
            None => Box::new(std::io::stdout()),
        };
        print_plan(&mut writer, &args, &execution_plan, &prepared, system, seed);
        let _ = writer.flush();
        return Ok(());
    }

    if !single && !args.quiet {
        eprintln!(
            "system: {} logical CPUs ({} physical cores), {} MiB memory, {}",
            system.logical_cpus,
            system.physical_cores,
            system.total_memory_mb,
            if system.elevated { "elevated" } else { "not elevated" }
        );
    }

    let tuning = if single || args.no_tune_system {
        None
    } else {
        let report = performance::apply_network_tuning();
        if !args.quiet {
            eprintln!("network: {}", report.detail);
        }
        Some(report)
    };

    let (certificate_validation, certificate_callback) =
        certificate_policy(args.skip_certificate_check).unwrap_or_else(|error| fatal(format!("{error:#}")));

    let resolved = resolve_hosts(&targets, Duration::from_millis(args.connect_timeout_ms.max(1))).await;

    let unique_hosts = unique_host_count(&targets);
    let per_host = args.per_host.max(1);
    let (auto_start, auto_max) = controller::plan_limits(
        system.logical_cpus,
        system.physical_cores,
        system.total_memory_mb,
        unique_hosts,
        per_host,
    );
    let pinned = args.concurrency > 0;
    let (start_limit, max_limit) = if pinned {
        if !args.quiet && args.concurrency > auto_max {
            eprintln!(
                "auth-check: warning: --concurrency {} is above the computed ceiling of {auto_max}",
                args.concurrency
            );
        }
        (args.concurrency, args.concurrency)
    } else {
        (auto_start, auto_max)
    };
    if !single && !args.quiet {
        eprintln!(
            "plan: {} checks against {} hosts; concurrency {}..{} (per-host {})",
            targets.len(),
            unique_hosts,
            start_limit,
            max_limit,
            per_host
        );
    }

    let config = SchedulerConfig {
        initial_limit: start_limit,
        max_limit,
        pinned,
        per_host,
        timeout: Duration::from_millis(args.timeout_ms.max(1)),
        connect_timeout: Duration::from_millis(args.connect_timeout_ms.max(1)),
        retries: args.retries,
        reset_on_close: !args.graceful_close,
        worker_threads: if single {
            1
        } else {
            usize::try_from(system.logical_cpus).unwrap_or(4).clamp(1, 16)
        },
        certificate_validation,
        certificate_callback,
    };

    let emitter = Emitter::new(args.format, args.output.as_deref(), args.quiet, targets.len())
        .unwrap_or_else(|error| fatal(format!("{error:#}")));
    let progress = Arc::clone(&emitter.progress);
    let reporter = args.progress.then(|| output::spawn_progress_reporter(progress));

    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            let _ = stop_tx.send(());
            if tokio::signal::ctrl_c().await.is_ok() {
                std::process::exit(130);
            }
        }
    });
    let shutdown = async move {
        let _ = stop_rx.await;
    };

    let emitter = core::cell::RefCell::new(emitter);
    let outcome: RunOutcome = scheduler::run(
        execution_plan,
        &resolved,
        &config,
        |result| emitter.borrow_mut().emit(result),
        |stats, change, limit| emitter.borrow_mut().on_window(stats, change, limit),
        shutdown,
    )
    .await;
    if let Some(reporter) = reporter {
        reporter.abort();
    }

    let mut emitter = emitter.into_inner();
    let options = SummaryOptions {
        seed,
        unique_hosts,
        per_host,
        timeout_ms: args.timeout_ms,
        connect_timeout_ms: args.connect_timeout_ms,
        retries: args.retries,
        skip_certificate_check: args.skip_certificate_check,
        reset_on_close: !args.graceful_close,
        pinned,
        start_limit,
        tuning: tuning.as_ref().map(|report| report.detail.as_str()),
        tuning_applied: tuning.as_ref().is_some_and(|report| report.applied),
    };
    let summary = emitter.summary(&outcome, &options);
    emitter.emit_summary(&summary, &options);
    emitter.flush();

    let code = if summary.cancelled {
        130
    } else if summary.errors > 0 {
        2
    } else if summary.invalid > 0 {
        1
    } else {
        0
    };
    std::process::exit(code);
}

fn fatal(message: impl core::fmt::Display) -> ! {
    eprintln!("auth-check: {message}");
    std::process::exit(2);
}

struct RawInput {
    targets: Vec<CheckTarget>,
    single: bool,
}

fn build_targets(args: &AuthCheckArgs) -> anyhow::Result<RawInput> {
    // Environment-backed credential variables apply only when the command line selects the
    // single-check mode. Otherwise a caller who has RDP_PASSWORD exported could never run a
    // bulk audit without a flag conflict.
    let single_flags =
        args.server.is_some() || args.username.is_some() || args.password.is_some() || args.domain.is_some();
    let lists = args.hosts.is_some() || args.domains.is_some();
    let records = args.input.is_some();

    let modes = usize::from(single_flags) + usize::from(lists) + usize::from(records);
    if modes == 0 {
        bail!("no input: pass --server/--username/--password, or --input FILE, or --hosts/--users/--passwords");
    }
    if modes > 1 {
        bail!(
            "input modes are mutually exclusive: use exactly one of the single-check flags, --input, or \
             --hosts/--users/--passwords"
        );
    }
    if args.input_format.is_some() && !records {
        bail!("--input-format requires --input");
    }
    if args.domains.is_some() && args.users.is_none() {
        bail!("--users is required with --domains");
    }
    if args.domains.is_some() && args.passwords.is_none() {
        bail!("--passwords is required with --domains");
    }

    if single_flags {
        let server = args
            .server
            .clone()
            .or_else(|| std::env::var("RDP_HOSTNAME").ok())
            .ok_or_else(|| anyhow::anyhow!("--server or RDP_HOSTNAME is required for a single check"))?;
        let username = args
            .username
            .clone()
            .or_else(|| std::env::var("RDP_USERNAME").ok())
            .ok_or_else(|| anyhow::anyhow!("--username or RDP_USERNAME is required for a single check"))?;
        let password = args
            .password
            .clone()
            .or_else(|| std::env::var("RDP_PASSWORD").ok())
            .ok_or_else(|| anyhow::anyhow!("--password or RDP_PASSWORD is required for a single check"))?;
        if username.trim().is_empty() {
            bail!("--username must not be empty");
        }
        Ok(RawInput {
            targets: vec![CheckTarget {
                input_index: 0,
                server: input::normalize_server(&server)?,
                username,
                password,
                domain: args.domain.clone().filter(|domain| !domain.trim().is_empty()),
            }],
            single: true,
        })
    } else if records {
        let path = args.input.as_deref().expect("records mode implies --input");
        let format = args.input_format.unwrap_or_else(|| infer_format(path));
        let text = input::read_text(path)?;
        let targets = input::parse_records(&text, format)?;
        Ok(RawInput { targets, single: false })
    } else {
        let hosts = args
            .hosts
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("--hosts is required for list mode"))?;
        let users = args
            .users
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("--users is required with --hosts"))?;
        let passwords = args
            .passwords
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("--passwords is required with --hosts"))?;
        let hosts_text = input::read_text(hosts)?;
        let users_text = input::read_text(users)?;
        let passwords_text = input::read_text(passwords)?;
        let domains_text = args.domains.as_deref().map(input::read_text).transpose()?;
        let targets = input::parse_lists(&hosts_text, &users_text, &passwords_text, domains_text.as_deref())?;
        Ok(RawInput { targets, single: false })
    }
}

fn infer_format(path: &Path) -> InputFormat {
    match path
        .extension()
        .and_then(|extension| extension.to_str())
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("csv") => InputFormat::Csv,
        Some("jsonl" | "ndjson" | "json") => InputFormat::Jsonl,
        _ => InputFormat::Txt,
    }
}

pub(crate) fn unique_host_count(targets: &[CheckTarget]) -> usize {
    let mut hosts = HashSet::new();
    for target in targets {
        hosts.insert(target.server.to_ascii_lowercase());
    }
    hosts.len()
}

/// Resolves every unique host up front, at most 32 lookups in flight, so DNS latency
/// never occupies a check slot. Failures are omitted and surface as `unreachable`.
pub(crate) async fn resolve_hosts(targets: &[CheckTarget], timeout: Duration) -> HashMap<String, Vec<SocketAddr>> {
    let mut hosts = Vec::new();
    let mut seen = HashSet::new();
    for target in targets {
        let key = target.server.to_ascii_lowercase();
        if seen.insert(key) {
            hosts.push(target.server.clone());
        }
    }

    let semaphore = Arc::new(tokio::sync::Semaphore::new(32));
    let mut tasks = tokio::task::JoinSet::new();
    for server in hosts {
        let permit = match Arc::clone(&semaphore).acquire_owned().await {
            Ok(permit) => permit,
            Err(_) => break,
        };
        tasks.spawn(async move {
            let _permit = permit;
            match tokio::time::timeout(timeout, tokio::net::lookup_host(&server)).await {
                Ok(Ok(addresses)) => {
                    let addresses: Vec<SocketAddr> = addresses.collect();
                    (!addresses.is_empty()).then(|| (server.to_ascii_lowercase(), addresses))
                }
                _ => None,
            }
        });
    }

    let mut resolved = HashMap::new();
    while let Some(joined) = tasks.join_next().await {
        if let Ok(Some((host, address))) = joined {
            resolved.insert(host, address);
        }
    }
    resolved
}

fn print_plan(
    writer: &mut dyn std::io::Write,
    args: &AuthCheckArgs,
    targets: &[CheckTarget],
    prepared: &PreparedInput,
    system: performance::SystemProfile,
    seed: Option<u64>,
) {
    let unique_hosts = unique_host_count(targets);
    let per_host = args.per_host.max(1);
    let (auto_start, auto_max) = controller::plan_limits(
        system.logical_cpus,
        system.physical_cores,
        system.total_memory_mb,
        unique_hosts,
        per_host,
    );
    let (start_limit, max_limit) = if args.concurrency > 0 {
        (args.concurrency, args.concurrency)
    } else {
        (auto_start, auto_max)
    };

    match args.format {
        OutputFormat::Ndjson => {
            for target in targets {
                let _ = writeln!(
                    writer,
                    "{}",
                    serde_json::json!({
                        "domain": target.domain,
                        "index": target.input_index,
                        "server": target.server,
                        "type": "plan",
                        "username": target.username,
                    })
                );
            }
            let _ = writeln!(
                writer,
                "{}",
                serde_json::json!({
                    "concurrency": {"max": max_limit, "per_host": per_host, "start": start_limit},
                    "duplicates_dropped": prepared.duplicates_dropped,
                    "elevated": system.elevated,
                    "logical_cpus": system.logical_cpus,
                    "physical_cores": system.physical_cores,
                    "seed": seed,
                    "total": targets.len(),
                    "total_memory_mb": system.total_memory_mb,
                    "type": "plan_summary",
                    "unique_hosts": unique_hosts,
                })
            );
        }
        OutputFormat::Json => {
            let target = &targets[0];
            let _ = writeln!(
                writer,
                "{}",
                serde_json::json!({
                    "domain": target.domain,
                    "server": target.server,
                    "type": "plan",
                    "username": target.username,
                })
            );
        }
        OutputFormat::Human => {
            let _ = writeln!(
                writer,
                "system: {} logical CPUs ({} physical cores), {} MiB memory, {}",
                system.logical_cpus,
                system.physical_cores,
                system.total_memory_mb,
                if system.elevated { "elevated" } else { "not elevated" }
            );
            let _ = writeln!(
                writer,
                "plan: {} checks against {} hosts (concurrency {}..{}, per-host {})",
                targets.len(),
                unique_hosts,
                start_limit,
                max_limit,
                per_host
            );
            if prepared.duplicates_dropped > 0 {
                let _ = writeln!(writer, "duplicates dropped: {}", prepared.duplicates_dropped);
            }
            if !prepared.multiple_passwords.is_empty() {
                let _ = writeln!(
                    writer,
                    "accounts with multiple passwords: {}",
                    prepared.multiple_passwords.join(", ")
                );
            }
            if let Some(seed) = seed {
                let _ = writeln!(writer, "shuffle seed: {seed}");
            }
            for (index, target) in targets.iter().take(20).enumerate() {
                let account = match &target.domain {
                    Some(domain) => format!("{domain}\\{}", target.username),
                    None => target.username.clone(),
                };
                let _ = writeln!(
                    writer,
                    "  [{}/{}] {account}@{}",
                    index + 1,
                    targets.len(),
                    target.server
                );
            }
            if targets.len() > 20 {
                let _ = writeln!(writer, "  ... {} more", targets.len() - 20);
            }
        }
    }
}

pub(crate) fn certificate_policy(
    skip_certificate_check: bool,
) -> anyhow::Result<(CertificateValidation, Option<CertificateValidationCallback>)> {
    if skip_certificate_check {
        return Ok((CertificateValidation::DangerouslyAcceptInvalidCertificate, None));
    }

    use ironrdp_daemon::known_certificates::KnownCertificates;

    let store = KnownCertificates::default_path()
        .and_then(|path| KnownCertificates::load(&path))
        .map_err(|error| anyhow::anyhow!("load the known-certificates store: {error}"))?;
    let callback: CertificateValidationCallback =
        Arc::new(move |der, endpoint, _reason| store.is_trusted(endpoint, der));

    Ok((CertificateValidation::Strict, Some(callback)))
}
