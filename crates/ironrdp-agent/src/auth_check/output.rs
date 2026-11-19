//! Result, progress, and summary emitters for credential checks.
//!
//! The ndjson stream is the machine contract a UI consumes: one `result` object per
//! completed check, optionally `plan` objects for a dry run, and a final `summary` object.
//! Passwords are never emitted.

use core::sync::atomic::{AtomicUsize, Ordering};
use core::time::Duration;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use serde_json::json;

use crate::cli::OutputFormat;

use super::controller::{LimitChange, WindowStats};
use super::scheduler::{CheckResult, CheckStatus, RunOutcome};

/// Upper bound on retained latency samples for the summary percentiles.
const MAX_LATENCY_SAMPLES: usize = 1_000_000;

/// Counters shared with the periodic progress reporter.
#[derive(Debug, Default)]
pub(crate) struct Progress {
    pub(crate) completed: AtomicUsize,
    pub(crate) total: AtomicUsize,
    pub(crate) valid: AtomicUsize,
    pub(crate) invalid: AtomicUsize,
    pub(crate) errors: AtomicUsize,
    pub(crate) limit: AtomicUsize,
}

/// Options carried from the command line into the summary.
pub(crate) struct SummaryOptions<'a> {
    pub(crate) seed: Option<u64>,
    pub(crate) unique_hosts: usize,
    pub(crate) per_host: usize,
    pub(crate) timeout_ms: u64,
    pub(crate) connect_timeout_ms: u64,
    pub(crate) retries: u32,
    pub(crate) skip_certificate_check: bool,
    pub(crate) reset_on_close: bool,
    pub(crate) pinned: bool,
    pub(crate) start_limit: usize,
    pub(crate) tuning: Option<&'a str>,
    pub(crate) tuning_applied: bool,
}

/// Aggregate statistics of one run.
pub(crate) struct Summary {
    pub(crate) total: usize,
    pub(crate) completed: usize,
    pub(crate) valid: usize,
    pub(crate) invalid: usize,
    pub(crate) errors: usize,
    error_kinds: BTreeMap<&'static str, usize>,
    pub(crate) unique_hosts: usize,
    pub(crate) hosts_down: usize,
    retried: u32,
    elapsed: Duration,
    p50_ms: Option<u32>,
    p95_ms: Option<u32>,
    start_limit: usize,
    final_limit: usize,
    peak_limit: usize,
    per_host: usize,
    pinned: bool,
    seed: Option<u64>,
    pub(crate) cancelled: bool,
}

/// Streams results in the selected format and accumulates summary statistics.
pub(crate) struct Emitter {
    format: OutputFormat,
    writer: Box<dyn Write + Send>,
    summary_to_stderr: bool,
    quiet: bool,
    total: usize,
    completed: usize,
    valid: usize,
    invalid: usize,
    errors: usize,
    error_kinds: BTreeMap<&'static str, usize>,
    latencies: Vec<u32>,
    started: Instant,
    write_failed: bool,
    pub(crate) progress: Arc<Progress>,
}

impl Emitter {
    /// Creates an emitter writing to `output` or standard output.
    pub(crate) fn new(format: OutputFormat, output: Option<&Path>, quiet: bool, total: usize) -> anyhow::Result<Self> {
        let writer: Box<dyn Write + Send> = match output {
            Some(path) => Box::new(BufWriter::new(
                File::create(path).map_err(|error| anyhow::anyhow!("create {}: {error}", path.display()))?,
            )),
            None => Box::new(BufWriter::new(std::io::stdout())),
        };
        let progress = Arc::new(Progress::default());
        progress.total.store(total, Ordering::Relaxed);
        Ok(Self {
            format,
            writer,
            summary_to_stderr: output.is_none() && format == OutputFormat::Human,
            quiet,
            total,
            completed: 0,
            valid: 0,
            invalid: 0,
            errors: 0,
            error_kinds: BTreeMap::new(),
            latencies: Vec::new(),
            started: Instant::now(),
            write_failed: false,
            progress,
        })
    }

    /// Emits one completed check and updates the statistics.
    pub(crate) fn emit(&mut self, result: &CheckResult) {
        self.completed += 1;
        match &result.status {
            CheckStatus::Valid => self.valid += 1,
            CheckStatus::Invalid { .. } => self.invalid += 1,
            CheckStatus::Error { kind, .. } => {
                self.errors += 1;
                *self.error_kinds.entry(kind.as_str()).or_default() += 1;
            }
        }
        if result.elapsed_ms > 0
            && !matches!(
                result.status,
                CheckStatus::Error {
                    kind: super::scheduler::ErrorKind::Timeout | super::scheduler::ErrorKind::HostDown,
                    ..
                }
            )
            && self.latencies.len() < MAX_LATENCY_SAMPLES
        {
            self.latencies
                .push(u32::try_from(result.elapsed_ms).unwrap_or(u32::MAX));
        }

        self.progress.completed.store(self.completed, Ordering::Relaxed);
        self.progress.valid.store(self.valid, Ordering::Relaxed);
        self.progress.invalid.store(self.invalid, Ordering::Relaxed);
        self.progress.errors.store(self.errors, Ordering::Relaxed);

        match self.format {
            OutputFormat::Human => {
                if !self.quiet {
                    let line = human_line(result, self.completed, self.total);
                    self.write_line(&line);
                }
            }
            OutputFormat::Ndjson | OutputFormat::Json => {
                let value = result_json(result);
                self.write_json(&value);
            }
        }
    }

    /// Reports a controller decision on standard error (never in the machine stream).
    pub(crate) fn on_window(&mut self, stats: &WindowStats, change: LimitChange, limit: usize) {
        self.progress.limit.store(limit, Ordering::Relaxed);
        if self.quiet {
            return;
        }
        let p50 = stats
            .p50_service_ms
            .map(|value| format!("{value:.0} ms"))
            .unwrap_or_else(|| String::from("n/a"));
        let direction = match change {
            LimitChange::Grow(_) => "grow",
            LimitChange::Shrink(_) => "shrink",
            LimitChange::Hold => return,
        };
        let _ = writeln!(
            std::io::stderr(),
            "concurrency: {direction} to {limit} (p50 {p50}, {} checks, {} stalls, {} socket errors)",
            stats.completed,
            stats.post_connect_stalls,
            stats.local_socket_errors
        );
    }

    /// Builds the summary from the accumulated statistics and the scheduler outcome.
    pub(crate) fn summary(&self, outcome: &RunOutcome, options: &SummaryOptions<'_>) -> Summary {
        let mut latencies = self.latencies.clone();
        latencies.sort_unstable();
        Summary {
            total: self.total,
            completed: self.completed,
            valid: self.valid,
            invalid: self.invalid,
            errors: self.errors,
            error_kinds: self.error_kinds.clone(),
            unique_hosts: options.unique_hosts,
            hosts_down: outcome.hosts_down,
            retried: outcome.retried,
            elapsed: self.started.elapsed(),
            p50_ms: percentile(&latencies, 50),
            p95_ms: percentile(&latencies, 95),
            start_limit: options.start_limit,
            final_limit: outcome.final_limit,
            peak_limit: outcome.peak_limit,
            per_host: options.per_host,
            pinned: options.pinned,
            seed: options.seed,
            cancelled: outcome.cancelled,
        }
    }

    /// Writes the summary in the selected format.
    pub(crate) fn emit_summary(&mut self, summary: &Summary, options: &SummaryOptions<'_>) {
        match self.format {
            OutputFormat::Ndjson => {
                let value = summary_json(summary, options);
                self.write_json(&value);
            }
            OutputFormat::Human => {
                let line = summary_line(summary);
                if self.summary_to_stderr {
                    let _ = writeln!(std::io::stderr(), "{line}");
                } else {
                    self.write_line(&line);
                }
            }
            OutputFormat::Json => {}
        }
    }

    /// Flushes buffered output, ignoring errors (the process is about to exit).
    pub(crate) fn flush(&mut self) {
        let _ = self.writer.flush();
    }

    fn write_line(&mut self, line: &str) {
        if self.write_failed {
            return;
        }
        if writeln!(self.writer, "{line}").is_err() {
            // A closed consumer (EPIPE) must not abort the audit or change its exit code.
            self.write_failed = true;
        }
    }

    fn write_json(&mut self, value: &serde_json::Value) {
        if self.write_failed {
            return;
        }
        let mut buffer = Vec::new();
        if serde_json::to_writer(&mut buffer, value).is_err() {
            self.write_failed = true;
            return;
        }
        buffer.push(b'\n');
        if self.writer.write_all(&buffer).is_err() {
            self.write_failed = true;
        }
    }
}

/// Spawns the periodic progress reporter (stderr, every 5 s).
pub(crate) fn spawn_progress_reporter(progress: Arc<Progress>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        interval.tick().await;
        loop {
            interval.tick().await;
            let completed = progress.completed.load(Ordering::Relaxed);
            let total = progress.total.load(Ordering::Relaxed);
            let valid = progress.valid.load(Ordering::Relaxed);
            let invalid = progress.invalid.load(Ordering::Relaxed);
            let errors = progress.errors.load(Ordering::Relaxed);
            let limit = progress.limit.load(Ordering::Relaxed);
            let _ = writeln!(
                std::io::stderr(),
                "progress: {completed}/{total} done ({valid} valid, {invalid} invalid, {errors} errors), concurrency limit {limit}"
            );
        }
    })
}

fn checks_per_second(completed: usize, elapsed: Duration) -> f64 {
    let seconds = elapsed.as_secs_f64();
    if seconds <= 0.0 {
        return 0.0;
    }
    let completed = u32::try_from(completed).map_or_else(|_| f64::from(u32::MAX), f64::from);
    completed / seconds
}

fn percentile(sorted: &[u32], percent: usize) -> Option<u32> {
    if sorted.is_empty() {
        return None;
    }
    let index = (sorted.len() * percent / 100).min(sorted.len() - 1);
    Some(sorted[index])
}

fn stage_str(stage: ironrdp_client::auth_check::CheckStage) -> &'static str {
    use ironrdp_client::auth_check::CheckStage;
    match stage {
        CheckStage::Resolve => "resolve",
        CheckStage::Tcp => "tcp",
        CheckStage::X224 => "x224",
        CheckStage::Tls => "tls",
        CheckStage::Credssp => "credssp",
    }
}

fn human_account(result: &CheckResult) -> String {
    match &result.domain {
        Some(domain) => format!("{domain}\\{}", result.username),
        None => result.username.clone(),
    }
}

fn human_line(result: &CheckResult, index: usize, total: usize) -> String {
    let account = human_account(result);
    match &result.status {
        CheckStatus::Valid => format!(
            "[{index}/{total}] {account}@{}: valid ({} ms)",
            result.server, result.elapsed_ms
        ),
        CheckStatus::Invalid { nt_status, message } => {
            let status = nt_status
                .map(|status| format!(", NTSTATUS 0x{status:08X}"))
                .unwrap_or_default();
            format!(
                "[{index}/{total}] {account}@{}: invalid ({} ms{status}): {message}",
                result.server, result.elapsed_ms
            )
        }
        CheckStatus::Error { kind, stage, message } => {
            let at = stage
                .map(|stage| format!(" at {}", stage_str(stage)))
                .unwrap_or_default();
            format!(
                "[{index}/{total}] {account}@{}: error ({}{at}, {} ms): {message}",
                result.server,
                kind.as_str(),
                result.elapsed_ms
            )
        }
    }
}

fn result_json(result: &CheckResult) -> serde_json::Value {
    use ironrdp_client::auth_check::CheckStage;
    let (label, kind, stage, nt_status, message) = match &result.status {
        CheckStatus::Valid => ("valid", None, None, None, None),
        CheckStatus::Invalid { nt_status, message } => (
            "invalid",
            None,
            Some(stage_str(CheckStage::Credssp)),
            *nt_status,
            Some(message.as_str()),
        ),
        CheckStatus::Error { kind, stage, message } => (
            "error",
            Some(kind.as_str()),
            stage.map(stage_str),
            None,
            Some(message.as_str()),
        ),
    };
    json!({
        "attempts": result.attempts,
        "domain": result.domain,
        "elapsed_ms": result.elapsed_ms,
        "index": result.index,
        "kind": kind,
        "message": message,
        "nt_status": nt_status,
        "result": label,
        "server": result.server,
        "stage": stage,
        "type": "result",
        "username": result.username,
    })
}

fn summary_json(summary: &Summary, options: &SummaryOptions<'_>) -> serde_json::Value {
    let rate = checks_per_second(summary.completed, summary.elapsed);
    json!({
        "cancelled": summary.cancelled,
        "checks_per_second": rate,
        "completed": summary.completed,
        "concurrency": {
            "final": summary.final_limit,
            "peak": summary.peak_limit,
            "per_host": summary.per_host,
            "pinned": summary.pinned,
            "start": summary.start_limit,
        },
        "elapsed_ms": u64::try_from(summary.elapsed.as_millis()).unwrap_or(u64::MAX),
        "error_kinds": summary.error_kinds,
        "errors": summary.errors,
        "flags": {
            "connect_timeout_ms": options.connect_timeout_ms,
            "reset_on_close": options.reset_on_close,
            "retries": options.retries,
            "skip_certificate_check": options.skip_certificate_check,
            "timeout_ms": options.timeout_ms,
        },
        "hosts_down": summary.hosts_down,
        "invalid": summary.invalid,
        "network_tuning": options.tuning,
        "network_tuning_applied": options.tuning_applied,
        "p50_ms": summary.p50_ms,
        "p95_ms": summary.p95_ms,
        "retried": summary.retried,
        "seed": summary.seed,
        "total": summary.total,
        "type": "summary",
        "unique_hosts": summary.unique_hosts,
        "valid": summary.valid,
        "version": env!("CARGO_PKG_VERSION"),
    })
}

fn summary_line(summary: &Summary) -> String {
    let elapsed_s = summary.elapsed.as_secs_f64();
    let rate = checks_per_second(summary.completed, summary.elapsed);
    let mut line = format!(
        "summary: {} of {} checks in {elapsed_s:.1} s ({rate:.1}/s): {} valid, {} invalid, {} errors",
        summary.completed, summary.total, summary.valid, summary.invalid, summary.errors
    );
    if !summary.error_kinds.is_empty() {
        let kinds: Vec<String> = summary
            .error_kinds
            .iter()
            .map(|(kind, count)| format!("{kind} {count}"))
            .collect();
        line.push_str(&format!(" ({})", kinds.join(", ")));
    }
    if let Some(p50) = summary.p50_ms {
        line.push_str(&format!("; p50 {p50} ms"));
    }
    if let Some(p95) = summary.p95_ms {
        line.push_str(&format!(", p95 {p95} ms"));
    }
    line.push_str(&format!(
        "; {} hosts ({} down); concurrency {} -> {} (peak {}, per-host {})",
        summary.unique_hosts,
        summary.hosts_down,
        summary.start_limit,
        summary.final_limit,
        summary.peak_limit,
        summary.per_host
    ));
    if let Some(seed) = summary.seed {
        line.push_str(&format!("; seed {seed}"));
    }
    if summary.cancelled {
        line.push_str("; cancelled");
    }
    line
}
