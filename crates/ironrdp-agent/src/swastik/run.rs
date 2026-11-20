//! Shared execution pipeline for the terminal and browser front ends.
//!
//! Scheduler results carry an input-order `index`. Credentials are joined back by that
//! index only when writing the operator-requested credential reports; they are never part
//! of the browser state or the credential-free summary stream.

use core::time::Duration;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use anyhow::Context as _;
use ironrdp_tls::{CertificateValidation, CertificateValidationCallback};
use serde::Serialize;
use tokio::sync::watch;

use crate::auth_check::input;
use crate::auth_check::input::CheckTarget;
use crate::auth_check::scheduler::{self, CheckStatus, SchedulerConfig};
use crate::auth_check::{certificate_policy, resolve_hosts, unique_host_count};

use super::config::{RunConfig, load_inputs};
use super::report::Summary;

/// What the browser is allowed to see: counters and paths, never a credential or a record.
#[derive(Debug, Clone, Copy, Default, Serialize, PartialEq, Eq)]
pub(crate) enum RunState {
    #[default]
    Idle,
    Preparing,
    Running,
    Finished,
    Failed,
    Cancelled,
}

impl RunState {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Preparing => "preparing",
            Self::Running => "running",
            Self::Finished => "finished",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize)]
pub(crate) struct Progress {
    pub(crate) state: &'static str,
    pub(crate) total: usize,
    pub(crate) completed: usize,
    pub(crate) valid: usize,
    pub(crate) invalid: usize,
    pub(crate) errors: usize,
    pub(crate) concurrency: usize,
    pub(crate) elapsed_ms: u64,
}

impl Progress {
    pub(crate) fn is_running(&self) -> bool {
        matches!(self.state, label if label == RunState::Running.as_str() || label == RunState::Preparing.as_str())
    }

    pub(crate) fn average_pps(&self) -> f64 {
        rate(self.completed, self.elapsed_ms)
    }

    fn new(total: usize) -> Self {
        Self {
            state: RunState::Idle.as_str(),
            total,
            completed: 0,
            valid: 0,
            invalid: 0,
            errors: 0,
            concurrency: 0,
            elapsed_ms: 0,
        }
    }
}

fn rate(completed: usize, elapsed_ms: u64) -> f64 {
    let seconds = f64::from(u32::try_from(elapsed_ms).unwrap_or(u32::MAX)) / 1000.0;
    if seconds <= 0.0 {
        return 0.0;
    }
    f64::from(u32::try_from(completed).unwrap_or(u32::MAX)) / seconds
}

/// A cheap cloneable handle to the shared progress snapshot.
#[derive(Debug, Clone)]
pub(crate) struct RunHandle {
    tx: watch::Sender<Progress>,
    started: Arc<Instant>,
}

impl RunHandle {
    /// Returns the current snapshot without awaiting. Safe to call from a GUI frame.
    pub(crate) fn snapshot(&self) -> Progress {
        *self.tx.borrow()
    }

    fn publish(&self, mutate: impl FnOnce(&mut Progress)) {
        self.tx.send_modify(|value| {
            mutate(value);
            value.elapsed_ms = u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX);
        });
    }
}

impl Default for RunHandle {
    fn default() -> Self {
        let (tx, _) = watch::channel(Progress::new(0));
        Self {
            tx,
            started: Arc::new(Instant::now()),
        }
    }
}

/// A cheap cloneable cancellation handle. It carries no credential data.
#[derive(Debug, Clone)]
pub(crate) struct RunController {
    stop: watch::Sender<bool>,
}

impl RunController {
    pub(crate) fn stop(&self) {
        let _ = self.stop.send(true);
    }
}

pub(crate) fn exit_code(summary: &Summary) -> u8 {
    if summary.cancelled {
        130
    } else if summary.errors > 0 {
        2
    } else if summary.invalid > 0 {
        1
    } else {
        0
    }
}

/// Prepares inputs and machine limits before any network work starts.
async fn prepare(
    config: &RunConfig,
    targets: Vec<CheckTarget>,
    validation: CertificateValidation,
    callback: Option<CertificateValidationCallback>,
) -> anyhow::Result<Prepared> {
    config.validate()?;
    let deduped = input::dedupe(targets, config.allow_multiple_passwords).context("validate credential inputs")?;
    let mut targets = deduped.targets;
    for (index, target) in targets.iter_mut().enumerate() {
        target.input_index = index;
    }
    if targets.is_empty() {
        anyhow::bail!("no checks after normalization and deduplication");
    }
    let total = targets.len();
    // Input-order credentials are joined to `result.index` only at report-write time.
    let credentials: HashMap<usize, String> = targets
        .iter()
        .map(|target| (target.input_index, target.password.clone()))
        .collect();
    let unique_hosts = unique_host_count(&targets);
    let system = crate::performance::profile();
    let limits = config.profile.limits(system, unique_hosts, &config.custom);
    let seed = (!config.no_shuffle).then(|| config.seed.unwrap_or_else(input::entropy_seed));
    if let Some(seed) = seed {
        let mut order: Vec<usize> = (0..targets.len()).collect();
        input::shuffle(&mut order, seed);
        targets = order.into_iter().map(|index| targets[index].clone()).collect();
    }

    // Credentials travel with the execution plan into the workers, and are then forgotten:
    // `CheckResult` has no password field, so browser state cannot leak one.
    let resolved = resolve_hosts(&targets, Duration::from_millis(config.custom.connect_timeout_ms.max(1))).await;
    let config = SchedulerConfig {
        initial_limit: limits.start,
        max_limit: limits.max,
        pinned: limits.pinned,
        per_host: limits.per_host,
        timeout: Duration::from_millis(config.custom.timeout_ms),
        connect_timeout: Duration::from_millis(config.custom.connect_timeout_ms),
        retries: config.custom.retries,
        reset_on_close: true,
        worker_threads: limits.worker_threads,
        certificate_validation: validation,
        certificate_callback: callback,
    };
    Ok(Prepared {
        targets,
        credentials,
        resolved,
        config,
        total,
        unique_hosts,
        limits,
    })
}

struct Prepared {
    targets: Vec<CheckTarget>,
    /// Input-indexed passwords, kept only for the credential report files.
    credentials: HashMap<usize, String>,
    resolved: HashMap<String, Vec<core::net::SocketAddr>>,
    config: SchedulerConfig,
    total: usize,
    unique_hosts: usize,
    limits: super::config::SchedulerLimits,
}

/// Runs one audit end to end: inputs, scheduler, reports, and summary.
///
/// `handle` is optional so the terminal path pays no synchronization cost. When present it
/// is the only channel through which the browser learns about the run.
pub(crate) async fn execute(
    config: RunConfig,
    handle: Option<RunHandle>,
    stop_rx: watch::Receiver<bool>,
) -> anyhow::Result<(Summary, RunHandle)> {
    let handle = handle.unwrap_or_else(|| RunHandle {
        tx: watch::channel(Progress::new(0)).0,
        started: Arc::new(Instant::now()),
    });
    handle.publish(|progress| {
        progress.state = RunState::Preparing.as_str();
    });

    let result = execute_inner(&config, &handle, stop_rx).await;
    match &result {
        Ok((summary, _)) => handle.publish(|progress| {
            progress.state = if summary.cancelled {
                RunState::Cancelled.as_str()
            } else {
                RunState::Finished.as_str()
            };
        }),
        Err(error) => {
            // The error text is rendered only on the local terminal; the browser sees a
            // generic failed state so a file path or server name cannot be echoed to it.
            eprintln!("swastik-rdp: run failed: {error:#}");
            handle.publish(|progress| progress.state = RunState::Failed.as_str());
        }
    }
    result.map(|(summary, _)| (summary, handle))
}

/// Creates a fresh cancellation channel. The caller keeps the controller and passes the
/// receiver to [`execute`], so Stop is available before the first check starts.
pub(crate) fn cancellation_channel() -> (RunController, watch::Receiver<bool>) {
    let (stop_tx, stop_rx) = watch::channel(false);
    (RunController { stop: stop_tx }, stop_rx)
}

async fn execute_inner(
    config: &RunConfig,
    handle: &RunHandle,
    stop_rx: watch::Receiver<bool>,
) -> anyhow::Result<(Summary, ())> {
    let targets = load_inputs(config)?;
    let (validation, callback) =
        certificate_policy(config.skip_certificate_check).context("load known certificates")?;
    let prepared = prepare(config, targets, validation, callback).await?;
    handle.publish(|progress| {
        progress.state = RunState::Running.as_str();
        progress.total = prepared.total;
        progress.concurrency = prepared.config.max_limit;
    });

    let mut results = Vec::with_capacity(prepared.total);
    let progress = handle.clone();
    // The GUI Stop button writes to the controller; terminal runs rely on Ctrl+C handling.
    let outcome = scheduler::run(
        prepared.targets,
        &prepared.resolved,
        &prepared.config,
        |result| {
            results.push(result.clone());
            progress.publish(|value| {
                value.completed += 1;
                match &result.status {
                    CheckStatus::Valid => value.valid += 1,
                    CheckStatus::Invalid { .. } => value.invalid += 1,
                    CheckStatus::Error { .. } => value.errors += 1,
                }
            });
        },
        |_stats, _change, limit| progress.publish(|value| value.concurrency = limit),
        async move {
            let mut stop_rx = stop_rx;
            let _ = stop_rx.changed().await;
        },
    )
    .await;

    let elapsed_ms = u64::try_from(handle.started.elapsed().as_millis()).unwrap_or(u64::MAX);
    let completed = results.len();
    let valid = results
        .iter()
        .filter(|result| matches!(result.status, CheckStatus::Valid))
        .count();
    let invalid = results
        .iter()
        .filter(|result| matches!(result.status, CheckStatus::Invalid { .. }))
        .count();
    let errors = completed - valid - invalid;
    let summary = Summary {
        total: prepared.total,
        completed,
        valid,
        invalid,
        errors,
        unique_hosts: prepared.unique_hosts,
        profile: config.profile.label(),
        start_limit: prepared.limits.start,
        max_limit: prepared.limits.max,
        per_host: prepared.limits.per_host,
        elapsed_ms,
        checks_per_second: if elapsed_ms == 0 {
            0.0
        } else {
            f64::from(u32::try_from(completed).unwrap_or(u32::MAX))
                / (f64::from(u32::try_from(elapsed_ms).unwrap_or(u32::MAX)) / 1000.0)
        },
        cancelled: outcome.cancelled,
    };
    super::report::write_all(&config.output_dir, &results, &summary, &prepared.credentials)?;
    Ok((summary, ()))
}
