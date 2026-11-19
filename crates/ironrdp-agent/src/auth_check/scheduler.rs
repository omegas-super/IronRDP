//! Bulk-check scheduler: centralized admission with per-host caps, a per-host circuit
//! breaker, pre-authentication-only retries, and a worker pool.
//!
//! A credential-check future is not `Send` in a way rustc can prove: it holds a
//! `&dyn PduHint` across awaits inside the connector, which trips the higher-ranked
//! "implementation of `Send` is not general enough" limitation, so checks cannot be
//! spawned onto the multi-thread runtime. Instead a small pool of worker threads each
//! drive their own current-thread runtime and poll their checks in a `FuturesUnordered`,
//! which requires no `Send` future and still gives real CPU parallelism.
//!
//! Admission is decided here rather than on the workers so a check queued for a
//! saturated host never occupies a global slot (head-of-line blocking); per-host FIFO
//! fairness falls out of the deferred queues.

use core::net::SocketAddr;
use core::panic::AssertUnwindSafe;
use core::time::Duration;
use std::collections::{HashMap, HashSet, VecDeque};
use std::time::Instant;

use futures_util::FutureExt as _;
use futures_util::StreamExt as _;
use futures_util::stream::FuturesUnordered;
use ironrdp_client::auth_check::{
    CheckStage, CredentialCheckOutcome, CredentialCheckParams, FailureKind, check_credentials,
};
use tokio::sync::mpsc;

use super::controller::{LimitChange, LimitController, WindowStats};
use super::input::CheckTarget;

/// Failure classification surfaced to output and statistics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ErrorKind {
    Timeout,
    Unreachable,
    HostDown,
    Tls,
    Protocol,
    LocalSocket,
    NotNla,
}

impl ErrorKind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Timeout => "timeout",
            Self::Unreachable => "unreachable",
            Self::HostDown => "host_down",
            Self::Tls => "tls",
            Self::Protocol => "protocol",
            Self::LocalSocket => "local_socket",
            Self::NotNla => "not_nla",
        }
    }
}

/// Result classification for one check.
#[derive(Debug)]
pub(crate) enum CheckStatus {
    Valid,
    Invalid {
        nt_status: Option<u32>,
        message: String,
    },
    Error {
        kind: ErrorKind,
        stage: Option<CheckStage>,
        message: String,
    },
}

/// One completed check.
#[derive(Debug)]
pub(crate) struct CheckResult {
    /// Input-order index (pre-shuffle).
    pub(crate) index: usize,
    pub(crate) server: String,
    pub(crate) username: String,
    pub(crate) domain: Option<String>,
    pub(crate) status: CheckStatus,
    pub(crate) elapsed_ms: u64,
    pub(crate) attempts: u32,
}

/// Scheduler configuration.
pub(crate) struct SchedulerConfig {
    pub(crate) initial_limit: usize,
    pub(crate) max_limit: usize,
    pub(crate) pinned: bool,
    pub(crate) per_host: usize,
    pub(crate) timeout: Duration,
    pub(crate) connect_timeout: Duration,
    pub(crate) retries: u32,
    pub(crate) reset_on_close: bool,
    pub(crate) worker_threads: usize,
    pub(crate) certificate_validation: ironrdp_tls::CertificateValidation,
    pub(crate) certificate_callback: Option<ironrdp_tls::CertificateValidationCallback>,
}

/// Aggregate outcome of a scheduler run.
#[derive(Debug, Default)]
pub(crate) struct RunOutcome {
    pub(crate) hosts_down: usize,
    pub(crate) retried: u32,
    pub(crate) final_limit: usize,
    pub(crate) peak_limit: usize,
    pub(crate) cancelled: bool,
}

const CONSECUTIVE_CONNECT_FAILURES_BEFORE_DOWN: u32 = 3;
const PER_HOST_START_INTERVAL: Duration = Duration::from_millis(10);
const WINDOW_INTERVAL: Duration = Duration::from_secs(2);
const WINDOW_MAX_AGE: Duration = Duration::from_secs(10);
const MIN_WINDOW_SAMPLES: u32 = 32;

/// Runs the bulk checks to completion (or shutdown), invoking `on_result` for every final
/// result and `on_window` after every controller evaluation.
pub(crate) async fn run<F, W, S>(
    targets: Vec<CheckTarget>,
    resolved: &HashMap<String, SocketAddr>,
    config: &SchedulerConfig,
    mut on_result: F,
    mut on_window: W,
    shutdown: S,
) -> RunOutcome
where
    F: FnMut(&CheckResult),
    W: FnMut(&WindowStats, LimitChange, usize),
    S: Future<Output = ()>,
{
    let mut shutdown = std::pin::pin!(shutdown);
    let (result_tx, mut result_rx) = mpsc::unbounded_channel::<CheckResult>();
    let mut workers = spawn_workers(config.worker_threads.max(1), config.timeout, result_tx);
    let mut worker_of: HashMap<usize, usize> = HashMap::new();
    let mut ready: VecDeque<usize> = (0..targets.len()).collect();
    let mut deferred: HashMap<String, VecDeque<usize>> = HashMap::new();
    let mut host_in_flight: HashMap<String, usize> = HashMap::new();
    let mut host_failures: HashMap<String, u32> = HashMap::new();
    let mut hosts_down: HashSet<String> = HashSet::new();
    let mut last_start: HashMap<String, Instant> = HashMap::new();
    let mut delayed: Vec<(Instant, usize)> = Vec::new();
    let mut attempts: Vec<u32> = vec![0; targets.len()];
    let mut in_flight = 0usize;
    let mut controller = LimitController::new(config.initial_limit, config.max_limit, config.pinned);
    let mut window = WindowAccumulator::new();
    let mut outcome = RunOutcome {
        final_limit: controller.limit(),
        peak_limit: controller.limit(),
        ..RunOutcome::default()
    };
    let mut timer = tokio::time::interval(WINDOW_INTERVAL);
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        if ready.is_empty() && delayed.is_empty() && !has_deferred_work(&deferred) && in_flight == 0 {
            break;
        }

        promote_due_retries(&mut ready, &mut delayed);
        if in_flight == 0 && has_deferred_work(&deferred) {
            // With nothing in flight no host can be at its cap, so deferred work is only
            // pacing-delayed; re-admit it now and let the dispatch pass re-apply pacing.
            promote_deferred(&mut ready, &mut deferred);
        }

        let mut pacing_wake: Option<Instant> = None;
        dispatch(
            &targets,
            resolved,
            config,
            &mut ready,
            &mut deferred,
            &mut host_in_flight,
            &mut hosts_down,
            &mut last_start,
            &mut workers,
            &mut worker_of,
            &mut in_flight,
            controller.limit(),
            &mut pacing_wake,
            &mut window,
            &mut on_result,
        );

        let pacing_sleep = sleep_until_optional(pacing_wake);
        let window_sleep = tokio::time::sleep(WINDOW_MAX_AGE.saturating_sub(window.age()));

        tokio::select! {
            biased;
            () = &mut shutdown => {
                outcome.cancelled = true;
                break;
            }
            Some(result) = result_rx.recv() => {
                in_flight = in_flight.saturating_sub(1);
                if let Some(worker) = worker_of.remove(&result.index) {
                    if let Some(slot) = workers.get_mut(worker) {
                        slot.outstanding = slot.outstanding.saturating_sub(1);
                    }
                }
                handle_result(
                    result,
                    config,
                    &mut host_in_flight,
                    &mut host_failures,
                    &mut hosts_down,
                    &mut deferred,
                    &mut ready,
                    &mut delayed,
                    &mut attempts,
                    &mut window,
                    &mut outcome,
                    &mut on_result,
                );
            }
            _ = timer.tick() => {
                promote_deferred(&mut ready, &mut deferred);
                let bound = globally_bound(&targets, &ready, &host_in_flight, in_flight, controller.limit(), config.per_host);
                if let Some(stats) = window.maybe_finish(bound, MIN_WINDOW_SAMPLES, WINDOW_MAX_AGE) {
                    let change = controller.observe(&stats);
                    outcome.final_limit = controller.limit();
                    outcome.peak_limit = outcome.peak_limit.max(controller.limit());
                    on_window(&stats, change, controller.limit());
                }
            }
            _ = window_sleep, if !ready.is_empty() || in_flight > 0 => {
                let bound = globally_bound(&targets, &ready, &host_in_flight, in_flight, controller.limit(), config.per_host);
                if let Some(stats) = window.maybe_finish(bound, MIN_WINDOW_SAMPLES, WINDOW_MAX_AGE) {
                    let change = controller.observe(&stats);
                    outcome.final_limit = controller.limit();
                    outcome.peak_limit = outcome.peak_limit.max(controller.limit());
                    on_window(&stats, change, controller.limit());
                }
            }
            () = pacing_sleep, if pacing_wake.is_some() => {
                promote_deferred(&mut ready, &mut deferred);
            }
        }
    }

    outcome.hosts_down = hosts_down.len();
    outcome
}

/// One check handed to a worker.
struct WorkerJob {
    index: usize,
    params: CredentialCheckParams,
    server: String,
    username: String,
    domain: Option<String>,
}

struct Worker {
    job_tx: mpsc::UnboundedSender<WorkerJob>,
    outstanding: usize,
}

fn spawn_workers(count: usize, timeout: Duration, result_tx: mpsc::UnboundedSender<CheckResult>) -> Vec<Worker> {
    let mut workers = Vec::with_capacity(count);
    for _ in 0..count {
        let (job_tx, job_rx) = mpsc::unbounded_channel();
        let result_tx = result_tx.clone();
        std::thread::Builder::new()
            .name(String::from("auth-check"))
            .spawn(move || worker_loop(job_rx, result_tx, timeout))
            .expect("spawn an auth-check worker thread");
        workers.push(Worker { job_tx, outstanding: 0 });
    }
    workers
}

fn submit_job(workers: &mut [Worker], worker_of: &mut HashMap<usize, usize>, job: WorkerJob) -> bool {
    let worker = workers
        .iter()
        .enumerate()
        .min_by_key(|(_, worker)| worker.outstanding)
        .map(|(index, _)| index)
        .unwrap_or(0);
    let Some(slot) = workers.get_mut(worker) else {
        return false;
    };
    let index = job.index;
    if slot.job_tx.send(job).is_ok() {
        slot.outstanding += 1;
        worker_of.insert(index, worker);
        true
    } else {
        false
    }
}

/// Worker thread entry point: a current-thread runtime driving its checks concurrently.
fn worker_loop(
    mut job_rx: mpsc::UnboundedReceiver<WorkerJob>,
    result_tx: mpsc::UnboundedSender<CheckResult>,
    timeout: Duration,
) {
    let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(runtime) => runtime,
        Err(error) => {
            // Surface every queued job as an error instead of leaving the scheduler waiting.
            while let Ok(job) = job_rx.try_recv() {
                let _ = result_tx.send(CheckResult {
                    index: job.index,
                    server: job.server,
                    username: job.username,
                    domain: job.domain,
                    status: CheckStatus::Error {
                        kind: ErrorKind::Protocol,
                        stage: None,
                        message: format!("check worker runtime failed: {error}"),
                    },
                    elapsed_ms: 0,
                    attempts: 0,
                });
            }
            return;
        }
    };

    runtime.block_on(async move {
        let mut in_flight: FuturesUnordered<_> = FuturesUnordered::new();
        loop {
            tokio::select! {
                job = job_rx.recv() => match job {
                    Some(job) => in_flight.push(run_one(job, timeout)),
                    None => {
                        while in_flight.next().await.is_some() {}
                        break;
                    }
                },
                Some(result) = in_flight.next() => {
                    let _ = result_tx.send(result);
                }
            }
        }
    });
}

async fn run_one(job: WorkerJob, timeout: Duration) -> CheckResult {
    let WorkerJob {
        index,
        params,
        server,
        username,
        domain,
    } = job;
    let started = Instant::now();
    // A panicking check is reported as an internal error; the worker thread survives.
    let outcome = match AssertUnwindSafe(tokio::time::timeout(timeout, Box::pin(check_credentials(params))))
        .catch_unwind()
        .await
    {
        Ok(Ok(outcome)) => outcome,
        Ok(Err(_elapsed)) => CredentialCheckOutcome::Failed {
            stage: CheckStage::Credssp,
            kind: FailureKind::Timeout,
            message: format!("check timed out after {timeout:?}"),
        },
        Err(_panic) => CredentialCheckOutcome::Failed {
            stage: CheckStage::Tcp,
            kind: FailureKind::Protocol,
            message: String::from("internal error: the check panicked"),
        },
    };
    let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    CheckResult {
        index,
        server,
        username,
        domain,
        status: classify(outcome),
        elapsed_ms,
        attempts: 0,
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "the scheduler threads its state maps explicitly so the main loop stays borrow-checkable"
)]
fn dispatch<F: FnMut(&CheckResult)>(
    targets: &[CheckTarget],
    resolved: &HashMap<String, SocketAddr>,
    config: &SchedulerConfig,
    ready: &mut VecDeque<usize>,
    deferred: &mut HashMap<String, VecDeque<usize>>,
    host_in_flight: &mut HashMap<String, usize>,
    hosts_down: &mut HashSet<String>,
    last_start: &mut HashMap<String, Instant>,
    workers: &mut [Worker],
    worker_of: &mut HashMap<usize, usize>,
    in_flight: &mut usize,
    limit: usize,
    pacing_wake: &mut Option<Instant>,
    window: &mut WindowAccumulator,
    on_result: &mut F,
) {
    let mut scan_budget = ready.len();
    while *in_flight < limit && scan_budget > 0 {
        let Some(index) = ready.pop_front() else {
            break;
        };
        scan_budget -= 1;

        let target = &targets[index];
        let host = target.server.to_ascii_lowercase();

        if hosts_down.contains(&host) {
            let result = CheckResult {
                index,
                server: target.server.clone(),
                username: target.username.clone(),
                domain: target.domain.clone(),
                status: CheckStatus::Error {
                    kind: ErrorKind::HostDown,
                    stage: None,
                    message: String::from("host marked down after repeated connect failures"),
                },
                elapsed_ms: 0,
                attempts: 0,
            };
            window.record(&result);
            on_result(&result);
            continue;
        }

        if host_in_flight.get(&host).copied().unwrap_or(0) >= config.per_host {
            deferred.entry(host).or_default().push_back(index);
            continue;
        }

        let now = Instant::now();
        if let Some(last) = last_start.get(&host) {
            let allowed_at = *last + PER_HOST_START_INTERVAL;
            if now < allowed_at {
                deferred.entry(host.clone()).or_default().push_back(index);
                *pacing_wake = Some(pacing_wake.map_or(allowed_at, |wake| wake.min(allowed_at)));
                continue;
            }
        }

        let Some(addr) = resolved.get(&host).copied() else {
            let result = CheckResult {
                index,
                server: target.server.clone(),
                username: target.username.clone(),
                domain: target.domain.clone(),
                status: CheckStatus::Error {
                    kind: ErrorKind::Unreachable,
                    stage: Some(CheckStage::Resolve),
                    message: String::from("host could not be resolved"),
                },
                elapsed_ms: 0,
                attempts: 0,
            };
            window.record(&result);
            on_result(&result);
            continue;
        };

        let mut params =
            CredentialCheckParams::new(target.server.clone(), target.username.clone(), target.password.clone());
        params.domain = target.domain.clone();
        params.certificate_validation = config.certificate_validation;
        params.certificate_callback = config.certificate_callback.clone();
        params.connect_timeout = Some(config.connect_timeout);
        params.resolved_addr = Some(addr);
        params.reset_on_close = config.reset_on_close;

        let job = WorkerJob {
            index,
            params,
            server: target.server.clone(),
            username: target.username.clone(),
            domain: target.domain.clone(),
        };

        if submit_job(workers, worker_of, job) {
            *in_flight += 1;
            *host_in_flight.entry(host.clone()).or_default() += 1;
            last_start.insert(host, now);
        } else {
            let result = CheckResult {
                index,
                server: target.server.clone(),
                username: target.username.clone(),
                domain: target.domain.clone(),
                status: CheckStatus::Error {
                    kind: ErrorKind::Protocol,
                    stage: None,
                    message: String::from("no check worker available"),
                },
                elapsed_ms: 0,
                attempts: 0,
            };
            window.record(&result);
            on_result(&result);
        }
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "the scheduler threads its state maps explicitly so the main loop stays borrow-checkable"
)]
fn handle_result<F: FnMut(&CheckResult)>(
    mut result: CheckResult,
    config: &SchedulerConfig,
    host_in_flight: &mut HashMap<String, usize>,
    host_failures: &mut HashMap<String, u32>,
    hosts_down: &mut HashSet<String>,
    deferred: &mut HashMap<String, VecDeque<usize>>,
    ready: &mut VecDeque<usize>,
    delayed: &mut Vec<(Instant, usize)>,
    attempts: &mut [u32],
    window: &mut WindowAccumulator,
    outcome: &mut RunOutcome,
    on_result: &mut F,
) {
    let host = result.server.to_ascii_lowercase();
    if let Some(count) = host_in_flight.get_mut(&host) {
        *count = count.saturating_sub(1);
    }

    match &result.status {
        CheckStatus::Error {
            kind: ErrorKind::Unreachable,
            stage: Some(CheckStage::Resolve | CheckStage::Tcp),
            ..
        } => {
            let failures = host_failures.entry(host.clone()).or_default();
            *failures += 1;
            if *failures >= CONSECUTIVE_CONNECT_FAILURES_BEFORE_DOWN {
                hosts_down.insert(host.clone());
            }
        }
        CheckStatus::Error { .. } => {}
        _ => {
            host_failures.remove(&host);
        }
    }

    let attempt = attempts[result.index] + 1;
    let retryable = config.retries > 0
        && attempts[result.index] < config.retries
        && matches!(
            result.status,
            CheckStatus::Error {
                kind: ErrorKind::Unreachable,
                ..
            }
        );

    if retryable {
        attempts[result.index] += 1;
        outcome.retried += 1;
        let backoff = Duration::from_millis(250u64 << u32::min(attempts[result.index], 4));
        delayed.push((Instant::now() + backoff, result.index));
    } else {
        result.attempts = attempt;
        window.record(&result);
        on_result(&result);
    }

    if let Some(queue) = deferred.get_mut(&host) {
        if let Some(index) = queue.pop_front() {
            ready.push_back(index);
        }
    }
}

fn promote_due_retries(ready: &mut VecDeque<usize>, delayed: &mut Vec<(Instant, usize)>) {
    let now = Instant::now();
    let mut index = 0;
    while index < delayed.len() {
        if delayed[index].0 <= now {
            let (_, target) = delayed.swap_remove(index);
            ready.push_back(target);
        } else {
            index += 1;
        }
    }
}

/// Whether any host still has deferred work (empty per-host queues do not count).
fn has_deferred_work(deferred: &HashMap<String, VecDeque<usize>>) -> bool {
    deferred.values().any(|queue| !queue.is_empty())
}

fn promote_deferred(ready: &mut VecDeque<usize>, deferred: &mut HashMap<String, VecDeque<usize>>) {
    for (_, mut queue) in deferred.drain() {
        while let Some(index) = queue.pop_front() {
            ready.push_back(index);
        }
    }
}

fn globally_bound(
    targets: &[CheckTarget],
    ready: &VecDeque<usize>,
    host_in_flight: &HashMap<String, usize>,
    in_flight: usize,
    limit: usize,
    per_host: usize,
) -> bool {
    if in_flight < limit || ready.is_empty() {
        return false;
    }
    ready.iter().take(64).any(|index| {
        let host = targets[*index].server.to_ascii_lowercase();
        host_in_flight.get(&host).copied().unwrap_or(0) < per_host
    })
}

fn classify(outcome: CredentialCheckOutcome) -> CheckStatus {
    match outcome {
        CredentialCheckOutcome::Valid => CheckStatus::Valid,
        CredentialCheckOutcome::Invalid { nt_status, message, .. } => CheckStatus::Invalid { nt_status, message },
        CredentialCheckOutcome::Failed { kind, stage, message } => CheckStatus::Error {
            kind: match kind {
                FailureKind::Timeout => ErrorKind::Timeout,
                FailureKind::Unreachable => ErrorKind::Unreachable,
                FailureKind::Tls => ErrorKind::Tls,
                FailureKind::Protocol => ErrorKind::Protocol,
                FailureKind::LocalSocket => ErrorKind::LocalSocket,
                FailureKind::NotNla => ErrorKind::NotNla,
            },
            stage: Some(stage),
            message,
        },
    }
}

async fn sleep_until_optional(wake: Option<Instant>) {
    match wake {
        Some(at) => tokio::time::sleep_until(tokio::time::Instant::from_std(at)).await,
        None => core::future::pending().await,
    }
}

/// Accumulates one control window of statistics.
#[derive(Debug)]
struct WindowAccumulator {
    started: Instant,
    completed: u32,
    post_connect_stalls: u32,
    local_socket_errors: u32,
    latencies_ms: Vec<u32>,
}

impl WindowAccumulator {
    fn new() -> Self {
        Self {
            started: Instant::now(),
            completed: 0,
            post_connect_stalls: 0,
            local_socket_errors: 0,
            latencies_ms: Vec::new(),
        }
    }

    fn age(&self) -> Duration {
        self.started.elapsed()
    }

    fn record(&mut self, result: &CheckResult) {
        self.completed += 1;
        match &result.status {
            CheckStatus::Error {
                kind: ErrorKind::Timeout,
                ..
            } => self.post_connect_stalls += 1,
            CheckStatus::Error {
                kind: ErrorKind::LocalSocket,
                ..
            } => self.local_socket_errors += 1,
            _ => {}
        }
        if !matches!(
            result.status,
            CheckStatus::Error {
                kind: ErrorKind::Timeout | ErrorKind::HostDown,
                ..
            }
        ) {
            self.latencies_ms
                .push(u32::try_from(result.elapsed_ms).unwrap_or(u32::MAX));
        }
    }

    fn maybe_finish(&mut self, globally_bound: bool, min_samples: u32, max_age: Duration) -> Option<WindowStats> {
        let old_enough = self.age() >= max_age;
        if self.completed < min_samples && !old_enough {
            return None;
        }
        if self.completed == 0 {
            self.started = Instant::now();
            return None;
        }

        let p50 = median(&mut self.latencies_ms).map(f64::from);
        let stats = WindowStats {
            completed: self.completed,
            post_connect_stalls: self.post_connect_stalls,
            local_socket_errors: self.local_socket_errors,
            p50_service_ms: p50,
            globally_bound,
        };

        *self = Self::new();
        Some(stats)
    }
}

fn median(values: &mut [u32]) -> Option<u32> {
    if values.is_empty() {
        return None;
    }
    values.sort_unstable();
    Some(values[values.len() / 2])
}
