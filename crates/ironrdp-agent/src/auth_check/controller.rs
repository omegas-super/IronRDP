//! Pure concurrency-limit controller for bulk checks.
//!
//! The controller is a small state machine over per-window statistics so it can be
//! unit-tested without tokio or a network. It grows the limit only when the scheduler is
//! globally bound and latency stays near its moving baseline, shrinks immediately on
//! post-connect stalls or local socket errors, and never reacts to rejected credentials
//! or unreachable hosts (both are normal audit outcomes).

/// Minimum samples before a window is evaluated.
pub(crate) const MIN_WINDOW_SAMPLES: u32 = 32;
/// Hard floor for the limit; recovering from 1 is slower than the overload it avoids.
pub(crate) const MIN_LIMIT: usize = 4;

/// Signals observed over one control window.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct WindowStats {
    /// Checks completed in the window (all outcomes).
    pub(crate) completed: u32,
    /// Timeouts that happened after the TCP connection was established.
    pub(crate) post_connect_stalls: u32,
    /// Local socket resource errors (buffer/port exhaustion).
    pub(crate) local_socket_errors: u32,
    /// Median service time (check start to result) of the window, timeouts excluded.
    pub(crate) p50_service_ms: Option<f64>,
    /// Whether the scheduler was globally bound: the limit was reached, ready work
    /// existed, and at least one ready target's host was below its per-host cap.
    pub(crate) globally_bound: bool,
}

/// What the controller decided for the next window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LimitChange {
    Grow(usize),
    Shrink(usize),
    Hold,
}

/// Latency-aware limit controller with warmup doubling, fast shrink, and slow growth.
#[derive(Debug)]
pub(crate) struct LimitController {
    limit: usize,
    max_limit: usize,
    baseline_p50_ms: Option<f64>,
    good_windows: u32,
    cooldown_windows: u32,
    warmup: bool,
    pinned: bool,
}

impl LimitController {
    /// Creates a controller starting at `start` and never exceeding `max_limit`.
    /// A pinned controller always reports [`LimitChange::Hold`] and honors an explicit
    /// limit below [`MIN_LIMIT`] — that floor exists only to keep the automatic
    /// controller from collapsing to an unrecoverable limit.
    pub(crate) fn new(start: usize, max_limit: usize, pinned: bool) -> Self {
        let max_limit = if pinned {
            max_limit.max(1)
        } else {
            max_limit.max(MIN_LIMIT)
        };
        let limit = if pinned {
            start.clamp(1, max_limit)
        } else {
            start.clamp(MIN_LIMIT, max_limit)
        };
        Self {
            limit,
            max_limit,
            baseline_p50_ms: None,
            good_windows: 0,
            cooldown_windows: 0,
            warmup: true,
            pinned,
        }
    }

    pub(crate) fn limit(&self) -> usize {
        self.limit
    }

    /// Feeds one window of statistics and returns the resulting limit decision.
    pub(crate) fn observe(&mut self, stats: &WindowStats) -> LimitChange {
        if self.pinned || stats.completed < MIN_WINDOW_SAMPLES {
            return LimitChange::Hold;
        }

        let attempts = f64::from(stats.completed);
        let stall_rate = f64::from(stats.post_connect_stalls) / attempts;

        // Fast shrink on the first bad window; growth needs consecutive good windows.
        if stats.local_socket_errors > 0 || stall_rate > 0.20 {
            self.warmup = false;
            self.good_windows = 0;
            self.cooldown_windows = 1;
            return self.set(self.limit / 2);
        }
        if stall_rate > 0.05 {
            self.warmup = false;
            self.good_windows = 0;
            self.cooldown_windows = 1;
            let next = self.limit.saturating_mul(7) / 10;
            return self.set(next);
        }

        if let Some(p50) = stats.p50_service_ms {
            self.baseline_p50_ms = Some(match self.baseline_p50_ms {
                Some(baseline) => baseline * 0.8 + p50 * 0.2,
                None => p50,
            });
        }

        if self.cooldown_windows > 0 {
            self.cooldown_windows -= 1;
            return LimitChange::Hold;
        }

        let latency_ok = match (stats.p50_service_ms, self.baseline_p50_ms) {
            (Some(p50), Some(baseline)) => p50 <= baseline * 1.25,
            _ => true,
        };
        if !stats.globally_bound || !latency_ok {
            self.good_windows = 0;
            return LimitChange::Hold;
        }

        self.good_windows += 1;
        if self.good_windows < 2 {
            return LimitChange::Hold;
        }
        self.good_windows = 0;

        let next = if self.warmup {
            self.limit.saturating_mul(2)
        } else {
            self.limit + (self.limit / 8).max(1)
        };
        if next >= self.max_limit {
            self.warmup = false;
        }
        self.set(next)
    }

    fn set(&mut self, next: usize) -> LimitChange {
        let next = next.clamp(MIN_LIMIT, self.max_limit);
        if next == self.limit {
            return LimitChange::Hold;
        }
        let change = if next > self.limit {
            LimitChange::Grow(next)
        } else {
            LimitChange::Shrink(next)
        };
        self.limit = next;
        change
    }
}

/// Computes the initial limit and ceiling from the machine profile and the fleet size.
///
/// The ceiling is the smallest of the CPU term (0.75 physical cores' worth of checks in
/// flight at a nominal 100 ms service time and 3 ms of CPU per check, i.e. 25 per core),
/// the RAM term (a 0.25 × installed-memory budget at 8 MiB per check), and the
/// per-host-bounded fleet term; the start is deliberately low so a constrained uplink
/// does not see a first-window timeout storm.
pub(crate) fn plan_limits(
    logical_cpus: u32,
    physical_cores: u32,
    total_memory_mb: u64,
    unique_hosts: usize,
    per_host: usize,
) -> (usize, usize) {
    let start = (usize::try_from(logical_cpus).unwrap_or(1) * 2).clamp(4, 32);
    let cpu_term = usize::try_from(physical_cores.max(1)).unwrap_or(1).saturating_mul(25);
    let ram_term = if total_memory_mb == 0 {
        usize::MAX
    } else {
        usize::try_from(total_memory_mb / 32).unwrap_or(usize::MAX)
    };
    let fleet_term = unique_hosts.max(1).saturating_mul(per_host);
    let max_limit = cpu_term.min(ram_term).min(fleet_term).clamp(start, 512);
    (start.min(max_limit), max_limit)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn window(completed: u32, stalls: u32, bound: bool, p50: f64) -> WindowStats {
        WindowStats {
            completed,
            post_connect_stalls: stalls,
            local_socket_errors: 0,
            p50_service_ms: Some(p50),
            globally_bound: bound,
        }
    }

    #[test]
    fn warmup_doubles_after_two_good_windows() {
        let mut controller = LimitController::new(8, 128, false);
        assert_eq!(controller.observe(&window(64, 0, true, 100.0)), LimitChange::Hold);
        assert_eq!(controller.observe(&window(64, 0, true, 100.0)), LimitChange::Grow(16));
        assert_eq!(controller.limit(), 16);
    }

    #[test]
    fn no_growth_when_host_bound_or_latency_inflated() {
        let mut controller = LimitController::new(8, 128, false);
        controller.observe(&window(64, 0, true, 100.0));
        // Host-bound window: no growth.
        assert_eq!(controller.observe(&window(64, 0, false, 100.0)), LimitChange::Hold);
        // Latency-inflated window: no growth.
        assert_eq!(controller.observe(&window(64, 0, true, 300.0)), LimitChange::Hold);
    }

    #[test]
    fn first_bad_window_shrinks_immediately() {
        let mut controller = LimitController::new(64, 128, false);
        assert_eq!(controller.observe(&window(64, 5, true, 100.0)), LimitChange::Shrink(44));
        // Cooldown window holds even when healthy.
        assert_eq!(controller.observe(&window(64, 0, true, 100.0)), LimitChange::Hold);
    }

    #[test]
    fn severe_stall_or_socket_error_halves_the_limit() {
        let mut controller = LimitController::new(64, 128, false);
        assert_eq!(
            controller.observe(&window(64, 20, true, 100.0)),
            LimitChange::Shrink(32)
        );

        let mut controller = LimitController::new(64, 128, false);
        let mut stats = window(64, 0, true, 100.0);
        stats.local_socket_errors = 1;
        assert_eq!(controller.observe(&stats), LimitChange::Shrink(32));
    }

    #[test]
    fn floor_and_ceiling_are_enforced() {
        let mut controller = LimitController::new(5, 10, false);
        for _ in 0..50 {
            controller.observe(&window(64, 30, true, 100.0));
        }
        assert_eq!(controller.limit(), MIN_LIMIT);

        let mut controller = LimitController::new(8, 16, false);
        for _ in 0..50 {
            controller.observe(&window(64, 0, true, 100.0));
        }
        assert_eq!(controller.limit(), 16);
    }

    #[test]
    fn pinned_controller_never_changes() {
        let mut controller = LimitController::new(32, 128, true);
        assert_eq!(controller.observe(&window(64, 30, true, 500.0)), LimitChange::Hold);
        assert_eq!(controller.limit(), 32);
    }

    #[test]
    fn pinned_limit_below_the_floor_is_honored() {
        let mut controller = LimitController::new(2, 2, true);
        assert_eq!(controller.limit(), 2);
        assert_eq!(controller.observe(&window(64, 30, true, 500.0)), LimitChange::Hold);
        assert_eq!(controller.limit(), 2);
    }

    #[test]
    fn small_windows_are_ignored() {
        let mut controller = LimitController::new(8, 128, false);
        assert_eq!(controller.observe(&window(16, 16, true, 100.0)), LimitChange::Hold);
        assert_eq!(controller.limit(), 8);
    }

    #[test]
    fn plan_limits_bounds() {
        let (start, max) = plan_limits(8, 4, 16_384, 2, 8);
        assert_eq!(start, 16);
        assert_eq!(max, 16); // fleet term binds: 2 hosts × 8
        let (start, max) = plan_limits(2, 1, 16_384, 100, 8);
        assert_eq!(start, 4);
        assert_eq!(max, 25); // CPU term binds: 1 core × 25
        let (start, max) = plan_limits(4, 2, 0, 100, 8);
        assert_eq!(start, 8);
        assert_eq!(max, 50); // unknown RAM: CPU term binds
    }
}
