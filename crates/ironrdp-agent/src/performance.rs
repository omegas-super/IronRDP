//! Best-effort performance profile for the daemon process, machine capabilities for the
//! bulk credential checker, and Windows TCP tuning.
//!
//! The RDP session lives in the daemon child process, so raising that process's
//! scheduling priority is what keeps input and frame handling responsive when the
//! machine is busy with other work. The detected machine capabilities (logical CPUs,
//! physical cores, physical memory, elevation) are logged so the daemon log states which
//! profile was applied, and are reused by `auth-check` to size bulk concurrency.
//!
//! Everything here is opt-out through `IRONRDP_NO_PERF_PROFILE` and never fails the
//! process: every step is best effort.

use tracing::info;

/// Disables the automatic performance profile when set to a non-empty value.
pub(crate) const DISABLE_ENV: &str = "IRONRDP_NO_PERF_PROFILE";

/// Machine capabilities used to size bulk-check concurrency.
#[derive(Debug, Clone, Copy)]
pub(crate) struct SystemProfile {
    /// Logical processors available to this process.
    pub(crate) logical_cpus: u32,
    /// Physical cores (best effort; equals `logical_cpus` when unknown).
    pub(crate) physical_cores: u32,
    /// Installed physical memory in MiB (0 when unknown).
    pub(crate) total_memory_mb: u64,
    /// Whether the process token is elevated.
    pub(crate) elevated: bool,
}

/// Detects the machine capabilities, best effort.
pub(crate) fn profile() -> SystemProfile {
    #[cfg(windows)]
    {
        windows::profile()
    }

    #[cfg(not(windows))]
    {
        let logical_cpus = std::thread::available_parallelism()
            .map(std::num::NonZero::get)
            .unwrap_or(1);
        let logical_cpus = u32::try_from(logical_cpus).unwrap_or(1);
        SystemProfile {
            logical_cpus,
            physical_cores: logical_cpus,
            total_memory_mb: 0,
            elevated: false,
        }
    }
}

/// Applies the process performance profile, best effort.
pub(crate) fn apply() {
    if std::env::var_os(DISABLE_ENV).is_some_and(|value| !value.is_empty()) {
        info!(variable = DISABLE_ENV, "Performance profile disabled");
        return;
    }

    let system = profile();

    #[cfg(windows)]
    windows::apply_priority(system);

    #[cfg(not(windows))]
    info!(logical_cpus = system.logical_cpus, "Performance profile detected");
}

/// Outcome of the bulk-mode TCP tuning step.
#[derive(Debug, Default)]
pub(crate) struct NetworkTuningReport {
    /// Whether the dynamic port range was widened during this call.
    pub(crate) applied: bool,
    /// Human-readable summary for the run report.
    pub(crate) detail: String,
}

/// Raises the Windows dynamic TCP port range when elevated, so large fleets do not run
/// out of ephemeral ports. Best effort: a failure is reported, never propagated.
pub(crate) fn apply_network_tuning() -> NetworkTuningReport {
    if std::env::var_os(DISABLE_ENV).is_some_and(|value| !value.is_empty()) {
        return NetworkTuningReport {
            applied: false,
            detail: format!("TCP port tuning disabled by {DISABLE_ENV}"),
        };
    }

    #[cfg(windows)]
    {
        windows::apply_network_tuning()
    }

    #[cfg(not(windows))]
    {
        NetworkTuningReport {
            applied: false,
            detail: String::from("TCP port tuning is Windows-only"),
        }
    }
}

#[cfg(windows)]
mod windows {
    use std::os::windows::process::CommandExt as _;
    use std::process::Command;

    use tracing::{info, warn};
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Security::{GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation};
    use windows::Win32::System::Registry::{
        HKEY, HKEY_LOCAL_MACHINE, KEY_READ, REG_DWORD, RegCloseKey, RegOpenKeyExW, RegQueryValueExW,
    };
    use windows::Win32::System::SystemInformation::{
        GetLogicalProcessorInformation, GetSystemInfo, GlobalMemoryStatusEx, MEMORYSTATUSEX, SYSTEM_INFO,
        SYSTEM_LOGICAL_PROCESSOR_INFORMATION,
    };
    use windows::Win32::System::Threading::{
        ABOVE_NORMAL_PRIORITY_CLASS, GetCurrentProcess, HIGH_PRIORITY_CLASS, OpenProcessToken, PROCESS_CREATION_FLAGS,
        SetPriorityClass,
    };
    use windows::core::{PCWSTR, w};

    use super::{NetworkTuningReport, SystemProfile};

    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    /// Below this many dynamic ports the fleet path can exhaust the ephemeral range.
    const MIN_DYNAMIC_PORTS: u32 = 40_000;
    const TUNED_PORT_START: u32 = 10_000;
    const TUNED_PORT_COUNT: u32 = 55_535;

    pub(super) fn profile() -> SystemProfile {
        let mut system_info = SYSTEM_INFO::default();
        // SAFETY: `system_info` is valid writable storage for GetSystemInfo.
        unsafe { GetSystemInfo(&mut system_info) };

        let mut memory = MEMORYSTATUSEX {
            dwLength: u32::try_from(size_of::<MEMORYSTATUSEX>()).expect("MEMORYSTATUSEX size fits in u32"),
            ..Default::default()
        };
        // SAFETY: `memory.dwLength` is initialized as required by GlobalMemoryStatusEx.
        let memory_ok = unsafe { GlobalMemoryStatusEx(&mut memory) }.is_ok();

        let logical_cpus = system_info.dwNumberOfProcessors;
        SystemProfile {
            logical_cpus,
            physical_cores: physical_core_count().unwrap_or(logical_cpus),
            total_memory_mb: if memory_ok {
                memory.ullTotalPhys / (1024 * 1024)
            } else {
                0
            },
            elevated: is_process_elevated(),
        }
    }

    pub(super) fn apply_priority(system: SystemProfile) {
        let priority: PROCESS_CREATION_FLAGS = if system.elevated {
            HIGH_PRIORITY_CLASS
        } else {
            ABOVE_NORMAL_PRIORITY_CLASS
        };
        // SAFETY: GetCurrentProcess returns a pseudo-handle that needs no cleanup.
        let process = unsafe { GetCurrentProcess() };
        // SAFETY: the pseudo-handle stays valid for the lifetime of the process.
        let applied = unsafe { SetPriorityClass(process, priority) }.is_ok();

        if applied {
            info!(
                logical_cpus = system.logical_cpus,
                total_memory_mb = system.total_memory_mb,
                elevated = system.elevated,
                "Performance profile applied"
            );
        } else {
            warn!(
                logical_cpus = system.logical_cpus,
                elevated = system.elevated,
                "Failed to raise process priority"
            );
        }
    }

    pub(super) fn apply_network_tuning() -> NetworkTuningReport {
        if !is_process_elevated() {
            return NetworkTuningReport {
                applied: false,
                detail: format!(
                    "not elevated; run as administrator to widen the dynamic TCP port range \
                     (netsh int ipv4 set dynamicport tcp start={TUNED_PORT_START} num={TUNED_PORT_COUNT})"
                ),
            };
        }

        let current = dynamic_port_range().unwrap_or((49_152, 16_384));
        if current.1 >= MIN_DYNAMIC_PORTS {
            return NetworkTuningReport {
                applied: false,
                detail: format!(
                    "dynamic TCP port range already wide (start {}, {} ports)",
                    current.0, current.1
                ),
            };
        }

        let netsh = std::env::var_os("SystemRoot")
            .map(std::path::PathBuf::from)
            .map(|root| root.join("System32").join("netsh.exe"))
            .filter(|path| path.exists())
            .unwrap_or_else(|| std::path::PathBuf::from("netsh.exe"));
        let result = Command::new(&netsh)
            .args(["int", "ipv4", "set", "dynamicport", "tcp", "start=10000", "num=55535"])
            .creation_flags(CREATE_NO_WINDOW)
            .output();

        match result {
            Ok(output) if output.status.success() => NetworkTuningReport {
                applied: true,
                detail: format!(
                    "dynamic TCP port range widened from start {} ({} ports) to start {TUNED_PORT_START} ({TUNED_PORT_COUNT} ports)",
                    current.0, current.1
                ),
            },
            Ok(output) => NetworkTuningReport {
                applied: false,
                detail: format!(
                    "netsh failed ({}); run manually: netsh int ipv4 set dynamicport tcp start={TUNED_PORT_START} num={TUNED_PORT_COUNT}",
                    String::from_utf8_lossy(&output.stderr).trim()
                ),
            },
            Err(error) => NetworkTuningReport {
                applied: false,
                detail: format!("failed to run netsh: {error}"),
            },
        }
    }

    fn dynamic_port_range() -> Option<(u32, u32)> {
        let mut key = HKEY::default();
        // SAFETY: `key` is valid writable storage; the subkey path is a static NUL-terminated string.
        let status = unsafe {
            RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                w!("SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters"),
                Some(0),
                KEY_READ,
                &mut key,
            )
        };
        if status.is_err() {
            return None;
        }

        let start = query_dword(key, w!("DynamicPortRangeStartPort"));
        let count = query_dword(key, w!("DynamicPortRangeNumberOfPorts"));

        // SAFETY: `key` was opened above and is not used afterwards.
        let _ = unsafe { RegCloseKey(key) };

        match (start, count) {
            (Some(start), Some(count)) => Some((start, count)),
            _ => None,
        }
    }

    fn query_dword(key: HKEY, name: PCWSTR) -> Option<u32> {
        let mut value = 0u32;
        let mut value_size = u32::try_from(size_of::<u32>()).ok()?;
        let mut value_type = REG_DWORD;
        // SAFETY: `value` is sized for a DWORD and `value_size` receives the byte length;
        // the value name is a static NUL-terminated string.
        let status = unsafe {
            RegQueryValueExW(
                key,
                name,
                None,
                Some(&raw mut value_type),
                Some((&raw mut value).cast()),
                Some(&raw mut value_size),
            )
        };
        (status.is_ok() && value_type == REG_DWORD).then_some(value)
    }

    fn physical_core_count() -> Option<u32> {
        let mut length = 0u32;
        // SAFETY: a null buffer with a zero length queries the required size.
        let _ = unsafe { GetLogicalProcessorInformation(None, &mut length) };
        if length == 0 {
            return None;
        }

        let entries = usize::try_from(length).ok()? / size_of::<SYSTEM_LOGICAL_PROCESSOR_INFORMATION>();
        if entries == 0 {
            return None;
        }
        let mut buffer = vec![SYSTEM_LOGICAL_PROCESSOR_INFORMATION::default(); entries];
        // SAFETY: `buffer` holds `entries` records, matching the byte length reported above.
        unsafe { GetLogicalProcessorInformation(Some(buffer.as_mut_ptr()), &mut length) }.ok()?;

        let cores = buffer
            .iter()
            .filter(|entry| entry.Relationship == windows::Win32::System::SystemInformation::RelationProcessorCore)
            .count();
        u32::try_from(cores).ok().filter(|count| *count > 0)
    }

    pub(super) fn is_process_elevated() -> bool {
        let mut token = HANDLE::default();
        // SAFETY: GetCurrentProcess returns a pseudo-handle that needs no cleanup.
        let process = unsafe { GetCurrentProcess() };
        // SAFETY: the pseudo-handle is valid and `token` is writable storage for the handle.
        if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) }.is_err() {
            return false;
        }

        let mut elevation = TOKEN_ELEVATION::default();
        let mut returned_length = 0u32;
        // SAFETY: `elevation` is sized for TOKEN_ELEVATION and `returned_length` receives the length.
        let result = unsafe {
            GetTokenInformation(
                token,
                TokenElevation,
                Some((&raw mut elevation).cast()),
                u32::try_from(size_of::<TOKEN_ELEVATION>()).expect("TOKEN_ELEVATION size fits in u32"),
                &mut returned_length,
            )
        };
        // SAFETY: `token` was opened by OpenProcessToken and is not used afterwards.
        let _ = unsafe { CloseHandle(token) };

        result.is_ok() && elevation.TokenIsElevated != 0
    }
}
