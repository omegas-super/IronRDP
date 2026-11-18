//! Best-effort performance profile for the daemon process.
//!
//! The RDP session lives in the daemon child process, so raising that process's
//! scheduling priority is what keeps input and frame handling responsive when the
//! machine is busy with other work. The detected machine capabilities (logical CPUs,
//! physical memory, elevation) are logged so the daemon log states which profile was
//! applied.
//!
//! The profile is opt-out through `IRONRDP_NO_PERF_PROFILE` and never fails the
//! daemon: every step is best effort.

use tracing::info;

/// Disables the automatic performance profile when set to a non-empty value.
pub(crate) const DISABLE_ENV: &str = "IRONRDP_NO_PERF_PROFILE";

/// Applies the process performance profile, best effort.
pub(crate) fn apply() {
    if std::env::var_os(DISABLE_ENV).is_some_and(|value| !value.is_empty()) {
        info!(variable = DISABLE_ENV, "Performance profile disabled");
        return;
    }

    #[cfg(windows)]
    windows::apply_windows_profile();

    #[cfg(not(windows))]
    info!(
        logical_cpus = std::thread::available_parallelism()
            .map(std::num::NonZero::get)
            .unwrap_or(0),
        "Performance profile detected"
    );
}

#[cfg(windows)]
mod windows {
    use tracing::{info, warn};
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Security::{GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation};
    use windows::Win32::System::SystemInformation::{GetSystemInfo, GlobalMemoryStatusEx, MEMORYSTATUSEX, SYSTEM_INFO};
    use windows::Win32::System::Threading::{
        ABOVE_NORMAL_PRIORITY_CLASS, GetCurrentProcess, HIGH_PRIORITY_CLASS, OpenProcessToken, PROCESS_CREATION_FLAGS,
        SetPriorityClass,
    };

    pub(super) fn apply_windows_profile() {
        // SAFETY: `system_info` is valid writable storage for GetSystemInfo.
        let mut system_info = SYSTEM_INFO::default();
        unsafe { GetSystemInfo(&mut system_info) };

        let mut memory = MEMORYSTATUSEX {
            dwLength: u32::try_from(size_of::<MEMORYSTATUSEX>()).expect("MEMORYSTATUSEX size fits in u32"),
            ..Default::default()
        };
        // SAFETY: `memory.dwLength` is initialized as required by GlobalMemoryStatusEx.
        let memory_ok = unsafe { GlobalMemoryStatusEx(&mut memory) }.is_ok();
        let total_memory_mb = memory.ullTotalPhys / (1024 * 1024);

        let elevated = is_process_elevated();
        let priority: PROCESS_CREATION_FLAGS = if elevated {
            HIGH_PRIORITY_CLASS
        } else {
            ABOVE_NORMAL_PRIORITY_CLASS
        };
        // SAFETY: GetCurrentProcess returns a pseudo-handle that needs no cleanup.
        let applied = unsafe { SetPriorityClass(GetCurrentProcess(), priority) }.is_ok();

        if applied {
            info!(
                logical_cpus = system_info.dwNumberOfProcessors,
                total_memory_mb = memory_ok.then_some(total_memory_mb).unwrap_or(0),
                elevated,
                "Performance profile applied"
            );
        } else {
            warn!(
                logical_cpus = system_info.dwNumberOfProcessors,
                elevated, "Failed to raise process priority"
            );
        }
    }

    fn is_process_elevated() -> bool {
        let mut token = HANDLE::default();
        // SAFETY: GetCurrentProcess returns a pseudo-handle; `token` is valid writable storage.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }.is_err() {
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
