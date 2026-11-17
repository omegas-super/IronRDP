//! Runtime-loaded Windows WebAuthn API.
//!
//! The WebAuthn exports are resolved with `GetProcAddress` instead of being linked
//! statically so the binaries keep starting on Windows versions that lack some or all
//! of them. Windows Server 2019 (10.0.17763) exports only the v1 subset, and builds
//! before 10.0.19041 do not export the cancellation/version APIs at all; a static
//! import would make the whole process fail to load with `STATUS_ENTRYPOINT_NOT_FOUND`.

use std::sync::OnceLock;

use windows::Win32::Foundation::{HMODULE, HWND};
use windows::Win32::Networking::WindowsWebServices::{
    WEBAUTHN_ASSERTION, WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS, WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS,
    WEBAUTHN_CLIENT_DATA, WEBAUTHN_COSE_CREDENTIAL_PARAMETERS, WEBAUTHN_CREDENTIAL_ATTESTATION,
    WEBAUTHN_RP_ENTITY_INFORMATION, WEBAUTHN_USER_ENTITY_INFORMATION,
};
use windows::Win32::System::LibraryLoader::{GetProcAddress, LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW};
use windows::core::PCSTR;
use windows::core::{BOOL, GUID, HRESULT, PCWSTR, w};

type GetApiVersionNumberFn = unsafe extern "system" fn() -> u32;
type IsUvpaaFn = unsafe extern "system" fn(*mut BOOL) -> HRESULT;
type MakeCredentialFn = unsafe extern "system" fn(
    HWND,
    *const WEBAUTHN_RP_ENTITY_INFORMATION,
    *const WEBAUTHN_USER_ENTITY_INFORMATION,
    *const WEBAUTHN_COSE_CREDENTIAL_PARAMETERS,
    *const WEBAUTHN_CLIENT_DATA,
    *const WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS,
    *mut *mut WEBAUTHN_CREDENTIAL_ATTESTATION,
) -> HRESULT;
type GetAssertionFn = unsafe extern "system" fn(
    HWND,
    PCWSTR,
    *const WEBAUTHN_CLIENT_DATA,
    *const WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS,
    *mut *mut WEBAUTHN_ASSERTION,
) -> HRESULT;
type FreeAssertionFn = unsafe extern "system" fn(*const WEBAUTHN_ASSERTION);
type FreeCredentialAttestationFn = unsafe extern "system" fn(*const WEBAUTHN_CREDENTIAL_ATTESTATION);
type GetCancellationIdFn = unsafe extern "system" fn(*mut GUID) -> HRESULT;
type CancelCurrentOperationFn = unsafe extern "system" fn(*const GUID) -> HRESULT;

/// Function table for the WebAuthn APIs used by the native backend.
pub(crate) struct WebAuthnApi {
    /// Keeps the DLL loaded for the process lifetime; the function pointers below
    /// would dangle if the module were unloaded. Stored as an integer because the
    /// table lives in a `static`, which requires `Sync`.
    _module: usize,
    pub(crate) get_api_version_number: GetApiVersionNumberFn,
    pub(crate) is_uvpaa: IsUvpaaFn,
    pub(crate) make_credential: MakeCredentialFn,
    pub(crate) get_assertion: GetAssertionFn,
    pub(crate) free_assertion: FreeAssertionFn,
    pub(crate) free_credential_attestation: FreeCredentialAttestationFn,
    pub(crate) get_cancellation_id: GetCancellationIdFn,
    pub(crate) cancel_current_operation: CancelCurrentOperationFn,
}

/// Returns the WebAuthn API table, or `None` when the running Windows version does
/// not provide the full API surface the native backend relies on.
pub(crate) fn api() -> Option<&'static WebAuthnApi> {
    static API: OnceLock<Option<WebAuthnApi>> = OnceLock::new();
    API.get_or_init(load).as_ref()
}

/// Whether the native RDPEWA backend can run on this Windows version.
pub fn is_supported() -> bool {
    api().is_some()
}

fn load() -> Option<WebAuthnApi> {
    // `LOAD_LIBRARY_SEARCH_SYSTEM32` forces resolution from System32, so a planted
    // webauthn.dll next to the executable cannot be picked up.
    let module = unsafe { LoadLibraryExW(w!("webauthn.dll"), None, LOAD_LIBRARY_SEARCH_SYSTEM32) }.ok()?;

    Some(WebAuthnApi {
        _module: module.0.addr(),
        get_api_version_number: resolve(module, c"WebAuthNGetApiVersionNumber")?,
        is_uvpaa: resolve(module, c"WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable")?,
        make_credential: resolve(module, c"WebAuthNAuthenticatorMakeCredential")?,
        get_assertion: resolve(module, c"WebAuthNAuthenticatorGetAssertion")?,
        free_assertion: resolve(module, c"WebAuthNFreeAssertion")?,
        free_credential_attestation: resolve(module, c"WebAuthNFreeCredentialAttestation")?,
        get_cancellation_id: resolve(module, c"WebAuthNGetCancellationId")?,
        cancel_current_operation: resolve(module, c"WebAuthNCancelCurrentOperation")?,
    })
}

fn resolve<T: Copy>(module: HMODULE, name: &core::ffi::CStr) -> Option<T> {
    let proc = unsafe { GetProcAddress(module, PCSTR(name.as_ptr().cast())) }?;
    debug_assert_eq!(size_of::<T>(), size_of_val(&proc));
    // SAFETY: every caller instantiates `T` with the exact signature of the export named
    // by `name`; `T` is always a function pointer, which is pointer-sized like `FARPROC`.
    Some(unsafe { core::mem::transmute_copy(&proc) })
}
