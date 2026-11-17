# ironrdp-rdpewa-native

Windows backend for the IronRDP [MS-RDPEWA] client.

## Paths

1. **webauthn.dll oneshot (preferred for ceremonies)**
   Forwards the original RDPEWA CBOR through `webauthn.dll`'s IWTS remote-RPC path
   (same private stack MSTSC uses). Required for **hash-only** hosts that omit
   `clientDataJSON` — public `WebAuthN*` APIs cannot complete those ceremonies.

2. **Public WebAuthN* APIs (fallback)**
   Used when oneshot is unavailable and the host supplied full `clientDataJSON`.

The public WebAuthN exports are resolved at runtime with `GetProcAddress` rather than
imported statically, so binaries keep starting on Windows versions that export only
part of the API. The backend is enabled only when the full surface it relies on is
present; `is_webauthn_supported()` reports availability. Windows 10 2004+ and
Windows 11 export everything. Windows 10 1903/1909 and Windows Server 2019 export
only the v1 subset (no `WebAuthNGetApiVersionNumber`, `WebAuthNGetCancellationId`,
`WebAuthNCancelCurrentOperation`), so the native backend declines RDPEWA requests
with `E_NOTIMPL` there.

Session channel registration may still prefer hosting `webauthn.dll` as a DVC COM
listener (`ironrdp-dvc-com-plugin`) for full MSTSC parity. Set
`IRONRDP_WEBAUTHN_FORCE_NATIVE=1` to exercise this backend via `RdpewaClientListener`
instead.

[MS-RDPEWA]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpewa/
