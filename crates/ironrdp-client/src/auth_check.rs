//! Credential-only authentication check.
//!
//! Runs the RDP connection sequence only as far as NLA — TCP, X.224 negotiation, the
//! TLS handshake, and the CredSSP exchange — and stops there. Nothing after
//! authentication runs (no MCS, licensing, activation, or channel setup), so a check
//! costs the protocol minimum of about seven round trips instead of the roughly fifteen
//! of a full connect.

use core::net::SocketAddr;
use core::time::Duration;

use ironrdp_connector::credssp::CredsspSequence;
use ironrdp_connector::{ClientConnector, ConnectorError, ConnectorErrorKind};
use ironrdp_core::WriteBuf;
use ironrdp_tokio::reqwest::ReqwestNetworkClient;
use tracing::warn;

use crate::config::{ConfigBuilder, Destination};
use crate::rdp::{AsyncReadWrite, connect_tcp};

/// Default TCP connect sub-deadline when [`CredentialCheckParams::connect_timeout`] is unset.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Stage of the connection sequence a check reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckStage {
    Resolve,
    Tcp,
    X224,
    Tls,
    Credssp,
}

/// Classification of a failed check, used by retry and concurrency-control policies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureKind {
    /// The deadline expired before the stage completed.
    Timeout,
    /// The server could not be reached (refused, unresolved, network unreachable).
    Unreachable,
    /// The TLS upgrade or certificate validation failed.
    Tls,
    /// A protocol-level failure in the X.224 negotiation.
    Protocol,
    /// A local socket resource error (buffer/port exhaustion); retrying immediately hurts.
    LocalSocket,
    /// The server did not negotiate NLA, so credentials cannot be verified without a full logon.
    NotNla,
}

/// Parameters for [`check_credentials`].
#[derive(Clone)]
pub struct CredentialCheckParams {
    /// RDP server address as `host[:port]`; the port defaults to 3389.
    pub server: String,
    /// Account user name.
    pub username: String,
    /// Account password.
    pub password: String,
    /// Optional account domain.
    pub domain: Option<String>,
    /// Certificate validation policy for the TLS upgrade.
    pub certificate_validation: ironrdp_tls::CertificateValidation,
    /// Optional callback consulted when strict validation fails.
    pub certificate_callback: Option<ironrdp_tls::CertificateValidationCallback>,
    /// TCP connect sub-deadline; [`DEFAULT_CONNECT_TIMEOUT`] when unset.
    pub connect_timeout: Option<Duration>,
    /// Pre-resolved address; when set, DNS resolution is skipped and the hostname from
    /// `server` is still used for SNI and certificate validation.
    pub resolved_addr: Option<SocketAddr>,
    /// Close the connection abortively (SO_LINGER 0) so the local port is released
    /// immediately instead of lingering in TIME_WAIT.
    pub reset_on_close: bool,
}

impl CredentialCheckParams {
    /// Creates parameters with the given target and credentials; other fields default to
    /// strict validation, a 5 s connect timeout, and no abortive close.
    #[must_use]
    pub fn new(server: impl Into<String>, username: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            server: server.into(),
            username: username.into(),
            password: password.into(),
            domain: None,
            certificate_validation: ironrdp_tls::CertificateValidation::Strict,
            certificate_callback: None,
            connect_timeout: None,
            resolved_addr: None,
            reset_on_close: false,
        }
    }
}

/// Outcome of a credential check.
#[derive(Debug)]
pub enum CredentialCheckOutcome {
    /// The server accepted the credentials.
    Valid,
    /// The server rejected the logon (or the account cannot log on).
    Invalid {
        stage: CheckStage,
        /// NTSTATUS reported by the server when it surfaced one (for example
        /// `0xC000_006D` for a bad password or `0xC000_0234` for a locked account).
        nt_status: Option<u32>,
        message: String,
    },
    /// The check could not complete; the credentials were not (or not necessarily) evaluated.
    Failed {
        stage: CheckStage,
        kind: FailureKind,
        message: String,
    },
}

/// Verifies credentials against the RDP server, stopping right after NLA.
///
/// Returns [`CredentialCheckOutcome::Valid`] once the CredSSP exchange completes,
/// [`CredentialCheckOutcome::Invalid`] when the server rejects the logon, and
/// [`CredentialCheckOutcome::Failed`] when the check could not be completed.
pub async fn check_credentials(params: CredentialCheckParams) -> CredentialCheckOutcome {
    let destination = match Destination::new(params.server.clone()) {
        Ok(destination) => destination,
        Err(error) => {
            return failed(
                CheckStage::Resolve,
                FailureKind::Unreachable,
                format!("invalid server address: {error}"),
            );
        }
    };

    let mut builder = ConfigBuilder::new()
        .with_destination(destination.clone())
        .with_username(params.username.clone())
        .with_password(params.password.clone())
        .with_client_build(0)
        .with_client_dir("C:\\Windows\\System32")
        .with_client_name("ironrdp-auth-check")
        .with_platform(ironrdp_pdu::rdp::capability_sets::MajorPlatformType::WINDOWS);
    if let Some(domain) = &params.domain {
        builder = builder.with_domain(domain.clone());
    }
    let mut config = match builder.build() {
        Ok(config) => config,
        Err(error) => return failed(CheckStage::Resolve, FailureKind::Unreachable, error.to_string()),
    };
    // A credential check is only meaningful over NLA, which requires TLS.
    config.connector.enable_tls = true;
    config.connector.enable_credssp = true;
    config.connector.enable_standard_rdp_security = false;

    let stream = match connect(&params).await {
        Ok(stream) => stream,
        Err((stage, kind, message)) => return failed(stage, kind, message),
    };
    if let Err(error) = stream.set_nodelay(true) {
        warn!(%error, "Failed to enable TCP_NODELAY on the RDP socket");
    }
    if params.reset_on_close {
        // SO_LINGER(0) turns the close into a RST, releasing the local port immediately
        // instead of holding it in TIME_WAIT for the system's timed-wait delay.
        if let Err(error) = socket2::SockRef::from(&stream).set_linger(Some(Duration::ZERO)) {
            warn!(%error, "Failed to enable SO_LINGER(0) on the RDP socket");
        }
    }
    let client_addr = match stream.local_addr() {
        Ok(client_addr) => client_addr,
        Err(error) => {
            return failed(
                CheckStage::Tcp,
                FailureKind::LocalSocket,
                format!("get socket local address: {error}"),
            );
        }
    };

    let mut framed = ironrdp_tokio::TokioFramed::new(stream);
    let mut connector = ClientConnector::new(config.connector, client_addr);

    let should_upgrade = match ironrdp_tokio::connect_begin(&mut framed, &mut connector).await {
        Ok(should_upgrade) => should_upgrade,
        Err(error) => {
            return failed(
                CheckStage::X224,
                FailureKind::Protocol,
                format!("RDP negotiation failed: {error}"),
            );
        }
    };

    let (stream, leftover_bytes) = framed.into_inner();
    let tls_upgrade = match params.certificate_callback.clone() {
        Some(callback) => {
            ironrdp_tls::upgrade_with_certificate_validation_callback_for_endpoint(
                stream,
                destination.name(),
                &destination.to_string(),
                callback,
            )
            .await
        }
        None => {
            ironrdp_tls::upgrade_with_certificate_validation(stream, destination.name(), params.certificate_validation)
                .await
        }
    };
    let (tls_stream, tls_cert) = match tls_upgrade {
        Ok(upgraded) => upgraded,
        Err(error) => {
            return failed(
                CheckStage::Tls,
                FailureKind::Tls,
                format!("TLS upgrade failed: {error}"),
            );
        }
    };

    let Some(server_public_key) = ironrdp_tls::extract_tls_server_public_key(&tls_cert) else {
        return failed(
            CheckStage::Tls,
            FailureKind::Tls,
            "unable to extract the TLS server public key".to_owned(),
        );
    };
    let server_public_key = server_public_key.to_owned();

    let _upgraded = ironrdp_tokio::mark_as_upgraded(should_upgrade, &mut connector);
    let erased_stream: Box<dyn AsyncReadWrite + Unpin + Send + Sync> = Box::new(tls_stream);
    let mut upgraded_framed = ironrdp_tokio::TokioFramed::new_with_leftover(erased_stream, leftover_bytes);

    if !connector.should_perform_credssp() {
        return failed(
            CheckStage::Credssp,
            FailureKind::NotNla,
            "the server did not negotiate NLA; credentials cannot be verified without a full logon".to_owned(),
        );
    }

    let sequence = match CredsspSequence::init_for_connector(&connector, (&destination).into(), server_public_key, None)
    {
        Ok((sequence, ts_request)) => (sequence, ts_request),
        Err(error) => {
            return failed(
                CheckStage::Credssp,
                FailureKind::Protocol,
                format!("CredSSP setup failed: {error}"),
            );
        }
    };
    let mut network_client = ReqwestNetworkClient::new();
    let mut buf = WriteBuf::new();

    match ironrdp_tokio::perform_credssp(
        &mut upgraded_framed,
        &mut network_client,
        &mut buf,
        sequence.0,
        sequence.1,
    )
    .await
    {
        Ok(()) => CredentialCheckOutcome::Valid,
        // TCP and TLS already succeeded, so a failure inside the CredSSP exchange means
        // the logon did not authenticate. Windows servers abort the TLS channel right
        // after a rejected NTLM authenticate, which surfaces as a read error rather than
        // a CredSSP status; both outcomes are a rejection from the caller's point of view.
        Err(error) => CredentialCheckOutcome::Invalid {
            stage: CheckStage::Credssp,
            nt_status: nt_status_of(&error),
            message: error.to_string(),
        },
    }
}

type ConnectFailure = (CheckStage, FailureKind, String);

async fn connect(params: &CredentialCheckParams) -> Result<tokio::net::TcpStream, ConnectFailure> {
    let timeout = params.connect_timeout.unwrap_or(DEFAULT_CONNECT_TIMEOUT);

    match params.resolved_addr {
        Some(addr) => match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => Ok(stream),
            Ok(Err(error)) => Err(classify_connect_error(error, params)),
            Err(_) => Err((
                CheckStage::Tcp,
                FailureKind::Timeout,
                format!("connect to {addr} timed out after {timeout:?}"),
            )),
        },
        None => connect_tcp(&params.server, Some(timeout))
            .await
            .map_err(|error| classify_connect_error(error, params)),
    }
}

fn classify_connect_error(error: std::io::Error, params: &CredentialCheckParams) -> ConnectFailure {
    let message = format!("connect to {}: {error}", params.server);
    let kind = match error.kind() {
        std::io::ErrorKind::TimedOut => FailureKind::Timeout,
        std::io::ErrorKind::NotFound => FailureKind::Unreachable,
        _ => match error.raw_os_error() {
            // WSAENOBUFS, WSAEADDRINUSE, WSAEADDRNOTAVAIL: local socket resources exhausted.
            Some(10055 | 10048 | 10049) => FailureKind::LocalSocket,
            _ => FailureKind::Unreachable,
        },
    };
    let stage = if error.kind() == std::io::ErrorKind::NotFound {
        CheckStage::Resolve
    } else {
        CheckStage::Tcp
    };
    (stage, kind, message)
}

fn nt_status_of(error: &ConnectorError) -> Option<u32> {
    match error.kind() {
        ConnectorErrorKind::Credssp(sspi_error) => sspi_error.nstatus.map(|status| status.0),
        _ => None,
    }
}

fn failed(stage: CheckStage, kind: FailureKind, message: String) -> CredentialCheckOutcome {
    CredentialCheckOutcome::Failed { stage, kind, message }
}
