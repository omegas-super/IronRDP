//! Credential-only authentication check.
//!
//! Runs the RDP connection sequence only as far as NLA — TCP, X.224 negotiation, the
//! TLS handshake, and the CredSSP exchange — and stops there. Nothing after
//! authentication runs (no MCS, licensing, activation, or channel setup), so a check
//! costs the protocol minimum of about five round trips instead of the roughly fifteen
//! of a full connect.

use ironrdp_connector::ClientConnector;
use ironrdp_connector::credssp::CredsspSequence;
use ironrdp_core::WriteBuf;
use ironrdp_tokio::reqwest::ReqwestNetworkClient;
use tracing::warn;

use crate::config::{ConfigBuilder, Destination};
use crate::rdp::{AsyncReadWrite, connect_tcp};

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
}

/// Outcome of a credential check.
#[derive(Debug)]
pub enum CredentialCheck {
    /// The server accepted the credentials.
    Valid,
    /// The server rejected the credentials, or the account cannot log on.
    Invalid {
        /// The CredSSP/NTLM failure reported by the server.
        message: String,
    },
}

/// Verifies credentials against the RDP server, stopping right after NLA.
///
/// Returns [`CredentialCheck::Valid`] once the CredSSP exchange completes and
/// [`CredentialCheck::Invalid`] when the server rejects the logon. Network, TLS, and
/// protocol failures surface as errors instead, so callers can tell "wrong password"
/// from "server unreachable".
pub async fn check_credentials(params: &CredentialCheckParams) -> anyhow::Result<CredentialCheck> {
    let destination = Destination::new(params.server.clone())?;

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
    let mut config = builder.build()?;
    // A credential check is only meaningful over NLA, which requires TLS.
    config.connector.enable_tls = true;
    config.connector.enable_credssp = true;
    config.connector.enable_standard_rdp_security = false;

    let stream = connect_tcp(&params.server, None)
        .await
        .map_err(|error| anyhow::anyhow!("connect to {}: {error}", params.server))?;
    if let Err(error) = stream.set_nodelay(true) {
        warn!(%error, "Failed to enable TCP_NODELAY on the RDP socket");
    }
    let client_addr = stream
        .local_addr()
        .map_err(|error| anyhow::anyhow!("get socket local address: {error}"))?;

    let mut framed = ironrdp_tokio::TokioFramed::new(stream);
    let mut connector = ClientConnector::new(config.connector, client_addr);

    let should_upgrade = ironrdp_tokio::connect_begin(&mut framed, &mut connector)
        .await
        .map_err(|error| anyhow::anyhow!("RDP negotiation failed: {error}"))?;

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
    let (tls_stream, tls_cert) = tls_upgrade.map_err(|error| anyhow::anyhow!("TLS upgrade failed: {error}"))?;

    let server_public_key = ironrdp_tls::extract_tls_server_public_key(&tls_cert)
        .ok_or_else(|| anyhow::anyhow!("unable to extract the TLS server public key"))?
        .to_owned();

    let _upgraded = ironrdp_tokio::mark_as_upgraded(should_upgrade, &mut connector);
    let erased_stream: Box<dyn AsyncReadWrite + Unpin + Send + Sync> = Box::new(tls_stream);
    let mut upgraded_framed = ironrdp_tokio::TokioFramed::new_with_leftover(erased_stream, leftover_bytes);

    if !connector.should_perform_credssp() {
        anyhow::bail!("the server did not negotiate NLA; credentials cannot be verified without a full logon");
    }

    let (sequence, ts_request) =
        CredsspSequence::init_for_connector(&mut connector, (&destination).into(), server_public_key, None)?;
    let mut network_client = ReqwestNetworkClient::new();
    let mut buf = WriteBuf::new();

    match ironrdp_tokio::perform_credssp(
        &mut upgraded_framed,
        &mut network_client,
        &mut buf,
        sequence,
        ts_request,
    )
    .await
    {
        Ok(()) => Ok(CredentialCheck::Valid),
        // TCP and TLS already succeeded, so a failure inside the CredSSP exchange means
        // the logon did not authenticate. Windows servers abort the TLS channel right
        // after a rejected NTLM authenticate, which surfaces as a read error rather than
        // a CredSSP status; both outcomes are a rejection from the caller's point of view.
        Err(error) => Ok(CredentialCheck::Invalid {
            message: error.to_string(),
        }),
    }
}
