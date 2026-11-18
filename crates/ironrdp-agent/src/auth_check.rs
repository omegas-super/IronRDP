//! Credential-only authentication check (`auth-check`).
//!
//! Verifies a username and password against an RDP server by running the connection
//! sequence only as far as NLA, without opening a session on the server.

use std::sync::Arc;
use std::time::Instant;

use anyhow::Context as _;
use ironrdp_client::auth_check::{CredentialCheck, CredentialCheckParams, check_credentials};
use ironrdp_tls::{CertificateValidation, CertificateValidationCallback};

use crate::cli::AuthCheckArgs;

pub(crate) async fn run_auth_check(args: AuthCheckArgs) -> anyhow::Result<()> {
    let (certificate_validation, certificate_callback) = certificate_policy(args.skip_certificate_check)?;
    let params = CredentialCheckParams {
        server: args.server,
        username: args.username,
        password: args.password,
        domain: args.domain,
        certificate_validation,
        certificate_callback,
    };

    let started = Instant::now();
    let outcome = check_credentials(&params).await?;
    let elapsed_ms = started.elapsed().as_millis();

    match outcome {
        CredentialCheck::Valid => {
            println!("valid: the server accepted the credentials ({elapsed_ms} ms)");
            Ok(())
        }
        CredentialCheck::Invalid { message } => {
            anyhow::bail!("invalid: the server rejected the credentials ({elapsed_ms} ms): {message}")
        }
    }
}

fn certificate_policy(
    skip_certificate_check: bool,
) -> anyhow::Result<(CertificateValidation, Option<CertificateValidationCallback>)> {
    if skip_certificate_check {
        return Ok((CertificateValidation::DangerouslyAcceptInvalidCertificate, None));
    }

    use ironrdp_daemon::known_certificates::KnownCertificates;

    let store = KnownCertificates::default_path()
        .and_then(|path| KnownCertificates::load(&path))
        .context("load the known-certificates store")?;
    let callback: CertificateValidationCallback =
        Arc::new(move |der, endpoint, _reason| store.is_trusted(endpoint, der));

    Ok((CertificateValidation::Strict, Some(callback)))
}
