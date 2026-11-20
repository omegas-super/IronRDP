//! Atomic, no-overwrite report writing for `swastik-rdp`.
//!
//! Each file is serialized to a temporary sibling and renamed into place only after all
//! four payloads have been prepared successfully. A name collision never truncates an
//! existing file. Passwords appear only in goods.txt and bad.txt, which are written at the
//! explicit request of the operator; the HTTP surface and summary.ndjson never carry them.

use core::fmt::Write as _;
use std::fs::OpenOptions;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};

use anyhow::{Context as _, bail};
use serde::Serialize;

use std::collections::HashMap;

use crate::auth_check::scheduler::{CheckResult, CheckStatus};

pub(crate) const FILE_NAMES: [&str; 4] = ["goods.txt", "bad.txt", "errors.txt", "summary.ndjson"];
pub(crate) const HEADER: &str = "# swastik-rdp results v1\nserver\tusername\tpassword\tdomain\telapsed_ms\n";

#[derive(Debug, Clone, Serialize)]
pub(crate) struct Summary {
    pub(crate) total: usize,
    pub(crate) completed: usize,
    pub(crate) valid: usize,
    pub(crate) invalid: usize,
    pub(crate) errors: usize,
    pub(crate) unique_hosts: usize,
    pub(crate) profile: &'static str,
    pub(crate) start_limit: usize,
    pub(crate) max_limit: usize,
    pub(crate) per_host: usize,
    pub(crate) elapsed_ms: u64,
    pub(crate) checks_per_second: f64,
    pub(crate) cancelled: bool,
}

/// Writes all four reports into `dir`, which must already exist and be empty of report names.
pub(crate) fn write_all(
    dir: &Path,
    results: &[CheckResult],
    summary: &Summary,
    credentials: &HashMap<usize, String>,
) -> anyhow::Result<()> {
    std::fs::create_dir_all(dir).with_context(|| format!("create output directory {}", dir.display()))?;
    let mut order: Vec<usize> = (0..results.len()).collect();
    order.sort_by_key(|&position| results[position].index);

    let mut goods = String::from(HEADER);
    let mut bad = String::from(HEADER);
    let mut errors = String::from("# swastik-rdp results v1\nindex\tserver\tusername\tkind\tstage\tmessage\n");
    let mut ndjson = String::new();

    for &position in &order {
        let result = &results[position];
        let mut fields = String::new();
        write_tsv_field(&mut fields, &result.server);
        fields.push('\t');
        write_tsv_field(&mut fields, &result.username);
        fields.push('\t');
        write_tsv_field(&mut fields, credentials.get(&result.index).map_or("", String::as_str));
        fields.push('\t');
        write_tsv_field(&mut fields, result.domain.as_deref().unwrap_or_default());
        let _ = writeln!(fields, "\t{}", result.elapsed_ms);

        match &result.status {
            CheckStatus::Valid => goods.push_str(&fields),
            CheckStatus::Invalid { nt_status, message } => {
                bad.push_str(&fields);
                bad.push('\t');
                bad.push_str(&json_string(&nt_status.map(|status| format!("0x{status:08X}"))));
                bad.push('\t');
                bad.push_str(&json_string(&sanitize_message(message)));
                bad.push('\n');
            }
            CheckStatus::Error { kind, stage, message } => {
                let _ = writeln!(
                    errors,
                    "{}\t{}\t{}\t{}\t{}\t{}",
                    json_string(&result.index),
                    json_string(&result.server),
                    json_string(&result.username),
                    json_string(&kind.as_str()),
                    json_string(&stage.map(stage_name).unwrap_or_default()),
                    json_string(&sanitize_message(message))
                );
            }
        }
        append_summary_line(&mut ndjson, result)?;
    }
    let summary_record = serde_json::json!({
        "type": "summary",
        "total": summary.total,
        "completed": summary.completed,
        "valid": summary.valid,
        "invalid": summary.invalid,
        "errors": summary.errors,
        "unique_hosts": summary.unique_hosts,
        "profile": summary.profile,
        "concurrency": {
            "start": summary.start_limit,
            "max": summary.max_limit,
            "per_host": summary.per_host,
        },
        "elapsed_ms": summary.elapsed_ms,
        "checks_per_second": summary.checks_per_second,
        "cancelled": summary.cancelled,
    });
    let _ = writeln!(ndjson, "{}", serde_json::to_string(&summary_record)?);

    let payloads = [goods, bad, errors, ndjson];
    let mut temps = Vec::new();
    for (name, contents) in FILE_NAMES.iter().zip(payloads) {
        let path = dir.join(name);
        if path.exists() {
            bail!("report already exists: {}", path.display());
        }
        let temp = temp_path(dir, name)?;
        write_new(&temp, contents.as_bytes()).with_context(|| format!("stage report {}", temp.display()))?;
        temps.push((temp, path));
    }
    for (temp, path) in &temps {
        std::fs::rename(temp, path).with_context(|| format!("publish {}", path.display()))?;
    }
    Ok(())
}

/// Remote error text is untrusted. Keep it as a single printable line so a server cannot use
/// control characters to forge report structure, even though JSON escaping already prevents
/// an NDJSON line break.
fn sanitize_message(message: &str) -> String {
    const MAX_LENGTH: usize = 512;
    let cleaned: String = message
        .chars()
        .map(|character| if character.is_control() { ' ' } else { character })
        .take(MAX_LENGTH)
        .collect();
    if cleaned.is_empty() { String::from("-") } else { cleaned }
}

fn stage_name(stage: ironrdp_client::auth_check::CheckStage) -> &'static str {
    use ironrdp_client::auth_check::CheckStage;
    match stage {
        CheckStage::Resolve => "resolve",
        CheckStage::Tcp => "tcp",
        CheckStage::X224 => "x224",
        CheckStage::Tls => "tls",
        CheckStage::Credssp => "credssp",
    }
}

fn append_summary_line(buffer: &mut String, result: &CheckResult) -> anyhow::Result<()> {
    let (label, detail) = match &result.status {
        CheckStatus::Valid => ("valid", serde_json::Value::Null),
        CheckStatus::Invalid { nt_status, message } => (
            "invalid",
            serde_json::json!({"nt_status": nt_status, "message": sanitize_message(message)}),
        ),
        CheckStatus::Error { kind, stage, message } => (
            "error",
            serde_json::json!({
                "kind": kind.as_str(),
                "stage": stage.map(stage_name),
                "message": sanitize_message(message),
            }),
        ),
    };
    let line = serde_json::json!({
        "server": result.server,
        "username": result.username,
        "domain": result.domain,
        "elapsed_ms": result.elapsed_ms,
        "index": result.index,
        "result": label,
        "detail": detail,
    });
    let text = serde_json::to_string(&line).context("serialize summary line")?;
    let _ = writeln!(buffer, "{text}");
    Ok(())
}

/// JSON string escaping also makes tabs/newlines safe inside a TSV column.
fn json_string(value: &impl Serialize) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| String::from("\"\""))
}

fn write_tsv_field(buffer: &mut String, value: &str) {
    buffer.push_str(&json_string(&value));
}

fn temp_path(dir: &Path, name: &str) -> anyhow::Result<PathBuf> {
    let pid = std::process::id();
    for attempt in 0..100 {
        let candidate = dir.join(format!(".{name}.{pid}.{attempt}.tmp"));
        if !candidate.exists() {
            return Ok(candidate);
        }
    }
    bail!("could not allocate a temporary file for {name}")
}

fn write_new(path: &Path, contents: &[u8]) -> io::Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(contents)?;
    file.sync_all()?;
    drop(file);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth_check::scheduler::ErrorKind;
    use ironrdp_client::auth_check::CheckStage;

    fn result(index: usize, status: CheckStatus) -> CheckResult {
        CheckResult {
            index,
            plan_index: index,
            server: String::from("10.0.0.1:3389"),
            username: String::from("alice"),
            domain: Some(String::from("CORP")),
            status,
            elapsed_ms: 12,
            attempts: 1,
            timeout_stage: None,
        }
    }

    fn summary() -> Summary {
        Summary {
            total: 3,
            completed: 3,
            valid: 1,
            invalid: 1,
            errors: 1,
            unique_hosts: 1,
            profile: "max",
            start_limit: 8,
            max_limit: 8,
            per_host: 8,
            elapsed_ms: 36,
            checks_per_second: 83.3,
            cancelled: false,
        }
    }

    #[test]
    fn writes_credentials_by_index_and_keeps_them_out_of_errors_and_summary() {
        let root = std::env::temp_dir().join(format!("swastik-report-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("isolated temp dir");

        let results = vec![
            result(
                1,
                CheckStatus::Invalid {
                    nt_status: Some(0xC000006D),
                    message: String::from("rejected"),
                },
            ),
            result(0, CheckStatus::Valid),
            result(
                2,
                CheckStatus::Error {
                    kind: ErrorKind::Unreachable,
                    stage: Some(CheckStage::Tcp),
                    message: String::from("host down"),
                },
            ),
        ];
        let credentials = HashMap::from([
            (0, String::from("good-pass")),
            (1, String::from("bad-pass")),
            (2, String::from("error-pass")),
        ]);
        write_all(&root, &results, &summary(), &credentials).expect("reports written");

        let goods = std::fs::read_to_string(root.join("goods.txt")).expect("goods");
        let bad = std::fs::read_to_string(root.join("bad.txt")).expect("bad");
        let errors = std::fs::read_to_string(root.join("errors.txt")).expect("errors");
        let ndjson = std::fs::read_to_string(root.join("summary.ndjson")).expect("summary");

        assert!(
            goods.contains("good-pass"),
            "result index 0 must join to its own password"
        );
        assert!(!goods.contains("bad-pass"));
        assert!(bad.contains("bad-pass"), "result index 1 must join to its own password");
        assert!(!bad.contains("good-pass"));
        assert!(!errors.contains("-pass"), "errors.txt must not contain any password");
        assert!(
            !ndjson.contains("-pass"),
            "summary.ndjson must not contain any password"
        );
        assert!(
            ndjson
                .lines()
                .last()
                .is_some_and(|line| line.contains("\"type\":\"summary\""))
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn refuses_to_overwrite_existing_reports() {
        let root = std::env::temp_dir().join(format!("swastik-overwrite-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("isolated temp dir");
        let results = vec![result(0, CheckStatus::Valid)];
        let credentials = HashMap::from([(0, String::from("pw"))]);
        write_all(&root, &results, &summary(), &credentials).expect("first write");
        assert!(write_all(&root, &results, &summary(), &credentials).is_err());
        let _ = std::fs::remove_dir_all(&root);
    }
}
