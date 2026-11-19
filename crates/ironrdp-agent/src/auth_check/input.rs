//! Input parsing, normalization, deduplication, and shuffling for bulk checks.

use std::collections::{HashMap, HashSet};
use std::io::Read as _;
use std::path::Path;

use anyhow::{Context as _, bail};
use rand::SeedableRng as _;
use rand::seq::SliceRandom as _;
use serde::Deserialize;

use crate::cli::InputFormat;

/// One credential check to perform.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CheckTarget {
    /// Server as canonical `host:port` (`[v6]:port` for IPv6).
    pub(crate) server: String,
    pub(crate) username: String,
    pub(crate) password: String,
    pub(crate) domain: Option<String>,
}

/// Input after parsing, normalization, and deduplication.
#[derive(Debug)]
pub(crate) struct PreparedInput {
    pub(crate) targets: Vec<CheckTarget>,
    pub(crate) duplicates_dropped: usize,
    pub(crate) multiple_passwords: Vec<String>,
}

/// Reads a text file (`-` for stdin) and decodes it from UTF-8 (BOM tolerated) or UTF-16.
pub(crate) fn read_text(path: &Path) -> anyhow::Result<String> {
    let bytes = if path == Path::new("-") {
        let mut buffer = Vec::new();
        std::io::stdin()
            .read_to_end(&mut buffer)
            .context("read standard input")?;
        buffer
    } else {
        std::fs::read(path).with_context(|| format!("read {}", path.display()))?
    };
    decode_text(bytes).with_context(|| format!("decode {}", path.display()))
}

fn decode_text(bytes: Vec<u8>) -> anyhow::Result<String> {
    if let Some(rest) = bytes.strip_prefix(&[0xFF, 0xFE]) {
        let units: Vec<u16> = rest
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect();
        String::from_utf16(&units).context("input is not valid UTF-16LE")
    } else if let Some(rest) = bytes.strip_prefix(&[0xFE, 0xFF]) {
        let units: Vec<u16> = rest
            .chunks_exact(2)
            .map(|chunk| u16::from_be_bytes([chunk[0], chunk[1]]))
            .collect();
        String::from_utf16(&units).context("input is not valid UTF-16BE")
    } else {
        let text = String::from_utf8(bytes).context("input is not valid UTF-8; save it as UTF-8")?;
        Ok(text.strip_prefix('\u{FEFF}').map(str::to_owned).unwrap_or(text))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct JsonRecord {
    server: String,
    username: String,
    password: String,
    #[serde(default)]
    domain: Option<String>,
}

/// Parses one-record-per-line input in the selected format.
pub(crate) fn parse_records(text: &str, format: InputFormat) -> anyhow::Result<Vec<CheckTarget>> {
    let mut targets = Vec::new();
    let mut errors = Vec::new();
    let mut first_data_line = true;

    for (line_no, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let parsed = match format {
            InputFormat::Txt => parse_txt_line(line),
            InputFormat::Csv => {
                let fields = match split_csv_line(line) {
                    Ok(fields) => fields,
                    Err(error) => {
                        push_error(&mut errors, line_no, &error);
                        continue;
                    }
                };
                if first_data_line && looks_like_header(&fields) {
                    first_data_line = false;
                    continue;
                }
                parse_fields(&fields, "csv")
            }
            InputFormat::Jsonl => match serde_json::from_str::<JsonRecord>(line) {
                Ok(record) => Ok(Some(CheckTarget {
                    server: record.server,
                    username: record.username,
                    password: record.password,
                    domain: record.domain,
                })),
                Err(error) => Err(format!("invalid JSON object: {error}")),
            },
        };
        first_data_line = false;

        match parsed {
            Ok(Some(target)) => match normalize_target(target) {
                Ok(target) => targets.push(target),
                Err(error) => push_error(&mut errors, line_no, &error),
            },
            Ok(None) => {}
            Err(error) => push_error(&mut errors, line_no, &error),
        }
    }

    finish_parsing(targets, errors)
}

fn push_error(errors: &mut Vec<String>, line_no: usize, error: &str) {
    if errors.len() < 20 {
        errors.push(format!("line {}: {error}", line_no + 1));
    }
}

fn finish_parsing(targets: Vec<CheckTarget>, errors: Vec<String>) -> anyhow::Result<Vec<CheckTarget>> {
    if !errors.is_empty() {
        bail!("invalid input:\n{}", errors.join("\n"));
    }
    if targets.is_empty() {
        bail!("input contains no checks");
    }
    Ok(targets)
}

fn parse_txt_line(line: &str) -> Result<Option<CheckTarget>, String> {
    let fields: Vec<&str> = line.split_whitespace().collect();
    match fields.as_slice() {
        [server, username, password] => Ok(Some(CheckTarget {
            server: (*server).to_owned(),
            username: (*username).to_owned(),
            password: (*password).to_owned(),
            domain: None,
        })),
        _ => Err(String::from(
            "expected exactly `server username password`; use CSV or JSONL when a domain is needed \
             (a fourth whitespace field would silently become a password/domain mix-up)",
        )),
    }
}

fn parse_fields(fields: &[String], format: &str) -> Result<Option<CheckTarget>, String> {
    match fields {
        [server, username, password] => Ok(Some(CheckTarget {
            server: server.clone(),
            username: username.clone(),
            password: password.clone(),
            domain: None,
        })),
        [server, username, password, domain] => Ok(Some(CheckTarget {
            server: server.clone(),
            username: username.clone(),
            password: password.clone(),
            domain: (!domain.trim().is_empty()).then(|| domain.clone()),
        })),
        _ => Err(format!(
            "expected 3 or 4 {format} fields (server, username, password, optional domain), got {}",
            fields.len()
        )),
    }
}

/// Minimal RFC 4180 subset: double-quoted fields, `""` escapes, no embedded newlines.
fn split_csv_line(line: &str) -> Result<Vec<String>, String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut chars = line.chars().peekable();
    let mut in_quotes = false;

    while let Some(character) = chars.next() {
        match character {
            '"' if in_quotes => {
                if chars.peek() == Some(&'"') {
                    chars.next();
                    current.push('"');
                } else {
                    in_quotes = false;
                }
            }
            '"' => {
                if current.trim().is_empty() {
                    current.clear();
                    in_quotes = true;
                } else {
                    return Err(String::from("unexpected quote inside an unquoted field"));
                }
            }
            ',' if !in_quotes => fields.push(core::mem::take(&mut current)),
            character => current.push(character),
        }
    }
    if in_quotes {
        return Err(String::from("unterminated quoted field"));
    }
    fields.push(current);

    Ok(fields)
}

fn looks_like_header(fields: &[String]) -> bool {
    const SERVER: &[&str] = &["server", "host", "hostname", "ip"];
    const USERNAME: &[&str] = &["username", "user", "login"];
    const PASSWORD: &[&str] = &["password", "pass"];
    const DOMAIN: &[&str] = &["domain"];

    let matches = |field: &str, names: &[&str]| {
        let field = field.trim().to_ascii_lowercase();
        names.contains(&field.as_str())
    };

    match fields {
        [server, username, password] => {
            matches(server, SERVER) && matches(username, USERNAME) && matches(password, PASSWORD)
        }
        [server, username, password, domain] => {
            matches(server, SERVER)
                && matches(username, USERNAME)
                && matches(password, PASSWORD)
                && matches(domain, DOMAIN)
        }
        _ => false,
    }
}

/// Parses the list-wise mode: hosts (one per line, optional `:port`) crossed with
/// line-wise zipped username/password pairs.
pub(crate) fn parse_lists(
    hosts_text: &str,
    users_text: &str,
    passwords_text: &str,
) -> anyhow::Result<Vec<CheckTarget>> {
    let hosts = meaningful_lines(hosts_text);
    let users = meaningful_lines(users_text);
    let passwords = meaningful_lines(passwords_text);

    if hosts.is_empty() {
        bail!("hosts list contains no entries");
    }
    if users.is_empty() {
        bail!("users list contains no entries");
    }
    if users.len() != passwords.len() {
        bail!(
            "users list has {} entries but passwords list has {}; they are paired line-wise",
            users.len(),
            passwords.len()
        );
    }

    let mut targets = Vec::with_capacity(hosts.len() * users.len());
    for (line_no, host) in hosts.iter().enumerate() {
        let server = normalize_server(host).with_context(|| format!("hosts line {}", line_no + 1))?;
        for (username, password) in users.iter().zip(passwords.iter()) {
            targets.push(CheckTarget {
                server: server.clone(),
                username: username.clone(),
                password: password.clone(),
                domain: None,
            });
        }
    }

    Ok(targets)
}

fn meaningful_lines(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_owned)
        .collect()
}

fn normalize_target(target: CheckTarget) -> Result<CheckTarget, String> {
    Ok(CheckTarget {
        server: normalize_server(&target.server).map_err(|error| error.to_string())?,
        username: target.username,
        password: target.password,
        domain: target.domain.filter(|domain| !domain.trim().is_empty()),
    })
}

/// Validates a server address and canonicalizes it to `host:port` (default port 3389).
pub(crate) fn normalize_server(raw: &str) -> anyhow::Result<String> {
    let server = raw.trim();
    if server.is_empty() {
        bail!("empty server address");
    }
    if server
        .chars()
        .any(|character| character.is_whitespace() || character.is_control())
    {
        bail!("server address {server:?} contains whitespace or control characters");
    }
    let destination = ironrdp_client::config::Destination::new(server.to_owned())
        .map_err(|error| anyhow::anyhow!("invalid server address {server:?}: {error}"))?;
    Ok(destination.to_string())
}

/// Normalized dedupe; refuses multiple passwords for the same account unless allowed.
pub(crate) fn dedupe(targets: Vec<CheckTarget>, allow_multiple_passwords: bool) -> anyhow::Result<PreparedInput> {
    let mut seen: HashSet<(String, String, Option<String>, String)> = HashSet::new();
    let mut account_password: HashMap<(String, String, Option<String>), String> = HashMap::new();
    let mut multiple_passwords: Vec<String> = Vec::new();
    let mut duplicates_dropped = 0usize;
    let mut deduped = Vec::with_capacity(targets.len());

    for target in targets {
        let host_key = target.server.to_ascii_lowercase();
        let user_key = target.username.to_ascii_lowercase();
        let domain_key = target
            .domain
            .as_deref()
            .map(str::to_ascii_lowercase)
            .filter(|domain| !domain.is_empty());

        let triple = (
            host_key.clone(),
            user_key.clone(),
            domain_key.clone(),
            target.password.clone(),
        );
        if !seen.insert(triple) {
            duplicates_dropped += 1;
            continue;
        }

        let account = (host_key, user_key, domain_key);
        match account_password.get(&account) {
            Some(existing) if existing != &target.password => {
                multiple_passwords.push(format!("{}@{}", target.username, target.server));
            }
            Some(_) => {}
            None => {
                account_password.insert(account, target.password.clone());
            }
        }

        deduped.push(target);
    }

    multiple_passwords.sort();
    multiple_passwords.dedup();
    if !multiple_passwords.is_empty() && !allow_multiple_passwords {
        bail!(
            "multiple passwords for the same account (the checker audits credentials you hold, one password \
             per account); pass --allow-multiple-passwords to override:\n{}",
            multiple_passwords.join("\n")
        );
    }

    Ok(PreparedInput {
        targets: deduped,
        duplicates_dropped,
        multiple_passwords,
    })
}

/// Shuffles targets with a reproducible seed.
pub(crate) fn shuffle(targets: &mut [CheckTarget], seed: u64) {
    let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
    targets.shuffle(&mut rng);
}

/// Derives a shuffle seed from the system clock and process id.
pub(crate) fn entropy_seed() -> u64 {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    let pid = u64::from(std::process::id());
    let mut state = u64::try_from(nanos).unwrap_or(u64::MAX) ^ (pid << 32) ^ 0x9E37_79B9_7F4A_7C15;
    // xorshift64: spread the entropy so adjacent runs differ in the low bits too.
    state ^= state << 13;
    state ^= state >> 7;
    state ^= state << 17;
    state
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn txt_requires_exactly_three_fields() {
        let targets = parse_records("10.0.0.1 alice secret\n", InputFormat::Txt).expect("valid input");
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].server, "10.0.0.1:3389");

        let error = parse_records("10.0.0.1 alice secret DOMAIN\n", InputFormat::Txt).expect_err("4 fields rejected");
        assert!(error.to_string().contains("exactly"));
    }

    #[test]
    fn csv_handles_quotes_and_headers() {
        let text = "server,username,password,domain\n10.0.0.1,alice,\"p,a\"\"ss\",CORP\n";
        let targets = parse_records(text, InputFormat::Csv).expect("valid csv");
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].password, "p,a\"ss");
        assert_eq!(targets[0].domain.as_deref(), Some("CORP"));
    }

    #[test]
    fn jsonl_rejects_unknown_fields() {
        let error = parse_records(
            "{\"server\":\"h\",\"usrname\":\"u\",\"password\":\"p\"}\n",
            InputFormat::Jsonl,
        )
        .expect_err("unknown field rejected");
        assert!(error.to_string().contains("invalid input"));
    }

    #[test]
    fn utf16_and_bom_are_decoded() {
        let utf16: Vec<u8> = [0xFF, 0xFE]
            .into_iter()
            .chain("h u p\n".encode_utf16().flat_map(u16::to_le_bytes))
            .collect();
        let text = decode_text(utf16).expect("utf16 decodes");
        assert_eq!(text, "h u p\n");

        let bom = decode_text(b"\xEF\xBB\xBFh u p\n".to_vec()).expect("bom stripped");
        assert_eq!(bom, "h u p\n");
    }

    #[test]
    fn dedupe_drops_exact_duplicates_and_refuses_multiple_passwords() {
        let targets = vec![
            CheckTarget {
                server: "h:3389".into(),
                username: "u".into(),
                password: "p".into(),
                domain: None,
            },
            CheckTarget {
                server: "H:3389".into(),
                username: "U".into(),
                password: "p".into(),
                domain: None,
            },
        ];
        let prepared = dedupe(targets, false).expect("duplicates only");
        assert_eq!(prepared.targets.len(), 1);
        assert_eq!(prepared.duplicates_dropped, 1);

        let conflicting = vec![
            CheckTarget {
                server: "h:3389".into(),
                username: "u".into(),
                password: "p1".into(),
                domain: None,
            },
            CheckTarget {
                server: "h:3389".into(),
                username: "u".into(),
                password: "p2".into(),
                domain: None,
            },
        ];
        assert!(dedupe(conflicting.clone(), false).is_err());
        let prepared = dedupe(conflicting, true).expect("override allowed");
        assert_eq!(prepared.multiple_passwords.len(), 1);
    }

    #[test]
    fn lists_zip_users_with_passwords() {
        let targets = parse_lists("10.0.0.1\n10.0.0.2:3391\n", "alice\nbob\n", "pw1\npw2\n").expect("lists parse");
        assert_eq!(targets.len(), 4);
        assert_eq!(targets[0].username, "alice");
        assert_eq!(targets[0].password, "pw1");
        assert_eq!(targets[1].server, "10.0.0.1:3389");
        assert_eq!(targets[2].server, "10.0.0.2:3391");

        let error = parse_lists("h\n", "a\nb\n", "p\n").expect_err("mismatched lengths");
        assert!(error.to_string().contains("paired line-wise"));
    }

    #[test]
    fn shuffle_is_deterministic_for_a_seed() {
        let make = || {
            vec![
                CheckTarget {
                    server: "a:1".into(),
                    username: "u".into(),
                    password: "p".into(),
                    domain: None,
                },
                CheckTarget {
                    server: "b:1".into(),
                    username: "u".into(),
                    password: "p".into(),
                    domain: None,
                },
                CheckTarget {
                    server: "c:1".into(),
                    username: "u".into(),
                    password: "p".into(),
                    domain: None,
                },
            ]
        };
        let mut first = make();
        let mut second = make();
        shuffle(&mut first, 42);
        shuffle(&mut second, 42);
        assert_eq!(first, second);
    }
}
