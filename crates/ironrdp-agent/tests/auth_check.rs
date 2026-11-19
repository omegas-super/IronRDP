#![allow(unused_crate_dependencies)]
#![allow(clippy::panic)]
#![allow(clippy::std_instead_of_core)]

//! Integration tests for `auth-check` against in-process fake servers.
//!
//! The fake servers never speak RDP: a closed connection surfaces as a `protocol`
//! error during X.224 negotiation, and a silent one as a `timeout`, which is enough to
//! exercise the scheduler, the admission limits, the ndjson contract, and the exit codes.

use std::io::Read as _;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Output;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

use serde_json::Value;

#[derive(Clone, Copy)]
enum Behavior {
    CloseImmediately,
    StaySilent,
}

struct TestServer {
    addr: SocketAddr,
    peak: Arc<AtomicUsize>,
    accepted: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl TestServer {
    fn start(behavior: Behavior) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind fake server");
        let addr = listener.local_addr().expect("fake server address");
        listener.set_nonblocking(true).expect("nonblocking listener");

        let peak = Arc::new(AtomicUsize::new(0));
        let accepted = Arc::new(AtomicUsize::new(0));
        let current = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));

        let handle = thread::spawn({
            let peak = Arc::clone(&peak);
            let accepted = Arc::clone(&accepted);
            let current = Arc::clone(&current);
            let stop = Arc::clone(&stop);
            move || {
                while !stop.load(Ordering::Relaxed) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            accepted.fetch_add(1, Ordering::SeqCst);
                            match behavior {
                                Behavior::CloseImmediately => drop(stream),
                                Behavior::StaySilent => {
                                    let now = current.fetch_add(1, Ordering::SeqCst) + 1;
                                    peak.fetch_max(now, Ordering::SeqCst);
                                    let current = Arc::clone(&current);
                                    thread::spawn(move || {
                                        hold_connection(stream);
                                        current.fetch_sub(1, Ordering::SeqCst);
                                    });
                                }
                            }
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(2));
                        }
                        Err(_) => break,
                    }
                }
            }
        });

        Self {
            addr,
            peak,
            accepted,
            stop,
            handle: Some(handle),
        }
    }

    fn peak(&self) -> usize {
        self.peak.load(Ordering::SeqCst)
    }

    fn accepted(&self) -> usize {
        self.accepted.load(Ordering::SeqCst)
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// Reads until the client resets or closes the connection.
fn hold_connection(mut stream: TcpStream) {
    // Windows may hand an accepted socket the listener's non-blocking mode; force blocking
    // so the connection stays open instead of being dropped on the first `WouldBlock`.
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
    let mut buffer = [0u8; 4096];
    loop {
        match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(_) => break,
        }
    }
}

fn temp_input(name: &str, contents: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("ironrdp-auth-check-{}-{name}.txt", std::process::id()));
    std::fs::write(&path, contents).expect("write input file");
    path
}

fn records(server: SocketAddr, count: usize) -> String {
    let mut text = String::new();
    for index in 0..count {
        text.push_str(&format!("{server} user{index} pass-{index}\n"));
    }
    text
}

fn run(args: &[&str]) -> Output {
    run_with_env(args, &[])
}

fn run_with_env(args: &[&str], vars: &[(&str, &str)]) -> Output {
    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_ironrdp-agent"));
    command.arg("auth-check").args(args);
    for (name, value) in vars {
        command.env(name, value);
    }
    command.output().expect("run ironrdp-agent")
}

fn json_lines(output: &Output) -> Vec<Value> {
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("ndjson line parses"))
        .collect()
}

fn summary(values: &[Value]) -> &Value {
    values
        .iter()
        .find(|value| value["type"] == "summary")
        .expect("summary event")
}

fn path_arg(path: &Path) -> &str {
    path.to_str().expect("utf-8 path")
}

#[test]
fn fast_completing_checks_are_not_dropped_by_pacing() {
    // Connections that fail in about a millisecond complete faster than the 10 ms per-host
    // start pacing, so results arrive while more work for the host is parked as deferred.
    // Every target must still produce exactly one result.
    let server = TestServer::start(Behavior::CloseImmediately);
    let input = temp_input("pacing", &records(server.addr, 50));
    let output = run(&[
        "--input",
        path_arg(&input),
        "--format",
        "ndjson",
        "--no-shuffle",
        "--no-tune-system",
        "--concurrency",
        "8",
        "--per-host",
        "2",
        "--timeout-ms",
        "1000",
        "--connect-timeout-ms",
        "1000",
    ]);

    assert_eq!(output.status.code(), Some(2));
    let values = json_lines(&output);
    let results = values.iter().filter(|value| value["type"] == "result").count();
    assert_eq!(results, 50, "every check must produce a result");
    let summary = summary(&values);
    assert_eq!(summary["completed"], 50);
    assert_eq!(summary["total"], 50);
}

#[test]
fn closed_connections_report_protocol_errors() {
    let server = TestServer::start(Behavior::CloseImmediately);
    let input = temp_input("closed", &records(server.addr, 5));
    let output = run(&[
        "--input",
        path_arg(&input),
        "--format",
        "ndjson",
        "--no-shuffle",
        "--no-tune-system",
        "--concurrency",
        "2",
        "--per-host",
        "2",
        "--timeout-ms",
        "1000",
        "--connect-timeout-ms",
        "1000",
    ]);

    assert_eq!(
        output.status.code(),
        Some(2),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let values = json_lines(&output);
    let results: Vec<&Value> = values.iter().filter(|value| value["type"] == "result").collect();
    assert_eq!(results.len(), 5);
    for value in &results {
        assert_eq!(value["result"], "error");
        assert_eq!(value["kind"], "protocol");
        assert_eq!(value["stage"], "x224");
    }

    let summary = summary(&values);
    assert_eq!(summary["total"], 5);
    assert_eq!(summary["completed"], 5);
    assert_eq!(summary["errors"], 5);
    assert_eq!(summary["error_kinds"]["protocol"], 5);
    assert_eq!(summary["valid"], 0);
    assert_eq!(summary["invalid"], 0);

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains("pass-0"), "passwords must never appear in output");
}

#[test]
fn silent_servers_produce_timeout_errors() {
    let server = TestServer::start(Behavior::StaySilent);
    let input = temp_input("silent", &records(server.addr, 4));
    let output = run(&[
        "--input",
        path_arg(&input),
        "--format",
        "ndjson",
        "--no-shuffle",
        "--no-tune-system",
        "--concurrency",
        "4",
        "--per-host",
        "4",
        "--timeout-ms",
        "300",
        "--connect-timeout-ms",
        "300",
    ]);

    assert_eq!(output.status.code(), Some(2));
    let values = json_lines(&output);
    let results: Vec<&Value> = values.iter().filter(|value| value["type"] == "result").collect();
    assert_eq!(results.len(), 4);
    for value in &results {
        assert_eq!(value["result"], "error", "result line: {value}");
        assert_eq!(value["kind"], "timeout", "result line: {value}");
        assert!(
            value["elapsed_ms"].as_u64().expect("elapsed") >= 200,
            "a timed-out check reports its deadline, got {value}"
        );
    }
    assert_eq!(summary(&values)["error_kinds"]["timeout"], 4);
    assert_eq!(server.accepted(), 4);
}

#[test]
fn per_host_cap_serializes_connections() {
    let server = TestServer::start(Behavior::StaySilent);
    let input = temp_input("host-cap", &records(server.addr, 12));

    let capped = run(&[
        "--input",
        path_arg(&input),
        "--format",
        "ndjson",
        "--no-shuffle",
        "--no-tune-system",
        "--concurrency",
        "12",
        "--per-host",
        "2",
        "--timeout-ms",
        "300",
        "--connect-timeout-ms",
        "300",
    ]);
    assert_eq!(capped.status.code(), Some(2));
    let capped_values = json_lines(&capped);
    let capped_elapsed = summary(&capped_values)["elapsed_ms"].as_u64().expect("elapsed");
    assert!(
        capped_elapsed >= 1000,
        "12 checks at 300 ms with a per-host cap of 2 need at least 6 rounds, took {capped_elapsed} ms"
    );
    assert!(
        server.peak() <= 3,
        "per-host cap of 2 exceeded (allowing one in-flight close race): peak {}",
        server.peak()
    );

    let uncapped = run(&[
        "--input",
        path_arg(&input),
        "--format",
        "ndjson",
        "--no-shuffle",
        "--no-tune-system",
        "--concurrency",
        "12",
        "--per-host",
        "12",
        "--timeout-ms",
        "300",
        "--connect-timeout-ms",
        "300",
    ]);
    assert_eq!(uncapped.status.code(), Some(2));
    let uncapped_values = json_lines(&uncapped);
    let uncapped_elapsed = summary(&uncapped_values)["elapsed_ms"].as_u64().expect("elapsed");
    assert!(
        uncapped_elapsed <= 900,
        "without a per-host cap the 12 checks run in one round, took {uncapped_elapsed} ms"
    );
}

#[test]
fn global_limit_serializes_connections() {
    let server = TestServer::start(Behavior::StaySilent);
    let input = temp_input("global-cap", &records(server.addr, 12));

    let limited = run(&[
        "--input",
        path_arg(&input),
        "--format",
        "ndjson",
        "--no-shuffle",
        "--no-tune-system",
        "--concurrency",
        "3",
        "--per-host",
        "12",
        "--timeout-ms",
        "300",
        "--connect-timeout-ms",
        "300",
    ]);
    assert_eq!(limited.status.code(), Some(2));
    let limited_values = json_lines(&limited);
    let limited_elapsed = summary(&limited_values)["elapsed_ms"].as_u64().expect("elapsed");
    assert!(
        limited_elapsed >= 1000,
        "12 checks at 300 ms with a global limit of 3 need 4 rounds, took {limited_elapsed} ms"
    );
    let concurrency = &summary(&limited_values)["concurrency"];
    assert_eq!(concurrency["start"], 3);
    assert_eq!(concurrency["final"], 3);
    assert_eq!(concurrency["pinned"], true);
}

#[test]
fn dry_run_prints_the_plan_without_connecting() {
    let server = TestServer::start(Behavior::StaySilent);
    let input = temp_input("dry", &records(server.addr, 3));
    let output = run(&[
        "--input",
        path_arg(&input),
        "--format",
        "ndjson",
        "--no-shuffle",
        "--dry-run",
    ]);

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(server.accepted(), 0, "a dry run must not connect");
    let values = json_lines(&output);
    assert_eq!(values.iter().filter(|value| value["type"] == "plan").count(), 3);
    let summary = values.last().expect("plan summary");
    assert_eq!(summary["type"], "plan_summary");
    assert_eq!(summary["total"], 3);
}

#[test]
fn ambient_rdp_credentials_do_not_break_bulk_mode() {
    let server = TestServer::start(Behavior::CloseImmediately);
    let input = temp_input("env", &records(server.addr, 3));
    let output = run_with_env(
        &[
            "--input",
            path_arg(&input),
            "--format",
            "ndjson",
            "--no-shuffle",
            "--no-tune-system",
            "--concurrency",
            "2",
            "--per-host",
            "2",
            "--timeout-ms",
            "1000",
            "--connect-timeout-ms",
            "1000",
        ],
        &[
            ("RDP_HOSTNAME", "unreachable.invalid"),
            ("RDP_USERNAME", "env-user"),
            ("RDP_PASSWORD", "env-password"),
        ],
    );

    assert_eq!(
        output.status.code(),
        Some(2),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let values = json_lines(&output);
    let results: Vec<&Value> = values.iter().filter(|value| value["type"] == "result").collect();
    assert_eq!(results.len(), 3, "bulk input wins over ambient credentials");
    assert!(
        results
            .iter()
            .all(|value| value["username"].as_str() != Some("env-user")),
        "ambient credentials must not enter the bulk plan"
    );
}

#[test]
fn malformed_input_exits_with_two() {
    let input = temp_input("bad", "10.0.0.1 alice secret DOMAIN\n");
    let output = run(&["--input", path_arg(&input), "--no-shuffle"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("exactly"),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn lists_pair_users_with_passwords_line_wise() {
    let hosts = temp_input("hosts", "127.0.0.1\n127.0.0.1:3390\n");
    let users = temp_input("users", "alice\nbob\n");
    let passwords = temp_input("passwords", "pw-one\npw-two\n");
    let output = run(&[
        "--hosts",
        path_arg(&hosts),
        "--users",
        path_arg(&users),
        "--passwords",
        path_arg(&passwords),
        "--format",
        "ndjson",
        "--no-shuffle",
        "--dry-run",
    ]);

    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let values = json_lines(&output);
    let plans: Vec<&Value> = values.iter().filter(|value| value["type"] == "plan").collect();
    assert_eq!(plans.len(), 4, "2 hosts x 2 line-wise credential pairs");
    let usernames: Vec<&str> = plans
        .iter()
        .map(|value| value["username"].as_str().expect("username"))
        .collect();
    assert_eq!(usernames, ["alice", "bob", "alice", "bob"]);
}

#[test]
#[ignore = "requires a live NLA-enabled RDP server; set AUTH_CHECK_LIVE_RECORDS to a records file"]
fn live_nla_check() {
    let path = std::env::var("AUTH_CHECK_LIVE_RECORDS").expect("AUTH_CHECK_LIVE_RECORDS");
    let output = run(&[
        "--input",
        &path,
        "--format",
        "ndjson",
        "--skip-certificate-check",
        "--no-tune-system",
    ]);
    assert!(
        matches!(output.status.code(), Some(0 | 1)),
        "expected valid or invalid results, got {:?}: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
}
