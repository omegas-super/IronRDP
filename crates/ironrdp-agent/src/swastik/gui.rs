//! Built-in browser interface for `swastik-rdp`.
//!
//! The GUI is served by the same binary over loopback only. It reuses the exact same
//! [`RunConfig`] and execution path as the terminal prompts, so profile semantics, report
//! layout, and safety invariants cannot drift between front ends. The page never receives
//! credential values: it posts paths to files the operator already holds on this machine.

use core::net::{IpAddr, Ipv4Addr, SocketAddr};
use core::time::Duration;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context as _;
use serde::Deserialize;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

use super::config::{CustomLimits, PerformanceProfile, RunConfig};
use super::run::{Progress, RunHandle, RunState, execute};

const LOOPBACK_PORT: u16 = 8765;

/// Starts the loopback GUI server and blocks until the process is stopped.
pub(crate) async fn serve() -> anyhow::Result<()> {
    let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), LOOPBACK_PORT);
    let listener = TcpListener::bind(address)
        .await
        .with_context(|| format!("bind GUI server to {address}"))?;
    eprintln!("swastik-rdp GUI: open http://{address}/ (loopback only; press Ctrl+C to stop)");
    let state = Arc::new(AppState::default());
    loop {
        let (stream, _) = listener.accept().await.context("accept a GUI connection")?;
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            if let Err(error) = handle_connection(stream, state).await {
                eprintln!("swastik-rdp GUI connection error: {error:#}");
            }
        });
    }
}

#[derive(Default)]
struct AppState {
    run: RunHandle,
    active: Mutex<Option<tokio::task::JoinHandle<()>>>,
    last_error: Mutex<Option<String>>,
}

#[derive(Debug, Deserialize)]
struct StartRequest {
    hosts: String,
    users: String,
    passwords: String,
    #[serde(default)]
    domains: String,
    output_dir: String,
    #[serde(default = "default_profile")]
    profile: String,
    #[serde(default)]
    concurrency: usize,
    #[serde(default = "default_per_host")]
    per_host: usize,
    #[serde(default = "default_timeout_ms")]
    timeout_ms: u64,
    #[serde(default = "default_connect_timeout_ms")]
    connect_timeout_ms: u64,
    #[serde(default)]
    retries: u32,
}

fn default_profile() -> String {
    String::from("balanced")
}
fn default_per_host() -> usize {
    8
}
fn default_timeout_ms() -> u64 {
    10_000
}
fn default_connect_timeout_ms() -> u64 {
    5_000
}

impl StartRequest {
    fn into_config(self) -> anyhow::Result<RunConfig> {
        let config = RunConfig {
            hosts: PathBuf::from(self.hosts),
            users: PathBuf::from(self.users),
            passwords: PathBuf::from(self.passwords),
            domains: (!self.domains.trim().is_empty()).then(|| PathBuf::from(self.domains.trim())),
            output_dir: PathBuf::from(self.output_dir),
            profile: PerformanceProfile::from_menu(&self.profile)?,
            custom: CustomLimits {
                concurrency: (self.concurrency > 0).then_some(self.concurrency),
                per_host: self.per_host,
                timeout_ms: self.timeout_ms,
                connect_timeout_ms: self.connect_timeout_ms,
                retries: self.retries,
            },
            skip_certificate_check: false,
            allow_multiple_passwords: false,
            no_shuffle: false,
            tune_system: true,
            seed: None,
        };
        config.validate()?;
        Ok(config)
    }
}

async fn handle_connection(mut stream: TcpStream, state: Arc<AppState>) -> anyhow::Result<()> {
    let mut buffer = vec![0u8; 16 * 1024];
    let read = stream.read(&mut buffer).await.context("read an HTTP request")?;
    let request = String::from_utf8_lossy(&buffer[..read]);
    let request_line = request.lines().next().unwrap_or_default();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let path = parts.next().unwrap_or_default();

    match (method, path) {
        ("GET", "/" | "/index.html") => {
            serve_html(&mut stream, PAGE).await?;
        }
        ("GET", "/api/progress") => {
            let progress = wait_for_progress(&state).await;
            let error = state.last_error.lock().await.clone();
            let response = serde_json::json!({"progress": progress, "error": error});
            serve_json(&mut stream, &response.to_string()).await?;
        }
        ("POST", "/api/start") => {
            let body = request.split_once("\r\n\r\n").map_or("", |(_, body)| body);
            let response = match serde_json::from_str::<StartRequest>(body) {
                Ok(request) => match request.into_config() {
                    Ok(config) => {
                        start_run(&state, config).await;
                        String::from("{\"ok\":true}")
                    }
                    Err(error) => json_error(&format!("{error:#}")),
                },
                Err(error) => json_error(&format!("invalid request: {error}")),
            };
            serve_json(&mut stream, &response).await?;
        }
        _ => {
            let body = "{\"error\":\"not found\"}";
            stream
                .write_all(format!("HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes())
                .await?;
        }
    }
    stream.shutdown().await?;
    Ok(())
}

/// Long-polls progress so the browser does not burn CPU on a tight timer. Returns promptly
/// on state changes and at most once per second while a run is active.
async fn wait_for_progress(state: &AppState) -> Progress {
    let mut receiver = state.run.subscribe();
    let first = *receiver.borrow_and_update();
    if first.state != RunState::Running.as_str() && first.state != RunState::Preparing.as_str() {
        return first;
    }
    if tokio::time::timeout(Duration::from_secs(1), receiver.changed())
        .await
        .is_err()
    {
        return *receiver.borrow();
    }
    *receiver.borrow()
}

async fn start_run(state: &AppState, config: RunConfig) {
    let mut active = state.active.lock().await;
    if let Some(task) = active.as_ref() {
        if !task.is_finished() {
            *state.last_error.lock().await = Some(String::from("a run is already active"));
            return;
        }
    }
    *state.last_error.lock().await = None;
    let handle = state.run.clone();
    let task = tokio::spawn(async move {
        if let Err(error) = execute(config, Some(handle)).await {
            eprintln!("swastik-rdp GUI run failed: {error:#}");
        }
    });
    *active = Some(task);
}

fn json_error(message: &str) -> String {
    serde_json::json!({"ok": false, "error": message}).to_string()
}

async fn serve_json(stream: &mut TcpStream, body: &str) -> anyhow::Result<()> {
    let header = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes()).await?;
    stream.write_all(body.as_bytes()).await?;
    Ok(())
}

async fn serve_html(stream: &mut TcpStream, body: &str) -> anyhow::Result<()> {
    let header = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes()).await?;
    stream.write_all(body.as_bytes()).await?;
    Ok(())
}

const PAGE: &str = include_str!("index.html");
