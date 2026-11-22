//! Native Windows GUI for `swastik-rdp`.
//!
//! The interface mirrors a high-throughput audit console: Brute for live statistics and
//! run control, Settings for safe performance limits, Work Files for operator-supplied lists.
//! It never displays credentials; it only holds paths to files the operator selected.

use core::fmt::Display;
use core::ops::RangeInclusive;
use core::time::Duration;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use anyhow::Context as _;
use eframe::egui;
use rfd::FileDialog;

use super::config::{CustomLimits, PerformanceProfile, RunConfig};
use super::run::{RunController, RunHandle, cancellation_channel, execute};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tab {
    Brute,
    Settings,
    WorkFiles,
}

#[derive(Debug, Clone)]
struct Settings {
    profile: PerformanceProfile,
    concurrency: usize,
    per_host: usize,
    timeout_ms: u64,
    connect_timeout_ms: u64,
    retries: u32,
    output_dir: String,
    skip_certificate_check: bool,
    allow_multiple_passwords: bool,
    no_shuffle: bool,
    tune_system: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            profile: PerformanceProfile::Max,
            concurrency: 0,
            per_host: 8,
            timeout_ms: 10_000,
            connect_timeout_ms: 5_000,
            retries: 0,
            output_dir: String::from("swastik-results"),
            skip_certificate_check: false,
            allow_multiple_passwords: false,
            no_shuffle: false,
            tune_system: true,
        }
    }
}

#[derive(Debug, Default)]
struct WorkFiles {
    servers: String,
    users: String,
    passwords: String,
    domains: String,
    counts: FileCounts,
}

#[derive(Debug, Default, Clone, Copy)]
struct FileCounts {
    servers: usize,
    users: usize,
    passwords: usize,
    domains: usize,
}

struct App {
    tab: Tab,
    settings: Settings,
    files: WorkFiles,
    runtime: tokio::runtime::Runtime,
    progress: RunHandle,
    controller: Option<RunController>,
    running: bool,
    last_error: Option<String>,
    run_error: Arc<Mutex<Option<String>>>,
    started: Option<std::time::Instant>,
    last_sample: Option<(std::time::Instant, usize)>,
    current_pps: f64,
    peak_pps: f64,
}

impl App {
    fn new() -> anyhow::Result<Self> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .thread_name("swastik-gui")
            .build()
            .context("create the GUI async runtime")?;
        Ok(Self {
            tab: Tab::Brute,
            settings: Settings::default(),
            files: WorkFiles::default(),
            runtime,
            progress: RunHandle::default(),
            controller: None,
            running: false,
            last_error: None,
            run_error: Arc::new(Mutex::new(None)),
            started: None,
            last_sample: None,
            current_pps: 0.0,
            peak_pps: 0.0,
        })
    }

    fn config(&self) -> RunConfig {
        RunConfig {
            hosts: PathBuf::from(&self.files.servers),
            users: PathBuf::from(&self.files.users),
            passwords: PathBuf::from(&self.files.passwords),
            domains: (!self.files.domains.trim().is_empty()).then(|| PathBuf::from(self.files.domains.trim())),
            output_dir: PathBuf::from(&self.settings.output_dir),
            profile: self.settings.profile,
            custom: CustomLimits {
                concurrency: (self.settings.concurrency > 0).then_some(self.settings.concurrency),
                per_host: self.settings.per_host,
                timeout_ms: self.settings.timeout_ms,
                connect_timeout_ms: self.settings.connect_timeout_ms,
                retries: self.settings.retries,
            },
            skip_certificate_check: self.settings.skip_certificate_check,
            allow_multiple_passwords: self.settings.allow_multiple_passwords,
            no_shuffle: self.settings.no_shuffle,
            tune_system: self.settings.tune_system,
            seed: None,
        }
    }

    fn start(&mut self, ctx: &egui::Context) {
        if self.running {
            return;
        }
        self.cancel_active_run();
        self.last_error = None;
        let config = self.config();
        if let Err(error) = config.validate() {
            self.last_error = Some(format!("{error:#}"));
            return;
        }

        let progress = self.progress.clone();
        let (controller, stop_rx) = cancellation_channel();
        let repaint = ctx.clone();
        let mut progress_rx = progress.subscribe();
        let error_slot = Arc::clone(&self.run_error);
        self.runtime.spawn(async move {
            let repainter = repaint.clone();
            let repaint_task = tokio::spawn(async move {
                while progress_rx.changed().await.is_ok() {
                    repainter.request_repaint();
                }
            });
            if let Err(error) = execute(config, Some(progress), stop_rx).await {
                let message = format!("{error:#}");
                eprintln!("swastik-rdp GUI run failed: {message}");
                if let Ok(mut slot) = error_slot.lock() {
                    *slot = Some(message);
                }
            }
            repaint_task.abort();
            repaint.request_repaint();
        });
        self.controller = Some(controller);
        self.running = true;
        self.started = Some(std::time::Instant::now());
        self.last_sample = Some((std::time::Instant::now(), 0));
        self.current_pps = 0.0;
        self.peak_pps = 0.0;
        self.tab = Tab::Brute;
    }

    fn cancel_active_run(&mut self) {
        if let Some(controller) = &self.controller {
            controller.stop();
        }
        self.controller = None;
        self.running = false;
    }

    fn stop(&mut self) {
        self.cancel_active_run();
    }

    fn clear(&mut self) {
        self.cancel_active_run();
        self.progress = RunHandle::default();
        self.last_error = None;
        self.started = None;
        self.last_sample = None;
        self.current_pps = 0.0;
        self.peak_pps = 0.0;
        self.consume_run_error();
    }

    fn consume_run_error(&mut self) -> Option<String> {
        let message = self.run_error.lock().ok().and_then(|mut slot| slot.take());
        if message.is_some() {
            self.running = false;
        }
        message
    }

    fn draw(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("swastik-rdp - authorized credential audit");
            ui.separator();
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.tab, Tab::Brute, "Brute");
                if ui
                    .add_enabled(
                        !self.running,
                        egui::Button::selectable(self.tab == Tab::Settings, "Settings"),
                    )
                    .clicked()
                {
                    self.tab = Tab::Settings;
                }
                if ui
                    .add_enabled(
                        !self.running,
                        egui::Button::selectable(self.tab == Tab::WorkFiles, "Work Files"),
                    )
                    .clicked()
                {
                    self.tab = Tab::WorkFiles;
                }
            });
            ui.separator();
            match self.tab {
                Tab::Brute => self.brute_tab(ui),
                Tab::Settings => self.settings_tab(ui),
                Tab::WorkFiles => self.work_files_tab(ui),
            }
        });
    }

    fn brute_tab(&mut self, ui: &mut egui::Ui) {
        let progress = self.progress.snapshot();
        if !progress.is_running() && self.running {
            self.running = false;
        }
        if let Some(error) = self.consume_run_error() {
            self.last_error = Some(error);
        }
        let now = std::time::Instant::now();
        if let Some((sample_time, sample_completed)) = self.last_sample {
            let window = now.duration_since(sample_time);
            if window >= Duration::from_millis(500) {
                let delta = progress.completed.saturating_sub(sample_completed);
                self.current_pps = f64::from(u32::try_from(delta).unwrap_or(u32::MAX)) / window.as_secs_f64();
                self.peak_pps = self.peak_pps.max(self.current_pps);
                self.last_sample = Some((now, progress.completed));
            }
        }

        egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.heading("Statistics");
            ui.separator();
            egui::Grid::new("stats").striped(true).num_columns(2).show(ui, |ui| {
                stat(ui, "State", progress.state);
                stat(ui, "Active threads", &progress.concurrency.to_string());
                stat(ui, "Current PPS", &format!("{:.1}", self.current_pps));
                stat(ui, "Average PPS", &format!("{:.1}", progress.average_pps()));
                stat(ui, "Peak PPS", &format!("{:.1}", self.peak_pps));
                stat(ui, "Good count", &progress.valid.to_string());
                stat(ui, "Bad count", &progress.invalid.to_string());
                stat(ui, "Errors", &progress.errors.to_string());
                stat(ui, "Completed", &format!("{} / {}", progress.completed, progress.total));
                stat(
                    ui,
                    "Remaining",
                    &progress.total.saturating_sub(progress.completed).to_string(),
                );
                let elapsed = self.started.map_or(Duration::ZERO, |start| start.elapsed());
                stat(
                    ui,
                    "Elapsed time",
                    &format!(
                        "{:02}:{:02}:{:02}",
                        elapsed.as_secs() / 3600,
                        (elapsed.as_secs() / 60) % 60,
                        elapsed.as_secs() % 60
                    ),
                );
            });
        });

        ui.add_space(12.0);
        ui.horizontal(|ui| {
            if ui.add_enabled(!self.running, egui::Button::new("Start")).clicked() {
                let ctx = ui.ctx().clone();
                self.start(&ctx);
            }
            if ui.add_enabled(self.running, egui::Button::new("Stop")).clicked() {
                self.stop();
            }
            if ui.button("Clear").clicked() {
                self.clear();
            }
        });
        if let Some(error) = &self.last_error {
            ui.colored_label(ui.visuals().error_fg_color, error);
        }
        ui.label("Credentials are read from Work Files and are never shown here.");
    }

    fn settings_tab(&mut self, ui: &mut egui::Ui) {
        egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.heading("Performance and audit settings");
            ui.separator();
            egui::Grid::new("settings").num_columns(2).show(ui, |ui| {
                ui.label("Profile");
                egui::ComboBox::from_id_salt("profile")
                    .selected_text(self.settings.profile.label())
                    .show_ui(ui, |ui| {
                        for profile in [
                            PerformanceProfile::Max,
                            PerformanceProfile::Conservative,
                            PerformanceProfile::Balanced,
                            PerformanceProfile::Aggressive,
                            PerformanceProfile::Custom,
                        ] {
                            ui.selectable_value(&mut self.settings.profile, profile, profile.label());
                        }
                    });
                ui.end_row();
                number(ui, "Global concurrency (0 = adaptive)", &mut self.settings.concurrency, 0..=512);
                number(ui, "Per-host limit", &mut self.settings.per_host, 1..=256);
                number(ui, "Check timeout (ms)", &mut self.settings.timeout_ms, 1..=600_000);
                number(ui, "Connect timeout (ms)", &mut self.settings.connect_timeout_ms, 1..=600_000);
                number(ui, "Pre-auth retries", &mut self.settings.retries, 0..=2);
                ui.label("Output directory");
                ui.text_edit_singleline(&mut self.settings.output_dir);
                ui.end_row();
            });
            ui.separator();
            ui.checkbox(&mut self.settings.tune_system, "Widen Windows dynamic port range when elevated");
            ui.checkbox(&mut self.settings.no_shuffle, "Keep input order (no randomized execution)");
            ui.checkbox(&mut self.settings.allow_multiple_passwords, "Allow multiple passwords per account");
            ui.checkbox(
                &mut self.settings.skip_certificate_check,
                "Skip certificate validation (authorized test endpoints only)",
            );
            ui.separator();
            ui.label("MAX uses the machine-derived ceiling and never disables certificate validation or retries rejected credentials.");
            ui.label("No raw-socket or OS-limit bypass is available; throughput comes from adaptive concurrency, port tuning, and abortive closes.");
        });
    }

    fn work_files_tab(&mut self, ui: &mut egui::Ui) {
        egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.heading("Work files");
            ui.separator();
            let mut changed = false;
            egui::Grid::new("work_files").num_columns(3).show(ui, |ui| {
                changed |= file_row(ui, "Servers", &mut self.files.servers, self.files.counts.servers);
                changed |= file_row(ui, "Users", &mut self.files.users, self.files.counts.users);
                changed |= file_row(ui, "Passwords", &mut self.files.passwords, self.files.counts.passwords);
                changed |= file_row(ui, "Domains (optional)", &mut self.files.domains, self.files.counts.domains);
            });
            if changed {
                self.files.counts = count_lines(&self.files);
            }
            ui.separator();
            if ui.button("Recount lines").clicked() {
                self.files.counts = count_lines(&self.files);
            }
            ui.label("Users and passwords pair line by line. Domains, when provided, must have one line per user; a blank line means no domain.");
            ui.label("The checker audits credentials you already hold. Password generation and wordlists are not available.");
        });
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.draw(ctx);
    }
}

fn stat(ui: &mut egui::Ui, label: &str, value: &str) {
    ui.label(label);
    ui.strong(value);
    ui.end_row();
}

fn number<T>(ui: &mut egui::Ui, label: &str, value: &mut T, range: RangeInclusive<T>)
where
    T: egui::emath::Numeric + Display + Copy + PartialOrd,
{
    ui.label(label);
    ui.add(egui::DragValue::new(value).range(range));
    ui.end_row();
}

fn file_row(ui: &mut egui::Ui, label: &str, value: &mut String, count: usize) -> bool {
    ui.label(label);
    ui.set_min_width(260.0);
    let edited = ui.text_edit_singleline(value).changed();
    if ui.button("Browse").clicked() {
        if let Some(path) = FileDialog::new().pick_file() {
            *value = path.display().to_string();
            return true;
        }
    }
    ui.label(count.to_string());
    ui.end_row();
    edited
}

fn count_lines(files: &WorkFiles) -> FileCounts {
    let count = |path: &str| count_file_lines(path).unwrap_or(0);
    FileCounts {
        servers: count(&files.servers),
        users: count(&files.users),
        passwords: count(&files.passwords),
        domains: count(&files.domains),
    }
}

fn count_file_lines(path: &str) -> std::io::Result<usize> {
    if path.trim().is_empty() {
        return Ok(0);
    }
    let text = std::fs::read_to_string(path)?;
    Ok(text.lines().count())
}

/// Launches the native window. Called from the `1` menu choice.
pub(super) fn run() -> anyhow::Result<()> {
    let app = App::new()?;
    let mut options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("swastik-rdp")
            .with_inner_size([900.0, 620.0])
            .with_min_inner_size([700.0, 460.0]),
        renderer: eframe::Renderer::Wgpu,
        ..Default::default()
    };
    options.wgpu_options.wgpu_setup = eframe::egui_wgpu::WgpuSetup::CreateNew(eframe::egui_wgpu::WgpuSetupCreateNew {
        instance_descriptor: wgpu::InstanceDescriptor {
            backends: wgpu::Backends::DX12 | wgpu::Backends::VULKAN | wgpu::Backends::GL,
            ..Default::default()
        },
        native_adapter_selector: Some(Arc::new(select_adapter)),
        ..Default::default()
    });
    eframe::run_native("swastik-rdp", options, Box::new(move |_cc| Ok(Box::new(app))))
        .map_err(|error| anyhow::anyhow!("native GUI failed: {error}"))
}

fn select_adapter(adapters: &[wgpu::Adapter], surface: Option<&wgpu::Surface<'_>>) -> Result<wgpu::Adapter, String> {
    let usable = |adapter: &wgpu::Adapter| surface.is_none_or(|surface| adapter.is_surface_supported(surface));
    let rank = |adapter: &wgpu::Adapter| match adapter.get_info().backend {
        wgpu::Backend::Dx12 => 0,
        wgpu::Backend::Vulkan => 1,
        wgpu::Backend::Gl => 2,
        _ => 3,
    };

    adapters
        .iter()
        .filter(|adapter| usable(adapter))
        .filter(|adapter| {
            !matches!(
                adapter.get_info().device_type,
                wgpu::DeviceType::Cpu | wgpu::DeviceType::VirtualGpu
            )
        })
        .min_by_key(|adapter| rank(adapter))
        .or_else(|| {
            adapters
                .iter()
                .filter(|adapter| usable(adapter))
                .min_by_key(|adapter| rank(adapter))
        })
        .cloned()
        .ok_or_else(|| "no compatible graphics adapter (tried DX12, Vulkan, and OpenGL)".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn count_file_lines_handles_empty_path_and_content() {
        assert_eq!(count_file_lines("").unwrap(), 0);
        assert_eq!(count_file_lines("   ").unwrap(), 0);
    }

    #[test]
    fn count_file_lines_counts_lines_without_adding_a_trailing_empty_line() {
        let dir = std::env::temp_dir().join(format!("swastik-gui-count-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("lines.txt");
        std::fs::write(&path, "a\nb\n").unwrap();
        assert_eq!(count_file_lines(&path.display().to_string()).unwrap(), 2);
        std::fs::write(&path, "a\nb\nc").unwrap();
        assert_eq!(count_file_lines(&path.display().to_string()).unwrap(), 3);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
