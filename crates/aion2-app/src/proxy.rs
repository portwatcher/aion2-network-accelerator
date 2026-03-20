use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tauri::{AppHandle, Emitter};
use tokio::sync::Mutex;

/// Config received from the frontend.
#[derive(Debug, Deserialize)]
pub struct RelayConfig {
    pub relay_addr: String,
    pub key_hex: String,
}

/// Status sent to the frontend.
#[derive(Debug, Clone, Serialize)]
pub struct ProxyStatus {
    pub state: &'static str,
    pub rtt_ms: Option<u64>,
    pub uptime_secs: u64,
    pub bytes_tx: u64,
    pub bytes_rx: u64,
    pub active_connections: u32,
}

/// Log entry sent to the frontend.
#[derive(Debug, Clone, Serialize)]
pub struct LogEntry {
    pub timestamp: String,
    pub level: &'static str,
    pub message: String,
}

/// Shared proxy state managed by Tauri.
pub struct ProxyState {
    inner: Mutex<Option<RunningProxy>>,
}

struct RunningProxy {
    cancel: tokio::sync::watch::Sender<bool>,
    stats: Arc<ProxyStats>,
    key_file: PathBuf,
    child_pid: u32,
}

struct ProxyStats {
    rtt_ms: AtomicU64,
    bytes_tx: AtomicU64,
    bytes_rx: AtomicU64,
    active_connections: AtomicU64,
    connected: AtomicBool,
    started_at: std::time::Instant,
}

impl Default for ProxyState {
    fn default() -> Self {
        Self {
            inner: Mutex::new(None),
        }
    }
}

fn now_iso() -> String {
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap();
    let secs = d.as_secs();
    let h = (secs / 3600) % 24;
    let m = (secs / 60) % 60;
    let s = secs % 60;
    format!("{:02}:{:02}:{:02}", h, m, s)
}

fn emit_log(app: &AppHandle, level: &'static str, message: impl Into<String>) {
    let entry = LogEntry {
        timestamp: now_iso(),
        level,
        message: message.into(),
    };
    let _ = app.emit("proxy-log", &entry);
    match level {
        "error" => tracing::error!("{}", entry.message),
        "warn" => tracing::warn!("{}", entry.message),
        _ => tracing::info!("{}", entry.message),
    }
}

fn hex_decode(hex: &str) -> Result<[u8; 32], String> {
    if hex.len() != 64 {
        return Err(format!(
            "Key must be 64 hex chars (32 bytes), got {}",
            hex.len()
        ));
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .map_err(|e| format!("Invalid hex at position {}: {e}", i * 2))?;
    }
    Ok(out)
}

/// Kill a process by PID.
fn kill_process(pid: u32) {
    #[cfg(windows)]
    {
        let _ = std::process::Command::new("taskkill")
            .args(["/F", "/PID", &pid.to_string()])
            .output();
    }
    #[cfg(not(windows))]
    {
        unsafe { libc::kill(pid as i32, libc::SIGTERM); }
    }
}

/// Locate the aion2-proxy binary.
/// Also ensures wintun.dll is present next to it on Windows.
fn find_proxy_binary() -> Result<PathBuf, String> {
    let name = if cfg!(windows) {
        "aion2-proxy.exe"
    } else {
        "aion2-proxy"
    };

    let proxy_path;

    // Dev mode: look in target/debug relative to manifest dir
    #[cfg(debug_assertions)]
    {
        let dev_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/debug")
            .join(name);
        if dev_path.exists() {
            proxy_path = dev_path;
        } else {
            return Err("aion2-proxy binary not found. Run: cargo build -p aion2-proxy".into());
        }
    }

    #[cfg(not(debug_assertions))]
    {
        // Production: look next to the application exe, and in binaries/ subdir
        proxy_path = find_near_exe(name)?;
    }

    // Ensure wintun.dll is next to the proxy binary
    #[cfg(windows)]
    {
        if let Some(proxy_dir) = proxy_path.parent() {
            let wintun_dst = proxy_dir.join("wintun.dll");
            if !wintun_dst.exists() {
                // Try to find wintun.dll in known locations and copy it
                let search_paths: Vec<PathBuf> = vec![
                    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("binaries/wintun.dll"),
                    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../wintun.dll"),
                ];
                let mut found = false;
                for src in &search_paths {
                    if src.exists() {
                        if std::fs::copy(src, &wintun_dst).is_ok() {
                            found = true;
                            break;
                        }
                    }
                }
                if !found {
                    return Err(
                        "wintun.dll not found. Download from https://www.wintun.net/builds/wintun-0.14.1.zip \
                        and place wintun.dll (from bin/amd64/) into the project root or crates/aion2-app/binaries/"
                            .into(),
                    );
                }
            }
        }
    }

    Ok(proxy_path)
}

#[cfg(not(debug_assertions))]
fn find_near_exe(name: &str) -> Result<PathBuf, String> {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let proxy = dir.join(name);
            if proxy.exists() {
                return Ok(proxy);
            }
            let proxy = dir.join("binaries").join(name);
            if proxy.exists() {
                return Ok(proxy);
            }
        }
    }
    Err("aion2-proxy binary not found".into())
}

/// Parse a log line from the proxy process to update stats.
fn parse_proxy_line(stats: &ProxyStats, line: &str) {
    // Parse RTT and byte counters from pong lines:
    //   "...rtt_ms=42...bytes_tx=1234...bytes_rx=5678..."
    if line.contains("pong") {
        if let Some(rtt_part) = line.split("rtt_ms").nth(1) {
            // Skip '=' and optional spaces
            let digits: String = rtt_part
                .chars()
                .skip_while(|c| *c == '=' || *c == ' ')
                .take_while(|c| c.is_ascii_digit())
                .collect();
            if let Ok(rtt) = digits.parse::<u64>() {
                stats.rtt_ms.store(rtt, Ordering::Relaxed);
                stats.connected.store(true, Ordering::Relaxed);
            }
        }
        // Parse bytes_tx
        if let Some(part) = line.split("bytes_tx").nth(1) {
            let digits: String = part
                .chars()
                .skip_while(|c| *c == '=' || *c == ' ')
                .take_while(|c| c.is_ascii_digit())
                .collect();
            if let Ok(v) = digits.parse::<u64>() {
                stats.bytes_tx.store(v, Ordering::Relaxed);
            }
        }
        // Parse bytes_rx
        if let Some(part) = line.split("bytes_rx").nth(1) {
            let digits: String = part
                .chars()
                .skip_while(|c| *c == '=' || *c == ' ')
                .take_while(|c| c.is_ascii_digit())
                .collect();
            if let Ok(v) = digits.parse::<u64>() {
                stats.bytes_rx.store(v, Ordering::Relaxed);
            }
        }
    }

    // Track active connections
    if line.contains("connection established") || line.contains("SYN captured") {
        stats.active_connections.fetch_add(1, Ordering::Relaxed);
    }
    if line.contains("server closed")
        || line.contains("server shutdown")
        || line.contains("server reset")
    {
        let prev = stats.active_connections.load(Ordering::Relaxed);
        if prev > 0 {
            stats.active_connections.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

/// Strip the tracing prefix (timestamp + level + module) for cleaner display.
fn strip_tracing_prefix(line: &str) -> &str {
    for keyword in &["INFO ", "WARN ", "ERROR ", "DEBUG "] {
        if let Some(kw_pos) = line.find(keyword) {
            let after_kw = &line[kw_pos + keyword.len()..];
            if let Some(colon_pos) = after_kw.find(": ") {
                return &after_kw[colon_pos + 2..];
            }
            return after_kw;
        }
    }
    line
}

#[tauri::command]
pub async fn start_proxy(
    app: AppHandle,
    state: tauri::State<'_, ProxyState>,
    config: RelayConfig,
) -> Result<(), String> {
    let mut lock = state.inner.lock().await;

    // Stop existing if running
    if let Some(running) = lock.take() {
        let _ = running.cancel.send(true);
        let _ = std::fs::remove_file(&running.key_file);
        kill_process(running.child_pid);
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    // Validate key format
    hex_decode(config.key_hex.trim())?;

    // Find the proxy binary
    let proxy_bin = find_proxy_binary()?;
    emit_log(
        &app,
        "info",
        format!("Found proxy: {}", proxy_bin.display()),
    );

    // Write key to a temp file for the proxy binary to read
    let key_file = std::env::temp_dir().join("aion2_tunnel.key");
    std::fs::write(&key_file, config.key_hex.trim())
        .map_err(|e| format!("Failed to write key file: {e}"))?;

    emit_log(
        &app,
        "info",
        format!("Connecting to relay {}...", config.relay_addr),
    );

    // Spawn the proxy process
    let mut child = std::process::Command::new(&proxy_bin)
        .args([
            "--relay",
            &config.relay_addr,
            "--key",
            &key_file.to_string_lossy(),
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to start proxy: {e}"))?;

    let child_pid = child.id();

    let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
    let stats = Arc::new(ProxyStats {
        rtt_ms: AtomicU64::new(0),
        bytes_tx: AtomicU64::new(0),
        bytes_rx: AtomicU64::new(0),
        active_connections: AtomicU64::new(0),
        connected: AtomicBool::new(false),
        started_at: std::time::Instant::now(),
    });

    // Read stderr on a blocking thread (reliable on Windows piped handles)
    let stderr = child.stderr.take().expect("stderr was piped");
    let (line_tx, mut line_rx) = tokio::sync::mpsc::channel::<String>(128);
    std::thread::spawn(move || {
        use std::io::BufRead;
        let reader = std::io::BufReader::new(stderr);
        for line in reader.lines() {
            match line {
                Ok(line) => {
                    if line_tx.blocking_send(line).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    // Process lines from stderr and emit as logs
    let log_app = app.clone();
    let log_stats = stats.clone();
    let mut log_cancel = cancel_rx.clone();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                line = line_rx.recv() => {
                    match line {
                        Some(line) => {
                            parse_proxy_line(&log_stats, &line);
                            let level = if line.contains("ERROR") {
                                "error"
                            } else if line.contains("WARN") {
                                "warn"
                            } else {
                                "info"
                            };
                            let msg = strip_tracing_prefix(&line);
                            emit_log(&log_app, level, msg);
                        }
                        None => {
                            log_stats.connected.store(false, Ordering::Relaxed);
                            emit_log(&log_app, "warn", "Proxy process exited");
                            break;
                        }
                    }
                }
                _ = log_cancel.changed() => break,
            }
        }
    });

    // Wait for process exit in background
    let exit_app = app.clone();
    let exit_stats = stats.clone();
    let mut exit_cancel = cancel_rx.clone();
    tokio::spawn(async move {
        let result = tokio::select! {
            r = tokio::task::spawn_blocking(move || child.wait()) => r,
            _ = exit_cancel.changed() => {
                // Stop requested — kill is handled below
                return;
            }
        };
        match result {
            Ok(Ok(status)) => {
                emit_log(
                    &exit_app,
                    if status.success() { "info" } else { "error" },
                    format!("Proxy exited: {status}"),
                );
            }
            Ok(Err(e)) => {
                emit_log(&exit_app, "error", format!("Proxy wait error: {e}"));
            }
            Err(e) => {
                emit_log(&exit_app, "error", format!("Proxy task error: {e}"));
            }
        }
        exit_stats.connected.store(false, Ordering::Relaxed);
    });

    // Emit status updates to frontend every second
    let status_app = app.clone();
    let status_stats = stats.clone();
    let mut status_cancel = cancel_rx.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let s = build_status(&status_stats);
                    let _ = status_app.emit("proxy-status", &s);
                }
                _ = status_cancel.changed() => break,
            }
        }
    });

    *lock = Some(RunningProxy {
        cancel: cancel_tx,
        stats,
        key_file,
        child_pid,
    });

    Ok(())
}

#[tauri::command]
pub async fn stop_proxy(
    app: AppHandle,
    state: tauri::State<'_, ProxyState>,
) -> Result<(), String> {
    let mut lock = state.inner.lock().await;
    if let Some(running) = lock.take() {
        let _ = running.cancel.send(true);
        let _ = std::fs::remove_file(&running.key_file);
        // Kill the proxy process
        kill_process(running.child_pid);
        emit_log(&app, "info", "Proxy stopped");
    }
    Ok(())
}

#[tauri::command]
pub async fn get_status(state: tauri::State<'_, ProxyState>) -> Result<ProxyStatus, String> {
    let lock = state.inner.lock().await;
    match &*lock {
        Some(running) => Ok(build_status(&running.stats)),
        None => Ok(ProxyStatus {
            state: "disconnected",
            rtt_ms: None,
            uptime_secs: 0,
            bytes_tx: 0,
            bytes_rx: 0,
            active_connections: 0,
        }),
    }
}

fn build_status(stats: &ProxyStats) -> ProxyStatus {
    let rtt = stats.rtt_ms.load(Ordering::Relaxed);
    ProxyStatus {
        state: if stats.connected.load(Ordering::Relaxed) {
            "connected"
        } else {
            "connecting"
        },
        rtt_ms: if rtt > 0 { Some(rtt) } else { None },
        uptime_secs: stats.started_at.elapsed().as_secs(),
        bytes_tx: stats.bytes_tx.load(Ordering::Relaxed),
        bytes_rx: stats.bytes_rx.load(Ordering::Relaxed),
        active_connections: stats.active_connections.load(Ordering::Relaxed) as u32,
    }
}
