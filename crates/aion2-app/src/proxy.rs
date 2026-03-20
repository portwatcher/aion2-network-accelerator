use aion2_common::crypto::{self, TunnelKey};
use aion2_common::protocol::{TunnelMessage, MAX_PACKET_SIZE};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tauri::{AppHandle, Emitter};
use tokio::net::UdpSocket;
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
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let relay_addr: SocketAddr = config
        .relay_addr
        .parse()
        .map_err(|e| format!("Invalid relay address: {e}"))?;

    let key_bytes = hex_decode(config.key_hex.trim())?;
    let key = TunnelKey::from_bytes(&key_bytes);

    let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
    let stats = Arc::new(ProxyStats {
        rtt_ms: AtomicU64::new(0),
        bytes_tx: AtomicU64::new(0),
        bytes_rx: AtomicU64::new(0),
        active_connections: AtomicU64::new(0),
        connected: AtomicBool::new(false),
        started_at: std::time::Instant::now(),
    });

    emit_log(&app, "info", format!("Connecting to relay {relay_addr}..."));

    // Spawn the tunnel tasks
    let app_handle = app.clone();
    let stats_clone = stats.clone();
    tokio::spawn(async move {
        if let Err(e) = run_tunnel(app_handle.clone(), relay_addr, key, stats_clone, cancel_rx).await {
            emit_log(&app_handle, "error", format!("Tunnel error: {e}"));
        }
    });

    // Spawn status emitter
    let status_app = app.clone();
    let status_stats = stats.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        loop {
            interval.tick().await;
            let s = build_status(&status_stats);
            let _ = status_app.emit("proxy-status", &s);
        }
    });

    *lock = Some(RunningProxy {
        cancel: cancel_tx,
        stats,
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

/// Run the UDP tunnel (ping/pong + receive loop).
async fn run_tunnel(
    app: AppHandle,
    relay_addr: SocketAddr,
    key: TunnelKey,
    stats: Arc<ProxyStats>,
    mut cancel: tokio::sync::watch::Receiver<bool>,
) -> Result<(), String> {
    let socket = Arc::new(
        UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|e| format!("Failed to bind socket: {e}"))?,
    );

    let local = socket.local_addr().map_err(|e| e.to_string())?;
    emit_log(
        &app,
        "info",
        format!("Tunnel bound on {local}, relay: {relay_addr}"),
    );

    // Ping loop
    let ping_socket = socket.clone();
    let ping_key = key.clone();
    let ping_stats = stats.clone();
    let ping_app = app.clone();
    let mut ping_cancel = cancel.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        let mut seq: u64 = 0;
        loop {
            tokio::select! {
                _ = interval.tick() => {}
                _ = ping_cancel.changed() => break,
            }

            let timestamp_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64;

            let msg = TunnelMessage::Ping {
                seq,
                timestamp_ms,
            };
            match crypto::seal(&ping_key, &msg) {
                Ok(packet) => {
                    ping_stats
                        .bytes_tx
                        .fetch_add(packet.len() as u64, Ordering::Relaxed);
                    if let Err(e) = ping_socket.send_to(&packet, relay_addr).await {
                        emit_log(&ping_app, "warn", format!("Ping send failed: {e}"));
                    }
                }
                Err(e) => {
                    emit_log(&ping_app, "error", format!("Ping encrypt failed: {e}"));
                }
            }
            seq += 1;
        }
    });

    // Receive loop
    let mut buf = vec![0u8; MAX_PACKET_SIZE];
    loop {
        tokio::select! {
            result = socket.recv_from(&mut buf) => {
                match result {
                    Ok((len, _peer)) => {
                        stats.bytes_rx.fetch_add(len as u64, Ordering::Relaxed);
                        let packet = &buf[..len];
                        match crypto::open(&key, packet) {
                            Ok(msg) => handle_relay_msg(&app, &stats, msg),
                            Err(e) => {
                                emit_log(&app, "warn", format!("Decrypt failed: {e}"));
                            }
                        }
                    }
                    Err(e) => {
                        emit_log(&app, "error", format!("Recv error: {e}"));
                        break;
                    }
                }
            }
            _ = cancel.changed() => {
                emit_log(&app, "info", "Tunnel shutting down");
                break;
            }
        }
    }

    stats.connected.store(false, Ordering::Relaxed);
    Ok(())
}

fn handle_relay_msg(app: &AppHandle, stats: &ProxyStats, msg: TunnelMessage) {
    match msg {
        TunnelMessage::Pong {
            seq,
            client_timestamp_ms,
        } => {
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64;
            let rtt = now_ms.saturating_sub(client_timestamp_ms);
            stats.rtt_ms.store(rtt, Ordering::Relaxed);
            stats.connected.store(true, Ordering::Relaxed);
            emit_log(app, "info", format!("Pong seq={seq} rtt={rtt}ms"));
        }
        TunnelMessage::Connected(conn) => {
            stats
                .active_connections
                .fetch_add(1, Ordering::Relaxed);
            emit_log(app, "info", format!("Connection established: {conn}"));
        }
        TunnelMessage::ConnectFailed { conn, reason } => {
            emit_log(app, "error", format!("Connect failed {conn}: {reason}"));
        }
        TunnelMessage::Shutdown(conn) => {
            stats
                .active_connections
                .fetch_sub(1, Ordering::Relaxed);
            emit_log(app, "info", format!("Connection closed: {conn}"));
        }
        TunnelMessage::Reset(conn) => {
            stats
                .active_connections
                .fetch_sub(1, Ordering::Relaxed);
            emit_log(app, "warn", format!("Connection reset: {conn}"));
        }
        TunnelMessage::Data { payload, .. } => {
            stats
                .bytes_rx
                .fetch_add(payload.len() as u64, Ordering::Relaxed);
        }
        _ => {}
    }
}
