use aion2_common::crypto::{self, TunnelKey};
use aion2_common::protocol::{ConnId, TunnelMessage, MAX_PACKET_SIZE, MAX_PAYLOAD_SIZE};
use anyhow::Result;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, RwLock};

/// Events from the relay that the TUN handler needs to process.
pub enum RelayEvent {
    Connected(ConnId),
    ConnectFailed { conn: ConnId, reason: String },
    Data { conn: ConnId, payload: Vec<u8> },
    Shutdown(ConnId),
    Reset(ConnId),
}

/// Per-connection state on the client side.
#[allow(dead_code)]
struct ConnState {
    /// Buffered data received from the relay (game server → client).
    rx_buf: Vec<u8>,
    /// Notify when new data arrives from relay.
    notify: mpsc::Sender<()>,
    /// Whether the relay signaled connection established.
    connected: bool,
    /// Whether the relay signaled shutdown.
    shutdown: bool,
}

/// Shared tunnel state.
pub struct TunnelState {
    pub key: TunnelKey,
    socket: Arc<UdpSocket>,
    pub relay_addr: SocketAddr,
    conns: RwLock<HashMap<ConnId, ConnState>>,
    /// Channel for relay events consumed by the TUN handler.
    relay_events: mpsc::Sender<RelayEvent>,
    /// Stats
    ping_seq: std::sync::atomic::AtomicU64,
    pub last_rtt_ms: std::sync::atomic::AtomicU64,
    pub bytes_tx: std::sync::atomic::AtomicU64,
    pub bytes_rx: std::sync::atomic::AtomicU64,
}

pub async fn run(relay_addr: SocketAddr, key: TunnelKey) -> Result<()> {
    // Create UDP socket with large buffers to reduce packet loss under burst.
    let sock2 = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
    sock2.set_recv_buffer_size(2 * 1024 * 1024)?;
    sock2.set_send_buffer_size(2 * 1024 * 1024)?;
    sock2.set_nonblocking(true)?;
    sock2.bind(&socket2::SockAddr::from("0.0.0.0:0".parse::<SocketAddr>().unwrap()))?;
    let socket = Arc::new(UdpSocket::from_std(sock2.into())?);
    let local_addr = socket.local_addr()?;
    tracing::info!(%local_addr, %relay_addr, "tunnel socket bound");

    let (relay_tx, relay_rx) = mpsc::channel(1024);

    let state = Arc::new(TunnelState {
        key,
        socket,
        relay_addr,
        conns: RwLock::new(HashMap::new()),
        relay_events: relay_tx,
        ping_seq: std::sync::atomic::AtomicU64::new(0),
        last_rtt_ms: std::sync::atomic::AtomicU64::new(0),
        bytes_tx: std::sync::atomic::AtomicU64::new(0),
        bytes_rx: std::sync::atomic::AtomicU64::new(0),
    });

    // Spawn receiver task (reads from relay)
    let recv_state = state.clone();
    let recv_task = tokio::spawn(async move {
        if let Err(e) = recv_loop(recv_state).await {
            tracing::error!("recv loop error: {e}");
        }
    });

    // Spawn ping task
    let ping_state = state.clone();
    let ping_task = tokio::spawn(async move {
        ping_loop(ping_state).await;
    });

    // On non-Windows (dev/test), run a simple SOCKS-like forwarder or just wait.
    // On Windows, this would integrate with the TUN adapter.
    #[cfg(not(windows))]
    {
        tracing::info!("running in development mode (no TUN adapter)");
        tracing::info!("use AION2_TEST_DST=ip:port to test a single TCP connection");

        if let Ok(dst) = std::env::var("AION2_TEST_DST") {
            // Test mode: proxy stdin/stdout to a game server via the tunnel
            let dst: SocketAddr = dst.parse()?;
            test_single_connection(state.clone(), dst).await?;
        } else {
            // Just run the listener and ping loop
            tracing::info!("no test destination set, running ping-only mode");
            tracing::info!("press Ctrl+C to stop");
            tokio::signal::ctrl_c().await?;
        }
    }

    #[cfg(windows)]
    {
        // Windows: integrate with TUN adapter
        crate::tun_windows::run_tun(state.clone(), relay_rx).await?;
    }

    #[cfg(not(windows))]
    drop(relay_rx);

    recv_task.abort();
    ping_task.abort();
    Ok(())
}

/// Receive loop: read encrypted packets from relay, dispatch to connections.
async fn recv_loop(state: Arc<TunnelState>) -> Result<()> {
    let mut buf = vec![0u8; MAX_PACKET_SIZE];
    loop {
        let (len, _peer) = state.socket.recv_from(&mut buf).await?;
        let packet = &buf[..len];

        let msg = match crypto::open(&state.key, packet) {
            Ok(msg) => msg,
            Err(e) => {
                tracing::warn!("failed to decrypt relay packet: {e}");
                continue;
            }
        };

        match msg {
            TunnelMessage::Connected(conn) => {
                tracing::info!(%conn, "connection established");
                let _ = state.relay_events.try_send(RelayEvent::Connected(conn));
                #[cfg(not(windows))]
                {
                    let mut conns = state.conns.write().await;
                    if let Some(cs) = conns.get_mut(&conn) {
                        cs.connected = true;
                        let _ = cs.notify.send(()).await;
                    }
                }
            }

            TunnelMessage::ConnectFailed { conn, reason } => {
                tracing::error!(%conn, %reason, "connection failed");
                let _ = state.relay_events.try_send(RelayEvent::ConnectFailed {
                    conn,
                    reason: reason.clone(),
                });
                let mut conns = state.conns.write().await;
                conns.remove(&conn);
            }

            TunnelMessage::Data { conn, payload } => {
                state.bytes_rx.fetch_add(payload.len() as u64, std::sync::atomic::Ordering::Relaxed);
                #[cfg(not(windows))]
                {
                    let mut conns = state.conns.write().await;
                    if let Some(cs) = conns.get_mut(&conn) {
                        cs.rx_buf.extend_from_slice(&payload);
                        let _ = cs.notify.send(()).await;
                    }
                }
                // Move owned payload directly — no clone needed.
                let _ = state.relay_events.try_send(RelayEvent::Data {
                    conn,
                    payload,
                });
            }

            TunnelMessage::Shutdown(conn) => {
                tracing::info!(%conn, "server shutdown");
                let _ = state.relay_events.try_send(RelayEvent::Shutdown(conn));
                #[cfg(not(windows))]
                {
                    let mut conns = state.conns.write().await;
                    if let Some(cs) = conns.get_mut(&conn) {
                        cs.shutdown = true;
                        let _ = cs.notify.send(()).await;
                    }
                }
            }

            TunnelMessage::Reset(conn) => {
                tracing::info!(%conn, "server reset");
                let _ = state.relay_events.try_send(RelayEvent::Reset(conn));
                let mut conns = state.conns.write().await;
                conns.remove(&conn);
            }

            TunnelMessage::Pong {
                seq,
                client_timestamp_ms,
            } => {
                let now_ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u64;
                let rtt = now_ms.saturating_sub(client_timestamp_ms);
                state
                    .last_rtt_ms
                    .store(rtt, std::sync::atomic::Ordering::Relaxed);
                let tx = state.bytes_tx.load(std::sync::atomic::Ordering::Relaxed);
                let rx = state.bytes_rx.load(std::sync::atomic::Ordering::Relaxed);
                tracing::info!(seq, rtt_ms = rtt, bytes_tx = tx, bytes_rx = rx, "pong");
            }

            _ => {
                tracing::warn!("unexpected message from relay");
            }
        }
    }
}

/// Periodic ping to measure tunnel latency.
async fn ping_loop(state: Arc<TunnelState>) {
    let mut interval = tokio::time::interval(Duration::from_secs(5));
    loop {
        interval.tick().await;
        let seq = state
            .ping_seq
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let timestamp_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let msg = TunnelMessage::Ping { seq, timestamp_ms };
        if let Err(e) = send_to_relay(&state, &msg).await {
            tracing::warn!("ping send failed: {e}");
        }
    }
}

/// Encrypt and send a message to the relay.
async fn send_to_relay(state: &TunnelState, msg: &TunnelMessage) -> Result<()> {
    let packet = crypto::seal(&state.key, msg)?;
    state.socket.send_to(&packet, state.relay_addr).await?;
    Ok(())
}

/// Request a new TCP connection through the tunnel.
/// Returns a handle for reading/writing data.
pub async fn open_connection(
    state: &Arc<TunnelState>,
    src_ip: Ipv4Addr,
    src_port: u16,
    dst_ip: Ipv4Addr,
    dst_port: u16,
) -> Result<(ConnId, mpsc::Receiver<()>)> {
    let conn = ConnId::new(src_ip, src_port, dst_ip, dst_port);
    let (notify_tx, notify_rx) = mpsc::channel(32);

    {
        let mut conns = state.conns.write().await;
        conns.insert(
            conn,
            ConnState {
                rx_buf: Vec::new(),
                notify: notify_tx,
                connected: false,
                shutdown: false,
            },
        );
    }

    // Send connect request to relay
    send_to_relay(state, &TunnelMessage::Connect(conn)).await?;
    tracing::info!(%conn, "requesting connection");

    Ok((conn, notify_rx))
}

/// Send data through an existing tunnel connection.
pub async fn send_data(state: &Arc<TunnelState>, conn: ConnId, payload: Vec<u8>) -> Result<()> {
    state.bytes_tx.fetch_add(payload.len() as u64, std::sync::atomic::Ordering::Relaxed);
    // Split into MAX_PAYLOAD_SIZE chunks
    for chunk in payload.chunks(MAX_PAYLOAD_SIZE) {
        let msg = TunnelMessage::Data {
            conn,
            payload: chunk.to_vec(),
        };
        send_to_relay(state, &msg).await?;
    }
    Ok(())
}

/// Send a shutdown (FIN) for a tunnel connection.
pub async fn send_shutdown(state: &Arc<TunnelState>, conn: ConnId) -> Result<()> {
    send_to_relay(state, &TunnelMessage::Shutdown(conn)).await
}

/// Send a reset (RST) for a tunnel connection.
pub async fn send_reset(state: &Arc<TunnelState>, conn: ConnId) -> Result<()> {
    send_to_relay(state, &TunnelMessage::Reset(conn)).await
}

/// Drain received data for a connection.
#[cfg(not(windows))]
pub async fn drain_rx(state: &Arc<TunnelState>, conn: &ConnId) -> Vec<u8> {
    let mut conns = state.conns.write().await;
    if let Some(cs) = conns.get_mut(conn) {
        std::mem::take(&mut cs.rx_buf)
    } else {
        Vec::new()
    }
}

/// Check if connection is established.
#[cfg(not(windows))]
pub async fn is_connected(state: &Arc<TunnelState>, conn: &ConnId) -> bool {
    let conns = state.conns.read().await;
    conns.get(conn).is_some_and(|cs| cs.connected)
}

/// Check if server signaled shutdown.
#[cfg(not(windows))]
pub async fn is_shutdown(state: &Arc<TunnelState>, conn: &ConnId) -> bool {
    let conns = state.conns.read().await;
    conns.get(conn).is_some_and(|cs| cs.shutdown)
}

/// Test mode: proxy a single TCP connection through the tunnel (for dev/testing).
#[cfg(not(windows))]
async fn test_single_connection(state: Arc<TunnelState>, dst: SocketAddr) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let dst_ip = match dst.ip() {
        std::net::IpAddr::V4(ip) => ip,
        _ => anyhow::bail!("only IPv4 supported"),
    };

    let (conn, mut notify) = open_connection(
        &state,
        Ipv4Addr::new(10, 200, 0, 2),
        12345,
        dst_ip,
        dst.port(),
    )
    .await?;

    // Wait for connection
    tracing::info!("waiting for relay to connect to {dst}...");
    loop {
        notify.recv().await;
        if is_connected(&state, &conn).await {
            tracing::info!("connected!");
            break;
        }
    }

    // Simple echo: read from stdin, send to tunnel; read from tunnel, write to stdout
    let mut stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let mut stdin_buf = vec![0u8; MAX_PAYLOAD_SIZE];

    loop {
        tokio::select! {
            result = stdin.read(&mut stdin_buf) => {
                match result {
                    Ok(0) => {
                        send_to_relay(&state, &TunnelMessage::Shutdown(conn)).await?;
                        break;
                    }
                    Ok(n) => {
                        send_data(&state, conn, stdin_buf[..n].to_vec()).await?;
                    }
                    Err(e) => {
                        tracing::error!("stdin read error: {e}");
                        break;
                    }
                }
            }
            _ = notify.recv() => {
                let data = drain_rx(&state, &conn).await;
                if !data.is_empty() {
                    stdout.write_all(&data).await?;
                    stdout.flush().await?;
                }
                if is_shutdown(&state, &conn).await {
                    tracing::info!("server closed connection");
                    break;
                }
            }
        }
    }

    Ok(())
}

