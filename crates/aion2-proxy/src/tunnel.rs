use aion2_common::crypto::{self, TunnelKey};
use aion2_common::protocol::{ConnId, SessionId, TunnelMessage, MAX_PACKET_SIZE, MAX_PAYLOAD_SIZE};
use anyhow::Result;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
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
    pub session_id: SessionId,
    socket: Arc<UdpSocket>,
    pub relay_addr: SocketAddr,
    conns: RwLock<HashMap<ConnId, ConnState>>,
    /// Channel for relay events consumed by the TUN handler.
    relay_events: mpsc::Sender<RelayEvent>,
    /// TCP transport: send encrypted packets to relay via TCP
    tcp_tx: mpsc::Sender<Vec<u8>>,
    /// Stats
    ping_seq: std::sync::atomic::AtomicU64,
    pub last_rtt_ms: std::sync::atomic::AtomicU64,
    pub bytes_tx: std::sync::atomic::AtomicU64,
    pub bytes_rx: std::sync::atomic::AtomicU64,
}

pub async fn run(relay_addr: SocketAddr, key: TunnelKey) -> Result<()> {
    // Generate a random session ID for this proxy instance.
    // This allows multiple clients sharing the same key to coexist on the relay.
    let mut session_id: SessionId = [0u8; 8];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut session_id);
    let session_hex: String = session_id.iter().map(|b| format!("{b:02x}")).collect();
    tracing::info!(session = %session_hex, "generated session ID");

    // Create UDP socket for ping/pong latency measurement
    let sock2 = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
    sock2.set_recv_buffer_size(2 * 1024 * 1024)?;
    sock2.set_send_buffer_size(2 * 1024 * 1024)?;
    sock2.set_nonblocking(true)?;
    sock2.bind(&socket2::SockAddr::from("0.0.0.0:0".parse::<SocketAddr>().unwrap()))?;
    let socket = Arc::new(UdpSocket::from_std(sock2.into())?);
    let local_addr = socket.local_addr()?;
    tracing::info!(%local_addr, %relay_addr, "UDP socket bound (ping/pong)");

    // Connect to relay via TCP for reliable data transport
    tracing::info!(%relay_addr, "connecting TCP tunnel to relay...");
    let tcp_stream = tokio::net::TcpStream::connect(relay_addr).await?;
    tcp_stream.set_nodelay(true)?;
    tracing::info!(%relay_addr, "TCP tunnel connected");

    let (tcp_read, mut tcp_write_half) = tcp_stream.into_split();

    // Channel for TCP write: proxy→relay
    let (tcp_tx, mut tcp_rx) = mpsc::channel::<Vec<u8>>(16384);

    let (relay_tx, relay_rx) = mpsc::channel(16384);

    let state = Arc::new(TunnelState {
        key,
        session_id,
        socket,
        relay_addr,
        conns: RwLock::new(HashMap::new()),
        relay_events: relay_tx,
        tcp_tx,
        ping_seq: std::sync::atomic::AtomicU64::new(0),
        last_rtt_ms: std::sync::atomic::AtomicU64::new(0),
        bytes_tx: std::sync::atomic::AtomicU64::new(0),
        bytes_rx: std::sync::atomic::AtomicU64::new(0),
    });

    // TCP write task: sends length-prefixed encrypted packets to relay
    tokio::spawn(async move {
        while let Some(packet) = tcp_rx.recv().await {
            let len = (packet.len() as u32).to_be_bytes();
            if tcp_write_half.write_all(&len).await.is_err() {
                tracing::error!("TCP tunnel write error (length)");
                break;
            }
            if tcp_write_half.write_all(&packet).await.is_err() {
                tracing::error!("TCP tunnel write error (payload)");
                break;
            }
        }
        tracing::info!("TCP tunnel write task ended");
    });

    // TCP read task: reads length-prefixed encrypted packets from relay
    let tcp_recv_state = state.clone();
    let tcp_recv_task = tokio::spawn(async move {
        if let Err(e) = tcp_recv_loop(tcp_recv_state, tcp_read).await {
            tracing::error!("TCP recv loop error: {e}");
        }
    });

    // UDP receiver task (for ping/pong responses only)
    let recv_state = state.clone();
    let recv_task = tokio::spawn(async move {
        if let Err(e) = recv_loop(recv_state).await {
            tracing::error!("UDP recv loop error: {e}");
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

    tcp_recv_task.abort();
    recv_task.abort();
    ping_task.abort();
    Ok(())
}

/// Receive loop for TCP: reads length-prefixed encrypted packets from relay.
/// Handles all message types (reliable transport).
async fn tcp_recv_loop(state: Arc<TunnelState>, mut tcp_read: tokio::net::tcp::OwnedReadHalf) -> Result<()> {
    loop {
        let mut len_buf = [0u8; 4];
        tcp_read.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;
        if len > MAX_PACKET_SIZE * 2 {
            anyhow::bail!("frame too large from relay: {len}");
        }
        let mut packet = vec![0u8; len];
        tcp_read.read_exact(&mut packet).await?;

        let msg = match crypto::open(&state.key, &packet) {
            Ok(msg) => msg,
            Err(e) => {
                tracing::warn!("failed to decrypt relay TCP packet: {e}");
                continue;
            }
        };

        dispatch_relay_message(&state, msg).await;
    }
}

/// Receive loop for UDP: now only handles Pong messages (latency measurement).
async fn recv_loop(state: Arc<TunnelState>) -> Result<()> {
    let mut buf = vec![0u8; MAX_PACKET_SIZE];
    loop {
        let (len, _peer) = state.socket.recv_from(&mut buf).await?;
        let packet = &buf[..len];

        let msg = match crypto::open(&state.key, packet) {
            Ok(msg) => msg,
            Err(e) => {
                tracing::warn!("failed to decrypt relay UDP packet: {e}");
                continue;
            }
        };

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
                state
                    .last_rtt_ms
                    .store(rtt, std::sync::atomic::Ordering::Relaxed);
                let tx = state.bytes_tx.load(std::sync::atomic::Ordering::Relaxed);
                let rx = state.bytes_rx.load(std::sync::atomic::Ordering::Relaxed);
                tracing::info!(seq, rtt_ms = rtt, bytes_tx = tx, bytes_rx = rx, "pong");
            }
            // If we receive non-Pong messages on UDP (shouldn't happen with TCP relay),
            // dispatch them normally as fallback.
            other => {
                dispatch_relay_message(&state, other).await;
            }
        }
    }
}

/// Dispatch a decrypted relay message to the appropriate handler.
async fn dispatch_relay_message(state: &TunnelState, msg: TunnelMessage) {
    match msg {
        TunnelMessage::Connected(conn) => {
            tracing::info!(%conn, "connection established");
            if state.relay_events.send(RelayEvent::Connected(conn)).await.is_err() {
                tracing::error!(%conn, "relay_events channel closed (Connected)");
            }
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
            if state.relay_events.send(RelayEvent::ConnectFailed {
                conn,
                reason: reason.clone(),
            }).await.is_err() {
                tracing::error!(%conn, "relay_events channel closed (ConnectFailed)");
            }
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
            if let Err(e) = state.relay_events.try_send(RelayEvent::Data {
                conn,
                payload,
            }) {
                tracing::warn!(%conn, "relay_events channel full, dropping data ({e})");
            }
        }

        TunnelMessage::Shutdown(conn) => {
            tracing::info!(%conn, "server shutdown");
            if state.relay_events.send(RelayEvent::Shutdown(conn)).await.is_err() {
                tracing::error!(%conn, "relay_events channel closed (Shutdown)");
            }
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
            if state.relay_events.send(RelayEvent::Reset(conn)).await.is_err() {
                tracing::error!(%conn, "relay_events channel closed (Reset)");
            }
            let mut conns = state.conns.write().await;
            conns.remove(&conn);
        }

        TunnelMessage::Pong { seq, client_timestamp_ms } => {
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

/// Periodic ping to measure tunnel latency (sent via UDP for low overhead).
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
        // Send ping via UDP for lower latency measurement
        if let Err(e) = send_to_relay_udp(&state, &msg).await {
            tracing::warn!("ping send failed: {e}");
        }
    }
}

/// Encrypt and send a message to the relay via TCP (reliable).
async fn send_to_relay(state: &TunnelState, msg: &TunnelMessage) -> Result<()> {
    let packet = crypto::seal(&state.key, &state.session_id, msg)?;
    if state.tcp_tx.send(packet).await.is_err() {
        anyhow::bail!("TCP tunnel write channel closed");
    }
    Ok(())
}

/// Encrypt and send a message to the relay via UDP (for ping/pong).
async fn send_to_relay_udp(state: &TunnelState, msg: &TunnelMessage) -> Result<()> {
    let packet = crypto::seal(&state.key, &state.session_id, msg)?;
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

