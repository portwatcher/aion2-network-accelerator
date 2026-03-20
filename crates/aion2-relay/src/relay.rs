use aion2_common::crypto::{self, KeyId, TunnelKey};
use aion2_common::protocol::{ConnId, TunnelMessage, MAX_PACKET_SIZE};
use anyhow::Result;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, RwLock};

/// State for a single proxied TCP connection.
struct TcpConn {
    /// Send data to the TCP write half.
    tx: mpsc::Sender<Vec<u8>>,
    /// Send shutdown signal.
    shutdown_tx: mpsc::Sender<()>,
}

/// Per-user state.
struct UserState {
    key: Arc<TunnelKey>,
    name: String,
    /// The user's latest UDP address (learned from packets).
    addr: Option<SocketAddr>,
    /// TCP transport: channel to send encrypted packets to the user.
    tcp_tx: Option<mpsc::Sender<Vec<u8>>>,
}

/// Shared relay state.
pub struct RelayState {
    socket: Arc<UdpSocket>,
    /// key_id → user state. Protected by RwLock for hot-reload.
    users: RwLock<HashMap<KeyId, UserState>>,
    /// ConnId → active TCP connection state.
    conns: RwLock<HashMap<ConnId, TcpConn>>,
}

impl RelayState {
    /// Load or reload keys from a map of name → TunnelKey.
    pub async fn load_keys(&self, keys: HashMap<String, TunnelKey>) {
        let mut users = self.users.write().await;
        // Keep existing user addresses for keys that didn't change
        let mut new_users = HashMap::new();
        for (name, key) in keys {
            let existing_addr = users.get(&key.key_id).and_then(|u| u.addr);
            let existing_tcp_tx = users.get(&key.key_id).and_then(|u| u.tcp_tx.clone());
            new_users.insert(
                key.key_id,
                UserState {
                    key: Arc::new(key),
                    name,
                    addr: existing_addr,
                    tcp_tx: existing_tcp_tx,
                },
            );
        }
        let old_count = users.len();
        let new_count = new_users.len();
        *users = new_users;
        tracing::info!(old_count, new_count, "keys (re)loaded");
    }
}

pub async fn run(listen_addr: SocketAddr, keys: HashMap<String, TunnelKey>) -> Result<()> {
    // Create UDP socket with large buffers to absorb traffic bursts.
    let sock2 = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
    sock2.set_recv_buffer_size(4 * 1024 * 1024)?;
    sock2.set_send_buffer_size(4 * 1024 * 1024)?;
    sock2.set_nonblocking(true)?;
    sock2.bind(&socket2::SockAddr::from(listen_addr))?;
    let socket = Arc::new(UdpSocket::from_std(sock2.into())?);
    tracing::info!("UDP listening on {listen_addr}");

    // Create TCP listener on the same port
    let tcp_listener = TcpListener::bind(listen_addr).await?;
    tracing::info!("TCP listening on {listen_addr}");

    let state = Arc::new(RelayState {
        socket,
        users: RwLock::new(HashMap::new()),
        conns: RwLock::new(HashMap::new()),
    });

    state.load_keys(keys).await;

    // Install SIGHUP handler for key reload (Unix only)
    #[cfg(unix)]
    {
        let reload_state = state.clone();
        tokio::spawn(async move {
            use tokio::signal::unix::{signal, SignalKind};
            let mut sighup =
                signal(SignalKind::hangup()).expect("failed to install SIGHUP handler");
            loop {
                sighup.recv().await;
                tracing::info!("SIGHUP received, reloading keys...");
                match load_keys_from_dir("/etc/aion2-relay/keys") {
                    Ok(keys) => reload_state.load_keys(keys).await,
                    Err(e) => tracing::error!("failed to reload keys: {e}"),
                }
            }
        });
    }

    // Spawn TCP acceptor task
    let tcp_state = state.clone();
    tokio::spawn(async move {
        loop {
            match tcp_listener.accept().await {
                Ok((stream, peer)) => {
                    tracing::info!(%peer, "TCP tunnel connection accepted");
                    let s = tcp_state.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_tcp_tunnel(s, stream, peer).await {
                            tracing::warn!(%peer, "TCP tunnel error: {e}");
                        }
                    });
                }
                Err(e) => {
                    tracing::error!("TCP accept error: {e}");
                }
            }
        }
    });

    let mut buf = vec![0u8; MAX_PACKET_SIZE];

    loop {
        let (len, peer) = state.socket.recv_from(&mut buf).await?;
        let packet = &buf[..len];

        // Peek key_id to identify user
        let key_id = match crypto::peek_key_id(packet) {
            Ok(id) => id,
            Err(e) => {
                tracing::warn!(%peer, "invalid packet (no key_id): {e}");
                continue;
            }
        };

        // Look up user, decrypt — use read lock for the common path.
        // Only upgrade to write lock when the user's address changes.
        let msg = {
            let users = state.users.read().await;
            let user = match users.get(&key_id) {
                Some(u) => u,
                None => {
                    tracing::warn!(%peer, key_id = hex_encode(key_id), "unknown key_id");
                    continue;
                }
            };

            let msg = match crypto::open(&user.key, packet) {
                Ok(msg) => msg,
                Err(e) => {
                    tracing::warn!(%peer, user = %user.name, "decrypt failed: {e}");
                    continue;
                }
            };

            let need_update = user.addr != Some(peer);
            drop(users);

            // Update user's address only when it actually changed (rare).
            if need_update {
                let mut users = state.users.write().await;
                if let Some(user) = users.get_mut(&key_id) {
                    tracing::info!(%peer, user = %user.name, "client connected");
                    user.addr = Some(peer);
                }
            }

            msg
        };

        handle_message(state.clone(), msg, key_id).await;
    }
}

/// Load all `*.key` files from a directory. Filename (sans extension) = username.
pub fn load_keys_from_dir(dir: &str) -> Result<HashMap<String, TunnelKey>> {
    let mut keys = HashMap::new();
    let dir_path = std::path::Path::new(dir);
    if !dir_path.is_dir() {
        anyhow::bail!("{dir} is not a directory");
    }

    for entry in std::fs::read_dir(dir_path)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("key") {
            continue;
        }
        let name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
            .to_string();

        let hex = std::fs::read_to_string(&path)
            .map_err(|e| anyhow::anyhow!("failed to read {}: {e}", path.display()))?;
        let hex = hex.trim();
        let key_bytes = crate::hex_decode(hex)
            .map_err(|e| anyhow::anyhow!("invalid key in {}: {e}", path.display()))?;
        let key = TunnelKey::from_bytes(&key_bytes);

        tracing::info!(user = %name, key_id = hex_encode(key.key_id), "loaded key");
        keys.insert(name, key);
    }

    if keys.is_empty() {
        anyhow::bail!("no .key files found in {dir}");
    }

    Ok(keys)
}

/// Handle an authenticated TCP tunnel connection from a proxy client.
/// Reads length-prefixed encrypted messages, dispatches them like UDP.
/// Also registers a TCP write channel for sending data back.
async fn handle_tcp_tunnel(state: Arc<RelayState>, stream: TcpStream, peer: SocketAddr) -> Result<()> {
    stream.set_nodelay(true)?;
    let (mut tcp_read, mut tcp_write) = stream.into_split();

    // Read the first message to identify the user (authenticate)
    let first_packet = read_framed(&mut tcp_read).await?;
    let key_id = crypto::peek_key_id(&first_packet)?;

    let (key, user_name) = {
        let users = state.users.read().await;
        match users.get(&key_id) {
            Some(u) => (Arc::clone(&u.key), u.name.clone()),
            None => {
                anyhow::bail!("unknown key_id {}", hex_encode(key_id));
            }
        }
    };

    // Decrypt the first message to verify authentication
    let first_msg = crypto::open(&key, &first_packet)?;
    tracing::info!(%peer, user = %user_name, "TCP tunnel authenticated");

    // Create a channel for sending messages back to this user over TCP
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(8192);

    // Register TCP transport for this user
    {
        let mut users = state.users.write().await;
        if let Some(user) = users.get_mut(&key_id) {
            user.tcp_tx = Some(tx.clone());
            user.addr = Some(peer);
        }
    }

    // Spawn TCP write task: relay→proxy direction
    let write_key_id = key_id;
    let write_state = state.clone();
    let write_task = tokio::spawn(async move {
        while let Some(packet) = rx.recv().await {
            let len = (packet.len() as u32).to_be_bytes();
            if tcp_write.write_all(&len).await.is_err() {
                break;
            }
            if tcp_write.write_all(&packet).await.is_err() {
                break;
            }
        }
        // Clean up TCP transport on disconnect
        let mut users = write_state.users.write().await;
        if let Some(user) = users.get_mut(&write_key_id) {
            user.tcp_tx = None;
            tracing::info!(user = %user.name, "TCP tunnel write task ended");
        }
    });

    // Process the first message we already decrypted
    handle_message(state.clone(), first_msg, key_id).await;

    // Read loop: proxy→relay direction
    loop {
        let packet = match read_framed(&mut tcp_read).await {
            Ok(p) => p,
            Err(_) => break,
        };

        let peeked_key_id = match crypto::peek_key_id(&packet) {
            Ok(id) => id,
            Err(_) => continue,
        };

        let msg = {
            let users = state.users.read().await;
            match users.get(&peeked_key_id) {
                Some(user) => match crypto::open(&user.key, &packet) {
                    Ok(msg) => msg,
                    Err(e) => {
                        tracing::warn!(%peer, "TCP decrypt failed: {e}");
                        continue;
                    }
                },
                None => continue,
            }
        };

        handle_message(state.clone(), msg, peeked_key_id).await;
    }

    tracing::info!(%peer, user = %user_name, "TCP tunnel disconnected");

    // Clean up TCP transport
    {
        let mut users = state.users.write().await;
        if let Some(user) = users.get_mut(&key_id) {
            user.tcp_tx = None;
        }
    }

    write_task.abort();
    Ok(())
}

/// Read a length-prefixed frame from a TCP stream.
/// Format: 4-byte big-endian length, then that many bytes of payload.
async fn read_framed(reader: &mut tokio::net::tcp::OwnedReadHalf) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_PACKET_SIZE * 2 {
        anyhow::bail!("frame too large: {len}");
    }
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).await?;
    Ok(buf)
}

async fn handle_message(state: Arc<RelayState>, msg: TunnelMessage, key_id: KeyId) {
    match msg {
        TunnelMessage::Connect(conn) => {
            tracing::info!(%conn, key_id = hex_encode(key_id), "connect request");
            let state = state.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_connect(state, conn, key_id).await {
                    tracing::error!(%conn, "connect failed: {e}");
                }
            });
        }

        TunnelMessage::Data { conn, payload } => {
            let conns = state.conns.read().await;
            if let Some(tcp) = conns.get(&conn) {
                if tcp.tx.try_send(payload).is_err() {
                    tracing::warn!(%conn, "TCP write channel full or closed");
                }
            }
        }

        TunnelMessage::Shutdown(conn) => {
            let conns = state.conns.read().await;
            if let Some(tcp) = conns.get(&conn) {
                let _ = tcp.shutdown_tx.try_send(());
            }
        }

        TunnelMessage::Reset(conn) => {
            tracing::info!(%conn, "reset");
            let mut conns = state.conns.write().await;
            conns.remove(&conn);
        }

        TunnelMessage::Ping {
            seq,
            timestamp_ms,
        } => {
            let reply = TunnelMessage::Pong {
                seq,
                client_timestamp_ms: timestamp_ms,
            };
            send_to_user(&state, key_id, &reply).await;
        }

        _ => {
            tracing::warn!("unexpected message from client: {:?}", msg);
        }
    }
}

/// Open a real TCP connection to the game server and bridge it to the tunnel.
async fn handle_connect(state: Arc<RelayState>, conn: ConnId, key_id: KeyId) -> Result<()> {
    let dst = SocketAddr::new(conn.dst_addr().into(), conn.dst_port);
    tracing::info!(%conn, %dst, "connecting to game server");

    let tcp_stream = match TcpStream::connect(dst).await {
        Ok(s) => {
            s.set_nodelay(true)?;
            tracing::info!(%conn, "connected to game server");
            send_to_user(&state, key_id, &TunnelMessage::Connected(conn)).await;
            s
        }
        Err(e) => {
            tracing::error!(%conn, "TCP connect failed: {e}");
            send_to_user(
                &state,
                key_id,
                &TunnelMessage::ConnectFailed {
                    conn,
                    reason: e.to_string(),
                },
            )
            .await;
            return Ok(());
        }
    };

    let (mut tcp_read, mut tcp_write) = tcp_stream.into_split();

    // Channel for data from tunnel → TCP write
    let (data_tx, mut data_rx) = mpsc::channel::<Vec<u8>>(4096);
    // Channel for shutdown signal
    let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);

    // Register the connection
    {
        let mut conns = state.conns.write().await;
        conns.insert(conn, TcpConn { tx: data_tx, shutdown_tx });
    }

    // Shared write counters so read task can log them on close
    let write_bytes = Arc::new(AtomicU64::new(0));
    let write_msgs = Arc::new(AtomicU64::new(0));

    // Task: tunnel → TCP (write to game server)
    let write_state = state.clone();
    let wb = write_bytes.clone();
    let wm = write_msgs.clone();
    let write_task = tokio::spawn(async move {
        loop {
            tokio::select! {
                biased; // Always check data first to avoid sending FIN before draining data
                data = data_rx.recv() => {
                    match data {
                        Some(payload) => {
                            wb.fetch_add(payload.len() as u64, Ordering::Relaxed);
                            wm.fetch_add(1, Ordering::Relaxed);
                            if let Err(e) = tcp_write.write_all(&payload).await {
                                tracing::warn!(%conn, "TCP write error: {e}");
                                break;
                            }
                        }
                        None => break,
                    }
                }
                _ = shutdown_rx.recv() => {
                    // Drain all remaining data before shutting down TCP
                    while let Ok(payload) = data_rx.try_recv() {
                        wb.fetch_add(payload.len() as u64, Ordering::Relaxed);
                        wm.fetch_add(1, Ordering::Relaxed);
                        if let Err(e) = tcp_write.write_all(&payload).await {
                            tracing::warn!(%conn, "TCP write error during drain: {e}");
                            break;
                        }
                    }
                    let _ = tcp_write.shutdown().await;
                    break;
                }
            }
        }
        let mut conns = write_state.conns.write().await;
        conns.remove(&conn);
    });

    // Task: TCP read → tunnel (read from game server, send to user)
    let read_state = state.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; aion2_common::protocol::MAX_PAYLOAD_SIZE];
        let mut bytes_read: u64 = 0;
        let mut read_msgs: u64 = 0;
        let start = std::time::Instant::now();
        let mut last_read = std::time::Instant::now();
        let mut last_data: Vec<u8> = Vec::new(); // Last chunk received (for diagnostics)
        loop {
            match tcp_read.read(&mut buf).await {
                Ok(0) => {
                    let bw = write_bytes.load(Ordering::Relaxed);
                    let wm = write_msgs.load(Ordering::Relaxed);
                    let lifetime = start.elapsed().as_secs();
                    let idle_read = last_read.elapsed().as_millis();
                    // Log last bytes for protocol analysis
                    let last_hex: String = last_data.iter().take(64).map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ");
                    tracing::info!(%conn, bytes_read, read_msgs, bytes_written=bw, write_msgs=wm, lifetime, idle_read_ms=idle_read, last_bytes=last_hex, last_len=last_data.len(), "game server closed connection");
                    send_to_user(&read_state, key_id, &TunnelMessage::Shutdown(conn)).await;
                    break;
                }
                Ok(n) => {
                    last_read = std::time::Instant::now();
                    bytes_read += n as u64;
                    read_msgs += 1;
                    last_data = buf[..n].to_vec();
                    let msg = TunnelMessage::Data {
                        conn,
                        payload: buf[..n].to_vec(),
                    };
                    send_to_user(&read_state, key_id, &msg).await;
                }
                Err(e) => {
                    let bw = write_bytes.load(Ordering::Relaxed);
                    let wm = write_msgs.load(Ordering::Relaxed);
                    let lifetime = start.elapsed().as_secs();
                    tracing::warn!(%conn, bytes_read, read_msgs, bytes_written=bw, write_msgs=wm, lifetime, "TCP read error: {e}");
                    send_to_user(&read_state, key_id, &TunnelMessage::Reset(conn)).await;
                    break;
                }
            }
        }
        write_task.abort();
        let mut conns = read_state.conns.write().await;
        conns.remove(&conn);
    });

    Ok(())
}

/// Encrypt and send a TunnelMessage to a specific user identified by key_id.
/// Prefers TCP transport when available (reliable), falls back to UDP.
async fn send_to_user(state: &RelayState, key_id: KeyId, msg: &TunnelMessage) {
    let (addr, key, tcp_tx) = {
        let users = state.users.read().await;
        match users.get(&key_id) {
            Some(user) => (
                user.addr,
                Arc::clone(&user.key),
                user.tcp_tx.clone(),
            ),
            None => {
                tracing::warn!(key_id = hex_encode(key_id), "user no longer exists");
                return;
            }
        }
    };

    let packet = match crypto::seal(&key, msg) {
        Ok(p) => p,
        Err(e) => {
            tracing::error!("failed to encrypt message: {e}");
            return;
        }
    };

    // Prefer TCP (reliable, ordered) over UDP
    if let Some(tx) = tcp_tx {
        if tx.try_send(packet).is_err() {
            tracing::warn!(key_id = hex_encode(key_id), "TCP send channel full or closed");
        }
        return;
    }

    // Fall back to UDP
    if let Some(addr) = addr {
        if let Err(e) = state.socket.send_to(&packet, addr).await {
            tracing::warn!(%addr, "failed to send to client via UDP: {e}");
        }
    } else {
        tracing::warn!(key_id = hex_encode(key_id), "user has no address yet");
    }
}

fn hex_encode(bytes: impl AsRef<[u8]>) -> String {
    bytes
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
