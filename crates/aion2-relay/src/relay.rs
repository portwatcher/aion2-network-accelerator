use aion2_common::crypto::{self, KeyId, TunnelKey};
use aion2_common::protocol::{ConnId, SessionId, TunnelMessage, MAX_PACKET_SIZE};
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

/// Per-key configuration (loaded from disk).
struct KeyInfo {
    key: Arc<TunnelKey>,
    name: String,
}

/// Per-client session state. Multiple clients can share the same key,
/// each distinguished by a random SessionId generated at proxy startup.
struct ClientState {
    key: Arc<TunnelKey>,
    name: String,
    /// The client's latest UDP address (learned from packets).
    addr: Option<SocketAddr>,
    /// TCP transport: channel to send encrypted packets to this client.
    tcp_tx: Option<mpsc::Sender<Vec<u8>>>,
}

/// Shared relay state.
pub struct RelayState {
    socket: Arc<UdpSocket>,
    /// key_id → key info. For decrypting incoming packets. Protected by RwLock for hot-reload.
    keys: RwLock<HashMap<KeyId, KeyInfo>>,
    /// session_id → per-client state. Multiple sessions may share a key.
    clients: RwLock<HashMap<SessionId, ClientState>>,
    /// (session_id, conn_id) → active TCP connection state. Scoped per session to avoid
    /// collisions when multiple clients use the same TUN IP.
    conns: RwLock<HashMap<(SessionId, ConnId), TcpConn>>,
}

impl RelayState {
    /// Load or reload keys from a map of name → TunnelKey.
    pub async fn load_keys(&self, keys: HashMap<String, TunnelKey>) {
        let mut key_map = self.keys.write().await;
        let mut new_keys = HashMap::new();
        for (name, key) in keys {
            tracing::info!(user = %name, key_id = hex_encode(key.key_id), "loaded key");
            new_keys.insert(
                key.key_id,
                KeyInfo {
                    key: Arc::new(key),
                    name,
                },
            );
        }
        let old_count = key_map.len();
        let new_count = new_keys.len();
        *key_map = new_keys;
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
        keys: RwLock::new(HashMap::new()),
        clients: RwLock::new(HashMap::new()),
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

        // Peek key_id and session_id to identify the client
        let key_id = match crypto::peek_key_id(packet) {
            Ok(id) => id,
            Err(e) => {
                tracing::warn!(%peer, "invalid packet (no key_id): {e}");
                continue;
            }
        };

        let session_id = match crypto::peek_session_id(packet) {
            Ok(id) => id,
            Err(e) => {
                tracing::warn!(%peer, "invalid packet (no session_id): {e}");
                continue;
            }
        };

        // Look up key and decrypt
        let (msg, key, user_name) = {
            let keys = state.keys.read().await;
            match keys.get(&key_id) {
                Some(ki) => match crypto::open(&ki.key, packet) {
                    Ok(msg) => (msg, Arc::clone(&ki.key), ki.name.clone()),
                    Err(e) => {
                        tracing::warn!(%peer, user = %ki.name, "decrypt failed: {e}");
                        continue;
                    }
                },
                None => {
                    tracing::warn!(%peer, key_id = hex_encode(key_id), "unknown key_id");
                    continue;
                }
            }
        };

        // Register or update client session (read lock on hot path)
        let need_update = {
            let clients = state.clients.read().await;
            match clients.get(&session_id) {
                Some(c) => c.addr != Some(peer),
                None => true,
            }
        };

        if need_update {
            let mut clients = state.clients.write().await;
            let client = clients.entry(session_id).or_insert_with(|| {
                tracing::info!(%peer, user = %user_name, session = hex_encode(session_id), "new client session (UDP)");
                ClientState {
                    key: Arc::clone(&key),
                    name: user_name,
                    addr: None,
                    tcp_tx: None,
                }
            });
            client.addr = Some(peer);
        }

        handle_message(state.clone(), msg, session_id).await;
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
    let session_id = crypto::peek_session_id(&first_packet)?;

    let (key, user_name) = {
        let keys = state.keys.read().await;
        match keys.get(&key_id) {
            Some(ki) => (Arc::clone(&ki.key), ki.name.clone()),
            None => {
                anyhow::bail!("unknown key_id {}", hex_encode(key_id));
            }
        }
    };

    // Decrypt the first message to verify authentication
    let first_msg = crypto::open(&key, &first_packet)?;
    tracing::info!(%peer, user = %user_name, session = hex_encode(session_id), "TCP tunnel authenticated");

    // Create a channel for sending messages back to this client over TCP
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(8192);

    // Register client session with TCP transport
    {
        let mut clients = state.clients.write().await;
        let client = clients.entry(session_id).or_insert_with(|| {
            ClientState {
                key: Arc::clone(&key),
                name: user_name.clone(),
                addr: None,
                tcp_tx: None,
            }
        });
        client.tcp_tx = Some(tx.clone());
        client.addr = Some(peer);
    }

    // Spawn TCP write task: relay→proxy direction
    let write_session_id = session_id;
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
        let mut clients = write_state.clients.write().await;
        if let Some(client) = clients.get_mut(&write_session_id) {
            client.tcp_tx = None;
            tracing::info!(user = %client.name, "TCP tunnel write task ended");
        }
    });

    // Process the first message we already decrypted
    handle_message(state.clone(), first_msg, session_id).await;

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
            let keys = state.keys.read().await;
            match keys.get(&peeked_key_id) {
                Some(ki) => match crypto::open(&ki.key, &packet) {
                    Ok(msg) => msg,
                    Err(e) => {
                        tracing::warn!(%peer, "TCP decrypt failed: {e}");
                        continue;
                    }
                },
                None => continue,
            }
        };

        // All messages on this TCP connection belong to the same session
        handle_message(state.clone(), msg, session_id).await;
    }

    tracing::info!(%peer, user = %user_name, "TCP tunnel disconnected");

    // Clean up TCP transport and remove client session
    {
        let mut clients = state.clients.write().await;
        if let Some(client) = clients.get_mut(&session_id) {
            client.tcp_tx = None;
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

async fn handle_message(state: Arc<RelayState>, msg: TunnelMessage, session_id: SessionId) {
    match msg {
        TunnelMessage::Connect(conn) => {
            tracing::info!(%conn, session = hex_encode(session_id), "connect request");
            let state = state.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_connect(state, conn, session_id).await {
                    tracing::error!(%conn, "connect failed: {e}");
                }
            });
        }

        TunnelMessage::Data { conn, payload } => {
            let conns = state.conns.read().await;
            if let Some(tcp) = conns.get(&(session_id, conn)) {
                if tcp.tx.try_send(payload).is_err() {
                    tracing::warn!(%conn, "TCP write channel full or closed");
                }
            }
        }

        TunnelMessage::Shutdown(conn) => {
            let conns = state.conns.read().await;
            if let Some(tcp) = conns.get(&(session_id, conn)) {
                let _ = tcp.shutdown_tx.try_send(());
            }
        }

        TunnelMessage::Reset(conn) => {
            tracing::info!(%conn, "reset");
            let mut conns = state.conns.write().await;
            conns.remove(&(session_id, conn));
        }

        TunnelMessage::Ping {
            seq,
            timestamp_ms,
        } => {
            let reply = TunnelMessage::Pong {
                seq,
                client_timestamp_ms: timestamp_ms,
            };
            send_to_client(&state, session_id, &reply).await;
        }

        _ => {
            tracing::warn!("unexpected message from client: {:?}", msg);
        }
    }
}

/// Open a real TCP connection to the game server and bridge it to the tunnel.
async fn handle_connect(state: Arc<RelayState>, conn: ConnId, session_id: SessionId) -> Result<()> {
    let dst = SocketAddr::new(conn.dst_addr().into(), conn.dst_port);
    tracing::info!(%conn, %dst, "connecting to game server");

    let tcp_stream = match TcpStream::connect(dst).await {
        Ok(s) => {
            s.set_nodelay(true)?;
            tracing::info!(%conn, "connected to game server");
            send_to_client(&state, session_id, &TunnelMessage::Connected(conn)).await;
            s
        }
        Err(e) => {
            tracing::error!(%conn, "TCP connect failed: {e}");
            send_to_client(
                &state,
                session_id,
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

    // Register the connection (scoped per session)
    {
        let mut conns = state.conns.write().await;
        conns.insert((session_id, conn), TcpConn { tx: data_tx, shutdown_tx });
    }

    // Shared write counters so read task can log them on close
    let write_bytes = Arc::new(AtomicU64::new(0));
    let write_msgs = Arc::new(AtomicU64::new(0));

    // Task: tunnel → TCP (write to game server)
    let write_state = state.clone();
    let wb = write_bytes.clone();
    let wm = write_msgs.clone();
    let write_session_id = session_id;
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
        conns.remove(&(write_session_id, conn));
    });

    // Task: TCP read → tunnel (read from game server, send to user)
    let read_state = state.clone();
    let read_session_id = session_id;
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
                    send_to_client(&read_state, read_session_id, &TunnelMessage::Shutdown(conn)).await;
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
                    send_to_client(&read_state, read_session_id, &msg).await;
                }
                Err(e) => {
                    let bw = write_bytes.load(Ordering::Relaxed);
                    let wm = write_msgs.load(Ordering::Relaxed);
                    let lifetime = start.elapsed().as_secs();
                    tracing::warn!(%conn, bytes_read, read_msgs, bytes_written=bw, write_msgs=wm, lifetime, "TCP read error: {e}");
                    send_to_client(&read_state, read_session_id, &TunnelMessage::Reset(conn)).await;
                    break;
                }
            }
        }
        write_task.abort();
        let mut conns = read_state.conns.write().await;
        conns.remove(&(read_session_id, conn));
    });

    Ok(())
}

/// Encrypt and send a TunnelMessage to a specific client identified by session_id.
/// Prefers TCP transport when available (reliable), falls back to UDP.
async fn send_to_client(state: &RelayState, session_id: SessionId, msg: &TunnelMessage) {
    let (addr, key, tcp_tx) = {
        let clients = state.clients.read().await;
        match clients.get(&session_id) {
            Some(client) => (
                client.addr,
                Arc::clone(&client.key),
                client.tcp_tx.clone(),
            ),
            None => {
                tracing::warn!(session = hex_encode(session_id), "client session no longer exists");
                return;
            }
        }
    };

    let packet = match crypto::seal(&key, &session_id, msg) {
        Ok(p) => p,
        Err(e) => {
            tracing::error!("failed to encrypt message: {e}");
            return;
        }
    };

    // Prefer TCP (reliable, ordered) over UDP
    if let Some(tx) = tcp_tx {
        if tx.try_send(packet).is_err() {
            tracing::warn!(session = hex_encode(session_id), "TCP send channel full or closed");
        }
        return;
    }

    // Fall back to UDP
    if let Some(addr) = addr {
        if let Err(e) = state.socket.send_to(&packet, addr).await {
            tracing::warn!(%addr, "failed to send to client via UDP: {e}");
        }
    } else {
        tracing::warn!(session = hex_encode(session_id), "client has no address yet");
    }
}

fn hex_encode(bytes: impl AsRef<[u8]>) -> String {
    bytes
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
