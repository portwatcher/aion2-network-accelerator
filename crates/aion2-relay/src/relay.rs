use aion2_common::crypto::{self, KeyId, TunnelKey};
use aion2_common::protocol::{ConnId, TunnelMessage, MAX_PACKET_SIZE};
use anyhow::Result;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{mpsc, RwLock};

/// State for a single proxied TCP connection.
struct TcpConn {
    /// Send data to the TCP write half.
    tx: mpsc::Sender<Vec<u8>>,
    /// Send shutdown signal.
    shutdown_tx: mpsc::Sender<()>,
    /// Which user owns this connection (for routing responses).
    key_id: KeyId,
}

/// Per-user state.
struct UserState {
    key: TunnelKey,
    name: String,
    /// The user's latest UDP address (learned from packets).
    addr: Option<SocketAddr>,
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
            new_users.insert(
                key.key_id,
                UserState {
                    key,
                    name,
                    addr: existing_addr,
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
    let socket = Arc::new(UdpSocket::bind(listen_addr).await?);
    tracing::info!("listening on {listen_addr}");

    let state = Arc::new(RelayState {
        socket,
        users: RwLock::new(HashMap::new()),
        conns: RwLock::new(HashMap::new()),
    });

    state.load_keys(keys).await;

    // Install SIGHUP handler for key reload
    let reload_state = state.clone();
    tokio::spawn(async move {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sighup = signal(SignalKind::hangup()).expect("failed to install SIGHUP handler");
        loop {
            sighup.recv().await;
            tracing::info!("SIGHUP received, reloading keys...");
            match load_keys_from_dir("/etc/aion2-relay/keys") {
                Ok(keys) => reload_state.load_keys(keys).await,
                Err(e) => tracing::error!("failed to reload keys: {e}"),
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

        // Look up user, decrypt
        let msg = {
            let mut users = state.users.write().await;
            let user = match users.get_mut(&key_id) {
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

            // Update user's address
            if user.addr != Some(peer) {
                tracing::info!(%peer, user = %user.name, "client connected");
                user.addr = Some(peer);
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
                if tcp.tx.send(payload).await.is_err() {
                    tracing::warn!(%conn, "TCP write channel closed");
                }
            } else {
                tracing::warn!(%conn, "data for unknown connection");
            }
        }

        TunnelMessage::Shutdown(conn) => {
            let conns = state.conns.read().await;
            if let Some(tcp) = conns.get(&conn) {
                let _ = tcp.shutdown_tx.send(()).await;
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
    let (data_tx, mut data_rx) = mpsc::channel::<Vec<u8>>(64);
    // Channel for shutdown signal
    let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);

    // Register the connection
    {
        let mut conns = state.conns.write().await;
        conns.insert(conn, TcpConn { tx: data_tx, shutdown_tx, key_id });
    }

    // Task: tunnel → TCP (write to game server)
    let write_state = state.clone();
    let write_task = tokio::spawn(async move {
        loop {
            tokio::select! {
                data = data_rx.recv() => {
                    match data {
                        Some(payload) => {
                            if let Err(e) = tcp_write.write_all(&payload).await {
                                tracing::warn!(%conn, "TCP write error: {e}");
                                break;
                            }
                        }
                        None => break, // channel closed
                    }
                }
                _ = shutdown_rx.recv() => {
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
        loop {
            match tcp_read.read(&mut buf).await {
                Ok(0) => {
                    tracing::info!(%conn, "game server closed connection");
                    send_to_user(&read_state, key_id, &TunnelMessage::Shutdown(conn)).await;
                    break;
                }
                Ok(n) => {
                    let msg = TunnelMessage::Data {
                        conn,
                        payload: buf[..n].to_vec(),
                    };
                    send_to_user(&read_state, key_id, &msg).await;
                }
                Err(e) => {
                    tracing::warn!(%conn, "TCP read error: {e}");
                    send_to_user(&read_state, key_id, &TunnelMessage::Reset(conn)).await;
                    break;
                }
            }
        }
        // Clean up: abort write task, remove connection
        write_task.abort();
        let mut conns = read_state.conns.write().await;
        conns.remove(&conn);
    });

    Ok(())
}

/// Encrypt and send a TunnelMessage to a specific user identified by key_id.
async fn send_to_user(state: &RelayState, key_id: KeyId, msg: &TunnelMessage) {
    let (addr, key) = {
        let users = state.users.read().await;
        match users.get(&key_id) {
            Some(user) => match user.addr {
                Some(a) => (a, user.key.clone()),
                None => {
                    tracing::warn!(key_id = hex_encode(key_id), "user has no address yet");
                    return;
                }
            },
            None => {
                tracing::warn!(key_id = hex_encode(key_id), "user no longer exists");
                return;
            }
        }
    };

    match crypto::seal(&key, msg) {
        Ok(packet) => {
            if let Err(e) = state.socket.send_to(&packet, addr).await {
                tracing::warn!(%addr, "failed to send to client: {e}");
            }
        }
        Err(e) => {
            tracing::error!("failed to encrypt message: {e}");
        }
    }
}

fn hex_encode(bytes: impl AsRef<[u8]>) -> String {
    bytes
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
