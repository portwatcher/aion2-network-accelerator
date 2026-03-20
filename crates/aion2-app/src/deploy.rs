use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use ssh2::Session;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use tauri::{AppHandle, Emitter, Manager};

#[derive(Debug, Deserialize)]
pub struct DeployConfig {
    pub host: String,
    pub port: Option<u16>,
    pub user: String,
    pub password: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DeployResult {
    pub key_hex: String,
    pub relay_addr: String,
}

const SYSTEMD_SERVICE: &str = "[Unit]
Description=Aion2 Relay Daemon
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/aion2-relay /etc/aion2-relay/keys
Environment=LISTEN_ADDR=0.0.0.0:443
Environment=RUST_LOG=info
Restart=always
RestartSec=3
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadOnlyPaths=/
ReadWritePaths=/var/log
PrivateTmp=true

[Install]
WantedBy=multi-user.target
";

fn emit_progress(app: &AppHandle, msg: impl Into<String>) {
    let msg = msg.into();
    tracing::info!("[deploy] {}", msg);
    let _ = app.emit("deploy-progress", &msg);
}

fn find_relay_binary(app: &AppHandle) -> Result<Vec<u8>, String> {
    // Prefer cross-compiled Linux musl binary (dev workspace)
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent());

    if let Some(ws) = workspace {
        let musl_path = ws.join("target/x86_64-unknown-linux-musl/release/aion2-relay");
        if let Ok(data) = std::fs::read(&musl_path) {
            return Ok(data);
        }
    }

    // Fallback: bundled resource (distributed app — CI builds the correct Linux binary)
    if let Ok(resource_dir) = app.path().resource_dir() {
        let bundled = resource_dir.join("binaries/aion2-relay");
        if let Ok(data) = std::fs::read(&bundled) {
            return Ok(data);
        }
    }

    let hint = workspace
        .map(|ws| ws.join("target/x86_64-unknown-linux-musl/release/aion2-relay").display().to_string())
        .unwrap_or_else(|| "<workspace>/target/x86_64-unknown-linux-musl/release/aion2-relay".into());

    Err(format!(
        "Linux relay binary not found.\nRun: cargo zigbuild --release --target x86_64-unknown-linux-musl -p aion2-relay\nExpected at: {hint}"
    ))
}

fn ssh_connect(host: &str, port: u16, user: &str, password: &str) -> Result<Session, String> {
    let tcp = TcpStream::connect(format!("{host}:{port}"))
        .map_err(|e| format!("TCP connect to {host}:{port} failed: {e}"))?;
    tcp.set_read_timeout(Some(std::time::Duration::from_secs(30)))
        .ok();

    let mut session = Session::new().map_err(|e| format!("SSH session init failed: {e}"))?;
    session.set_tcp_stream(tcp);
    session.set_timeout(30_000);
    session
        .handshake()
        .map_err(|e| format!("SSH handshake failed: {e}"))?;
    session
        .userauth_password(user, password)
        .map_err(|e| format!("SSH auth failed: {e}"))?;

    if !session.authenticated() {
        return Err("Authentication failed: invalid credentials".into());
    }

    Ok(session)
}

fn ssh_exec(session: &Session, cmd: &str) -> Result<(i32, String, String), String> {
    let mut channel = session
        .channel_session()
        .map_err(|e| format!("Channel open failed: {e}"))?;
    channel
        .exec(cmd)
        .map_err(|e| format!("Exec failed: {e}"))?;

    let mut stdout = String::new();
    channel
        .read_to_string(&mut stdout)
        .map_err(|e| format!("Read stdout failed: {e}"))?;

    let mut stderr = String::new();
    channel
        .stderr()
        .read_to_string(&mut stderr)
        .map_err(|e| format!("Read stderr failed: {e}"))?;

    channel
        .wait_close()
        .map_err(|e| format!("Channel close failed: {e}"))?;

    let exit = channel
        .exit_status()
        .map_err(|e| format!("Exit status failed: {e}"))?;

    Ok((exit, stdout.trim().to_string(), stderr.trim().to_string()))
}

fn scp_upload(session: &Session, data: &[u8], remote_path: &str, mode: i32) -> Result<(), String> {
    let mut remote_file = session
        .scp_send(Path::new(remote_path), mode, data.len() as u64, None)
        .map_err(|e| format!("SCP init for {remote_path} failed: {e}"))?;

    remote_file
        .write_all(data)
        .map_err(|e| format!("SCP write to {remote_path} failed: {e}"))?;
    remote_file
        .send_eof()
        .map_err(|e| format!("SCP EOF failed: {e}"))?;
    remote_file
        .wait_eof()
        .map_err(|e| format!("SCP wait EOF failed: {e}"))?;
    remote_file
        .close()
        .map_err(|e| format!("SCP close failed: {e}"))?;
    remote_file
        .wait_close()
        .map_err(|e| format!("SCP wait close failed: {e}"))?;

    Ok(())
}

fn generate_key_hex() -> String {
    let mut rng = rand::thread_rng();
    let mut key = [0u8; 32];
    rng.fill(&mut key);
    key.iter().map(|b| format!("{b:02x}")).collect()
}

fn sha256_hex(data: &[u8]) -> String {
    let hash = Sha256::digest(data);
    hash.iter().map(|b| format!("{b:02x}")).collect()
}

fn remote_sha256(session: &Session, path: &str) -> Option<String> {
    let (exit, stdout, _) =
        ssh_exec(session, &format!("sha256sum {path} 2>/dev/null | cut -d' ' -f1")).ok()?;
    if exit == 0 && stdout.len() == 64 && stdout.chars().all(|c| c.is_ascii_hexdigit()) {
        Some(stdout)
    } else {
        None
    }
}

fn deploy_relay_impl(app: &AppHandle, config: DeployConfig) -> Result<DeployResult, String> {
    let port = config.port.unwrap_or(22);

    // 1. Read the pre-compiled musl binary
    emit_progress(app, "Reading relay binary...");
    let binary = find_relay_binary(app)?;
    emit_progress(app, format!("Binary loaded ({} bytes)", binary.len()));

    // 2. Connect via SSH
    emit_progress(app, format!("Connecting to {}:{}...", config.host, port));
    let session = ssh_connect(&config.host, port, &config.user, &config.password)?;
    emit_progress(app, "SSH connected");

    let mut needs_restart = false;

    // 3. Check binary hash — upload only if changed
    emit_progress(app, "Checking relay binary...");
    let local_hash = sha256_hex(&binary);
    let remote_hash = remote_sha256(&session, "/usr/local/bin/aion2-relay");

    if remote_hash.as_deref() == Some(local_hash.as_str()) {
        emit_progress(app, "Binary unchanged, skipping upload");
    } else {
        // Stop service before overwriting the running binary
        emit_progress(app, "Stopping existing service...");
        let _ = ssh_exec(&session, "systemctl stop aion2-relay 2>/dev/null || true");
        emit_progress(app, "Uploading relay binary...");
        scp_upload(&session, &binary, "/usr/local/bin/aion2-relay", 0o755)?;
        emit_progress(app, "Binary uploaded");
        needs_restart = true;
    }

    // 4. Create keys directory
    emit_progress(app, "Setting up directories...");
    ssh_exec(
        &session,
        "mkdir -p /etc/aion2-relay/keys && chmod 700 /etc/aion2-relay/keys",
    )?;

    // 5. Check if a key already exists; if so, reuse it
    let (exit, existing_key, _) = ssh_exec(
        &session,
        "cat /etc/aion2-relay/keys/app.key 2>/dev/null || echo ''",
    )?;

    let key_hex = if exit == 0 && existing_key.len() == 64 && existing_key.chars().all(|c| c.is_ascii_hexdigit()) {
        emit_progress(app, "Reusing existing key");
        existing_key
    } else {
        emit_progress(app, "Generating tunnel key...");
        let new_key = generate_key_hex();
        scp_upload(
            &session,
            new_key.as_bytes(),
            "/etc/aion2-relay/keys/app.key",
            0o600,
        )?;
        emit_progress(app, "Key uploaded");
        needs_restart = true;
        new_key
    };

    // 6. Check service file hash — upload only if changed
    emit_progress(app, "Checking systemd service...");
    let local_svc_hash = sha256_hex(SYSTEMD_SERVICE.as_bytes());
    let remote_svc_hash = remote_sha256(&session, "/etc/systemd/system/aion2-relay.service");

    if remote_svc_hash.as_deref() == Some(local_svc_hash.as_str()) {
        emit_progress(app, "Service file unchanged, skipping");
    } else {
        emit_progress(app, "Installing systemd service...");
        scp_upload(
            &session,
            SYSTEMD_SERVICE.as_bytes(),
            "/etc/systemd/system/aion2-relay.service",
            0o644,
        )?;
        ssh_exec(&session, "systemctl daemon-reload")?;
        needs_restart = true;
    }

    // 7. Open firewall (UDP + TCP)
    emit_progress(app, "Configuring firewall...");
    let _ = ssh_exec(
        &session,
        "command -v ufw >/dev/null 2>&1 && ufw allow 443/udp 2>/dev/null && ufw allow 443/tcp 2>/dev/null; \
         iptables -C INPUT -p udp --dport 443 -j ACCEPT 2>/dev/null || \
         iptables -A INPUT -p udp --dport 443 -j ACCEPT 2>/dev/null; \
         iptables -C INPUT -p tcp --dport 443 -j ACCEPT 2>/dev/null || \
         iptables -A INPUT -p tcp --dport 443 -j ACCEPT 2>/dev/null; true",
    );

    // 8. Enable and (re)start service only if something changed
    ssh_exec(&session, "systemctl enable aion2-relay 2>/dev/null || true")?;
    if needs_restart {
        emit_progress(app, "Restarting relay service (config changed)...");
        ssh_exec(&session, "systemctl restart aion2-relay")?;
    } else {
        // Ensure it's running even if nothing changed
        emit_progress(app, "Ensuring service is running...");
        ssh_exec(&session, "systemctl start aion2-relay 2>/dev/null || true")?;
    }

    // Give it a moment to start
    std::thread::sleep(std::time::Duration::from_secs(1));

    // 9. Verify service is running
    let (exit, stdout, _) = ssh_exec(&session, "systemctl is-active aion2-relay")?;
    if exit != 0 || stdout != "active" {
        let (_, journal, _) = ssh_exec(
            &session,
            "journalctl -u aion2-relay -n 10 --no-pager 2>/dev/null || true",
        )?;
        return Err(format!(
            "Service not active (status: {stdout}). Journal:\n{journal}"
        ));
    }

    let relay_addr = format!("{}:443", config.host);
    emit_progress(
        app,
        format!("Relay deployed successfully at {relay_addr}"),
    );

    Ok(DeployResult {
        key_hex,
        relay_addr,
    })
}

#[tauri::command]
pub async fn deploy_relay(
    app: AppHandle,
    config: DeployConfig,
) -> Result<DeployResult, String> {
    tokio::task::spawn_blocking(move || deploy_relay_impl(&app, config))
        .await
        .map_err(|e| format!("Deploy task failed: {e}"))?
}
