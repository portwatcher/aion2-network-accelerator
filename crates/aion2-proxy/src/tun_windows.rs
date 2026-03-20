/// Windows TUN adapter integration using wintun crate.
/// Captures raw IP packets, maintains a TCP NAT table,
/// and provides bidirectional packet flow through the encrypted UDP tunnel.

#[cfg(windows)]
use anyhow::Result;
#[cfg(windows)]
use std::collections::HashMap;
#[cfg(windows)]
use std::net::Ipv4Addr;
#[cfg(windows)]
use std::sync::Arc;
#[cfg(windows)]
use tokio::sync::mpsc;

#[cfg(windows)]
use aion2_common::protocol::ConnId;
#[cfg(windows)]
use crate::tunnel::{self, RelayEvent, TunnelState};

// ── TCP flags ────────────────────────────────────────────────────────────────
#[cfg(windows)]
const TCP_FIN: u8 = 0x01;
#[cfg(windows)]
const TCP_SYN: u8 = 0x02;
#[cfg(windows)]
const TCP_RST: u8 = 0x04;
#[cfg(windows)]
const TCP_PSH: u8 = 0x08;
#[cfg(windows)]
const TCP_ACK: u8 = 0x10;

// ── NAT table entry ─────────────────────────────────────────────────────────
#[cfg(windows)]
struct NatEntry {
    src_ip: Ipv4Addr,
    src_port: u16,
    dst_ip: Ipv4Addr,
    dst_port: u16,
    /// Client's initial sequence number (from SYN).
    _client_isn: u32,
    /// Our initial sequence number (in SYN-ACK).
    _our_isn: u32,
    /// Next expected sequence number from client.
    client_next_seq: u32,
    /// Our next sequence number when sending to client.
    our_next_seq: u32,
    state: NatState,
    /// Data buffered before the relay signals Connected.
    pending_data: Vec<Vec<u8>>,
    /// Whether the relay has confirmed the connection.
    tunnel_connected: bool,
}

#[cfg(windows)]
#[derive(PartialEq)]
enum NatState {
    SynReceived,
    Established,
    Closing,
}

#[cfg(windows)]
type NatTable = Arc<tokio::sync::Mutex<HashMap<ConnId, NatEntry>>>;

// ── Main entry point ─────────────────────────────────────────────────────────
#[cfg(windows)]
pub async fn run_tun(
    state: Arc<TunnelState>,
    mut relay_rx: mpsc::Receiver<RelayEvent>,
) -> Result<()> {
    use wintun::Adapter;

    let wintun = unsafe { wintun::load()? };
    let adapter = Adapter::create(&wintun, "Aion2Proxy", "Aion2 Tunnel", None)?;

    // Get the adapter's interface index so routes can target it explicitly.
    let if_index = get_adapter_index("Aion2Proxy")?;
    tracing::info!(if_index, "TUN adapter created");

    set_adapter_ip(&adapter, "10.200.0.2", "255.255.255.0")?;

    // Brief delay to let the interface become fully operational.
    std::thread::sleep(std::time::Duration::from_millis(500));

    let relay_ip = state.relay_addr.ip();
    add_default_routes(&relay_ip.to_string(), if_index)?;

    // Log the effective routing table for debugging.
    dump_routes();

    let session = Arc::new(adapter.start_session(0x400000)?); // 4 MB ring
    tracing::info!("wintun session started, waiting for packets");

    let nat_table: NatTable = Arc::new(tokio::sync::Mutex::new(HashMap::new()));

    // Channel: TUN read thread → main loop
    let (tun_read_tx, mut tun_read_rx) = mpsc::channel::<Vec<u8>>(512);

    // Thread: read raw packets from TUN adapter
    let read_session = session.clone();
    std::thread::spawn(move || {
        tracing::info!("TUN read thread started");
        let mut pkt_count: u64 = 0;
        loop {
            match read_session.receive_blocking() {
                Ok(packet) => {
                    pkt_count += 1;
                    let bytes = packet.bytes().to_vec();
                    if pkt_count <= 5 || pkt_count % 100 == 0 {
                        let proto = if bytes.len() >= 10 { bytes[9] } else { 0 };
                        tracing::info!(pkt_count, len = bytes.len(), proto, "TUN read");
                    }
                    if tun_read_tx.blocking_send(bytes).is_err() {
                        tracing::warn!("TUN read channel closed");
                        break;
                    }
                }
                Err(e) => {
                    tracing::error!("wintun read error: {e}");
                    break;
                }
            }
        }
    });

    // Main event loop: process TUN packets and relay events.
    // TUN writes go directly to the wintun session (no intermediate channel).
    loop {
        tokio::select! {
            Some(packet) = tun_read_rx.recv() => {
                handle_tun_packet(&state, &nat_table, &session, &packet).await;
            }
            Some(event) = relay_rx.recv() => {
                handle_relay_event(&state, &nat_table, &session, event).await;
            }
            else => break,
        }
    }

    Ok(())
}

// ── Write a packet directly to the wintun session (non-blocking ring buffer) ─
#[cfg(windows)]
#[inline]
fn tun_send(session: &Arc<wintun::Session>, data: &[u8]) {
    let session = Arc::clone(session);
    match session.allocate_send_packet(data.len() as u16) {
        Ok(mut pkt) => {
            pkt.bytes_mut().copy_from_slice(data);
            session.send_packet(pkt);
        }
        Err(e) => {
            tracing::warn!(len = data.len(), "wintun write alloc failed: {e}");
        }
    }
}

// ── Process a raw IP packet coming from the OS via TUN ───────────────────────
#[cfg(windows)]
async fn handle_tun_packet(
    state: &Arc<TunnelState>,
    nat_table: &NatTable,
    session: &Arc<wintun::Session>,
    ip_packet: &[u8],
) {
    // Must be IPv4 with at least a minimal header
    if ip_packet.len() < 20 || (ip_packet[0] >> 4) != 4 {
        return;
    }

    let ihl = ((ip_packet[0] & 0x0F) as usize) * 4;
    let protocol = ip_packet[9];
    let src_ip = Ipv4Addr::new(ip_packet[12], ip_packet[13], ip_packet[14], ip_packet[15]);
    let dst_ip = Ipv4Addr::new(ip_packet[16], ip_packet[17], ip_packet[18], ip_packet[19]);

    // Only handle TCP (protocol 6)
    if protocol != 6 || ip_packet.len() < ihl + 20 {
        return;
    }

    let tcp = &ip_packet[ihl..];
    let src_port = u16::from_be_bytes([tcp[0], tcp[1]]);
    let dst_port = u16::from_be_bytes([tcp[2], tcp[3]]);
    let seq = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);
    let _ack_num = u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]);
    let data_offset = ((tcp[12] >> 4) as usize) * 4;
    let flags = tcp[13];

    let syn = flags & TCP_SYN != 0;
    let fin = flags & TCP_FIN != 0;
    let rst = flags & TCP_RST != 0;
    let ack = flags & TCP_ACK != 0;

    let payload = if ip_packet.len() > ihl + data_offset {
        &ip_packet[ihl + data_offset..]
    } else {
        &[]
    };

    let conn = ConnId::new(src_ip, src_port, dst_ip, dst_port);

    if syn && !ack && !rst {
        // ── New TCP connection (SYN) ─────────────────────────────────────
        let our_isn: u32 = rand::random();

        let entry = NatEntry {
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            _client_isn: seq,
            _our_isn: our_isn,
            client_next_seq: seq.wrapping_add(1), // SYN consumes 1 seq
            our_next_seq: our_isn.wrapping_add(1), // SYN-ACK consumes 1 seq
            state: NatState::SynReceived,
            pending_data: Vec::new(),
            tunnel_connected: false,
        };
        nat_table.lock().await.insert(conn, entry);

        // Immediately send SYN-ACK back to the OS (optimistic)
        let syn_ack = build_tcp_packet(
            dst_ip, src_ip, dst_port, src_port,
            our_isn,
            seq.wrapping_add(1),
            TCP_SYN | TCP_ACK,
            65535,
            &[],
            true, // include MSS option
        );
        tun_send(session, &syn_ack);

        // Ask the relay to open a real TCP connection to the destination
        let _ = tunnel::open_connection(state, src_ip, src_port, dst_ip, dst_port).await;
        tracing::info!(%src_ip, %dst_ip, dst_port, "SYN → opened tunnel connection");
    } else if rst {
        // ── RST from client ──────────────────────────────────────────────
        let mut table = nat_table.lock().await;
        if table.remove(&conn).is_some() {
            drop(table);
            let _ = tunnel::send_reset(state, conn).await;
        }
    } else {
        // ── ACK / DATA / FIN for existing connection ─────────────────────
        // Collect all packets/actions while holding the lock, then execute after.
        let mut ack_pkt = None;
        let mut data_to_send = None;
        let mut fin_ack_pkt = None;
        let mut do_shutdown = false;

        {
            let mut table = nat_table.lock().await;
            if let Some(entry) = table.get_mut(&conn) {
                if ack && entry.state == NatState::SynReceived {
                    entry.state = NatState::Established;
                }

                if !payload.is_empty() {
                    entry.client_next_seq = seq.wrapping_add(payload.len() as u32);

                    ack_pkt = Some(build_tcp_packet(
                        entry.dst_ip, entry.src_ip, entry.dst_port, entry.src_port,
                        entry.our_next_seq,
                        entry.client_next_seq,
                        TCP_ACK,
                        65535,
                        &[],
                        false,
                    ));

                    if entry.tunnel_connected {
                        data_to_send = Some(payload.to_vec());
                    } else {
                        entry.pending_data.push(payload.to_vec());
                    }
                }

                if fin {
                    entry.client_next_seq = entry.client_next_seq.wrapping_add(1);
                    entry.state = NatState::Closing;

                    fin_ack_pkt = Some(build_tcp_packet(
                        entry.dst_ip, entry.src_ip, entry.dst_port, entry.src_port,
                        entry.our_next_seq,
                        entry.client_next_seq,
                        TCP_FIN | TCP_ACK,
                        65535,
                        &[],
                        false,
                    ));
                    entry.our_next_seq = entry.our_next_seq.wrapping_add(1);
                    do_shutdown = true;
                }
            }
        } // lock released

        if let Some(pkt) = ack_pkt {
            tun_send(session, &pkt);
        }
        if let Some(data) = data_to_send {
            let _ = tunnel::send_data(state, conn, data).await;
        }
        if let Some(pkt) = fin_ack_pkt {
            tun_send(session, &pkt);
        }
        if do_shutdown {
            let _ = tunnel::send_shutdown(state, conn).await;
        }
    }
}

// ── Process events coming back from the relay ────────────────────────────────
#[cfg(windows)]
async fn handle_relay_event(
    state: &Arc<TunnelState>,
    nat_table: &NatTable,
    session: &Arc<wintun::Session>,
    event: RelayEvent,
) {
    match event {
        RelayEvent::Connected(conn) => {
            let mut table = nat_table.lock().await;
            if let Some(entry) = table.get_mut(&conn) {
                entry.tunnel_connected = true;
                let pending: Vec<Vec<u8>> = std::mem::take(&mut entry.pending_data);
                drop(table);
                // Flush any data that arrived before relay connected
                for data in pending {
                    let _ = tunnel::send_data(state, conn, data).await;
                }
                tracing::debug!(%conn, "tunnel connected, flushed pending data");
            }
        }

        RelayEvent::ConnectFailed { conn, reason } => {
            let mut table = nat_table.lock().await;
            if let Some(entry) = table.remove(&conn) {
                let rst = build_tcp_packet(
                    entry.dst_ip, entry.src_ip, entry.dst_port, entry.src_port,
                    entry.our_next_seq,
                    entry.client_next_seq,
                    TCP_RST | TCP_ACK,
                    0,
                    &[],
                    false,
                );
                tun_send(session, &rst);
                tracing::warn!(%conn, %reason, "tunnel connect failed, sent RST");
            }
        }

        RelayEvent::Data { conn, payload } => {
            let mut table = nat_table.lock().await;
            if let Some(entry) = table.get_mut(&conn) {
                // Deliver data from the relay to the OS in MSS-sized segments
                for chunk in payload.chunks(1400) {
                    let data_pkt = build_tcp_packet(
                        entry.dst_ip, entry.src_ip, entry.dst_port, entry.src_port,
                        entry.our_next_seq,
                        entry.client_next_seq,
                        TCP_PSH | TCP_ACK,
                        65535,
                        chunk,
                        false,
                    );
                    entry.our_next_seq = entry.our_next_seq.wrapping_add(chunk.len() as u32);
                    tun_send(session, &data_pkt);
                }
            }
        }

        RelayEvent::Shutdown(conn) => {
            let mut table = nat_table.lock().await;
            if let Some(entry) = table.get_mut(&conn) {
                let fin = build_tcp_packet(
                    entry.dst_ip, entry.src_ip, entry.dst_port, entry.src_port,
                    entry.our_next_seq,
                    entry.client_next_seq,
                    TCP_FIN | TCP_ACK,
                    65535,
                    &[],
                    false,
                );
                entry.our_next_seq = entry.our_next_seq.wrapping_add(1);
                entry.state = NatState::Closing;
                tun_send(session, &fin);
                tracing::debug!(%conn, "relay shutdown, sent FIN to OS");
            }
        }

        RelayEvent::Reset(conn) => {
            let mut table = nat_table.lock().await;
            if let Some(entry) = table.remove(&conn) {
                let rst = build_tcp_packet(
                    entry.dst_ip, entry.src_ip, entry.dst_port, entry.src_port,
                    entry.our_next_seq,
                    entry.client_next_seq,
                    TCP_RST | TCP_ACK,
                    0,
                    &[],
                    false,
                );
                tun_send(session, &rst);
            }
        }
    }
}

// ── Raw TCP/IP packet construction ───────────────────────────────────────────

/// Build a complete IPv4+TCP packet.  When `include_mss` is true the SYN-ACK
/// carries an MSS option so the OS uses a reasonable segment size.
#[cfg(windows)]
fn build_tcp_packet(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    payload: &[u8],
    include_mss: bool,
) -> Vec<u8> {
    let ip_hdr_len = 20;
    let tcp_opts_len: usize = if include_mss { 4 } else { 0 };
    let tcp_hdr_len = 20 + tcp_opts_len;
    let total_len = ip_hdr_len + tcp_hdr_len + payload.len();

    let mut pkt = vec![0u8; total_len];

    // ── IPv4 header ──────────────────────────────────────────────────────
    pkt[0] = 0x45; // version 4, IHL 5
    pkt[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    pkt[6] = 0x40; // Don't Fragment
    pkt[8] = 64;   // TTL
    pkt[9] = 6;    // Protocol: TCP
    pkt[12..16].copy_from_slice(&src_ip.octets());
    pkt[16..20].copy_from_slice(&dst_ip.octets());
    let ip_cksum = compute_checksum(&pkt[..ip_hdr_len]);
    pkt[10..12].copy_from_slice(&ip_cksum.to_be_bytes());

    // ── TCP header ───────────────────────────────────────────────────────
    let t = ip_hdr_len;
    pkt[t..t + 2].copy_from_slice(&src_port.to_be_bytes());
    pkt[t + 2..t + 4].copy_from_slice(&dst_port.to_be_bytes());
    pkt[t + 4..t + 8].copy_from_slice(&seq.to_be_bytes());
    pkt[t + 8..t + 12].copy_from_slice(&ack.to_be_bytes());
    pkt[t + 12] = ((tcp_hdr_len / 4) as u8) << 4; // data offset
    pkt[t + 13] = flags;
    pkt[t + 14..t + 16].copy_from_slice(&window.to_be_bytes());

    if include_mss {
        // MSS option: Kind=2, Length=4, Value=1460
        pkt[t + 20] = 2;
        pkt[t + 21] = 4;
        pkt[t + 22..t + 24].copy_from_slice(&1460u16.to_be_bytes());
    }

    // ── Payload ──────────────────────────────────────────────────────────
    if !payload.is_empty() {
        pkt[t + tcp_hdr_len..].copy_from_slice(payload);
    }

    // ── TCP checksum (includes pseudo-header) ────────────────────────────
    let tcp_cksum = compute_tcp_checksum(src_ip, dst_ip, &pkt[t..]);
    pkt[t + 16..t + 18].copy_from_slice(&tcp_cksum.to_be_bytes());

    pkt
}

/// Internet checksum (RFC 1071) over a byte slice.
#[cfg(windows)]
fn compute_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for i in (0..data.len()).step_by(2) {
        let word = if i + 1 < data.len() {
            ((data[i] as u32) << 8) | (data[i + 1] as u32)
        } else {
            (data[i] as u32) << 8
        };
        sum += word;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !sum as u16
}

/// TCP checksum including the IPv4 pseudo-header.
#[cfg(windows)]
fn compute_tcp_checksum(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, tcp_segment: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let s = src_ip.octets();
    let d = dst_ip.octets();
    sum += ((s[0] as u32) << 8) | (s[1] as u32);
    sum += ((s[2] as u32) << 8) | (s[3] as u32);
    sum += ((d[0] as u32) << 8) | (d[1] as u32);
    sum += ((d[2] as u32) << 8) | (d[3] as u32);
    sum += 6; // protocol TCP
    sum += tcp_segment.len() as u32;
    for i in (0..tcp_segment.len()).step_by(2) {
        let word = if i + 1 < tcp_segment.len() {
            ((tcp_segment[i] as u32) << 8) | (tcp_segment[i + 1] as u32)
        } else {
            (tcp_segment[i] as u32) << 8
        };
        sum += word;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !sum as u16
}

// ── Adapter / route helpers ──────────────────────────────────────────────────

/// Set the IP address on the wintun adapter using netsh.
#[cfg(windows)]
fn set_adapter_ip(_adapter: &wintun::Adapter, ip: &str, mask: &str) -> Result<()> {
    let output = std::process::Command::new("netsh")
        .args([
            "interface", "ip", "set", "address",
            "name=Aion2Proxy",
            "source=static",
            &format!("addr={ip}"),
            &format!("mask={mask}"),
        ])
        .output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        tracing::warn!("netsh set address: {stderr}");
    }
    Ok(())
}

/// Add routes so all public traffic goes through TUN, while keeping
/// private-network / relay traffic on the original gateway.
#[cfg(windows)]
fn add_default_routes(relay_ip: &str, if_index: u32) -> Result<()> {
    let gw = get_default_gateway()?;
    tracing::info!("original default gateway: {gw}");

    let if_str = if_index.to_string();

    // Relay IP via original gateway (avoid routing loop)
    run_route(&["add", relay_ip, "mask", "255.255.255.255", &gw, "metric", "5"]);

    // Private networks via original gateway (keeps LAN + DNS working)
    run_route(&["add", "10.0.0.0", "mask", "255.0.0.0", &gw, "metric", "5"]);
    run_route(&["add", "172.16.0.0", "mask", "255.240.0.0", &gw, "metric", "5"]);
    run_route(&["add", "192.168.0.0", "mask", "255.255.0.0", &gw, "metric", "5"]);

    // Two /1 routes override the existing 0.0.0.0/0 without replacing it.
    // Explicit IF ensures routes bind to the TUN adapter.
    run_route(&["add", "0.0.0.0", "mask", "128.0.0.0", "10.200.0.1", "metric", "5", "IF", &if_str]);
    run_route(&["add", "128.0.0.0", "mask", "128.0.0.0", "10.200.0.1", "metric", "5", "IF", &if_str]);

    tracing::info!("default routes installed");
    Ok(())
}

#[cfg(windows)]
fn run_route(args: &[&str]) {
    match std::process::Command::new("route").args(args).output() {
        Ok(output) if !output.status.success() => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            tracing::warn!("route {}: {stderr}", args.join(" "));
        }
        Err(e) => tracing::warn!("route {}: {e}", args.join(" ")),
        _ => {}
    }
}

/// Parse the current default gateway from `route print`.
#[cfg(windows)]
fn get_default_gateway() -> Result<String> {
    let output = std::process::Command::new("route")
        .args(["print", "0.0.0.0"])
        .output()?;
    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 5 && parts[0] == "0.0.0.0" && parts[1] == "0.0.0.0" {
            return Ok(parts[2].to_string());
        }
    }
    anyhow::bail!("could not determine default gateway from routing table")
}

/// Get the interface index of a named network adapter via `netsh`.
#[cfg(windows)]
fn get_adapter_index(name: &str) -> Result<u32> {
    let output = std::process::Command::new("netsh")
        .args(["interface", "ipv4", "show", "interfaces"])
        .output()?;
    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        if line.contains(name) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if let Some(idx_str) = parts.first() {
                if let Ok(idx) = idx_str.parse::<u32>() {
                    return Ok(idx);
                }
            }
        }
    }
    anyhow::bail!("could not find interface index for adapter '{name}'")
}

/// Log the current routing table (filtered to show our routes).
#[cfg(windows)]
fn dump_routes() {
    match std::process::Command::new("route").args(["print", "-4"]).output() {
        Ok(output) => {
            let text = String::from_utf8_lossy(&output.stdout);
            let mut relevant = Vec::new();
            for line in text.lines() {
                let trimmed = line.trim();
                // Show entries that mention our TUN gateway or key destinations
                if trimmed.contains("10.200.0.") || trimmed.contains("0.0.0.0") || trimmed.contains("128.0.0.0") {
                    if !trimmed.is_empty() && !trimmed.starts_with("===") {
                        relevant.push(trimmed.to_string());
                    }
                }
            }
            for line in &relevant {
                tracing::info!("route: {line}");
            }
        }
        Err(e) => tracing::warn!("failed to dump routes: {e}"),
    }
}
