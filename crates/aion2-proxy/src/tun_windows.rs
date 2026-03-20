/// Windows TUN adapter integration using wintun crate.
/// Captures raw IP packets for game server IPs, extracts TCP streams
/// via smoltcp, and forwards them through the encrypted UDP tunnel.

#[cfg(windows)]
use anyhow::Result;
#[cfg(windows)]
use std::sync::Arc;

#[cfg(windows)]
use crate::tunnel::{self, is_game_ip, TunnelState};

#[cfg(windows)]
pub async fn run_tun(state: Arc<TunnelState>) -> Result<()> {
    use std::net::Ipv4Addr;
    use wintun::Adapter;

    // Load wintun.dll (must be in the same directory or PATH)
    let wintun = unsafe { wintun::load()? };

    // Create or open the TUN adapter
    let adapter = Adapter::create(&wintun, "Aion2Proxy", "Aion2 Tunnel", None)?;

    // Set adapter IP address
    // This requires netsh or WinAPI calls
    set_adapter_ip(&adapter, "10.200.0.2", "255.255.255.0")?;

    // Add routes for game IPs
    add_game_routes()?;

    // Start a session with ring capacity
    let session = Arc::new(adapter.start_session(0x20000)?); // 128KB ring

    tracing::info!("wintun adapter created, capturing game traffic");

    // Read packets from TUN
    let read_session = session.clone();
    let read_state = state.clone();
    let read_handle = tokio::task::spawn_blocking(move || {
        loop {
            match read_session.receive_blocking() {
                Ok(packet) => {
                    let bytes = packet.bytes().to_vec();
                    // Parse IPv4 header to check destination
                    if bytes.len() >= 20 && (bytes[0] >> 4) == 4 {
                        let dst_ip = Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19]);
                        if is_game_ip(dst_ip) {
                            // Process this packet through smoltcp / tunnel
                            let state = read_state.clone();
                            tokio::runtime::Handle::current().spawn(async move {
                                handle_tun_packet(&state, &bytes).await;
                            });
                        }
                    }
                }
                Err(e) => {
                    tracing::error!("wintun read error: {e}");
                    break;
                }
            }
        }
    });

    read_handle.await?;
    Ok(())
}

/// Handle a raw IP packet captured from the TUN adapter.
/// Extract TCP connection info and forward data through the tunnel.
#[cfg(windows)]
async fn handle_tun_packet(state: &Arc<TunnelState>, ip_packet: &[u8]) {
    use aion2_common::protocol::TunnelMessage;
    use std::net::Ipv4Addr;

    if ip_packet.len() < 20 {
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
    let flags = tcp[13];
    let syn = flags & 0x02 != 0;
    let fin = flags & 0x01 != 0;
    let rst = flags & 0x04 != 0;
    let data_offset = ((tcp[12] >> 4) as usize) * 4;
    let payload = &tcp[data_offset..];

    let conn = aion2_common::protocol::ConnId::new(src_ip, src_port, dst_ip, dst_port);

    if syn && !rst {
        // New connection: send Connect to relay
        tracing::info!(%conn, "TUN: SYN captured, initiating tunnel connection");
        let _ = tunnel::open_connection(state, src_ip, src_port, dst_ip, dst_port).await;
    } else if rst {
        // Reset
        let msg = TunnelMessage::Reset(conn);
        let _ = aion2_common::crypto::seal(&state.key, &msg);
    } else if fin {
        // Shutdown
        let msg = TunnelMessage::Shutdown(conn);
        let _ = aion2_common::crypto::seal(&state.key, &msg);
    } else if !payload.is_empty() {
        // Data
        let _ = tunnel::send_data(state, conn, payload.to_vec()).await;
    }
}

/// Set the IP address on the wintun adapter using netsh.
#[cfg(windows)]
fn set_adapter_ip(
    _adapter: &wintun::Adapter,
    ip: &str,
    mask: &str,
) -> Result<()> {
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

/// Add routes for game server IP ranges through the TUN adapter.
#[cfg(windows)]
fn add_game_routes() -> Result<()> {
    let routes = [
        ("210.242.0.0", "255.255.0.0"),     // HiNet game servers
        ("216.107.244.0", "255.255.255.0"),  // NCSOFT auth
        ("216.107.253.0", "255.255.255.0"),  // NCSOFT auth
    ];

    for (network, mask) in &routes {
        let output = std::process::Command::new("route")
            .args(["add", network, "mask", mask, "10.200.0.1", "metric", "5"])
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            tracing::warn!("route add {network}: {stderr}");
        } else {
            tracing::info!("added route: {network}/{mask} via TUN");
        }
    }
    Ok(())
}
