mod tunnel;

#[cfg(windows)]
mod tun_windows;
#[cfg(not(windows))]
mod tun_stub;

use anyhow::Result;
use clap::Parser;
use std::net::SocketAddr;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "aion2-proxy", about = "Aion2 game traffic proxy client")]
struct Args {
    /// Relay server address (UDP)
    #[arg(short, long, default_value = "130.94.37.247:443")]
    relay: SocketAddr,

    /// Path to shared key file (64 hex characters)
    #[arg(short, long, default_value = "key.txt")]
    key: String,

    /// TUN adapter IP (used on Windows for the virtual interface)
    #[arg(long, default_value = "10.200.0.2")]
    tun_ip: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();

    let key_hex = std::fs::read_to_string(&args.key)
        .map_err(|e| anyhow::anyhow!("failed to read key file {}: {e}", args.key))?;
    let key_hex = key_hex.trim();
    let key_bytes = hex_decode(key_hex)?;
    let tunnel_key = aion2_common::crypto::TunnelKey::from_bytes(&key_bytes);

    tracing::info!(relay = %args.relay, "starting aion2-proxy");

    tunnel::run(args.relay, tunnel_key).await
}

fn hex_decode(hex: &str) -> Result<[u8; 32]> {
    if hex.len() != 64 {
        anyhow::bail!("key must be 64 hex characters (32 bytes), got {}", hex.len());
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .map_err(|e| anyhow::anyhow!("invalid hex at position {}: {e}", i * 2))?;
    }
    Ok(out)
}
