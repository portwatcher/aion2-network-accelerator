mod relay;

use anyhow::Result;
use std::net::SocketAddr;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let keys_dir = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/etc/aion2-relay/keys".to_string());

    let keys = relay::load_keys_from_dir(&keys_dir)?;
    tracing::info!(users = keys.len(), "loaded {} user key(s)", keys.len());

    let listen_addr: SocketAddr = std::env::var("LISTEN_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:443".into())
        .parse()?;

    tracing::info!(%listen_addr, "starting aion2-relay");

    relay::run(listen_addr, keys).await
}

pub fn hex_decode(hex: &str) -> Result<[u8; 32]> {
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
