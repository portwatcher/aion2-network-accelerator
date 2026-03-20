/// Stub TUN module for non-Windows platforms (development/testing only).
/// The real TUN integration uses wintun on Windows.

pub async fn run_tun(
    _state: std::sync::Arc<super::tunnel::TunnelState>,
) -> anyhow::Result<()> {
    anyhow::bail!("TUN adapter is only supported on Windows. Use AION2_TEST_DST for testing.")
}
