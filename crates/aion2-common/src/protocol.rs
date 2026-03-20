use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

/// 8-byte random session identifier, generated per proxy instance.
/// Allows multiple clients sharing the same key to coexist on the same relay.
pub type SessionId = [u8; 8];

/// Unique identifier for a proxied TCP connection (src_ip:src_port → dst_ip:dst_port).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ConnId {
    pub src_ip: [u8; 4],
    pub src_port: u16,
    pub dst_ip: [u8; 4],
    pub dst_port: u16,
}

impl ConnId {
    pub fn new(src_ip: Ipv4Addr, src_port: u16, dst_ip: Ipv4Addr, dst_port: u16) -> Self {
        Self {
            src_ip: src_ip.octets(),
            src_port,
            dst_ip: dst_ip.octets(),
            dst_port,
        }
    }

    pub fn src_addr(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.src_ip)
    }

    pub fn dst_addr(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.dst_ip)
    }
}

impl std::fmt::Display for ConnId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{} → {}:{}",
            self.src_addr(),
            self.src_port,
            self.dst_addr(),
            self.dst_port
        )
    }
}

/// Messages sent over the UDP tunnel between proxy (client) and relay (server).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TunnelMessage {
    /// Client → Relay: Request to open a new TCP connection to the game server.
    Connect(ConnId),

    /// Relay → Client: TCP connection established successfully.
    Connected(ConnId),

    /// Relay → Client: TCP connection failed.
    ConnectFailed { conn: ConnId, reason: String },

    /// Bidirectional: Forward TCP payload data.
    Data { conn: ConnId, payload: Vec<u8> },

    /// Bidirectional: Signal that this side is done sending (TCP FIN equivalent).
    Shutdown(ConnId),

    /// Bidirectional: Force-close the connection (TCP RST equivalent).
    Reset(ConnId),

    /// Client → Relay: Keepalive / latency probe.
    Ping { seq: u64, timestamp_ms: u64 },

    /// Relay → Client: Keepalive response.
    Pong { seq: u64, client_timestamp_ms: u64 },
}

/// Maximum payload size per tunnel message to stay within typical MTU.
/// UDP payload = 1400 (MTU) - 20 (IP) - 8 (UDP) - 24 (nonce) - 16 (AEAD tag) - framing overhead.
/// Conservative: use 1280 bytes for data payloads.
pub const MAX_PAYLOAD_SIZE: usize = 1280;

/// Maximum size of an encrypted tunnel packet on the wire.
/// bincode framing + payload + nonce + AEAD tag.
pub const MAX_PACKET_SIZE: usize = 2048;

/// Encode a `TunnelMessage` to bytes using bincode.
pub fn encode_message(msg: &TunnelMessage) -> anyhow::Result<Vec<u8>> {
    Ok(bincode::serialize(msg)?)
}

/// Decode a `TunnelMessage` from bytes using bincode.
pub fn decode_message(data: &[u8]) -> anyhow::Result<TunnelMessage> {
    Ok(bincode::deserialize(data)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_connect() {
        let conn = ConnId::new(
            Ipv4Addr::new(192, 168, 1, 100),
            12345,
            Ipv4Addr::new(210, 242, 123, 135),
            13328,
        );
        let msg = TunnelMessage::Connect(conn);
        let encoded = encode_message(&msg).unwrap();
        let decoded = decode_message(&encoded).unwrap();
        match decoded {
            TunnelMessage::Connect(c) => assert_eq!(c, conn),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn roundtrip_data() {
        let conn = ConnId::new(
            Ipv4Addr::new(10, 0, 0, 1),
            5000,
            Ipv4Addr::new(210, 242, 186, 61),
            27500,
        );
        let payload = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let msg = TunnelMessage::Data {
            conn,
            payload: payload.clone(),
        };
        let encoded = encode_message(&msg).unwrap();
        let decoded = decode_message(&encoded).unwrap();
        match decoded {
            TunnelMessage::Data { conn: c, payload: p } => {
                assert_eq!(c, conn);
                assert_eq!(p, payload);
            }
            _ => panic!("wrong variant"),
        }
    }
}
