use anyhow::{anyhow, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use rand::RngCore;

/// 4-byte key identifier prepended (unencrypted) to every wire packet.
/// Derived from truncated SHA-256 of the raw key bytes.
/// Allows O(1) key lookup on the relay without trying all keys.
pub type KeyId = [u8; 4];

/// Size of the key ID prefix on the wire.
pub const KEY_ID_SIZE: usize = 4;

/// Shared symmetric key for the tunnel (256-bit).
/// Exchanged out-of-band (e.g., over SSH during relay setup).
#[derive(Clone)]
pub struct TunnelKey {
    cipher: XChaCha20Poly1305,
    /// First 4 bytes of SHA-256(raw_key). Identifies this key on the wire.
    pub key_id: KeyId,
}

/// Size of the XChaCha20-Poly1305 nonce (24 bytes).
pub const NONCE_SIZE: usize = 24;

/// Size of the AEAD authentication tag (16 bytes).
pub const TAG_SIZE: usize = 16;

/// Compute key_id: first 4 bytes of a simple hash of the key material.
/// We use a basic round of repeated XOR-mixing to avoid pulling in SHA-2 crate
/// just for a non-security-critical identifier. Collisions are harmless
/// (relay falls back to trying the key and failing AEAD).
fn compute_key_id(key: &[u8; 32]) -> KeyId {
    // Simple: fold the 32 bytes into 4 using XOR + rotation
    let mut id = [0u8; 4];
    for (i, &b) in key.iter().enumerate() {
        id[i % 4] ^= b;
    }
    // Mix further to reduce trivial collisions
    let mixed = u32::from_le_bytes(id).wrapping_mul(0x9E3779B9);
    mixed.to_le_bytes()
}

impl TunnelKey {
    /// Create a `TunnelKey` from a 32-byte secret.
    pub fn from_bytes(key: &[u8; 32]) -> Self {
        Self {
            cipher: XChaCha20Poly1305::new(key.into()),
            key_id: compute_key_id(key),
        }
    }

    /// Generate a random tunnel key.
    pub fn generate() -> ([u8; 32], Self) {
        let mut key_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key_bytes);
        let key = Self::from_bytes(&key_bytes);
        (key_bytes, key)
    }

    /// Encrypt plaintext directly into a caller-provided buffer.
    /// Appends `nonce || ciphertext || tag` to `out`.
    pub fn encrypt_into(&self, plaintext: &[u8], out: &mut Vec<u8>) -> Result<()> {
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = XNonce::from_slice(&nonce_bytes);

        let ciphertext = self
            .cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| anyhow!("encryption failed: {e}"))?;

        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        Ok(())
    }

    /// Encrypt plaintext. Returns `nonce || ciphertext || tag`.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(NONCE_SIZE + plaintext.len() + TAG_SIZE);
        self.encrypt_into(plaintext, &mut out)?;
        Ok(out)
    }

    /// Decrypt a packet produced by `encrypt`. Input is `nonce || ciphertext || tag`.
    pub fn decrypt(&self, packet: &[u8]) -> Result<Vec<u8>> {
        if packet.len() < NONCE_SIZE + TAG_SIZE {
            return Err(anyhow!(
                "packet too short: {} bytes (need at least {})",
                packet.len(),
                NONCE_SIZE + TAG_SIZE
            ));
        }

        let (nonce_bytes, ciphertext) = packet.split_at(NONCE_SIZE);
        let nonce = XNonce::from_slice(nonce_bytes);

        self.cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| anyhow!("decryption failed: {e}"))
    }
}

/// Encrypt a tunnel message and prepend the key_id.
/// Wire format: `key_id (4B) || nonce (24B) || ciphertext || tag (16B)`
pub fn seal(key: &TunnelKey, msg: &crate::protocol::TunnelMessage) -> Result<Vec<u8>> {
    let plaintext = crate::protocol::encode_message(msg)?;
    // Single allocation: key_id + nonce + ciphertext + tag
    let mut packet = Vec::with_capacity(KEY_ID_SIZE + NONCE_SIZE + plaintext.len() + TAG_SIZE);
    packet.extend_from_slice(&key.key_id);
    key.encrypt_into(&plaintext, &mut packet)?;
    Ok(packet)
}

/// Extract the key_id from a wire packet without decrypting.
pub fn peek_key_id(packet: &[u8]) -> Result<KeyId> {
    if packet.len() < KEY_ID_SIZE + NONCE_SIZE + TAG_SIZE {
        return Err(anyhow!("packet too short for key_id extraction"));
    }
    let mut id = [0u8; 4];
    id.copy_from_slice(&packet[..KEY_ID_SIZE]);
    Ok(id)
}

/// Decrypt a wire packet (strip key_id prefix, then decrypt + deserialize).
pub fn open(key: &TunnelKey, packet: &[u8]) -> Result<crate::protocol::TunnelMessage> {
    if packet.len() < KEY_ID_SIZE + NONCE_SIZE + TAG_SIZE {
        return Err(anyhow!("packet too short"));
    }
    let plaintext = key.decrypt(&packet[KEY_ID_SIZE..])?;
    crate::protocol::decode_message(&plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{ConnId, TunnelMessage};
    use std::net::Ipv4Addr;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let (_, key) = TunnelKey::generate();
        let plaintext = b"hello game server";
        let encrypted = key.encrypt(plaintext).unwrap();
        let decrypted = key.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn seal_open_roundtrip() {
        let (_, key) = TunnelKey::generate();
        let conn = ConnId::new(
            Ipv4Addr::new(10, 0, 0, 1),
            5000,
            Ipv4Addr::new(210, 242, 123, 135),
            13328,
        );
        let msg = TunnelMessage::Data {
            conn,
            payload: vec![1, 2, 3, 4, 5],
        };
        let packet = seal(&key, &msg).unwrap();
        let decoded = open(&key, &packet).unwrap();
        match decoded {
            TunnelMessage::Data { conn: c, payload } => {
                assert_eq!(c, conn);
                assert_eq!(payload, vec![1, 2, 3, 4, 5]);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn tampered_packet_fails() {
        let (_, key) = TunnelKey::generate();
        let mut packet = key.encrypt(b"secret data").unwrap();
        // Flip a byte in the ciphertext
        let last = packet.len() - 1;
        packet[last] ^= 0xFF;
        assert!(key.decrypt(&packet).is_err());
    }

    #[test]
    fn wrong_key_fails() {
        let (_, key1) = TunnelKey::generate();
        let (_, key2) = TunnelKey::generate();
        let packet = key1.encrypt(b"secret").unwrap();
        assert!(key2.decrypt(&packet).is_err());
    }
}
