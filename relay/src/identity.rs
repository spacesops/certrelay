//! Relay signing identity.
//!
//! Each relay holds a long-lived secp256k1 keypair used to sign the anchor
//! root it serves (see [`RelayIdentity::sign_anchor`]). Clients that pin a
//! relay's public key can then verify the `X-Anchor-Sig` header end-to-end,
//! even when TLS terminates at a proxy in front of the origin.
//!
//! The secret key lives at `data_dir/identity_key`. It is generated on first
//! boot if absent ("first load" == the file does not exist yet), so a relay
//! that simply upgrades self-keys with no operator action and keeps a stable
//! public key across restarts.

use std::path::Path;

use rand::RngCore;
use secp256k1::{Keypair, Secp256k1, XOnlyPublicKey};

/// Domain tag mixed into the anchor-root signature. Bump the version suffix if
/// the signed-message layout ever changes, so old and new signatures can never
/// be confused across a format change.
const ANCHOR_SIG_TAG: &[u8] = b"certrelay-anchor-sig-v1";

/// A relay's persisted signing identity.
pub struct RelayIdentity {
    keypair: Keypair,
    pubkey: XOnlyPublicKey,
}

impl RelayIdentity {
    /// Load the identity from `path`, generating and persisting a fresh key if
    /// the file does not exist. Any other read error (permissions, malformed
    /// contents) is surfaced rather than silently regenerating, so a corrupt
    /// or unreadable key never rotates the relay's identity by accident.
    pub fn load_or_create(path: &Path) -> anyhow::Result<Self> {
        let secp = Secp256k1::new();
        let secret = match std::fs::read(path) {
            Ok(bytes) => {
                let bytes: [u8; 32] = bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("identity_key must be 32 bytes"))?;
                bytes
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let bytes = generate_secret(&secp);
                write_secret(path, &bytes)?;
                tracing::info!("generated relay identity key at {}", path.display());
                bytes
            }
            Err(e) => return Err(e.into()),
        };
        let keypair = Keypair::from_seckey_slice(&secp, &secret)
            .map_err(|_| anyhow::anyhow!("identity_key is not a valid secp256k1 secret"))?;
        let (pubkey, _parity) = keypair.x_only_public_key();
        Ok(Self { keypair, pubkey })
    }

    /// The x-only public key clients pin to verify this relay's signatures.
    pub fn public_key(&self) -> XOnlyPublicKey {
        self.pubkey
    }

    /// Hex-encoded 32-byte x-only public key (for logs and `/stats`).
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.pubkey.serialize())
    }

    /// BIP-340 Schnorr signature over the anchor root at a given chain height.
    /// The payload is hashed with `libveritas::hash_signable_message` (the
    /// Spaces signed-message prefix + SHA256), so every language binding can
    /// verify it with the `verify_spaces_message` primitive it already ships —
    /// no bespoke hashing to reimplement per client.
    pub fn sign_anchor(&self, trust_id: &[u8; 32], height: u32) -> [u8; 64] {
        let secp = Secp256k1::new();
        let message = libveritas::hash_signable_message(&anchor_sig_payload(trust_id, height));
        secp.sign_schnorr_no_aux_rand(&message, &self.keypair)
            .serialize()
    }
}

/// The domain-tagged payload signed for an `(anchor root, height)` pair.
/// Verifiers pass this same byte string to `verify_spaces_message`. Exposed so
/// tests (and any Rust-side verifier) can reconstruct it.
pub fn anchor_sig_payload(trust_id: &[u8; 32], height: u32) -> Vec<u8> {
    let mut payload = Vec::with_capacity(ANCHOR_SIG_TAG.len() + 36);
    payload.extend_from_slice(ANCHOR_SIG_TAG);
    payload.extend_from_slice(trust_id);
    payload.extend_from_slice(&height.to_be_bytes());
    payload
}

/// Draw a valid secp256k1 secret. `from_seckey_slice` rejects the vanishingly
/// rare out-of-range draw (zero / >= curve order), so retry until one lands.
fn generate_secret(secp: &Secp256k1<secp256k1::All>) -> [u8; 32] {
    loop {
        let mut bytes = [0u8; 32];
        rand::rng().fill_bytes(&mut bytes);
        if Keypair::from_seckey_slice(secp, &bytes).is_ok() {
            return bytes;
        }
    }
}

/// Persist the secret with owner-only permissions where the platform supports
/// it (0600 on unix).
fn write_secret(path: &Path, secret: &[u8; 32]) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(secret)?;
        file.flush()?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, secret)?;
    }
    Ok(())
}

/// A cached anchor-root signature. Recomputed only when the signed `(trust_id,
/// height)` pair changes, so steady-state `/anchors` responses reuse it.
#[derive(Clone)]
pub struct AnchorSig {
    pub trust_id: [u8; 32],
    pub height: u32,
    pub sig: [u8; 64],
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify_roundtrip() {
        let dir = std::env::temp_dir().join(format!("certrelay-id-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("identity_key");
        let _ = std::fs::remove_file(&path);

        let id = RelayIdentity::load_or_create(&path).unwrap();
        let trust_id = [7u8; 32];
        let height = 944_203u32;
        let sig = id.sign_anchor(&trust_id, height);
        let pubkey = id.public_key().serialize();

        // Verify exactly as a client would: same payload through
        // verify_spaces_message against the pinned public key.
        let payload = anchor_sig_payload(&trust_id, height);
        assert!(libveritas::verify_spaces_message(&payload, &sig, &pubkey).is_ok());
        // A different height changes the payload → signature no longer verifies.
        let other = anchor_sig_payload(&trust_id, height + 1);
        assert!(libveritas::verify_spaces_message(&other, &sig, &pubkey).is_err());

        // Reload keeps the same key (persisted, not regenerated).
        let reloaded = RelayIdentity::load_or_create(&path).unwrap();
        assert_eq!(id.public_key_hex(), reloaded.public_key_hex());

        std::fs::remove_file(&path).ok();
    }
}