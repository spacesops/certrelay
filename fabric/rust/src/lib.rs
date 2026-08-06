//! Wire format types for relay P2P communication.
//!
//! All protocol types use JSON serialization for cross-language compatibility.
//! Only the `Message` type from libveritas remains binary (borsh).

pub mod anchor;
#[cfg(feature = "client")]
pub mod client;
pub mod seeds;
#[cfg(feature = "signing")]
pub mod signing;

use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

// Re-export the entire libveritas crate
pub extern crate libveritas;
// Also re-export Message directly since it's used in the wire format
pub use libveritas::msg::Message;
use spaces_nums::RootAnchor;

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TrustId([u8; 32]);

impl TrustId {
    pub fn to_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl fmt::Display for TrustId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl From<[u8; 32]> for TrustId {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl FromStr for TrustId {
    type Err = hex::FromHexError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes: [u8; 32] = hex::decode(s)?
            .try_into()
            .map_err(|_| hex::FromHexError::InvalidStringLength)?;

        Ok(Self(bytes))
    }
}

/// Capability flags for peers.
///
/// Reserved for future use. Capabilities allow peers to advertise
/// what features they support.
pub mod capabilities {
    // No capabilities defined yet
}

/// A query for certificate data.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Query {
    /// The space to query (e.g., "@bitcoin").
    pub space: String,
    /// Handles within the space to query.
    pub handles: Vec<String>,
    /// Optional epoch hint for optimizing proof size.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epoch_hint: Option<EpochHint>,
}

impl Query {
    pub fn new(space: impl Into<String>, handles: Vec<String>) -> Self {
        Self {
            space: space.into(),
            handles,
            epoch_hint: None,
        }
    }

    pub fn with_epoch_hint(mut self, hint: EpochHint) -> Self {
        self.epoch_hint = Some(hint);
        self
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HintsResponse {
    pub anchor_tip: u32,
    pub hints: Vec<SpaceHint>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AnchorSet {
    pub entries: Vec<RootAnchor>,
}

impl AnchorSet {
    /// Height of the newest anchor. Entries are canonically ordered
    /// newest-first: the order is load-bearing because `compute_trust_set`
    /// hashes the anchors in sequence to derive the trust id, so relays and
    /// clients must agree on it (and the client sorts `Reverse(height)`). The
    /// tip is therefore the first entry — `.last()` was the bug, returning the
    /// OLDEST anchor in the window.
    pub fn tip_height(&self) -> u32 {
        self.entries.first().map(|a| a.block.height).unwrap_or(0)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SpaceHint {
    pub epoch_tip: u32,
    pub name: String,
    pub seq: u64,
    pub delegate_seq: u64,
    pub epochs: Vec<EpochResult>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EpochResult {
    pub epoch: u32,
    pub res: Vec<HandleHint>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HandleHint {
    pub seq: u64,
    pub name: String,
}

impl PartialEq for HintsResponse {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == std::cmp::Ordering::Equal
    }
}

impl Eq for HintsResponse {}

impl PartialOrd for HintsResponse {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for HintsResponse {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let mut score: i32 = 0;

        for space in &self.hints {
            let Some(other_space) = other.hints.iter().find(|s| s.name == space.name) else {
                score += 1;
                continue;
            };

            score += cmp_score(space.epoch_tip, other_space.epoch_tip);
            score += cmp_score(space.seq, other_space.seq);
            score += cmp_score(space.delegate_seq, other_space.delegate_seq);

            let self_handles = flatten_handles(space);
            let other_handles = flatten_handles(other_space);

            for (name, self_seq) in &self_handles {
                match other_handles.get(*name) {
                    Some(other_seq) => score += cmp_score(*self_seq, *other_seq),
                    None => score += 1,
                }
            }
            for name in other_handles.keys() {
                if !self_handles.contains_key(*name) {
                    score -= 1;
                }
            }
        }

        for other_space in &other.hints {
            if !self.hints.iter().any(|s| s.name == other_space.name) {
                score -= 1;
            }
        }

        if score != 0 {
            score.cmp(&0)
        } else {
            self.anchor_tip.cmp(&other.anchor_tip)
        }
    }
}

fn cmp_score<T: Ord>(a: T, b: T) -> i32 {
    match a.cmp(&b) {
        std::cmp::Ordering::Greater => 1,
        std::cmp::Ordering::Less => -1,
        std::cmp::Ordering::Equal => 0,
    }
}

fn flatten_handles(space: &SpaceHint) -> HashMap<&str, u64> {
    let mut map = HashMap::new();
    for epoch in &space.epochs {
        for handle in &epoch.res {
            let existing = map.get(handle.name.as_str()).copied().unwrap_or(0);
            if handle.seq > existing {
                map.insert(handle.name.as_str(), handle.seq);
            }
        }
    }
    map
}

/// Epoch hint for query optimization.
///
/// If the client has a cached epoch root, providing this hint allows
/// the relay to skip including redundant proofs.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EpochHint {
    /// The merkle root of the cached epoch (hex-encoded).
    pub root: String,
    /// The block height of the cached epoch.
    pub height: u32,
}

/// Request body for POST /query.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QueryRequest {
    /// The queries to execute.
    pub queries: Vec<Query>,
}

impl QueryRequest {
    pub fn new(queries: Vec<Query>) -> Self {
        Self { queries }
    }

    pub fn single(space: impl Into<String>, handles: Vec<String>) -> Self {
        Self {
            queries: vec![Query::new(space, handles)],
        }
    }
}

/// Announcement payload for POST /announce.
///
/// Sent by a peer to announce itself to another relay.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Announcement {
    /// The URL where this peer can be reached.
    pub url: String,
    /// Capability flags indicating what this peer supports.
    pub capabilities: u32,
}

impl Announcement {
    pub fn new(url: impl Into<String>, capabilities: u32) -> Self {
        Self {
            url: url.into(),
            capabilities,
        }
    }

    pub fn has_capability(&self, cap: u32) -> bool {
        self.capabilities & cap != 0
    }
}

/// Information about a peer, returned from GET /peers.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerInfo {
    /// The IP address that announced this peer. Informational only: a peers
    /// list is remote-controlled, so receivers must not trust this field for
    /// anything (defaults to the unspecified address when absent).
    #[serde(default = "unspecified_ip")]
    pub source_ip: IpAddr,
    /// The URL where this peer can be reached.
    pub url: String,
    /// Capability flags indicating what this peer supports.
    pub capabilities: u32,
}

impl PeerInfo {
    pub fn has_capability(&self, cap: u32) -> bool {
        self.capabilities & cap != 0
    }
}

fn unspecified_ip() -> IpAddr {
    IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
}

/// A reverse record mapping a numeric identity to its human-readable name.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReverseRecord {
    pub id: String,
    pub name: String,
}

/// Address lookup result — handles claiming an address.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AddrMatch {
    pub address: String,
    pub handles: Vec<AddrEntry>,
}

/// An entry in an address lookup result.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AddrEntry {
    /// Canonical/flattened handle name.
    pub handle: String,
    /// Human-readable reverse name (from Sig record).
    pub rev: String,
}

/// One stored handle row served by `GET /sync` (borsh-encoded inside [`SyncPage`]).
///
/// `cert` and `zone` are opaque borsh blobs passed through exactly as stored.
/// The metadata fields mirror the serving relay's table columns and are
/// **claims** used only for duplicate pre-filtering — a puller must never store
/// them; real values are re-derived from the zone after full verification.
#[derive(Clone, Debug, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct SyncRecord {
    pub handle: String,
    pub epoch_height: u32,
    pub seq: u64,
    pub delegate_seq: u64,
    pub cert: Vec<u8>,
    pub zone: Vec<u8>,
}

impl SyncRecord {
    /// The space portion of the handle (`"alice@bitcoin"` -> `"@bitcoin"`).
    pub fn space_name(&self) -> &str {
        match self.handle.find(['@', '#']) {
            Some(i) => &self.handle[i..],
            None => &self.handle,
        }
    }
}

/// A page of sync records. `next_cursor` is `None` when the page is empty
/// (nothing beyond the requested cursor).
#[derive(Clone, Debug, Default, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct SyncPage {
    pub records: Vec<SyncRecord>,
    pub next_cursor: Option<String>,
}

/// Body of `POST /poke` (JSON): "I have new data up to `cursor` — pull me."
///
/// Content-free by design: a poke can never transfer state, so it can never
/// amplify. `url` must already be a verified peer of the receiver (poke is not
/// discovery), and `cursor` is a claim checked against the receiver's
/// watermark — the watermark itself only advances from real sync pages.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Poke {
    /// The sender's own base URL (where to pull from).
    pub url: String,
    /// The sender's latest sync cursor.
    pub cursor: String,
}

/// Response of `GET /sync/summary` (JSON, curl-friendly).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SyncSummary {
    /// Total handle rows stored.
    pub count: u64,
    /// Cursor of the newest stored row, if any.
    pub latest_cursor: Option<String>,
}

/// Sync cursor: position in a relay's strictly-increasing write sequence.
///
/// Cursors are **peer-local** (they encode the serving relay's private write
/// counter): echo them back to the relay that issued them and compare only
/// cursors from the same relay. Serialized as a decimal string; treat the
/// format as opaque.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct SyncCursor(pub u64);

impl fmt::Display for SyncCursor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for SyncCursor {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.parse().map(Self).map_err(|_| "invalid cursor")
    }
}

impl AnchorSet {
    pub fn from_anchors(anchors: Vec<RootAnchor>) -> Self {
        Self { entries: anchors }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_query_roundtrip() {
        let query = Query::new("@bitcoin", vec!["alice".into()]);
        let req = QueryRequest::new(vec![query]);

        let json = serde_json::to_string(&req).unwrap();
        let decoded: QueryRequest = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded.queries.len(), 1);
        assert_eq!(decoded.queries[0].space, "@bitcoin");
        assert_eq!(decoded.queries[0].handles, vec!["alice"]);
    }

    #[test]
    fn test_announcement_roundtrip() {
        let announcement = Announcement::new("https://relay.example.com", 0);
        let json = serde_json::to_string(&announcement).unwrap();
        let decoded: Announcement = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded.url, "https://relay.example.com");
        assert_eq!(decoded.capabilities, 0);
    }

    #[test]
    fn test_peer_info_roundtrip() {
        let peer = PeerInfo {
            source_ip: "192.168.1.1".parse().unwrap(),
            url: "https://peer.example.com".to_string(),
            capabilities: 0,
        };
        let json = serde_json::to_string(&peer).unwrap();
        let decoded: PeerInfo = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded.url, "https://peer.example.com");
        assert_eq!(decoded.source_ip.to_string(), "192.168.1.1");
    }

    #[test]
    fn test_epoch_hint_skipped_when_none() {
        let query = Query::new("@bitcoin", vec!["alice".into()]);
        let json = serde_json::to_string(&query).unwrap();
        assert!(!json.contains("epoch_hint"));
    }
}
