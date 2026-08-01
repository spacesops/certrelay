//! Optional TOML configuration file (`--config` / `CERTRELAY_CONFIG`).
//!
//! Every field has a default matching the built-in constants, so a config
//! file only needs the values being tuned. Unknown keys are rejected to
//! catch typos.
//!
//! ```toml
//! [rate_limits]
//! message_per_min = 60
//! proof_per_min = 30
//! read_per_min = 120
//! announce_per_min = 5
//! sync_per_min = 60
//! poke_per_min = 30
//! space_per_min = 100
//! handle_period_secs = 300
//! handle_burst = 3
//!
//! [sync]
//! interval_secs = 45
//! jitter_secs = 15
//! page_limit = 1000
//! peers_per_round = 2
//! max_pages_per_peer = 200
//! poke_debounce_ms = 2000
//! poke_cooldown_ms = 5000
//!
//! [peers]
//! max_unverified = 1000
//! max_verified = 100
//! verified_ttl_secs = 600
//!
//! [limits]
//! max_message_size = 524288
//! proof_concurrency = 6
//! verify_concurrency = 4
//! ```

use std::num::NonZeroU32;
use std::path::Path;
use std::time::Duration;

use serde::Deserialize;

use crate::http::{RateLimitConfig, VERIFY_CONCURRENCY};
use crate::peer::PeerConfig;
use crate::sync::SyncConfig;
use crate::{DEFAULT_MAX_MESSAGE_SIZE, Quota, http::PROOF_CONCURRENCY};

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FileConfig {
    pub rate_limits: RateLimitsSection,
    pub sync: SyncSection,
    pub peers: PeersSection,
    pub limits: LimitsSection,
    pub retention: RetentionSection,
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RetentionSection {
    /// Budget for handle payload bytes. 0 = unlimited (no eviction, no gate).
    pub max_storage_bytes: u64,
    /// Handles per (space, epoch) counted as paid-for.
    pub entitlement_per_epoch: u64,
    pub evict_low_water_pct: u8,
    pub sweep_interval_secs: u64,
    pub eviction_batch: usize,
}

impl Default for RetentionSection {
    fn default() -> Self {
        let d = crate::retention::RetentionConfig::default();
        Self {
            max_storage_bytes: d.max_storage_bytes,
            entitlement_per_epoch: d.entitlement_per_epoch,
            evict_low_water_pct: d.low_water_pct,
            sweep_interval_secs: d.sweep_interval.as_secs(),
            eviction_batch: d.eviction_batch,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RateLimitsSection {
    pub message_per_min: u32,
    pub proof_per_min: u32,
    pub read_per_min: u32,
    pub announce_per_min: u32,
    pub sync_per_min: u32,
    pub poke_per_min: u32,
    /// Per-space content velocity cap (churn only).
    pub space_per_min: u32,
    /// Per-handle content cap period (churn only).
    pub handle_period_secs: u64,
    /// Per-handle burst within the period.
    pub handle_burst: u32,
}

impl Default for RateLimitsSection {
    fn default() -> Self {
        Self {
            message_per_min: 60,
            proof_per_min: 30,
            read_per_min: 120,
            announce_per_min: 5,
            sync_per_min: 60,
            poke_per_min: 30,
            space_per_min: 100,
            handle_period_secs: 300,
            handle_burst: 3,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SyncSection {
    pub interval_secs: u64,
    pub jitter_secs: u64,
    pub page_limit: usize,
    pub peers_per_round: usize,
    pub max_pages_per_peer: usize,
    pub poke_debounce_ms: u64,
    pub poke_cooldown_ms: u64,
}

impl Default for SyncSection {
    fn default() -> Self {
        let d = SyncConfig::default();
        Self {
            interval_secs: d.interval.as_secs(),
            jitter_secs: d.jitter.as_secs(),
            page_limit: d.page_limit,
            peers_per_round: d.peers_per_round,
            max_pages_per_peer: d.max_pages_per_peer,
            poke_debounce_ms: d.poke_debounce.as_millis() as u64,
            poke_cooldown_ms: d.poke_cooldown.as_millis() as u64,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PeersSection {
    pub max_unverified: usize,
    pub max_verified: usize,
    pub verified_ttl_secs: u64,
}

impl Default for PeersSection {
    fn default() -> Self {
        let d = PeerConfig::default();
        Self {
            max_unverified: d.max_unverified,
            max_verified: d.max_verified,
            verified_ttl_secs: d.verified_ttl.as_secs(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LimitsSection {
    pub max_message_size: usize,
    pub proof_concurrency: usize,
    pub verify_concurrency: usize,
}

impl Default for LimitsSection {
    fn default() -> Self {
        Self {
            max_message_size: DEFAULT_MAX_MESSAGE_SIZE,
            proof_concurrency: PROOF_CONCURRENCY,
            verify_concurrency: VERIFY_CONCURRENCY,
        }
    }
}

fn per_minute(n: u32) -> Quota {
    Quota::per_minute(NonZeroU32::new(n.max(1)).expect("nonzero"))
}

impl FileConfig {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("could not read config {}: {}", path.display(), e))?;
        toml::from_str(&raw)
            .map_err(|e| anyhow::anyhow!("invalid config {}: {}", path.display(), e))
    }

    pub fn rate_limit_config(&self) -> RateLimitConfig {
        let r = &self.rate_limits;
        RateLimitConfig {
            message: per_minute(r.message_per_min),
            proof: per_minute(r.proof_per_min),
            read: per_minute(r.read_per_min),
            announce: per_minute(r.announce_per_min),
            sync: per_minute(r.sync_per_min),
            poke: per_minute(r.poke_per_min),
        }
    }

    pub fn sync_config(&self) -> SyncConfig {
        let s = &self.sync;
        SyncConfig {
            interval: Duration::from_secs(s.interval_secs),
            jitter: Duration::from_secs(s.jitter_secs),
            page_limit: s.page_limit.clamp(1, crate::http::MAX_SYNC_PAGE_ROWS),
            peers_per_round: s.peers_per_round,
            max_pages_per_peer: s.max_pages_per_peer,
            poke_debounce: Duration::from_millis(s.poke_debounce_ms),
            poke_cooldown: Duration::from_millis(s.poke_cooldown_ms),
            // Serving pages overshoot by up to one record plus appended root
            // records; derive the acceptance slack from the configured max
            // message size so a raised limit can't wedge the puller.
            max_page_bytes: 2 * crate::http::MAX_SYNC_PAGE_BYTES + self.limits.max_message_size,
        }
    }

    pub fn retention_config(&self) -> crate::retention::RetentionConfig {
        let r = &self.retention;
        crate::retention::RetentionConfig {
            max_storage_bytes: r.max_storage_bytes,
            entitlement_per_epoch: r.entitlement_per_epoch.max(1),
            low_water_pct: r.evict_low_water_pct.min(100),
            sweep_interval: Duration::from_secs(r.sweep_interval_secs.max(1)),
            eviction_batch: r.eviction_batch.max(1),
            ..crate::retention::RetentionConfig::default()
        }
    }

    pub fn peer_config(&self) -> PeerConfig {
        let p = &self.peers;
        PeerConfig {
            max_unverified: p.max_unverified,
            max_verified: p.max_verified,
            verified_ttl: Duration::from_secs(p.verified_ttl_secs),
            ..PeerConfig::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_builtins() {
        let cfg = FileConfig::default();
        assert_eq!(cfg.limits.max_message_size, DEFAULT_MAX_MESSAGE_SIZE);
        assert_eq!(cfg.sync.interval_secs, 45);
        assert_eq!(cfg.peers.verified_ttl_secs, 600);
        assert_eq!(cfg.rate_limits.handle_burst, 3);
    }

    /// The README's example config must always parse against the real
    /// schema, so the docs can't drift.
    #[test]
    fn readme_example_parses() {
        let readme = include_str!("../../README.md");
        let start = readme
            .find("```toml")
            .expect("README should contain a toml example")
            + "```toml".len();
        let end = start
            + readme[start..]
                .find("```")
                .expect("unterminated toml block");
        let example = &readme[start..end];

        let cfg: FileConfig = toml::from_str(example).expect("README config must parse");
        // The example documents the defaults — they must match the code
        assert_eq!(cfg.rate_limits.message_per_min, 60);
        assert_eq!(cfg.sync.interval_secs, SyncSection::default().interval_secs);
        assert_eq!(
            cfg.retention.max_storage_bytes,
            RetentionSection::default().max_storage_bytes
        );
        assert_eq!(
            cfg.limits.max_message_size,
            LimitsSection::default().max_message_size
        );
    }

    #[test]
    fn parses_partial_file_and_rejects_typos() {
        let cfg: FileConfig =
            toml::from_str("[sync]\ninterval_secs = 10\n").expect("partial config");
        assert_eq!(cfg.sync.interval_secs, 10);
        assert_eq!(cfg.sync.page_limit, 1000, "unset fields keep defaults");

        let err = toml::from_str::<FileConfig>("[sync]\nintervall_secs = 10\n");
        assert!(err.is_err(), "unknown keys must be rejected");
    }
}
