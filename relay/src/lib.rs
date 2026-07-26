//! Certificate relay for verifying and storing zones and certificates.

pub mod app;
pub mod handler;
pub mod http;
pub mod peer;
pub mod relay;
pub mod retention;
pub mod settings;
pub mod spaced;
pub mod stats;
pub mod store;
pub mod sync;

pub use resolver::anchor;

pub use http::{
    AppState, BOOTSTRAP_RELAYS, DEFAULT_MAX_MESSAGE_SIZE, Quota, RateLimitConfig, RateLimiters,
    bootstrap, bootstrap_from, router,
};
use libveritas::{AnchorError, Veritas};
pub use peer::{AnnounceResult, PeerConfig, PeerTable};

// Re-export wire format types from relay-client
pub use handler::Handler;
pub use relay::{Config, Relay, ServiceRunner};
pub use resolver::{Announcement, EpochHint, PeerInfo, Query, QueryRequest, capabilities};
pub use retention::{QueryHeat, RetentionConfig, run_retention_loop};
pub use settings::FileConfig;
pub use spaced::SpacedClient;
pub use spaces_client::config::ExtendedNetwork;
use spaces_nums::RootAnchor;
pub use store::SqliteStore;
pub use sync::{
    SyncConfig, SyncIngest, ingest_sync_records, run_peer_maintenance_loop, run_poke_send_loop,
    run_poke_sync_loop, run_sync_loop, sync_round, sync_with_peer,
};

// Create veritas with disabled name expansion
fn create_relay_veritas(anchors: Vec<RootAnchor>) -> Result<Veritas, AnchorError> {
    Veritas::new().with_anchors(anchors)
}
