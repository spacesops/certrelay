//! In-memory counters for runner observability, exposed by `GET /stats`.
//!
//! Dependency-free by design: atomics snapshotted into JSON. Runners
//! `curl /stats`; a Prometheus endpoint can be layered on later.

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Default)]
pub struct Stats {
    // /message intake
    pub messages_received: AtomicU64,
    pub messages_accepted: AtomicU64,
    pub messages_deduped: AtomicU64,
    pub messages_rejected: AtomicU64,

    // Sync pulls (this relay acting as a client)
    pub sync_pages_pulled: AtomicU64,
    pub sync_records_stored: AtomicU64,
    pub sync_records_prefiltered: AtomicU64,
    pub sync_failed_spaces: AtomicU64,
    pub sync_errors: AtomicU64,

    // Poke
    pub pokes_received: AtomicU64,
    pub pokes_accepted: AtomicU64,
    pub pokes_sent: AtomicU64,

    // Proof generation served to clients
    pub proofs_served: AtomicU64,

    // Rate-limit rejections per bucket
    pub rl_message: AtomicU64,
    pub rl_proof: AtomicU64,
    pub rl_read: AtomicU64,
    pub rl_announce: AtomicU64,
    pub rl_sync: AtomicU64,
    pub rl_poke: AtomicU64,

    // Saturation rejections (semaphores full)
    pub busy_rejections: AtomicU64,

    // Retention
    pub evicted_rows: AtomicU64,
    pub admission_gated: AtomicU64,

    /// Unix seconds of the last successful sync, per peer. The single most
    /// important operational signal: a stalled sync loop shows up here.
    pub last_sync_success: Mutex<HashMap<String, i64>>,
}

impl Stats {
    pub fn record_sync_success(&self, peer_url: &str) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        self.last_sync_success
            .lock()
            .unwrap()
            .insert(peer_url.to_string(), now);
    }

    /// Snapshot every counter into a JSON object.
    pub fn snapshot(&self) -> serde_json::Value {
        let g = |a: &AtomicU64| a.load(Ordering::Relaxed);
        serde_json::json!({
            "messages": {
                "received": g(&self.messages_received),
                "accepted": g(&self.messages_accepted),
                "deduped": g(&self.messages_deduped),
                "rejected": g(&self.messages_rejected),
            },
            "sync": {
                "pages_pulled": g(&self.sync_pages_pulled),
                "records_stored": g(&self.sync_records_stored),
                "records_prefiltered": g(&self.sync_records_prefiltered),
                "failed_spaces": g(&self.sync_failed_spaces),
                "errors": g(&self.sync_errors),
                "last_success_by_peer": self.last_sync_success.lock().unwrap().clone(),
            },
            "pokes": {
                "received": g(&self.pokes_received),
                "accepted": g(&self.pokes_accepted),
                "sent": g(&self.pokes_sent),
            },
            "proofs_served": g(&self.proofs_served),
            "rate_limited": {
                "message": g(&self.rl_message),
                "proof": g(&self.rl_proof),
                "read": g(&self.rl_read),
                "announce": g(&self.rl_announce),
                "sync": g(&self.rl_sync),
                "poke": g(&self.rl_poke),
            },
            "busy_rejections": g(&self.busy_rejections),
            "retention": {
                "evicted_rows": g(&self.evicted_rows),
                "admission_gated": g(&self.admission_gated),
            },
        })
    }
}

/// Relaxed increment helper.
pub fn bump(counter: &AtomicU64) {
    counter.fetch_add(1, Ordering::Relaxed);
}

pub fn bump_by(counter: &AtomicU64, n: u64) {
    counter.fetch_add(n, Ordering::Relaxed);
}
