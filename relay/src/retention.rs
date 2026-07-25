//! Storage retention: entitlement-weighted eviction under a disk budget.
//!
//! Nothing verified is hard-rejected in normal operation. Each space's
//! *entitlement* is `entitlement_per_epoch x epochs it was seen committing` —
//! commitments cost on-chain transactions, so storage beyond entitlement is
//! storage nobody paid for. When the payload budget is exceeded, a background
//! sweep evicts from the most over-entitled space first (oldest, coldest rows
//! first), and an admission gate stops first-inserts for over-entitled spaces
//! so evicted rows aren't endlessly re-pulled from peers. Under budget, both
//! mechanisms are inert.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use crate::AppState;

/// Tuning for retention. All values TOML-configurable (`[retention]`).
#[derive(Clone)]
pub struct RetentionConfig {
    /// Budget for handle payload bytes (cert + zone blobs). 0 = unlimited.
    pub max_storage_bytes: u64,
    /// Handles per (space, epoch) counted as paid-for.
    pub entitlement_per_epoch: u64,
    /// Evict down to this percentage of the budget (hysteresis).
    pub low_water_pct: u8,
    /// Pressure check cadence.
    pub sweep_interval: Duration,
    /// Rows deleted per transaction.
    pub eviction_batch: usize,
    /// Max batches per sweep (bounds one sweep's runtime; the next sweep
    /// continues).
    pub max_batches_per_sweep: usize,
}

impl Default for RetentionConfig {
    fn default() -> Self {
        Self {
            max_storage_bytes: 10 * 1024 * 1024 * 1024,
            entitlement_per_epoch: 10_000,
            low_water_pct: 90,
            sweep_interval: Duration::from_secs(30),
            eviction_batch: 1_000,
            max_batches_per_sweep: 20,
        }
    }
}

/// Approximate recently-queried set: two generational HashSets swapped when
/// the active one fills. O(1) touch on the query path, no DB writes, no
/// persistence — eviction is rare and approximate, so losing heat on restart
/// is fine.
pub struct QueryHeat {
    cap: usize,
    active: HashSet<String>,
    prev: HashSet<String>,
}

impl QueryHeat {
    pub fn new(cap: usize) -> Self {
        Self {
            cap: cap.max(1),
            active: HashSet::new(),
            prev: HashSet::new(),
        }
    }

    pub fn touch(&mut self, handle: &str) {
        if self.active.len() >= self.cap {
            self.prev = std::mem::take(&mut self.active);
        }
        self.active.insert(handle.to_string());
    }

    pub fn is_hot(&self, handle: &str) -> bool {
        self.active.contains(handle) || self.prev.contains(handle)
    }
}

impl Default for QueryHeat {
    fn default() -> Self {
        Self::new(50_000)
    }
}

/// True when a first-insert for `space` should be skipped: only under
/// storage pressure AND when the space already exceeds its entitlement.
/// Inert (always false) with no budget or under budget.
pub fn first_insert_gated(
    state: &AppState,
    config: &RetentionConfig,
    space: &str,
) -> anyhow::Result<bool> {
    if config.max_storage_bytes == 0 {
        return Ok(false);
    }
    let (_, bytes) = state.handler.store.storage_totals()?;
    if bytes <= config.max_storage_bytes {
        return Ok(false);
    }
    let (stored, epochs) = state.handler.store.space_usage(space)?;
    Ok(stored > epochs.max(1) * config.entitlement_per_epoch)
}

/// Run pressure checks forever. Spawned as a background task at startup.
pub async fn run_retention_loop(state: Arc<AppState>, config: RetentionConfig) {
    if config.max_storage_bytes == 0 {
        return;
    }
    let mut ticker = tokio::time::interval(config.sweep_interval);
    loop {
        ticker.tick().await;
        match sweep(&state, &config).await {
            Ok(0) => {}
            Ok(evicted) => tracing::info!("retention: evicted {} handles", evicted),
            Err(e) => tracing::warn!("retention sweep failed: {}", e),
        }
    }
}

/// One sweep: evict batches from the most over-entitled space until the
/// low-water mark (or the per-sweep batch budget) is reached. Returns rows
/// evicted. Public so tests can drive it directly.
pub async fn sweep(state: &Arc<AppState>, config: &RetentionConfig) -> anyhow::Result<usize> {
    let mut evicted = 0;
    let low_water = config.max_storage_bytes * config.low_water_pct.min(100) as u64 / 100;
    // Spaces that yielded no candidates this sweep (e.g. only their root row
    // remains, which is never evicted) — move on to the next-worst victim.
    let mut exhausted: HashSet<String> = HashSet::new();

    for _ in 0..config.max_batches_per_sweep {
        let (_, bytes) = state.handler.store.storage_totals()?;
        if bytes
            <= if evicted == 0 {
                config.max_storage_bytes
            } else {
                low_water
            }
        {
            break;
        }

        // Victim: worst stored/entitlement ratio; if nobody is over
        // entitlement the budget still wins (a full disk kills the relay),
        // so fall back to the largest space and tell the operator.
        let usage = {
            let blocking_state = Arc::clone(state);
            tokio::task::spawn_blocking(move || blocking_state.handler.store.space_usage_all())
                .await??
        };
        let usage: Vec<_> = usage
            .into_iter()
            .filter(|(space, _, _)| !exhausted.contains(space))
            .collect();
        let over = usage
            .iter()
            .filter(|(_, stored, epochs)| *stored > epochs.max(&1) * config.entitlement_per_epoch)
            .max_by(|a, b| {
                let ra = a.1 as f64 / (a.2.max(1) * config.entitlement_per_epoch) as f64;
                let rb = b.1 as f64 / (b.2.max(1) * config.entitlement_per_epoch) as f64;
                ra.total_cmp(&rb)
            });
        let victim = match over {
            Some((space, _, _)) => space.clone(),
            None => match usage.iter().max_by_key(|(_, stored, _)| *stored) {
                Some((space, _, _)) => {
                    tracing::warn!(
                        "retention: over budget but every space is within entitlement — \
                         evicting from {}; raise max_storage_bytes",
                        space
                    );
                    space.clone()
                }
                None => break,
            },
        };

        // Oldest rows first (the root row is never a candidate), sparing
        // recently-queried handles when possible — but never stalling: if
        // everything is hot, evict anyway.
        let candidates = {
            let blocking_state = Arc::clone(state);
            let victim_space = victim.clone();
            let limit = config.eviction_batch * 2;
            tokio::task::spawn_blocking(move || {
                blocking_state
                    .handler
                    .store
                    .eviction_candidates(&victim_space, limit)
            })
            .await??
        };
        if candidates.is_empty() {
            exhausted.insert(victim);
            continue;
        }
        let batch: Vec<String> = {
            let heat = state.query_heat.lock().unwrap();
            let cold: Vec<String> = candidates
                .iter()
                .filter(|h| !heat.is_hot(h))
                .take(config.eviction_batch)
                .cloned()
                .collect();
            if cold.is_empty() {
                candidates.into_iter().take(config.eviction_batch).collect()
            } else {
                cold
            }
        };

        let deleted = {
            let blocking_state = Arc::clone(state);
            tokio::task::spawn_blocking(move || blocking_state.handler.store.delete_handles(&batch))
                .await??
        };
        crate::stats::bump_by(&state.stats.evicted_rows, deleted as u64);
        evicted += deleted;
        if deleted == 0 {
            break;
        }
    }

    Ok(evicted)
}
