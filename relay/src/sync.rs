//! Pull-based propagation: periodically sync stored handles from verified peers.
//!
//! This is THE propagation mechanism (there is no push gossip). Each relay
//! pages `/sync` from peers it selected, re-verifies everything locally, and
//! tracks a persistent per-peer watermark so downtime resumes as a delta pull.
//! A relay with an empty database bootstraps through the same code path — the
//! watermark just starts at zero.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use libveritas::builder::{DataUpdateRequest, MessageBuilder};
use libveritas::cert::Certificate;
use libveritas::{ProvableOption, Zone};
use rand::seq::SliceRandom;
use resolver::{SyncCursor, SyncPage, SyncSummary};

use crate::AppState;

/// Outcome of ingesting one batch of pulled sync records.
#[derive(Debug, Default)]
pub struct SyncIngest {
    /// Handles actually stored (new or better than existing).
    pub stored: usize,
    /// Records skipped before any crypto (exact metadata match with our row).
    pub prefiltered: usize,
    /// Spaces whose records could not be verified this round (missing root,
    /// stale anchor, bad data). Not retried within the round.
    pub failed_spaces: usize,
    /// First-insert records skipped by the retention admission gate
    /// (before any prove/verify work).
    pub gated: usize,
    /// False when the failed-space budget tripped and the rest of the batch
    /// was left unattempted — the caller must NOT advance its watermark past
    /// this page (unattempted != processed).
    pub incomplete: bool,
}

/// Tuning for the sync loop. Millisecond-scale values are valid so the test
/// harness can drive convergence in-process.
#[derive(Clone)]
pub struct SyncConfig {
    /// Base interval between rounds.
    pub interval: Duration,
    /// Random extra delay added per round (jitter).
    pub jitter: Duration,
    /// Rows requested per page.
    pub page_limit: usize,
    /// Peers contacted per round.
    pub peers_per_round: usize,
    /// Max pages pulled from one peer in one round (a partial bootstrap
    /// resumes from the watermark next round).
    pub max_pages_per_peer: usize,
    /// Max bytes accepted for one page body.
    pub max_page_bytes: usize,
    /// Coalescing window for outgoing pokes: bursts of stores within this
    /// window produce one poke per peer.
    pub poke_debounce: Duration,
    /// Minimum gap between poke-triggered syncs with the same peer.
    pub poke_cooldown: Duration,
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(45),
            jitter: Duration::from_secs(15),
            page_limit: crate::http::MAX_SYNC_PAGE_ROWS,
            peers_per_round: 2,
            max_pages_per_peer: 200,
            // Serving pages overshoot MAX_SYNC_PAGE_BYTES by up to one row
            // plus appended root records — accept double, plus one message.
            max_page_bytes: 2 * crate::http::MAX_SYNC_PAGE_BYTES + crate::DEFAULT_MAX_MESSAGE_SIZE,
            poke_debounce: Duration::from_secs(2),
            poke_cooldown: Duration::from_secs(5),
        }
    }
}

/// Run sync rounds forever. Spawned as a background task at startup.
pub async fn run_sync_loop(state: Arc<AppState>, config: SyncConfig) {
    loop {
        let jitter_ms = if config.jitter.is_zero() {
            0
        } else {
            rand::random_range(0..config.jitter.as_millis() as u64)
        };
        tokio::time::sleep(config.interval + Duration::from_millis(jitter_ms)).await;
        sync_round(&state, &config).await;
    }
}

/// One round: pick up to `peers_per_round` random verified peers and sync
/// from each.
pub async fn sync_round(state: &Arc<AppState>, config: &SyncConfig) {
    let mut peer_urls: Vec<String> = {
        let peers = state.peers.lock().await;
        peers.peers().iter().map(|s| s.to_string()).collect()
    };
    peer_urls.shuffle(&mut rand::rng());
    peer_urls.truncate(config.peers_per_round);

    for url in peer_urls {
        match sync_with_peer(state, &url, config).await {
            Ok(stats) => {
                if stats.stored > 0 || stats.failed_spaces > 0 {
                    tracing::info!(
                        "sync from {}: stored {}, prefiltered {}, failed spaces {}",
                        url,
                        stats.stored,
                        stats.prefiltered,
                        stats.failed_spaces
                    );
                }
                if stats.stored > 0 {
                    // We have data our other peers may lack — poke them
                    // (multi-hop propagation).
                    state.poke_dirty.notify_one();
                }
                state.stats.record_sync_success(&url);
                state.peers.lock().await.mark_synced(&url);
            }
            Err(e) => {
                crate::stats::bump(&state.stats.sync_errors);
                tracing::debug!("sync from {} failed: {}", url, e);
                state.peers.lock().await.record_sync_failure(&url);
            }
        }
    }
}

/// Peer-table maintenance: proactively refresh verified peers before their
/// TTL expires (decoupling liveness from data traffic) and verify several
/// unverified candidates per tick so simultaneous expiries recover quickly.
///
/// `seeds` are standing candidates re-asserted every tick, so joining the
/// mesh never depends on a bootstrap peer's list being populated at the
/// right moment (e.g. during a fleet-wide restart). Pass an empty list in
/// tests to keep them off the network.
pub async fn run_peer_maintenance_loop(
    state: Arc<AppState>,
    interval: Duration,
    candidates_per_tick: usize,
    seeds: Vec<String>,
) {
    let mut ticker = tokio::time::interval(interval);
    let mut tick: u64 = 0;
    loop {
        ticker.tick().await;
        tick += 1;

        // Evict stale per-IP rate limiter entries periodically (~10 min at
        // the default 10s tick) — these maps otherwise grow forever.
        if tick.is_multiple_of(60) {
            state.limiters.cleanup();
        }

        let (refresh, candidates) = {
            let mut peers = state.peers.lock().await;
            for seed in &seeds {
                peers.ensure_seed(seed);
            }
            peers.demote_expired();
            peers.expire_unverified();
            let refresh = peers.refresh_candidates();
            let candidates = if peers.needs_peers() {
                peers.next_candidates(candidates_per_tick)
            } else {
                vec![]
            };
            (refresh, candidates)
        };

        for url in refresh.into_iter().chain(candidates) {
            let state = Arc::clone(&state);
            tokio::spawn(async move {
                // peer_client resolve-checks and pins the address: a DNS-named
                // peer pointing at a private/internal address (SSRF via
                // /announce) is refused and removed.
                let client = match state.peer_client(&url).await {
                    Ok(c) => c,
                    Err(e) => {
                        tracing::debug!("peer failed address policy, removing {}: {}", url, e);
                        state.peers.lock().await.remove(&url);
                        return;
                    }
                };
                let check_url = format!("{}/health", url);
                match client.head(&check_url).send().await {
                    Ok(resp) if resp.status().is_success() => {
                        state.peers.lock().await.mark_alive(&url);
                        tracing::debug!("peer alive: {}", url);
                    }
                    _ => {
                        tracing::debug!("peer health check failed: {}", url);
                    }
                }
            });
        }
    }
}

/// Send pokes to all verified peers whenever new data lands, coalescing
/// bursts into one poke per peer per debounce window. Requires `self_url`
/// (peers must know where to pull from); without it, propagation still
/// happens via peers' interval loops.
pub async fn run_poke_send_loop(state: Arc<AppState>, config: SyncConfig) {
    let Some(self_url) = state.self_url.clone() else {
        return;
    };
    loop {
        state.poke_dirty.notified().await;
        // Coalesce: everything stored during this window rides one poke.
        tokio::time::sleep(config.poke_debounce).await;

        let cursor = match state.handler.store.sync_summary() {
            Ok(s) => match s.latest_cursor {
                Some(c) => c,
                None => continue,
            },
            Err(e) => {
                tracing::warn!("poke send: sync summary failed: {}", e);
                continue;
            }
        };
        let poke = resolver::Poke {
            url: self_url.clone(),
            cursor,
        };
        let peer_urls: Vec<String> = {
            let peers = state.peers.lock().await;
            peers.peers().iter().map(|s| s.to_string()).collect()
        };
        for url in peer_urls {
            let state = Arc::clone(&state);
            let poke = poke.clone();
            crate::stats::bump(&state.stats.pokes_sent);
            tokio::spawn(async move {
                // Best-effort: a lost poke is recovered by the interval loop.
                let Ok(client) = state.peer_client(&url).await else {
                    return;
                };
                let _ = client
                    .post(format!("{}/poke", url))
                    .json(&poke)
                    .send()
                    .await;
            });
        }
    }
}

/// Drain poke-triggered sync requests, enforcing a per-peer cooldown so a
/// poke flood can't exceed the steady-state pull cadence. Serial by design:
/// one poke-triggered sync at a time bounds concurrent verify work.
pub async fn run_poke_sync_loop(state: Arc<AppState>, config: SyncConfig) {
    let Some(mut rx) = state.poke_sync_rx.lock().await.take() else {
        tracing::warn!("poke sync receiver already taken");
        return;
    };
    let mut last_synced: std::collections::HashMap<String, std::time::Instant> =
        std::collections::HashMap::new();

    while let Some(url) = rx.recv().await {
        // Cooldown: recently-synced peers wait for the interval loop.
        let now = std::time::Instant::now();
        if last_synced
            .get(&url)
            .is_some_and(|t| now.duration_since(*t) < config.poke_cooldown)
        {
            continue;
        }
        last_synced.insert(url.clone(), now);
        last_synced.retain(|_, t| now.duration_since(*t) < config.poke_cooldown * 4);

        match sync_with_peer(&state, &url, &config).await {
            Ok(stats) => {
                if stats.stored > 0 {
                    tracing::info!("poke sync from {}: stored {}", url, stats.stored);
                    // Cascade to our own peers.
                    state.poke_dirty.notify_one();
                }
                state.stats.record_sync_success(&url);
                state.peers.lock().await.mark_synced(&url);
            }
            Err(e) => {
                crate::stats::bump(&state.stats.sync_errors);
                tracing::debug!("poke sync from {} failed: {}", url, e);
                state.peers.lock().await.record_sync_failure(&url);
            }
        }
    }
}

/// Verify and store records pulled from a peer via `/sync`.
///
/// The peer's metadata fields are claims used only to skip exact duplicates;
/// surviving records are rebuilt into a message with a chain proof from **our
/// own** spaced and pushed through the same `handle_message` verification
/// path as a client publish, so nothing a peer serves is trusted. Proof
/// generation waits on the global proof semaphore, and verification runs on
/// the blocking pool under the global verify semaphore.
///
/// Returns an error only on undecodable input (the caller should abort the
/// page and not advance its watermark); per-space verification failures are
/// counted and skipped. `max_failed_spaces` bounds the prove+verify CPU a
/// batch of unverifiable spaces can burn: once spent, the remaining spaces in
/// the batch are skipped (they self-heal via other peers or the next update).
pub async fn ingest_sync_records(
    state: &Arc<AppState>,
    records: Vec<resolver::SyncRecord>,
    max_failed_spaces: usize,
) -> anyhow::Result<SyncIngest> {
    let mut out = SyncIngest::default();
    let store = &state.handler.store;

    // Pre-filter: drop records whose claimed metadata AND zone bytes exactly
    // match our stored row — the common multi-peer duplicate. Anything else
    // goes to full verification, which is authoritative.
    let handles: Vec<&str> = records.iter().map(|r| r.handle.as_str()).collect();
    let existing: HashMap<String, (u32, u64, u64, Vec<u8>)> = store
        .get_handle_hints(&handles)?
        .into_iter()
        .map(|r| {
            (
                r.handle,
                (
                    r.epoch_height,
                    r.offchain_seq,
                    r.delegate_offchain_seq,
                    r.zone_hash,
                ),
            )
        })
        .collect();
    let survivors: Vec<resolver::SyncRecord> = records
        .into_iter()
        .filter(|r| {
            let dup = existing.get(&r.handle).is_some_and(|(e, s, d, hash)| {
                (*e, *s, *d) == (r.epoch_height, r.seq, r.delegate_seq)
                    && crate::store::zone_hash(&r.zone) == *hash
            });
            if dup {
                out.prefiltered += 1;
            }
            !dup
        })
        .collect();

    // Decode blobs; garbage fails the whole batch (untrusted page).
    let mut decoded: Vec<(Certificate, Zone)> = Vec::new();
    for r in &survivors {
        let cert: Certificate = borsh::from_slice(&r.cert)
            .map_err(|e| anyhow::anyhow!("undecodable cert for {}: {}", r.handle, e))?;
        let zone: Zone = borsh::from_slice(&r.zone)
            .map_err(|e| anyhow::anyhow!("undecodable zone for {}: {}", r.handle, e))?;
        if cert.subject.to_string() != r.handle {
            anyhow::bail!("record handle {} does not match cert subject", r.handle);
        }
        decoded.push((cert, zone));
    }

    // Group by space; roots sort first within a group (single-label names).
    let mut by_space: HashMap<String, Vec<(Certificate, Zone)>> = HashMap::new();
    for (cert, zone) in decoded {
        let Some(space) = cert.subject.space().map(|s| s.to_string()) else {
            continue;
        };
        by_space.entry(space).or_default().push((cert, zone));
    }

    // One message per space: failure isolation, and the prove call is local.
    for (space, mut group) in by_space {
        // In-batch circuit breaker: a page full of bogus spaces stops burning
        // prove+verify CPU once the failure budget is spent. The rest of the
        // batch is unattempted, so the page must not be marked processed.
        if out.failed_spaces >= max_failed_spaces {
            tracing::warn!(
                "failed-space budget spent ({}), aborting rest of batch",
                out.failed_spaces
            );
            out.incomplete = true;
            break;
        }

        // Retention admission gate, applied before any prove/verify work so
        // re-pulls of evicted rows cost ~nothing: drop first-insert records
        // of over-entitled spaces under storage pressure (updates pass).
        if crate::retention::first_insert_gated(state, &state.retention, &space).unwrap_or(false) {
            let before = group.len();
            group.retain(|(cert, _)| existing.contains_key(&cert.subject.to_string()));
            out.gated += before - group.len();
            if group.is_empty() {
                continue;
            }
        }

        let mut builder = MessageBuilder::new();

        let root_idx = group
            .iter()
            .position(|(c, _)| c.subject.to_string() == space);
        let (root_cert, root_zone) = match root_idx {
            Some(i) => group.remove(i),
            // Root not in this page — use our stored copy (it sorts before
            // its sub-handles, so it normally synced in an earlier row).
            None => match store.get_handle(&space)? {
                Some(rec) => (rec.cert, rec.zone),
                None => {
                    tracing::debug!("{}: no root available for sync batch, skipping", space);
                    out.failed_spaces += 1;
                    continue;
                }
            },
        };

        for (cert, zone) in std::iter::once((root_cert, root_zone)).chain(group) {
            builder.add_update(DataUpdateRequest {
                handle: cert.subject.clone(),
                records: Some(zone.records.clone()),
                delegate_records: if let ProvableOption::Exists { value } = zone.delegate {
                    Some(value.records)
                } else {
                    None
                },
            });
            builder.add_cert(cert);
        }

        // Infra failures (spaced down, task join) abort the whole batch —
        // the watermark must not advance past records dropped for reasons
        // unrelated to their validity. Only affirmative build/verification
        // rejections count as failed spaces.
        let proof = {
            let _permit = state.proof_sem.acquire().await?;
            state
                .chain
                .prove(&builder.chain_proof_request())
                .await
                .map_err(|e| anyhow::anyhow!("chain proof failed (infra): {e}"))?
        };
        let result = match builder.build(proof) {
            Ok((msg, _unsigned)) => {
                let _permit = state.verify_sem.acquire().await?;
                let blocking_state = Arc::clone(state);
                tokio::task::spawn_blocking(move || {
                    // Sync is exempt from the content velocity caps: a
                    // rate-dropped record would be silently lost behind the
                    // advancing watermark. CPU is bounded by the failed-space
                    // budget + verify semaphore, storage by retention.
                    blocking_state
                        .handler
                        .handle_message_opts(msg, &Default::default(), false)
                })
                .await
                .map_err(|e| anyhow::anyhow!("verify task failed (infra): {e}"))?
            }
            Err(e) => Err(anyhow::Error::from(e)),
        };
        match result {
            Ok(res) => out.stored += res.stored,
            Err(e) => {
                tracing::debug!("{}: sync batch failed verification: {}", space, e);
                out.failed_spaces += 1;
            }
        }
    }

    Ok(out)
}

/// Failed-space budget per sync round with one peer: bounds the prove+verify
/// CPU a peer serving unverifiable data can burn before the round stops.
const MAX_FAILED_SPACES_PER_ROUND: usize = 32;

/// Sync from one peer: check its summary against our watermark, then page
/// `/sync` until caught up (or the per-round page budget runs out).
///
/// The watermark advances only after a page has been fully processed —
/// never from a summary claim — and is clamped to the peer's advertised
/// `latest_cursor`, so a bogus `next_cursor` (e.g. `u64::MAX`) can't poison
/// it past data that actually exists.
pub async fn sync_with_peer(
    state: &Arc<AppState>,
    peer_url: &str,
    config: &SyncConfig,
) -> anyhow::Result<SyncIngest> {
    let mut totals = SyncIngest::default();
    let client = state.peer_client(peer_url).await?;
    let watermark: Option<SyncCursor> = state
        .handler
        .store
        .get_watermark(peer_url)?
        .and_then(|c| c.parse().ok());

    // Cheap freshness check: nothing new past our watermark → done.
    let summary: SyncSummary = client
        .get(format!("{}/sync/summary", peer_url))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let latest: Option<SyncCursor> = summary.latest_cursor.and_then(|c| c.parse().ok());
    let latest = match (&watermark, latest) {
        (_, None) => return Ok(totals),
        (Some(mark), Some(latest)) if latest < *mark => {
            // The peer's cursor space regressed below our watermark: it wiped
            // or recreated its DB (fresh counter), or a past run stored a
            // poisoned watermark. Start over — the pre-filter makes the
            // re-pull cheap.
            tracing::info!("{}: cursor space regressed, resetting watermark", peer_url);
            state.handler.store.set_watermark(peer_url, "0")?;
            return Ok(totals);
        }
        (Some(mark), Some(latest)) if latest == *mark => return Ok(totals),
        (_, Some(latest)) => latest,
    };

    let mut cursor = watermark;
    for _ in 0..config.max_pages_per_peer {
        let mut req = client
            .get(format!("{}/sync", peer_url))
            .query(&[("limit", config.page_limit.to_string())]);
        if let Some(c) = &cursor {
            req = req.query(&[("cursor", c.to_string())]);
        }
        let resp = req.send().await?.error_for_status()?;
        if let Some(len) = resp.content_length()
            && len > config.max_page_bytes as u64
        {
            anyhow::bail!("sync page too large: {} bytes", len);
        }
        let body = resp.bytes().await?;
        if body.len() > config.max_page_bytes {
            anyhow::bail!("sync page too large: {} bytes", body.len());
        }
        let page: SyncPage = borsh::from_slice(&body)?;
        if page.records.is_empty() {
            // Nothing exists between our cursor and the advertised latest
            // (rows were evicted/deleted on the peer) — catch the watermark
            // up so future rounds short-circuit on the summary. New writes
            // always get sequences above `latest`, so nothing can be missed.
            if cursor.unwrap_or_default() < latest {
                state
                    .handler
                    .store
                    .set_watermark(peer_url, &latest.to_string())?;
            }
            break;
        }
        let next_cursor: SyncCursor = page
            .next_cursor
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("sync page missing cursor"))?
            .parse()
            .map_err(|e| anyhow::anyhow!("bad sync cursor: {e}"))?;
        // A stuck or rewinding cursor means a broken/malicious peer.
        if cursor.as_ref().is_some_and(|c| next_cursor <= *c) {
            anyhow::bail!("sync cursor did not advance");
        }

        let remaining_failures =
            MAX_FAILED_SPACES_PER_ROUND.saturating_sub(totals.failed_spaces) + 1;
        let stats = ingest_sync_records(state, page.records, remaining_failures).await?;
        crate::stats::bump(&state.stats.sync_pages_pulled);
        crate::stats::bump_by(&state.stats.sync_records_stored, stats.stored as u64);
        crate::stats::bump_by(
            &state.stats.sync_records_prefiltered,
            stats.prefiltered as u64,
        );
        crate::stats::bump_by(&state.stats.sync_failed_spaces, stats.failed_spaces as u64);
        totals.stored += stats.stored;
        totals.prefiltered += stats.prefiltered;
        totals.failed_spaces += stats.failed_spaces;

        // The failed-space budget tripped mid-page: the tail of the page was
        // never attempted, so advancing the watermark would silently discard
        // it. Abort the round instead; a peer serving garbage at this volume
        // also gets deprioritized by the caller.
        if stats.incomplete {
            anyhow::bail!(
                "failed-space budget spent mid-page ({} failures) — not advancing",
                totals.failed_spaces
            );
        }

        // Page fully processed (every record stored, prefiltered, gated, or
        // affirmatively rejected by verification) — safe to advance. Clamp to
        // the advertised latest: rows written on the peer after our summary
        // check are simply re-pulled next round.
        let accepted = next_cursor.min(latest);
        state
            .handler
            .store
            .set_watermark(peer_url, &accepted.to_string())?;
        cursor = Some(next_cursor);

        // Caught up to everything the summary advertised — rows written on
        // the peer since then are next round's work.
        if next_cursor >= latest {
            break;
        }

        // Round-level breaker: cumulative affirmative failures across fully
        // processed pages still cut the round short (bounded CPU per round).
        if totals.failed_spaces > MAX_FAILED_SPACES_PER_ROUND {
            tracing::warn!(
                "{}: too many failed spaces this round ({}), stopping",
                peer_url,
                totals.failed_spaces
            );
            break;
        }
    }

    Ok(totals)
}
