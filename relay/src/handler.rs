use crate::anchor::AnchorSets;
use crate::spaced::SpacedClient;
use crate::store::{BulkStoreResult, HandleRecord, SqliteStore};
use governor::DefaultKeyedRateLimiter;
use governor::Quota;
use libveritas::builder::{DataUpdateRequest, MessageBuilder};
use libveritas::cert::Witness;
use libveritas::msg::{self, QueryContext};
use libveritas::sip7::{ParsedRecord, SIG_PRIMARY_ZONE};
use libveritas::spaces_protocol::sname::{NameLike, SName, Subname};
use libveritas::{ProvableOption, Veritas, Zone};
use resolver::{EpochResult, HandleHint, SpaceHint};
use spaces_protocol::slabel::SLabel;
use std::collections::{HashMap, HashSet};
use std::num::NonZeroU32;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, RwLock};

/// Certificate handler that verifies messages and stores zones/handles.
pub struct Handler {
    pub veritas: RwLock<Veritas>,
    pub anchor_store: Mutex<AnchorSets>,
    pub store: SqliteStore,
    pub dev_mode: bool,
    /// Rate limiter per space: 100 handle updates per minute.
    space_rate: DefaultKeyedRateLimiter<String>,
    /// Rate limiter per handle: 1 update per 5 minutes.
    handle_rate: DefaultKeyedRateLimiter<String>,
    /// Counter for periodic rate limiter cleanup.
    msg_count: AtomicU64,
}

impl Handler {
    pub fn new(veritas: Veritas, store: SqliteStore, anchor_store: AnchorSets) -> Self {
        Self {
            veritas: RwLock::new(veritas),
            anchor_store: Mutex::new(anchor_store),
            store,
            dev_mode: false,
            space_rate: governor::RateLimiter::keyed(Quota::per_minute(
                NonZeroU32::new(100).unwrap(),
            )),
            handle_rate: governor::RateLimiter::keyed(
                Quota::with_period(std::time::Duration::from_secs(300))
                    .unwrap()
                    .allow_burst(NonZeroU32::new(3).unwrap()),
            ),
            msg_count: AtomicU64::new(0),
        }
    }

    /// Override the per-space and per-handle content rate limits (config file).
    pub fn with_content_rates(
        mut self,
        space_per_min: u32,
        handle_period: std::time::Duration,
        handle_burst: u32,
    ) -> Self {
        self.space_rate = governor::RateLimiter::keyed(Quota::per_minute(
            NonZeroU32::new(space_per_min.max(1)).unwrap(),
        ));
        self.handle_rate = governor::RateLimiter::keyed(
            Quota::with_period(handle_period)
                .unwrap_or_else(|| Quota::with_period(std::time::Duration::from_secs(300)).unwrap())
                .allow_burst(NonZeroU32::new(handle_burst.max(1)).unwrap()),
        );
        self
    }

    pub async fn resolve(
        &self,
        chain: &SpacedClient,
        queries: Vec<resolver::Query>,
    ) -> anyhow::Result<msg::Message> {
        let mut seen_spaces: HashSet<String> = HashSet::new();
        let mut builder = MessageBuilder::new();

        for query in queries {
            if !seen_spaces.insert(query.space.clone()) {
                continue; // Skip duplicate spaces
            }

            let space = SLabel::from_str(&query.space)
                .map_err(|_| anyhow::anyhow!("invalid space: {}", query.space))?;

            // Load root handle (has zone + parent cert)
            let parent = match self.store.get_handle(&query.space)? {
                Some(record) => record,
                None => {
                    builder.add_cert(libveritas::cert::Certificate {
                        version: 0,
                        subject: SName::from_space(&space),
                        witness: Witness::Root { receipt: None },
                    });
                    continue;
                }
            };
            let mut parent_cert = parent.cert;
            // Skip receipt if client can verify from their cached epoch
            if query
                .epoch_hint
                .as_ref()
                .is_some_and(|h| epoch_hint_verifiable_by(h, &parent.zone))
                && let Witness::Root { receipt } = &mut parent_cert.witness
            {
                std::mem::take(receipt);
            }

            builder.add_update(DataUpdateRequest {
                handle: parent_cert.subject.clone(),
                records: Some(parent.zone.records.clone()),
                delegate_records: if let ProvableOption::Exists { value } = parent.zone.delegate {
                    Some(value.records)
                } else {
                    None
                },
            });

            builder.add_cert(parent_cert);

            let unique_handles: Vec<String> = query
                .handles
                .iter()
                .filter_map(|h| Subname::from_str(h).ok())
                .collect::<HashSet<_>>()
                .into_iter()
                .filter_map(|h| SName::join(&h, &space).ok())
                .map(|sname| sname.to_string())
                .collect();

            let handle_refs: Vec<&str> = unique_handles.iter().map(|s| s.as_str()).collect();
            let handle_entries = self.store.get_handles(&handle_refs)?;

            for handle in handle_entries {
                builder.add_update(DataUpdateRequest {
                    handle: handle.cert.subject.clone(),
                    records: Some(handle.zone.records),
                    delegate_records: if let ProvableOption::Exists { value } = handle.zone.delegate
                    {
                        Some(value.records)
                    } else {
                        None
                    },
                });
                builder.add_cert(handle.cert);
            }
        }
        let chain = chain.prove(&builder.chain_proof_request()).await?;
        let (msg, unsigned) = builder.build(chain)?;
        if !unsigned.is_empty() && unsigned.iter().all(|u| !u.records.is_empty()) {
            let missing_sigs = unsigned
                .iter()
                .map(|u| u.canonical.to_string())
                .collect::<Vec<_>>()
                .join(", ");

            return Err(anyhow::anyhow!(
                "Could not build response: missing signatures for {}",
                missing_sigs
            ));
        }

        Ok(msg)
    }

    pub fn hints(&self, handles: &mut [&str]) -> anyhow::Result<resolver::HintsResponse> {
        handles.sort();
        if let Some(w) = handles.windows(2).find(|w| w[0] == w[1]) {
            return Err(anyhow::anyhow!("duplicate handle: {}", w[0]));
        }

        let mut res = resolver::HintsResponse {
            anchor_tip: self.veritas.read().expect("lock").newest_anchor(),
            hints: vec![],
        };

        let all_rows = self.store.get_handle_hints(handles)?;
        for space in handles
            .iter()
            .filter(|h| h.starts_with("@") || h.starts_with("#"))
        {
            let Some(space_row) = all_rows.iter().find(|r| &r.handle == space) else {
                continue;
            };

            let mut hint = SpaceHint {
                epoch_tip: space_row.epoch_height,
                name: space.to_string(),
                seq: space_row.offchain_seq,
                delegate_seq: space_row.delegate_offchain_seq,
                epochs: vec![],
            };
            for row in all_rows
                .iter()
                .filter(|r| r.handle.ends_with(space) && r.handle != *space)
                .collect::<Vec<_>>()
            {
                let idx = hint
                    .epochs
                    .iter()
                    .position(|x| x.epoch == row.epoch_height)
                    .unwrap_or_else(|| {
                        hint.epochs.push(EpochResult {
                            epoch: row.epoch_height,
                            res: vec![],
                        });
                        hint.epochs.len() - 1
                    });

                let item = &mut hint.epochs[idx];
                item.res.push(HandleHint {
                    seq: row.offchain_seq,
                    name: row.handle.clone(),
                })
            }
            res.hints.push(hint);
        }
        Ok(res)
    }

    /// Handle an incoming certificate message.
    ///
    /// Verifies the message against the current chain state, updates stored zones,
    /// and stores any new handle records. Returns the store result so callers can
    /// distinguish new data (`stored > 0`) from duplicates and stale updates.
    pub fn handle_message(&self, msg: msg::Message) -> anyhow::Result<BulkStoreResult> {
        self.handle_message_opts(msg, &HashSet::new(), true)
    }

    /// [`Handler::handle_message`] with a set of spaces whose **first
    /// inserts** must be skipped (retention admission gate under storage
    /// pressure). Updates to existing handles are never gated.
    pub fn handle_message_gated(
        &self,
        msg: msg::Message,
        gated_spaces: &HashSet<String>,
    ) -> anyhow::Result<BulkStoreResult> {
        self.handle_message_opts(msg, gated_spaces, true)
    }

    /// Full-control variant: `charge_content_limits = false` exempts the
    /// message from the per-space/per-handle velocity caps. Used by sync
    /// ingest — silently rate-dropping synced records would advance the
    /// watermark past data that was never stored (permanent loss); sync CPU
    /// is already bounded by the failed-space budget and verify semaphore,
    /// and storage by retention.
    pub fn handle_message_opts(
        &self,
        msg: msg::Message,
        gated_spaces: &HashSet<String>,
        charge_content_limits: bool,
    ) -> anyhow::Result<BulkStoreResult> {
        // Periodically clean up expired rate limiter entries
        if self
            .msg_count
            .fetch_add(1, Ordering::Relaxed)
            .is_multiple_of(10_000)
        {
            self.space_rate.retain_recent();
            self.handle_rate.retain_recent();
            self.space_rate.shrink_to_fit();
            self.handle_rate.shrink_to_fit();
        }

        // Build query context from stored zones
        let mut ctx = QueryContext::new();
        let spaces: Vec<&SLabel> = msg.spaces.iter().map(|s| &s.subject).collect();
        let zones = self.store.get_zones(&spaces)?;
        for zone in zones {
            ctx.add_zone(zone);
        }

        // Verify the message
        let options = if self.dev_mode {
            libveritas::VERIFY_DEV_MODE
        } else {
            0
        };
        let res = self
            .veritas
            .read()
            .unwrap()
            .verify_with_options(&ctx, msg, options)?;

        // Build zone lookup by canonical name and epoch height by space
        let mut zone_map: HashMap<String, &Zone> = HashMap::new();
        let mut epoch_map: HashMap<String, u32> = HashMap::new();
        for zone in &res.zones {
            zone_map.insert(zone.canonical.to_string(), zone);
            // Root zones (single-label like "@bitcoin") carry the commitment
            if zone.canonical.is_single_label() {
                let epoch_height = match &zone.commitment {
                    ProvableOption::Exists { value: c } => c.onchain.block_height,
                    _ => 0,
                };
                epoch_map.insert(zone.canonical.to_string(), epoch_height);
            }
        }

        // Max offchain records size per handle (1 KB)
        const MAX_RECORDS_SIZE: usize = 1024;

        // Bulk-load existing hint rows: powers the duplicate pre-skip and the
        // churn-only rate limits (first insert of a handle is free; replacing
        // an existing row is what gets rate limited — otherwise bootstrap sync
        // would trip handle_rate on a network's worth of first-time handles).
        let all_handles: Vec<String> = res.certificates().map(|c| c.subject.to_string()).collect();
        let handle_refs: Vec<&str> = all_handles.iter().map(|s| s.as_str()).collect();
        let existing: HashMap<String, (u32, u64, u64, Vec<u8>)> = self
            .store
            .get_handle_hints(&handle_refs)?
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

        // Bundle each certificate with its zone and epoch height
        let mut preskipped = 0usize;
        let mut gated = 0usize;
        let mut revs: Vec<(String, String)> = Vec::new();
        // canonical_handle -> (rev_name, vec of (addr_name, addr_value))
        let mut addr_index: HashMap<String, (String, Vec<(String, String)>)> = HashMap::new();
        let updates: Vec<HandleRecord> = res
            .certificates()
            .filter_map(|cert| {
                let handle_str = cert.subject.to_string();
                let zone = zone_map.get(&handle_str)?;

                if zone.records.as_slice().len() > MAX_RECORDS_SIZE {
                    tracing::warn!(
                        "{}: records exceed {} bytes, skipping",
                        handle_str,
                        MAX_RECORDS_SIZE
                    );
                    return None;
                }
                if let Some(sig) = zone.records.sig() {
                    let rev_name = sig.handle.to_string();
                    if sig.flags & SIG_PRIMARY_ZONE == SIG_PRIMARY_ZONE
                        && let Some(num_id) = &zone.num_id
                    {
                        revs.push((num_id.to_string(), rev_name.clone()));
                    }
                    // Collect addr records for the index
                    let addrs: Vec<(String, String)> = zone
                        .records
                        .iter()
                        .map(|rrs| {
                            rrs.filter_map(|r| match r {
                                ParsedRecord::Addr { key, value } => value
                                    .iter()
                                    .next()
                                    .map(|v| (key.to_string(), v.to_string())),
                                _ => None,
                            })
                            .collect::<Vec<_>>()
                        })
                        .unwrap_or_default();
                    if !addrs.is_empty() {
                        addr_index.insert(handle_str.clone(), (rev_name, addrs));
                    }
                }

                let space = cert.subject.space()?.to_string();

                let epoch_height = epoch_map.get(&space).copied().unwrap_or(0);
                let offchain_seq = zone.records.seq().unwrap_or(0);
                let delegate_offchain_seq = match &zone.delegate {
                    ProvableOption::Exists { value: d } => d.records.seq().unwrap_or(0),
                    _ => 0,
                };

                // Duplicate pre-skip: identical metadata AND identical zone bytes
                // means a redelivery (multi-path sync, republish) — skip it
                // without charging the content rate limits. The hash check
                // matters: a better zone can carry unchanged seqs (e.g. a
                // pending->finalized commitment transition).
                let stored = existing.get(&handle_str);
                if let Some((e, s, d, hash)) = stored
                    && (*e, *s, *d) == (epoch_height, offchain_seq, delegate_offchain_seq)
                    && borsh::to_vec(*zone).is_ok_and(|z| crate::store::zone_hash(&z) == *hash)
                {
                    preskipped += 1;
                    return None;
                }

                // Retention admission gate: under storage pressure, spaces
                // over their entitlement get no new handles (updates pass).
                if stored.is_none() && gated_spaces.contains(&space) {
                    gated += 1;
                    return None;
                }

                // Rate limit per space (100 handle updates/min) and per handle
                // (1 per 5 min) — churn only: first insert of a handle is free.
                if charge_content_limits && !self.dev_mode && stored.is_some() {
                    if self.space_rate.check_key(&space).is_err() {
                        tracing::warn!("{}: space rate limited, skipping", space);
                        return None;
                    }
                    if self.handle_rate.check_key(&handle_str).is_err() {
                        tracing::warn!("{}: handle rate limited, skipping", handle_str);
                        return None;
                    }
                }
                Some(HandleRecord {
                    cert,
                    zone: (*zone).clone(),
                    epoch_height,
                    offchain_seq,
                    delegate_offchain_seq,
                })
            })
            .collect();

        let mut result = self.store.update_handles(&updates)?;
        result.skipped += preskipped;
        result.gated += gated;
        tracing::debug!(
            "stored {} handles, skipped {} (existing zone was better)",
            result.stored,
            result.skipped
        );

        if !revs.is_empty() {
            let rev_refs: Vec<(&str, &str)> = revs
                .iter()
                .map(|(id, name)| (id.as_str(), name.as_str()))
                .collect();
            self.store.set_revs(&rev_refs)?;
        }

        // Update address index for stored handles
        for handle in &result.stored_handles {
            if let Some((rev, addrs)) = addr_index.get(handle) {
                let refs: Vec<(&str, &str)> = addrs
                    .iter()
                    .map(|(n, a)| (n.as_str(), a.as_str()))
                    .collect();
                self.store.set_addrs(handle, rev, &refs)?;
            }
        }

        Ok(result)
    }
}

/// Check whether a client's cached epoch hint lets it verify the served zone
/// without the relay including the ZK receipt.
///
/// libveritas restores a stripped receipt from the client's cache only when the
/// served commitment's `state_root` matches the cached one (see
/// `Zone::update_receipt_cache`), so the relay may drop the receipt only when the
/// roots match. If the client's cached commitment is strictly newer than the one
/// being served, the client discards the served (older) zone in favor of its
/// cache and never asks for the receipt, so dropping it is safe there too.
fn epoch_hint_verifiable_by(hint: &resolver::EpochHint, zone: &Zone) -> bool {
    if let ProvableOption::Exists { value: c } = &zone.commitment {
        if hint.height > c.onchain.block_height {
            return true; // client already verified a newer commitment
        }
        hint.height == c.onchain.block_height && hint.root == hex::encode(c.onchain.state_root)
    } else {
        false
    }
}
