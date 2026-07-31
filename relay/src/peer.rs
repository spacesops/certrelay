use std::{
    collections::HashMap,
    net::IpAddr,
    time::{Duration, Instant},
};

pub use resolver::{PeerInfo, capabilities};

/// Syntactic policy check for a peer URL: http(s) scheme, a host, no
/// credentials, and — unless `allow_private` — no private/reserved IP literal.
/// Plain http and bare-IP URLs are allowed by design: peer data re-verifies
/// locally, so the network must not depend on DNS/CA infrastructure.
/// DNS-named hosts are additionally resolve-checked in [`peer_addr_allowed`].
pub fn validate_peer_url(raw: &str, allow_private: bool) -> Result<(), &'static str> {
    let parsed = url::Url::parse(raw).map_err(|_| "invalid url")?;
    if parsed.scheme() != "http" && parsed.scheme() != "https" {
        return Err("url scheme must be http or https");
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("url must not contain credentials");
    }
    match parsed.host() {
        None => Err("url must have a host"),
        Some(url::Host::Domain(_)) => Ok(()),
        Some(url::Host::Ipv4(ip)) if allow_private || ip_is_public(&IpAddr::V4(ip)) => Ok(()),
        Some(url::Host::Ipv6(ip)) if allow_private || ip_is_public(&IpAddr::V6(ip)) => Ok(()),
        Some(_) => Err("url resolves to a private address"),
    }
}

/// Resolve a peer URL's host and check every address against the IP policy.
/// Returns false on resolution failure — an unresolvable peer can re-announce.
pub async fn peer_addr_allowed(raw: &str, allow_private: bool) -> bool {
    if validate_peer_url(raw, allow_private).is_err() {
        return false;
    }
    if allow_private {
        return true;
    }
    let Ok(parsed) = url::Url::parse(raw) else {
        return false;
    };
    match parsed.host() {
        Some(url::Host::Domain(domain)) => {
            let port = parsed.port_or_known_default().unwrap_or(443);
            match tokio::net::lookup_host((domain, port)).await {
                Ok(mut addrs) => addrs.all(|a| ip_is_public(&a.ip())),
                Err(_) => false,
            }
        }
        Some(url::Host::Ipv4(_)) | Some(url::Host::Ipv6(_)) => true, // checked above
        None => false,
    }
}

/// True if the address is publicly routable (not private, loopback,
/// link-local, CGNAT, documentation, or otherwise reserved).
pub(crate) fn ip_is_public(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
                || o[0] == 0
                || (o[0] == 100 && (o[1] & 0xc0) == 64)) // CGNAT 100.64/10
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return ip_is_public(&IpAddr::V4(v4));
            }
            let s = v6.segments();
            !(v6.is_loopback()
                || v6.is_unspecified()
                || (s[0] & 0xfe00) == 0xfc00 // unique local fc00::/7
                || (s[0] & 0xffc0) == 0xfe80 // link-local fe80::/10
                || (s[0] == 0x2001 && s[1] == 0xdb8)) // documentation
        }
    }
}

pub struct PeerTable {
    /// IP -> announced URL (one slot per IP)
    ip_slots: HashMap<IpAddr, String>,
    /// URL -> unverified peer info
    unverified: HashMap<String, PeerEntry>,
    /// URL -> verified peer info
    verified: HashMap<String, PeerEntry>,
    config: PeerConfig,
    /// Our own URL (never returned in peer lists)
    self_url: Option<String>,
}

pub struct PeerConfig {
    pub max_unverified: usize,
    pub max_verified: usize,
    pub verified_ttl: Duration,
    /// How long an unverified entry may sit without a successful health
    /// check or a fresh announcement before it is dropped. Generous by
    /// design: a peer offline for days can still come back on its own, and
    /// one that misses the window simply re-announces.
    pub unverified_ttl: Duration,
}

impl Default for PeerConfig {
    fn default() -> Self {
        Self {
            max_unverified: 1_000,
            max_verified: 1_00,
            verified_ttl: Duration::from_secs(600),
            unverified_ttl: Duration::from_secs(3 * 24 * 3600),
        }
    }
}

/// Consecutive sync failures before a verified peer is demoted back to
/// unverified (it must re-pass health checks and stops consuming sync slots).
const SYNC_FAILURES_BEFORE_DEMOTE: u32 = 3;

struct PeerEntry {
    source_ip: IpAddr,
    capabilities: u32,
    last_seen: Instant,
    /// When this entry (re-)entered its current table. Unlike `last_seen`,
    /// never bumped by failed checks — it anchors the unverified expiry.
    added: Instant,
    /// Consecutive sync failures while verified; any success resets it.
    sync_failures: u32,
}

#[derive(Debug, PartialEq)]
pub enum AnnounceResult {
    /// Already verified and still fresh
    AlreadyVerified,
    /// Added or refreshed as unverified
    Unverified,
}

impl PeerTable {
    pub fn new(config: PeerConfig) -> Self {
        Self {
            ip_slots: HashMap::new(),
            unverified: HashMap::new(),
            verified: HashMap::new(),
            config,
            self_url: None,
        }
    }

    /// Set our own URL so we never gossip to ourselves.
    pub fn set_self_url(&mut self, url: &str) {
        self.self_url = Some(normalize_url(url));
    }

    fn is_self(&self, url: &str) -> bool {
        self.self_url.as_ref().is_some_and(|s| s == url)
    }

    /// Announce a peer.
    /// One slot per IP. Deduplicated by URL.
    pub fn announce(&mut self, peer: &PeerInfo) -> AnnounceResult {
        let url = normalize_url(&peer.url);
        let source_ip = peer.source_ip;
        let capabilities = peer.capabilities;

        // Never add ourselves
        if self.is_self(&url) {
            return AnnounceResult::AlreadyVerified;
        }

        let now = Instant::now();

        // Already verified and fresh? Just refresh.
        if let Some(peer) = self.verified.get_mut(&url)
            && now.duration_since(peer.last_seen) < self.config.verified_ttl
        {
            peer.last_seen = now;
            peer.capabilities = capabilities;
            return AnnounceResult::AlreadyVerified;
        }

        // An unspecified source IP means the announcement is unattributed
        // (e.g. learned from a peers list, where the claimed IP is
        // remote-controlled and unverifiable). Such entries never own an IP
        // slot and never displace anything: they only fill spare capacity.
        let unattributed = source_ip.is_unspecified();
        if unattributed {
            if !self.unverified.contains_key(&url)
                && self.unverified.len() >= self.config.max_unverified
            {
                return AnnounceResult::Unverified; // table full, don't evict for it
            }
        } else {
            // Remove this IP's previous announcement if it was a different URL
            if let Some(old_url) = self.ip_slots.get(&source_ip)
                && *old_url != url
            {
                let old_url = old_url.clone();
                // Remove old URL from unverified if no other IP points to it
                let other_refs = self
                    .ip_slots
                    .iter()
                    .any(|(ip, u)| *ip != source_ip && *u == old_url);
                if !other_refs {
                    self.unverified.remove(&old_url);
                }
            }

            // Assign this IP's slot
            self.ip_slots.insert(source_ip, url.clone());
        }

        // Upsert into unverified. A fresh announcement is liveness evidence,
        // so it also renews the expiry anchor.
        self.unverified
            .entry(url)
            .and_modify(|e| {
                e.last_seen = now;
                e.added = now;
                e.capabilities = capabilities;
            })
            .or_insert(PeerEntry {
                source_ip,
                capabilities,
                last_seen: now,
                added: now,
                sync_failures: 0,
            });

        // Evict oldest if over capacity
        while self.unverified.len() > self.config.max_unverified {
            if let Some(oldest) = self
                .unverified
                .iter()
                .min_by_key(|(_, e)| e.last_seen)
                .map(|(url, _)| url.clone())
            {
                self.unverified.remove(&oldest);
                self.ip_slots.retain(|_, u| *u != oldest);
            } else {
                break;
            }
        }

        AnnounceResult::Unverified
    }

    /// Mark a URL as alive (call after successful health check or gossip send).
    /// Moves from unverified to verified, or refreshes if already verified.
    pub fn mark_alive(&mut self, url: &str) {
        let url = normalize_url(url);
        let now = Instant::now();

        // If already verified, just refresh
        if let Some(entry) = self.verified.get_mut(&url) {
            entry.last_seen = now;
            entry.sync_failures = 0;
            return;
        }

        // Move from unverified to verified
        let Some(entry) = self.unverified.remove(&url) else {
            return; // Unknown peer, ignore
        };

        self.ip_slots.retain(|_, u| *u != url);

        self.verified.insert(
            url,
            PeerEntry {
                source_ip: entry.source_ip,
                capabilities: entry.capabilities,
                last_seen: now,
                added: now,
                sync_failures: 0,
            },
        );

        // Evict oldest verified if over capacity
        while self.verified.len() > self.config.max_verified {
            if let Some(oldest) = self
                .verified
                .iter()
                .min_by_key(|(_, e)| e.last_seen)
                .map(|(url, _)| url.clone())
            {
                self.verified.remove(&oldest);
            } else {
                break;
            }
        }
    }

    /// True if the URL is a verified, non-stale peer.
    pub fn is_verified(&self, url: &str) -> bool {
        let url = normalize_url(url);
        self.verified
            .get(&url)
            .is_some_and(|e| Instant::now().duration_since(e.last_seen) < self.config.verified_ttl)
    }

    /// Remove a peer entirely (e.g., its address failed the IP policy).
    pub fn remove(&mut self, url: &str) {
        let url = normalize_url(url);
        self.unverified.remove(&url);
        self.verified.remove(&url);
        self.ip_slots.retain(|_, u| *u != url);
    }

    /// Make a locally-configured seed URL a standing candidate. Idempotent:
    /// inserts into unverified only when the URL is not ourselves and not
    /// already known (either table). Called every maintenance tick, so
    /// discovery never depends on a bootstrap peer's list being populated at
    /// the right moment — even a lost seed entry comes right back.
    pub fn ensure_seed(&mut self, url: &str) {
        let url = normalize_url(url);
        if self.is_self(&url) || self.verified.contains_key(&url) {
            return;
        }
        let now = Instant::now();
        // Seeds are unattributed (no real source IP is known behind their
        // public proxied URL) but first-class: unlike propagated entries they
        // may displace the oldest entry when the table is full.
        self.unverified.entry(url).or_insert(PeerEntry {
            source_ip: IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            capabilities: 0,
            last_seen: now,
            added: now,
            sync_failures: 0,
        });
        while self.unverified.len() > self.config.max_unverified {
            if let Some(oldest) = self
                .unverified
                .iter()
                .min_by_key(|(_, e)| e.last_seen)
                .map(|(url, _)| url.clone())
            {
                self.unverified.remove(&oldest);
                self.ip_slots.retain(|_, u| *u != oldest);
            } else {
                break;
            }
        }
    }

    /// Record a failed sync attempt from a peer.
    ///
    /// Unverified: bumped to the back of the health-check line. Verified:
    /// counted, and after `SYNC_FAILURES_BEFORE_DEMOTE` consecutive failures
    /// the peer is demoted to unverified — a peer whose `/health` answers but
    /// whose `/sync` is broken must not keep winning sync slots. Any sync
    /// success or verified refresh resets the counter.
    pub fn record_sync_failure(&mut self, url: &str) {
        let url = normalize_url(url);
        let now = Instant::now();
        if let Some(entry) = self.unverified.get_mut(&url) {
            entry.last_seen = now;
            return;
        }
        let Some(entry) = self.verified.get_mut(&url) else {
            return;
        };
        entry.sync_failures += 1;
        if entry.sync_failures >= SYNC_FAILURES_BEFORE_DEMOTE {
            let mut entry = self.verified.remove(&url).unwrap();
            tracing::info!(
                "{}: demoting after {} sync failures",
                url,
                entry.sync_failures
            );
            entry.last_seen = now;
            entry.added = now;
            entry.sync_failures = 0;
            self.unverified.insert(url, entry);
        }
    }

    /// Drop unverified entries with no fresh announcement or successful check
    /// within `unverified_ttl`. A peer that comes back later re-announces.
    pub fn expire_unverified(&mut self) {
        let now = Instant::now();
        self.unverified
            .retain(|_, e| now.duration_since(e.added) < self.config.unverified_ttl);
        self.ip_slots
            .retain(|_, u| self.unverified.contains_key(u) || self.verified.contains_key(u));
    }

    /// Get list of verified, non-stale peer URLs.
    pub fn peers(&self) -> Vec<&str> {
        let now = Instant::now();
        self.verified
            .iter()
            .filter(|(url, e)| {
                !self.is_self(url) && now.duration_since(e.last_seen) < self.config.verified_ttl
            })
            .map(|(url, _)| url.as_str())
            .collect()
    }

    /// Get list of verified, non-stale peers with full info.
    pub fn peers_info(&self) -> Vec<PeerInfo> {
        let now = Instant::now();
        self.verified
            .iter()
            .filter(|(url, e)| {
                !self.is_self(url) && now.duration_since(e.last_seen) < self.config.verified_ttl
            })
            .map(|(url, e)| PeerInfo {
                source_ip: e.source_ip,
                url: url.clone(),
                capabilities: e.capabilities,
            })
            .collect()
    }

    /// Pick a candidate from unverified to health-check.
    /// Returns the least-recently-seen URL (tried longest ago or never tried).
    pub fn next_candidate(&self) -> Option<&str> {
        self.unverified
            .iter()
            .min_by_key(|(_, e)| e.last_seen)
            .map(|(url, _)| url.as_str())
    }

    /// Up to `n` unverified candidates to health-check, least-recently-seen
    /// first, so simultaneous expiries don't drain the verified list one
    /// candidate at a time.
    pub fn next_candidates(&self, n: usize) -> Vec<String> {
        let mut entries: Vec<(&String, Instant)> = self
            .unverified
            .iter()
            .map(|(url, e)| (url, e.last_seen))
            .collect();
        entries.sort_by_key(|(_, t)| *t);
        entries
            .into_iter()
            .take(n)
            .map(|(u, _)| u.clone())
            .collect()
    }

    /// Verified peers past half their TTL: due for a proactive liveness
    /// refresh so quiet periods (no sync traffic) don't expire them.
    pub fn refresh_candidates(&self) -> Vec<String> {
        let now = Instant::now();
        self.verified
            .iter()
            .filter(|(_, e)| now.duration_since(e.last_seen) >= self.config.verified_ttl / 2)
            .map(|(url, _)| url.clone())
            .collect()
    }

    /// True if we need more verified peers.
    pub fn needs_peers(&self) -> bool {
        let active = self
            .verified
            .values()
            .filter(|e| Instant::now().duration_since(e.last_seen) < self.config.verified_ttl)
            .count();
        active < self.config.max_verified / 2
    }

    /// Move expired verified peers back to unverified so they can be re-checked.
    pub fn demote_expired(&mut self) {
        let now = Instant::now();
        let expired: Vec<(String, PeerEntry)> = self
            .verified
            .extract_if(|_, e| now.duration_since(e.last_seen) >= self.config.verified_ttl)
            .collect();
        for (url, mut entry) in expired {
            entry.added = now; // fresh expiry anchor in the new table
            entry.sync_failures = 0;
            self.unverified.entry(url).or_insert(entry);
        }
    }

    pub fn verified_count(&self) -> usize {
        self.verified.len()
    }

    pub fn unverified_count(&self) -> usize {
        self.unverified.len()
    }
}

/// Canonicalize a peer URL so trivial variants map to one table identity:
/// lowercased scheme/host, default ports elided, trailing slashes stripped
/// (the url crate handles the first two). Unparseable input falls back to
/// trim-only so existing behavior is preserved for it.
pub(crate) fn normalize_url(url: &str) -> String {
    match url::Url::parse(url.trim()) {
        Ok(parsed) => parsed.as_str().trim_end_matches('/').to_string(),
        Err(_) => url.trim().trim_end_matches('/').to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> PeerConfig {
        PeerConfig {
            max_unverified: 3,
            max_verified: 2,
            verified_ttl: Duration::from_secs(600),
            unverified_ttl: Duration::from_secs(3 * 24 * 3600),
        }
    }

    fn ip(last: u8) -> IpAddr {
        IpAddr::from([10, 0, 0, last])
    }

    fn peer(last: u8, url: &str) -> PeerInfo {
        PeerInfo {
            source_ip: ip(last),
            url: url.to_string(),
            capabilities: 0,
        }
    }

    #[test]
    fn announce_and_list() {
        let mut table = PeerTable::new(config());
        table.announce(&peer(1, "https://relay1.com"));
        table.announce(&peer(2, "https://relay2.com"));

        assert_eq!(table.unverified_count(), 2);
        assert_eq!(table.peers().len(), 0);

        table.mark_alive("https://relay1.com");
        assert_eq!(table.unverified_count(), 1);
        assert_eq!(table.peers(), vec!["https://relay1.com"]);
    }

    #[test]
    fn one_slot_per_ip() {
        let mut table = PeerTable::new(config());
        table.announce(&peer(1, "https://relay1.com"));
        table.announce(&peer(1, "https://relay2.com"));

        // relay1 should be gone since ip(1) switched to relay2
        assert_eq!(table.unverified_count(), 1);
        assert!(table.next_candidate().unwrap().contains("relay2"));
    }

    #[test]
    fn dedup_same_url_different_ips() {
        let mut table = PeerTable::new(config());
        table.announce(&peer(1, "https://relay1.com"));
        table.announce(&peer(2, "https://relay1.com"));

        // Same URL, only one unverified entry
        assert_eq!(table.unverified_count(), 1);
    }

    #[test]
    fn shared_url_not_removed_when_one_ip_switches() {
        let mut table = PeerTable::new(config());
        table.announce(&peer(1, "https://relay1.com"));
        table.announce(&peer(2, "https://relay1.com"));

        // ip(1) switches to a new URL
        table.announce(&peer(1, "https://relay2.com"));

        // relay1 still exists because ip(2) still points to it
        assert_eq!(table.unverified_count(), 2);
    }

    #[test]
    fn evicts_oldest_unverified() {
        let mut table = PeerTable::new(config()); // max_unverified = 3
        table.announce(&peer(1, "https://relay1.com"));
        table.announce(&peer(2, "https://relay2.com"));
        table.announce(&peer(3, "https://relay3.com"));
        table.announce(&peer(4, "https://relay4.com"));

        assert_eq!(table.unverified_count(), 3);
    }

    #[test]
    fn sync_failure_sends_unverified_to_back() {
        let mut table = PeerTable::new(config());
        table.announce(&peer(1, "https://relay1.com"));
        table.announce(&peer(2, "https://relay2.com"));

        // relay1 announced first, so it's the next candidate
        assert!(table.next_candidate().unwrap().contains("relay1"));

        // a sync failure bumps it to the back
        table.record_sync_failure("https://relay1.com");
        assert!(table.next_candidate().unwrap().contains("relay2"));
    }

    /// A verified peer whose syncs keep failing is demoted back to unverified
    /// after the threshold — a working /health must not keep a peer with a
    /// broken /sync in the rotation forever. Any success resets the count.
    #[test]
    fn repeated_sync_failures_demote_verified_peer() {
        let mut table = PeerTable::new(config());
        table.announce(&peer(1, "https://relay1.com"));
        table.mark_alive("https://relay1.com");

        // Failures below the threshold, then a success: counter resets.
        table.record_sync_failure("https://relay1.com");
        table.record_sync_failure("https://relay1.com");
        table.mark_alive("https://relay1.com");
        table.record_sync_failure("https://relay1.com");
        table.record_sync_failure("https://relay1.com");
        assert_eq!(table.peers(), vec!["https://relay1.com"]);

        // Third consecutive failure: demoted, must re-verify.
        table.record_sync_failure("https://relay1.com");
        assert!(table.peers().is_empty());
        assert_eq!(table.unverified_count(), 1);

        // It can come back through the normal health-check path.
        table.mark_alive("https://relay1.com");
        assert_eq!(table.peers(), vec!["https://relay1.com"]);
    }

    /// Seeds are standing candidates: idempotent insert, never duplicating a
    /// verified entry and never adding ourselves.
    #[test]
    fn ensure_seed_is_idempotent_and_skips_self_and_verified() {
        let mut table = PeerTable::new(config());
        table.set_self_url("https://me.com");

        table.ensure_seed("https://me.com");
        assert_eq!(table.unverified_count(), 0);

        table.ensure_seed("https://seed1.com/");
        table.ensure_seed("https://seed1.com");
        assert_eq!(table.unverified_count(), 1);

        table.mark_alive("https://seed1.com");
        table.ensure_seed("https://seed1.com");
        assert_eq!(table.unverified_count(), 0);
        assert_eq!(table.peers(), vec!["https://seed1.com"]);

        // A full table still admits a seed (displacing the oldest) — unlike
        // unattributed peers-list entries, seeds are first-class.
        let mut table = PeerTable::new(config()); // max_unverified = 3
        table.announce(&peer(1, "https://relay1.com"));
        table.announce(&peer(2, "https://relay2.com"));
        table.announce(&peer(3, "https://relay3.com"));
        table.ensure_seed("https://seed1.com");
        assert_eq!(table.unverified_count(), 3);
        assert!(table.next_candidates(3).iter().any(|u| u.contains("seed1")));
    }

    /// Unverified entries expire after `unverified_ttl` with no fresh
    /// announcement; failed checks (which bump `last_seen`) don't keep a dead
    /// entry alive, while a re-announce does.
    #[test]
    fn unverified_entries_expire() {
        let mut table = PeerTable::new(PeerConfig {
            unverified_ttl: Duration::ZERO, // everything is instantly expired
            ..config()
        });
        table.announce(&peer(1, "https://relay1.com"));
        table.record_sync_failure("https://relay1.com"); // bumps last_seen only
        table.expire_unverified();
        assert_eq!(table.unverified_count(), 0);

        // A verified peer is untouched by unverified expiry.
        table.announce(&peer(2, "https://relay2.com"));
        table.mark_alive("https://relay2.com");
        table.expire_unverified();
        assert_eq!(table.peers(), vec!["https://relay2.com"]);
    }

    /// Trivial URL variants (host case, default port, trailing slash) map to
    /// one table identity.
    #[test]
    fn normalize_url_canonicalizes_variants() {
        for v in [
            "https://Relay1.COM",
            "https://relay1.com:443",
            "https://relay1.com/",
            "  https://relay1.com  ",
            "HTTPS://relay1.com",
        ] {
            assert_eq!(normalize_url(v), "https://relay1.com", "variant: {v}");
        }
        // Non-default ports and paths survive.
        assert_eq!(
            normalize_url("http://relay1.com:7778/base/"),
            "http://relay1.com:7778/base"
        );

        let mut table = PeerTable::new(config());
        table.announce(&peer(1, "https://Relay1.com/"));
        table.announce(&peer(2, "https://relay1.com:443"));
        assert_eq!(table.unverified_count(), 1);
    }

    #[test]
    fn already_verified_refreshes() {
        let mut table = PeerTable::new(config());
        table.announce(&peer(1, "https://relay1.com"));
        table.mark_alive("https://relay1.com");

        let result = table.announce(&peer(1, "https://relay1.com"));
        assert_eq!(result, AnnounceResult::AlreadyVerified);
    }

    #[test]
    fn url_policy() {
        // Allowed: http and https, domains and public IP literals, with ports
        for ok in [
            "https://relay.example.com",
            "http://relay.example.com:7778",
            "http://8.8.8.8:7778",
        ] {
            assert!(validate_peer_url(ok, false).is_ok(), "{ok} should pass");
        }

        // Rejected without allow_private
        for bad in [
            "http://127.0.0.1:7778",
            "http://10.0.0.5",
            "http://192.168.1.10:7778",
            "http://169.254.169.254/latest/meta-data",
            "http://100.64.0.1",
            "http://[::1]:7778",
            "http://[fc00::1]",
            "ftp://relay.example.com",
            "file:///etc/passwd",
            "http://user:pass@relay.example.com",
            "not a url",
        ] {
            assert!(validate_peer_url(bad, false).is_err(), "{bad} should fail");
        }

        // allow_private admits loopback/private, still rejects bad schemes
        assert!(validate_peer_url("http://127.0.0.1:7778", true).is_ok());
        assert!(validate_peer_url("ftp://127.0.0.1", true).is_err());
    }

    #[test]
    fn remove_clears_everywhere() {
        let mut table = PeerTable::new(config());
        table.announce(&peer(1, "https://relay1.com"));
        table.announce(&peer(2, "https://relay2.com"));
        table.mark_alive("https://relay2.com");

        table.remove("https://relay1.com");
        table.remove("https://relay2.com");
        assert_eq!(table.unverified_count(), 0);
        assert_eq!(table.verified_count(), 0);

        // Re-announcing after removal works (ip slot was freed)
        table.announce(&peer(1, "https://relay1.com"));
        assert_eq!(table.unverified_count(), 1);
    }

    fn unattributed(url: &str) -> PeerInfo {
        PeerInfo {
            source_ip: IpAddr::from([0, 0, 0, 0]),
            url: url.to_string(),
            capabilities: 0,
        }
    }

    /// Unattributed announcements (unspecified source IP, e.g. peers-list
    /// propagation) never own an IP slot: they coexist instead of evicting
    /// each other, and never displace an attributed entry.
    #[test]
    fn unattributed_announces_claim_no_slot() {
        let mut table = PeerTable::new(config());
        table.announce(&peer(1, "https://relay1.com"));
        table.announce(&unattributed("https://seed1.com"));
        table.announce(&unattributed("https://seed2.com"));

        // No slot fights: all three coexist.
        assert_eq!(table.unverified_count(), 3);

        // An attributed announce from a fresh IP doesn't collide with them.
        table.announce(&peer(2, "https://relay1.com"));
        assert_eq!(table.unverified_count(), 3);
    }

    /// A full unverified table drops unattributed announcements instead of
    /// letting them evict attributed entries; attributed announcements still
    /// evict the oldest as before.
    #[test]
    fn unattributed_never_evicts_at_capacity() {
        let mut table = PeerTable::new(config()); // max_unverified = 3
        table.announce(&peer(1, "https://relay1.com"));
        table.announce(&peer(2, "https://relay2.com"));
        table.announce(&peer(3, "https://relay3.com"));

        table.announce(&unattributed("https://evil.com"));
        assert_eq!(table.unverified_count(), 3);
        assert!(!table.next_candidates(3).iter().any(|u| u.contains("evil")));

        // Refreshing an unattributed entry that's already present still works.
        table.announce(&unattributed("https://relay2.com"));
        assert_eq!(table.unverified_count(), 3);

        // An attributed announce still rotates the table normally.
        table.announce(&peer(4, "https://relay4.com"));
        assert_eq!(table.unverified_count(), 3);
        assert!(
            table
                .next_candidates(3)
                .iter()
                .any(|u| u.contains("relay4"))
        );
    }

    #[test]
    fn peers_info_includes_capabilities() {
        let mut table = PeerTable::new(config());
        let p = PeerInfo {
            source_ip: ip(1),
            url: "https://relay1.com".to_string(),
            capabilities: 0x1,
        };
        table.announce(&p);
        table.mark_alive("https://relay1.com");

        let peers = table.peers_info();
        assert_eq!(peers.len(), 1);
        assert!(peers[0].has_capability(0x1));
        assert_eq!(peers[0].source_ip, ip(1));
    }
}
