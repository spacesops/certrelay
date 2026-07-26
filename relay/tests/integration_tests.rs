use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use libveritas::Veritas;
use libveritas::msg::QueryContext;
use libveritas_testutil::fixture::*;
use relay::anchor::AnchorSets;
use relay::{
    AppState, Config, ExtendedNetwork, Handler, PeerInfo, Relay, SqliteStore, SyncConfig,
    sync_with_peer,
};
use resolver::{AnchorSet, HintsResponse};
use spaces_protocol::slabel::SLabel;

// ─────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────

/// Build a Veritas that includes the current root anchor so the tip
/// matches the current chain height (important after Finalize steps).
fn build_veritas(state: &ChainState) -> Veritas {
    let mut anchors = state.anchors.clone();
    anchors.push(state.chain.current_root_anchor());
    anchors.sort_by(|a, b| b.block.height.cmp(&a.block.height));
    anchors.dedup_by_key(|a| a.block.height);
    Veritas::new().with_anchors(anchors).unwrap()
}

/// Create a Handler wired to the test chain state with an in-memory store.
fn setup_handler(state: &ChainState) -> Handler {
    let veritas = build_veritas(state);
    let store = SqliteStore::in_memory().unwrap();
    let mut handler = Handler::new(veritas, store, AnchorSets::from_anchors(vec![]));
    handler.dev_mode = true;
    handler
}

/// Replace the handler's Veritas with one built from the current chain state.
fn sync_veritas(handler: &Handler, state: &ChainState) {
    *handler.veritas.write().unwrap() = build_veritas(state);
}

/// Collect the test anchors from a ChainState.
fn test_anchors(state: &ChainState) -> Vec<spaces_nums::RootAnchor> {
    let mut anchors = state.anchors.clone();
    anchors.push(state.chain.current_root_anchor());
    anchors.sort_by(|a, b| b.block.height.cmp(&a.block.height));
    anchors.dedup_by_key(|a| a.block.height);
    anchors
}

/// Start a relay HTTP server on a random port.
/// Returns (base_url, Arc<AppState>).
async fn start_relay(chain_state: &ChainState) -> (String, Arc<AppState>) {
    let mut config = Config::new(PathBuf::from("/tmp/relay-test"), ExtendedNetwork::Testnet4);
    config.db_path = PathBuf::from(":memory:");
    config.spaced_url = Some("http://127.0.0.1:1".into());
    config.anchors = test_anchors(chain_state);
    config.dev_mode = true;
    config.allow_private_peers = true;

    let relay = Relay::new(config).unwrap();
    *relay.state().handler.veritas.write().unwrap() = build_veritas(chain_state);
    *relay.state().handler.anchor_store.lock().unwrap() =
        AnchorSets::from_anchors(test_anchors(chain_state));

    let state = relay.state().clone();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("http://{}", addr);

    tokio::spawn(async move {
        relay.run(listener).await.unwrap();
    });

    (url, state)
}

/// Chain proof matching the current test chain state (what a relay's own
/// spaced would produce for any request).
fn chain_proof(state: &ChainState) -> libveritas::msg::ChainProof {
    state.message(vec![]).chain
}

/// Start a relay whose SpacedClient is mocked from the test chain state, so
/// sync ingestion can build chain proofs "locally".
async fn start_relay_mocked(chain_state: &ChainState) -> (String, Arc<AppState>) {
    let mut config = Config::new(PathBuf::from("/tmp/relay-test"), ExtendedNetwork::Testnet4);
    config.db_path = PathBuf::from(":memory:");
    config.spaced_url = Some("http://127.0.0.1:1".into());
    config.anchors = test_anchors(chain_state);
    config.dev_mode = true;
    config.allow_private_peers = true;
    config.mock_chain = Some((chain_proof(chain_state), test_anchors(chain_state)));

    let relay = Relay::new(config).unwrap();
    *relay.state().handler.veritas.write().unwrap() = build_veritas(chain_state);
    *relay.state().handler.anchor_store.lock().unwrap() =
        AnchorSets::from_anchors(test_anchors(chain_state));

    let state = relay.state().clone();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("http://{}", addr);

    tokio::spawn(async move {
        relay.run(listener).await.unwrap();
    });

    (url, state)
}

/// Build a QueryContext from the handler's store (mirrors what handler does internally).
fn build_ctx(handler: &Handler, spaces: &[SLabel]) -> QueryContext {
    let mut ctx = QueryContext::new();
    let space_refs: Vec<&SLabel> = spaces.iter().collect();
    let zones = handler.store.get_zones(&space_refs).unwrap();
    for z in zones {
        ctx.add_zone(z);
    }
    ctx
}

// ─────────────────────────────────────────────────────────────────────────
// Handler-level tests
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn test_single_commit_finalized() {
    let mut state = ChainState::new();
    let mut runner = FixtureRunner::new(&mut state, single_commit_finalized());
    runner.run(&mut state);

    let handler = setup_handler(&state);
    let bundle = runner.build_bundle();
    let msg = state.message(vec![bundle]);
    handler.handle_message(msg).unwrap();

    for name in ["alice", "bob"] {
        let key = format!("{}@sovereign", name);
        assert!(
            handler.store.get_handle(&key).unwrap().is_some(),
            "{} should be stored",
            key
        );
    }

    assert!(
        handler.store.get_handle("@sovereign").unwrap().is_some(),
        "root handle should be stored"
    );
}

#[test]
fn test_kitchen_sink() {
    let mut state = ChainState::new();
    let mut runner = FixtureRunner::new(&mut state, kitchen_sink());
    runner.run(&mut state);

    let handler = setup_handler(&state);
    let bundle = runner.build_bundle();
    let msg = state.message(vec![bundle]);
    handler.handle_message(msg).unwrap();

    for name in ["alice", "bob", "charlie", "dave", "eve", "frank"] {
        let key = format!("{}@kitchensink", name);
        assert!(
            handler.store.get_handle(&key).unwrap().is_some(),
            "{} should be stored",
            key
        );
    }

    for name in ["grace", "heidi"] {
        let key = format!("{}@kitchensink", name);
        assert!(
            handler.store.get_handle(&key).unwrap().is_some(),
            "{} (staged) should be stored",
            key
        );
    }

    assert!(
        handler.store.get_handle("@kitchensink").unwrap().is_some(),
        "root handle should be stored"
    );
}

/// Submit messages incrementally and verify the relay always stores the best
/// zone for each handle.  The relay's update_handles uses is_better_than to
/// keep fresher zones, so a later message with a worse zone (e.g. Dependent
/// replacing Pending) is correctly rejected.  We mirror that logic here.
#[test]
fn test_incremental_zone_replacement() {
    use libveritas::Zone;
    use std::collections::HashMap;

    let mut chain_state = ChainState::new();
    let mut runner = FixtureRunner::new(&mut chain_state, kitchen_sink());
    let handler = setup_handler(&chain_state);

    // Track the best known zone for each handle across steps.
    let mut best_zones: HashMap<String, Vec<u8>> = HashMap::new();

    while let Some(_step) = runner.run_next(&mut chain_state) {
        sync_veritas(&handler, &chain_state);

        let bundle = runner.build_bundle();
        let msg = chain_state.message(vec![bundle]);

        // Build the same context the handler will use
        let spaces: Vec<SLabel> = msg.spaces.iter().map(|s| s.subject.clone()).collect();
        let ctx = build_ctx(&handler, &spaces);

        // Verify manually to get expected zones
        let veritas = build_veritas(&chain_state);
        let verified = veritas
            .verify_with_options(&ctx, msg.clone(), libveritas::VERIFY_DEV_MODE)
            .unwrap();

        // Update best_zones: only replace when the new zone is strictly better
        for zone in &verified.zones {
            let key = zone.canonical.to_string();
            let new_bytes = borsh::to_vec(zone).unwrap();
            let dominated = best_zones.get(&key).map_or(true, |existing_bytes| {
                let existing: Zone = borsh::from_slice(existing_bytes).unwrap();
                zone.is_better_than(&existing).unwrap_or(false)
            });
            if dominated {
                best_zones.insert(key, new_bytes);
            }
        }

        // Submit to handler (uses the same context + is_better_than internally)
        handler.handle_message(msg).unwrap();

        // Query back and compare — store should have the best zone seen so far
        for (handle_key, expected_bytes) in &best_zones {
            let stored = handler
                .store
                .get_handle(handle_key)
                .unwrap()
                .unwrap_or_else(|| panic!("{} should be stored", handle_key));

            let stored_bytes = borsh::to_vec(&stored.zone).unwrap();
            assert_eq!(
                &stored_bytes, expected_bytes,
                "stored zone for {} should match best known zone",
                handle_key
            );
        }
    }
}

#[test]
fn test_all_fixtures() {
    let fixtures: Vec<(&str, Fixture, Vec<&str>)> = vec![
        ("@staged", staged_only(), vec!["alice", "bob"]),
        ("@pending", single_commit_pending(), vec!["alice", "bob"]),
        (
            "@sovereign",
            single_commit_finalized(),
            vec!["alice", "bob"],
        ),
        (
            "@two-pending",
            two_commits_second_pending(),
            vec!["alice", "bob", "charlie"],
        ),
        (
            "@two-finalized",
            two_commits_both_finalized(),
            vec!["alice", "bob", "charlie"],
        ),
        (
            "@finalized-staged",
            finalized_with_staged(),
            vec!["alice", "bob"],
        ),
    ];

    for (space, fixture, expected_handles) in fixtures {
        let mut state = ChainState::new();
        let mut runner = FixtureRunner::new(&mut state, fixture);
        runner.run(&mut state);

        let handler = setup_handler(&state);
        let bundle = runner.build_bundle();
        let msg = state.message(vec![bundle]);
        handler.handle_message(msg).unwrap();

        for name in expected_handles {
            let key = format!("{}{}", name, space);
            assert!(
                handler.store.get_handle(&key).unwrap().is_some(),
                "{} should be stored for fixture {}",
                key,
                space
            );
        }

        assert!(
            handler.store.get_handle(space).unwrap().is_some(),
            "root {} should be stored",
            space
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────
// HTTP-level tests
// ─────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_relay_accepts_message() {
    let mut state = ChainState::new();
    let mut runner = FixtureRunner::new(&mut state, single_commit_finalized());
    runner.run(&mut state);

    let (url, app_state) = start_relay(&state).await;

    let bundle = runner.build_bundle();
    let msg = state.message(vec![bundle]);
    let msg_bytes = msg.to_bytes();

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/message", url))
        .body(msg_bytes)
        .header("content-type", "application/octet-stream")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status().as_u16(), 200);
    let body = resp.text().await.unwrap();
    assert_eq!(body, "ok");

    let record = app_state
        .handler
        .store
        .get_handle("alice@sovereign")
        .unwrap();
    assert!(
        record.is_some(),
        "alice should be stored after HTTP submission"
    );
}

#[tokio::test]
async fn test_broadcast_invalid_bytes() {
    let mut state = ChainState::new();
    let mut runner = FixtureRunner::new(&mut state, single_commit_finalized());
    runner.run(&mut state);

    let (url, _) = start_relay(&state).await;

    let client = reqwest::Client::new();

    // Empty body
    let resp = client
        .post(format!("{}/message", url))
        .body(vec![])
        .header("content-type", "application/octet-stream")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 400);
    let body = resp.text().await.unwrap();
    assert_eq!(body, "invalid message format");

    // Garbage bytes
    let resp = client
        .post(format!("{}/message", url))
        .body(vec![0xDE, 0xAD, 0xBE, 0xEF])
        .header("content-type", "application/octet-stream")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 400);
    let body = resp.text().await.unwrap();
    assert_eq!(body, "invalid message format");
}

#[tokio::test]
async fn test_broadcast_response_readable() {
    let mut state = ChainState::new();
    let mut runner = FixtureRunner::new(&mut state, single_commit_finalized());
    runner.run(&mut state);

    let (url, _) = start_relay(&state).await;

    let bundle = runner.build_bundle();
    let msg = state.message(vec![bundle]);
    let msg_bytes = msg.to_bytes();

    // Use the same reqwest setup as the Fabric client
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/message", url))
        .body(msg_bytes)
        .header("content-type", "application/octet-stream")
        .send()
        .await
        .unwrap();

    let status = resp.status();
    assert!(status.is_success(), "expected 2xx, got {}", status);

    // This is the path that would produce "error decoding response body"
    let body_text = resp
        .text()
        .await
        .expect("should be able to read response body as text");
    assert_eq!(body_text, "ok");
}

#[tokio::test]
async fn test_peers_endpoint() {
    let mut state = ChainState::new();
    let mut runner = FixtureRunner::new(&mut state, single_commit_finalized());
    runner.run(&mut state);

    let (url, app_state) = start_relay(&state).await;

    // Add a peer and mark it alive (peers endpoint only returns verified peers)
    {
        let mut peers = app_state.peers.lock().await;
        peers.announce(&PeerInfo {
            source_ip: IpAddr::from([10, 0, 0, 2]),
            url: "http://relay2.example.com".to_string(),
            capabilities: 0,
        });
        peers.mark_alive("http://relay2.example.com");
    }

    let client = reqwest::Client::new();
    let resp = client.get(format!("{}/peers", url)).send().await.unwrap();

    assert_eq!(resp.status().as_u16(), 200);

    // Should parse as valid JSON array of PeerInfo
    let peers: Vec<PeerInfo> = resp
        .json()
        .await
        .expect("peers response should be valid JSON");
    assert!(!peers.is_empty(), "should have at least one peer");
}

#[tokio::test]
async fn test_anchors_endpoint() {
    let mut state = ChainState::new();
    let mut runner = FixtureRunner::new(&mut state, single_commit_finalized());
    runner.run(&mut state);

    let (url, _) = start_relay(&state).await;

    let client = reqwest::Client::new();

    // HEAD /anchors should return headers
    let resp = client
        .head(format!("{}/anchors", url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);

    let root = resp
        .headers()
        .get("x-anchor-root")
        .expect("should have x-anchor-root header")
        .to_str()
        .unwrap();
    assert!(!root.is_empty(), "anchor root should not be empty");

    let height = resp
        .headers()
        .get("x-anchor-height")
        .expect("should have x-anchor-height header")
        .to_str()
        .unwrap();
    assert!(!height.is_empty(), "anchor height should not be empty");

    // GET /anchors should return valid JSON
    let resp = client.get(format!("{}/anchors", url)).send().await.unwrap();
    assert_eq!(resp.status().as_u16(), 200);

    let anchor_set: AnchorSet = resp
        .json()
        .await
        .expect("anchors response should be valid JSON AnchorSet");
    assert!(!anchor_set.entries.is_empty(), "should have anchor entries");

    // GET /anchors?root=<hex> should return the same set
    let trust_set = libveritas::compute_trust_set(&anchor_set.entries);
    let root_hex = hex::encode(trust_set.id);
    let resp = client
        .get(format!("{}/anchors?root={}", url, root_hex))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);

    let fetched: AnchorSet = resp
        .json()
        .await
        .expect("anchors response with root param should be valid JSON");
    let fetched_trust = libveritas::compute_trust_set(&fetched.entries);
    assert_eq!(
        fetched_trust.id, trust_set.id,
        "fetched anchor root should match"
    );

    // GET /anchors?root=<nonexistent> should return 404
    let fake_root = "cd00e292c5970d3c5e2f0ffa5171e555bc46bfc4faddfb4a418b6840b86e79a3";
    let resp = client
        .get(format!("{}/anchors?root={}", url, fake_root))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 404);
    let body = resp.text().await.unwrap();
    assert_eq!(body, "anchor set not found");
}

#[tokio::test]
async fn test_hints_endpoint() {
    let mut state = ChainState::new();
    let mut runner = FixtureRunner::new(&mut state, single_commit_finalized());
    runner.run(&mut state);

    let (url, _) = start_relay(&state).await;

    // Submit message first
    let bundle = runner.build_bundle();
    let msg = state.message(vec![bundle]);
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/message", url))
        .body(msg.to_bytes())
        .header("content-type", "application/octet-stream")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);

    // Query hints
    let resp = client
        .get(format!(
            "{}/hints?q=alice@sovereign,bob@sovereign,@sovereign",
            url
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);

    let hints: HintsResponse = resp
        .json()
        .await
        .expect("hints response should be valid JSON");
    assert!(!hints.hints.is_empty(), "should have space hints");
    assert!(hints.anchor_tip > 0, "anchor_tip should be > 0");
}

/// Propagation is pull-based: accepting a message must never push it to peers,
/// even when verified peers are present.
#[tokio::test]
async fn test_message_is_not_forwarded_to_peers() {
    let mut state = ChainState::new();
    let mut runner = FixtureRunner::new(&mut state, single_commit_finalized());
    runner.run(&mut state);

    let (url_a, state_a) = start_relay(&state).await;
    let (url_b, state_b) = start_relay(&state).await;

    // Add relay B as a verified peer in relay A
    {
        let mut peers = state_a.peers.lock().await;
        peers.announce(&PeerInfo {
            source_ip: IpAddr::from([10, 0, 0, 2]),
            url: url_b.clone(),
            capabilities: 0,
        });
        peers.mark_alive(&url_b);
    }

    let bundle = runner.build_bundle();
    let msg = state.message(vec![bundle]);
    let msg_bytes = msg.to_bytes();

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/message", url_a))
        .body(msg_bytes)
        .header("content-type", "application/octet-stream")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);

    tokio::time::sleep(Duration::from_millis(500)).await;

    let alice = state_a.handler.store.get_handle("alice@sovereign").unwrap();
    assert!(alice.is_some(), "relay A should have stored the message");

    let root = state_b.handler.store.get_handle("@sovereign").unwrap();
    assert!(root.is_none(), "relay B must not receive pushed messages");

    let alice = state_b.handler.store.get_handle("alice@sovereign").unwrap();
    assert!(alice.is_none(), "relay B must not receive pushed messages");
}

/// /announce rejects URLs pointing at private or internal addresses.
#[tokio::test]
async fn test_announce_rejects_private_urls() {
    let mut state = ChainState::new();
    let mut runner = FixtureRunner::new(&mut state, single_commit_finalized());
    runner.run(&mut state);

    let (url, app_state) = start_relay(&state).await;
    let client = reqwest::Client::new();

    let announce = |peer_url: &str| {
        let client = client.clone();
        let url = url.clone();
        let body = serde_json::json!({ "url": peer_url, "capabilities": 0 });
        async move {
            client
                .post(format!("{}/announce", url))
                .json(&body)
                .send()
                .await
                .unwrap()
                .status()
                .as_u16()
        }
    };

    // start_relay sets allow_private_peers, so loopback is accepted here —
    // but bad schemes and credentials are always rejected
    assert_eq!(announce("http://127.0.0.1:9999").await, 200);
    assert_eq!(announce("ftp://relay.example.com").await, 400);
    assert_eq!(announce("file:///etc/passwd").await, 400);
    assert_eq!(announce("http://user:pass@relay.example.com").await, 400);

    // Flip to strict mode via a second relay? allow_private_peers is baked into
    // AppState at construction, so exercise the validator directly instead.
    assert!(relay::peer::validate_peer_url("http://169.254.169.254/", false).is_err());
    assert!(relay::peer::validate_peer_url("http://127.0.0.1:12888", false).is_err());
    assert!(relay::peer::validate_peer_url("https://relay.example.com", false).is_ok());

    // The accepted loopback announce landed in the unverified table
    let peers = app_state.peers.lock().await;
    assert_eq!(peers.unverified_count(), 1);
}

// ─────────────────────────────────────────────────────────────────────────
// Sync (pull-based propagation)
// ─────────────────────────────────────────────────────────────────────────

/// Publish to relay A over HTTP, returning the stored handle names.
async fn publish(url: &str, state: &ChainState, runner: &mut FixtureRunner) {
    let bundle = runner.build_bundle();
    let msg = state.message(vec![bundle]);
    let resp = reqwest::Client::new()
        .post(format!("{}/message", url))
        .body(msg.to_bytes())
        .header("content-type", "application/octet-stream")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200, "publish should succeed");
}

/// Fresh-DB bootstrap: relay B pulls everything relay A has via /sync and
/// converges; a second sync transfers nothing new.
#[tokio::test]
async fn test_sync_bootstrap_convergence() {
    let mut state = ChainState::new();
    let mut runner = FixtureRunner::new(&mut state, single_commit_finalized());
    runner.run(&mut state);

    let (url_a, state_a) = start_relay(&state).await;
    publish(&url_a, &state, &mut runner).await;
    assert!(
        state_a
            .handler
            .store
            .get_handle("alice@sovereign")
            .unwrap()
            .is_some()
    );

    // B starts empty, with a mocked local chain for proof building
    let (_url_b, state_b) = start_relay_mocked(&state).await;
    let stats = sync_with_peer(&state_b, &url_a, &SyncConfig::default())
        .await
        .unwrap();
    assert!(stats.stored > 0, "bootstrap should store handles");
    assert_eq!(stats.failed_spaces, 0, "no spaces should fail verification");

    for key in ["@sovereign", "alice@sovereign", "bob@sovereign"] {
        assert!(
            state_b.handler.store.get_handle(key).unwrap().is_some(),
            "{} should be on relay B after sync",
            key
        );
    }

    // Watermark is caught up: the next sync short-circuits on the summary
    let again = sync_with_peer(&state_b, &url_a, &SyncConfig::default())
        .await
        .unwrap();
    assert_eq!(again.stored, 0);
    assert_eq!(again.prefiltered, 0, "summary check should skip the pull");
}

/// Re-pulling already-synced rows (watermark reset) is caught by the metadata
/// pre-filter without storing or re-verifying anything.
#[tokio::test]
async fn test_sync_prefilter_skips_duplicates() {
    let mut state = ChainState::new();
    let mut runner = FixtureRunner::new(&mut state, single_commit_finalized());
    runner.run(&mut state);

    let (url_a, _state_a) = start_relay(&state).await;
    publish(&url_a, &state, &mut runner).await;

    let (_url_b, state_b) = start_relay_mocked(&state).await;
    let first = sync_with_peer(&state_b, &url_a, &SyncConfig::default())
        .await
        .unwrap();
    assert!(first.stored > 0);

    // Rewind the watermark: everything gets re-pulled, nothing gets re-stored
    state_b.handler.store.set_watermark(&url_a, "0").unwrap();
    let second = sync_with_peer(&state_b, &url_a, &SyncConfig::default())
        .await
        .unwrap();
    assert_eq!(second.stored, 0, "duplicates must not store");
    assert_eq!(
        second.prefiltered, first.stored,
        "every previously-synced row should be pre-filtered"
    );
}

/// After the first sync, only new data crosses the wire (delta pull from the
/// persisted watermark).
#[tokio::test]
async fn test_sync_watermark_delta() {
    let mut state = ChainState::new();
    let mut runner = FixtureRunner::new(&mut state, two_commits_both_finalized());
    runner.run_next(&mut state); // first step only

    let (url_a, state_a) = start_relay(&state).await;
    publish(&url_a, &state, &mut runner).await;

    let (_url_b, state_b) = start_relay_mocked(&state).await;
    let first = sync_with_peer(&state_b, &url_a, &SyncConfig::default())
        .await
        .unwrap();
    assert!(first.stored > 0);

    // The chain advances and more data lands on A after B's first sync
    runner.run(&mut state);
    *state_a.handler.veritas.write().unwrap() = build_veritas(&state);
    publish(&url_a, &state, &mut runner).await;

    // B refreshes its chain view (anchors moved) and pulls the delta
    *state_b.handler.veritas.write().unwrap() = build_veritas(&state);
    *state_b.chain.mock_chain_proof.lock().unwrap() =
        Some((chain_proof(&state), test_anchors(&state)));

    let delta = sync_with_peer(&state_b, &url_a, &SyncConfig::default())
        .await
        .unwrap();
    assert!(delta.stored > 0, "delta sync should store the new data");
    assert_eq!(
        delta.prefiltered, 0,
        "already-synced rows must not be re-pulled"
    );
    assert!(
        state_b
            .handler
            .store
            .get_handle("charlie@two-finalized")
            .unwrap()
            .is_some(),
        "second-commit handle should reach relay B"
    );
    assert!(
        state_b
            .handler
            .store
            .get_handle("alice@two-finalized")
            .unwrap()
            .is_some(),
        "first-commit handle must survive the delta sync"
    );
}

/// /sync pages respect limit and cursor ordering; the final page is empty.
#[tokio::test]
async fn test_sync_pagination() {
    let mut state = ChainState::new();
    let mut runner = FixtureRunner::new(&mut state, single_commit_finalized());
    runner.run(&mut state);

    let (url_a, state_a) = start_relay(&state).await;
    publish(&url_a, &state, &mut runner).await;

    let store = &state_a.handler.store;
    let total = store.sync_summary().unwrap().count as usize;
    assert!(total >= 3, "fixture should store at least 3 handles");

    let mut seen = 0;
    let mut cursor = None;
    loop {
        let page = store.sync_page(cursor, 2, usize::MAX).unwrap();
        if page.records.is_empty() {
            assert!(page.next_cursor.is_none());
            break;
        }
        assert!(page.records.len() <= 2, "limit must be respected");
        seen += page.records.len();
        let next: resolver::SyncCursor = page.next_cursor.unwrap().parse().unwrap();
        if let Some(prev) = cursor {
            assert!(next > prev, "cursor must advance");
        }
        cursor = Some(next);
    }
    assert_eq!(seen, total, "pagination must cover every row exactly once");
}

/// A peer serving garbage pages fails the sync without moving the watermark
/// or storing anything.
#[tokio::test]
async fn test_sync_garbage_page_rejected() {
    use axum::{Router, routing::get};

    let mut state = ChainState::new();
    let mut runner = FixtureRunner::new(&mut state, single_commit_finalized());
    runner.run(&mut state);

    // Fake peer: summary claims data, /sync serves garbage
    let app = Router::new()
        .route(
            "/sync/summary",
            get(|| async { axum::Json(serde_json::json!({ "count": 5, "latest_cursor": "5" })) }),
        )
        .route("/sync", get(|| async { vec![0xFFu8; 64] }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let fake_url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let (_url_b, state_b) = start_relay_mocked(&state).await;
    let result = sync_with_peer(&state_b, &fake_url, &SyncConfig::default()).await;
    assert!(result.is_err(), "garbage page must fail the sync");
    assert!(
        state_b
            .handler
            .store
            .get_watermark(&fake_url)
            .unwrap()
            .is_none(),
        "watermark must not advance on garbage"
    );
    assert_eq!(state_b.handler.store.sync_summary().unwrap().count, 0);
}

/// Verified peers must survive past their TTL with zero data traffic — the
/// maintenance loop proactively refreshes them (regression: /peers used to
/// intermittently empty out in quiet periods).
#[tokio::test]
async fn test_verified_peers_survive_quiet_periods() {
    let mut state = ChainState::new();
    let mut runner = FixtureRunner::new(&mut state, single_commit_finalized());
    runner.run(&mut state);

    let (url_b, _state_b) = start_relay(&state).await;

    // Relay A with a very short verified TTL
    let mut config = Config::new(PathBuf::from("/tmp/relay-test"), ExtendedNetwork::Testnet4);
    config.db_path = PathBuf::from(":memory:");
    config.spaced_url = Some("http://127.0.0.1:1".into());
    config.anchors = test_anchors(&state);
    config.dev_mode = true;
    config.allow_private_peers = true;
    config.peer_config = relay::PeerConfig {
        max_unverified: 1000,
        max_verified: 100,
        verified_ttl: Duration::from_millis(500),
    };
    let relay_a = Relay::new(config).unwrap();
    let state_a = relay_a.state().clone();

    {
        let mut peers = state_a.peers.lock().await;
        peers.announce(&PeerInfo {
            source_ip: IpAddr::from([10, 0, 0, 2]),
            url: url_b.clone(),
            capabilities: 0,
        });
        peers.mark_alive(&url_b);
    }

    tokio::spawn(relay::run_peer_maintenance_loop(
        state_a.clone(),
        Duration::from_millis(50),
        3,
    ));

    // Wait well past several TTLs with no data traffic at all
    tokio::time::sleep(Duration::from_millis(1500)).await;

    let peers = state_a.peers.lock().await;
    assert!(
        peers.peers().contains(&url_b.as_str()),
        "verified peer must stay listed across TTLs via proactive refresh"
    );
}

// ─────────────────────────────────────────────────────────────────────────
// Poke (fast propagation)
// ─────────────────────────────────────────────────────────────────────────

/// Fast SyncConfig for poke tests: interval loop effectively off, poke paths
/// tuned to milliseconds.
fn poke_test_config() -> SyncConfig {
    SyncConfig {
        interval: Duration::from_secs(3600),
        jitter: Duration::ZERO,
        poke_debounce: Duration::from_millis(50),
        poke_cooldown: Duration::from_millis(100),
        ..SyncConfig::default()
    }
}

/// Poll until `check` passes or the timeout elapses.
async fn wait_for(timeout: Duration, mut check: impl FnMut() -> bool) -> bool {
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if check() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    false
}

/// End-to-end fast propagation: publish to A → A pokes B → B pulls from A,
/// with no interval-loop involvement.
#[tokio::test]
async fn test_publish_pokes_peer_into_pulling() {
    let mut state = ChainState::new();
    let mut runner = FixtureRunner::new(&mut state, single_commit_finalized());
    runner.run(&mut state);

    // A needs self_url (it goes in the poke body), so bind before building
    let listener_a = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url_a = format!("http://{}", listener_a.local_addr().unwrap());

    let mut config_a = Config::new(PathBuf::from("/tmp/relay-test"), ExtendedNetwork::Testnet4);
    config_a.db_path = PathBuf::from(":memory:");
    config_a.spaced_url = Some("http://127.0.0.1:1".into());
    config_a.anchors = test_anchors(&state);
    config_a.dev_mode = true;
    config_a.allow_private_peers = true;
    config_a.self_url = Some(url_a.clone());
    let relay_a = Relay::new(config_a).unwrap();
    *relay_a.state().handler.veritas.write().unwrap() = build_veritas(&state);
    let state_a = relay_a.state().clone();
    tokio::spawn(async move { relay_a.run(listener_a).await.unwrap() });

    let (url_b, state_b) = start_relay_mocked(&state).await;

    // A gossips pokes to B; B accepts pokes only from verified peers
    {
        let mut peers = state_a.peers.lock().await;
        peers.announce(&PeerInfo {
            source_ip: IpAddr::from([10, 0, 0, 2]),
            url: url_b.clone(),
            capabilities: 0,
        });
        peers.mark_alive(&url_b);
    }
    {
        let mut peers = state_b.peers.lock().await;
        peers.announce(&PeerInfo {
            source_ip: IpAddr::from([10, 0, 0, 1]),
            url: url_a.clone(),
            capabilities: 0,
        });
        peers.mark_alive(&url_a);
    }

    let cfg = poke_test_config();
    tokio::spawn(relay::run_poke_send_loop(state_a.clone(), cfg.clone()));
    tokio::spawn(relay::run_poke_sync_loop(state_b.clone(), cfg));

    publish(&url_a, &state, &mut runner).await;

    let converged = wait_for(Duration::from_secs(5), || {
        state_b
            .handler
            .store
            .get_handle("alice@sovereign")
            .unwrap()
            .is_some()
    })
    .await;
    assert!(converged, "poke should drive B to pull A's data within 5s");
}

/// Pokes from unknown peers and pokes with stale cursors must not trigger any
/// pull; a fresh cursor from a verified peer must.
#[tokio::test]
async fn test_poke_validation_gates_pulls() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let mut state = ChainState::new();
    let mut runner = FixtureRunner::new(&mut state, single_commit_finalized());
    runner.run(&mut state);

    // Counting fake peer: valid summary, empty page
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_clone = hits.clone();
    let app = axum::Router::new()
        .route(
            "/sync/summary",
            axum::routing::get(move || {
                hits_clone.fetch_add(1, Ordering::SeqCst);
                async { axum::Json(serde_json::json!({ "count": 1, "latest_cursor": "15" })) }
            }),
        )
        .route(
            "/sync",
            axum::routing::get(|| async { borsh::to_vec(&resolver::SyncPage::default()).unwrap() }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let fake_url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let (url_b, state_b) = start_relay_mocked(&state).await;
    tokio::spawn(relay::run_poke_sync_loop(
        state_b.clone(),
        poke_test_config(),
    ));

    let client = reqwest::Client::new();
    let poke = |url: String, cursor: &str| {
        let client = client.clone();
        let body = serde_json::json!({ "url": url, "cursor": cursor });
        let target = format!("{}/poke", url_b);
        async move {
            client
                .post(target)
                .json(&body)
                .send()
                .await
                .unwrap()
                .status()
                .as_u16()
        }
    };

    // Unknown peer: accepted (no membership leak) but ignored
    assert_eq!(poke(fake_url.clone(), "15").await, 200);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "unknown peer must be ignored"
    );

    // Known peer, stale cursor: dropped against the watermark
    {
        let mut peers = state_b.peers.lock().await;
        peers.announce(&PeerInfo {
            source_ip: IpAddr::from([10, 0, 0, 9]),
            url: fake_url.clone(),
            capabilities: 0,
        });
        peers.mark_alive(&fake_url);
    }
    state_b
        .handler
        .store
        .set_watermark(&fake_url, "20")
        .unwrap();
    assert_eq!(poke(fake_url.clone(), "15").await, 200);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "stale cursor must be dropped"
    );

    // URL variants (trailing slashes) must normalize to the same watermark
    // key — a stale cursor stays dropped no matter how the URL is spelled
    assert_eq!(poke(format!("{}//", fake_url), "15").await, 200);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "slash variants must not bypass the watermark dedup"
    );

    // Known peer, fresh cursor: triggers a pull
    assert_eq!(poke(fake_url.clone(), "25").await, 200);
    let pulled = wait_for(Duration::from_secs(3), || hits.load(Ordering::SeqCst) > 0).await;
    assert!(
        pulled,
        "fresh cursor from verified peer must trigger a pull"
    );

    // Malformed pokes are rejected
    let bad = client
        .post(format!("{}/poke", url_b))
        .json(&serde_json::json!({ "url": fake_url, "cursor": "not-a-number" }))
        .send()
        .await
        .unwrap();
    assert_eq!(bad.status().as_u16(), 400);
}

/// A peer's next_cursor is clamped to its advertised latest_cursor, so a
/// bogus u64::MAX cursor can't poison the watermark; and a peer whose cursor
/// space regressed below our watermark (DB wipe / prior poisoning) gets its
/// watermark reset instead of never being pulled again.
#[tokio::test]
async fn test_sync_cursor_clamped_and_regression_resets() {
    let mut state = ChainState::new();
    let mut runner = FixtureRunner::new(&mut state, single_commit_finalized());
    runner.run(&mut state);

    // Real records from relay A so ingestion verifies, but served by a fake
    // peer that lies about the cursor
    let (url_a, state_a) = start_relay(&state).await;
    publish(&url_a, &state, &mut runner).await;
    let mut page = state_a
        .handler
        .store
        .sync_page(None, 100, usize::MAX)
        .unwrap();
    let honest_latest = state_a
        .handler
        .store
        .sync_summary()
        .unwrap()
        .latest_cursor
        .unwrap();
    page.next_cursor = Some(u64::MAX.to_string());
    let page_bytes = borsh::to_vec(&page).unwrap();

    let latest_for_summary = honest_latest.clone();
    let app = axum::Router::new()
        .route(
            "/sync/summary",
            axum::routing::get(move || {
                let latest = latest_for_summary.clone();
                async move {
                    axum::Json(serde_json::json!({ "count": 3, "latest_cursor": latest }))
                }
            }),
        )
        .route(
            "/sync",
            axum::routing::get(move || {
                let bytes = page_bytes.clone();
                async move { bytes }
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let fake_url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let (_url_b, state_b) = start_relay_mocked(&state).await;
    let stats = sync_with_peer(&state_b, &fake_url, &SyncConfig::default())
        .await
        .unwrap();
    assert!(stats.stored > 0, "records should still ingest");
    assert_eq!(
        state_b.handler.store.get_watermark(&fake_url).unwrap(),
        Some(honest_latest.clone()),
        "watermark must be clamped to the advertised latest, not u64::MAX"
    );

    // Regression: watermark far beyond the peer's advertised latest → reset
    state_b
        .handler
        .store
        .set_watermark(&fake_url, &u64::MAX.to_string())
        .unwrap();
    sync_with_peer(&state_b, &fake_url, &SyncConfig::default())
        .await
        .unwrap();
    assert_eq!(
        state_b.handler.store.get_watermark(&fake_url).unwrap(),
        Some("0".to_string()),
        "regressed cursor space must reset the watermark for recovery"
    );
}

/// A root republished after its sub-handles carries a higher sync_seq; /sync
/// must append it to pages containing the subs so a bootstrapping relay can
/// verify them (regression: subs were skipped and lost behind the watermark).
#[tokio::test]
async fn test_bootstrap_survives_root_republished_after_subs() {
    let mut state = ChainState::new();
    let mut runner = FixtureRunner::new(&mut state, single_commit_finalized());
    runner.run(&mut state);

    let (url_a, state_a) = start_relay(&state).await;
    publish(&url_a, &state, &mut runner).await;

    // Simulate the root being republished after its subs: move it to the
    // end of the sync stream
    state_a.handler.store.bump_sync_seq("@sovereign").unwrap();

    // The first page no longer contains the root in cursor order — the
    // server must append it so the subs are verifiable
    let page = state_a
        .handler
        .store
        .sync_page(None, 2, usize::MAX)
        .unwrap();
    assert!(
        page.records.iter().any(|r| r.handle == "@sovereign"),
        "later-seq root must be appended to pages containing its subs"
    );

    // A fresh relay bootstrapping with tiny pages converges completely
    let (_url_b, state_b) = start_relay_mocked(&state).await;
    let cfg = SyncConfig {
        page_limit: 2,
        ..SyncConfig::default()
    };
    let stats = sync_with_peer(&state_b, &url_a, &cfg).await.unwrap();
    assert_eq!(stats.failed_spaces, 0, "no space may fail on bootstrap");
    for key in ["@sovereign", "alice@sovereign", "bob@sovereign"] {
        assert!(
            state_b.handler.store.get_handle(key).unwrap().is_some(),
            "{} must survive root-after-sub ordering",
            key
        );
    }
}

/// Infra failures (spaced unreachable) must abort the page without advancing
/// the watermark — records dropped for reasons unrelated to their validity
/// must be re-pulled once the infra recovers.
#[tokio::test]
async fn test_sync_infra_failure_does_not_advance_watermark() {
    let mut state = ChainState::new();
    let mut runner = FixtureRunner::new(&mut state, single_commit_finalized());
    runner.run(&mut state);

    let (url_a, _state_a) = start_relay(&state).await;
    publish(&url_a, &state, &mut runner).await;

    // B has NO mocked chain: its spaced URL points nowhere, so local proof
    // building fails — an infra failure, not a data rejection
    let (_url_b, state_b) = start_relay(&state).await;
    let result = sync_with_peer(&state_b, &url_a, &SyncConfig::default()).await;
    assert!(result.is_err(), "infra failure must fail the sync round");
    assert!(
        state_b
            .handler
            .store
            .get_watermark(&url_a)
            .unwrap()
            .is_none(),
        "watermark must not advance past records dropped by infra failures"
    );
    assert_eq!(state_b.handler.store.sync_summary().unwrap().count, 0);
}

/// Affirmative verification rejections are terminal: they count as failed
/// spaces and the watermark advances (retrying them forever would wedge).
#[tokio::test]
async fn test_sync_verification_reject_advances_watermark() {
    let mut state_a = ChainState::new();
    let mut runner = FixtureRunner::new(&mut state_a, single_commit_finalized());
    runner.run(&mut state_a);

    let (url_a, state_a_app) = start_relay(&state_a).await;
    publish(&url_a, &state_a, &mut runner).await;
    let latest_a = state_a_app
        .handler
        .store
        .sync_summary()
        .unwrap()
        .latest_cursor
        .unwrap();

    // B lives on a different chain: A's records affirmatively fail
    // verification against B's anchors
    let mut state_b_chain = ChainState::new();
    let mut runner_b = FixtureRunner::new(&mut state_b_chain, staged_only());
    runner_b.run(&mut state_b_chain);
    let (_url_b, state_b) = start_relay_mocked(&state_b_chain).await;

    let stats = sync_with_peer(&state_b, &url_a, &SyncConfig::default())
        .await
        .unwrap();
    assert!(stats.failed_spaces > 0, "foreign-chain records must fail");
    assert_eq!(stats.stored, 0);
    assert_eq!(
        state_b.handler.store.get_watermark(&url_a).unwrap(),
        Some(latest_a),
        "affirmative rejections advance the watermark"
    );
}

/// The in-batch failure budget gates space processing: with the budget spent,
/// no further prove/verify work happens even for valid records.
#[tokio::test]
async fn test_ingest_failure_budget_gates_processing() {
    let mut state = ChainState::new();
    let mut runner = FixtureRunner::new(&mut state, single_commit_finalized());
    runner.run(&mut state);

    let (url_a, state_a) = start_relay(&state).await;
    publish(&url_a, &state, &mut runner).await;
    let page = state_a
        .handler
        .store
        .sync_page(None, 100, usize::MAX)
        .unwrap();

    let (_url_b, state_b) = start_relay_mocked(&state).await;

    // Budget of zero: nothing may be processed, valid or not — and the
    // batch must be flagged incomplete so no watermark can advance past it
    let gated = relay::ingest_sync_records(&state_b, page.records.clone(), 0)
        .await
        .unwrap();
    assert_eq!(gated.stored, 0, "spent budget must gate all processing");
    assert!(
        gated.incomplete,
        "unattempted batch must be flagged incomplete"
    );

    // Normal budget: the same records ingest fine
    let ok = relay::ingest_sync_records(&state_b, page.records, 32)
        .await
        .unwrap();
    assert!(ok.stored > 0);
}

/// Outbound requests must not follow redirects — a 302 from a peer must never
/// steer a request at internal services.
#[tokio::test]
async fn test_sync_does_not_follow_redirects() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let mut state = ChainState::new();
    let mut runner = FixtureRunner::new(&mut state, single_commit_finalized());
    runner.run(&mut state);

    // "Internal" target that must never be reached
    let internal_hits = Arc::new(AtomicUsize::new(0));
    let internal_hits_clone = internal_hits.clone();
    let internal = axum::Router::new().route(
        "/sync/summary",
        axum::routing::get(move || {
            internal_hits_clone.fetch_add(1, Ordering::SeqCst);
            async { "gotcha" }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let internal_url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, internal).await.unwrap() });

    // Malicious peer redirecting everything at the internal target
    let redirect_to = format!("{}/sync/summary", internal_url);
    let evil = axum::Router::new().route(
        "/sync/summary",
        axum::routing::get(move || {
            let target = redirect_to.clone();
            async move { axum::response::Redirect::temporary(&target) }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let evil_url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, evil).await.unwrap() });

    let (_url_b, state_b) = start_relay_mocked(&state).await;
    let result = sync_with_peer(&state_b, &evil_url, &SyncConfig::default()).await;
    assert!(result.is_err(), "redirected summary must fail the sync");
    assert_eq!(
        internal_hits.load(Ordering::SeqCst),
        0,
        "the redirect target must never be contacted"
    );
}

// ─────────────────────────────────────────────────────────────────────────
// Retention (storage budget, eviction, admission gate)
// ─────────────────────────────────────────────────────────────────────────

/// Under a tiny budget the sweep evicts from the over-entitled space until
/// under the low-water mark, keeping the accounting true.
#[tokio::test]
async fn test_retention_sweep_evicts_over_entitled_space() {
    let mut state = ChainState::new();
    let mut runner = FixtureRunner::new(&mut state, single_commit_finalized());
    runner.run(&mut state);

    let (url, app_state) = start_relay(&state).await;
    publish(&url, &state, &mut runner).await;

    let (rows_before, bytes_before) = app_state.handler.store.storage_totals().unwrap();
    assert!(rows_before >= 3 && bytes_before > 0);

    // entitlement 1 handle/epoch makes the fixture space over-entitled;
    // budget of 1 byte forces full pressure
    let cfg = relay::RetentionConfig {
        max_storage_bytes: 1,
        entitlement_per_epoch: 1,
        ..relay::RetentionConfig::default()
    };
    let evicted = relay::retention::sweep(&app_state, &cfg).await.unwrap();
    assert_eq!(
        evicted as u64,
        rows_before - 1,
        "everything except the root evicted under pressure"
    );

    let (rows_after, _) = app_state.handler.store.storage_totals().unwrap();
    assert_eq!(rows_after, 1, "only the root row survives");
    assert!(
        app_state
            .handler
            .store
            .get_handle("@sovereign")
            .unwrap()
            .is_some(),
        "the root handle must never be evicted while the space has data"
    );
    // Emptied epoch buckets still count toward entitlement
    let (_, epochs) = app_state.handler.store.space_usage("@sovereign").unwrap();
    assert!(epochs >= 1, "entitlement epochs survive eviction");
}

/// Recently-queried handles are spared while cold rows are evicted first.
#[tokio::test]
async fn test_retention_spares_hot_handles() {
    let mut state = ChainState::new();
    let mut runner = FixtureRunner::new(&mut state, single_commit_finalized());
    runner.run(&mut state);

    let (url, app_state) = start_relay(&state).await;
    publish(&url, &state, &mut runner).await;

    app_state
        .query_heat
        .lock()
        .unwrap()
        .touch("alice@sovereign");

    // Evict exactly one row: it must be a cold one, not alice
    let cfg = relay::RetentionConfig {
        max_storage_bytes: 1,
        entitlement_per_epoch: 1,
        eviction_batch: 1,
        max_batches_per_sweep: 1,
        ..relay::RetentionConfig::default()
    };
    let evicted = relay::retention::sweep(&app_state, &cfg).await.unwrap();
    assert_eq!(evicted, 1);
    assert!(
        app_state
            .handler
            .store
            .get_handle("alice@sovereign")
            .unwrap()
            .is_some(),
        "hot handle must be spared while cold rows exist"
    );
}

/// Under storage pressure, first-inserts for an over-entitled space are
/// gated while updates to existing handles still pass.
#[tokio::test]
async fn test_admission_gate_blocks_new_handles_under_pressure() {
    let mut state = ChainState::new();
    let mut runner = FixtureRunner::new(&mut state, two_commits_both_finalized());
    runner.run_next(&mut state); // first step: alice + bob staged

    // Relay with pressure-inducing retention settings: budget 1 byte,
    // entitlement 1 handle/epoch
    let mut config = Config::new(PathBuf::from("/tmp/relay-test"), ExtendedNetwork::Testnet4);
    config.db_path = PathBuf::from(":memory:");
    config.spaced_url = Some("http://127.0.0.1:1".into());
    config.anchors = test_anchors(&state);
    config.dev_mode = true;
    config.allow_private_peers = true;
    config.settings.retention.max_storage_bytes = 1;
    config.settings.retention.entitlement_per_epoch = 1;
    let relay_a = Relay::new(config).unwrap();
    *relay_a.state().handler.veritas.write().unwrap() = build_veritas(&state);
    let app_state = relay_a.state().clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { relay_a.run(listener).await.unwrap() });

    // First publish: no pressure yet (empty DB) — everything admits
    publish(&url, &state, &mut runner).await;
    assert!(
        app_state
            .handler
            .store
            .get_handle("alice@two-finalized")
            .unwrap()
            .is_some()
    );

    // Chain advances; charlie appears. Now bytes > budget and the space is
    // over-entitled: charlie (first insert) must be gated, existing handles
    // must still update.
    runner.run(&mut state);
    *app_state.handler.veritas.write().unwrap() = build_veritas(&state);
    publish(&url, &state, &mut runner).await;

    assert!(
        app_state
            .handler
            .store
            .get_handle("charlie@two-finalized")
            .unwrap()
            .is_none(),
        "new handle must be gated under storage pressure"
    );
    let alice = app_state
        .handler
        .store
        .get_handle("alice@two-finalized")
        .unwrap()
        .expect("alice still stored");
    assert!(
        alice.epoch_height > 0,
        "existing handle updated past staging"
    );
    assert!(
        app_state
            .stats
            .admission_gated
            .load(std::sync::atomic::Ordering::Relaxed)
            > 0,
        "gated first-inserts must be counted"
    );
}

/// /stats reports message counters and /health is unmetered.
#[tokio::test]
async fn test_stats_and_health_endpoints() {
    let mut state = ChainState::new();
    let mut runner = FixtureRunner::new(&mut state, single_commit_finalized());
    runner.run(&mut state);

    let (url, _state) = start_relay(&state).await;
    let client = reqwest::Client::new();

    // /health responds without consuming any rate budget
    for _ in 0..30 {
        let resp = client.get(format!("{}/health", url)).send().await.unwrap();
        assert_eq!(resp.status().as_u16(), 200);
    }

    publish(&url, &state, &mut runner).await;

    let stats: serde_json::Value = client
        .get(format!("{}/stats", url))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(stats["messages"]["received"], 1);
    assert_eq!(stats["messages"]["accepted"], 1);
    assert!(stats["peers"]["verified"].is_number());
    assert!(stats["concurrency"]["verify_permits_available"].is_number());
    assert!(stats["sync"]["last_success_by_peer"].is_object());
}

/// Duplicate and stale messages are accepted but reported as skipped, not stored.
#[test]
fn test_duplicate_message_reports_nothing_stored() {
    let mut state = ChainState::new();
    let mut runner = FixtureRunner::new(&mut state, single_commit_finalized());
    runner.run(&mut state);

    let handler = setup_handler(&state);
    let bundle = runner.build_bundle();
    let msg = state.message(vec![bundle]);

    let first = handler.handle_message(msg.clone()).unwrap();
    assert!(first.stored > 0, "first delivery should store handles");

    let second = handler.handle_message(msg).unwrap();
    assert_eq!(second.stored, 0, "duplicate delivery should store nothing");
    assert!(second.skipped > 0, "duplicate delivery should be skipped");
}
