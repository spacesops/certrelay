# Certrelay

Certificate relay network for the [Spaces protocol](https://spacesprotocol.org). Stores and serves cryptographic proofs that bind human-readable names to owner keys anchored to Bitcoin.

## Overview

Certrelay consists of two components:

- **relay** — HTTP server that verifies certificates, stores them in SQLite, and syncs with peers (pull-based replication with poke notifications)
- **fabric** — Client library available in Rust, JavaScript, Go, Python, Kotlin, and Swift

The protocol is plain HTTP — relays are queryable from browsers, mobile apps, and any language with an HTTP client. All verification is done client-side against Bitcoin's chain state.

## Fabric Client

For documentation on using Fabric to resolve handles, publish records, and verify identities, see **[spacesprotocol.org/docs](https://spacesprotocol.org/docs)**.

## Running a Relay

```bash
cargo install --git https://github.com/spacesprotocol/certrelay.git --bin certrelay
certrelay
```

On first run, certrelay will:
1. Download a checkpoint (~8MB)
2. Build hash indexes (~2 min)
3. Start an embedded Bitcoin light client ([yuki](https://github.com/imperviousinc/yuki)) and [spaced](https://github.com/spacesprotocol/spaces) node
4. Sync to the chain tip and start serving

No external Bitcoin node required. Data is stored in `~/.certrelay` by default.

### Configuration

| Flag | Env | Default | Description |
|------|-----|---------|-------------|
| `--chain` | `CERTRELAY_CHAIN` | `mainnet` | Network (`mainnet`, `testnet4`) |
| `--data-dir` | `CERTRELAY_DATA_DIR` | `~/.certrelay` | Data directory |
| `--bind` | `CERTRELAY_BIND` | `127.0.0.1` | Bind address |
| `--port` | `CERTRELAY_PORT` | `7778` (mainnet) / `7779` (other) | Listen port |
| `--self-url` | `CERTRELAY_SELF_URL` | - | Public URL for peer announcements (also enables poke sending) |
| `--config` | `CERTRELAY_CONFIG` | - | Path to a TOML config file (see below) |
| `--spaced-rpc-url` | `CERTRELAY_SPACED_RPC_URL` | - | External spaced RPC (skips embedded node) |
| `--remote-ip-header` | `CERTRELAY_REMOTE_IP_HEADER` | - | Header for client IP behind reverse proxy (rightmost entry is used) |
| `--is-bootstrap` | `CERTRELAY_BOOTSTRAP` | `false` | Run as a bootstrap node |
| `--anchor-refresh` | `CERTRELAY_ANCHOR_REFRESH` | `300` | Anchor refresh interval in seconds |
| `--allow-private-peers` | `CERTRELAY_ALLOW_PRIVATE_PEERS` | `false` | Accept peers on private/loopback addresses (local development only) |
| `--skip-checkpoint-sync` | - | `false` | Skip checkpoint download, sync from scratch |

### Configuration file

Rate limits, sync tuning, peer table sizes, concurrency caps, and storage
retention live in an optional TOML file passed via `--config` (or
`CERTRELAY_CONFIG`). Every field is optional and defaults to the values shown —
a config file only needs the settings being changed. Unknown keys are rejected
to catch typos.

```toml
[rate_limits]
message_per_min = 60       # /message (client publishes)
proof_per_min = 30         # /query, /chain-proof (trigger proof generation)
read_per_min = 120         # /hints, /reverse, /addrs, /anchors, /peers, /stats
announce_per_min = 5       # /announce
sync_per_min = 60          # /sync, /sync/summary (pages are the unit)
poke_per_min = 30          # /poke
space_per_min = 100        # per-space content updates (replacements only)
handle_period_secs = 300   # per-handle content cap period (replacements only)
handle_burst = 3           # per-handle burst within the period

[sync]
interval_secs = 45         # pull round cadence (plus jitter)
jitter_secs = 15
page_limit = 1000          # rows requested per /sync page (max 1000)
peers_per_round = 2        # peers pulled from per round
max_pages_per_peer = 200   # page budget per peer per round
poke_debounce_ms = 2000    # coalescing window for outgoing pokes
poke_cooldown_ms = 5000    # min gap between poke-triggered pulls per peer

[peers]
max_unverified = 1000      # announced-but-unverified peer slots
max_verified = 100         # verified peer slots
verified_ttl_secs = 600    # verified peers expire without a liveness refresh

[limits]
max_message_size = 524288  # /message body cap in bytes (512 KB)
proof_concurrency = 6      # concurrent chain-proof generations (503 beyond)
verify_concurrency = 4     # concurrent message verifications (503 beyond)

[retention]
max_storage_bytes = 10737418240  # handle payload budget (10 GB); 0 = unlimited
entitlement_per_epoch = 10000    # handles per (space, epoch) counted as paid-for
evict_low_water_pct = 90         # evict down to this % of the budget
sweep_interval_secs = 30         # pressure check cadence
eviction_batch = 1000            # rows deleted per transaction
```

Notes on the less obvious knobs:

- **Content limits are churn-only.** `space_per_min` and the `handle_*` caps
  charge only when an existing record is *replaced*; the first insert of a
  handle is always free so relays can bootstrap-sync a whole network's data.
- **Retention never rejects data under budget.** A space's *entitlement* is
  `entitlement_per_epoch × epochs it committed on-chain` — commitments cost
  Bitcoin transactions, so storage beyond entitlement is storage nobody paid
  for. Only when `max_storage_bytes` is exceeded does the relay evict, most
  over-entitled space first (oldest and least-queried rows first), and stop
  admitting *new* handles for over-entitled spaces until pressure clears.
  Size the budget to your disk; a small relay stays functional by shedding
  the heaviest spaces, a big relay can hold everything.

### Monitoring

- `GET /health` — unmetered liveness check for load balancers and peers.
- `GET /stats` — JSON counters: message intake, sync progress (including last
  successful sync per peer — the key signal that replication is healthy),
  pokes, rate-limit rejections, storage totals versus budget, and evictions.

### Public relay behind a reverse proxy

```bash
certrelay \
  --bind 0.0.0.0 \
  --self-url https://relay.example.com \
  --remote-ip-header x-forwarded-for
```

### Using an external spaced node

```bash
certrelay --spaced-rpc-url http://user:password@127.0.0.1:12888
```

## License

MIT