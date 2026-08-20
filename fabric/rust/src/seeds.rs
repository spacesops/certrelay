/// Initial set of seeds to discover the relay network.
pub const SEEDS: &[&str] = &[
    "https://relay-cosmos.spacesprotocol.org",
    "https://relay-atlas.spacesprotocol.org",
];

/// Default semi-trusted relay pool: `(url, pinned x-only pubkey hex)` pairs.
///
/// A semi-trusted relay is a pinned `(url, key)` pair; these are the keys the
/// production relays advertise (`X-Anchor-Pubkey` / `/stats.anchor_pubkey`).
/// Combined with the default `Quorum::Majority` this is a 3-of-4 pool, so it
/// keeps working while any one relay is down or lagging.
pub const SEED_SEMI_TRUSTED: &[(&str, &str)] = &[
    (
        "https://relay-cosmos.spacesprotocol.org",
        "b4e6def56fe1c7fedc3168b100254e184fbbd1175628e5ba92e36644a107ac70",
    ),
    (
        "https://relay-atlas.spacesprotocol.org",
        "33621830b05efe450f1dbbfb064ed94db50a033ae83b982643d1957f95c94ce7",
    ),
    (
        "https://relay-orion.spacesprotocol.org",
        "7126eaafb140c43ec50b22a37d44aeb451f87a03c9994994f3c0ebebd5b0ff0b",
    ),
    (
        "https://relay-pulsar.spacesprotocol.org",
        "f3c827ea7bf9d2e621b629c4420d25a0633f671953deff67926d38fe49679730",
    ),
];
