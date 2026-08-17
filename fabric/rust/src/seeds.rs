/// Initial set of seeds to discover the relay network.
pub const SEEDS: &[&str] = &[
    "https://relay-cosmos.spacesprotocol.org",
    "https://relay-atlas.spacesprotocol.org",
];

/// Default semi-trusted relay pool: `(url, pinned x-only pubkey hex)` pairs.
///
/// A semi-trusted relay is only meaningful once its signing key is known to
/// pin, so this stays empty until our bootstrap relays publish their keys —
/// fill the pairs in then and every consumer picks them up. Until then
/// `refresh_semi_trusted` on the default pool is a safe no-op.
pub const SEED_SEMI_TRUSTED: &[(&str, &str)] = &[];
