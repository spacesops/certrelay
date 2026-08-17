export const DEFAULT_SEEDS = ["https://relay-cosmos.spacesprotocol.org", "https://relay-atlas.spacesprotocol.org"];

/**
 * Default semi-trusted relay pool: `{url, pubkey}` pairs, where `pubkey` is the
 * relay's pinned x-only key (advertised as `X-Anchor-Pubkey` / `/stats`).
 * Combined with the default `"majority"` quorum this is a 3-of-4 pool, so it
 * keeps working while any one relay is down or lagging.
 */
export const DEFAULT_SEMI_TRUSTED: { url: string; pubkey: string }[] = [
  { url: "https://relay-cosmos.spacesprotocol.org", pubkey: "b4e6def56fe1c7fedc3168b100254e184fbbd1175628e5ba92e36644a107ac70" },
  { url: "https://relay-atlas.spacesprotocol.org", pubkey: "33621830b05efe450f1dbbfb064ed94db50a033ae83b982643d1957f95c94ce7" },
  { url: "https://relay-orion.spacesprotocol.org", pubkey: "7126eaafb140c43ec50b22a37d44aeb451f87a03c9994994f3c0ebebd5b0ff0b" },
  { url: "https://relay-pulsar.spacesprotocol.org", pubkey: "f3c827ea7bf9d2e621b629c4420d25a0633f671953deff67926d38fe49679730" },
];
