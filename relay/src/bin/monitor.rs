//! Bootstrap relay health monitor.
//!
//! Polls each URL in [`BOOTSTRAP_RELAYS`] with `GET /peers` on a fixed interval.
//! Logs error/recovery transitions and peer counts for healthy relays.

use clap::Parser;
use relay::BOOTSTRAP_RELAYS;
use relay::PeerInfo;
use std::collections::HashMap;
use std::time::{Duration, Instant};

const DEFAULT_CHECK_INTERVAL_MINS: u64 = 30;
const DEFAULT_REQUEST_TIMEOUT_SECS: u64 = 15;

#[derive(Parser)]
#[command(
    name = "monitor",
    about = "Poll bootstrap certrelay seeds and track /peers health",
    long_about = "Polls each URL listed in BOOTSTRAP_RELAYS with GET /peers on a \
                  fixed interval. Logs when a seed enters or leaves an error state \
                  (unreachable, timeout, empty peer list). Logs peer counts for \
                  seeds that return a non-empty list."
)]
struct Args {
    /// Minutes to wait between poll loops.
    #[arg(
        long,
        env = "CHECK_INTERVAL",
        default_value_t = DEFAULT_CHECK_INTERVAL_MINS
    )]
    check_interval: u64,

    /// Per-request HTTP timeout in seconds.
    #[arg(
        long,
        env = "REQUEST_TIMEOUT",
        default_value_t = DEFAULT_REQUEST_TIMEOUT_SECS
    )]
    timeout: u64,

    /// Log filter passed to env_logger (e.g. info, debug, monitor=debug).
    #[arg(long, env = "RUST_LOG", default_value = "info")]
    rust_log: String,
}

struct RelayTracker {
    in_error: bool,
    error_since: Option<Instant>,
}

enum ProbeOutcome {
    Ok(usize),
    Err(String),
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    env_logger::Builder::new()
        .parse_filters(&args.rust_log)
        .init();

    let check_interval = Duration::from_secs(args.check_interval * 60);

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(args.timeout))
        .build()
        .expect("failed to build HTTP client");

    let mut trackers: HashMap<String, RelayTracker> = HashMap::new();

    log::info!(
        "monitor: watching {} bootstrap relay(s), interval={}min, timeout={}s",
        BOOTSTRAP_RELAYS.len(),
        args.check_interval,
        args.timeout
    );

    loop {
        for &base in BOOTSTRAP_RELAYS {
            let url = peers_url(base);
            let outcome = probe(&client, &url, args.timeout).await;

            let tracker = trackers.entry(base.to_string()).or_insert(RelayTracker {
                in_error: false,
                error_since: None,
            });

            match outcome {
                ProbeOutcome::Ok(count) => {
                    if tracker.in_error {
                        let down_for = tracker
                            .error_since
                            .map(|t| t.elapsed())
                            .unwrap_or_default();
                        log::info!(
                            "{base}: resumed from error state (was down for {:.1}s)",
                            down_for.as_secs_f64()
                        );
                        tracker.in_error = false;
                        tracker.error_since = None;
                    }
                    if count > 0 {
                        log::info!("{base}: {count} peer(s)");
                    }
                }
                ProbeOutcome::Err(reason) => {
                    if !tracker.in_error {
                        log::error!("{base}: entered error state — {reason}");
                        tracker.in_error = true;
                        tracker.error_since = Some(Instant::now());
                    } else {
                        log::warn!("{base}: still in error state — {reason}");
                    }
                }
            }
        }

        tokio::time::sleep(check_interval).await;
    }
}

fn peers_url(base: &str) -> String {
    format!("{}/peers", base.trim_end_matches('/'))
}

async fn probe(client: &reqwest::Client, url: &str, timeout_secs: u64) -> ProbeOutcome {
    let resp = match client.get(url).send().await {
        Ok(r) => r,
        Err(e) => {
            let reason = if e.is_timeout() {
                format!("connection timed out after {timeout_secs}s")
            } else if e.is_connect() {
                format!("unreachable: {e}")
            } else {
                format!("request failed: {e}")
            };
            return ProbeOutcome::Err(reason);
        }
    };

    if !resp.status().is_success() {
        return ProbeOutcome::Err(format!("HTTP {}", resp.status()));
    }

    let peers: Vec<PeerInfo> = match resp.json().await {
        Ok(p) => p,
        Err(e) => return ProbeOutcome::Err(format!("invalid JSON: {e}")),
    };

    if peers.is_empty() {
        return ProbeOutcome::Err("empty peer list []".into());
    }

    ProbeOutcome::Ok(peers.len())
}
