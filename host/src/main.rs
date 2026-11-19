//! Fetch a streaming HTTP body and print it as a Hyperlight guest anonymizes it.
//!
//! Usage: `hl-http [URL]`. `HL_HTTP_GUEST` overrides the guest binary path. The body goes to
//! stdout. Tracing events go to stderr, filtered by `RUST_LOG` (default `warn,hl_http=info`).
//! The response headers log at `debug`, so `RUST_LOG=hl_http=debug` shows them.

use std::{env, io};

use anyhow::{Context, Result};
use hyper::Uri;
use hyperlight_host::SandboxBuilder;
use tracing::{debug, info};
use tracing_subscriber::EnvFilter;

/// A page that streams JSON lines, each holding the client's IP address.
const DEFAULT_URL: &str = "http://httpbin.org/stream/20";

/// The log filter when `RUST_LOG` is unset. Hyperlight logs its setup at `info`.
const DEFAULT_LOG: &str = "warn,hl_http=info";

/// Fetch the URL and stream its body through the guest.
///
/// 1. Log to stderr.
/// 2. Start a Tokio runtime whose worker thread runs the HTTP connection.
/// 3. Build the sandbox, then fetch the response head.
/// 4. Filter the body on this thread, which drives the sandbox.
/// 5. Log the trailers the guest returns.
fn main() -> Result<()> {
    let filter = if env::var_os(EnvFilter::DEFAULT_ENV).is_some() {
        EnvFilter::try_from_default_env().context("invalid RUST_LOG")?
    } else {
        EnvFilter::new(DEFAULT_LOG)
    };

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(io::stderr)
        .init();

    let url: Uri = env::args()
        .nth(1)
        .as_deref()
        .unwrap_or(DEFAULT_URL)
        .parse()
        .context("invalid URL")?;

    let guest = env::var("HL_HTTP_GUEST").unwrap_or_else(|_| hl_http::GUEST.to_string());

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()?;

    let mut sandbox = SandboxBuilder::from_file(&guest)
        .build()
        .with_context(|| format!("failed to load the guest at {guest}"))?;

    info!(%url, "sending request");

    let response = runtime.block_on(hl_http::get(&url))?;

    info!(version = ?response.version(), status = %response.status(), "received response");

    for (name, value) in response.headers() {
        let value = String::from_utf8_lossy(value.as_bytes());

        debug!(?name, ?value, "response header");
    }

    let trailers = hl_http::filter(&mut sandbox, response.into_body(), &mut io::stdout().lock())?;

    for (name, value) in trailers.iter() {
        info!(?name, ?value, "trailer");
    }

    Ok(())
}
