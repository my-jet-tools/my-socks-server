#![forbid(unsafe_code)]
#![deny(warnings)]
#![deny(clippy::all)]
#![deny(clippy::pedantic)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

use std::io::IsTerminal;
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::Context;
use my_socks_server::config::{ServerConfig, settings_file_path};
use my_socks_server::limits::raise_nofile_limit;
use my_socks_server::policy::InternalWhitelistEntry;
use my_socks_server::server::SocksServer;
use tracing::level_filters::LevelFilter;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

/// After draining, blocking DNS lookups still in flight are abandoned after this long.
const RUNTIME_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(1);
/// Descriptors needed besides the two per connection (listener, runtime, logs, ...).
const FD_RESERVE: u64 = 64;

fn main() -> ExitCode {
    init_logging();
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            error!("{error:#}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> anyhow::Result<()> {
    let settings_path = settings_file_path()?;
    let config = ServerConfig::load(&settings_path)?;
    log_settings(&settings_path, &config);
    raise_file_limit(&config);

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("cannot start the Tokio runtime")?;
    let result = runtime.block_on(serve(config));
    runtime.shutdown_timeout(RUNTIME_SHUTDOWN_TIMEOUT);
    result
}

async fn serve(config: ServerConfig) -> anyhow::Result<()> {
    let listen_address = config.listen_address;
    let server = SocksServer::bind(config)
        .await
        .with_context(|| format!("cannot listen on {listen_address}"))?;
    info!(
        listen = %server.local_addr()?,
        version = env!("CARGO_PKG_VERSION"),
        "my-socks-server started"
    );
    server.run(shutdown_signal()).await;
    info!("my-socks-server stopped");
    Ok(())
}

/// `RUST_LOG` sets the level (default `info`), `LOG_FORMAT=json` switches to JSON lines.
fn init_logging() {
    let filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .from_env_lossy();
    let format = std::env::var("LOG_FORMAT").unwrap_or_default();
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false);
    let result = if format.eq_ignore_ascii_case("json") {
        builder
            .json()
            .flatten_event(true)
            .with_current_span(false)
            .with_span_list(false)
            .try_init()
    } else {
        builder
            .with_ansi(std::io::stdout().is_terminal())
            .try_init()
    };
    if let Err(error) = result {
        eprintln!("cannot initialise logging: {error}");
    }
    if !format.is_empty()
        && !format.eq_ignore_ascii_case("json")
        && !format.eq_ignore_ascii_case("text")
    {
        warn!(LOG_FORMAT = %format, "unknown LOG_FORMAT, using text (expected text or json)");
    }
}

fn log_settings(path: &Path, config: &ServerConfig) {
    let policy = &config.destination_policy;
    let client_whitelist: Vec<String> = config
        .client_acl
        .networks()
        .iter()
        .map(ToString::to_string)
        .collect();
    let internal_whitelist: Vec<String> = policy
        .internal_whitelist()
        .iter()
        .map(InternalWhitelistEntry::to_string)
        .collect();
    let users: Vec<&str> = config.users.usernames().collect();
    info!(
        settings = %path.display(),
        listen_address = %config.listen_address,
        users = ?users,
        max_connections = config.max_connections,
        handshake_timeout_sec = config.timeouts.handshake.as_secs(),
        connect_timeout_sec = config.timeouts.connect.as_secs(),
        idle_timeout_sec = config.timeouts.idle.as_secs(),
        shutdown_grace_sec = config.timeouts.shutdown_grace.as_secs(),
        client_whitelist = ?client_whitelist,
        blocked_ports = ?policy.blocked_ports(),
        allow_internal = policy.allow_internal(),
        internal_whitelist = ?internal_whitelist,
        ban_max_failures = config.ban.max_failures,
        ban_window_sec = config.ban.window.as_secs(),
        ban_duration_sec = config.ban.duration.as_secs(),
        "settings loaded"
    );
    if config.client_acl.is_open() {
        warn!(
            "client_whitelist is empty: any IP may connect. SOCKS5 sends passwords in clear \
             text, restrict clients with client_whitelist"
        );
    }
    if policy.allow_internal() {
        warn!("allow_internal is on: private networks are reachable through the proxy");
    }
    #[cfg(unix)]
    if my_socks_server::config::is_readable_by_others(path) {
        warn!(
            settings = %path.display(),
            "settings file holds passwords but is readable by other users (chmod 600)"
        );
    }
}

fn raise_file_limit(config: &ServerConfig) {
    match raise_nofile_limit() {
        Ok(limit) => {
            info!(soft = limit.soft, hard = limit.hard, "RLIMIT_NOFILE");
            // Every proxied connection holds two descriptors: client and target.
            let needed = u64::from(config.max_connections) * 2 + FD_RESERVE;
            if limit.soft < needed {
                warn!(
                    soft = limit.soft,
                    needed,
                    "RLIMIT_NOFILE is below 2 x max_connections: accept() may hit EMFILE under \
                     load (the server survives it; raise LimitNOFILE / ulimits nofile)"
                );
            }
        }
        Err(error) => warn!(%error, "cannot raise RLIMIT_NOFILE"),
    }
}

async fn shutdown_signal() {
    let signal = tokio::select! {
        () = sigterm() => "SIGTERM",
        () = sigint() => "SIGINT",
    };
    info!(signal, "shutdown requested");
}

#[cfg(unix)]
async fn sigterm() {
    use tokio::signal::unix::{SignalKind, signal};
    match signal(SignalKind::terminate()) {
        Ok(mut stream) => {
            stream.recv().await;
        }
        Err(error) => {
            error!(%error, "cannot install the SIGTERM handler");
            std::future::pending::<()>().await;
        }
    }
}

#[cfg(not(unix))]
async fn sigterm() {
    std::future::pending::<()>().await;
}

async fn sigint() {
    if let Err(error) = tokio::signal::ctrl_c().await {
        error!(%error, "cannot install the SIGINT handler");
        std::future::pending::<()>().await;
    }
}
