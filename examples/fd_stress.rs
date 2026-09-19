//! Descriptor-leak stress check.
//!
//! Starts the proxy and an echo target in-process, opens many connections and abandons them
//! without closing: half finish the SOCKS handshake and go silent (idle timeout), half stop in
//! the middle of the greeting (handshake timeout). Once the timeouts fire, the process must be
//! back at its baseline descriptor count, apart from the client sockets this program still holds.
//!
//! ```text
//! cargo run --release --example fd_stress -- --connections 2000 --timeout-ms 2000
//! ```

use std::net::SocketAddr;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use anyhow::{Context, bail, ensure};
use my_socks_server::config::{ServerConfig, SettingsModel};
use my_socks_server::limits::{count_open_fds, raise_nofile_limit};
use my_socks_server::server::{ServerState, SocksServer};
use my_socks_server::socks::{TargetAddr, client_handshake};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::sleep;

const USAGE: &str = "usage: fd_stress [--connections N] [--timeout-ms MS]";
const USER: &str = "stress";
const PASSWORD: &str = "stress-password";

struct Options {
    /// Total abandoned connections (half established, half mid-handshake).
    connections: usize,
    /// Idle and handshake timeout of the proxy under test.
    timeout: Duration,
}

impl Options {
    fn from_args() -> anyhow::Result<Self> {
        let mut options = Self {
            connections: 1000,
            timeout: Duration::from_millis(2000),
        };
        let mut args = std::env::args().skip(1);
        while let Some(flag) = args.next() {
            let value = args
                .next()
                .with_context(|| format!("{flag} needs a value"))?;
            match flag.as_str() {
                "--connections" => options.connections = value.parse()?,
                "--timeout-ms" => options.timeout = Duration::from_millis(value.parse()?),
                other => bail!("unknown argument {other}"),
            }
        }
        ensure!(options.connections >= 2, "--connections must be at least 2");
        Ok(options)
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => {
            println!("PASS: every descriptor was released");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("FAIL: {error:#}\n{USAGE}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> anyhow::Result<()> {
    let options = Options::from_args()?;
    let limit = raise_nofile_limit()?;
    println!("RLIMIT_NOFILE soft={} hard={}", limit.soft, limit.hard);

    let echo = start_echo_server().await?;
    let (proxy, state) = start_proxy(&options).await?;

    let mut warm_up = connect_through(proxy, echo).await?;
    warm_up.write_all(b"warm-up").await?;
    let mut buffer = [0; 7];
    warm_up.read_exact(&mut buffer).await?;
    drop(warm_up);
    wait_until_idle(&state, options.timeout * 3).await?;
    sleep(Duration::from_millis(200)).await;
    let baseline = count_open_fds()?;
    println!("baseline: {baseline} open descriptors");

    let established = options.connections / 2;
    let mut abandoned: Vec<TcpStream> = Vec::with_capacity(options.connections);
    for _ in 0..established {
        abandoned.push(connect_through(proxy, echo).await?);
    }
    for _ in established..options.connections {
        let mut stream = TcpStream::connect(proxy).await?;
        stream.write_all(&[0x05]).await?;
        abandoned.push(stream);
    }
    println!(
        "opened {} connections ({established} silent relays, {} half handshakes): {} open descriptors, {} active in the proxy",
        abandoned.len(),
        abandoned.len() - established,
        count_open_fds()?,
        state.active_connections()
    );

    let started = Instant::now();
    wait_until_idle(&state, options.timeout * 3 + Duration::from_secs(10)).await?;
    sleep(Duration::from_millis(500)).await;
    let after = count_open_fds()?;
    println!(
        "timeouts fired after {:.1}s: {after} open descriptors ({} are the abandoned client sockets)",
        started.elapsed().as_secs_f64(),
        abandoned.len()
    );
    ensure!(
        after == baseline + abandoned.len(),
        "expected {} descriptors, found {after}",
        baseline + abandoned.len()
    );

    drop(abandoned);
    sleep(Duration::from_millis(200)).await;
    let released = count_open_fds()?;
    println!("client sockets closed: {released} open descriptors");
    ensure!(
        released == baseline,
        "expected the baseline of {baseline}, found {released}"
    );
    Ok(())
}

async fn start_proxy(
    options: &Options,
) -> anyhow::Result<(SocketAddr, std::sync::Arc<ServerState>)> {
    let max_connections = options.connections + 16;
    let yaml = format!(
        "users:\n  - username: {USER}\n    password: {PASSWORD}\n\
         internal_whitelist: [127.0.0.1]\nmax_connections: {max_connections}\n"
    );
    let mut config = ServerConfig::from_settings(SettingsModel::from_yaml(yaml.as_bytes())?)?;
    config.listen_address = "127.0.0.1:0".parse()?;
    config.timeouts.idle = options.timeout;
    config.timeouts.handshake = options.timeout;
    let server = SocksServer::bind(config).await?;
    let addr = server.local_addr()?;
    let state = server.state();
    tokio::spawn(server.run(std::future::pending()));
    Ok((addr, state))
}

async fn connect_through(proxy: SocketAddr, target: SocketAddr) -> anyhow::Result<TcpStream> {
    let mut stream = TcpStream::connect(proxy).await?;
    client_handshake(&mut stream, USER, PASSWORD, &TargetAddr::Ip(target)).await?;
    Ok(stream)
}

async fn wait_until_idle(state: &ServerState, limit: Duration) -> anyhow::Result<()> {
    let started = Instant::now();
    let mut last_report = Instant::now();
    while state.active_connections() > 0 {
        ensure!(
            started.elapsed() < limit,
            "{} connections still open after {limit:?}",
            state.active_connections()
        );
        if last_report.elapsed() >= Duration::from_secs(1) {
            println!(
                "  waiting: {} active connections, {} open descriptors",
                state.active_connections(),
                count_open_fds()?
            );
            last_report = Instant::now();
        }
        sleep(Duration::from_millis(50)).await;
    }
    Ok(())
}

async fn start_echo_server() -> anyhow::Result<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (mut reader, mut writer) = stream.split();
                let _ = tokio::io::copy(&mut reader, &mut writer).await;
            });
        }
    });
    Ok(addr)
}
