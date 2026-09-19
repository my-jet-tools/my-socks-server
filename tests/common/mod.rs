//! Shared helpers for the integration tests: an in-process proxy and an echo target.
#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use my_socks_server::config::{ServerConfig, SettingsModel};
use my_socks_server::server::{ServerState, SocksServer};
use my_socks_server::socks::{TargetAddr, client_handshake};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio::time::{Instant, sleep, timeout};

pub const USER: &str = "alice";
pub const PASSWORD: &str = "correct horse battery staple";

/// Settings YAML with one user plus `extra` lines.
pub fn settings(extra: &str) -> String {
    format!("users:\n  - username: {USER}\n    password: \"{PASSWORD}\"\n{extra}")
}

pub struct TestProxy {
    pub addr: SocketAddr,
    pub state: Arc<ServerState>,
    shutdown: Option<oneshot::Sender<()>>,
    task: JoinHandle<()>,
}

impl TestProxy {
    /// Starts a proxy on 127.0.0.1 with an ephemeral port; `tweak` adjusts the parsed config
    /// (e.g. sub-second timeouts).
    pub async fn start(yaml: &str, tweak: impl FnOnce(&mut ServerConfig)) -> Self {
        let settings = SettingsModel::from_yaml(yaml.as_bytes()).expect("valid test settings");
        let mut config = ServerConfig::from_settings(settings).expect("valid test config");
        config.listen_address = "127.0.0.1:0".parse().unwrap();
        // Tests stop the server with connections still open; do not wait the default 10 s.
        config.timeouts.shutdown_grace = Duration::from_secs(1);
        tweak(&mut config);
        let server = SocksServer::bind(config).await.unwrap();
        let addr = server.local_addr().unwrap();
        let state = server.state();
        let (shutdown, signal) = oneshot::channel::<()>();
        let task = tokio::spawn(server.run(async move {
            let _ = signal.await;
        }));
        Self {
            addr,
            state,
            shutdown: Some(shutdown),
            task,
        }
    }

    /// Triggers the graceful shutdown without waiting for it.
    pub fn begin_shutdown(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
    }

    /// Triggers the graceful shutdown and waits until `run` returned.
    pub async fn stop(mut self) {
        self.begin_shutdown();
        timeout(Duration::from_secs(30), self.task)
            .await
            .expect("server stops in time")
            .unwrap();
    }

    pub fn is_finished(&self) -> bool {
        self.task.is_finished()
    }

    /// Connection through the proxy to `target`, authenticated as the test user.
    pub async fn connect(&self, target: SocketAddr) -> TcpStream {
        let mut stream = TcpStream::connect(self.addr).await.unwrap();
        client_handshake(&mut stream, USER, PASSWORD, &TargetAddr::Ip(target))
            .await
            .unwrap();
        stream
    }

    /// Waits until no client connection is open.
    pub async fn wait_idle(&self, limit: Duration) {
        let deadline = Instant::now() + limit;
        while self.state.active_connections() > 0 {
            assert!(
                Instant::now() < deadline,
                "{} connections still open",
                self.state.active_connections()
            );
            sleep(Duration::from_millis(20)).await;
        }
    }
}

/// Echo server on 127.0.0.1: returns everything it reads, closes on EOF.
pub async fn start_echo_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (mut reader, mut writer) = stream.split();
                let _ = tokio::io::copy(&mut reader, &mut writer).await;
            });
        }
    });
    addr
}

/// Sends `payload` and reads the same number of bytes back (concurrently, so large payloads
/// cannot deadlock on full socket buffers).
pub async fn echo_round_trip(stream: &mut TcpStream, payload: &[u8]) -> Vec<u8> {
    let (mut reader, mut writer) = stream.split();
    let mut received = vec![0; payload.len()];
    let (written, read) = timeout(Duration::from_secs(10), async {
        tokio::join!(writer.write_all(payload), reader.read_exact(&mut received))
    })
    .await
    .expect("echo in time");
    written.unwrap();
    read.unwrap();
    received
}

/// True when the peer closes the connection (EOF or reset) within `limit`.
pub async fn closed_within(stream: &mut TcpStream, limit: Duration) -> bool {
    let mut buffer = [0; 64];
    loop {
        match timeout(limit, stream.read(&mut buffer)).await {
            Ok(Ok(0) | Err(_)) => return true,
            Ok(Ok(_)) => {}
            Err(_elapsed) => return false,
        }
    }
}
