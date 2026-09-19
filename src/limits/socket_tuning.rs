use std::io;
use std::time::Duration;

use socket2::{SockRef, TcpKeepalive};
use tokio::net::TcpStream;

/// Idle time before the first keepalive probe.
pub const KEEPALIVE_IDLE: Duration = Duration::from_secs(60);
/// Interval between keepalive probes.
pub const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);
/// Unanswered probes before the kernel drops the connection.
pub const KEEPALIVE_RETRIES: u32 = 3;
/// Linux `TCP_USER_TIMEOUT`: data unacknowledged for this long kills the connection. Keepalive
/// only probes idle connections; this covers a peer that vanished while we were sending, with
/// the same budget as keepalive (60 s + 3 × 10 s).
#[cfg(target_os = "linux")]
pub const TCP_USER_TIMEOUT: Duration = Duration::from_secs(90);

/// Enables `TCP_NODELAY` and TCP keepalive, so the kernel detects dead peers on its own.
///
/// # Errors
/// `setsockopt` failure.
pub fn tune_tcp_stream(stream: &TcpStream) -> io::Result<()> {
    stream.set_nodelay(true)?;
    let socket = SockRef::from(stream);
    let keepalive = TcpKeepalive::new().with_time(KEEPALIVE_IDLE);
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    let keepalive = keepalive
        .with_interval(KEEPALIVE_INTERVAL)
        .with_retries(KEEPALIVE_RETRIES);
    socket.set_tcp_keepalive(&keepalive)?;
    #[cfg(target_os = "linux")]
    socket.set_tcp_user_timeout(Some(TCP_USER_TIMEOUT))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn applies_socket_options() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        tune_tcp_stream(&client).unwrap();
        assert!(client.nodelay().unwrap());
        let socket = SockRef::from(&client);
        assert!(socket.keepalive().unwrap());
        assert_eq!(socket.tcp_keepalive_time().unwrap(), KEEPALIVE_IDLE);
    }
}
