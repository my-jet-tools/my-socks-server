//! Abandoned clients must not leak descriptors: after the timeouts the process holds exactly
//! what it held before, apart from the client sockets the test itself keeps open.
//! Runs in its own test binary (own process), so the descriptor count is not disturbed by
//! other tests.

mod common;

use std::time::Duration;

use common::{TestProxy, echo_round_trip, settings, start_echo_server};
use my_socks_server::limits::{count_open_fds, raise_nofile_limit};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::time::sleep;

const ESTABLISHED: usize = 150;
const HALF_HANDSHAKES: usize = 150;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn abandoned_connections_release_every_descriptor() {
    raise_nofile_limit().unwrap();
    let echo = start_echo_server().await;
    let proxy = TestProxy::start(&settings("internal_whitelist: [127.0.0.1]\n"), |config| {
        config.timeouts.idle = Duration::from_millis(700);
        config.timeouts.handshake = Duration::from_millis(700);
    })
    .await;

    // Warm up once, so lazily created runtime resources exist before the baseline.
    {
        let mut stream = proxy.connect(echo).await;
        assert_eq!(echo_round_trip(&mut stream, b"warm-up").await, b"warm-up");
    }
    proxy.wait_idle(Duration::from_secs(5)).await;
    sleep(Duration::from_millis(200)).await;
    let baseline = count_open_fds().unwrap();

    // Clients that vanish without closing: relays gone silent, and half-sent greetings.
    let mut abandoned: Vec<TcpStream> = Vec::new();
    for _ in 0..ESTABLISHED {
        abandoned.push(proxy.connect(echo).await);
    }
    for _ in 0..HALF_HANDSHAKES {
        let mut stream = TcpStream::connect(proxy.addr).await.unwrap();
        stream.write_all(&[0x05]).await.unwrap();
        abandoned.push(stream);
    }
    let peak = count_open_fds().unwrap();
    // client + proxy client side + proxy target side + echo side per relay,
    // client + proxy side per half handshake.
    assert!(
        peak >= baseline + ESTABLISHED * 4 + HALF_HANDSHAKES * 2,
        "baseline={baseline} peak={peak}"
    );

    proxy.wait_idle(Duration::from_secs(10)).await;
    // The echo server closes its side after the proxy's FIN.
    sleep(Duration::from_millis(300)).await;
    let after_timeouts = count_open_fds().unwrap();
    assert_eq!(
        after_timeouts,
        baseline + abandoned.len(),
        "only the test's own client sockets may remain"
    );

    drop(abandoned);
    sleep(Duration::from_millis(100)).await;
    assert_eq!(count_open_fds().unwrap(), baseline);

    // And the server still works.
    let mut stream = proxy.connect(echo).await;
    assert_eq!(echo_round_trip(&mut stream, b"alive").await, b"alive");
    drop(stream);
    proxy.stop().await;
}
