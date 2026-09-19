mod common;

use std::time::Duration;

use common::{
    PASSWORD, TestProxy, USER, closed_within, echo_round_trip, settings, start_echo_server,
};
use my_socks_server::policy::DestinationPolicy;
use my_socks_server::socks::{
    ClientError, Command, Greeting, METHOD_NO_AUTH, METHOD_USER_PASS, MethodSelection, Reply,
    ReplyCode, Request, TargetAddr, UserPassRequest, UserPassResponse, client_handshake,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{Instant, sleep, timeout};

const LOOPBACK_WHITELIST: &str = "internal_whitelist: [127.0.0.1]\n";

async fn raw_connect(proxy: &TestProxy) -> TcpStream {
    TcpStream::connect(proxy.addr).await.unwrap()
}

async fn handshake_as(
    proxy: &TestProxy,
    username: &str,
    password: &str,
    target: TargetAddr,
) -> Result<TcpStream, ClientError> {
    let mut stream = raw_connect(proxy).await;
    client_handshake(&mut stream, username, password, &target)
        .await
        .map(|_| stream)
}

#[tokio::test]
async fn relays_data_after_handshake_auth_and_connect() {
    let echo = start_echo_server().await;
    let proxy = TestProxy::start(&settings(LOOPBACK_WHITELIST), |_| {}).await;

    let mut stream = proxy.connect(echo).await;
    assert_eq!(echo_round_trip(&mut stream, b"hello").await, b"hello");
    let big: Vec<u8> = (0..200_000_u32).map(|i| (i % 251) as u8).collect();
    assert_eq!(echo_round_trip(&mut stream, &big).await, big);

    // Client half-close is forwarded; the echo server then closes and so does the proxy.
    stream.shutdown().await.unwrap();
    assert!(closed_within(&mut stream, Duration::from_secs(5)).await);
    proxy.wait_idle(Duration::from_secs(5)).await;
    assert_eq!(proxy.state.stats.accepted.get(), 1);
    assert_eq!(proxy.state.stats.bytes_in.get(), 5 + 200_000);
    assert_eq!(proxy.state.stats.bytes_out.get(), 5 + 200_000);
    proxy.stop().await;
}

#[tokio::test]
async fn resolves_domain_targets_on_the_server() {
    let echo = start_echo_server().await;
    let proxy = TestProxy::start(&settings(LOOPBACK_WHITELIST), |_| {}).await;

    // "localhost" may also resolve to ::1, which is not whitelisted: it is filtered out.
    let target = TargetAddr::Domain {
        host: "localhost".into(),
        port: echo.port(),
    };
    let mut stream = handshake_as(&proxy, USER, PASSWORD, target).await.unwrap();
    assert_eq!(echo_round_trip(&mut stream, b"by name").await, b"by name");
    proxy.stop().await;
}

#[tokio::test]
async fn wrong_password_is_rejected_and_connection_closed() {
    let echo = start_echo_server().await;
    let proxy = TestProxy::start(&settings(LOOPBACK_WHITELIST), |_| {}).await;

    let mut stream = raw_connect(&proxy).await;
    let result = client_handshake(&mut stream, USER, "wrong", &TargetAddr::Ip(echo)).await;
    assert!(
        matches!(result, Err(ClientError::AuthRejected)),
        "{result:?}"
    );
    assert!(closed_within(&mut stream, Duration::from_secs(2)).await);

    let result = handshake_as(&proxy, "mallory", PASSWORD, TargetAddr::Ip(echo)).await;
    assert!(matches!(result, Err(ClientError::AuthRejected)));
    assert_eq!(proxy.state.stats.auth_failures.get(), 2);
    proxy.stop().await;
}

#[tokio::test]
async fn no_authentication_method_is_refused() {
    let proxy = TestProxy::start(&settings(""), |_| {}).await;
    let mut stream = raw_connect(&proxy).await;
    let greeting = Greeting {
        methods: vec![METHOD_NO_AUTH],
    };
    stream.write_all(&greeting.encode().unwrap()).await.unwrap();
    let selection = MethodSelection::read_from(&mut stream).await.unwrap();
    assert_eq!(selection, MethodSelection::NO_ACCEPTABLE);
    assert!(closed_within(&mut stream, Duration::from_secs(2)).await);
    proxy.stop().await;
}

#[tokio::test]
async fn idle_connection_is_closed_by_timeout() {
    let echo = start_echo_server().await;
    let proxy = TestProxy::start(&settings(LOOPBACK_WHITELIST), |config| {
        config.timeouts.idle = Duration::from_millis(500);
    })
    .await;

    let mut stream = proxy.connect(echo).await;
    assert_eq!(echo_round_trip(&mut stream, b"ping").await, b"ping");
    let started = Instant::now();
    assert!(closed_within(&mut stream, Duration::from_secs(5)).await);
    assert!(started.elapsed() >= Duration::from_millis(400));
    proxy.wait_idle(Duration::from_secs(2)).await;
    proxy.stop().await;
}

#[tokio::test]
async fn silent_client_hits_handshake_timeout() {
    let proxy = TestProxy::start(&settings(""), |config| {
        config.timeouts.handshake = Duration::from_millis(300);
    })
    .await;

    let mut stream = raw_connect(&proxy).await;
    stream.write_all(&[0x05]).await.unwrap(); // half a greeting, then silence
    assert!(closed_within(&mut stream, Duration::from_secs(3)).await);
    proxy.wait_idle(Duration::from_secs(2)).await;
    proxy.stop().await;
}

#[tokio::test]
async fn internal_destinations_need_the_whitelist() {
    let echo = start_echo_server().await;

    let closed = TestProxy::start(&settings(""), |_| {}).await;
    let result = handshake_as(&closed, USER, PASSWORD, TargetAddr::Ip(echo)).await;
    assert!(
        matches!(
            result,
            Err(ClientError::RequestRejected(ReplyCode::NotAllowed))
        ),
        "{result:?}"
    );
    assert_eq!(closed.state.stats.denied_by_policy.get(), 1);
    closed.stop().await;

    // allow_internal opens private networks, not the loopback of the proxy host.
    let private_only = TestProxy::start(&settings("allow_internal: true\n"), |_| {}).await;
    let result = handshake_as(&private_only, USER, PASSWORD, TargetAddr::Ip(echo)).await;
    assert!(matches!(
        result,
        Err(ClientError::RequestRejected(ReplyCode::NotAllowed))
    ));
    private_only.stop().await;

    // A whitelist entry with a different port does not open this one.
    let other_port =
        TestProxy::start(&settings("internal_whitelist: [\"127.0.0.1:1\"]\n"), |_| {}).await;
    let result = handshake_as(&other_port, USER, PASSWORD, TargetAddr::Ip(echo)).await;
    assert!(matches!(
        result,
        Err(ClientError::RequestRejected(ReplyCode::NotAllowed))
    ));
    other_port.stop().await;

    let whitelisted = TestProxy::start(
        &settings(&format!(
            "internal_whitelist: [\"127.0.0.1:{}\"]\n",
            echo.port()
        )),
        |_| {},
    )
    .await;
    let mut stream = whitelisted.connect(echo).await;
    assert_eq!(echo_round_trip(&mut stream, b"ok").await, b"ok");
    whitelisted.stop().await;
}

#[tokio::test]
async fn ipv4_mapped_ipv6_target_is_judged_as_ipv4() {
    let echo = start_echo_server().await;
    let proxy = TestProxy::start(&settings(""), |_| {}).await;
    let mapped = format!("[::ffff:127.0.0.1]:{}", echo.port())
        .parse()
        .unwrap();
    let result = handshake_as(&proxy, USER, PASSWORD, TargetAddr::Ip(mapped)).await;
    assert!(matches!(
        result,
        Err(ClientError::RequestRejected(ReplyCode::NotAllowed))
    ));
    proxy.stop().await;
}

#[tokio::test]
async fn blocked_ports_apply_to_whitelisted_destinations() {
    let echo = start_echo_server().await;
    let proxy = TestProxy::start(&settings(LOOPBACK_WHITELIST), |config| {
        let whitelist = config.destination_policy.internal_whitelist().to_vec();
        config.destination_policy = DestinationPolicy::new(vec![echo.port()], false, whitelist);
    })
    .await;
    let result = handshake_as(&proxy, USER, PASSWORD, TargetAddr::Ip(echo)).await;
    assert!(matches!(
        result,
        Err(ClientError::RequestRejected(ReplyCode::NotAllowed))
    ));
    proxy.stop().await;
}

#[tokio::test]
async fn unsupported_command_is_answered() {
    let echo = start_echo_server().await;
    let proxy = TestProxy::start(&settings(LOOPBACK_WHITELIST), |_| {}).await;
    let mut stream = raw_connect(&proxy).await;

    let greeting = Greeting {
        methods: vec![METHOD_USER_PASS],
    };
    stream.write_all(&greeting.encode().unwrap()).await.unwrap();
    MethodSelection::read_from(&mut stream).await.unwrap();
    let credentials = UserPassRequest {
        username: USER.into(),
        password: PASSWORD.into(),
    };
    stream
        .write_all(&credentials.encode().unwrap())
        .await
        .unwrap();
    assert!(
        UserPassResponse::read_from(&mut stream)
            .await
            .unwrap()
            .is_success()
    );
    let request = Request {
        command: Command::Bind,
        target: TargetAddr::Ip(echo),
    };
    stream.write_all(&request.encode().unwrap()).await.unwrap();
    let reply = Reply::read_from(&mut stream).await.unwrap();
    assert_eq!(reply.code, ReplyCode::CommandNotSupported);
    assert!(closed_within(&mut stream, Duration::from_secs(2)).await);
    proxy.stop().await;
}

#[tokio::test]
async fn repeated_auth_failures_ban_the_client() {
    let echo = start_echo_server().await;
    let yaml = settings(&format!("{LOOPBACK_WHITELIST}ban_max_failures: 2\n"));
    let proxy = TestProxy::start(&yaml, |_| {}).await;

    for _ in 0..2 {
        let result = handshake_as(&proxy, USER, "wrong", TargetAddr::Ip(echo)).await;
        assert!(matches!(result, Err(ClientError::AuthRejected)));
    }
    // Banned: dropped right after accept, even with the right password.
    let mut stream = raw_connect(&proxy).await;
    let _ = stream.write_all(&[0x05, 0x01, METHOD_USER_PASS]).await;
    assert!(closed_within(&mut stream, Duration::from_secs(2)).await);
    let mut first_byte = [0; 1];
    assert!(!matches!(stream.read(&mut first_byte).await, Ok(1)));
    assert_eq!(proxy.state.stats.rejected_banned.get(), 1);
    assert_eq!(proxy.state.ban_list.stats().banned, 1);
    proxy.stop().await;
}

#[tokio::test]
async fn clients_outside_the_whitelist_are_dropped() {
    let proxy = TestProxy::start(&settings("client_whitelist: [10.0.0.0/8]\n"), |_| {}).await;
    let mut stream = raw_connect(&proxy).await;
    let _ = stream.write_all(&[0x05, 0x01, METHOD_USER_PASS]).await;
    assert!(closed_within(&mut stream, Duration::from_secs(2)).await);
    assert_eq!(proxy.state.stats.rejected_not_whitelisted.get(), 1);
    assert_eq!(proxy.state.stats.accepted.get(), 0);
    proxy.stop().await;
}

#[tokio::test]
async fn connections_over_the_limit_are_closed_immediately() {
    let echo = start_echo_server().await;
    let proxy = TestProxy::start(
        &settings(&format!("{LOOPBACK_WHITELIST}max_connections: 1\n")),
        |_| {},
    )
    .await;

    let mut first = proxy.connect(echo).await;
    let mut second = raw_connect(&proxy).await;
    assert!(closed_within(&mut second, Duration::from_secs(2)).await);
    assert_eq!(proxy.state.stats.rejected_over_limit.get(), 1);
    assert_eq!(
        echo_round_trip(&mut first, b"still fine").await,
        b"still fine"
    );

    drop(first);
    proxy.wait_idle(Duration::from_secs(5)).await;
    let mut third = proxy.connect(echo).await;
    assert_eq!(echo_round_trip(&mut third, b"again").await, b"again");
    proxy.stop().await;
}

#[tokio::test]
async fn graceful_shutdown_lets_connections_finish_then_closes_them() {
    let echo = start_echo_server().await;
    let mut proxy = TestProxy::start(&settings(LOOPBACK_WHITELIST), |config| {
        config.timeouts.shutdown_grace = Duration::from_millis(800);
    })
    .await;
    let mut active = proxy.connect(echo).await;
    let addr = proxy.addr;

    proxy.begin_shutdown();
    // New connections are refused once the listener is closed.
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match TcpStream::connect(addr).await {
            Err(_) => break,
            Ok(_) if Instant::now() < deadline => sleep(Duration::from_millis(10)).await,
            Ok(_) => panic!("listener still accepts after shutdown"),
        }
    }
    // The open connection keeps working during the grace period ...
    assert_eq!(echo_round_trip(&mut active, b"grace").await, b"grace");
    // ... and is closed when it ends.
    assert!(closed_within(&mut active, Duration::from_secs(3)).await);
    let started = Instant::now();
    while !proxy.is_finished() {
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "server did not stop"
        );
        sleep(Duration::from_millis(10)).await;
    }
    proxy.stop().await;
}

#[tokio::test]
async fn garbage_input_does_not_hurt_the_server() {
    let echo = start_echo_server().await;
    let proxy = TestProxy::start(&settings(LOOPBACK_WHITELIST), |_| {}).await;
    for garbage in [
        &b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"[..],
        &[0x04, 0x01, 0x00, 0x50, 127, 0, 0, 1, 0],
        &[0x05, 0x00],
        &[0x05, 0x01, 0x02, 0x05, 0x00],
    ] {
        let mut stream = raw_connect(&proxy).await;
        let _ = stream.write_all(garbage).await;
        assert!(closed_within(&mut stream, Duration::from_secs(2)).await);
    }
    let mut stream = timeout(Duration::from_secs(2), proxy.connect(echo))
        .await
        .unwrap();
    assert_eq!(echo_round_trip(&mut stream, b"alive").await, b"alive");
    proxy.stop().await;
}
