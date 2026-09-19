use std::io;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use super::ActivityClock;

/// Copy buffer per direction.
pub const RELAY_BUFFER_SIZE: usize = 16 * 1024;

/// Bytes delivered by each direction; updated after every write, so the numbers stay correct
/// even if the relay future is dropped half-way (shutdown).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RelayCounters {
    /// Written to the target: what the client uploaded (`bytes_in` in the logs).
    pub client_to_target: u64,
    /// Written to the client: what the client downloaded (`bytes_out` in the logs).
    pub target_to_client: u64,
}

/// How a relay ended. On every variant both streams are finished with: the caller drops them.
#[derive(Debug)]
pub enum RelayEnd {
    /// Both directions reached EOF; each half-close was forwarded to the other side.
    Completed,
    /// No byte moved in either direction for the idle timeout.
    IdleTimeout,
    /// Reading from or writing to the client failed.
    ClientError(io::Error),
    /// Reading from or writing to the target failed.
    TargetError(io::Error),
}

/// The four halves of a client/target stream pair.
pub struct RelayHalves<ClientRead, ClientWrite, TargetRead, TargetWrite> {
    pub client_reader: ClientRead,
    pub client_writer: ClientWrite,
    pub target_reader: TargetRead,
    pub target_writer: TargetWrite,
}

/// Relays a proxied TCP connection until both sides close, one side fails, or nothing moves
/// for `idle_timeout`.
pub async fn relay_tcp(
    client: &mut TcpStream,
    target: &mut TcpStream,
    idle_timeout: Duration,
    counters: &mut RelayCounters,
) -> RelayEnd {
    let (client_reader, client_writer) = client.split();
    let (target_reader, target_writer) = target.split();
    let halves = RelayHalves {
        client_reader,
        client_writer,
        target_reader,
        target_writer,
    };
    relay(halves, idle_timeout, counters).await
}

/// Copies both directions concurrently (`tokio::io::copy_bidirectional` has no idle timeout).
///
/// * Every `read` and `write` is wrapped in `tokio::time::timeout`, so no await can hang.
///   The deadline is shared: a direction whose timer fires keeps waiting as long as the
///   other direction moved data within `idle_timeout`.
/// * EOF on one side is forwarded as `shutdown()` of the other side's write half; the
///   remaining direction keeps flowing (half-close).
/// * An error or the idle timeout ends the relay at once; the caller drops both streams.
pub async fn relay<ClientRead, ClientWrite, TargetRead, TargetWrite>(
    halves: RelayHalves<ClientRead, ClientWrite, TargetRead, TargetWrite>,
    idle_timeout: Duration,
    counters: &mut RelayCounters,
) -> RelayEnd
where
    ClientRead: AsyncRead + Unpin,
    ClientWrite: AsyncWrite + Unpin,
    TargetRead: AsyncRead + Unpin,
    TargetWrite: AsyncWrite + Unpin,
{
    let RelayHalves {
        mut client_reader,
        mut client_writer,
        mut target_reader,
        mut target_writer,
    } = halves;
    let clock = ActivityClock::new();
    let upload = pump(
        &mut client_reader,
        &mut target_writer,
        &clock,
        idle_timeout,
        &mut counters.client_to_target,
    );
    let download = pump(
        &mut target_reader,
        &mut client_writer,
        &clock,
        idle_timeout,
        &mut counters.target_to_client,
    );
    tokio::pin!(upload, download);

    let mut upload_done = false;
    let mut download_done = false;
    while !(upload_done && download_done) {
        tokio::select! {
            result = &mut upload, if !upload_done => match result {
                Ok(()) => upload_done = true,
                Err(PumpError::Idle) => return RelayEnd::IdleTimeout,
                Err(PumpError::Read(error)) => return RelayEnd::ClientError(error),
                Err(PumpError::Write(error)) => return RelayEnd::TargetError(error),
            },
            result = &mut download, if !download_done => match result {
                Ok(()) => download_done = true,
                Err(PumpError::Idle) => return RelayEnd::IdleTimeout,
                Err(PumpError::Read(error)) => return RelayEnd::TargetError(error),
                Err(PumpError::Write(error)) => return RelayEnd::ClientError(error),
            },
        }
    }
    RelayEnd::Completed
}

enum PumpError {
    Idle,
    Read(io::Error),
    Write(io::Error),
}

/// One direction: read → write until EOF, then half-close the writer.
async fn pump<R, W>(
    reader: &mut R,
    writer: &mut W,
    clock: &ActivityClock,
    idle_timeout: Duration,
    delivered: &mut u64,
) -> Result<(), PumpError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = vec![0; RELAY_BUFFER_SIZE];
    loop {
        let read = read_with_idle(reader, &mut buffer, clock, idle_timeout).await?;
        let Some(chunk) = buffer.get(..read).filter(|chunk| !chunk.is_empty()) else {
            // EOF: forward the half-close. A failure here means the peer is already gone,
            // which the other direction reports on its own.
            let _ = timeout(idle_timeout, writer.shutdown()).await;
            return Ok(());
        };
        clock.touch();
        write_all_with_idle(writer, chunk, clock, idle_timeout, delivered).await?;
    }
}

async fn read_with_idle<R: AsyncRead + Unpin>(
    reader: &mut R,
    buffer: &mut [u8],
    clock: &ActivityClock,
    idle_timeout: Duration,
) -> Result<usize, PumpError> {
    loop {
        let remaining = clock.remaining(idle_timeout);
        if remaining.is_zero() {
            return Err(PumpError::Idle);
        }
        // `read` is cancel safe: a timed-out attempt loses no data.
        if let Ok(result) = timeout(remaining, reader.read(buffer)).await {
            return result.map_err(PumpError::Read);
        }
    }
}

async fn write_all_with_idle<W: AsyncWrite + Unpin>(
    writer: &mut W,
    mut data: &[u8],
    clock: &ActivityClock,
    idle_timeout: Duration,
    delivered: &mut u64,
) -> Result<(), PumpError> {
    while !data.is_empty() {
        let remaining = clock.remaining(idle_timeout);
        if remaining.is_zero() {
            return Err(PumpError::Idle);
        }
        // `write` is cancel safe: nothing is written by an attempt that timed out.
        let Ok(result) = timeout(remaining, writer.write(data)).await else {
            continue;
        };
        let written = result.map_err(PumpError::Write)?;
        if written == 0 {
            return Err(PumpError::Write(io::ErrorKind::WriteZero.into()));
        }
        clock.touch();
        *delivered = delivered.saturating_add(u64::try_from(written).unwrap_or(u64::MAX));
        data = data.get(written..).unwrap_or_default();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, duplex, split};
    use tokio::time::{Instant, sleep};

    use super::*;

    const IDLE: Duration = Duration::from_secs(10);

    /// Returns (client-side peer, target-side peer, relay task).
    fn start_relay() -> (
        DuplexStream,
        DuplexStream,
        tokio::task::JoinHandle<(RelayEnd, RelayCounters)>,
    ) {
        let (client_peer, client_side) = duplex(64 * 1024);
        let (target_side, target_peer) = duplex(64 * 1024);
        let task = tokio::spawn(async move {
            let (client_reader, client_writer) = split(client_side);
            let (target_reader, target_writer) = split(target_side);
            let halves = RelayHalves {
                client_reader,
                client_writer,
                target_reader,
                target_writer,
            };
            let mut counters = RelayCounters::default();
            let end = relay(halves, IDLE, &mut counters).await;
            (end, counters)
        });
        (client_peer, target_peer, task)
    }

    #[tokio::test(start_paused = true)]
    async fn copies_both_directions_and_propagates_half_close() {
        let (mut client, mut target, task) = start_relay();

        client.write_all(b"request").await.unwrap();
        client.shutdown().await.unwrap();
        let mut received = Vec::new();
        target.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, b"request", "client EOF reaches the target");

        target
            .write_all(b"response after half-close")
            .await
            .unwrap();
        target.shutdown().await.unwrap();
        let mut received = Vec::new();
        client.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, b"response after half-close");

        let (end, counters) = task.await.unwrap();
        assert!(matches!(end, RelayEnd::Completed), "{end:?}");
        assert_eq!(counters.client_to_target, 7);
        assert_eq!(counters.target_to_client, 25);
    }

    #[tokio::test(start_paused = true)]
    async fn silent_connection_hits_idle_timeout() {
        let (_client, _target, task) = start_relay();
        let started = Instant::now();
        let (end, _) = task.await.unwrap();
        assert!(matches!(end, RelayEnd::IdleTimeout), "{end:?}");
        assert!(started.elapsed() >= IDLE);
        assert!(started.elapsed() < IDLE + Duration::from_secs(1));
    }

    #[tokio::test(start_paused = true)]
    async fn one_way_traffic_is_not_idle() {
        let (mut client, mut target, task) = start_relay();
        let started = Instant::now();
        // A long download: only target → client moves, far longer than the idle timeout.
        for _ in 0..6 {
            sleep(IDLE / 2).await;
            target.write_all(b"chunk").await.unwrap();
            let mut chunk = [0; 5];
            client.read_exact(&mut chunk).await.unwrap();
        }
        assert!(started.elapsed() >= IDLE * 3);
        assert!(!task.is_finished(), "relay must survive one-way traffic");

        let (end, counters) = task.await.unwrap();
        assert!(matches!(end, RelayEnd::IdleTimeout), "{end:?}");
        assert_eq!(counters.target_to_client, 30);
    }

    #[tokio::test(start_paused = true)]
    async fn half_closed_connection_still_times_out() {
        let (mut client, _target, task) = start_relay();
        client.shutdown().await.unwrap();
        let (end, _) = task.await.unwrap();
        assert!(matches!(end, RelayEnd::IdleTimeout), "{end:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn stalled_writer_times_out() {
        // The target never reads: once the pipe buffer is full, writes stall.
        let (client_peer, client_side) = duplex(64 * 1024);
        let (target_side, _target_peer) = duplex(1024);
        let task = tokio::spawn(async move {
            let (client_reader, client_writer) = split(client_side);
            let (target_reader, target_writer) = split(target_side);
            let halves = RelayHalves {
                client_reader,
                client_writer,
                target_reader,
                target_writer,
            };
            let mut counters = RelayCounters::default();
            relay(halves, IDLE, &mut counters).await
        });
        let (_client_reader, mut client_writer) = split(client_peer);
        client_writer.write_all(&[7; 8 * 1024]).await.unwrap();
        let end = task.await.unwrap();
        assert!(matches!(end, RelayEnd::IdleTimeout), "{end:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn target_failure_ends_relay_with_target_error() {
        let (mut client, target, task) = start_relay();
        // Writes towards a dropped duplex end fail with BrokenPipe.
        drop(target);
        client.write_all(b"data").await.unwrap();
        let (end, _) = task.await.unwrap();
        assert!(matches!(end, RelayEnd::TargetError(_)), "{end:?}");
    }
}
