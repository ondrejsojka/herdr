use super::*;
#[derive(Clone, Copy)]
pub(super) enum NetworkMode {
    Online,
    ThreeG,
    Blackhole,
}

pub(super) async fn run_udp_proxy(
    socket: Arc<tokio::net::UdpSocket>,
    server: SocketAddr,
    mode: watch::Receiver<NetworkMode>,
    profile: ShapingProfile,
) {
    let mut client = None;
    let mut packet_index = 0u64;
    let mut buffer = vec![0u8; 65_535];
    let mut next_upstream = tokio::time::Instant::now();
    let mut next_downstream = tokio::time::Instant::now();
    loop {
        let Ok((length, source)) = socket.recv_from(&mut buffer).await else {
            return;
        };
        let from_server = source == server;
        let target = if from_server {
            let Some(client) = client else { continue };
            client
        } else {
            client = Some(source);
            server
        };
        packet_index = packet_index.saturating_add(1);
        let current_mode = *mode.borrow();
        let lose_packet = profile
            .loss_every_nth
            .is_some_and(|n| packet_index.is_multiple_of(n));
        if matches!(current_mode, NetworkMode::Blackhole)
            || (matches!(current_mode, NetworkMode::ThreeG) && lose_packet)
        {
            continue;
        }
        let packet = buffer[..length].to_vec();
        let socket = Arc::clone(&socket);
        let delay = if matches!(current_mode, NetworkMode::ThreeG) {
            let rate = if from_server {
                profile.down_bytes_per_second
            } else {
                profile.up_bytes_per_second
            };
            let serialization = Duration::from_secs_f64(packet.len() as f64 / rate);
            let next_delivery = if from_server {
                &mut next_downstream
            } else {
                &mut next_upstream
            };
            let now = tokio::time::Instant::now();
            *next_delivery = (*next_delivery).max(now) + serialization;
            let jitter_ms = packet_index.wrapping_mul(17) % profile.jitter_span_ms;
            next_delivery
                .saturating_duration_since(now)
                .saturating_add(Duration::from_millis(profile.base_latency_ms + jitter_ms))
        } else {
            Duration::ZERO
        };
        tokio::spawn(async move {
            tokio::time::sleep(delay).await;
            let _ = socket.send_to(&packet, target).await;
        });
    }
}

/// Shapes one direction of a TCP byte stream to the same delay/jitter/
/// bandwidth model `run_udp_proxy` applies per datagram, applied per
/// `read()` chunk instead of per packet. Order is preserved by a channel's
/// FIFO delivery plus a single sequential drain task -- unlike UDP,
/// reordering a TCP byte stream would corrupt framing, not merely arrive
/// late, so (unlike `run_udp_proxy`) delayed chunks are never sent
/// independently/concurrently.
pub(super) async fn shape_tcp_direction(
    mut reader: OwnedReadHalf,
    mut writer: OwnedWriteHalf,
    from_server: bool,
    mode: watch::Receiver<NetworkMode>,
    profile: ShapingProfile,
) {
    let (tx, mut rx) = mpsc::unbounded_channel::<(tokio::time::Instant, Vec<u8>)>();
    let delivery = tokio::spawn(async move {
        while let Some((deliver_at, chunk)) = rx.recv().await {
            tokio::time::sleep_until(deliver_at).await;
            if writer.write_all(&chunk).await.is_err() {
                break;
            }
        }
    });

    let mut buffer = vec![0u8; 16_384];
    let mut chunk_index = 0u64;
    let mut next_delivery = tokio::time::Instant::now();
    loop {
        let length = match reader.read(&mut buffer).await {
            Ok(0) | Err(_) => break,
            Ok(length) => length,
        };
        chunk_index = chunk_index.saturating_add(1);
        let current_mode = *mode.borrow();
        if matches!(current_mode, NetworkMode::Blackhole) {
            continue;
        }
        let chunk = buffer[..length].to_vec();
        let delay = if matches!(current_mode, NetworkMode::ThreeG) {
            let rate = if from_server {
                profile.down_bytes_per_second
            } else {
                profile.up_bytes_per_second
            };
            let serialization = Duration::from_secs_f64(chunk.len() as f64 / rate);
            let now = tokio::time::Instant::now();
            next_delivery = next_delivery.max(now) + serialization;
            let jitter_ms = chunk_index.wrapping_mul(17) % profile.jitter_span_ms;
            next_delivery
                .saturating_duration_since(now)
                .saturating_add(Duration::from_millis(profile.base_latency_ms + jitter_ms))
        } else {
            Duration::ZERO
        };
        if tx
            .send((tokio::time::Instant::now() + delay, chunk))
            .is_err()
        {
            break;
        }
    }
    drop(tx);
    let _ = delivery.await;
}

/// Shaped TCP relay standing in for a real WAN hop under a reliable-ordered
/// tunnel. Accepts exactly one inbound connection, dials `server` once, and
/// shapes both directions independently via `shape_tcp_direction`.
pub(super) async fn run_tcp_proxy(
    listener: tokio::net::TcpListener,
    server: SocketAddr,
    mode: watch::Receiver<NetworkMode>,
    profile: ShapingProfile,
) {
    assert!(
        profile.loss_every_nth.is_none(),
        "a TCP relay cannot drop bytes without corrupting length-prefixed framing; \
         use a loss-free ShapingProfile for the TCP arm"
    );
    let Ok((inbound, _)) = listener.accept().await else {
        return;
    };
    let Ok(outbound) = tokio::net::TcpStream::connect(server).await else {
        return;
    };
    let _ = inbound.set_nodelay(true);
    let _ = outbound.set_nodelay(true);
    let (inbound_read, inbound_write) = inbound.into_split();
    let (outbound_read, outbound_write) = outbound.into_split();
    tokio::join!(
        shape_tcp_direction(outbound_read, inbound_write, true, mode.clone(), profile),
        shape_tcp_direction(inbound_read, outbound_write, false, mode, profile),
    );
}
