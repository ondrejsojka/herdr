//! Unix remote-host side of the SSH stdio bridge and the QUIC bootstrap helper.

use std::io;
use std::os::unix::net::UnixStream;
use std::thread;
use std::time::Duration;

pub(crate) fn run_remote_client_bridge() -> io::Result<()> {
    ensure_remote_server_running()?;

    let socket_path = crate::server::socket_paths::client_socket_path();
    let stream = UnixStream::connect(&socket_path).map_err(|err| {
        io::Error::new(
            err.kind(),
            format!(
                "failed to connect to remote Herdr client socket {}: {err}",
                socket_path.display()
            ),
        )
    })?;

    let mut stdout = io::stdout().lock();
    let mut socket_to_stdout = stream.try_clone()?;
    let mut stdin_to_socket = stream;

    let _upload = thread::spawn(move || {
        let mut stdin = io::stdin();
        let _ = copy_flush(&mut stdin, &mut stdin_to_socket);
        let _ = stdin_to_socket.shutdown(std::net::Shutdown::Write);
    });

    copy_flush(&mut socket_to_stdout, &mut stdout).map(|_| ())
}

/// `herdr remote-quic-bootstrap <client-id>`: ask the local server for a QUIC
/// credential on behalf of the SSH-authenticated caller and print it as JSON.
/// The caller's SSH session is the authentication; this helper only relays.
pub(crate) fn run_remote_quic_bootstrap(logical_client_id: Option<&str>) -> io::Result<()> {
    let logical_client_id = logical_client_id
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing logical client id"))
        .and_then(parse_logical_client_id)?;
    ensure_remote_server_running()?;

    let socket_path = crate::server::socket_paths::client_socket_path();
    let mut stream = UnixStream::connect(&socket_path).map_err(|err| {
        io::Error::new(
            err.kind(),
            format!(
                "failed to connect to remote Herdr client socket {}: {err}",
                socket_path.display()
            ),
        )
    })?;
    let session = crate::session::active_name()
        .unwrap_or_else(|| crate::session::DEFAULT_SESSION_NAME.to_owned());
    crate::protocol::write_message(
        &mut stream,
        &crate::protocol::ClientMessage::RemoteBootstrap(crate::protocol::RemoteBootstrapRequest {
            session,
            logical_client_id,
        }),
    )
    .map_err(|err| io::Error::other(err.to_string()))?;
    let response: crate::protocol::ServerMessage =
        crate::protocol::read_message(&mut stream, crate::protocol::MAX_FRAME_SIZE)
            .map_err(|err| io::Error::other(err.to_string()))?;
    let record = match response {
        crate::protocol::ServerMessage::RemoteBootstrap {
            record: Some(record),
            error: None,
        } => record,
        crate::protocol::ServerMessage::RemoteBootstrap {
            error: Some(error), ..
        } => return Err(io::Error::other(error)),
        _ => return Err(io::Error::other("invalid remote QUIC bootstrap response")),
    };
    serde_json::to_writer(io::stdout().lock(), &record)
        .map_err(|err| io::Error::other(format!("failed to encode QUIC bootstrap: {err}")))?;
    println!();
    Ok(())
}

fn parse_logical_client_id(value: &str) -> io::Result<[u8; crate::protocol::REMOTE_QUIC_ID_BYTES]> {
    if value.len() != crate::protocol::REMOTE_QUIC_ID_BYTES * 2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "logical client id must contain 32 hexadecimal characters",
        ));
    }
    let mut bytes = [0u8; crate::protocol::REMOTE_QUIC_ID_BYTES];
    for (index, output) in bytes.iter_mut().enumerate() {
        let offset = index * 2;
        *output = u8::from_str_radix(&value[offset..offset + 2], 16).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "logical client id contains non-hexadecimal characters",
            )
        })?;
    }
    Ok(bytes)
}

fn copy_flush<R: io::Read, W: io::Write>(reader: &mut R, writer: &mut W) -> io::Result<u64> {
    let mut buffer = [0_u8; 16 * 1024];
    let mut total = 0;
    loop {
        let read = match reader.read(&mut buffer) {
            Ok(0) => return Ok(total),
            Ok(read) => read,
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err),
        };
        writer.write_all(&buffer[..read])?;
        writer.flush()?;
        total += read as u64;
    }
}

fn ensure_remote_server_running() -> io::Result<()> {
    let socket_path = crate::server::socket_paths::client_socket_path();
    if crate::server::autodetect::is_server_listening() {
        let status = crate::api::read_runtime_status_at(
            &crate::api::socket_path(),
            Duration::from_millis(500),
        )?
        .ok_or_else(|| io::Error::other("remote server status API is unavailable"))?;
        if status
            .capabilities
            .as_ref()
            .and_then(|capabilities| capabilities.endpoint_protocol_generation)
            == Some(crate::protocol::endpoint::ENDPOINT_PROTOCOL_GENERATION)
        {
            return Ok(());
        }
        return Err(io::Error::other(
            "remote herdr server needs one final update before this bridge can attach; rerun `herdr --remote` from an interactive terminal to approve it",
        ));
    }

    crate::server::autodetect::spawn_server_daemon()?;
    crate::server::autodetect::wait_for_server_socket(&socket_path, Duration::from_secs(5))
}

#[cfg(test)]
mod tests {
    use super::parse_logical_client_id;

    #[test]
    fn logical_client_id_parses_exactly_32_hex_digits() {
        assert_eq!(
            parse_logical_client_id("00ff00ff00ff00ff00ff00ff00ff00ff").unwrap(),
            [
                0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff,
                0x00, 0xff
            ]
        );
        assert!(parse_logical_client_id("00ff").is_err());
        assert!(parse_logical_client_id("zz").is_err());
        assert!(parse_logical_client_id("0g000000000000000000000000000000").is_err());
    }
}
