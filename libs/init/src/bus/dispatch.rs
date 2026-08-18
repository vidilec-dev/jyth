use crate::components::process_manager::ProcessManager;
use crate::components::tcp::TcpCommandListener;
use crate::errors::{InitError, InitResult};
use async_io::Async;
use error_stack::Report;
use futures_lite::{AsyncReadExt, AsyncWriteExt};
use protocol::Command;
use protocol::auth::{
    AUTHENTICATION_DEADLINE, AuthAcceptedV1, AuthChallengeV1, AuthResponseV1,
    COMMAND_AUTH_CONTEXT_V1, MAX_AUTH_FRAME, MAX_COMMAND_FRAME, MAX_GUEST_CONNECTIONS,
    PROTOCOL_VERSION, SessionCapability, compute_auth_mac, derive_auth_challenge,
};
use smol::{future::race, spawn};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use std::time::Duration;
use tokio_util::sync::CancellationToken;
#[cfg(feature = "tracing")]
use tracing::instrument;
use uuid::Uuid;

/// Bound on every post-authentication command/reply frame operation. A
/// connected, authenticated peer that never sends a command (or never reads
/// a reply) must not hold a `ConnectionAdmission` permit forever; after this
/// deadline the handler fails with `InitError::FrameIoTimeout` and the
/// spawned connection task ends, releasing the permit. The bound is a
/// `Timer` race (the auth-phase pattern) because init runs on smol —
/// `tokio::time::timeout` would need a tokio runtime. Unit tests compile a
/// short deadline so stall scenarios run fast; consumers see the production
/// bound.
#[cfg(not(test))]
const FRAME_IO_DEADLINE: Duration = Duration::from_secs(5);
#[cfg(test)]
const FRAME_IO_DEADLINE: Duration = Duration::from_millis(250);

pub struct Dispatcher {
    tcp: TcpCommandListener,
    cancel: CancellationToken,
    process_manager: ProcessManager,
    authentication: GuestAuthentication,
    admission: ConnectionAdmission,
}

/// Bounds the number of accepted guest command connections that can retain a
/// handler, including peers that are still in authentication. New connections
/// are rejected at admission when the bound is exhausted; they never wait for
/// an attacker-controlled connection to finish.
#[derive(Clone)]
struct ConnectionAdmission {
    permits: Arc<tokio::sync::Semaphore>,
}

impl ConnectionAdmission {
    fn new() -> Self {
        Self {
            permits: Arc::new(tokio::sync::Semaphore::new(MAX_GUEST_CONNECTIONS)),
        }
    }

    fn try_acquire(&self) -> Option<tokio::sync::OwnedSemaphorePermit> {
        self.permits.clone().try_acquire_owned().ok()
    }
}

#[derive(Clone, Debug)]
struct GuestAuthentication {
    vm_id: Uuid,
    capability: Arc<SessionCapability>,
    next_connection: Arc<AtomicU64>,
}

impl GuestAuthentication {
    fn new(vm_id: Uuid, capability: Arc<SessionCapability>) -> Self {
        Self {
            vm_id,
            capability,
            next_connection: Arc::new(AtomicU64::new(0)),
        }
    }
}

impl Dispatcher {
    pub fn new(tcp: TcpCommandListener, vm_id: Uuid, capability: Arc<SessionCapability>) -> Self {
        let cancel = CancellationToken::new();
        Self {
            tcp,
            cancel: cancel.clone(),
            process_manager: ProcessManager::new(cancel),
            authentication: GuestAuthentication::new(vm_id, capability),
            admission: ConnectionAdmission::new(),
        }
    }

    pub async fn run(self) -> InitResult<()> {
        while !self.cancel.is_cancelled() {
            let cancel = self.cancel.clone();
            let tcp = &self.tcp;
            let accepted = race(
                async move {
                    cancel.cancelled().await;
                    return Err(Report::new(InitError::BusDisconnected));
                },
                async move {
                    let (stream, peer) = tcp.accept().await?;
                    #[cfg(feature = "tracing")]
                    tracing::info!(
                        "[Bus][Dispatcher] accepted TCP command connection from {}",
                        peer
                    );
                    Ok((stream, peer))
                },
            )
            .await;

            let (stream, peer) = match accepted {
                Ok((stream, peer)) => (stream, peer),
                Err(report) => {
                    // Only the cancellation/disconnect sentinel terminates
                    // the dispatcher. Any other accept() error (EMFILE,
                    // ENFILE, EBADF, ...) is transient: exiting the loop
                    // would make `run_bus` return Ok and guest PID 1 exit.
                    if accept_error_is_disconnect(&report) {
                        return Ok(());
                    }
                    #[cfg(feature = "tracing")]
                    tracing::warn!(
                        "[Bus][Dispatcher] accept() failed, continuing: {:?}",
                        report
                    );
                    continue;
                }
            };
            let Some(connection_permit) = self.admission.try_acquire() else {
                let _ = stream.get_ref().shutdown(Shutdown::Both);
                continue;
            };
            let pm = self.process_manager.clone();
            let cancel = self.cancel.clone();
            let authentication = self.authentication.clone();
            spawn(async move {
                let _connection_permit = connection_permit;
                if let Err(e) = handle_connection(stream, pm, cancel, authentication, peer).await {
                    #[cfg(feature = "tracing")]
                    tracing::info!("[Bus][Connection] handler error: {:?}", e);
                }
            })
            .detach();
        }
        #[cfg(feature = "tracing")]
        tracing::info!("[Bus][Dispatcher] Command channel closed, shutting down dispatcher");
        Ok(())
    }
}

/// Accept-loop error policy: only the cancellation/disconnect sentinel
/// terminates the dispatcher. Transient accept errors must log and let the
/// loop continue — treating them as shutdown would let `run_bus` return Ok
/// and guest PID 1 exit.
fn accept_error_is_disconnect(report: &error_stack::Report<InitError>) -> bool {
    report.current_context() == &InitError::BusDisconnected
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::InitError;

    #[test]
    fn admission_rejects_immediately_after_the_connection_limit() {
        let admission = ConnectionAdmission::new();
        let mut permits = (0..MAX_GUEST_CONNECTIONS)
            .map(|_| admission.try_acquire().expect("permit should be available"))
            .collect::<Vec<_>>();

        assert!(admission.try_acquire().is_none());

        drop(permits.pop());
        assert!(admission.try_acquire().is_some());
    }

    #[test]
    fn transient_accept_errors_are_not_treated_as_disconnect() {
        let disconnect = Report::new(InitError::BusDisconnected);
        let transient_emfile = Report::new(std::io::Error::from_raw_os_error(libc::EMFILE))
            .change_context(InitError::Io);

        assert!(accept_error_is_disconnect(&disconnect));
        assert!(!accept_error_is_disconnect(&transient_emfile));
    }

    #[test]
    fn file_read_round_trips_through_authenticated_connection() {
        use protocol::Event;
        use std::io::{Read, Write};
        use std::net::{TcpListener, TcpStream};
        use std::time::Duration;

        fn read_client_frame(client: &mut TcpStream) -> Vec<u8> {
            let mut len_buf = [0u8; 4];
            client.read_exact(&mut len_buf).unwrap();
            let len = u32::from_le_bytes(len_buf) as usize;
            let mut payload = vec![0u8; len];
            client.read_exact(&mut payload).unwrap();
            payload
        }

        fn write_client_frame(client: &mut TcpStream, payload: &[u8]) {
            client
                .write_all(&(payload.len() as u32).to_le_bytes())
                .unwrap();
            client.write_all(payload).unwrap();
        }

        let capability = Arc::new(SessionCapability::from_bytes([0x0b; 32]));
        let vm_id = Uuid::from_bytes([0x11; 16]);
        let pm = ProcessManager::new(CancellationToken::new());
        let authentication = GuestAuthentication::new(vm_id, capability.clone());

        // A connected TCP pair: the loopback listener plays the host side.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(addr).unwrap();
        let (server, peer) = listener.accept().unwrap();
        client
            .set_read_timeout(Some(AUTHENTICATION_DEADLINE + Duration::from_secs(2)))
            .unwrap();

        let handler = smol::spawn(async move {
            handle_connection(
                Async::new(server).unwrap(),
                pm,
                CancellationToken::new(),
                authentication,
                peer,
            )
            .await
        });

        // Authenticate as the host would: challenge, HMAC response, accept.
        let challenge_payload = read_client_frame(&mut client);
        let challenge = AuthChallengeV1::try_from(challenge_payload.as_slice()).unwrap();
        assert!(challenge_payload.len() <= MAX_AUTH_FRAME);
        let response = AuthResponseV1::for_challenge(&capability, &vm_id, &challenge);
        write_client_frame(&mut client, &response.to_bytes().unwrap());
        let accepted_payload = read_client_frame(&mut client);
        assert!(AuthAcceptedV1::try_from(accepted_payload.as_slice()).is_ok());

        // FileRead: the blocking fs read runs on the unblock pool; the
        // handler must still answer the round trip.
        let tmp = std::env::temp_dir().join(format!("jyth-dispatch-read-{}", std::process::id()));
        std::fs::write(&tmp, b"hello from guest fs").unwrap();
        let command: Vec<u8> = Command::FileRead {
            path: tmp.display().to_string(),
        }
        .try_into()
        .unwrap();
        write_client_frame(&mut client, &command);
        let event_payload = read_client_frame(&mut client);
        match Event::try_from(event_payload.as_slice()).unwrap() {
            Event::FileRead { path, data } => {
                assert_eq!(path, tmp.display().to_string());
                assert_eq!(data, b"hello from guest fs");
            }
            other => panic!("expected FileRead event, got {other:?}"),
        }
        std::fs::remove_file(&tmp).unwrap();

        drop(client);
        smol::block_on(handler).unwrap();
    }

    #[test]
    fn stalled_post_auth_peer_fails_with_frame_io_timeout_and_releases_the_permit() {
        use std::io::{Read, Write};
        use std::net::{TcpListener, TcpStream};
        use std::time::{Duration, Instant};

        fn read_client_frame(client: &mut TcpStream) -> Vec<u8> {
            let mut len_buf = [0u8; 4];
            client.read_exact(&mut len_buf).unwrap();
            let len = u32::from_le_bytes(len_buf) as usize;
            let mut payload = vec![0u8; len];
            client.read_exact(&mut payload).unwrap();
            payload
        }

        fn write_client_frame(client: &mut TcpStream, payload: &[u8]) {
            client
                .write_all(&(payload.len() as u32).to_le_bytes())
                .unwrap();
            client.write_all(payload).unwrap();
        }

        let capability = Arc::new(SessionCapability::from_bytes([0x0b; 32]));
        let vm_id = Uuid::from_bytes([0x11; 16]);
        let pm = ProcessManager::new(CancellationToken::new());
        let authentication = GuestAuthentication::new(vm_id, capability.clone());

        // The dispatcher run-loop wiring: a permit acquired before the
        // handler runs must return when the handler task ends.
        let admission = ConnectionAdmission::new();
        let connection_permit = admission.try_acquire().expect("permit should be available");
        assert_eq!(
            admission.permits.available_permits(),
            MAX_GUEST_CONNECTIONS - 1
        );

        // A connected TCP pair: the loopback listener plays the host side.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(addr).unwrap();
        let (server, peer) = listener.accept().unwrap();
        client
            .set_read_timeout(Some(AUTHENTICATION_DEADLINE + Duration::from_secs(2)))
            .unwrap();

        let handler = smol::spawn(async move {
            let _connection_permit = connection_permit;
            handle_connection(
                Async::new(server).unwrap(),
                pm,
                CancellationToken::new(),
                authentication,
                peer,
            )
            .await
        });

        // Authenticate as the host would, then stall: never write the
        // command frame the handler is waiting for.
        let challenge_payload = read_client_frame(&mut client);
        let challenge = AuthChallengeV1::try_from(challenge_payload.as_slice()).unwrap();
        let response = AuthResponseV1::for_challenge(&capability, &vm_id, &challenge);
        write_client_frame(&mut client, &response.to_bytes().unwrap());
        let accepted_payload = read_client_frame(&mut client);
        assert!(AuthAcceptedV1::try_from(accepted_payload.as_slice()).is_ok());

        // The client socket is deliberately kept OPEN but SILENT: a dropped
        // client would send FIN and make the bounded read fail fast with
        // FrameTruncated. The stall scenario is a live peer that never writes
        // the command frame — that is what the bounded read must time out on
        // (the 250ms cfg(test) FRAME_IO_DEADLINE).

        // The handler must terminate within the short cfg(test) deadline
        // rather than hanging on the stalled peer.
        let started = Instant::now();
        let result = smol::block_on(handler);
        let elapsed = started.elapsed();

        let report = result.expect_err("a stalled post-auth peer must fail with FrameIoTimeout");
        assert!(matches!(
            report.current_context(),
            InitError::FrameIoTimeout
        ));

        // Complete Report: operation, budget, and peer address attachments.
        assert!(
            report.frames().any(|f| f
                .downcast_ref::<String>()
                .is_some_and(|s| s.contains("operation="))),
            "the report must carry the operation attachment: {report:?}"
        );
        assert!(
            report.frames().any(|f| f
                .downcast_ref::<String>()
                .is_some_and(|s| s.contains("budget="))),
            "the report must carry the budget attachment: {report:?}"
        );
        assert!(
            report.frames().any(|f| f
                .downcast_ref::<String>()
                .is_some_and(|s| s.contains("peer="))),
            "the report must carry the peer attachment: {report:?}"
        );

        // Termination is bounded, and the admission permit returned to the
        // pool once the handler task ended.
        assert!(
            elapsed < Duration::from_secs(2),
            "handler must terminate within a bounded time, took {elapsed:?}"
        );
        assert_eq!(admission.permits.available_permits(), MAX_GUEST_CONNECTIONS);
    }
}

/// Complete `InitError::FrameIoTimeout` report: the operation name, the
/// frame-I/O budget, and the peer address, matching the complete-Report
/// contract (operation + budget + endpoint) for facade-facing timeouts.
fn frame_io_timeout(operation: &'static str, peer: SocketAddr) -> Report<InitError> {
    Report::new(InitError::FrameIoTimeout)
        .attach(format!("operation={operation}"))
        .attach(format!("budget={FRAME_IO_DEADLINE:?}"))
        .attach(format!("peer={peer}"))
}

async fn read_frame(stream: &mut Async<TcpStream>, maximum: usize) -> InitResult<Vec<u8>> {
    validate_frame_limit(maximum)?;
    let mut len_buf = [0u8; 4];
    match stream.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            return Err(Report::new(InitError::FrameTruncated));
        }
        Err(e) => return Err(Report::new(e).change_context(InitError::Io)),
    }
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > maximum {
        return Err(Report::new(InitError::FrameTooLarge).attach(format!(
            "declared frame length {len} exceeds maximum {maximum}"
        )));
    }
    let mut payload = Vec::new();
    payload.try_reserve_exact(len).map_err(|_| {
        Report::new(InitError::FrameAllocation).attach(format!("could not reserve {len} bytes"))
    })?;
    payload.resize(len, 0);
    stream.read_exact(&mut payload).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            Report::new(InitError::FrameTruncated)
        } else {
            Report::new(e).change_context(InitError::Io)
        }
    })?;
    Ok(payload)
}

/// Post-authentication frame read bounded by [`FRAME_IO_DEADLINE`]. The
/// auth-phase deadline race (a `Timer` on smol) is reused so a stalled host
/// cannot hold a connection admission permit indefinitely.
async fn read_frame_bounded(
    stream: &mut Async<TcpStream>,
    maximum: usize,
    peer: SocketAddr,
) -> InitResult<Vec<u8>> {
    race(read_frame(stream, maximum), async move {
        async_io::Timer::after(FRAME_IO_DEADLINE).await;
        Err(frame_io_timeout("read_frame", peer))
    })
    .await
}

async fn write_payload(
    stream: &mut Async<TcpStream>,
    payload: &[u8],
    maximum: usize,
) -> InitResult<()> {
    validate_frame_limit(maximum)?;
    let len = u32::try_from(payload.len()).map_err(|_| {
        Report::new(InitError::FrameTooLarge).attach("frame length does not fit u32")
    })?;
    if payload.len() > maximum {
        return Err(Report::new(InitError::FrameTooLarge).attach(format!(
            "frame length {} exceeds maximum {maximum}",
            payload.len()
        )));
    }
    stream
        .write_all(&len.to_le_bytes())
        .await
        .map_err(|e| Report::new(e).change_context(InitError::Io))?;
    stream
        .write_all(&payload)
        .await
        .map_err(|e| Report::new(e).change_context(InitError::Io))?;
    Ok(())
}

fn validate_frame_limit(maximum: usize) -> InitResult<()> {
    if maximum > MAX_COMMAND_FRAME {
        return Err(Report::new(InitError::FrameTooLarge).attach(format!(
            "requested frame limit {maximum} exceeds library maximum {MAX_COMMAND_FRAME}"
        )));
    }
    Ok(())
}

/// Serialize one `Event` and write it bounded by [`FRAME_IO_DEADLINE`]. Every
/// post-authentication reply is a bounded frame operation: a peer that stops
/// reading must not stall the handler (and its admission permit) forever.
async fn write_frame(
    stream: &mut Async<TcpStream>,
    peer: SocketAddr,
    event: protocol::Event,
) -> InitResult<()> {
    let payload: Vec<u8> =
        event
            .try_into()
            .map_err(|e: error_stack::Report<protocol::ProtocolError>| {
                e.change_context(InitError::Serialize)
                    .attach("transport error")
            })?;
    race(
        write_payload(stream, &payload, MAX_COMMAND_FRAME),
        async move {
            async_io::Timer::after(FRAME_IO_DEADLINE).await;
            Err(frame_io_timeout("write_payload", peer))
        },
    )
    .await
}

async fn authenticate_connection(
    stream: &mut Async<TcpStream>,
    authentication: &GuestAuthentication,
) -> InitResult<()> {
    let counter = authentication
        .next_connection
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            current.checked_add(1)
        })
        .map_err(|_| Report::new(InitError::Authentication))?;
    let challenge = AuthChallengeV1 {
        version: PROTOCOL_VERSION,
        challenge: derive_auth_challenge(
            &authentication.capability,
            &authentication.vm_id,
            counter,
        ),
    };
    let challenge_payload: Vec<u8> = challenge
        .try_into()
        .map_err(|_| Report::new(InitError::Authentication))?;
    write_payload(stream, &challenge_payload, MAX_AUTH_FRAME).await?;

    let response_payload = read_frame(stream, MAX_AUTH_FRAME).await?;
    let response = AuthResponseV1::try_from(response_payload.as_slice())
        .map_err(|_| Report::new(InitError::Authentication))?;
    let expected = compute_auth_mac(
        &authentication.capability,
        &authentication.vm_id,
        COMMAND_AUTH_CONTEXT_V1,
        &challenge.challenge,
    );
    if !protocol::auth::constant_time_eq(&expected, &response.mac) {
        return Err(Report::new(InitError::Authentication));
    }

    let accepted = AuthAcceptedV1 {
        version: PROTOCOL_VERSION,
    };
    let accepted_payload: Vec<u8> = accepted
        .try_into()
        .map_err(|_| Report::new(InitError::Authentication))?;
    write_payload(stream, &accepted_payload, MAX_AUTH_FRAME).await
}

/// Handles a single accepted TCP connection. One connection = one command
/// frame; the connection is closed (or handed off to `ProcessManager::bind`
/// as a raw stdio pipe) after the reply. Post-authentication frame I/O is
/// bounded by [`FRAME_IO_DEADLINE`] so a stalled host cannot retain a
/// `ConnectionAdmission` permit; the caller releases the permit when the
/// handler task ends.
#[cfg_attr(
    feature = "tracing",
    instrument(skip(stream, pm, cancel, authentication), level = "debug")
)]
async fn handle_connection(
    mut stream: Async<TcpStream>,
    pm: ProcessManager,
    cancel: CancellationToken,
    authentication: GuestAuthentication,
    peer: SocketAddr,
) -> InitResult<()> {
    let authentication_result = race(
        authenticate_connection(&mut stream, &authentication),
        async {
            async_io::Timer::after(AUTHENTICATION_DEADLINE).await;
            Err(Report::new(InitError::Authentication))
        },
    )
    .await;
    authentication_result?;

    // Authentication completes before this length is read. An unauthenticated
    // peer therefore cannot make the command decoder or its length-driven
    // allocation observe attacker-controlled command bytes.
    let payload = read_frame_bounded(&mut stream, MAX_COMMAND_FRAME, peer).await?;
    let cmd = match protocol::Command::try_from(payload.as_slice()) {
        Ok(c) => c,
        Err(e) => {
            return Err(e
                .change_context(InitError::Deserialize)
                .attach("command frame"));
        }
    };
    match cmd {
        Command::ProcessStart {
            uuid,
            path,
            args,
            envs,
            cwd,
            stdout,
            stderr,
        } => {
            match pm.spawn(uuid, path, args, envs, cwd, stdout, stderr).await {
                Ok(()) => {
                    let _ =
                        write_frame(&mut stream, peer, protocol::Event::ProcessStarted { uuid })
                            .await;
                }
                Err(e) => {
                    let msg = format!("{:?}", e);
                    let _ = write_frame(&mut stream, peer, protocol::Event::Error { code: 1, msg })
                        .await;
                }
            }
            let _ = stream.get_ref().shutdown(Shutdown::Both);
        }
        Command::ProcessStop { uuid } => {
            match pm.kill(uuid).await {
                Ok(exit) => {
                    let _ = write_frame(
                        &mut stream,
                        peer,
                        protocol::Event::ProcessExited {
                            uuid,
                            exit_code: exit.exit_code,
                            signal: exit.signal,
                        },
                    )
                    .await;
                }
                Err(e) => {
                    let msg = format!("{:?}", e);
                    let _ = write_frame(&mut stream, peer, protocol::Event::Error { code: 2, msg })
                        .await;
                }
            }
            let _ = stream.get_ref().shutdown(Shutdown::Both);
        }
        Command::ProcessWait { uuid } => {
            match pm.wait(uuid).await {
                Ok(exit) => {
                    let _ = write_frame(
                        &mut stream,
                        peer,
                        protocol::Event::ProcessExited {
                            uuid,
                            exit_code: exit.exit_code,
                            signal: exit.signal,
                        },
                    )
                    .await;
                }
                Err(e) => {
                    let _ = write_frame(
                        &mut stream,
                        peer,
                        protocol::Event::Error {
                            code: 9,
                            msg: format!("{:?}", e),
                        },
                    )
                    .await;
                }
            }
            let _ = stream.get_ref().shutdown(Shutdown::Both);
        }
        Command::ProcessClose { uuid } => {
            match pm.close(uuid) {
                Ok(()) => {
                    let _ = write_frame(&mut stream, peer, protocol::Event::ProcessClosed { uuid })
                        .await;
                }
                Err(e) => {
                    let _ = write_frame(
                        &mut stream,
                        peer,
                        protocol::Event::Error {
                            code: 10,
                            msg: format!("{:?}", e),
                        },
                    )
                    .await;
                }
            }
            let _ = stream.get_ref().shutdown(Shutdown::Both);
        }
        Command::ProcessBind { uuid, stay_framed } => {
            // Ack before switching modes: the host reads the reply frame and
            // then switches its side to raw or framed byte mode. Any further
            // bytes from here go directly onto the child's stdio pipe.
            if let Err(e) =
                write_frame(&mut stream, peer, protocol::Event::ProcessBound { uuid }).await
            {
                #[cfg(feature = "tracing")]
                tracing::info!("[Bus][ProcessBind] ack write failed for {}: {:?}", uuid, e);
                let _ = stream.get_ref().shutdown(Shutdown::Both);
                return Err(Report::new(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "write error",
                ))
                .change_context(InitError::Io));
            }
            if let Err(e) = pm.bind(uuid, stream, stay_framed).await {
                #[cfg(feature = "tracing")]
                tracing::info!("[Bus][ProcessBind] bind {} failed: {:?}", uuid, e);
                return Err(e);
            }
            // `bind` returned -> the host closed the bound stream (or the
            // process exited). The ProcessManager's reaper already cleaned
            // up the entry; the Async<TcpStream>'s Drop will call
            // Shutdown::Both on the underlying fd. Nothing to do here.
        }
        Command::ProcessOutputBind {
            uuid,
            stream: output,
        } => {
            if let Err(e) =
                write_frame(&mut stream, peer, protocol::Event::ProcessBound { uuid }).await
            {
                #[cfg(feature = "tracing")]
                tracing::info!(
                    "[Bus][ProcessOutputBind] ack write failed for {}: {:?}",
                    uuid,
                    e
                );
                let _ = stream.get_ref().shutdown(Shutdown::Both);
                return Err(Report::new(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "write error",
                ))
                .change_context(InitError::Io));
            }
            if let Err(e) = pm.bind_output(uuid, output, stream).await {
                #[cfg(feature = "tracing")]
                tracing::info!("[Bus][ProcessOutputBind] bind {} failed: {:?}", uuid, e);
                return Err(e);
            }
        }
        Command::VMShutdown => {
            let _ = write_frame(&mut stream, peer, protocol::Event::Shutdowned).await;
            let _ = stream.get_ref().shutdown(Shutdown::Both);
            cancel.cancel();
        }
        Command::Ping => {
            // Minimal liveness probe: reply with `VMReady` and close. Used
            // by future host-side health checks; not part of the current
            // request/reply flow but listed explicitly so the only catch-all
            // below truly only fires on unknown future variants.
            let _ = write_frame(&mut stream, peer, protocol::Event::VMReady).await;
            let _ = stream.get_ref().shutdown(Shutdown::Both);
        }
        Command::FileRead { path, .. } => {
            // The read happens on the blocking pool: a multi-MiB file body
            // must not stall the smol executor thread that also reaps
            // processes and serves every other connection.
            let reply_path = path.clone();
            let result = smol::unblock(move || std::fs::read(&path)).await;
            match result {
                Ok(data) => {
                    let _ = write_frame(
                        &mut stream,
                        peer,
                        protocol::Event::FileRead {
                            path: reply_path,
                            data,
                        },
                    )
                    .await;
                }
                Err(e) => {
                    let msg = format!("{:?}", e);
                    let _ = write_frame(&mut stream, peer, protocol::Event::Error { code: 3, msg })
                        .await;
                }
            }
            let _ = stream.get_ref().shutdown(Shutdown::Both);
        }
        Command::FileWrite { path, data, .. } => {
            let reply_path = path.clone();
            let result = smol::unblock(move || std::fs::write(&path, &data)).await;
            match result {
                Ok(()) => {
                    let _ = write_frame(
                        &mut stream,
                        peer,
                        protocol::Event::FileWritten { path: reply_path },
                    )
                    .await;
                }
                Err(e) => {
                    let msg = format!("{:?}", e);
                    let _ = write_frame(&mut stream, peer, protocol::Event::Error { code: 4, msg })
                        .await;
                }
            }
            let _ = stream.get_ref().shutdown(Shutdown::Both);
        }
        Command::FileRemove { path, .. } => {
            let reply_path = path.clone();
            let result = smol::unblock(move || std::fs::remove_file(&path)).await;
            match result {
                Ok(()) => {
                    let _ = write_frame(
                        &mut stream,
                        peer,
                        protocol::Event::FileRemoved { path: reply_path },
                    )
                    .await;
                }
                Err(e) => {
                    let msg = format!("{:?}", e);
                    let _ = write_frame(&mut stream, peer, protocol::Event::Error { code: 5, msg })
                        .await;
                }
            }
            let _ = stream.get_ref().shutdown(Shutdown::Both);
        }
        Command::DirRead { path, .. } => {
            let reply_path = path.clone();
            let result = smol::unblock(move || -> std::io::Result<Vec<String>> {
                let rd = std::fs::read_dir(&path)?;
                let mut entries = Vec::new();
                for entry in rd {
                    let Ok(entry) = entry else { continue };
                    entries.push(entry.file_name().to_string_lossy().to_string());
                }
                Ok(entries)
            })
            .await;
            match result {
                Ok(entries) => {
                    let _ = write_frame(
                        &mut stream,
                        peer,
                        protocol::Event::DirRead {
                            path: reply_path,
                            entries,
                        },
                    )
                    .await;
                }
                Err(e) => {
                    let msg = format!("{:?}", e);
                    let _ = write_frame(&mut stream, peer, protocol::Event::Error { code: 6, msg })
                        .await;
                }
            }
            let _ = stream.get_ref().shutdown(Shutdown::Both);
        }
        Command::DirCreate { path, .. } => {
            let reply_path = path.clone();
            let result = smol::unblock(move || std::fs::create_dir_all(&path)).await;
            match result {
                Ok(()) => {
                    let _ = write_frame(
                        &mut stream,
                        peer,
                        protocol::Event::DirCreated { path: reply_path },
                    )
                    .await;
                }
                Err(e) => {
                    let msg = format!("{:?}", e);
                    let _ = write_frame(&mut stream, peer, protocol::Event::Error { code: 7, msg })
                        .await;
                }
            }
            let _ = stream.get_ref().shutdown(Shutdown::Both);
        }
        Command::DirRemove { path, .. } => {
            let reply_path = path.clone();
            let result = smol::unblock(move || std::fs::remove_dir_all(&path)).await;
            match result {
                Ok(()) => {
                    let _ = write_frame(
                        &mut stream,
                        peer,
                        protocol::Event::DirRemoved { path: reply_path },
                    )
                    .await;
                }
                Err(e) => {
                    let msg = format!("{:?}", e);
                    let _ = write_frame(&mut stream, peer, protocol::Event::Error { code: 8, msg })
                        .await;
                }
            }
            let _ = stream.get_ref().shutdown(Shutdown::Both);
        }
        Command::PortBind { port } => {
            // Forwarding is not yet wired; the TCP relay from the host
            // side still operates by opening a second connection to the
            // guest's port 9000. Ack politely and move on. (See
            // libs/jyth/src/lib.rs ForwardTcpToTcp for the current path.)
            #[cfg(feature = "tracing")]
            tracing::info!("[Bus] PortBind for {} not implemented", port);
            let _ = stream.get_ref().shutdown(Shutdown::Both);
        }
        // Catch-all for forward-compatibility: reply with a typed guest
        // error and close the connection instead of leaving the host
        // waiting on a `read_frame` that will never arrive. The `code: 0`
        // sentinel signals "unhandled command" so the host can distinguish
        // an unsupported variant from a failed operation (codes 1-8).
        #[allow(unreachable_patterns)]
        unhandled => {
            let msg = format!("unhandled command variant: {:?}", unhandled);
            #[cfg(feature = "tracing")]
            tracing::info!("[Bus] {msg}");
            let _ = write_frame(&mut stream, peer, protocol::Event::Error { code: 0, msg }).await;
            let _ = stream.get_ref().shutdown(Shutdown::Both);
        }
    }
    Ok(())
}
