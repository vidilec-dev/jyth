use protocol::{Command, Event, GuestErrorCode};
use tokio::sync::mpsc;
use tokio::time::Instant;

use crate::error::GuestClientError;
use crate::transport::HostRequest;

/// Per-request timeout for the host's `Command` → guest `Event` roundtrip.
/// Covers `Client::request` (file/dir/process commands, `shutdown`) and
/// process stdio binds. Without this, a protocol-skew situation where the
/// guest accepts the connection but never writes a reply frame leaves
/// the host awaiting forever; the timeout turns that indefinite hang into a
/// typed `GuestClientError::RequestTimedOut`.
/// 5s is the bounded request-class default (cancel-timeout-policy): even
/// the slowest supported operation (a `FileRead` of a multi-MB file over the
/// guest command channel) finishes well under this.
pub const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Correlated command client over a guest command dispatcher.
///
/// Every request is queued to the shared [`Dispatcher`](crate::Dispatcher)
/// lane, correlated with its reply, and bounded by [`REQUEST_TIMEOUT`]. This
/// is the single request/reply entry point of the guest boundary.
pub struct Client {
    cmd_tx: mpsc::Sender<HostRequest>,
}

impl Client {
    /// Create a client over a dispatcher sender.
    pub fn new(cmd_tx: mpsc::Sender<HostRequest>) -> Self {
        Self { cmd_tx }
    }

    /// Borrow the underlying dispatcher sender.
    pub fn sender(&self) -> &mpsc::Sender<HostRequest> {
        &self.cmd_tx
    }

    /// Send a single command and await its framed `Event` reply, bounded by
    /// [`REQUEST_TIMEOUT`]. Transport failures become `Transport`; a reply
    /// not arriving within the timeout becomes `RequestTimedOut`.
    pub async fn request(&self, cmd: Command) -> Result<Event, GuestClientError> {
        Self::request_with_sender(self.cmd_tx.clone(), cmd).await
    }

    /// Like [`request`](Self::request) but over an explicit sender (used by
    /// the scheduler adapter and the VM shutdown path).
    pub async fn request_with_sender(
        cmd_tx: mpsc::Sender<HostRequest>,
        cmd: Command,
    ) -> Result<Event, GuestClientError> {
        Self::request_with_deadline(cmd_tx, cmd, Some(Instant::now() + REQUEST_TIMEOUT)).await
    }

    /// Send a command without a deadline. Reserved for long-running
    /// operations (`ProcessWait`) that may validly outlive
    /// [`REQUEST_TIMEOUT`]; the dispatcher places them on a separate permit
    /// lane.
    pub async fn request_without_deadline(
        cmd_tx: mpsc::Sender<HostRequest>,
        cmd: Command,
    ) -> Result<Event, GuestClientError> {
        Self::request_with_deadline(cmd_tx, cmd, None).await
    }

    /// Send a command with an explicit wall-clock deadline covering both the
    /// dispatcher queue wait and the transport roundtrip.
    pub async fn request_with_deadline(
        cmd_tx: mpsc::Sender<HostRequest>,
        cmd: Command,
        deadline: Option<Instant>,
    ) -> Result<Event, GuestClientError> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let request = HostRequest {
            cmd,
            deadline,
            reply: tx,
        };

        match deadline {
            Some(deadline) => {
                match tokio::time::timeout_at(deadline, cmd_tx.send(request)).await {
                    Ok(Ok(())) => {}
                    Ok(Err(_)) => return Err(GuestClientError::Shutdown),
                    Err(_) => return Err(GuestClientError::RequestTimedOut),
                }
                tokio::time::timeout_at(deadline, rx)
                    .await
                    .map_err(|_| GuestClientError::RequestTimedOut)?
                    .map_err(|_| GuestClientError::Shutdown)?
            }
            None => {
                if cmd_tx.send(request).await.is_err() {
                    return Err(GuestClientError::Shutdown);
                }
                rx.await.map_err(|_| GuestClientError::Shutdown)?
            }
        }
    }

    /// Like [`request`](Self::request) but turns a guest `Event::Error` into
    /// `GuestClientError::Guest` and leaves other events untouched.
    pub async fn request_expect(&self, cmd: Command) -> Result<Event, GuestClientError> {
        request_expect(&self.cmd_tx, cmd).await
    }
}

/// Expected-event validation: convert a guest `Event::Error` reply into the
/// typed guest failure and pass every other event through untouched.
pub async fn request_expect(
    cmd_tx: &mpsc::Sender<HostRequest>,
    cmd: Command,
) -> Result<Event, GuestClientError> {
    match Client::request_with_sender(cmd_tx.clone(), cmd).await? {
        Event::Error { code, msg } => Err(GuestClientError::Guest {
            code: GuestErrorCode::from_u32(code),
            message: msg,
        }),
        event => Ok(event),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::support::{ScriptedTransport, SilentTransport, start_dispatcher};
    use std::sync::Arc;

    fn started_client(transport: ScriptedTransport) -> (Client, crate::support::TestDispatcher) {
        let dispatcher = start_dispatcher(Arc::new(transport));
        (Client::new(dispatcher.tx()), dispatcher)
    }

    #[tokio::test]
    async fn request_expect_maps_guest_error_replies() {
        let (client, dispatcher) = started_client(ScriptedTransport::new(vec![Event::Error {
            code: 1,
            msg: "nope".to_string(),
        }]));

        let error = client
            .request_expect(Command::FileRead {
                path: "/tmp/x".to_string(),
            })
            .await
            .expect_err("guest error reply must fail");
        assert_eq!(
            error,
            GuestClientError::Guest {
                code: GuestErrorCode::ProcessStart,
                message: "nope".to_string(),
            }
        );

        dispatcher.shutdown().await;
    }

    #[tokio::test]
    async fn request_expect_passes_other_events_through() {
        let (client, dispatcher) = started_client(ScriptedTransport::new(vec![Event::VMReady]));

        let event = client
            .request_expect(Command::Ping)
            .await
            .expect("non-error event must pass through");
        assert_eq!(event, Event::VMReady);

        dispatcher.shutdown().await;
    }

    #[tokio::test]
    async fn request_times_out_on_silent_transport() {
        let dispatcher = start_dispatcher(Arc::new(SilentTransport));
        let client = Client::new(dispatcher.tx());

        let error = client
            .request(Command::Ping)
            .await
            .expect_err("silent transport must time out");
        assert_eq!(error, GuestClientError::RequestTimedOut);

        dispatcher.shutdown().await;
    }

    #[tokio::test]
    async fn request_on_closed_channel_reports_shutdown() {
        let (tx, _rx) = mpsc::channel::<HostRequest>(1);
        drop(_rx);
        let client = Client::new(tx);

        let error = client
            .request(Command::Ping)
            .await
            .expect_err("closed channel must report shutdown");
        assert_eq!(error, GuestClientError::Shutdown);
    }

    #[tokio::test]
    async fn request_returns_the_dispatcher_reply_unchanged() {
        let (client, dispatcher) = started_client(ScriptedTransport::new(vec![Event::Shutdowned]));

        let event = client
            .request(Command::VMShutdown)
            .await
            .expect("correlated reply must be delivered");
        assert_eq!(event, Event::Shutdowned);

        dispatcher.shutdown().await;
    }

    #[test]
    fn request_timeout_defaults_to_five_seconds() {
        assert_eq!(REQUEST_TIMEOUT, std::time::Duration::from_secs(5));
    }
}
