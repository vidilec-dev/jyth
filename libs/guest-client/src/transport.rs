use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use protocol::{Command, Event};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, TryAcquireError, mpsc, oneshot};
use tokio::task::JoinSet;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use crate::error::GuestClientError;

/// Maximum number of host requests executing concurrently on the guest
/// command bus. Requests beyond this bound wait in the dispatcher queue.
pub const MAX_IN_FLIGHT_HOST_REQUESTS: usize = 32;

/// Maximum number of long-running `ProcessWait` requests executing
/// concurrently. Process waits use a separate permit lane so they cannot
/// starve normal command traffic.
pub const MAX_IN_FLIGHT_PROCESS_WAITS: usize = 32;

/// A pin-boxed Send future for one guest command roundtrip.
pub type TransportFuture =
    Pin<Box<dyn Future<Output = Result<Event, GuestClientError>> + Send + 'static>>;

/// Consumer-owned port for executing one typed guest command and receiving
/// its correlated reply event.
///
/// The port is object-safe and does not require `Clone`: the dispatcher
/// stores implementations behind [`Arc`] and shares them by Arc clone.
/// Implementations must not expose socket construction or authentication
/// policy.
pub trait CommandTransport: Send + Sync + 'static {
    /// Execute one command and return the guest's reply event.
    fn command_async(&self, cmd: Command) -> TransportFuture;
}

/// A pin-boxed Send future for one process stdio bind.
pub type StreamFuture = Pin<
    Box<dyn Future<Output = Result<Box<dyn ProcessStream>, GuestClientError>> + Send + 'static>,
>;

/// Consumer-owned port for binding a guest process's stdio into a host-owned
/// byte stream. Kept separate from [`CommandTransport`] so the command port
/// exposes exactly one request operation and never a concrete socket type.
pub trait StreamTransport: Send + Sync + 'static {
    /// Bind the stream described by `cmd` (a `ProcessBind` or
    /// `ProcessOutputBind` command) and return the host-owned stream.
    fn bind_async(&self, cmd: Command) -> StreamFuture;
}

/// A host-owned byte stream over a bound guest process stdio endpoint.
pub trait ProcessStream: Send + 'static {
    /// Read up to an implementation-defined chunk of raw bytes. An empty
    /// `Vec` means the guest closed the stream.
    fn read(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, GuestClientError>> + Send + '_>>;

    /// Write raw bytes to the stream.
    fn write(
        &mut self,
        data: &[u8],
    ) -> Pin<Box<dyn Future<Output = Result<(), GuestClientError>> + Send + '_>>;
}

/// A queued host request awaiting its binary reply. Each entry represents one
/// command that travels on its own fresh authenticated TCP connection.
pub struct HostRequest {
    pub(crate) cmd: Command,
    pub(crate) deadline: Option<Instant>,
    pub(crate) reply: oneshot::Sender<Result<Event, GuestClientError>>,
}

fn request_cancelled() -> GuestClientError {
    GuestClientError::Shutdown
}

/// Schedules queued host requests against a shared transport.
///
/// Semaphore-bounded concurrency is preserved exactly: normal requests share
/// one lane of [`MAX_IN_FLIGHT_HOST_REQUESTS`] permits, `ProcessWait` uses a
/// separate lane, `VMShutdown` may start without a normal permit, and every
/// request has its own deadline that expires even while queued.
pub struct Dispatcher {
    receiver: mpsc::Receiver<HostRequest>,
    transport: Arc<dyn CommandTransport>,
    cancel: CancellationToken,
    permits: Arc<Semaphore>,
    process_wait_permits: Arc<Semaphore>,
    pending: VecDeque<HostRequest>,
    tasks: JoinSet<()>,
}

impl Dispatcher {
    /// Create a dispatcher with the default permit lanes.
    pub fn new(
        receiver: mpsc::Receiver<HostRequest>,
        transport: Arc<dyn CommandTransport>,
        cancel: CancellationToken,
    ) -> Self {
        Self::with_semaphore(
            receiver,
            transport,
            cancel,
            Arc::new(Semaphore::new(MAX_IN_FLIGHT_HOST_REQUESTS)),
        )
    }

    /// Create a dispatcher with a caller-selected normal request lane.
    pub fn with_semaphore(
        receiver: mpsc::Receiver<HostRequest>,
        transport: Arc<dyn CommandTransport>,
        cancel: CancellationToken,
        permits: Arc<Semaphore>,
    ) -> Self {
        Self::with_semaphores(
            receiver,
            transport,
            cancel,
            permits,
            Arc::new(Semaphore::new(MAX_IN_FLIGHT_PROCESS_WAITS)),
        )
    }

    /// Create a dispatcher with fully caller-selected permit lanes.
    pub fn with_semaphores(
        receiver: mpsc::Receiver<HostRequest>,
        transport: Arc<dyn CommandTransport>,
        cancel: CancellationToken,
        permits: Arc<Semaphore>,
        process_wait_permits: Arc<Semaphore>,
    ) -> Self {
        Self {
            receiver,
            transport,
            cancel,
            permits,
            process_wait_permits,
            pending: VecDeque::new(),
            tasks: JoinSet::new(),
        }
    }

    /// Run the dispatch loop until the cancel token fires, the request
    /// channel closes, or every pending request expires.
    pub async fn run(mut self) {
        loop {
            self.start_ready();

            match self.next_deadline() {
                Some(deadline) => {
                    tokio::select! {
                        biased;
                        _ = self.cancel.cancelled() => break,
                        request = self.receiver.recv() => {
                            if let Some(request) = request {
                                self.pending.push_back(request);
                            } else {
                                break;
                            }
                        }
                        _joined = self.tasks.join_next(), if !self.tasks.is_empty() => {
                            #[cfg(feature = "tracing")]
                            self.observe_join(_joined);
                        }
                        _ = tokio::time::sleep_until(deadline) => {
                            self.expire_pending();
                        }
                    }
                }
                None => {
                    tokio::select! {
                        biased;
                        _ = self.cancel.cancelled() => break,
                        request = self.receiver.recv() => {
                            if let Some(request) = request {
                                self.pending.push_back(request);
                            } else {
                                break;
                            }
                        }
                        _joined = self.tasks.join_next(), if !self.tasks.is_empty() => {
                            #[cfg(feature = "tracing")]
                            self.observe_join(_joined);
                        }
                    }
                }
            }
        }

        self.stop().await;
    }

    #[cfg(feature = "tracing")]
    fn observe_join(&mut self, joined: Option<Result<(), tokio::task::JoinError>>) {
        if let Some(Err(_error)) = joined {
            tracing::error!(error = %_error, "command request task failed to join");
        }
    }

    fn start_ready(&mut self) {
        self.expire_pending();

        loop {
            let Some(index) = self.next_start_index() else {
                return;
            };
            let request = self
                .pending
                .remove(index)
                .expect("pending request index must remain valid");
            let is_process_wait = matches!(request.cmd, Command::ProcessWait { .. });
            let permit_result = if is_process_wait {
                self.process_wait_permits.clone().try_acquire_owned()
            } else {
                self.permits.clone().try_acquire_owned()
            };
            let permit = match permit_result {
                Ok(permit) => Some(permit),
                Err(TryAcquireError::NoPermits)
                    if matches!(request.cmd, Command::VMShutdown) && !is_process_wait =>
                {
                    None
                }
                Err(TryAcquireError::NoPermits) => {
                    self.pending.push_front(request);
                    return;
                }
                Err(TryAcquireError::Closed) => {
                    let HostRequest { reply, .. } = request;
                    let _ = reply.send(Err(request_cancelled()));
                    continue;
                }
            };

            let transport = self.transport.clone();
            self.tasks.spawn(async move {
                execute_request(transport, request, permit).await;
            });
        }
    }

    fn next_start_index(&self) -> Option<usize> {
        if self.pending.is_empty() {
            return None;
        }

        self.pending.iter().position(|request| {
            let is_process_wait = matches!(request.cmd, Command::ProcessWait { .. });
            if is_process_wait {
                self.process_wait_permits.available_permits() > 0
            } else {
                self.permits.available_permits() > 0 || matches!(request.cmd, Command::VMShutdown)
            }
        })
    }

    fn next_deadline(&self) -> Option<Instant> {
        self.pending
            .iter()
            .filter_map(|request| request.deadline)
            .min()
    }

    fn expire_pending(&mut self) {
        let now = Instant::now();
        let mut retained = VecDeque::with_capacity(self.pending.len());
        while let Some(request) = self.pending.pop_front() {
            if request.deadline.is_some_and(|deadline| deadline <= now) {
                let HostRequest { reply, .. } = request;
                let _ = reply.send(Err(GuestClientError::RequestTimedOut));
            } else {
                retained.push_back(request);
            }
        }
        self.pending = retained;
    }

    async fn stop(&mut self) {
        while let Some(request) = self.pending.pop_front() {
            let HostRequest { reply, .. } = request;
            let _ = reply.send(Err(request_cancelled()));
        }

        // JoinSet::shutdown aborts every request task and waits until each
        // task has dropped its transport and semaphore permit.
        self.tasks.shutdown().await;
    }
}

async fn execute_request(
    transport: Arc<dyn CommandTransport>,
    request: HostRequest,
    permit: Option<OwnedSemaphorePermit>,
) {
    let HostRequest {
        cmd,
        deadline,
        reply,
    } = request;
    let result = match deadline {
        Some(deadline) => {
            match tokio::time::timeout_at(deadline, transport.command_async(cmd)).await {
                Ok(result) => result,
                Err(_) => Err(GuestClientError::RequestTimedOut),
            }
        }
        None => transport.command_async(cmd).await,
    };
    let _ = reply.send(result);
    drop(permit);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    #[derive(Clone, Copy)]
    enum Behavior {
        Never,
        NeverExceptHealthy,
    }

    struct FakeTransport {
        behavior: Behavior,
        calls: Arc<AtomicUsize>,
        active: Arc<AtomicUsize>,
    }

    impl FakeTransport {
        fn new(behavior: Behavior) -> Self {
            Self {
                behavior,
                calls: Arc::new(AtomicUsize::new(0)),
                active: Arc::new(AtomicUsize::new(0)),
            }
        }
    }

    struct ActiveGuard(Arc<AtomicUsize>);

    impl Drop for ActiveGuard {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }

    impl CommandTransport for FakeTransport {
        fn command_async(&self, cmd: Command) -> TransportFuture {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.active.fetch_add(1, Ordering::SeqCst);
            let active = self.active.clone();
            let behavior = self.behavior;
            Box::pin(async move {
                let _guard = ActiveGuard(active);
                let responds = match behavior {
                    Behavior::Never => false,
                    Behavior::NeverExceptHealthy => {
                        matches!(cmd, Command::FileRead { ref path } if path == "healthy")
                    }
                };
                if responds {
                    Ok(Event::VMReady)
                } else {
                    std::future::pending::<Result<Event, GuestClientError>>().await
                }
            })
        }
    }

    async fn send_request(
        sender: &mpsc::Sender<HostRequest>,
        cmd: Command,
        deadline: Option<Instant>,
    ) -> Result<Result<Event, GuestClientError>, oneshot::error::RecvError> {
        let (reply, receiver) = oneshot::channel();
        sender
            .send(HostRequest {
                cmd,
                deadline,
                reply,
            })
            .await
            .expect("dispatcher should still accept test requests");
        receiver.await
    }

    async fn wait_for_count(counter: &AtomicUsize, expected: usize) {
        for _ in 0..100 {
            if counter.load(Ordering::SeqCst) == expected {
                return;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        assert_eq!(counter.load(Ordering::SeqCst), expected);
    }

    fn assert_timed_out(
        response: Result<Result<Event, GuestClientError>, oneshot::error::RecvError>,
    ) {
        let error = response
            .expect("timed-out request should receive a typed response")
            .expect_err("timed-out request must fail");
        assert_eq!(error, GuestClientError::RequestTimedOut);
    }

    fn start_dispatcher(
        transport: FakeTransport,
        permits: Arc<Semaphore>,
    ) -> (
        mpsc::Sender<HostRequest>,
        CancellationToken,
        tokio::task::JoinHandle<()>,
    ) {
        start_dispatcher_with_semaphores(
            transport,
            permits,
            Arc::new(Semaphore::new(MAX_IN_FLIGHT_PROCESS_WAITS)),
        )
    }

    fn start_dispatcher_with_semaphores(
        transport: FakeTransport,
        permits: Arc<Semaphore>,
        process_wait_permits: Arc<Semaphore>,
    ) -> (
        mpsc::Sender<HostRequest>,
        CancellationToken,
        tokio::task::JoinHandle<()>,
    ) {
        let (sender, receiver) = mpsc::channel(128);
        let cancel = CancellationToken::new();
        let dispatcher = Dispatcher::with_semaphores(
            receiver,
            Arc::new(transport),
            cancel.clone(),
            permits,
            process_wait_permits,
        );
        let task = tokio::spawn(dispatcher.run());
        (sender, cancel, task)
    }

    #[tokio::test]
    async fn silent_transport_returns_request_timed_out() {
        let transport = FakeTransport::new(Behavior::Never);
        let active = transport.active.clone();
        let permits = Arc::new(Semaphore::new(MAX_IN_FLIGHT_HOST_REQUESTS));
        let (sender, cancel, task) = start_dispatcher(transport, permits.clone());

        let response = send_request(
            &sender,
            Command::Ping,
            Some(Instant::now() + Duration::from_millis(20)),
        )
        .await;
        assert_timed_out(response);
        wait_for_count(&active, 0).await;
        assert_eq!(permits.available_permits(), MAX_IN_FLIGHT_HOST_REQUESTS);

        cancel.cancel();
        task.await.unwrap();
    }

    #[tokio::test]
    async fn thirty_three_timed_out_requests_do_not_block_a_later_healthy_request() {
        let transport = FakeTransport::new(Behavior::NeverExceptHealthy);
        let calls = transport.calls.clone();
        let active = transport.active.clone();
        let permits = Arc::new(Semaphore::new(MAX_IN_FLIGHT_HOST_REQUESTS));
        let (sender, cancel, task) = start_dispatcher(transport, permits.clone());
        let deadline = Instant::now() + Duration::from_millis(40);

        let mut requests = Vec::new();
        for _ in 0..33 {
            let sender = sender.clone();
            requests.push(tokio::spawn(async move {
                send_request(&sender, Command::Ping, Some(deadline)).await
            }));
        }
        wait_for_count(&calls, MAX_IN_FLIGHT_HOST_REQUESTS).await;

        let healthy = send_request(
            &sender,
            Command::FileRead {
                path: "healthy".to_string(),
            },
            Some(Instant::now() + Duration::from_secs(1)),
        )
        .await
        .expect("healthy request reply channel should remain available")
        .expect("healthy request should run after timed-out requests");
        assert_eq!(healthy, Event::VMReady);

        for request in requests {
            assert_timed_out(request.await.unwrap());
        }
        wait_for_count(&active, 0).await;
        assert_eq!(permits.available_permits(), MAX_IN_FLIGHT_HOST_REQUESTS);

        cancel.cancel();
        task.await.unwrap();
    }

    #[tokio::test]
    async fn long_running_process_waits_do_not_consume_normal_request_permits() {
        let transport = FakeTransport::new(Behavior::NeverExceptHealthy);
        let calls = transport.calls.clone();
        let active = transport.active.clone();
        let permits = Arc::new(Semaphore::new(1));
        let process_wait_permits = Arc::new(Semaphore::new(1));
        let (sender, cancel, task) = start_dispatcher_with_semaphores(
            transport,
            permits.clone(),
            process_wait_permits.clone(),
        );

        let (reply, receiver) = oneshot::channel();
        sender
            .send(HostRequest {
                cmd: Command::ProcessWait {
                    uuid: uuid::Uuid::nil(),
                },
                deadline: None,
                reply,
            })
            .await
            .unwrap();
        drop(receiver);
        wait_for_count(&calls, 1).await;
        assert_eq!(permits.available_permits(), 1);
        assert_eq!(process_wait_permits.available_permits(), 0);

        let healthy = send_request(
            &sender,
            Command::FileRead {
                path: "healthy".to_string(),
            },
            Some(Instant::now() + Duration::from_secs(1)),
        )
        .await
        .expect("healthy request reply channel should remain available")
        .expect("normal request should run while ProcessWait is pending");
        assert_eq!(healthy, Event::VMReady);

        cancel.cancel();
        task.await.unwrap();
        wait_for_count(&active, 0).await;
        assert_eq!(permits.available_permits(), 1);
        assert_eq!(process_wait_permits.available_permits(), 1);
    }

    #[tokio::test]
    async fn dropping_dispatcher_cancels_tasks_and_releases_every_permit() {
        let transport = FakeTransport::new(Behavior::Never);
        let calls = transport.calls.clone();
        let active = transport.active.clone();
        let permits = Arc::new(Semaphore::new(MAX_IN_FLIGHT_HOST_REQUESTS));
        let (sender, cancel, task) = start_dispatcher(transport, permits.clone());

        for _ in 0..MAX_IN_FLIGHT_HOST_REQUESTS {
            let (reply, receiver) = oneshot::channel();
            sender
                .send(HostRequest {
                    cmd: Command::Ping,
                    deadline: None,
                    reply,
                })
                .await
                .unwrap();
            drop(receiver);
        }
        wait_for_count(&calls, MAX_IN_FLIGHT_HOST_REQUESTS).await;

        cancel.cancel();
        task.await.unwrap();
        wait_for_count(&active, 0).await;
        assert_eq!(permits.available_permits(), MAX_IN_FLIGHT_HOST_REQUESTS);
    }

    #[tokio::test]
    async fn queued_request_expiry_never_starts_transport_work() {
        let transport = FakeTransport::new(Behavior::Never);
        let calls = transport.calls.clone();
        let active = transport.active.clone();
        let permits = Arc::new(Semaphore::new(MAX_IN_FLIGHT_HOST_REQUESTS));
        let (sender, cancel, task) = start_dispatcher(transport, permits.clone());

        for _ in 0..MAX_IN_FLIGHT_HOST_REQUESTS {
            let (reply, receiver) = oneshot::channel();
            sender
                .send(HostRequest {
                    cmd: Command::Ping,
                    deadline: None,
                    reply,
                })
                .await
                .unwrap();
            drop(receiver);
        }
        wait_for_count(&calls, MAX_IN_FLIGHT_HOST_REQUESTS).await;

        let response = send_request(
            &sender,
            Command::Ping,
            Some(Instant::now() + Duration::from_millis(20)),
        )
        .await;
        assert_timed_out(response);
        assert_eq!(calls.load(Ordering::SeqCst), MAX_IN_FLIGHT_HOST_REQUESTS);

        cancel.cancel();
        task.await.unwrap();
        wait_for_count(&active, 0).await;
        assert_eq!(permits.available_permits(), MAX_IN_FLIGHT_HOST_REQUESTS);
    }

    #[tokio::test]
    async fn request_timeout_does_not_depend_on_reply_receiver_being_polled() {
        let transport = FakeTransport::new(Behavior::Never);
        let active = transport.active.clone();
        let permits = Arc::new(Semaphore::new(MAX_IN_FLIGHT_HOST_REQUESTS));
        let (sender, cancel, task) = start_dispatcher(transport, permits.clone());
        let (reply, receiver) = oneshot::channel();
        sender
            .send(HostRequest {
                cmd: Command::Ping,
                deadline: Some(Instant::now() + Duration::from_millis(20)),
                reply,
            })
            .await
            .unwrap();
        drop(receiver);

        wait_for_count(&active, 0).await;
        assert_eq!(permits.available_permits(), MAX_IN_FLIGHT_HOST_REQUESTS);
        cancel.cancel();
        task.await.unwrap();
    }

    #[tokio::test]
    async fn healthy_request_is_not_started_before_a_queued_request_expires() {
        let transport = FakeTransport::new(Behavior::NeverExceptHealthy);
        let calls = transport.calls.clone();
        let active = transport.active.clone();
        let permits = Arc::new(Semaphore::new(1));
        let (sender, cancel, task) = start_dispatcher(transport, permits.clone());

        let (first_reply, first_receiver) = oneshot::channel();
        sender
            .send(HostRequest {
                cmd: Command::Ping,
                deadline: None,
                reply: first_reply,
            })
            .await
            .unwrap();
        drop(first_receiver);
        wait_for_count(&calls, 1).await;

        let response = send_request(
            &sender,
            Command::FileRead {
                path: "healthy".to_string(),
            },
            Some(Instant::now() + Duration::from_millis(20)),
        )
        .await;
        assert_timed_out(response);
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        cancel.cancel();
        task.await.unwrap();
        wait_for_count(&active, 0).await;
        assert_eq!(permits.available_permits(), 1);
    }
}
