//! Shared fake transport/stream doubles for the guest-client contract tests.
//!
//! Every fake implements the same ports as the production `com::TcpEndpoint`
//! adapter, so the contract tests prove the dispatcher, client, file
//! service, and process runner are substitutable over any transport.

use std::collections::VecDeque;

use std::sync::{Arc, Mutex};

use protocol::{Command, Event};
use tokio_util::sync::CancellationToken;

use crate::error::GuestClientError;
use crate::transport::{
    CommandTransport, Dispatcher, HostRequest, ProcessStream, StreamFuture, StreamTransport,
    TransportFuture,
};

/// Reply selector for [`ScriptedTransport`]: decide the reply for one
/// command (typically by echoing the command's fields back).
pub(crate) type Reply = Box<dyn Fn(&Command) -> Event + Send + Sync>;

/// A command transport with a scripted reply queue.
///
/// The queue is popped per command; once empty, process-lifecycle commands
/// are answered with matching echoed events (`ProcessStarted`/`ProcessExited`/
/// `ProcessClosed` from the command's own uuid), so a full direct-process
/// run can be driven without scripting every step.
pub(crate) struct ScriptedTransport {
    replies: Mutex<VecDeque<Reply>>,
}

impl ScriptedTransport {
    /// Fixed replies, returned in order.
    pub(crate) fn new(events: Vec<Event>) -> Self {
        let replies = events
            .into_iter()
            .map(|event| {
                let reply: Reply = Box::new(move |_| event.clone());
                reply
            })
            .collect();
        Self {
            replies: Mutex::new(replies),
        }
    }

    /// Caller-selected reply functions, consumed in order.
    pub(crate) fn scripted(replies: Vec<Reply>) -> Self {
        Self {
            replies: Mutex::new(replies.into()),
        }
    }

    /// Echo-based lifecycle replies only.
    pub(crate) fn process_lifecycle() -> Self {
        Self {
            replies: Mutex::new(VecDeque::new()),
        }
    }
}

impl CommandTransport for ScriptedTransport {
    fn command_async(&self, cmd: Command) -> TransportFuture {
        let event = self
            .replies
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .pop_front()
            .map(|reply| reply(&cmd))
            .unwrap_or_else(|| process_reply(&cmd));
        Box::pin(async move { Ok(event) })
    }
}

/// A transport that never answers; used to prove deadline behavior.
pub(crate) struct SilentTransport;

impl CommandTransport for SilentTransport {
    fn command_async(&self, _cmd: Command) -> TransportFuture {
        Box::pin(std::future::pending::<Result<Event, GuestClientError>>())
    }
}

/// Stream binder that hands out scripted byte chunks.
pub(crate) struct FakeStreams {
    chunks: Mutex<VecDeque<Vec<u8>>>,
}

impl FakeStreams {
    /// Chunks are replayed on every bind, in order, then EOF.
    pub(crate) fn new(chunks: Vec<Vec<u8>>) -> Self {
        Self {
            chunks: Mutex::new(chunks.into()),
        }
    }
}

impl StreamTransport for FakeStreams {
    fn bind_async(&self, _cmd: Command) -> StreamFuture {
        let chunks = self
            .chunks
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .drain(..)
            .collect::<Vec<_>>();
        Box::pin(async move {
            Ok(Box::new(FakeStream {
                chunks: chunks.into(),
            }) as Box<dyn ProcessStream>)
        })
    }
}

struct FakeStream {
    chunks: VecDeque<Vec<u8>>,
}

impl ProcessStream for FakeStream {
    fn read(
        &mut self,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Vec<u8>, GuestClientError>> + Send + '_>,
    > {
        Box::pin(async move { Ok(self.chunks.pop_front().unwrap_or_default()) })
    }

    fn write(
        &mut self,
        _data: &[u8],
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<(), GuestClientError>> + Send + '_>,
    > {
        Box::pin(async move { Ok(()) })
    }
}

/// A running [`Dispatcher`] plus its sender and cancel token for tests.
pub(crate) struct TestDispatcher {
    tx: tokio::sync::mpsc::Sender<HostRequest>,
    cancel: CancellationToken,
    task: tokio::task::JoinHandle<()>,
}

impl TestDispatcher {
    /// The request sender this dispatcher drains.
    pub(crate) fn tx(&self) -> tokio::sync::mpsc::Sender<HostRequest> {
        self.tx.clone()
    }

    /// Cancel the dispatcher and join its task.
    pub(crate) async fn shutdown(self) {
        self.cancel.cancel();
        self.task.await.unwrap();
    }
}

/// Start a dispatcher over `transport` with default permit lanes.
pub(crate) fn start_dispatcher(transport: Arc<dyn CommandTransport>) -> TestDispatcher {
    let (tx, rx) = tokio::sync::mpsc::channel(128);
    let cancel = CancellationToken::new();
    let dispatcher = Dispatcher::new(rx, transport, cancel.clone());
    let task = tokio::spawn(dispatcher.run());
    TestDispatcher { tx, cancel, task }
}

/// Default per-command reply used when a scripted queue is exhausted.
fn process_reply(cmd: &Command) -> Event {
    match cmd {
        Command::ProcessStart { uuid, .. } => Event::ProcessStarted { uuid: *uuid },
        Command::ProcessWait { uuid } => Event::ProcessExited {
            uuid: *uuid,
            exit_code: Some(0),
            signal: None,
        },
        Command::ProcessStop { uuid } => Event::ProcessExited {
            uuid: *uuid,
            exit_code: Some(0),
            signal: None,
        },
        Command::ProcessClose { uuid } => Event::ProcessClosed { uuid: *uuid },
        Command::FileRead { .. } => Event::FileRead {
            path: String::new(),
            data: Vec::new(),
        },
        Command::FileWrite { path, .. } => Event::FileWritten { path: path.clone() },
        Command::FileRemove { path } => Event::FileRemoved { path: path.clone() },
        Command::DirCreate { path } => Event::DirCreated { path: path.clone() },
        Command::DirRemove { path } => Event::DirRemoved { path: path.clone() },
        Command::DirRead { path } => Event::DirRead {
            path: path.clone(),
            entries: Vec::new(),
        },
        Command::VMShutdown => Event::Shutdowned,
        _ => Event::VMReady,
    }
}
