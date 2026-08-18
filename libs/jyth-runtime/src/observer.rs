//! VM lifecycle observers (moved from the jyth facade, WP7 action 11).
//!
//! The runtime owns the launch, shutdown, and drop publication of the VM
//! lifecycle; the jyth facade re-exports these types so the public
//! `jyth::vm` paths keep compiling unchanged.

use std::sync::Arc;

use tokio::sync::watch;

/// A retained, cloneable view of one VM's lifecycle.
#[derive(Clone)]
pub struct VmObserver {
    receiver: watch::Receiver<VmState>,
}

/// The observable state of a VM launched through a builder observer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VmState {
    /// The builder exists but launch has not started.
    Pending,
    /// Image and VM preparation is in progress.
    Launching,
    /// The guest has completed its ready handshake.
    Running,
    /// The VM reached a normal terminal state.
    Finished(VmFinish),
    /// Launch or shutdown failed.
    Failed(VmFailure),
}

/// A normal terminal VM outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmFinish {
    /// The guest received a shutdown request.
    Shutdown,
    /// The VM handle was dropped before an explicit shutdown.
    Dropped,
}

impl std::fmt::Display for VmFinish {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Shutdown => write!(f, "Shutdown"),
            Self::Dropped => write!(f, "Dropped"),
        }
    }
}

/// The lifecycle phase in which a VM failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmPhase {
    /// Failure while preparing or starting the VM.
    Launch,
    /// Failure while shutting down the VM.
    Shutdown,
}

/// A terminal VM failure retained by [`VmObserver`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmFailure {
    /// Lifecycle phase in which the failure occurred.
    pub phase: VmPhase,
    /// Human-readable failure description.
    pub message: Arc<str>,
}

impl std::fmt::Display for VmFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "VM {:?} failed: {}", self.phase, self.message)
    }
}

impl std::error::Error for VmFailure {}

impl VmState {
    fn is_terminal(&self) -> bool {
        matches!(self, Self::Finished(_) | Self::Failed(_))
    }
}

impl VmObserver {
    /// Returns the latest state without waiting. `watch` retains its last value,
    /// so terminal state remains available after the VM and builder are gone.
    pub fn state(&self) -> VmState {
        self.receiver.borrow().clone()
    }

    /// Wait until the VM has started successfully or has failed to launch.
    /// A replayed normal terminal state also means it started successfully.
    pub fn started(
        &self,
    ) -> impl std::future::Future<Output = Result<(), VmFailure>> + Send + 'static {
        let mut receiver = self.receiver.clone();
        async move {
            loop {
                match receiver.borrow_and_update().clone() {
                    VmState::Running | VmState::Finished(_) => return Ok(()),
                    VmState::Failed(failure) => return Err(failure),
                    VmState::Pending | VmState::Launching => {}
                }
                if receiver.changed().await.is_err() {
                    return started_from_closed(receiver.borrow().clone());
                }
            }
        }
    }

    /// Wait until the VM reaches a terminal state, replaying an already
    /// retained terminal state to every observer clone.
    pub fn finished(
        &self,
    ) -> impl std::future::Future<Output = Result<VmFinish, VmFailure>> + Send + 'static {
        let mut receiver = self.receiver.clone();
        async move {
            loop {
                match receiver.borrow_and_update().clone() {
                    VmState::Finished(finish) => return Ok(finish),
                    VmState::Failed(failure) => return Err(failure),
                    VmState::Pending | VmState::Launching | VmState::Running => {}
                }
                if receiver.changed().await.is_err() {
                    return finished_from_closed(receiver.borrow().clone());
                }
            }
        }
    }
}

fn closed_failure() -> VmFailure {
    VmFailure {
        phase: VmPhase::Launch,
        message: Arc::from("VM lifecycle sender closed before launch completed"),
    }
}

fn started_from_closed(state: VmState) -> Result<(), VmFailure> {
    match state {
        VmState::Running | VmState::Finished(_) => Ok(()),
        VmState::Failed(failure) => Err(failure),
        VmState::Pending | VmState::Launching => Err(closed_failure()),
    }
}

fn finished_from_closed(state: VmState) -> Result<VmFinish, VmFailure> {
    match state {
        VmState::Finished(finish) => Ok(finish),
        VmState::Failed(failure) => Err(failure),
        VmState::Pending | VmState::Launching | VmState::Running => Err(closed_failure()),
    }
}

/// The producer side, consumed by the runtime launch and shutdown services
/// and constructed by the facade's observer-first builders.
#[derive(Clone)]
pub struct VmLifecycle {
    sender: watch::Sender<VmState>,
}

impl VmLifecycle {
    /// Create a lifecycle and its retained observer.
    pub fn new() -> (VmObserver, Self) {
        let (sender, receiver) = watch::channel(VmState::Pending);
        (VmObserver { receiver }, Self { sender })
    }

    /// Publish the launch phase (started by the launcher).
    pub fn launching(&self) {
        self.set(VmState::Launching);
    }

    /// Publish the ready-to-drive phase (published before the launcher
    /// returns the live VM).
    pub fn running(&self) {
        self.set(VmState::Running);
    }

    /// Publish a normal terminal outcome.
    pub fn finished(&self, finish: VmFinish) {
        self.set(VmState::Finished(finish));
    }

    /// Publish a terminal failure for the given phase.
    pub fn failed(&self, phase: VmPhase, message: impl Into<Arc<str>>) {
        self.set(VmState::Failed(VmFailure {
            phase,
            message: message.into(),
        }));
    }

    fn set(&self, next: VmState) {
        let _ = self.sender.send_if_modified(|current| {
            if current.is_terminal() {
                false
            } else {
                *current = next;
                true
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn state_and_waits_replay_terminal_state_to_clones() {
        let (observer, lifecycle) = VmLifecycle::new();
        let clone = observer.clone();
        assert_eq!(observer.state(), VmState::Pending);

        lifecycle.launching();
        lifecycle.running();
        lifecycle.finished(VmFinish::Shutdown);

        assert_eq!(observer.started().await, Ok(()));
        assert_eq!(clone.finished().await, Ok(VmFinish::Shutdown));
        assert_eq!(clone.state(), VmState::Finished(VmFinish::Shutdown));
    }

    #[tokio::test]
    async fn failure_releases_both_waits_and_is_retained() {
        let (observer, lifecycle) = VmLifecycle::new();
        lifecycle.failed(VmPhase::Launch, Arc::from("READY failed"));

        let expected = VmFailure {
            phase: VmPhase::Launch,
            message: Arc::from("READY failed"),
        };
        assert_eq!(observer.started().await, Err(expected.clone()));
        assert_eq!(observer.finished().await, Err(expected));
    }

    #[tokio::test]
    async fn terminal_state_cannot_be_overwritten() {
        let (observer, lifecycle) = VmLifecycle::new();
        lifecycle.finished(VmFinish::Dropped);
        lifecycle.failed(VmPhase::Shutdown, Arc::from("too late"));
        lifecycle.finished(VmFinish::Shutdown);

        assert_eq!(observer.state(), VmState::Finished(VmFinish::Dropped));
    }

    #[tokio::test]
    async fn closed_pending_sender_does_not_hang_waiters() {
        let (observer, lifecycle) = VmLifecycle::new();
        drop(lifecycle);

        let failure = tokio::time::timeout(std::time::Duration::from_secs(1), observer.finished())
            .await
            .expect("closed watch channel must wake observer")
            .expect_err("closed pending lifecycle is a launch failure");
        assert_eq!(failure.phase, VmPhase::Launch);
    }
}
