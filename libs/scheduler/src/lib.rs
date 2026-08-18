//! A generic conditional-action coordination engine.
//!
//! The engine coordinates work whose start is gated by a boolean trigger:
//! each [`ScheduledAction`] pairs a trigger future with a cancellation-aware
//! action callback. The engine owns trigger waiting, configured concurrency
//! policy, cancellation, and task joining; it never knows a VM, a guest
//! process, or a transport (SolidArchitecturePlan WP3, decision A7).
//!
//! The Jyth facade supplies the trigger/action adapter (see the jyth crate);
//! this crate reports generic action outcomes only.
//!
//! Defaults match the current Jyth scheduling behavior (unbounded
//! concurrency, no default deadline, no post-cancel grace). The standalone
//! concurrency, timeout, and grace policies remain opt-in until a
//! compatibility decision accepts them as defaults.
//!
//! # Responsibility (SolidArchitecturePlan target catalog)
//!
//! **Owner**: scheduler.
//!
//! **Responsibility**: generic conditional work coordination.
//!
//! **Allowed dependencies**: none (enforced by `tests/architecture`).
//!
//! **Forbidden concepts**: Jyth VM handles, guest protocol values, image
//! artifacts, HCS errors, and COM streams.

use std::{collections::BTreeMap, future::Future, pin::Pin, sync::Arc, time::Duration};

use tokio::{
    sync::{Mutex, Notify, Semaphore},
    task::JoinSet,
};
use tokio_util::sync::CancellationToken;

/// A boolean trigger: resolves `true` to run the action, `false` to skip it
/// (dependency-cancelled semantics).
pub type Trigger = Pin<Box<dyn Future<Output = bool> + Send + 'static>>;

/// The generic outcome of one scheduled action.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionResult {
    /// Whether the action reports success.
    pub succeeded: bool,
    /// Optional human-readable outcome detail.
    pub message: Option<String>,
}

impl ActionResult {
    /// A successful outcome with no detail.
    pub fn success() -> Self {
        Self {
            succeeded: true,
            message: None,
        }
    }

    /// A failed outcome with a reason.
    pub fn failure(message: impl Into<String>) -> Self {
        Self {
            succeeded: false,
            message: Some(message.into()),
        }
    }
}

/// Boxed asynchronous action execution result.
pub type ActionFuture = Pin<Box<dyn Future<Output = ActionResult> + Send + 'static>>;

/// A cancellation-aware action callback. The engine invokes it only after
/// the action's trigger resolves `true`.
pub type Action = Box<dyn FnOnce(CancellationToken) -> ActionFuture + Send + 'static>;

/// One scheduled action: a trigger and the action to run when it resolves.
pub struct ScheduledAction {
    trigger: Trigger,
    action: Action,
    deadline: Option<Duration>,
}

impl ScheduledAction {
    /// Pair a trigger with its action.
    pub fn new(trigger: Trigger, action: Action) -> Self {
        Self {
            trigger,
            action,
            deadline: None,
        }
    }

    /// Set an action deadline. On expiry the engine cancels the action and
    /// reports [`TaskState::TimedOut`]. This is a standalone-only policy;
    /// Jyth-backed calls do not set one (their processes carry their own
    /// deadlines).
    pub fn with_deadline(mut self, deadline: Duration) -> Self {
        self.deadline = Some(deadline);
        self
    }
}

/// Current state of one scheduled action (keyed by its index in the plan).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TaskState {
    /// The trigger has not resolved yet.
    Pending,
    /// The action is running.
    Running,
    /// The action reported a successful outcome.
    Succeeded(ActionResult),
    /// The action reported a failure.
    Failed(ActionResult),
    /// The action deadline elapsed.
    TimedOut,
    /// The trigger resolved `false`, or the engine cancelled the run before
    /// the action started.
    Cancelled,
}

impl TaskState {
    fn terminal(&self) -> bool {
        !matches!(self, Self::Pending | Self::Running)
    }
}

/// A point-in-time view of every action in a run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunSnapshot {
    /// Retained states keyed by action index.
    pub tasks: BTreeMap<usize, TaskState>,
    /// Whether all actions have reached terminal states.
    pub finished: bool,
}

/// A cloneable observer for a run executing in the background.
#[derive(Clone)]
pub struct RunObserver {
    state: Arc<Mutex<RunSnapshot>>,
    changed: Arc<Notify>,
}

impl RunObserver {
    /// Return the latest retained run state.
    pub async fn snapshot(&self) -> RunSnapshot {
        self.state.lock().await.clone()
    }

    /// Wait until every action reaches a terminal state.
    pub async fn wait(&self) -> RunSnapshot {
        loop {
            let notified = self.changed.notified();
            tokio::pin!(notified);
            // Register the waiter before inspecting state while holding the
            // same mutex that writers use. This closes the gap where a writer
            // could otherwise notify after the snapshot but before `await`
            // has registered with `Notify`.
            let snapshot = {
                let state = self.state.lock().await;
                notified.as_mut().enable();
                state.clone()
            };
            if snapshot.finished {
                return snapshot;
            }
            notified.await;
        }
    }
}

/// Handle for observing and cancelling a run executing in the background.
pub struct RunHandle {
    observer: RunObserver,
    cancel: CancellationToken,
    coordinator: tokio::task::JoinHandle<()>,
}

impl RunHandle {
    /// Clone an observer for snapshots or waits.
    pub fn observe(&self) -> RunObserver {
        self.observer.clone()
    }

    /// Cancel the run: pending actions stop waiting, running actions are
    /// cancelled. With a configured post-cancel grace the engine waits up to
    /// that long for actions to clean up before aborting; without one it
    /// aborts immediately.
    pub fn cancel(&self) {
        self.cancel.cancel();
    }

    /// Wait for the run to finish and return its report.
    pub async fn wait(self) -> RunReport {
        RunReport {
            snapshot: self.observer.wait().await,
            observer: self.observer,
        }
    }

    /// Join the coordinator task. Prefer `wait` unless the run was cancelled.
    pub async fn join(self) {
        let _ = self.coordinator.await;
    }
}

/// Completed run state and an observer for retained action details.
pub struct RunReport {
    /// Final snapshot of all action states.
    pub snapshot: RunSnapshot,
    /// Observer that can be used to inspect the same retained state.
    pub observer: RunObserver,
}

impl RunReport {
    /// Return `true` when every action reported success.
    pub fn succeeded(&self) -> bool {
        self.snapshot
            .tasks
            .values()
            .all(|state| matches!(state, TaskState::Succeeded(result) if result.succeeded))
    }
}

/// Coordinates a set of [`ScheduledAction`]s.
///
/// Defaults match the current Jyth scheduling behavior: every action waits
/// for its trigger concurrently (no concurrency cap), no default deadline,
/// and cancellation aborts immediately. The standalone-only policies
/// (concurrency cap, per-action deadlines, post-cancel grace) are opt-in.
#[derive(Default)]
pub struct Scheduler {
    max_concurrent: Option<usize>,
    post_cancel_grace: Option<Duration>,
}

impl Scheduler {
    /// Create a scheduler with the Jyth-compatible defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Bound the number of concurrently running actions. This is a
    /// standalone-only policy; Jyth-backed calls leave it unbounded.
    pub fn with_max_concurrent(mut self, max: usize) -> Self {
        self.max_concurrent = Some(max);
        self
    }

    /// Grant cancelled actions up to `grace` to finish cleanup before the
    /// engine aborts them. This is a standalone-only policy; Jyth-backed
    /// calls leave cancellation immediate.
    pub fn with_post_cancel_grace(mut self, grace: Duration) -> Self {
        self.post_cancel_grace = Some(grace);
        self
    }

    /// Start a set of actions on the current Tokio runtime.
    ///
    /// # Panics
    ///
    /// Panics when called without an active Tokio runtime, because
    /// coordinating the run uses [`tokio::spawn`].
    pub fn start(&self, actions: Vec<ScheduledAction>) -> RunHandle {
        let count = actions.len();
        let snapshot = RunSnapshot {
            tasks: (0..count)
                .map(|index| (index, TaskState::Pending))
                .collect(),
            finished: false,
        };
        let observer = RunObserver {
            state: Arc::new(Mutex::new(snapshot)),
            changed: Arc::new(Notify::new()),
        };
        let cancel = CancellationToken::new();
        let coordinator = tokio::spawn(coordinate(
            actions,
            observer.clone(),
            cancel.clone(),
            self.max_concurrent,
            self.post_cancel_grace,
        ));
        RunHandle {
            observer,
            cancel,
            coordinator,
        }
    }

    /// Run a set of actions to completion on the current Tokio runtime.
    pub async fn run(&self, actions: Vec<ScheduledAction>) -> RunReport {
        self.start(actions).wait().await
    }
}

async fn set_state(observer: &RunObserver, index: usize, state: TaskState) {
    observer.state.lock().await.tasks.insert(index, state);
    observer.changed.notify_waiters();
}

async fn coordinate(
    actions: Vec<ScheduledAction>,
    observer: RunObserver,
    engine_cancel: CancellationToken,
    max_concurrent: Option<usize>,
    post_cancel_grace: Option<Duration>,
) {
    let capacity = max_concurrent.map(|max| Arc::new(Semaphore::new(max)));
    let mut jobs = JoinSet::new();
    for (index, action) in actions.into_iter().enumerate() {
        let child_cancel = engine_cancel.child_token();
        let observer = observer.clone();
        let capacity = capacity.clone();
        jobs.spawn(async move {
            let _permit = match &capacity {
                Some(capacity) => Some(
                    capacity
                        .clone()
                        .acquire_owned()
                        .await
                        .expect("semaphore never closes"),
                ),
                None => None,
            };
            run_action(index, action, observer, child_cancel, post_cancel_grace).await
        });
    }

    let mut grace_started = false;
    loop {
        tokio::select! {
            result = jobs.join_next() => match result {
                Some(_) => {
                    // Per-action state transitions are published by
                    // `run_action`; the coordinator only tracks completion.
                }
                None => break,
            },
            _ = engine_cancel.cancelled(), if !grace_started => {
                grace_started = true;
                if let Some(grace) = post_cancel_grace {
                    let _ = tokio::time::timeout(grace, async {
                        while jobs.join_next().await.is_some() {}
                    })
                    .await;
                }
                jobs.abort_all();
            }
        }
    }

    let mut state = observer.state.lock().await;
    for value in state.tasks.values_mut() {
        if !value.terminal() {
            *value = TaskState::Cancelled;
        }
    }
    state.finished = true;
    drop(state);
    observer.changed.notify_waiters();
}

async fn run_action(
    index: usize,
    action: ScheduledAction,
    observer: RunObserver,
    cancel: CancellationToken,
    post_cancel_grace: Option<Duration>,
) {
    let triggered = tokio::select! {
        value = action.trigger => value,
        _ = cancel.cancelled() => {
            set_state(&observer, index, TaskState::Cancelled).await;
            return;
        }
    };
    if !triggered {
        // Dependency-cancelled: the action is never invoked.
        set_state(&observer, index, TaskState::Cancelled).await;
        return;
    }

    set_state(&observer, index, TaskState::Running).await;
    let future = (action.action)(cancel.clone());
    tokio::pin!(future);

    let outcome = match action.deadline {
        Some(deadline) => {
            let timer = tokio::time::sleep(deadline);
            tokio::pin!(timer);
            tokio::select! {
                value = &mut future => value,
                _ = &mut timer => {
                    cancel.cancel();
                    if let Some(grace) = post_cancel_grace {
                        let _ = tokio::time::timeout(grace, &mut future).await;
                    }
                    return set_state(&observer, index, TaskState::TimedOut).await;
                }
            }
        }
        None => future.await,
    };

    if outcome.succeeded {
        set_state(&observer, index, TaskState::Succeeded(outcome)).await;
    } else {
        set_state(&observer, index, TaskState::Failed(outcome)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::{Barrier, oneshot};

    fn gate() -> (Trigger, oneshot::Sender<bool>) {
        let (tx, rx) = oneshot::channel();
        (
            Box::pin(async move { rx.await.unwrap_or(false) }) as Trigger,
            tx,
        )
    }

    fn action_of(log: Arc<std::sync::Mutex<Vec<String>>>, name: &str) -> Action {
        let log = log.clone();
        let name = name.to_owned();
        Box::new(move |_cancel| {
            Box::pin(async move {
                log.lock().expect("test log").push(name);
                ActionResult::success()
            }) as ActionFuture
        })
    }

    fn pending_action() -> Action {
        Box::new(|_cancel| {
            Box::pin(async {
                let value: ActionResult = std::future::pending().await;
                value
            }) as ActionFuture
        })
    }

    fn ok_action() -> Action {
        Box::new(|_cancel| Box::pin(async { ActionResult::success() }) as ActionFuture)
    }

    #[tokio::test]
    async fn action_runs_when_its_trigger_resolves_true() {
        let (trigger, tx) = gate();
        let log = Arc::new(std::sync::Mutex::new(Vec::new()));
        let scheduler = Scheduler::new();
        let handle = scheduler.start(vec![ScheduledAction::new(
            trigger,
            action_of(log.clone(), "a"),
        )]);
        tx.send(true).unwrap();
        let report = handle.wait().await;
        assert!(report.succeeded());
        assert_eq!(*log.lock().expect("test log"), ["a"]);
    }

    #[tokio::test]
    async fn action_is_skipped_when_its_trigger_resolves_false() {
        let (trigger, tx) = gate();
        let log = Arc::new(std::sync::Mutex::new(Vec::new()));
        let scheduler = Scheduler::new();
        let handle = scheduler.start(vec![ScheduledAction::new(
            trigger,
            action_of(log.clone(), "a"),
        )]);
        tx.send(false).unwrap();
        let report = handle.wait().await;
        assert!(matches!(report.snapshot.tasks[&0], TaskState::Cancelled));
        assert!(log.lock().expect("test log").is_empty());
    }

    #[tokio::test]
    async fn linear_chain_runs_in_order() {
        let (a_gate, a_tx) = gate();
        let (b_gate, b_tx) = gate();
        let log = Arc::new(std::sync::Mutex::new(Vec::new()));
        let scheduler = Scheduler::new();
        let handle = scheduler.start(vec![
            ScheduledAction::new(a_gate, action_of(log.clone(), "a")),
            ScheduledAction::new(b_gate, action_of(log.clone(), "b")),
        ]);
        a_tx.send(true).unwrap();
        // b's trigger resolves only after a's action reported success.
        tokio::time::sleep(Duration::from_millis(5)).await;
        b_tx.send(true).unwrap();
        let report = handle.wait().await;
        assert!(report.succeeded());
        let log = log.lock().expect("test log");
        assert_eq!(*log, ["a", "b"]);
    }

    #[tokio::test]
    async fn fan_out_and_fan_in() {
        let (root_gate, root_tx) = gate();
        let (left_gate, left_tx) = gate();
        let (right_gate, right_tx) = gate();
        let (join_gate, join_tx) = gate();
        let log = Arc::new(std::sync::Mutex::new(Vec::new()));
        let scheduler = Scheduler::new();
        let handle = scheduler.start(vec![
            ScheduledAction::new(root_gate, action_of(log.clone(), "root")),
            ScheduledAction::new(left_gate, action_of(log.clone(), "left")),
            ScheduledAction::new(right_gate, action_of(log.clone(), "right")),
            ScheduledAction::new(join_gate, action_of(log.clone(), "join")),
        ]);
        root_tx.send(true).unwrap();
        left_tx.send(true).unwrap();
        right_tx.send(true).unwrap();
        tokio::time::sleep(Duration::from_millis(5)).await;
        join_tx.send(true).unwrap();
        let report = handle.wait().await;
        assert!(report.succeeded());
        let log = log.lock().expect("test log");
        let left = log.iter().position(|v| v == "left").unwrap();
        let right = log.iter().position(|v| v == "right").unwrap();
        let join = log.iter().position(|v| v == "join").unwrap();
        assert!(
            left < join && right < join,
            "join must run after both branches"
        );
    }

    #[tokio::test]
    async fn failed_success_dependency_prevents_the_action() {
        let (trigger, tx) = gate();
        let log = Arc::new(std::sync::Mutex::new(Vec::new()));
        let scheduler = Scheduler::new();
        let handle = scheduler.start(vec![ScheduledAction::new(
            trigger,
            action_of(log.clone(), "child"),
        )]);
        tx.send(false).unwrap();
        let report = handle.wait().await;
        assert!(matches!(report.snapshot.tasks[&0], TaskState::Cancelled));
        assert!(log.lock().expect("test log").is_empty());
    }

    #[tokio::test]
    async fn deadline_is_terminal() {
        let (trigger, tx) = gate();
        let scheduler = Scheduler::new();
        let handle = scheduler.start(vec![
            ScheduledAction::new(trigger, pending_action())
                .with_deadline(Duration::from_millis(10)),
        ]);
        tx.send(true).unwrap();
        let report = tokio::time::timeout(Duration::from_secs(5), handle.wait())
            .await
            .expect("deadline must finish the run");
        assert!(matches!(report.snapshot.tasks[&0], TaskState::TimedOut));
    }

    #[tokio::test]
    async fn cancellation_aborts_without_grace() {
        let (trigger, tx) = gate();
        let started = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let action = {
            let started = started.clone();
            Box::new(move |_cancel| {
                Box::pin(async move {
                    started.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    std::future::pending::<ActionResult>().await
                }) as ActionFuture
            })
        };
        let scheduler = Scheduler::new();
        let handle = scheduler.start(vec![ScheduledAction::new(trigger, action)]);
        tx.send(true).unwrap();
        // Wait until the action started, then cancel.
        tokio::time::timeout(Duration::from_secs(5), async {
            while started.load(std::sync::atomic::Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("action must start");
        handle.cancel();
        let report = tokio::time::timeout(Duration::from_secs(5), handle.wait())
            .await
            .expect("cancellation must finish the run");
        assert!(matches!(
            report.snapshot.tasks[&0],
            TaskState::Running | TaskState::Cancelled
        ));
    }

    #[tokio::test]
    async fn max_concurrent_bounds_in_flight_actions() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let (trigger_a, tx_a) = gate();
        let (trigger_b, tx_b) = gate();
        let in_flight = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let barrier = Arc::new(Barrier::new(3)); // cap 2 + test
        let scheduler = Scheduler::new().with_max_concurrent(2);
        let make_action = || {
            let in_flight = in_flight.clone();
            let peak = peak.clone();
            let barrier = barrier.clone();
            Box::new(move |_cancel| {
                Box::pin(async move {
                    let now = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                    peak.fetch_max(now, Ordering::SeqCst);
                    barrier.wait().await;
                    in_flight.fetch_sub(1, Ordering::SeqCst);
                    ActionResult::success()
                }) as ActionFuture
            })
        };
        let handle = scheduler.start(vec![
            ScheduledAction::new(trigger_a, make_action()),
            ScheduledAction::new(trigger_b, make_action()),
        ]);
        tx_a.send(true).unwrap();
        tx_b.send(true).unwrap();
        let run = tokio::spawn(async move { handle.wait().await });
        barrier.wait().await;
        let report = tokio::time::timeout(Duration::from_secs(5), run)
            .await
            .expect("run must finish")
            .expect("coordinator must not panic");
        assert!(report.succeeded());
        assert_eq!(
            peak.load(Ordering::SeqCst),
            2,
            "no more than the cap may run at once"
        );
    }

    #[tokio::test]
    async fn action_panic_is_reported_and_run_finishes() {
        let (trigger, tx) = gate();
        let action = Box::new(|_cancel| {
            Box::pin(async move {
                panic!("action panic");
                #[allow(unreachable_code)]
                ActionResult::success()
            }) as ActionFuture
        });
        let scheduler = Scheduler::new();
        let handle = scheduler.start(vec![ScheduledAction::new(trigger, action)]);
        tx.send(true).unwrap();
        let report = tokio::time::timeout(Duration::from_secs(1), handle.wait())
            .await
            .expect("scheduler must finish after an action panic");
        assert!(!report.succeeded());
    }

    #[tokio::test]
    async fn observers_retain_terminal_state() {
        let (trigger, tx) = gate();
        let scheduler = Scheduler::new();
        let handle = scheduler.start(vec![ScheduledAction::new(trigger, ok_action())]);
        let first = handle.observe();
        let second = first.clone();
        tx.send(true).unwrap();
        let _ = handle.wait().await;
        assert_eq!(first.wait().await, second.wait().await);
    }
}
