//! Jyth-owned scheduler declarations between the public `On` API and the
//! canonical scheduler engine (SolidArchitecturePlan WP3, decision A7).
//!
//! The trigger conversion ([`into_trigger`]) stays in `jyth::builder` next
//! to the public `On` combinator; the trigger/action *packaging* moved into
//! `jyth-runtime` (WP7), which receives the scheduled processes and the
//! shutdown trigger and builds the canonical [`scheduler::ScheduledAction`]
//! values over the runtime guest client.

use crate::vm::Process;

/// A pin-boxed boolean trigger (the canonical scheduler trigger type).
pub(crate) type Trigger = scheduler::Trigger;

/// One scheduled guest process retained by the builder: a trigger and the
/// process to run when the trigger resolves successfully.
pub(crate) struct ScheduledProcess {
    pub(crate) trigger: Trigger,
    pub(crate) process: Process,
}
