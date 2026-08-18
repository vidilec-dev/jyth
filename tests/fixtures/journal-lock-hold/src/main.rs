//! Test fixture: creates a real hypervisor-hcs session journal in a separate
//! process and holds the redb writer lock until terminated.
//!
//! The parent test owns the session id; this binary only creates the journal
//! through the public [`SessionJournal::create_current`] API and signals
//! readiness after the writer lock is acquired.
//!
//! Usage: journal-lock-hold <state-root> <session-id> <ready-file>
//!
//! Not part of any shipped product: compiled on demand by hypervisor-hcs
//! journal tests via escargot.

use std::path::PathBuf;
use std::time::Duration;

fn main() {
    let mut args = std::env::args_os().skip(1);
    let root = PathBuf::from(
        args.next()
            .expect("usage: journal-lock-hold <state-root> <session-id> <ready-file>"),
    );
    let session_id = args
        .next()
        .expect("usage: journal-lock-hold <state-root> <session-id> <ready-file>");
    let ready = PathBuf::from(
        args.next()
            .expect("usage: journal-lock-hold <state-root> <session-id> <ready-file>"),
    );
    let session_id = uuid::Uuid::parse_str(&session_id.to_string_lossy()).expect("parse session id");

    // Binding (not `let _ =`) keeps the database handle — and with it the
    // redb writer lock — alive for the lifetime of this process.
    let _session = hypervisor_hcs::journal::SessionJournal::create_current(&root, session_id)
        .expect("create child session journal");
    std::fs::write(&ready, b"ready").expect("publish readiness");

    loop {
        std::thread::sleep(Duration::from_secs(1));
    }
}
