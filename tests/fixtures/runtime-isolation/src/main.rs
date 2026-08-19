//! Test fixture: creates real HCS host resources in a separate process for
//! the e2e runtime-isolation tests.
//!
//! Usage:
//!   runtime-isolation-fixture leave-resources <state-root> <kernel> <initrd> <subnet> <vhdx> <ready>
//!   runtime-isolation-fixture hold-lock <state-root> <kernel> <initrd> <subnet> <vhdx> <ready>
//!   runtime-isolation-fixture recover-and-exit <state-root> <kernel> <initrd>
//!
//! Every mode sets `JYTH_STATE_DIR` from the explicit `<state-root>` argument
//! before any HCS use, so all children and the parent share one state root and
//! no child ever inherits the parent's environment.
//!
//! Not part of any shipped product: compiled on demand by the e2e runtime
//! isolation tests via escargot.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

use vm_model::disk::{DiskRetention, DiskSpec, ExistingDiskPolicy, GuestMount};
use vm_model::network::Nat;

/// Build a NAT on a caller-chosen /24 subnet (gateway `a.b.c.1`, guest
/// `a.b.c.10`). The HNS implementation on this host rejects a second NAT
/// network on an already-used subnet (`HcnCreateNetwork` fails with
/// 0x80071392), so every fixture process gets its own /24.
fn nat(subnet: &str) -> Nat {
    let octets: Vec<u32> = subnet
        .split('.')
        .take(3)
        .map(|octet| octet.parse().expect("subnet octet"))
        .collect();
    let gateway = format!("{}.{}.{}.1", octets[0], octets[1], octets[2]);
    let guest = format!("{}.{}.{}.10", octets[0], octets[1], octets[2]);
    Nat::try_new(subnet, gateway, guest, ["8.8.8.8", "1.1.1.1"]).expect("valid NAT subnet")
}

/// A 64 MiB ephemeral disk mounted at `/data` (the HCS fixture default).
fn ephemeral_disk(path: &Path) -> DiskSpec {
    DiskSpec::new(
        path,
        64,
        GuestMount::new("/data").expect("valid mount"),
        DiskRetention::Ephemeral,
        ExistingDiskPolicy::ReuseAndKeep,
    )
    .expect("valid ephemeral disk spec")
}

/// The `.redb` filenames currently in `root`.
fn list_session_dbs(root: &Path) -> Vec<String> {
    let mut dbs: Vec<String> = std::fs::read_dir(root)
        .expect("read state root")
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "redb")
        })
        .map(|path| {
            path.file_name()
                .expect("db name")
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    dbs.sort();
    dbs
}

/// The fixture's own session database: the `.redb` file that appeared while
/// its `Session::open` + `Vm::new_with_session` ran (each session open
/// creates the current session journal).
fn own_session_db(root: &Path, before: &[String]) -> String {
    let after = list_session_dbs(root);
    after
        .iter()
        .find(|db| !before.iter().any(|other| other.as_str() == db.as_str()))
        .cloned()
        .expect("fixture creates its own session DB")
}

/// Set `JYTH_STATE_DIR` from the explicit `<state-root>` argument and return
/// the root. Runs before any HCS use so the fixture never inherits the
/// parent's environment.
fn take_state_root(args: &mut impl Iterator<Item = OsString>) -> PathBuf {
    let root = PathBuf::from(args.next().expect("usage: <mode> <state-root> ..."));
    // SAFETY: `JYTH_STATE_DIR` is set exactly once, before any HCS use and
    // before the runtime starts any task.
    unsafe { std::env::set_var("JYTH_STATE_DIR", &root) };
    root
}

fn next_path(args: &mut impl Iterator<Item = OsString>, usage: &str) -> PathBuf {
    PathBuf::from(next_arg(args, usage))
}

fn next_string(args: &mut impl Iterator<Item = OsString>, usage: &str) -> String {
    next_arg(args, usage).to_string_lossy().into_owned()
}

fn next_arg(args: &mut impl Iterator<Item = OsString>, usage: &str) -> OsString {
    args.next().unwrap_or_else(|| panic!("usage: {usage}"))
}

/// Create the same host resources as a real launch (journal record, HNS
/// network, VHDX, compute system) without starting the VM. Returns the VM
/// handle (which keeps the session — and its redb writer lock — alive) plus
/// the fixture's own session database filename.
async fn create_resources(
    state_root: &Path,
    kernel: &Path,
    initrd: &Path,
    subnet: &str,
    vhdx: &Path,
) -> (hypervisor::Vm, String) {
    let dbs_before = list_session_dbs(state_root);
    let session = hypervisor::Session::open(state_root)
        .await
        .expect("fixture opens a session");
    let vm = hypervisor::Vm::new_with_session(
        &session,
        kernel,
        initrd,
        256,
        1,
        "console=ttyS0",
        Some(&nat(subnet)),
        Some(&[ephemeral_disk(vhdx)]),
    )
    .await
    .expect("fixture creates a VM without starting it");
    let own_db = own_session_db(state_root, &dbs_before);
    (vm, own_db)
}

/// Publish the ready file atomically: write the VM UUID plus the fixture's
/// own session database filename to `<ready>.tmp`, then rename it into place
/// so a poller never observes a partially written file.
fn publish_ready(ready: &Path, vm: &hypervisor::Vm, own_db: &str) {
    let marker_text = format!("{}\n{own_db}\n", vm.uuid());
    let tmp = ready.with_extension("tmp");
    std::fs::write(&tmp, marker_text).expect("write ready file");
    std::fs::rename(&tmp, ready).expect("publish ready file");
}

/// `leave-resources`: create resources, publish readiness, and exit without
/// running any cleanup — exactly the durable state a hard-killed Jyth process
/// leaves behind for the next recovery pass.
async fn leave_resources(args: &mut impl Iterator<Item = OsString>) {
    let state_root = take_state_root(args);
    let usage = "leave-resources <state-root> <kernel> <initrd> <subnet> <vhdx> <ready>";
    let kernel = next_path(args, usage);
    let initrd = next_path(args, usage);
    let subnet = next_string(args, usage);
    let vhdx = next_path(args, usage);
    let ready = next_path(args, usage);
    let (vm, own_db) = create_resources(&state_root, &kernel, &initrd, &subnet, &vhdx).await;
    publish_ready(&ready, &vm, &own_db);
    // Skip Drop cleanup entirely: the journal record, HNS network, VHDX, and
    // compute system all remain for the parent to recover. A plain binary may
    // call `exit(0)` — no libtest harness reports it as a failure.
    std::process::exit(0);
}

/// `hold-lock`: same resource creation and atomic ready publish as
/// `leave-resources`, then sleep forever. The process stays alive holding its
/// `.redb` writer lock — the liveness lease that must protect its session from
/// every other recovery pass. The parent kills this process.
async fn hold_lock(args: &mut impl Iterator<Item = OsString>) {
    let state_root = take_state_root(args);
    let usage = "hold-lock <state-root> <kernel> <initrd> <subnet> <vhdx> <ready>";
    let kernel = next_path(args, usage);
    let initrd = next_path(args, usage);
    let subnet = next_string(args, usage);
    let vhdx = next_path(args, usage);
    let ready = next_path(args, usage);
    let (vm, own_db) = create_resources(&state_root, &kernel, &initrd, &subnet, &vhdx).await;
    publish_ready(&ready, &vm, &own_db);
    loop {
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

/// `recover-and-exit`: create a VM with no network and no disks. Opening a
/// fresh session runs the stale-session reconciliation (each session open
/// reconciles once), cleaning a dead session exactly; the fixture's own VM
/// is closed again so the fixture leaves nothing behind.
async fn recover_and_exit(args: &mut impl Iterator<Item = OsString>) {
    let state_root = take_state_root(args);
    let usage = "recover-and-exit <state-root> <kernel> <initrd>";
    let kernel = next_path(args, usage);
    let initrd = next_path(args, usage);
    let session = hypervisor::Session::open(&state_root)
        .await
        .expect("fixture opens a session");
    let vm = hypervisor::Vm::new_with_session(
        &session,
        &kernel,
        &initrd,
        256,
        1,
        "console=ttyS0",
        None,
        None,
    )
    .await
    .expect("fixture VM creation");
    vm.close().await.expect("fixture VM close");
}

#[tokio::main]
async fn main() {
    let mut args = std::env::args_os().skip(1);
    let mode = args
        .next()
        .expect("usage: runtime-isolation-fixture <mode> ...")
        .to_string_lossy()
        .into_owned();
    match mode.as_str() {
        "leave-resources" => leave_resources(&mut args).await,
        "hold-lock" => hold_lock(&mut args).await,
        "recover-and-exit" => recover_and_exit(&mut args).await,
        other => panic!("unknown mode: {other:?}"),
    }
}
