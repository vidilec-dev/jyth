//! Live HCS isolation and crash-recovery gates (impl/ImplPlan.md Phase 6,
//! docs/TestE2E.md "Runtime hardening live gates").
//!
//! Scenarios:
//!
//! - `two_live_vms_are_not_cross_cleaned`: launching and shutting down one
//!   VM must never touch a second live VM's HNS network, VHDX file, or
//!   guest command service.
//! - `recovers_crashed_session_while_live_holder_is_untouched`: a parent
//!   launch recovers a crashed child session's resources (compute system,
//!   HNS network, VHDX, journal DB) while leaving a live child session's
//!   locked resources untouched; the live child is then killed and its now
//!   stale session is recovered by a fresh fixture process.
//! - `killed_holder_session_is_recovered_by_a_fresh_process`: the focused
//!   post-kill scenario — a killed holder's session is recovered exactly by
//!   a fresh fixture process.
//!
//! The children are a dedicated fixture binary (`tests/fixtures/runtime-isolation`,
//! built with escargot into a dedicated temp target dir — see
//! [`fixture_binary`]) with explicit CLI modes, mirroring the
//! `journal-lock-hold` recipe from `libs/hypervisor-hcs/src/journal.rs`
//! (`writer_lock_is_exclusive_across_processes_and_released_after_termination`).
//! Each run derives its NAT subnets from a per-run UUID ([`run_unique_subnets`])
//! so a retry after a failed run never collides with leftover HNS networks,
//! and the parent waits deterministically for the redb writer lock to be
//! released after a child dies ([`wait_for_unlocked`], which probes through
//! `hypervisor_hcs::journal::probe_session_lock`) before opening a fresh
//! session whose reconciliation pass must observe the unlocked database.
//!
//! All tests share one per-binary state directory (`JYTH_STATE_DIR` is read
//! once per process), serialized in-process by `hcs_test_guard` and across
//! processes by its `LockFileEx` host lock; the command line adds
//! `--test-threads=1`.
//!
//! Post-run inspection: `Get-VM`, `Get-HnsNetwork`, the per-binary state
//! dir (`%TEMP%\jyth-e2e\runtime_isolation\`: journal `*.redb` session DBs
//! and VHDX files), and `icacls` on any leftover VHDX. After a clean run
//! there must be no `jyth-nat-*` HNS network, no journaled compute system,
//! and no VHDX left by this binary.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Duration;

use e2e_tests::{VmGuard, alpine_image, hcs_test_guard, linuxkit_image, materialize_image};

use jyth::builder::VmBuilder;
use jyth::vm::ProcessBuilder;
use uuid::Uuid;

type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

/// Rootfs fixture for launches that attach disks. The stock `alpine`
/// busybox build ships no ext-family formatter, so a created disk would
/// fail init with `DiskFormatFailed`; the official `busybox` image's
/// default config includes `mke2fs`/`mkfs.ext2` plus `mount`/`sh`/`ip`.
fn disk_image() -> (jyth::builder::image::Kernel, jyth::builder::image::Rootfs) {
    linuxkit_image("busybox:1.36.1")
}

/// Build a NAT with a caller-chosen subnet. The HNS implementation on this
/// host rejects a second NAT network on an already-used subnet
/// (`HcnCreateNetwork` fails with 0x80071392 "The object already exists"),
/// and `Nat::default()` uses one fixed 10.77.0.0/24 — so every VM that may
/// coexist with another VM gets its own /24.
fn nat(subnet: &str) -> vm_model::network::Nat {
    let octets: Vec<u32> = subnet
        .split('.')
        .take(3)
        .map(|o| o.parse().expect("subnet"))
        .collect();
    let gateway = format!("{}.{}.{}.1", octets[0], octets[1], octets[2]);
    let guest = format!("{}.{}.{}.10", octets[0], octets[1], octets[2]);
    vm_model::network::Nat::try_new(subnet, gateway, guest, ["8.8.8.8", "1.1.1.1"])
        .expect("valid NAT subnet")
}

/// The single per-binary state directory. `JYTH_STATE_DIR` is read once per
/// process at first HCS use, so every test in this binary (and every child
/// helper it spawns) must agree on one directory. Stale session databases
/// from previous runs are deliberately NOT swept: the next session open
/// reconciles them and removes their exact resources (sweeping would orphan
/// the HNS networks and compute systems of any failed run forever).
fn state_dir() -> &'static Path {
    static STATE_DIR: OnceLock<PathBuf> = OnceLock::new();
    STATE_DIR.get_or_init(|| {
        let dir = std::env::temp_dir()
            .join("jyth-e2e")
            .join("runtime_isolation");
        std::fs::create_dir_all(&dir).expect("create per-binary state dir");
        dir
    })
}

/// Set `JYTH_STATE_DIR` for this process and return the directory. Called
/// at the start of every test; idempotent (the [`OnceLock`] in
/// [`state_dir`] makes the first call the only effective one).
fn ensure_state_dir() -> &'static Path {
    let dir = state_dir();
    // SAFETY: set before any HCS use; called from single-threaded test
    // setup (each test binary is one process, tests run serially).
    unsafe { std::env::set_var("JYTH_STATE_DIR", dir) };
    dir
}

/// Build the `runtime-isolation-fixture` binary with escargot and return its
/// executable path. Built once per test process into a dedicated temp target
/// dir: never the workspace target dir, whose build lock the outer
/// `cargo test` already holds. Called before any child is spawned so the
/// build cost never counts against the ready-file deadline.
fn fixture_binary() -> PathBuf {
    static BINARY: OnceLock<PathBuf> = OnceLock::new();
    BINARY
        .get_or_init(|| {
            let manifest = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/fixtures/runtime-isolation/Cargo.toml");
            let target_dir = std::env::temp_dir().join("jyth-runtime-isolation-target");
            escargot::CargoBuild::new()
                .bin("runtime-isolation-fixture")
                .manifest_path(&manifest)
                .target_dir(&target_dir)
                .run()
                .expect("build runtime isolation fixture")
                .path()
                .to_path_buf()
        })
        .clone()
}

/// Kill a spawned child on drop so a panicking parent test never leaks a
/// helper process that holds a session lock or an HNS network.
struct ChildGuard {
    child: Option<tokio::process::Child>,
}

impl ChildGuard {
    fn new(child: tokio::process::Child) -> Self {
        Self { child: Some(child) }
    }

    fn take(&mut self) -> Option<tokio::process::Child> {
        self.child.take()
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(child) = &mut self.child {
            let _ = child.start_kill();
        }
    }
}

/// Poll `path` until the fixture's ready file exists, then parse its two
/// lines: the VM UUID and the fixture's own `.redb` session database
/// filename. The fixture publishes via atomic rename, so no empty-file
/// window handling is needed — only a NotFound retry loop.
async fn wait_for_ready(path: &Path, cap: Duration) -> Result<(Uuid, String), String> {
    let wait = async {
        loop {
            match tokio::fs::read_to_string(path).await {
                Ok(contents) => {
                    let mut lines = contents.lines();
                    let uuid_line = lines
                        .next()
                        .ok_or_else(|| format!("empty ready file {}", path.display()))?;
                    let uuid =
                        Uuid::parse_str(uuid_line.trim()).map_err(|error| error.to_string())?;
                    let db = lines
                        .next()
                        .ok_or_else(|| format!("missing session DB line in {}", path.display()))?
                        .to_string();
                    return Ok((uuid, db));
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(format!("failed reading {}: {error}", path.display())),
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    };
    tokio::time::timeout(cap, wait)
        .await
        .map_err(|_| format!("timed out after {cap:?} waiting for {}", path.display()))?
}

/// Poll a session database until `probe_session_lock` reports it recoverable
/// — a deterministic wait for the redb writer lock release after the owning
/// process dies. `Corrupt` is a hard failure (the database is unlocked but
/// unreadable, which the parent's recovery pass could not fix either).
async fn wait_for_unlocked(path: &Path, cap: Duration) -> Result<(), String> {
    let deadline = std::time::Instant::now() + cap;
    loop {
        match hypervisor_hcs::journal::probe_session_lock(path)
            .map_err(|error| format!("probe {}: {error}", path.display()))?
        {
            hypervisor_hcs::journal::SessionLockState::Recoverable => return Ok(()),
            hypervisor_hcs::journal::SessionLockState::Locked => {}
            hypervisor_hcs::journal::SessionLockState::Corrupt(reason) => {
                return Err(format!(
                    "session database {} is unlocked but unreadable: {reason}",
                    path.display()
                ));
            }
        }
        if std::time::Instant::now() >= deadline {
            return Err(format!(
                "timed out after {cap:?} waiting for the writer lock on {} to be released",
                path.display()
            ));
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// Spawn a fixture mode with the given arguments, wrapping the child in a
/// guard that kills it on drop so a panicking parent test never leaks a
/// helper process that holds a session lock or an HNS network.
fn spawn_fixture(mode: &str, args: &[OsString]) -> Result<ChildGuard, std::io::Error> {
    let mut cmd = tokio::process::Command::new(fixture_binary());
    cmd.arg(mode);
    cmd.args(args);
    Ok(ChildGuard::new(cmd.spawn()?))
}

/// The `jyth-nat-*` HNS network names currently registered on the host.
fn list_network_names() -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
    let networks = hcs_admin::list_legacy_networks()?;
    Ok(networks
        .iter()
        .filter_map(|resource| resource.name.clone())
        .collect())
}

/// A 64 MiB ephemeral disk mounted at `/data` (the HCS fixture default).
fn ephemeral_disk(path: &Path) -> vm_model::disk::DiskSpec {
    vm_model::disk::DiskSpec::new(
        path,
        64,
        vm_model::disk::GuestMount::new("/data").expect("valid mount"),
        vm_model::disk::DiskRetention::Ephemeral,
        vm_model::disk::ExistingDiskPolicy::ReuseAndKeep,
    )
    .expect("valid ephemeral disk spec")
}

/// Derive three distinct /24 subnets from one per-run UUID. The HNS
/// implementation on this host rejects a second NAT network on an already-used
/// subnet (0x80071392), and a failed run leaves its HNS networks behind — so
/// fixed subnets would wedge the retry. Deriving the second octet from a fresh
/// UUID makes every run (including a retry) use subnets no leftover network
/// occupies. The second octet is kept away from 77 (the fixed default NAT) and
/// 91 (the subnets used by `two_live_vms_are_not_cross_cleaned`) so a run
/// never collides with a live neighbor's network either.
fn run_unique_subnets() -> (String, String, String) {
    let bytes = *Uuid::now_v7().as_bytes();
    let mut second = 20 + u32::from(bytes[0]) % 180;
    if second == 77 || second == 91 {
        second += 1;
    }
    let subnet = |third: u32| format!("10.{second}.{third}.0/24");
    (subnet(1), subnet(2), subnet(3))
}

/// Trigger stale-session reconciliation by opening a fresh session (each
/// open runs the reconcile pass once) and materializing a VM with no
/// network and no disks, then closing it. Lightweight: no boot, no guest
/// command. Each call opens its own session, so the pass runs even when an
/// earlier test in this process already used HCS.
async fn trigger_recovery_and_close() -> TestResult {
    let (kernel, rootfs) = alpine_image();
    let (kernel_path, initrd_path) = materialize_image(&kernel, &rootfs).await?;
    let session = hypervisor::Session::open(state_dir()).await?;
    let vm = hypervisor::Vm::new_with_session(
        &session,
        &kernel_path,
        &initrd_path,
        256,
        1,
        "console=ttyS0",
        None,
        None,
    )
    .await?;
    vm.close().await?;
    Ok(())
}

// ---
// Parent tests.
// ---

/// Two live VMs on one host: shutting one down must not remove the other's
/// HNS network, VHDX, or guest command service. Post-run inspection: no
/// `jyth-nat-*` network and no `isolation-*.vhdx` file may remain.
#[tokio::test]
async fn two_live_vms_are_not_cross_cleaned() -> TestResult {
    #[cfg(feature = "tracing")]
    tracing::init();

    let _hcs_guard = hcs_test_guard().await?;
    let state = ensure_state_dir();

    let disk1 = state.join("isolation-vm1.vhdx");
    let disk2 = state.join("isolation-vm2.vhdx");

    let (kernel, rootfs) = disk_image();
    let mut vm1 = VmGuard::new(
        VmBuilder::new()
            .kernel(kernel)
            .rootfs(rootfs)
            .network(nat("10.91.1.0/24"))
            .disk(ephemeral_disk(&disk1))
            .launch()
            .await?,
    );
    let (kernel, rootfs) = disk_image();
    let mut vm2 = VmGuard::new(
        VmBuilder::new()
            .kernel(kernel)
            .rootfs(rootfs)
            .network(nat("10.91.2.0/24"))
            .disk(ephemeral_disk(&disk2))
            .launch()
            .await?,
    );

    let uuid1 = vm1.uuid();
    let uuid2 = vm2.uuid();
    assert_ne!(uuid1, uuid2, "each launch must get a fresh VM UUID");

    let networks = list_network_names()?;
    assert!(
        networks.contains(&format!("jyth-nat-{uuid1}")),
        "vm1 network missing: {networks:?}"
    );
    assert!(
        networks.contains(&format!("jyth-nat-{uuid2}")),
        "vm2 network missing: {networks:?}"
    );
    assert!(disk1.exists(), "vm1 vhdx missing");
    assert!(disk2.exists(), "vm2 vhdx missing");

    vm1.shutdown().await?;

    let networks = list_network_names()?;
    assert!(
        !networks.contains(&format!("jyth-nat-{uuid1}")),
        "vm1 network must be removed by its own shutdown"
    );
    assert!(
        networks.contains(&format!("jyth-nat-{uuid2}")),
        "vm2 network must survive vm1 shutdown: {networks:?}"
    );
    assert!(disk2.exists(), "vm2 vhdx must survive vm1 shutdown");

    let exit = vm2
        .run(ProcessBuilder::new().shell("echo alive").build()?)
        .await?;
    assert!(exit.success(), "vm2 must still answer guest commands");

    vm2.shutdown().await?;

    assert!(!disk2.exists(), "ephemeral vm2 vhdx must be deleted");
    let networks = list_network_names()?;
    assert!(
        !networks.contains(&format!("jyth-nat-{uuid1}")),
        "no vm1 network may remain: {networks:?}"
    );
    assert!(
        !networks.contains(&format!("jyth-nat-{uuid2}")),
        "no vm2 network may remain: {networks:?}"
    );
    Ok(())
}

/// A crashed session's resources are recovered by the next launch while a
/// live session's locked resources are untouched; after the live holder is
/// killed, a fresh process recovers it exactly.
///
/// Post-run inspection: after this test there must be no `jyth-nat-*`
/// network, no child `*.redb` journal, and no `*-child.vhdx` file left in
/// the per-binary state dir.
#[tokio::test]
async fn recovers_crashed_session_while_live_holder_is_untouched() -> TestResult {
    #[cfg(feature = "tracing")]
    tracing::init();

    let _hcs_guard = hcs_test_guard().await?;
    let state = ensure_state_dir();

    let sleeping_marker = state.join("marker-sleeping.txt");
    let crashed_marker = state.join("marker-crashed.txt");
    let sleeping_vhdx = state.join("sleeping-child.vhdx");
    let crashed_vhdx = state.join("crashed-child.vhdx");
    // Stale markers from a previous run would satisfy the poll instantly,
    // and stale VHDX from a failed run would confuse the file assertions.
    for leftover in [
        &sleeping_marker,
        &crashed_marker,
        &sleeping_vhdx,
        &crashed_vhdx,
    ] {
        let _ = std::fs::remove_file(leftover);
    }

    // Build the fixture before spawning any child: the build cost must not
    // count against the ready-file deadline.
    fixture_binary();

    // Kernel/initrd for the children (they create a compute system, so the
    // materialized host paths must exist on disk).
    let (kernel, rootfs) = disk_image();
    let (kernel_path, initrd_path) = materialize_image(&kernel, &rootfs).await?;

    let (sleeping_subnet, crashed_subnet, _parent_subnet) = run_unique_subnets();

    let mut sleeping = spawn_fixture(
        "hold-lock",
        &[
            state.as_os_str().to_os_string(),
            kernel_path.as_os_str().to_os_string(),
            initrd_path.as_os_str().to_os_string(),
            OsString::from(sleeping_subnet),
            sleeping_vhdx.as_os_str().to_os_string(),
            sleeping_marker.as_os_str().to_os_string(),
        ],
    )?;
    let (sleeping_uuid, sleeping_db) =
        wait_for_ready(&sleeping_marker, Duration::from_secs(60)).await?;

    let mut crashed = spawn_fixture(
        "leave-resources",
        &[
            state.as_os_str().to_os_string(),
            kernel_path.as_os_str().to_os_string(),
            initrd_path.as_os_str().to_os_string(),
            OsString::from(crashed_subnet),
            crashed_vhdx.as_os_str().to_os_string(),
            crashed_marker.as_os_str().to_os_string(),
        ],
    )?;
    let (crashed_uuid, crashed_db) =
        wait_for_ready(&crashed_marker, Duration::from_secs(60)).await?;
    // Wait for the crashed child to actually exit so its redb writer lock is
    // released before the parent's recovery pass runs.
    let mut crashed_child = crashed.take().expect("crashed child handle");
    let crashed_status = crashed_child.wait().await?;
    assert!(
        crashed_status.success(),
        "crashed child must exit cleanly, got {crashed_status}"
    );

    // Deterministic lock-release wait BEFORE the parent's recovery pass (the
    // redesign's fix for the lock-release race): reconciliation runs once per
    // process, so it must not observe the crashed session as still locked.
    wait_for_unlocked(&state.join(&crashed_db), Duration::from_secs(15)).await?;

    let networks = list_network_names()?;
    assert!(
        networks.contains(&format!("jyth-nat-{crashed_uuid}")),
        "crashed child must have left its HNS network"
    );
    assert!(
        networks.contains(&format!("jyth-nat-{sleeping_uuid}")),
        "sleeping child must have left its HNS network"
    );
    assert!(
        state.join(&crashed_db).exists(),
        "crashed child journal must exist"
    );
    assert!(
        state.join(&sleeping_db).exists(),
        "sleeping child journal must exist"
    );
    assert!(crashed_vhdx.exists(), "crashed child vhdx must exist");
    assert!(sleeping_vhdx.exists(), "sleeping child vhdx must exist");

    // Opening a fresh session runs stale-session recovery: it must skip
    // the sleeping child's locked DB and recover the crashed child's exact
    // resources (compute system, HNS network, VHDX) and journal DB.
    trigger_recovery_and_close().await?;

    let networks = list_network_names()?;
    assert!(
        !networks.contains(&format!("jyth-nat-{crashed_uuid}")),
        "crashed network must be recovered: {networks:?}"
    );
    assert!(
        networks.contains(&format!("jyth-nat-{sleeping_uuid}")),
        "sleeping network must survive recovery: {networks:?}"
    );
    assert!(!crashed_vhdx.exists(), "crashed vhdx must be deleted");
    assert!(
        sleeping_vhdx.exists(),
        "sleeping vhdx must survive recovery"
    );
    assert!(
        !state.join(&crashed_db).exists(),
        "crashed journal DB must be removed"
    );
    assert!(
        state.join(&sleeping_db).exists(),
        "sleeping journal DB must survive recovery"
    );

    // Kill the live holder; its session becomes stale, but no session open
    // in this test recovers it (recovery runs per session open, and the
    // fixture process's own fresh session open does it next).
    let mut sleeping_child = sleeping.take().expect("sleeping child handle");
    sleeping_child.kill().await?;
    sleeping_child.wait().await?;
    wait_for_unlocked(&state.join(&sleeping_db), Duration::from_secs(15)).await?;

    // A fresh fixture process's fresh session open recovers the now-stale
    // sleeping session without touching anything else.
    let recovery = tokio::process::Command::new(fixture_binary())
        .args(["recover-and-exit"])
        .arg(state)
        .arg(&kernel_path)
        .arg(&initrd_path)
        .output()
        .await?;
    assert!(
        recovery.status.success(),
        "recovery fixture failed: {}",
        String::from_utf8_lossy(&recovery.stdout)
    );

    let networks = list_network_names()?;
    assert!(
        !networks.contains(&format!("jyth-nat-{sleeping_uuid}")),
        "sleeping network must be recovered after its owner is killed: {networks:?}"
    );
    assert!(!sleeping_vhdx.exists(), "sleeping vhdx must be deleted");
    assert!(
        !state.join(&sleeping_db).exists(),
        "sleeping journal DB must be removed"
    );

    Ok(())
}

/// The focused post-kill scenario, self-contained: a killed holder's session
/// is recovered exactly by a fresh fixture process.
///
/// Post-run inspection: after this test there must be no `jyth-nat-*`
/// network, no child `*.redb` journal, and no `holder-child.vhdx` file left
/// in the per-binary state dir.
#[tokio::test]
async fn killed_holder_session_is_recovered_by_a_fresh_process() -> TestResult {
    #[cfg(feature = "tracing")]
    tracing::init();

    let _hcs_guard = hcs_test_guard().await?;
    let state = ensure_state_dir();

    let holder_marker = state.join("marker-holder.txt");
    let holder_vhdx = state.join("holder-child.vhdx");
    // Stale marker/VHDX from a previous run would satisfy the poll instantly
    // and confuse the file assertions.
    let _ = std::fs::remove_file(&holder_marker);
    let _ = std::fs::remove_file(&holder_vhdx);

    // Build the fixture before spawning any child: the build cost must not
    // count against the ready-file deadline.
    fixture_binary();

    let (kernel, rootfs) = disk_image();
    let (kernel_path, initrd_path) = materialize_image(&kernel, &rootfs).await?;

    let (holder_subnet, _, _) = run_unique_subnets();

    let mut holder = spawn_fixture(
        "hold-lock",
        &[
            state.as_os_str().to_os_string(),
            kernel_path.as_os_str().to_os_string(),
            initrd_path.as_os_str().to_os_string(),
            OsString::from(holder_subnet),
            holder_vhdx.as_os_str().to_os_string(),
            holder_marker.as_os_str().to_os_string(),
        ],
    )?;
    let (holder_uuid, holder_db) =
        wait_for_ready(&holder_marker, Duration::from_secs(60)).await?;

    let networks = list_network_names()?;
    assert!(
        networks.contains(&format!("jyth-nat-{holder_uuid}")),
        "holder must have left its HNS network"
    );
    assert!(holder_vhdx.exists(), "holder vhdx must exist");
    assert!(state.join(&holder_db).exists(), "holder journal must exist");

    // Kill the live holder; its session becomes stale and only a fresh
    // process's session open will recover it.
    let mut holder_child = holder.take().expect("holder child handle");
    holder_child.kill().await?;
    holder_child.wait().await?;
    wait_for_unlocked(&state.join(&holder_db), Duration::from_secs(15)).await?;

    let recovery = tokio::process::Command::new(fixture_binary())
        .arg("recover-and-exit")
        .arg(state)
        .arg(&kernel_path)
        .arg(&initrd_path)
        .output()
        .await?;
    assert!(
        recovery.status.success(),
        "recovery fixture failed: {}",
        String::from_utf8_lossy(&recovery.stdout)
    );

    let networks = list_network_names()?;
    assert!(
        !networks.contains(&format!("jyth-nat-{holder_uuid}")),
        "holder network must be recovered: {networks:?}"
    );
    assert!(!holder_vhdx.exists(), "holder vhdx must be deleted");
    assert!(
        !state.join(&holder_db).exists(),
        "holder journal DB must be removed"
    );

    Ok(())
}