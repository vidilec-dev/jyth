//! Live HCS disk-lifecycle gates (impl/ImplPlan.md Phase 6, docs/TestE2E.md
//! "Runtime hardening live gates", Work package D).
//!
//! Scenarios:
//!
//! - `no_disk_creates_no_vhdx_or_empty_scratch_directory`: an empty disk
//!   list performs no disk operation and creates no VHDX.
//! - `ephemeral_disk_is_deleted`: a created ephemeral VHDX is deleted at
//!   shutdown.
//! - `persistent_disk_preserves_marker_across_launches`: a created
//!   persistent VHDX survives shutdown and preserves guest data across a
//!   second launch.
//! - `existing_ephemeral_request_is_retained_and_reported`: an ephemeral
//!   request landing on an existing path is reclassified to persistent and
//!   exposed as a structured `VmWarning::DiskReusedAsPersistent`.
//! - `existing_disk_is_not_formatted`: an existing disk keeps its content
//!   (never formatted) and stays writable.
//! - `failed_pre_ready_persistent_creation_rolls_back`: a launch that never
//!   reaches publication deletes the created persistent VHDX and HNS
//!   resources (rollback state, not caller-owned output).
//! - `disk_acl_targets_only_the_vm_identity`: the VHDX DACL carries the
//!   exact per-VM SID derived from the VM UUID.
//!
//! Post-run inspection: the per-binary state dir
//! (`%TEMP%\jyth-e2e\disk_lifecycle\`) must contain no `*.vhdx` after a
//! clean run (ephemeral files are deleted by shutdown, persistent fixtures
//! are removed explicitly at the end of the test that created them).

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use e2e_tests::{VmGuard, hcs_test_guard, linuxkit_image};
use jyth::builder::VmBuilder;
use jyth::vm::{CaptureOptions, Output, ProcessBuilder, VmWarning};
use jyth::{ApiError, VM};
use uuid::Uuid;

type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

/// Rootfs fixture for the disk tests. The stock `alpine` busybox build
/// ships no ext-family formatter, so a created disk would fail init with
/// `DiskFormatFailed` (correct product behavior, useless for the lifecycle
/// matrix); the official `busybox` image's default config includes
/// `mke2fs`/`mkfs.ext2`, `mount`, `sh`, `cat`, and `ip`, which the guest
/// format/mount and the test's `ProcessBuilder` commands need.
fn disk_image() -> (jyth::builder::image::Kernel, jyth::builder::image::Rootfs) {
    linuxkit_image("busybox:1.36.1")
}

/// The single per-binary state directory (see `runtime_isolation.rs` for
/// the reasoning; `JYTH_STATE_DIR` is read once per process). Stale session
/// databases are never swept: the next run's first launch reconciles them.
fn state_dir() -> &'static Path {
    static STATE_DIR: OnceLock<PathBuf> = OnceLock::new();
    STATE_DIR.get_or_init(|| {
        let dir = std::env::temp_dir().join("jyth-e2e").join("disk_lifecycle");
        std::fs::create_dir_all(&dir).expect("create per-binary state dir");
        dir
    })
}

fn ensure_state_dir() -> &'static Path {
    let dir = state_dir();
    // SAFETY: set before any HCS use; called from single-threaded test
    // setup (each test binary is one process, tests run serially).
    unsafe { std::env::set_var("JYTH_STATE_DIR", dir) };
    dir
}

/// A 64 MiB disk spec mounted at `/data`.
fn disk_spec(
    path: impl Into<PathBuf>,
    retention: vm_model::disk::DiskRetention,
    on_existing: vm_model::disk::ExistingDiskPolicy,
) -> vm_model::disk::DiskSpec {
    vm_model::disk::DiskSpec::new(
        path.into(),
        64,
        vm_model::disk::GuestMount::new("/data").expect("valid mount"),
        retention,
        on_existing,
    )
    .expect("valid disk spec")
}

fn ephemeral(path: impl Into<PathBuf>) -> vm_model::disk::DiskSpec {
    disk_spec(
        path,
        vm_model::disk::DiskRetention::Ephemeral,
        vm_model::disk::ExistingDiskPolicy::ReuseAndKeep,
    )
}

fn persistent(path: impl Into<PathBuf>) -> vm_model::disk::DiskSpec {
    disk_spec(
        path,
        vm_model::disk::DiskRetention::Persistent,
        vm_model::disk::ExistingDiskPolicy::ReuseAndKeep,
    )
}

/// Write `content` into a guest file on a mounted disk. The trailing
/// `sync` forces the ext2 pages out before shutdown: the guest is powered
/// off without a clean unmount, so without it the next launch can see an
/// empty (unwritten) filesystem.
async fn guest_write(
    vm: &VM,
    path: &str,
    content: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let process = ProcessBuilder::new()
        .shell(format!("printf '%s' '{}' > {} && sync", content, path))
        .build()?;
    let exit = vm.run(process).await?;
    assert!(exit.success(), "guest write to {path} failed: {exit}");
    Ok(())
}

/// Read a guest file on a mounted disk through a captured `cat`.
async fn guest_read(
    vm: &VM,
    path: &str,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let (observer, builder) = ProcessBuilder::with_observer();
    let process = builder
        .shell(format!("cat {}", path))
        .stdout(Output::Capture(CaptureOptions::default()))
        .build()?;
    let exit = vm.run(process).await?;
    assert!(exit.success(), "guest read of {path} failed: {exit}");
    let stdout = observer.stdout().await?;
    Ok(String::from_utf8_lossy(&stdout).trim().to_string())
}

/// Recursively collect every `*.vhdx` file under `root`.
fn vhdx_files(root: &Path) -> std::io::Result<Vec<PathBuf>> {
    let mut found = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if entry.file_type()?.is_dir() {
                stack.push(path);
            } else if path
                .extension()
                .is_some_and(|extension| extension.eq_ignore_ascii_case("vhdx"))
            {
                found.push(path);
            }
        }
    }
    Ok(found)
}

/// The `jyth-nat-*` HNS network names currently registered on the host.
fn list_network_names() -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
    let networks = hcs_admin::list_legacy_networks()?;
    Ok(networks
        .iter()
        .filter_map(|resource| resource.name.clone())
        .collect())
}

/// Derive the per-VM identity SID `S-1-5-83-1-<r1>-<r2>-<r3>-<r4>`: a
/// fixed identity RID `1` followed by the four little-endian u32 windows
/// of `vm_id.to_bytes_le()` (mirrors
/// `libs/hypervisor/src/hcs/security.rs::vm_identity_sid`, verified
/// against live per-VM accounts on a Hyper-V host).
fn vm_identity_sid(vm_id: Uuid) -> String {
    let bytes = vm_id.to_bytes_le();
    let rid = |start: usize| u32::from_le_bytes(bytes[start..start + 4].try_into().unwrap());
    format!("S-1-5-83-1-{}-{}-{}-{}", rid(0), rid(4), rid(8), rid(12))
}

/// An empty disk list must attach no disk and create no VHDX anywhere under
/// the state directory, before and after launch.
#[tokio::test]
async fn no_disk_creates_no_vhdx_or_empty_scratch_directory() -> TestResult {
    #[cfg(feature = "tracing")]
    tracing::init();

    let _hcs_guard = hcs_test_guard().await?;
    let state = ensure_state_dir();
    // Defensive purge of leftover VHDX from earlier tests in this binary so
    // the before/after scan reflects only this test's launch.
    for leftover in vhdx_files(state)? {
        let _ = std::fs::remove_file(leftover);
    }
    assert!(
        vhdx_files(state)?.is_empty(),
        "state dir must start without vhdx files"
    );

    let (kernel, rootfs) = disk_image();
    let mut vm = VmGuard::new(
        VmBuilder::new()
            .kernel(kernel)
            .rootfs(rootfs)
            .network(())
            .launch()
            .await?,
    );
    assert!(
        vm.attached_disks().is_empty(),
        "no disks requested -> no attached disks"
    );
    assert!(
        vhdx_files(state)?.is_empty(),
        "no disk list must create no vhdx file"
    );
    vm.shutdown().await?;
    assert!(
        vhdx_files(state)?.is_empty(),
        "no vhdx may appear after shutdown"
    );
    Ok(())
}

/// A created ephemeral VHDX is formatted in the guest, carries guest data,
/// and is deleted by shutdown.
#[tokio::test]
async fn ephemeral_disk_is_deleted() -> TestResult {
    #[cfg(feature = "tracing")]
    tracing::init();

    let _hcs_guard = hcs_test_guard().await?;
    let state = ensure_state_dir();
    let vhdx = state.join(format!("eph-{}.vhdx", Uuid::new_v4()));

    let (kernel, rootfs) = disk_image();
    let mut vm = VmGuard::new(
        VmBuilder::new()
            .kernel(kernel)
            .rootfs(rootfs)
            .disk(ephemeral(&vhdx))
            .network(())
            .launch()
            .await?,
    );
    let attached = &vm.attached_disks()[0];
    assert_eq!(attached.origin, vm_model::disk::DiskOrigin::CreatedByLaunch);
    assert_eq!(
        attached.requested_retention,
        vm_model::disk::DiskRetention::Ephemeral
    );
    assert_eq!(
        attached.effective_retention,
        vm_model::disk::DiskRetention::Ephemeral
    );
    assert!(
        vhdx.exists(),
        "created ephemeral vhdx must exist while alive"
    );

    guest_write(&vm, "/data/marker", "ephemeral").await?;
    assert_eq!(guest_read(&vm, "/data/marker").await?, "ephemeral");

    vm.shutdown().await?;
    assert!(!vhdx.exists(), "ephemeral vhdx must be deleted at shutdown");
    Ok(())
}

/// A created persistent VHDX survives shutdown and preserves guest data
/// across a second launch.
#[tokio::test]
async fn persistent_disk_preserves_marker_across_launches() -> TestResult {
    #[cfg(feature = "tracing")]
    tracing::init();

    let _hcs_guard = hcs_test_guard().await?;
    let state = ensure_state_dir();
    let vhdx = state.join(format!("persist-{}.vhdx", Uuid::new_v4()));

    let (kernel, rootfs) = disk_image();
    let mut vm1 = VmGuard::new(
        VmBuilder::new()
            .kernel(kernel)
            .rootfs(rootfs)
            .disk(persistent(&vhdx))
            .network(())
            .launch()
            .await?,
    );
    guest_write(&vm1, "/data/marker", "persist-1").await?;
    vm1.shutdown().await?;
    assert!(vhdx.exists(), "persistent vhdx must survive shutdown");

    let (kernel, rootfs) = disk_image();
    let mut vm2 = VmGuard::new(
        VmBuilder::new()
            .kernel(kernel)
            .rootfs(rootfs)
            .disk(persistent(&vhdx))
            .network(())
            .launch()
            .await?,
    );
    let attached = &vm2.attached_disks()[0];
    assert_eq!(
        attached.origin,
        vm_model::disk::DiskOrigin::PreExisting,
        "second launch must classify the disk as pre-existing"
    );
    assert_eq!(
        guest_read(&vm2, "/data/marker").await?,
        "persist-1",
        "marker must survive across launches"
    );
    vm2.shutdown().await?;
    assert!(
        vhdx.exists(),
        "persistent vhdx must survive the second shutdown"
    );

    std::fs::remove_file(&vhdx)?;
    Ok(())
}

/// An ephemeral request landing on an existing path is retained, visibly
/// reclassified to persistent, and reported through `VM::warnings()`.
#[tokio::test]
async fn existing_ephemeral_request_is_retained_and_reported() -> TestResult {
    #[cfg(feature = "tracing")]
    tracing::init();

    let _hcs_guard = hcs_test_guard().await?;
    let state = ensure_state_dir();
    let vhdx = state.join(format!("reuse-{}.vhdx", Uuid::new_v4()));

    let (kernel, rootfs) = disk_image();
    let mut vm1 = VmGuard::new(
        VmBuilder::new()
            .kernel(kernel)
            .rootfs(rootfs)
            .disk(persistent(&vhdx))
            .network(())
            .launch()
            .await?,
    );
    guest_write(&vm1, "/data/marker", "keep").await?;
    vm1.shutdown().await?;
    assert!(vhdx.exists(), "persistent fixture must survive shutdown");

    let (kernel, rootfs) = disk_image();
    let mut vm2 = VmGuard::new(
        VmBuilder::new()
            .kernel(kernel)
            .rootfs(rootfs)
            .disk(disk_spec(
                &vhdx,
                vm_model::disk::DiskRetention::Ephemeral,
                vm_model::disk::ExistingDiskPolicy::ReuseAndKeep,
            ))
            .network(())
            .launch()
            .await?,
    );
    let attached = &vm2.attached_disks()[0];
    assert_eq!(attached.origin, vm_model::disk::DiskOrigin::PreExisting);
    assert_eq!(
        attached.requested_retention,
        vm_model::disk::DiskRetention::Ephemeral
    );
    assert_eq!(
        attached.effective_retention,
        vm_model::disk::DiskRetention::Persistent,
        "existing path must be reclassified to persistent"
    );
    assert_eq!(
        vm2.warnings().len(),
        1,
        "reuse must be reported as a structured warning"
    );
    match &vm2.warnings()[0] {
        VmWarning::DiskReusedAsPersistent {
            host_path,
            requested,
            effective,
        } => {
            assert_eq!(host_path, &vhdx);
            assert_eq!(*requested, vm_model::disk::DiskRetention::Ephemeral);
            assert_eq!(*effective, vm_model::disk::DiskRetention::Persistent);
        }
    }
    assert_eq!(
        guest_read(&vm2, "/data/marker").await?,
        "keep",
        "a reused disk must never be formatted"
    );
    vm2.shutdown().await?;
    assert!(vhdx.exists(), "a reused disk must be retained at shutdown");

    std::fs::remove_file(&vhdx)?;
    Ok(())
}

/// An existing disk is mounted without formatting: its content survives the
/// second launch and stays writable.
#[tokio::test]
async fn existing_disk_is_not_formatted() -> TestResult {
    #[cfg(feature = "tracing")]
    tracing::init();

    let _hcs_guard = hcs_test_guard().await?;
    let state = ensure_state_dir();
    let vhdx = state.join(format!("noformat-{}.vhdx", Uuid::new_v4()));

    let (kernel, rootfs) = disk_image();
    let mut vm1 = VmGuard::new(
        VmBuilder::new()
            .kernel(kernel)
            .rootfs(rootfs)
            .disk(persistent(&vhdx))
            .network(())
            .launch()
            .await?,
    );
    guest_write(&vm1, "/data/marker", "first").await?;
    vm1.shutdown().await?;

    let (kernel, rootfs) = disk_image();
    let mut vm2 = VmGuard::new(
        VmBuilder::new()
            .kernel(kernel)
            .rootfs(rootfs)
            .disk(persistent(&vhdx))
            .network(())
            .launch()
            .await?,
    );
    assert_eq!(
        guest_read(&vm2, "/data/marker").await?,
        "first",
        "existing disk content must survive (never formatted)"
    );
    guest_write(&vm2, "/data/marker", "second").await?;
    assert_eq!(
        guest_read(&vm2, "/data/marker").await?,
        "second",
        "existing disk must stay writable"
    );
    vm2.shutdown().await?;
    assert!(vhdx.exists(), "existing disk must be retained at shutdown");

    std::fs::remove_file(&vhdx)?;
    Ok(())
}

/// A persistent disk created by a launch that never reaches READY is
/// rollback state: the failed launch deletes the unpublished VHDX and its
/// HNS resources.
#[tokio::test]
async fn failed_pre_ready_persistent_creation_rolls_back() -> TestResult {
    #[cfg(feature = "tracing")]
    tracing::init();

    let _hcs_guard = hcs_test_guard().await?;
    let state = ensure_state_dir();
    let vhdx = state.join(format!("rollback-{}.vhdx", Uuid::new_v4()));
    let networks_before = list_network_names()?;

    // Deterministic pre-READY trigger: the guest mounts proc/sys/dev before
    // applying disks (libs/init/src/main.rs), so a disk whose guest mount
    // path lies under /proc (validation only reserves the exact "/proc"
    // target) makes the guest's `mkdir -p` fail with EROFS
    // (libs/init/src/ops/disks.rs), which is fatal before READY. The
    // host's provisioning rollback must then remove the created persistent
    // VHDX (published == false) and the HNS network.
    let mount = vm_model::disk::GuestMount::new("/proc/jyth-rollback-trigger")
        .expect("valid mount trigger");
    let spec = vm_model::disk::DiskSpec::new(
        &vhdx,
        64,
        mount,
        vm_model::disk::DiskRetention::Persistent,
        vm_model::disk::ExistingDiskPolicy::ReuseAndKeep,
    )
    .expect("valid rollback disk spec");

    let (kernel, rootfs) = disk_image();
    let result = VmBuilder::new()
        .kernel(kernel)
        .rootfs(rootfs)
        .network(())
        .disk(spec)
        .launch()
        .await;

    let error = match result {
        Ok(_) => panic!("launch must fail before READY"),
        Err(error) => error,
    };
    assert!(
        matches!(
            error.current_context(),
            ApiError::ReadyTimeout | ApiError::Guest { .. } | ApiError::VmCreate
        ),
        "unexpected launch error: {error}"
    );

    assert!(
        !vhdx.exists(),
        "rollback must delete the unpublished created persistent vhdx"
    );
    let networks_after = list_network_names()?;
    assert_eq!(
        networks_after, networks_before,
        "rollback must remove the failed launch's HNS network"
    );
    Ok(())
}

/// While the VM is alive, the VHDX DACL carries the exact per-VM identity
/// SID derived from the VM UUID; shutdown deletes the file and with it the
/// ACE.
#[tokio::test]
async fn disk_acl_targets_only_the_vm_identity() -> TestResult {
    #[cfg(feature = "tracing")]
    tracing::init();

    let _hcs_guard = hcs_test_guard().await?;
    let state = ensure_state_dir();
    let vhdx = state.join(format!("acl-{}.vhdx", Uuid::new_v4()));

    let (kernel, rootfs) = disk_image();
    let mut vm = VmGuard::new(
        VmBuilder::new()
            .kernel(kernel)
            .rootfs(rootfs)
            .disk(ephemeral(&vhdx))
            .network(())
            .launch()
            .await?,
    );
    let vm_sid = vm_identity_sid(vm.uuid());

    let output = tokio::process::Command::new("icacls")
        .arg(&vhdx)
        .output()
        .await?;
    assert!(
        output.status.success(),
        "icacls failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    // The per-VM identity appears in the DACL as the raw SID (hosts that
    // cannot resolve the account) or as its account name `NT VIRTUAL
    // MACHINE\<vm-guid>` (icacls resolves the SID once the compute system
    // exists — verified on this host). Either form proves the exact-VM ACE.
    let vm_account = format!(
        "NT VIRTUAL MACHINE\\{}",
        vm.uuid().to_string().to_uppercase()
    );
    assert!(
        stdout.contains(&vm_sid) || stdout.contains(&vm_account),
        "icacls must show the exact per-VM identity ACE ({vm_sid} / {vm_account}); got:\n{stdout}"
    );

    vm.shutdown().await?;
    assert!(!vhdx.exists(), "ephemeral vhdx must be deleted at shutdown");
    Ok(())
}
