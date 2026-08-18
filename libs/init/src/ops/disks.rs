//! Mount the host-attached disks the HCS backend exposed as guest block
//! devices. Production launches pass each device index, validated mount
//! path, and `initialize` flag through the authenticated COM1 boot
//! configuration; the legacy `jyth.scratch=` cmdline parser survives only
//! as a TEST-ONLY adapter for focused unit tests. The HCS backend surfaces
//! devices as `/dev/sd<letter>` (sda, sdb, ...), matching the configured
//! indices.
//!
//! Semantics:
//!
//! - `initialize = true` (created-by-launch disks only): format with the
//!   supported ext-family tool, then mount.
//! - `initialize = false` (pre-existing disks): mount only; a failed
//!   existing-disk mount NEVER falls back to formatting.
//! - A missing device, a formatting failure, or a mount failure is a
//!   LAUNCH FAILURE that prevents READY: it propagates as a fatal
//!   `InitError` and the host launch aborts instead of continuing with a
//!   silently missing disk.
//!
//! There is deliberately no vfat fallback: vfat does not support symlinks,
//! which Linux build workloads (e.g. a kernel source tree) rely on. When no
//! supported ext-family formatter exists for a new disk, the init makes one
//! best-effort `apk add e2fsprogs` provisioning attempt (the boot network is
//! already up at this point) and retries the ladder once; if no formatter
//! still exists, initialization fails with a clear error.

use crate::errors::{InitError, InitResult};

#[cfg(target_os = "linux")]
use error_stack::Report;

/// PATH used for spawned `mkfs`/`mount`/`mkdir` so busybox applets
/// resolve despite `/init` being launched with no `PATH`. Same value
/// as `crate::ops::bring_up_net::SPAWN_PATH`; defined separately so
/// each module's sleeps/spawns stay self-contained.
#[cfg(target_os = "linux")]
const SPAWN_PATH: &str = "/sbin:/bin:/usr/sbin:/usr/bin";

/// One disk mount instruction after device mapping.
#[derive(Clone, Debug, PartialEq, Eq)]
struct MountEntry {
    device: String,
    mount: String,
    initialize: bool,
}

/// Apply the typed disk instructions received over the authenticated COM1
/// boot exchange. Missing devices, formatting failures, and mount failures
/// are fatal: they prevent READY by aborting the guest boot.
pub(crate) fn mount_disks_with_config(disks: &[protocol::GuestDiskConfigV1]) -> InitResult<()> {
    #[cfg(target_os = "linux")]
    {
        let entries: Vec<MountEntry> = disks
            .iter()
            .map(|disk| MountEntry {
                device: scsi_device_name(usize::from(disk.device_index)),
                mount: disk.mount_path.clone(),
                initialize: disk.initialize,
            })
            .collect();
        return apply_disks(&entries);
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = disks;
        Ok(())
    }
}

/// Map a 0-based index to its `/dev/sdX` name. Index 0 -> /dev/sda, 1 ->
/// /dev/sdb, ..., 25 -> /dev/sdz, 26 -> /dev/sdaa, 27 -> /dev/sdab, ...
/// mirroring the kernel's `sd` block-major naming. Saturates at
/// `/dev/sdzz` (i.e. never returns `/dev/sd...` with more than two letters)
/// which is well past any realistic disk count.
///
/// Returns the full `/dev/sdX` path (not just `sdX`) because the callers
/// feed the result straight to `Path::new(device).exists()` polling and
/// to `mkfs`/`mount` argv — a bare `sdX` would be resolved relative to
/// the init's cwd (which is `/`, so the lookup would try to stat a file
/// literally named `sda` at `/`), and `mkfs.ext2 sdX` would fail with
/// "no such file" instead of formatting the block device. The tests at
/// `scsi_device_name_double_letters_start_at_26` pin this contract.
#[cfg(target_os = "linux")]
fn scsi_device_name(idx: usize) -> String {
    // The kernel's sd driver names devices sd[a-z], sd[aa-az], sd[ba-bz],
    // ... — base-26 with no leading-zero padding, biased by `'a'`.
    let mut name = String::from("/dev/sd");
    let mut n = idx;
    loop {
        name.push(char::from(b'a' + (n % 26) as u8));
        n /= 26;
        if n == 0 {
            break;
        }
        n -= 1; // base-26 with no zero digit
    }
    name
}

/// Apply a validated disk plan with fatal semantics.
#[cfg(target_os = "linux")]
fn apply_disks(entries: &[MountEntry]) -> InitResult<()> {
    for disk in entries {
        // Wait briefly for the block device node to appear. The HCS
        // backend attaches the VHDX synchronously at VM start, but the
        // guest's sd driver registers `/dev/sdX` asynchronously from the
        // device probe — same race the NIC bringup handles for
        // `/sys/class/net/eth0`. devtmpfs auto-creates the node on probe
        // completion, so polling the node existence is the ready signal.
        // A missing device is a fatal launch failure, not a skip.
        if !wait_for_dev(&disk.device, std::time::Duration::from_secs(10)) {
            return Err(Report::new(InitError::DiskDeviceMissing).attach(format!(
                "device {} never appeared in /dev within 10s",
                disk.device
            )));
        }
        // Create the mount point UNCONDITIONALLY before any format/mount
        // attempt so a mount-point ENOENT can never be misread as a missing
        // binary. If the mount succeeds below, the directory is shadowed by
        // the mountpoint.
        run_fatal(
            "mkdir",
            &["-p", &disk.mount],
            "create mount point",
            InitError::Io,
        )?;

        if disk.initialize {
            format_disk(&disk.device)?;
        }
        run_fatal(
            "mount",
            &[&disk.device, &disk.mount],
            "mount disk",
            InitError::DiskMountFailed,
        )?;
    }
    Ok(())
}

/// Format a created disk with the supported ext-family tool ladder. ext4
/// is preferred; busybox `mke2fs`/`mkfs.ext2` used to cover the stock
/// alpine rootfs (which shipped the applets compiled into busybox even
/// without symlinks), but current alpine builds no longer include the
/// applet, so when the ladder exhausts the init provisions `e2fsprogs`
/// once and retries. There is NO vfat fallback: vfat cannot represent the
/// symlinks Linux build workloads rely on. If no formatter succeeds, the
/// launch fails with a clear init error.
#[cfg(target_os = "linux")]
fn format_disk(device: &str) -> InitResult<()> {
    format_disk_with(device, run_ok, provision_formatter)
}

/// Best-effort guest-side formatter provisioning. The boot network is
/// already up when disks are applied (`bring_up_net` runs before
/// `mount_disks` in `main.rs`), so a fresh `alpine` rootfs can install
/// `e2fsprogs` and retry the ladder. `apk update` is attempted first
/// (log-only) because the stock alpine image does not ship a usable
/// package index; a failed `apk add` still falls through to the fatal
/// no-formatter error.
#[cfg(target_os = "linux")]
fn provision_formatter() -> bool {
    let _ = run_ok("apk", &["update"]);
    run_ok("apk", &["add", "e2fsprogs"])
}

/// Formatting ladder with injectable probe and provisioner (unit-testable
/// on hosts without the tooling).
#[cfg(target_os = "linux")]
fn format_disk_with(
    device: &str,
    mut probe: impl FnMut(&str, &[&str]) -> bool,
    mut provision: impl FnMut() -> bool,
) -> InitResult<()> {
    let attempts: &[(&str, &[&str])] = &[
        ("mkfs.ext4", &[]),
        ("mkfs.ext2", &[]),
        ("mke2fs", &["-t", "ext2"]),
        ("busybox", &["mke2fs", "-t", "ext2"]),
        ("busybox", &["mkfs.ext2"]),
    ];
    let mut provisioned = false;
    loop {
        for (cmd, sub) in attempts {
            let mut argv: Vec<&str> = vec![cmd];
            argv.extend_from_slice(sub);
            argv.push(device);
            if probe(cmd, &argv[1..]) {
                return Ok(());
            }
        }
        // Ladder exhausted: one best-effort provisioning attempt, then a
        // single retry. A failed provisioning is not fatal by itself; the
        // retry ladder decides (still failing -> DiskFormatFailed below).
        if !provisioned && provision() {
            provisioned = true;
            continue;
        }
        break;
    }
    Err(Report::new(InitError::DiskFormatFailed).attach(format!(
        "no supported ext-family formatter (mkfs.ext4 / mkfs.ext2 / mke2fs) found for {}",
        device
    )))
}

/// Poll `/dev/<name>` once every 100ms until the device node exists
/// (the kernel has registered the block device), or `deadline`
/// elapses. Mirrors `crate::ops::bring_up_net::wait_for_iface`.
#[cfg(target_os = "linux")]
fn wait_for_dev(device: &str, deadline: std::time::Duration) -> bool {
    let path = std::path::Path::new(device);
    let started = std::time::Instant::now();
    let poll = std::time::Duration::from_millis(100);
    loop {
        if path.exists() {
            #[cfg(feature = "tracing")]
            tracing::info!(
                device,
                waited_ms = started.elapsed().as_millis() as u64,
                "[init] disk block device registered in /dev; proceeding with format/mount",
            );
            return true;
        }
        if started.elapsed() >= deadline {
            return false;
        }
        std::thread::sleep(poll);
    }
}

/// Run a command; `true` on success, `false` on failure (logged at WARN).
/// Used by the formatting ladder, where a missing formatter just means
/// "try the next one".
#[cfg(target_os = "linux")]
fn run_ok(cmd: &str, args: &[&str]) -> bool {
    match std::process::Command::new(cmd)
        .args(args)
        .env("PATH", SPAWN_PATH)
        .status()
    {
        Ok(s) if s.success() => true,
        Ok(_s) => {
            #[cfg(feature = "tracing")]
            tracing::warn!(%cmd, ?args, code = %_s, "[init] disk command exited non-zero");
            false
        }
        Err(_e) => {
            #[cfg(feature = "tracing")]
            tracing::warn!(%cmd, ?args, error = %_e, "[init] disk command not found / spawn failed");
            false
        }
    }
}

/// Run a required command; a failure is a typed, fatal init error that
/// prevents READY.
#[cfg(target_os = "linux")]
fn run_fatal(cmd: &str, args: &[&str], what: &str, on_failure: InitError) -> InitResult<()> {
    match std::process::Command::new(cmd)
        .args(args)
        .env("PATH", SPAWN_PATH)
        .status()
    {
        Ok(s) if s.success() => Ok(()),
        Ok(s) => Err(Report::new(on_failure).attach(format!("{what}: {cmd} exited with {s}"))),
        Err(e) => Err(Report::new(on_failure).attach(format!("{what}: {cmd} spawn failed: {e}"))),
    }
}

/// Legacy `jyth.scratch=` cmdline parser. TEST-ONLY adapter: production
/// launches carry disk instructions exclusively through the typed COM1
/// boot configuration, so this parser exists only to exercise the device
/// mapping and apply logic in unit tests.
#[cfg(all(target_os = "linux", test))]
mod legacy_cmdline {
    use super::MountEntry;
    use crate::errors::{InitError, InitResult};
    use error_stack::Report;

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub(crate) struct ScratchPlan {
        pub disks: Vec<MountEntry>,
    }

    impl ScratchPlan {
        /// Parse the plan out of a kernel cmdline string. Returns `Ok(None)`
        /// when no `jyth.scratch=` arg was present (no scratch requested);
        /// `Err` only on a malformed `jyth.scratch=` arg (the caller's
        /// intent was clear, so we don't silently skip a disk).
        pub(crate) fn parse(cmdline: &str) -> InitResult<Option<Self>> {
            let mut raw: Option<String> = None;
            for arg in cmdline.split_whitespace() {
                if let Some(v) = arg.strip_prefix("jyth.scratch=") {
                    raw = Some(v.to_string());
                }
            }
            let Some(raw) = raw else {
                return Ok(None);
            };

            let mut disks = Vec::new();
            for (idx, entry) in raw.split(',').enumerate() {
                let (idx_str, mount) = entry.split_once(':').ok_or_else(|| {
                    Report::new(InitError::UnsupportedHost)
                        .attach(format!("jyth.scratch entry {entry:?} is not <idx>:<mount>",))
                })?;
                let parsed_idx: usize = idx_str.parse().map_err(|e: std::num::ParseIntError| {
                    Report::new(InitError::UnsupportedHost)
                        .attach(e.to_string())
                        .attach(format!("jyth.scratch index {idx_str:?} not a usize"))
                })?;
                if parsed_idx != idx {
                    return Err(Report::new(InitError::UnsupportedHost).attach(format!(
                        "jyth.scratch entries out of order at position {idx}: got idx {parsed_idx}",
                    )));
                }
                if mount.is_empty() || !mount.starts_with('/') {
                    return Err(Report::new(InitError::UnsupportedHost).attach(format!(
                        "jyth.scratch mount {mount:?} must be an absolute guest path",
                    )));
                }
                disks.push(MountEntry {
                    device: super::scsi_device_name(idx),
                    mount: mount.to_string(),
                    initialize: true,
                });
            }
            if disks.is_empty() {
                return Err(Report::new(InitError::UnsupportedHost)
                    .attach("jyth.scratch= present but empty (no disks after parsing)"));
            }
            Ok(Some(Self { disks }))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    use crate::errors::InitError;

    /// The legacy parser is a test-only adapter pinned by these tests; the
    /// production path consumes the typed COM1 boot configuration.
    #[cfg(target_os = "linux")]
    #[test]
    fn parses_scratch_kernel_args() {
        let cmdline = "root=/dev/vda1 init=/init jyth.backend=hcs \
                       jyth.scratch=0:/build,1:/scratch/console=ttyS0";
        let plan = legacy_cmdline::ScratchPlan::parse(cmdline).expect("parse ok");
        let plan = plan.expect("Some(plan) when jyth.scratch present");
        assert_eq!(plan.disks.len(), 2);
        assert_eq!(plan.disks[0].device, "/dev/sda");
        assert_eq!(plan.disks[0].mount, "/build");
        assert_eq!(plan.disks[1].device, "/dev/sdb");
        assert_eq!(plan.disks[1].mount, "/scratch");
    }

    /// No scratch requested (no `jyth.scratch=`): `Ok(None)`.
    #[cfg(target_os = "linux")]
    #[test]
    fn parses_scratch_kernel_args_zero_disks() {
        let cmdline = "root=/dev/vda1 init=/init jyth.backend=kvm console=ttyS0";
        assert!(
            legacy_cmdline::ScratchPlan::parse(cmdline)
                .unwrap()
                .is_none()
        );
    }

    /// Bad index (not a usize): typed error.
    #[cfg(target_os = "linux")]
    #[test]
    fn parses_scratch_kernel_args_bad_index() {
        let cmdline = "jyth.scratch=abc:/build";
        assert!(legacy_cmdline::ScratchPlan::parse(cmdline).is_err());
    }

    /// Out-of-order index: typed error.
    #[cfg(target_os = "linux")]
    #[test]
    fn parses_scratch_kernel_args_out_of_order() {
        let cmdline = "jyth.scratch=1:/build";
        assert!(legacy_cmdline::ScratchPlan::parse(cmdline).is_err());
    }

    /// Relative mount path: typed error.
    #[cfg(target_os = "linux")]
    #[test]
    fn parses_scratch_kernel_args_relative_mount() {
        let cmdline = "jyth.scratch=0:build";
        assert!(legacy_cmdline::ScratchPlan::parse(cmdline).is_err());
    }

    /// Empty `jyth.scratch=`: typed error.
    #[cfg(target_os = "linux")]
    #[test]
    fn parses_scratch_kernel_args_empty() {
        let cmdline = "jyth.scratch=";
        assert!(legacy_cmdline::ScratchPlan::parse(cmdline).is_err());
    }

    /// `jyth.scratch=0:/build,1:/scratch,2:/foo,3:/bar,4:/baz` maps to
    /// sda, sdb, sdc, sdd, sde. Sanity-checks the device-name mapping
    /// covers up to a handful of disks.
    #[cfg(target_os = "linux")]
    #[test]
    fn parses_scratch_kernel_args_many_disks() {
        let cmdline = "jyth.scratch=0:/build,1:/a,2:/b,3:/c,4:/d";
        let plan = legacy_cmdline::ScratchPlan::parse(cmdline).expect("parse ok");
        let plan = plan.expect("Some(plan)");
        assert_eq!(plan.disks[0].device, "/dev/sda");
        assert_eq!(plan.disks[1].device, "/dev/sdb");
        assert_eq!(plan.disks[2].device, "/dev/sdc");
        assert_eq!(plan.disks[3].device, "/dev/sdd");
        assert_eq!(plan.disks[4].device, "/dev/sde");
    }

    /// `scsi_device_name` follows the kernel's base-26-with-no-zero
    /// scheme: 0..=25 -> a..z, 26 -> aa, 27 -> ab, ... 51 -> az, 52 ->
    /// ba. Without the post-divide `-1`, index 26 would round-trip to
    /// `ba` (the wrong name) — this test pins that the double-letter
    /// onset is at 26.
    #[cfg(target_os = "linux")]
    #[test]
    fn scsi_device_name_double_letters_start_at_26() {
        assert_eq!(scsi_device_name(0), "/dev/sda");
        assert_eq!(scsi_device_name(25), "/dev/sdz");
        assert_eq!(scsi_device_name(26), "/dev/sdaa");
        assert_eq!(scsi_device_name(27), "/dev/sdab");
        assert_eq!(scsi_device_name(51), "/dev/sdaz");
        assert_eq!(scsi_device_name(52), "/dev/sdba");
    }

    /// The formatting ladder accepts the first supported formatter and
    /// never consults vfat; a first-pass success never provisions.
    #[cfg(target_os = "linux")]
    #[test]
    fn format_ladder_prefers_ext4_and_never_uses_vfat() {
        let calls = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorded = calls.clone();
        let provisions = std::sync::Arc::new(std::sync::Mutex::new(0usize));
        let provision_calls = provisions.clone();
        let probe = move |cmd: &str, args: &[&str]| {
            recorded.lock().unwrap().push((
                cmd.to_string(),
                args.iter()
                    .map(|arg| (*arg).to_string())
                    .collect::<Vec<_>>(),
            ));
            cmd == "mkfs.ext4"
        };
        format_disk_with("/dev/sda", probe, move || {
            *provision_calls.lock().unwrap() += 1;
            false
        })
        .expect("mkfs.ext4 formats");
        assert_eq!(calls.lock().unwrap().len(), 1);
        assert_eq!(
            *provisions.lock().unwrap(),
            0,
            "no provisioning on first-pass success"
        );

        // When only busybox mke2fs succeeds, the earlier attempts fail and
        // the ladder continues.
        let calls = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorded = calls.clone();
        let provisions = std::sync::Arc::new(std::sync::Mutex::new(0usize));
        let provision_calls = provisions.clone();
        let probe = move |cmd: &str, args: &[&str]| {
            recorded.lock().unwrap().push((
                cmd.to_string(),
                args.iter()
                    .map(|arg| (*arg).to_string())
                    .collect::<Vec<_>>(),
            ));
            cmd == "busybox" && args == ["mke2fs", "-t", "ext2"]
        };
        format_disk_with("/dev/sda", probe, move || {
            *provision_calls.lock().unwrap() += 1;
            false
        })
        .expect("busybox mke2fs formats");
        assert_eq!(calls.lock().unwrap().len(), 4);
        assert_eq!(
            *provisions.lock().unwrap(),
            0,
            "no provisioning on first-pass success"
        );

        // No ext-family formatter ever succeeds, and vfat is not consulted.
        let probe = |_cmd: &str, _args: &[&str]| false;
        let error =
            format_disk_with("/dev/sda", probe, || false).expect_err("no formatter must fail");
        assert_eq!(*error.current_context(), InitError::DiskFormatFailed);
        let probe = |cmd: &str, _args: &[&str]| cmd == "mkfs.vfat";
        let error =
            format_disk_with("/dev/sda", probe, || false).expect_err("vfat alone must not format");
        assert_eq!(*error.current_context(), InitError::DiskFormatFailed);
    }

    /// When the first ladder pass exhausts, exactly one provisioning
    /// attempt happens and the retry ladder can then succeed.
    #[cfg(target_os = "linux")]
    #[test]
    fn exhausted_ladder_provisions_once_and_retries() {
        let calls = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorded = calls.clone();
        let provisions = std::sync::Arc::new(std::sync::Mutex::new(0usize));
        let provision_calls = provisions.clone();
        let probe = move |cmd: &str, args: &[&str]| {
            recorded.lock().unwrap().push((
                cmd.to_string(),
                args.iter()
                    .map(|arg| (*arg).to_string())
                    .collect::<Vec<_>>(),
            ));
            // First pass: everything fails (current alpine busybox ships no
            // mke2fs applet). Second pass: e2fsprogs made mkfs.ext4 appear.
            cmd == "mkfs.ext4" && recorded.lock().unwrap().len() > 5
        };
        format_disk_with("/dev/sda", probe, move || {
            *provision_calls.lock().unwrap() += 1;
            true
        })
        .expect("provisioning then retry formats");
        assert_eq!(*provisions.lock().unwrap(), 1, "provisioned exactly once");
        assert_eq!(
            calls.lock().unwrap().len(),
            6,
            "5 failed probes + 1 retry success"
        );
    }

    /// A failed provisioning attempt does not loop: the retry ladder still
    /// fails and the typed fatal error is preserved.
    #[cfg(target_os = "linux")]
    #[test]
    fn failed_provisioning_keeps_fatal_semantics() {
        let calls = std::sync::Arc::new(std::sync::Mutex::new(0usize));
        let probe_calls = calls.clone();
        let provisions = std::sync::Arc::new(std::sync::Mutex::new(0usize));
        let provision_calls = provisions.clone();
        let probe = move |_cmd: &str, _args: &[&str]| {
            *probe_calls.lock().unwrap() += 1;
            false
        };
        let error = format_disk_with("/dev/sda", probe, move || {
            *provision_calls.lock().unwrap() += 1;
            false
        })
        .expect_err("no formatter must fail");
        assert_eq!(*error.current_context(), InitError::DiskFormatFailed);
        assert_eq!(*provisions.lock().unwrap(), 1, "one provisioning attempt");
        assert_eq!(*calls.lock().unwrap(), 5, "retry ladder ran once more");
    }

    /// A required command that cannot even spawn is a fatal typed error.
    #[cfg(target_os = "linux")]
    #[test]
    fn required_command_failure_is_fatal() {
        let error = run_fatal(
            "definitely-not-a-real-command-xyz",
            &["/build"],
            "mount disk",
            InitError::DiskMountFailed,
        )
        .expect_err("missing command must fail");
        assert_eq!(*error.current_context(), InitError::DiskMountFailed);
    }
}
