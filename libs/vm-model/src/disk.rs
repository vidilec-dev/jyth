//! Public disk configuration surface for the `vm-model` crate.
//!
//! A small, OS-agnostic data-only description that threads through the
//! backend contracts and the jyth `VmBuilder::disk` API without leaking any
//! host-side (HCS/KVM) types upward. There is no disk without a path: every
//! disk is described by a validated absolute host path, an optional creation
//! size, and a validated guest mount target.
//!
//! Lifecycle responsibilities for the chosen backend:
//!
//! 1. **Before** the VM starts: materialize the host-side backing file
//!    (e.g. a sparse VHDX on HCS) at the exact configured path and
//!    reference it from the VM config so the hypervisor attaches it as a
//!    guest block device.
//! 2. **After** the VM stops (best-effort on `Drop`): remove the
//!    lifecycle-owned file only when it was created by this launch, its
//!    Windows file identity still matches the journal, and it is still
//!    deletable (ephemeral, or created by a launch that never reached
//!    publication). Pre-existing files are never deleted or formatted.
//!
//! The guest init is responsible for formatting (`initialize = true`,
//! created files only) and mounting each disk at
//! [`GuestMount`]; production launches pass that path in
//! the validated COM1 boot configuration.

use std::fmt;
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};

use crate::path::normalize_lexically;

/// How the host treats the disk at cleanup time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(target_os = "windows", derive(serde::Serialize, serde::Deserialize))]
pub enum DiskRetention {
    /// The file is deleted after cleanup when it was created by this launch.
    Ephemeral,
    /// The file is retained after a successfully published launch.
    Persistent,
}

/// What to do when the configured host path already exists at launch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExistingDiskPolicy {
    /// Validate and attach the existing file without formatting; an
    /// ephemeral request is visibly reclassified as persistent.
    ReuseAndKeep,
    /// Fail the launch before any compute system is created.
    Error,
}

/// Where the host-side file came from; used by cleanup decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(target_os = "windows", derive(serde::Serialize, serde::Deserialize))]
pub enum DiskOrigin {
    /// The file was created by this launch and carries the full ownership
    /// proof (recorded identity, init request, temporary ACE).
    CreatedByLaunch,
    /// The file existed before this launch and must never be deleted or
    /// formatted.
    PreExisting,
}

/// A validated absolute Linux mount path inside the guest.
///
/// Construction rejects relative paths, `.`/`..` components, NUL,
/// whitespace, comma, colon, and control characters, the reserved targets
/// `/`, `/proc`, `/sys`, `/dev`, `/run`, and every Jyth-reserved path
/// (anything at or below `/jyth`, which the builder uses for materialized
/// executables). Duplicate mount targets within one VM are rejected by the
/// builder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestMount {
    path: String,
}

/// Jyth-reserved guest paths that a disk must never mount over.
const RESERVED_GUEST_MOUNT_PATHS: &[&str] = &["/", "/proc", "/sys", "/dev", "/run", "/jyth"];

impl GuestMount {
    /// Validate `path` and wrap it. The path must be an absolute Linux
    /// mount target (see the type documentation for the rejection list).
    pub fn new(path: impl Into<String>) -> Result<Self, DiskError> {
        let path = path.into();
        if path.is_empty() {
            return Err(DiskError::MountPathEmpty);
        }
        if !path.starts_with('/') {
            return Err(DiskError::MountPathRelative);
        }
        if RESERVED_GUEST_MOUNT_PATHS.contains(&path.as_str()) || path.starts_with("/jyth/") {
            return Err(DiskError::MountPathReserved);
        }
        // Validate the raw string segments: `Path::components` collapses
        // `.`/`..`/empty segments, which would let them slip through.
        for (index, segment) in path.split('/').enumerate() {
            if index == 0 && segment.is_empty() {
                continue; // the leading root prefix
            }
            if segment.is_empty() || segment == "." || segment == ".." {
                return Err(DiskError::MountPathDotComponent);
            }
        }
        if path
            .chars()
            .any(|ch| ch == '\0' || ch.is_whitespace() || ch == ',' || ch == ':' || ch.is_control())
        {
            return Err(DiskError::MountPathContainsInvalidCharacter);
        }
        Ok(Self { path })
    }

    /// Borrow the validated mount path.
    pub fn as_str(&self) -> &str {
        &self.path
    }
}

impl fmt::Display for GuestMount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.path)
    }
}

/// A validated request for one guest disk.
///
/// `host_path` must be absolute with a `.vhdx` extension; `create_size_mb`
/// is used only when the file is absent (an existing VHDX keeps its actual
/// size and is never resized implicitly); `guest_mount` must pass
/// [`GuestMount::new`] validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiskSpec {
    host_path: PathBuf,
    create_size_mb: NonZeroU64,
    guest_mount: GuestMount,
    retention: DiskRetention,
    on_existing: ExistingDiskPolicy,
}

impl DiskSpec {
    /// Construct and validate a disk specification.
    pub fn new(
        host_path: impl Into<PathBuf>,
        create_size_mb: u64,
        guest_mount: GuestMount,
        retention: DiskRetention,
        on_existing: ExistingDiskPolicy,
    ) -> Result<Self, DiskError> {
        let host_path = host_path.into();
        if !host_path.is_absolute() {
            return Err(DiskError::HostPathRelative);
        }
        let extension = host_path
            .extension()
            .and_then(|extension| extension.to_str())
            .unwrap_or_default();
        if !extension.eq_ignore_ascii_case("vhdx") {
            return Err(DiskError::HostPathNotVhdx);
        }
        if host_path.to_string_lossy().contains('\0') {
            return Err(DiskError::HostPathContainsNul);
        }
        // Reject paths whose `..` components escape above the root: the
        // shared lexical normalizer would fail on them, and `normalized_host_path`
        // is an infallible public API, so the rejection happens at
        // construction.
        if normalize_lexically(&host_path).is_err() {
            return Err(DiskError::HostPathAboveRoot);
        }
        let create_size_mb = NonZeroU64::new(create_size_mb).ok_or(DiskError::SizeZero)?;
        Ok(Self {
            host_path,
            create_size_mb,
            guest_mount,
            retention,
            on_existing,
        })
    }

    /// The absolute host-side path of the backing file.
    pub fn host_path(&self) -> &Path {
        &self.host_path
    }

    /// The creation size in megabytes, used only when the file is absent.
    pub fn create_size_mb(&self) -> NonZeroU64 {
        self.create_size_mb
    }

    /// The validated guest mount target.
    pub fn guest_mount(&self) -> &GuestMount {
        &self.guest_mount
    }

    /// The requested retention for the backing file.
    pub fn retention(&self) -> DiskRetention {
        self.retention
    }

    /// The selected behavior when the host path already exists.
    pub fn on_existing(&self) -> ExistingDiskPolicy {
        self.on_existing
    }

    /// Lexically normalize the host path without following a final reparse
    /// point (the file may not exist yet). Used to reject duplicate paths
    /// in one builder and to derive the per-path lock identity. Infallible
    /// because `DiskSpec::new` rejects relative and above-root paths, and
    /// the fallback returns the raw absolute path rather than fabricating a
    /// wrong one.
    pub fn normalized_host_path(&self) -> PathBuf {
        normalize_lexically(&self.host_path).unwrap_or_else(|_| self.host_path.clone())
    }
}

/// A disk attached to a running VM with its classified lifecycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachedDisk {
    /// Absolute host-side path of the backing file.
    pub host_path: PathBuf,
    /// Validated guest mount target.
    pub guest_mount: String,
    /// Whether the file was created by this launch or existed before it.
    pub origin: DiskOrigin,
    /// The retention the caller requested.
    pub requested_retention: DiskRetention,
    /// The retention the backend actually applied (an existing path is
    /// never deleted, so an ephemeral request on an existing file is
    /// reclassified to [`DiskRetention::Persistent`]).
    pub effective_retention: DiskRetention,
}

/// A disk specification or mount validation failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiskError {
    /// The host path is not absolute.
    HostPathRelative,
    /// The host path does not end in `.vhdx`.
    HostPathNotVhdx,
    /// The host path contains a NUL byte.
    HostPathContainsNul,
    /// The host path's `..` components escape above the root (e.g.
    /// `C:\..\disks\disk.vhdx` would otherwise silently become
    /// drive-relative).
    HostPathAboveRoot,
    /// The creation size is zero.
    SizeZero,
    /// The mount path is empty.
    MountPathEmpty,
    /// The mount path is not absolute.
    MountPathRelative,
    /// The mount path contains a `.` or `..` component.
    MountPathDotComponent,
    /// The mount path contains a NUL, whitespace, comma, colon, or control
    /// character.
    MountPathContainsInvalidCharacter,
    /// The mount path is a reserved Jyth or system target.
    MountPathReserved,
}

impl fmt::Display for DiskError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            DiskError::HostPathRelative => "disk host path must be absolute",
            DiskError::HostPathNotVhdx => "disk host path must end in .vhdx",
            DiskError::HostPathContainsNul => "disk host path must not contain a NUL byte",
            DiskError::HostPathAboveRoot => {
                "disk host path must not escape above the root (no '..' past the drive root)"
            }
            DiskError::SizeZero => "disk creation size must be greater than zero",
            DiskError::MountPathEmpty => "guest mount path must not be empty",
            DiskError::MountPathRelative => "guest mount path must be absolute",
            DiskError::MountPathDotComponent => {
                "guest mount path must not contain '.' or '..' components"
            }
            DiskError::MountPathContainsInvalidCharacter => {
                "guest mount path must not contain NUL, whitespace, comma, colon, or control characters"
            }
            DiskError::MountPathReserved => "guest mount path is a reserved system or Jyth target",
        };
        f.write_str(message)
    }
}

impl std::error::Error for DiskError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_mount(path: &str) -> GuestMount {
        GuestMount::new(path).expect("valid mount")
    }

    fn spec(host_path: &str, size_mb: u64, mount: &str) -> Result<DiskSpec, DiskError> {
        DiskSpec::new(
            host_path,
            size_mb,
            valid_mount(mount),
            DiskRetention::Ephemeral,
            ExistingDiskPolicy::ReuseAndKeep,
        )
    }

    #[test]
    fn guest_mount_accepts_a_valid_absolute_path() {
        let mount = GuestMount::new("/build").expect("valid mount");
        assert_eq!(mount.as_str(), "/build");
        assert_eq!(mount.to_string(), "/build");
        assert_eq!(mount, GuestMount::new("/build").expect("same mount"));
        assert_ne!(mount, GuestMount::new("/scratch").expect("other mount"));
    }

    #[test]
    fn guest_mount_rejects_empty_and_relative_paths() {
        assert_eq!(GuestMount::new("").unwrap_err(), DiskError::MountPathEmpty);
        assert_eq!(
            GuestMount::new("build").unwrap_err(),
            DiskError::MountPathRelative
        );
    }

    #[test]
    fn guest_mount_rejects_dot_components() {
        assert_eq!(
            GuestMount::new("/build/.").unwrap_err(),
            DiskError::MountPathDotComponent
        );
        assert_eq!(
            GuestMount::new("/build/../build").unwrap_err(),
            DiskError::MountPathDotComponent
        );
        assert_eq!(
            GuestMount::new("/..").unwrap_err(),
            DiskError::MountPathDotComponent
        );
        assert_eq!(
            GuestMount::new("/build//").unwrap_err(),
            DiskError::MountPathDotComponent
        );
        assert_eq!(
            GuestMount::new("/build/").unwrap_err(),
            DiskError::MountPathDotComponent
        );
    }

    #[test]
    fn guest_mount_rejects_invalid_characters() {
        for path in [
            "/build\x00x",
            "/build with space",
            "/build\t",
            "/build\n",
            "/build,scratch",
            "/build:alt",
            "/build\x07",
        ] {
            assert_eq!(
                GuestMount::new(path).unwrap_err(),
                DiskError::MountPathContainsInvalidCharacter,
                "path {path:?} must be rejected"
            );
        }
    }

    #[test]
    fn guest_mount_rejects_reserved_targets() {
        for path in ["/", "/proc", "/sys", "/dev", "/run", "/jyth", "/jyth/x"] {
            assert_eq!(
                GuestMount::new(path).unwrap_err(),
                DiskError::MountPathReserved,
                "path {path:?} must be rejected"
            );
        }
        assert!(
            GuestMount::new("/jythx").is_ok(),
            "only /jyth itself and its subtree are reserved"
        );
    }

    #[test]
    fn disk_spec_validates_host_path() {
        assert_eq!(
            spec("relative/disk.vhdx", 1024, "/build").unwrap_err(),
            DiskError::HostPathRelative
        );
        assert_eq!(
            spec(r"C:\disks\disk.txt", 1024, "/build").unwrap_err(),
            DiskError::HostPathNotVhdx
        );
        assert_eq!(
            spec(r"C:\disks\disk.vhdx", 0, "/build").unwrap_err(),
            DiskError::SizeZero
        );
        assert!(
            spec(r"C:\disks\disk.VHDX", 1024, "/build").is_ok(),
            "extension check is case-insensitive"
        );
    }

    #[test]
    fn disk_spec_rejects_over_root_host_paths() {
        // `C:\..\disks\disk.vhdx` must fail closed: the old normalizer
        // turned it into the drive-relative `C:disks\disk.vhdx`, silently
        // resolved against the current directory of drive C.
        assert_eq!(
            spec(r"C:\..\disks\disk.vhdx", 1024, "/build").unwrap_err(),
            DiskError::HostPathAboveRoot,
            "over-root host paths must be rejected at construction"
        );
        assert_eq!(
            spec(r"C:\disks\..\..\disk.vhdx", 1024, "/build").unwrap_err(),
            DiskError::HostPathAboveRoot
        );
        // UNC roots are protected the same way.
        assert!(spec(r"\\server\share\disks\disk.vhdx", 1024, "/build").is_ok());
        assert_eq!(
            spec(r"\\server\share\..\..\disk.vhdx", 1024, "/build").unwrap_err(),
            DiskError::HostPathAboveRoot
        );
        // A `..` that cancels a real component stays legal.
        assert!(
            spec(r"C:\disks\..\disks\disk.vhdx", 1024, "/build").is_ok(),
            ".. cancelling a real component is not above the root"
        );
    }

    #[test]
    fn disk_spec_normalized_host_path_detects_duplicates() {
        let first = spec(r"C:\disks\..\disks\build.vhdx", 1024, "/build").expect("first spec");
        let second = spec(r"C:\disks\build.vhdx", 1024, "/build").expect("second spec");
        assert_eq!(
            first.normalized_host_path(),
            second.normalized_host_path(),
            "lexical normalization must make the same file comparable"
        );
        let other = spec(r"C:\disks\other.vhdx", 1024, "/build").expect("other spec");
        assert_ne!(first.normalized_host_path(), other.normalized_host_path());
    }

    #[test]
    fn disk_spec_retains_all_fields() {
        let mount = valid_mount("/data");
        let disk = DiskSpec::new(
            r"C:\disks\data.vhdx",
            4096,
            mount.clone(),
            DiskRetention::Persistent,
            ExistingDiskPolicy::Error,
        )
        .expect("valid spec");
        assert_eq!(disk.host_path(), Path::new(r"C:\disks\data.vhdx"));
        assert_eq!(disk.create_size_mb().get(), 4096);
        assert_eq!(disk.guest_mount(), &mount);
        assert_eq!(disk.retention(), DiskRetention::Persistent);
        assert_eq!(disk.on_existing(), ExistingDiskPolicy::Error);
    }
}
