//! The Jyth `KernelCompiler` adapter: builds custom kernels inside a
//! bootstrap VM.
//!
//! The adapter owns bootstrap VM construction, guest build execution,
//! artifact transfer, and ordered shutdown, and implements the
//! [`kernel::KernelCompiler`] port so the `kernel` crate stays unaware of VM
//! implementation details.
//!
//! # Bootstrap plan
//!
//! - boot [`kernel::Kernel::default()`] as the bootstrap kernel;
//! - boot the Jyth kernel-toolchain rootfs pinned by an immutable OCI
//!   manifest digest (the complete package set is baked into the image; no
//!   runtime package installation happens);
//! - request the lifecycle-owned NAT network (the guest needs it for the
//!   kernel.org source download);
//! - attach one unique generated build VHDX (a `jyth-kernel-build-<uuid>.vhdx`
//!   file created per compilation under the build-disk root) at `/build` with
//!   explicit size, retention, and existing-disk policy;
//! - inject the reusable build script and the canonical configuration into
//!   fixed guest paths;
//! - run the build process with the exact [`KernelVersion`], the pinned
//!   source URL, and the expected SHA-256 digest arguments;
//! - transfer the built bzImage to a host staging file;
//! - shut the bootstrap VM down through the ordered cleanup path.
//!
//! The adapter never publishes a partial output: the staged host file is
//! handed to the kernel service, which validates it by content and publishes
//! it only under the custom request digest.
//!
//! # Recursion invariant
//!
//! A custom target build invokes the Jyth compiler exactly once after a cache
//! miss. The compiler's bootstrap `VmBuilder` uses [`Kernel::default()`]
//! rather than `Kernel::custom`, so the bootstrap materialization path lowers
//! to an external OCI plan and never invokes the compiler again.
//!
//! # Responsibility (SolidArchitecturePlan target catalog)
//!
//! **Owner**: jyth.
//!
//! **Responsibility**: compiler adapter for the custom-kernel port.
//!
//! **Allowed dependencies**: kernel, rootfs, boot-image, jyth-runtime,
//! guest-client, vm-model, hypervisor, com (enforced by
//! `tests/architecture`).
//!
//! **Forbidden concepts**: scheduling algorithms, HCS journaling, image-index
//! transactions, frame codecs, guest process internals.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;

use error_stack::Report;

use kernel::compiler::{
    CompiledKernel, KernelCompiler, KernelCompilerError, KernelCompilerIdentity,
};
use kernel::{CustomKernelSpec, Kernel};

use crate::builder::file::File;
use crate::builder::permissions::Permissions;
use crate::builder::{BootstrapSpec, Cpu, Memory, VmBuilder};
use crate::{DiskRetention, DiskSpec, ExistingDiskPolicy, GuestMount};

/// Recipe version of this compiler adapter. Bump when the bootstrap plan,
/// the build script, or the deterministic Kbuild metadata changes so old
/// identities can never satisfy new cache keys.
const RECIPE_VERSION: u32 = 2;

/// The pinned Jyth kernel-toolchain rootfs (immutable manifest digest on the
/// Jyth GHCR repository). The image contains every package required by
/// `build_kernel.sh`; the build script verifies that every required tool
/// already exists in this rootfs instead of relying on a mutable package
/// repository. Publication is automated by
/// `.github/workflows/publish-toolchain.yml`: each rebuild pushes a new
/// immutable manifest to `ghcr.io/vidilec-dev/jyth/kernel-toolchain` and
/// opens a reviewed PR that records the new digest here. The manifest digest
/// is the immutable identity; the tag is never used at runtime.
pub const TOOLCHAIN_ROOTFS_OCI: &str = "http://ksmc-quartz.local:5000/jyth/kernel-toolchain@sha256:3ef3b703f40e3c669ea1ed7557344470f6f05921e7a48b9243da121ff5449f7f";

/// Guest path of the injected reusable build script.
pub const BUILD_SCRIPT_GUEST_PATH: &str = "/usr/local/bin/build-kernel.sh";
/// Guest path of the injected canonical configuration.
pub const CONFIG_GUEST_PATH: &str = "/.config.host";
/// Guest path of the fixed bzImage artifact produced by the build script.
pub const BUILT_KERNEL_GUEST_PATH: &str = "/build/artifacts/bzImage";
/// Guest mount point of the attached build VHDX.
pub const BUILD_DISK_MOUNT: &str = "/build";
/// File-name prefix of one generated build VHDX; the lease appends a
/// per-compilation UUID so no two compilations share a path.
const BUILD_DISK_FILE_PREFIX: &str = "jyth-kernel-build-";
/// Default size of the build VHDX in MiB.
pub const BUILD_DISK_SIZE_MIB: u64 = 16 * 1024;
/// The bootstrap VM receives this many vCPUs. Kernel compilation is
/// parallelized with one job per vCPU (the guest uses `-j$(nproc)`), so the
/// count directly scales the dominant build phase; the host's logical
/// processor count bounds the useful maximum.
pub const BOOTSTRAP_CPUS: u32 = 8;
/// The bootstrap VM receives this much memory in MiB. Sized for parallel
/// `cc1` processes at [`BOOTSTRAP_CPUS`] jobs plus the uncompressed initrd.
/// The value must stay well below the host's available memory: HCS fails
/// the VM start with "Insufficient system resources" when the reservation
/// cannot be satisfied, and the jyth test host has proven that 6 GiB
/// reservations already fail under memory pressure (0x800705AA).
pub const BOOTSTRAP_MEMORY_MIB: u64 = 5120;
/// The guest build and the bzImage transfer share the authenticated COM1
/// exchange; a cold kernel build can consume this budget before the serial
/// transfer even starts.
pub const BOOTSTRAP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(90 * 60);

/// The reusable in-guest kernel build script, shipped as a repository asset
/// consumed by the compiler adapter and the CLI tests.
pub const BUILD_KERNEL_SH: &[u8] = include_bytes!("../../assets/kernel-build/build_kernel.sh");

/// Deterministic Kbuild metadata for reproducible builds.
const KBUILD_METADATA: &str = "KBUILD_BUILD_TIMESTAMP=1970-01-01 KBUILD_BUILD_USER=jyth KBUILD_BUILD_HOST=jyth KBUILD_BUILD_VERSION=1 SOURCE_DATE_EPOCH=0";

/// The Jyth `KernelCompiler` adapter.
#[derive(Debug)]
pub struct JythKernelCompiler {
    identity: KernelCompilerIdentity,
    /// Host root directory under which each compilation generates one unique
    /// build VHDX path. Production callers pass `std::env::temp_dir()`.
    disk_root: PathBuf,
}
impl JythKernelCompiler {
    /// Construct the adapter over a caller-selected build-disk root. The
    /// generated build-disk path is created per compilation inside
    /// [`JythKernelCompiler::compile`]; this constructor performs no
    /// filesystem I/O.
    pub fn new(disk_root: impl Into<PathBuf>) -> Result<Self, KernelCompilerError> {
        let identity = KernelCompilerIdentity::new(
            RECIPE_VERSION,
            script_digest(),
            kernel::DEFAULT_KERNEL_OCI_REFERENCE
                .split('@')
                .nth(1)
                .unwrap_or(
                    "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                ),
            TOOLCHAIN_ROOTFS_OCI.split('@').nth(1).unwrap_or(
                "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            ),
            std::env::consts::ARCH,
            KBUILD_METADATA,
        )?;
        Ok(Self {
            identity,
            disk_root: disk_root.into(),
        })
    }

    /// Assemble the bootstrap plan without launching HCS. Unit tests use this
    /// to verify the plan without a Hyper-V host. The generated build-disk
    /// path is passed explicitly; the plan never reads a disk path from the
    /// compiler.
    fn bootstrap_builder(
        &self,
        spec: &CustomKernelSpec,
        build_disk: &Path,
    ) -> Result<VmBuilder, Report<KernelCompilerError>> {
        let mut builder = VmBuilder::new()
            // Recursion invariant: the bootstrap kernel is the default
            // external OCI plan, never a custom specification.
            .kernel(Kernel::default())
            .rootfs(crate::builder::image::Rootfs::new(
                crate::builder::image::Link::image(TOOLCHAIN_ROOTFS_OCI),
            ))
            .cpu(Cpu::Units(BOOTSTRAP_CPUS))
            .mem(Memory::MB(BOOTSTRAP_MEMORY_MIB))
            .network(())
            .disk(
                DiskSpec::new(
                    build_disk.to_path_buf(),
                    BUILD_DISK_SIZE_MIB,
                    GuestMount::new(BUILD_DISK_MOUNT).expect("valid guest mount"),
                    DiskRetention::Ephemeral,
                    ExistingDiskPolicy::Error,
                )
                .map_err(|error| {
                    Report::new(KernelCompilerError::BuildDisk)
                        .attach(error)
                        .attach(format!(
                            "generated build-disk path: {}",
                            build_disk.display()
                        ))
                })?,
            )
            .add_file(
                File::new()
                    .path(BUILD_SCRIPT_GUEST_PATH)
                    .content(BUILD_KERNEL_SH)
                    .permissions(Permissions::ALL),
            );
        // A complete configuration is applied directly; the default fragment
        // is already embedded in the build script.
        if spec.config().mode() == kernel::KernelConfigMode::Complete {
            builder = builder.add_file(
                File::new()
                    .path(CONFIG_GUEST_PATH)
                    .content(spec.config().as_bytes())
                    .permissions(Permissions::READ | Permissions::WRITE),
            );
        }
        Ok(builder)
    }
    /// The guest build-process arguments: the injected script path, the exact
    /// version, the pinned source URL, and the expected SHA-256 digest, plus
    /// the configuration path for complete configurations. The build script
    /// validates every argument and verifies the source digest before
    /// extraction.
    fn bootstrap_args(&self, spec: &CustomKernelSpec) -> Vec<String> {
        let sha256_hex = match spec.source().digest() {
            image_core::digest::ExpectedDigest::Sha256(bytes) => {
                let mut hex = String::with_capacity(64);
                for byte in bytes {
                    hex.push_str(&format!("{byte:02x}"));
                }
                hex
            }
            _ => {
                // The kernel facade only constructs SHA-256 pins; a different
                // digest cannot reach the compiler.
                unreachable!("custom kernel source pins are always SHA-256")
            }
        };
        let mut args = vec![
            BUILD_SCRIPT_GUEST_PATH.to_owned(),
            spec.version().as_str().to_owned(),
            spec.source().url().as_str().to_owned(),
            sha256_hex,
        ];
        if spec.config().mode() == kernel::KernelConfigMode::Complete {
            args.push(CONFIG_GUEST_PATH.to_owned());
        }
        args
    }
}

impl KernelCompiler for JythKernelCompiler {
    fn identity(&self) -> &KernelCompilerIdentity {
        &self.identity
    }

    fn compile<'a>(
        &'a self,
        spec: &'a CustomKernelSpec,
    ) -> Pin<
        Box<dyn Future<Output = Result<CompiledKernel, Report<KernelCompilerError>>> + Send + 'a>,
    > {
        Box::pin(async move { self.compile_inner(spec).await })
    }
}

impl JythKernelCompiler {
    async fn compile_inner(
        &self,
        spec: &CustomKernelSpec,
    ) -> Result<CompiledKernel, Report<KernelCompilerError>> {
        // One generated build-disk path per compilation: the lease rejects an
        // existing generated path before any VM is created and owns residual
        // cleanup after the bootstrap VM close completes.
        let mut lease = BuildDiskLease::new(&self.disk_root)?;
        #[cfg(feature = "tracing")]
        tracing::debug!(
            disk = %lease.path().file_name().unwrap_or_default().to_string_lossy(),
            "generated a unique build-disk path"
        );

        // Plan: the bootstrap VM, injected files, and the exact version,
        // source URL, and expected SHA-256 arguments. The build script
        // validates every argument and verifies the source digest before
        // extraction; the canonical KernelVersion is already validated.
        let builder = self.bootstrap_builder(spec, lease.path())?;
        let build_args = self.bootstrap_args(spec);

        // Stage the transferred artifact in a host temporary file; the
        // CompiledKernel owns and removes it unless the service publishes it.
        let staging_dir = std::env::temp_dir();
        let staging = staging_dir.join(format!("jyth-compiled-{}.bzImage", uuid::Uuid::now_v7()));

        let bootstrap = BootstrapSpec::new("/bin/sh", BUILT_KERNEL_GUEST_PATH, staging.clone())
            .args(build_args)
            .timeout(BOOTSTRAP_TIMEOUT);

        // The lease outlives the bootstrap VM cleanup (the close future runs
        // inside launch_com1_bootstrap) and removes a residual regular file
        // only after that close completes.
        let result = builder.launch_com1_bootstrap(bootstrap).await;
        match result {
            Ok(_timings) => {
                #[cfg(feature = "tracing")]
                tracing::info!("custom kernel bootstrap completed; transferring bzImage");
                // A successful compilation must not leak a build disk; a
                // cleanup failure is reported as KernelCompilerError::Cleanup.
                lease.finish()?;
            }
            Err(error) => {
                let _ = std::fs::remove_file(&staging);
                let detail = format!("{error:?}");
                #[cfg(feature = "tracing")]
                tracing::error!(chain = %detail, "bootstrap VM launch failed");
                let mut report = Report::new(KernelCompilerError::BootstrapLaunch).attach(detail);
                // A cleanup failure stays attached to the primary bootstrap
                // failure; it never replaces it.
                if let Err(cleanup) = lease.finish() {
                    #[cfg(feature = "tracing")]
                    tracing::error!(chain = %format!("{cleanup:?}"), "build-disk cleanup failed");
                    report = report.attach(cleanup);
                }
                return Err(report);
            }
        }

        let metadata = std::fs::metadata(&staging).map_err(|error| {
            let _ = std::fs::remove_file(&staging);
            Report::new(KernelCompilerError::ArtifactTransfer).attach(error)
        })?;
        if metadata.len() == 0 {
            let _ = std::fs::remove_file(&staging);
            return Err(
                Report::new(KernelCompilerError::Validation).attach("transferred bzImage is empty")
            );
        }

        CompiledKernel::new(staging).map_err(|error| Report::new(error))
    }
}

/// One generated build-disk path under a caller-selected root, owned for the
/// duration of one compilation.
///
/// The lease owns the lifecycle of the generated `jyth-kernel-build-<uuid>.vhdx`
/// path: it rejects an existing generated path before any VM is created, and
/// after the bootstrap VM close completes it verifies that backend cleanup
/// removed the generated file, removing a residual regular file only. A
/// residual directory or reparse point is rejected and never traversed.
#[derive(Debug)]
struct BuildDiskLease {
    root: PathBuf,
    path: PathBuf,
    finished: bool,
}

impl BuildDiskLease {
    /// Generate `jyth-kernel-build-<uuid>.vhdx` under the absolute existing
    /// directory `root`, rejecting an existing generated path.
    fn new(root: impl Into<PathBuf>) -> Result<Self, Report<KernelCompilerError>> {
        let root = root.into();
        if !root.is_absolute() {
            return Err(Report::new(KernelCompilerError::BuildDisk).attach(format!(
                "build-disk root must be absolute: {}",
                root.display()
            )));
        }
        if !root.is_dir() {
            return Err(Report::new(KernelCompilerError::BuildDisk).attach(format!(
                "build-disk root must be an existing directory: {}",
                root.display()
            )));
        }
        Self::new_named(
            root,
            format!("{BUILD_DISK_FILE_PREFIX}{}.vhdx", uuid::Uuid::now_v7()),
        )
    }

    /// The deterministic path-generation seam: [`BuildDiskLease::new`] picks a
    /// fresh UUID name, tests pass a fixed name to prove the existing-path
    /// rejection.
    fn new_named(root: PathBuf, name: String) -> Result<Self, Report<KernelCompilerError>> {
        // The name is a plain file name: the lease must never traverse
        // outside `root`.
        if name.is_empty()
            || name == "."
            || name == ".."
            || name.contains('/')
            || name.contains('\\')
        {
            return Err(Report::new(KernelCompilerError::BuildDisk)
                .attach("generated build-disk file name must be a plain file name"));
        }
        let path = root.join(&name);
        match std::fs::symlink_metadata(&path) {
            Ok(_) => Err(Report::new(KernelCompilerError::BuildDisk).attach(format!(
                "generated build-disk path already exists: {}",
                path.display()
            ))),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Self {
                root,
                path,
                finished: false,
            }),
            Err(error) => Err(Report::new(KernelCompilerError::BuildDisk)
                .attach(error)
                .attach(format!(
                    "failed to validate the generated build-disk path: {}",
                    path.display()
                ))),
        }
    }

    /// The generated build-disk path.
    fn path(&self) -> &Path {
        &self.path
    }

    /// Verify that backend cleanup removed the generated file and remove a
    /// residual regular file. A residual directory or reparse point is
    /// rejected and never deleted.
    fn finish(&mut self) -> Result<(), Report<KernelCompilerError>> {
        if self.finished {
            return Ok(());
        }
        let residual = match std::fs::symlink_metadata(&self.path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                // Backend cleanup already removed the generated file.
                self.finished = true;
                return Ok(());
            }
            Err(error) => {
                return Err(
                    self.cleanup_report(error, "failed to inspect the generated build-disk path")
                );
            }
        };
        if residual.file_type().is_file() {
            if !self.path_is_under_root() {
                return Err(self.cleanup_report(
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "residual path is outside the build-disk root",
                    ),
                    "refusing to remove a path outside the build-disk root",
                ));
            }
            if let Err(error) = std::fs::remove_file(&self.path) {
                return Err(
                    self.cleanup_report(error, "failed to remove the residual build-disk file")
                );
            }
            self.finished = true;
            Ok(())
        } else {
            Err(Report::new(KernelCompilerError::Cleanup).attach(format!(
                "residual build-disk path is not a regular file and will not be removed: {} ({:?})",
                self.path.display(),
                residual.file_type(),
            )))
        }
    }

    /// The lease only ever touches `root.join(<plain file name>)`; this is
    /// the ownership validation that deletion never escapes the root.
    fn path_is_under_root(&self) -> bool {
        self.path.parent() == Some(self.root.as_path())
    }

    fn cleanup_report(&self, error: std::io::Error, what: &str) -> Report<KernelCompilerError> {
        Report::new(KernelCompilerError::Cleanup)
            .attach(error)
            .attach(what.to_string())
            .attach(self.path.display().to_string())
    }
}

impl Drop for BuildDiskLease {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        // Bounded best-effort cleanup: remove a residual regular file only,
        // never a directory or reparse point, and never traverse outside
        // `root`.
        let Ok(metadata) = std::fs::symlink_metadata(&self.path) else {
            return;
        };
        if !metadata.file_type().is_file() || !self.path_is_under_root() {
            return;
        }
        if let Err(_error) = std::fs::remove_file(&self.path) {
            #[cfg(feature = "tracing")]
            tracing::warn!(
                chain = %format!("{_error:?}"),
                path = %self.path.display(),
                "best-effort build-disk cleanup failed"
            );
        }
    }
}

/// The SHA-256 digest of the reusable build script, part of the compiler
/// identity.
fn script_digest() -> String {
    use sha2::{Digest as _, Sha256};
    let hash = Sha256::digest(BUILD_KERNEL_SH);
    let mut hex = String::with_capacity(64);
    for byte in hash {
        hex.push_str(&format!("{byte:02x}"));
    }
    format!("sha256:{hex}")
}
#[cfg(test)]
mod tests {
    use super::*;
    use kernel::KernelConfig;

    fn spec(version: &str) -> CustomKernelSpec {
        CustomKernelSpec::new(version).expect("spec")
    }

    /// An isolated build-disk root per test, so no test ever touches the
    /// production temp directory or collides with another test.
    fn isolated_root() -> tempfile::TempDir {
        tempfile::tempdir().expect("isolated temp root")
    }

    /// One lease under `root`, mirroring the production `compile_inner` flow.
    fn lease_in(root: &Path) -> BuildDiskLease {
        BuildDiskLease::new(root).expect("lease")
    }

    /// F-01 contract: two compiler invocations attach different generated
    /// build-disk paths, so two custom requests can never attach, modify, or
    /// clean up the same writable VHDX concurrently.
    #[test]
    fn two_compiler_instances_generate_unique_build_disk_paths() {
        let root = isolated_root();
        let first = JythKernelCompiler::new(root.path()).expect("compiler");
        let second = JythKernelCompiler::new(root.path()).expect("compiler");
        // Each invocation generates its own lease inside the shared root.
        let first_lease = lease_in(root.path());
        let second_lease = lease_in(root.path());
        assert_ne!(
            first_lease.path(),
            second_lease.path(),
            "each compilation must own a distinct generated path"
        );

        let first_builder = first
            .bootstrap_builder(&spec("7.1.7"), first_lease.path())
            .expect("first plan");
        let second_builder = second
            .bootstrap_builder(&spec("7.1.7"), second_lease.path())
            .expect("second plan");

        let first_disk = &first_builder.disks_ref()[0];
        let second_disk = &second_builder.disks_ref()[0];
        assert_ne!(
            first_disk.normalized_host_path(),
            second_disk.normalized_host_path(),
            "two compiler invocations must never attach the same writable build disk"
        );
        assert_eq!(first_disk.host_path(), first_lease.path());
        assert_eq!(second_disk.host_path(), second_lease.path());
    }

    /// F-02 regression: the cacheable build script installs packages at
    /// runtime and resolves `latest` from the network, so one request digest
    /// can represent different toolchains or source bytes. The cacheable
    /// build must perform no package installation and no mutable version
    /// resolution.
    #[test]
    fn build_script_performs_no_runtime_package_installation_or_latest_resolution() {
        let script = std::str::from_utf8(BUILD_KERNEL_SH).expect("embedded script is UTF-8");
        assert!(
            !script.contains("apk add"),
            "the cacheable build must not install packages at runtime"
        );
        assert!(
            !script.contains("finger_banner"),
            "the cacheable build must not resolve latest from the network"
        );
    }

    #[test]
    fn identity_is_stable_and_available_without_io() {
        let root = isolated_root();
        let compiler = JythKernelCompiler::new(root.path()).expect("compiler");
        let identity = compiler.identity();
        assert_eq!(identity.recipe_version(), RECIPE_VERSION);
        assert_eq!(identity.target_arch(), std::env::consts::ARCH);
        // The identity must be derivable without any network or filesystem
        // I/O: constructing it never touches the build-disk root.
        let again = JythKernelCompiler::new(root.path()).expect("compiler");
        assert_eq!(identity, again.identity());
    }

    #[test]
    fn bootstrap_plan_uses_the_default_kernel_and_pinned_rootfs() {
        let root = isolated_root();
        let compiler = JythKernelCompiler::new(root.path()).expect("compiler");
        let lease = lease_in(root.path());
        // Plan assembly must not require a live host or HCS.
        let _builder = compiler
            .bootstrap_builder(&spec("7.1.7"), lease.path())
            .expect("plan");
        // The toolchain is the Jyth-owned image pinned by OCI manifest digest
        // (plan variation: explicit http scheme for the plain-HTTP LAN
        // registry; the digest is the immutable identity).
        assert!(TOOLCHAIN_ROOTFS_OCI.contains("@sha256:"));
        assert!(TOOLCHAIN_ROOTFS_OCI.contains("/jyth/kernel-toolchain@"));
        assert!(kernel::DEFAULT_KERNEL_OCI_REFERENCE.contains("@sha256:"));
    }

    #[test]
    fn bootstrap_arguments_carry_version_url_and_expected_digest() {
        let root = isolated_root();
        let compiler = JythKernelCompiler::new(root.path()).expect("compiler");
        let spec = spec("7.1.7");
        let args = compiler.bootstrap_args(&spec);
        assert_eq!(args.len(), 4, "version, url, sha256, then optional config");
        assert_eq!(args[0], BUILD_SCRIPT_GUEST_PATH);
        assert_eq!(args[1], "7.1.7");
        assert_eq!(
            args[2],
            "https://cdn.kernel.org/pub/linux/kernel/v7.x/linux-7.1.7.tar.xz"
        );
        assert_eq!(
            args[3],
            "ca8f2a6884a4d62043e9ab93ac1ab15efc2b6630fe8f768b2ef2ffdf4b5e26df"
        );

        let complete = CustomKernelSpec::with_config(
            "7.1.7",
            KernelConfig::complete(b"CONFIG_A=y").expect("config"),
        )
        .expect("spec");
        let complete_args = compiler.bootstrap_args(&complete);
        assert_eq!(complete_args.len(), 5, "complete config appends its path");
        assert_eq!(complete_args[4], CONFIG_GUEST_PATH);
    }

    #[test]
    fn bootstrap_plan_uses_an_error_existing_disk_policy() {
        let root = isolated_root();
        let compiler = JythKernelCompiler::new(root.path()).expect("compiler");
        let lease = lease_in(root.path());
        let builder = compiler
            .bootstrap_builder(&spec("7.1.7"), lease.path())
            .expect("plan");
        let disks = builder.disks_ref();
        assert_eq!(
            disks.len(),
            1,
            "the bootstrap plan attaches exactly one disk"
        );
        assert_eq!(disks[0].on_existing(), ExistingDiskPolicy::Error);
        assert_eq!(disks[0].retention(), DiskRetention::Ephemeral);
        assert_eq!(disks[0].host_path(), lease.path());
    }

    #[test]
    fn bootstrap_builder_rejects_an_invalid_disk_path_as_a_build_disk_error() {
        let root = isolated_root();
        let compiler = JythKernelCompiler::new(root.path()).expect("compiler");
        let error =
            match compiler.bootstrap_builder(&spec("7.1.7"), Path::new("relative/disk.vhdx")) {
                Ok(_) => panic!("a relative build-disk path must fail plan assembly"),
                Err(error) => error,
            };
        assert!(matches!(
            error.current_context(),
            KernelCompilerError::BuildDisk
        ));
    }

    #[test]
    fn build_disk_lease_rejects_a_root_that_is_not_an_existing_directory() {
        let error = BuildDiskLease::new("relative-root").expect_err("relative root");
        assert!(matches!(
            error.current_context(),
            KernelCompilerError::BuildDisk
        ));

        let root = isolated_root();
        let error = BuildDiskLease::new(root.path().join("missing"))
            .expect_err("missing root must be rejected");
        assert!(matches!(
            error.current_context(),
            KernelCompilerError::BuildDisk
        ));

        let file = tempfile::NamedTempFile::new().expect("temp file");
        let error = BuildDiskLease::new(file.path()).expect_err("a file root must be rejected");
        assert!(matches!(
            error.current_context(),
            KernelCompilerError::BuildDisk
        ));
    }

    #[test]
    fn build_disk_lease_rejects_an_existing_generated_path() {
        let root = isolated_root();
        let name = format!("{BUILD_DISK_FILE_PREFIX}{}.vhdx", uuid::Uuid::now_v7());
        std::fs::write(root.path().join(&name), b"pre-existing").expect("pre-create the path");
        let error = BuildDiskLease::new_named(root.path().to_path_buf(), name)
            .expect_err("an existing generated path must fail before VM creation");
        assert!(matches!(
            error.current_context(),
            KernelCompilerError::BuildDisk
        ));
    }

    #[test]
    fn build_disk_lease_finish_accepts_backend_cleanup() {
        let root = isolated_root();
        let mut lease = lease_in(root.path());
        assert!(!lease.path().exists(), "the lease creates no file itself");
        lease
            .finish()
            .expect("no residual file means backend cleanup succeeded");
        lease.finish().expect("finish is idempotent after success");
    }

    #[test]
    fn build_disk_lease_finish_removes_a_residual_regular_file() {
        let root = isolated_root();
        let mut lease = lease_in(root.path());
        let path = lease.path().to_path_buf();
        std::fs::write(&path, b"residual backing file").expect("simulate a leftover");
        lease
            .finish()
            .expect("finish removes the residual regular file");
        assert!(
            !path.exists(),
            "a successful compilation must not leak a build disk"
        );
    }

    #[test]
    fn build_disk_lease_finish_rejects_a_residual_directory() {
        let root = isolated_root();
        let mut lease = lease_in(root.path());
        let path = lease.path().to_path_buf();
        std::fs::create_dir(&path).expect("simulate a residual directory");
        let error = lease
            .finish()
            .expect_err("a residual directory must be rejected");
        assert!(matches!(
            error.current_context(),
            KernelCompilerError::Cleanup
        ));
        assert!(
            path.is_dir(),
            "the lease must never delete a residual directory"
        );
    }

    #[test]
    fn build_disk_lease_finish_rejects_a_residual_reparse_point() {
        let root = isolated_root();
        let mut lease = lease_in(root.path());
        let path = lease.path().to_path_buf();
        let target = root.path().join("victim");
        std::fs::write(&target, b"do not delete").expect("write victim");
        #[cfg(target_os = "windows")]
        let created = std::os::windows::fs::symlink_file(&target, &path).is_ok();
        #[cfg(not(target_os = "windows"))]
        let created = std::os::unix::fs::symlink(&target, &path).is_ok();
        if !created {
            // Windows requires Developer Mode or privileges to create
            // symlinks; the directory-rejection test covers the same guard.
            return;
        }
        let error = lease
            .finish()
            .expect_err("a residual reparse point must be rejected");
        assert!(matches!(
            error.current_context(),
            KernelCompilerError::Cleanup
        ));
        assert!(
            std::fs::symlink_metadata(&path)
                .expect("the symlink must still exist")
                .file_type()
                .is_symlink(),
            "the lease must never follow or delete a reparse point"
        );
        assert_eq!(
            std::fs::read(&target).expect("the target must be untouched"),
            b"do not delete"
        );
    }

    #[test]
    fn build_disk_lease_drop_removes_a_residual_regular_file() {
        let root = isolated_root();
        let path;
        {
            let lease = lease_in(root.path());
            path = lease.path().to_path_buf();
            std::fs::write(&path, b"residual").expect("write residual");
        }
        assert!(!path.exists(), "drop performs bounded best-effort cleanup");
    }

    #[test]
    fn build_disk_lease_drop_leaves_a_residual_directory_alone() {
        let root = isolated_root();
        let path;
        {
            let lease = lease_in(root.path());
            path = lease.path().to_path_buf();
            std::fs::create_dir(&path).expect("create residual directory");
        }
        assert!(path.is_dir(), "drop must never delete a residual directory");
    }

    #[test]
    fn build_disk_paths_are_unique_across_concurrent_tasks() {
        let root = isolated_root();
        let paths: Vec<PathBuf> = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..16)
                .map(|_| {
                    scope.spawn(|| {
                        BuildDiskLease::new(root.path())
                            .expect("lease")
                            .path()
                            .to_path_buf()
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|handle| handle.join().expect("task completed"))
                .collect()
        });
        let unique: std::collections::HashSet<PathBuf> = paths.iter().cloned().collect();
        assert_eq!(
            unique.len(),
            paths.len(),
            "concurrent compiler invocations must never generate the same build-disk path"
        );
    }

    #[test]
    fn build_script_asset_is_posix_lf_text() {
        let script = std::str::from_utf8(BUILD_KERNEL_SH).expect("embedded script is UTF-8");
        assert!(script.starts_with("#!/bin/sh\n"));
        assert!(!script.contains('\r'));
        assert!(!script.contains('\0'));
    }

    #[test]
    fn build_script_rejects_non_canonical_versions() {
        let script = std::str::from_utf8(BUILD_KERNEL_SH).expect("embedded script is UTF-8");
        assert!(
            script.contains("KERNEL_VERSION") && script.contains("invalid stable kernel version"),
            "the script validates its version argument"
        );
    }

    /// The expected-SHA-256 validation must accept only lowercase hex: digits
    /// belong to the allowed set and uppercase letters must be rejected. The
    /// `[!0-9a-f]` negation rejects both non-hex characters and uppercase
    /// letters in one pattern; a `[0-9A-F]` alternative would wrongly match
    /// digits and reject every valid digest (caught on the live host).
    #[test]
    fn build_script_digest_validation_accepts_lowercase_hex_only() {
        let script = std::str::from_utf8(BUILD_KERNEL_SH).expect("embedded script is UTF-8");
        assert!(
            script.contains("*[!0-9a-f]*"),
            "the script must reject any character outside lowercase hex"
        );
        assert!(
            !script.contains("[0-9A-F]"),
            "the script must not use a digit-matching uppercase alternative"
        );
        assert!(
            script.contains("64 lowercase hexadecimal characters"),
            "the digest validation must keep its error message"
        );
    }

    #[test]
    fn complete_configs_are_injected_and_fragments_use_the_embedded_default() {
        let root = isolated_root();
        let compiler = JythKernelCompiler::new(root.path()).expect("compiler");
        let lease = lease_in(root.path());

        let fragment_spec =
            CustomKernelSpec::with_config("7.1.7", KernelConfig::default()).expect("spec");
        let fragment_builder = compiler
            .bootstrap_builder(&fragment_spec, lease.path())
            .expect("fragment plan");
        // The default fragment lives in the build script asset, so the plan
        // injects no separate config file.
        assert!(!fragment_builder.has_guest_file(CONFIG_GUEST_PATH));

        let complete_spec = CustomKernelSpec::with_config(
            "7.1.7",
            KernelConfig::complete(b"CONFIG_A=y").expect("config"),
        )
        .expect("spec");
        let complete_builder = compiler
            .bootstrap_builder(&complete_spec, lease.path())
            .expect("complete plan");
        assert!(complete_builder.has_guest_file(CONFIG_GUEST_PATH));
    }
}
