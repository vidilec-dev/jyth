//! OCI image acquisition + cache-reuse acceptance.
//!
//! Exercises the launch-side materialization pipeline through
//! `e2e_tests::materialize_image` over the `kernel`/`rootfs` crates and
//! proves repeated acquisition is stable: cache hits return identical
//! content-addressed artifacts across rounds. Pure materialization — no VMs
//! are launched; `hcs_test_guard` only serializes against the suite binaries
//! that share the host and store.
//!
//! Acceptance: this binary must pass 3 consecutive runs.

use e2e_tests::{ALPINE_ROOTFS, E2eResult, hcs_test_guard, materialize_image};
use jyth::builder::image::{Kernel, Link, Rootfs};
use std::path::PathBuf;
use std::time::Instant;

#[tokio::test]
async fn oci_acquisition_is_stable_and_cache_reuse_holds() -> E2eResult<()> {
    let _host_guard = hcs_test_guard().await?;
    // The pinned default kernel: one immutable OCI manifest digest, never a
    // mutable tag (KernelApiDxPlan §4.5/§9.1).
    let kernel = Kernel::default();
    let rootfs = Rootfs::new(Link::image(ALPINE_ROOTFS));
    let mut first_paths: Option<(PathBuf, PathBuf)> = None;
    for round in 1..=3u32 {
        let started = Instant::now();
        let (kernel_path, rootfs_path) = materialize_image(&kernel, &rootfs).await?;
        // Both artifacts must exist and be non-empty.
        assert!(
            std::fs::metadata(&kernel_path)?.len() > 0,
            "empty kernel artifact in round {round}"
        );
        assert!(
            std::fs::metadata(&rootfs_path)?.len() > 0,
            "empty rootfs artifact in round {round}"
        );
        // Identity-stable across rounds: same content-addressed paths.
        if let Some((kernel0, rootfs0)) = &first_paths {
            assert_eq!(kernel0, &kernel_path, "kernel path changed between rounds");
            assert_eq!(rootfs0, &rootfs_path, "rootfs path changed between rounds");
        } else {
            first_paths = Some((kernel_path.clone(), rootfs_path.clone()));
        }
        eprintln!(
            "[image_acquisition] round {round}: {:.2}s kernel={} rootfs={}",
            started.elapsed().as_secs_f64(),
            kernel_path.display(),
            rootfs_path.display()
        );
    }
    Ok(())
}
