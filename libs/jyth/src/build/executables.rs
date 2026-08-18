//! Host-side compilation of Rust process executables injected into the
//! guest overlay.
//!
//! Guest boot-artifact assembly is owned by the `boot-image` crate; that
//! crate compiles only the hardcoded `init` binary. Process executables are
//! host-side process sources, so their compilation stays here: the build
//! facade passes the compiled bytes to boot-image as plain overlay file
//! entries.

use std::path::PathBuf;

use anyhow::{Context as _, Result, anyhow};

use crate::builder::file::RustBinary;

/// Resolve a [`RustBinary`] specification to its built binary's bytes.
///
/// The specification contains an explicit path to a crate's `Cargo.toml` and
/// an optional binary name. We drive `cargo build` through escargot (not
/// `cargo` itself) and read the produced executable out of the
/// `CompilerArtifact` messages.
///
/// Pointing escargot at a *workspace* root manifest (a virtual
/// manifest with no package of its own) is intentionally invalid — cargo
/// refuses to build a virtual manifest without `-p`, so this returns an
/// error. Pointing it at a member crate's manifest builds that crate.
///
/// `features` are passed straight through to `cargo build --features`
/// (space-separated); used to forward jyth's `logs` feature into the
/// `init` crate so its debug logging matches the host build.
///
/// Guest binaries run INSIDE the Linux VM, so they must be cross-compiled
/// for the Linux target regardless of the host OS — we cross-compile to
/// `{arch}-unknown-linux-musl` for exactly this reason. Building for the
/// host target (e.g. Windows, what `.current_target()` would pick) produces
/// a binary the Linux kernel can't `execve` as `/init`, so the guest never
/// reaches pid 1 and never emits `READY` on COM1. They're also always
/// built `--release`: a debug guest binary is enormous and reproducibly
/// fails to `execve` inside the guest with `ENOENT` (a kernel-side
/// initramfs single-binary extraction limit), so release is the practical
/// way to stay under it.
fn resolve_crate_with(spec: &RustBinary, features: &[&str]) -> Result<Vec<u8>> {
    // Guest binaries run inside the Linux guest: target the Linux musl triple,
    // never the host's.
    let arch = std::env::consts::ARCH;
    let triple = format!("{arch}-unknown-linux-musl");
    resolve_crate_for_target(spec, features, Some(&triple))
}

/// Build a Rust binary, optionally selecting the guest target triple.
///
/// Unit tests pass `None` so the repository-owned fixture can compile on a
/// host that does not have the Linux musl target installed. Production overlay
/// materialization always calls [`resolve_crate_with`] and therefore always
/// builds the guest target.
fn resolve_crate_for_target(
    spec: &RustBinary,
    features: &[&str],
    target: Option<&str>,
) -> Result<Vec<u8>> {
    let manifest = spec.manifest_path();

    let mut build = escargot::CargoBuild::new()
        .manifest_path(manifest)
        .release();
    if let Some(target) = target {
        build = build.target(target);
    }
    if let Some(binary_name) = spec.binary_name() {
        build = build.bin(binary_name);
    }
    if !features.is_empty() {
        build = build.features(features.join(" "));
    }

    // Cross-link for the musl guest target. A pure-Rust target links fine
    // with rustc's bundled `rust-lld`; a target with C dependencies needs
    // its C compiler driver (routed via `CC_<target>`) to link.
    if let Some(target) = target {
        let cc_env_key = format!("CC_{}", target.replace('-', "_"));
        if let Ok(cc) = std::env::var(&cc_env_key) {
            build = build.env(
                "RUSTFLAGS",
                format!("-C linker-flavor=gcc -C linker={cc} -C link-self-contained=no",),
            );
        } else {
            build = build.env("RUSTFLAGS", "-C linker-flavor=ld.lld -C linker=rust-lld");
        }
    }

    let msgs = build
        .exec()
        .map_err(|e| anyhow!("escargot build of {} failed: {e}", manifest.display()))?;

    let mut executables: Vec<PathBuf> = Vec::new();
    for msg in msgs {
        let msg = msg.map_err(|e| anyhow!("escargot message error: {e}"))?;
        if let Ok(escargot::format::Message::CompilerArtifact(art)) = msg.decode() {
            let is_bin = art.target.kind.iter().any(|kind| kind == "bin");
            if is_bin && let Some(exe) = &art.executable {
                executables.push(exe.to_path_buf());
            }
        }
    }

    let exe = match (executables.len(), spec.binary_name()) {
        (0, _) => {
            return Err(anyhow!(
                "escargot: no bin artifact produced for {}",
                manifest.display()
            ));
        }
        (1, _) => executables.into_iter().next().unwrap(),
        (_, None) => {
            return Err(anyhow!(
                "escargot: crate {} has multiple binaries; specify RustBinary::bin",
                manifest.display()
            ));
        }
        (_, Some(binary_name)) => executables
            .into_iter()
            .find(|p| {
                p.file_stem()
                    .map(|stem| stem == binary_name)
                    .unwrap_or(false)
            })
            .ok_or_else(|| {
                anyhow!(
                    "escargot: bin {binary_name} not found in {}",
                    manifest.display()
                )
            })?,
    };

    std::fs::read(&exe).with_context(|| format!("reading built binary {exe:?}"))
}

/// Convenience wrapper: resolve a crate with no extra cargo features.
pub(crate) fn resolve_crate(spec: &RustBinary) -> Result<Vec<u8>> {
    resolve_crate_with(spec, &[])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    // Crate resolution via escargot. Building a fixture crate requires a
    // Rust toolchain; the workspace-root manifest is intentionally
    // invalid (virtual manifest, no package of its own) while the member
    // crate's manifest is valid.
    #[tokio::test]
    async fn resolve_crate_workspace_vs_member() {
        let root =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/overlay-crate/Cargo.toml");
        let member = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/overlay-crate/bin/Cargo.toml");
        let root = RustBinary::new(root);
        let member = RustBinary::new(member);

        // Workspace root: virtual manifest -> no package -> escargot errors.
        assert!(resolve_crate(&root).is_err());

        // Member crate: valid -> produces a (non-empty) binary.
        let bytes = resolve_crate_for_target(&member, &[], None).unwrap();
        assert!(!bytes.is_empty());

        // The same member also accepts an explicit binary name without
        // embedding that selection in the manifest path.
        let named = member.clone().bin("overlay-crate-bin");
        let named_bytes = resolve_crate_for_target(&named, &[], None).unwrap();
        assert!(!named_bytes.is_empty());
    }
}
