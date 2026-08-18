//! Hardcoded initramfs stage: pid 1 is the `init` crate.
//!
//! The `init` crate is a workspace member and a boot artifact: it is
//! compiled here (via escargot) and later emitted at `/init` (executable)
//! in the merged rootfs, so the kernel's `init=/init` runs it as pid 1.
//! Host-side *process* executables are not compiled here — that host-side
//! preparation stays in the `jyth` facade, which passes compiled bytes as
//! plain overlay entries.

use std::path::{Path, PathBuf};

use error_stack::{Report, ResultExt};
use thiserror::Error;
use tokio_util::sync::CancellationToken;

/// Cargo features forwarded into the `init` build. (Historically this
/// mirrored jyth's `logs` feature onto `init`; logging is now unified on
/// `tracing`, so no extra features are forwarded.)
const INIT_FEATURES: &[&str] = &[];

/// Bounded grace given to a cancelled `spawn_blocking` worker to observe its
/// token and unwind before the join abandons the handle. Abort alone cannot
/// stop a worker thread, so the worker exits through its own
/// `is_cancelled()` checks within this window.
const CANCELLATION_GRACE: std::time::Duration = std::time::Duration::from_secs(1);

/// Await a `spawn_blocking` join, racing the cancellation token (spec
/// capability `blocking-cancellation`). When the token is cancelled first,
/// the worker gets a bounded [`CANCELLATION_GRACE`] to observe it and finish;
/// beyond that the handle is abandoned (abort alone cannot stop a worker
/// thread) and `cancelled` is returned. `map_join` converts a join failure
/// into `E`.
async fn bounded_join<T, E>(
    handle: tokio::task::JoinHandle<T>,
    token: &CancellationToken,
    map_join: impl FnOnce(tokio::task::JoinError) -> E,
    cancelled: E,
) -> Result<T, E> {
    tokio::pin!(handle);
    tokio::select! {
        result = handle.as_mut() => result.map_err(map_join),
        _ = token.cancelled() => match tokio::time::timeout(CANCELLATION_GRACE, handle.as_mut()).await {
            Ok(result) => result.map_err(map_join),
            Err(_) => Err(cancelled),
        },
    }
}

/// Resolve the `init` crate (a workspace member) with escargot and
/// return its built executable bytes. This is the hardcoded pid-1 stage:
/// the produced binary is later emitted at `/init` (executable) in the
/// merged rootfs, so the kernel's `init=/init` runs it as pid 1.
pub(crate) async fn resolve_init_binary(
    token: &CancellationToken,
) -> Result<Vec<u8>, Report<CompileBinaryError>> {
    // `init` lives at `libs/init` relative to this crate's manifest dir
    // (`libs/boot-image`).
    let manifest_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../init/Cargo.toml");
    bounded_join(
        tokio::task::spawn_blocking({
            let token = token.clone();
            let manifest_path = manifest_path.clone();
            move || {
                // Entry-only check: the escargot build is one blocking call,
                // so mid-call cancellation is impossible; the worker bails
                // before cargo is invoked.
                if token.is_cancelled() {
                    return Err(Report::new(CompileBinaryError::Cancelled));
                }
                compile_binary(&manifest_path)
            }
        }),
        token,
        |e| Report::new(CompileBinaryError::SpawnBlocking).attach(e),
        Report::new(CompileBinaryError::Cancelled),
    )
    .await?
}

/// Failures encountered when building and resolving the guest `init` binary.
///
/// Variants represent the distinct failure categories of the compilation and
/// artifact resolution workflow. Dynamic context such as manifest paths,
/// target triples, linker configuration, and underlying I/O or cargo errors
/// are attached as contextual frames to the [`error_stack::Report`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum CompileBinaryError {
    /// Resolution was cancelled before or during compilation.
    #[error("init binary compilation cancelled")]
    Cancelled,

    /// The blocking compilation task failed to join.
    #[error("failed to join blocking compilation task")]
    SpawnBlocking,

    /// Invoking the cargo build through escargot failed.
    #[error("cargo build failed for init binary")]
    CargoBuild,

    /// An escargot compiler message stream or decoding error occurred.
    #[error("failed to decode compiler artifact message")]
    MessageDecode,

    /// An escargot cargo build failed.
    #[error("escargot cargo build failed")]
    EscargotError,

    /// Cargo build succeeded but no binary artifact was produced for the crate.
    #[error("no binary artifact produced for crate")]
    NoBinaryArtifact,

    /// The crate produced multiple binary artifacts and the target was ambiguous.
    #[error("crate produced multiple binary artifacts")]
    MultipleBinaryArtifacts,

    /// Reading the compiled binary artifact from disk failed.
    #[error("failed to read compiled binary")]
    ReadBinary,
}

/// Build the `init` crate for the Linux guest target and return its bytes.
///
/// We drive `cargo build` through escargot (not `cargo` itself) and read
/// the produced executable out of the `CompilerArtifact` messages.
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
fn compile_binary(manifest: &Path) -> Result<Vec<u8>, Report<CompileBinaryError>> {
    // Guest binaries run inside the Linux guest: target the Linux musl triple,
    // never the host's.
    let arch = std::env::consts::ARCH;
    let triple = format!("{arch}-unknown-linux-musl");

    let mut build = escargot::CargoBuild::new()
        .manifest_path(manifest)
        .release()
        .target(&triple);
    if !INIT_FEATURES.is_empty() {
        build = build.features(INIT_FEATURES.join(" "));
    }

    // Cross-link for the musl guest target. A pure-Rust target links fine
    // with rustc's bundled `rust-lld`; a target with C dependencies needs
    // its C compiler driver (routed via `CC_<target>`) to link.
    let cc_env_key = format!("CC_{}", triple.replace('-', "_"));
    if let Ok(cc) = std::env::var(&cc_env_key) {
        build = build.env(
            "RUSTFLAGS",
            format!("-C linker-flavor=gcc -C linker={cc} -C link-self-contained=no"),
        );
    } else {
        build = build.env("RUSTFLAGS", "-C linker-flavor=ld.lld -C linker=rust-lld");
    }

    let msgs = build.exec().map_err(|e| {
        Report::new(CompileBinaryError::CargoBuild)
            .attach(format!("manifest: {}", manifest.display()))
            .attach(format!("target: {triple}"))
            .attach(e.to_string())
    })?;

    let mut executables: Vec<PathBuf> = Vec::new();
    for msg in msgs {
        let msg = msg.map_err(|e| {
            Report::new(CompileBinaryError::CargoBuild)
                .attach(format!("manifest: {}", manifest.display()))
                .attach(format!("target: {triple}"))
                .attach(format!("message: {e}"))
        })?;
        if let Ok(escargot::format::Message::CompilerArtifact(art)) = msg.decode() {
            let is_bin = art.target.kind.iter().any(|kind| kind == "bin");
            if is_bin && let Some(exe) = &art.executable {
                executables.push(exe.to_path_buf());
            }
        }
    }

    let exe = match executables.len() {
        0 => {
            return Err(Report::new(CompileBinaryError::NoBinaryArtifact)
                .attach(format!("manifest: {}", manifest.display()))
                .attach(format!("target: {triple}")));
        }
        1 => executables.into_iter().next().unwrap(),
        _ => {
            return Err(Report::new(CompileBinaryError::MultipleBinaryArtifacts)
                .attach(format!("manifest: {}", manifest.display()))
                .attach(format!("found binaries: {executables:?}")));
        }
    };

    std::fs::read(&exe)
        .change_context(CompileBinaryError::ReadBinary)
        .attach(format!("binary path: {}", exe.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_util::sync::CancellationToken;

    // The hardcoded pid-1 stage resolves the `init` workspace
    // member via escargot (the same escargot infra the overlay crate
    // sources use) and emits it at `/init`. Ignored by default
    // because it drives a real `cargo build`; mirrors the historical
    // `resolve_crate_workspace_vs_member` overlay fixture test.
    #[test]
    fn init_binary_resolves_via_escargot() {
        let manifest = Path::new(env!("CARGO_MANIFEST_DIR")).join("../init/Cargo.toml");
        let bytes = compile_binary(&manifest).unwrap();
        assert!(!bytes.is_empty());
    }

    /// A pre-cancelled token makes the blocking closure bail at entry: the
    /// resolution fails fast without invoking escargot (spec capability
    /// `blocking-cancellation`).
    #[tokio::test]
    async fn resolve_init_binary_with_cancelled_token_fails_fast() {
        let token = CancellationToken::new();
        token.cancel();

        let err = resolve_init_binary(&token)
            .await
            .expect_err("a cancelled resolution must fail");
        let text = format!("{err:#}");
        assert!(
            text.contains("cancelled"),
            "expected a cancelled error, got: {text}"
        );
    }
}
