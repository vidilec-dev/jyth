//! The Jyth adapter for executable injection (SolidArchitecturePlan WP6
//! action 10, WP7).
//!
//! boot-image owns deterministic boot-artifact assembly and must receive
//! prepared content. The runtime's boot artifact provider owns the
//! preparation call, so this module maps the public Jyth file/dir sources —
//! including Rust and bytes process executables — into the host-neutral
//! [`jyth_runtime::BootOverlayEntry`] values the provider consumes:
//!
//! - Rust process executables are compiled to bytes here (host-side
//!   preparation, `crate::build::executables`); boot-image never compiles a
//!   process source;
//! - byte sources are hashed for their cache origin identity;
//! - the hardcoded init binary is NOT built here: boot-image compiles it as
//!   a boot artifact.

use std::path::Path;

use boot_image::GuestPathReason;
use error_stack::Report;
use image_core::ops::bounded_join;
use jyth_runtime::{BootOverlayEntry, BootOverlayEntryKind};
use tokio_util::sync::CancellationToken;

use crate::build::{BuildError, executables};
use crate::builder::dir::Dir;
use crate::builder::file::{File, FileContent};

/// Build the host-neutral overlay entries for every configured file and dir.
///
/// Rust process executables are compiled to bytes here — host-side
/// preparation — because boot-image owns only boot artifacts and must
/// receive prepared content.
pub(crate) async fn overlay_entries(
    files: &[File],
    dirs: &[Dir],
    token: &CancellationToken,
) -> Result<Vec<BootOverlayEntry>, Report<BuildError>> {
    let mut entries = Vec::with_capacity(files.len() + dirs.len());

    for dir in dirs {
        let path = dir
            .path_ref()
            .ok_or(Report::new(BuildError::MissingOverlayPath {
                kind: "directory",
            }))?;
        entries.push(BootOverlayEntry {
            path: overlay_path_string(path)?,
            kind: BootOverlayEntryKind::Directory { mode: dir.mode() },
        });
    }

    for file in files {
        let path = file
            .path_ref()
            .ok_or(Report::new(BuildError::MissingOverlayPath { kind: "file" }))?;
        let path_string = overlay_path_string(path)?;
        let content = file.content_ref().ok_or_else(|| {
            Report::new(BuildError::Overlay).attach(format!(
                "overlay file {} has no content",
                display_overlay_path(&path_string)
            ))
        })?;
        let (bytes, origin) = match content {
            FileContent::Bytes(bytes) => {
                let digest = format!("blake3_{}", blake3::hash(bytes).to_hex());
                (bytes.clone(), format!("bytes:{digest}"))
            }
            FileContent::Crate(spec) => {
                let identity = spec.cache_identity();
                let spec = spec.clone();
                let bytes = bounded_join(
                    tokio::task::spawn_blocking({
                        let token = token.clone();
                        move || -> Result<Vec<u8>, Report<BuildError>> {
                            // Entry-only check: the escargot build is one
                            // blocking call, so mid-call cancellation is
                            // impossible; the worker bails before cargo is
                            // invoked (spec capability `blocking-cancellation`).
                            if token.is_cancelled() {
                                return Err(Report::new(BuildError::Cancelled)
                                    .attach("crate build cancelled"));
                            }
                            executables::resolve_crate(&spec)
                                .map_err(|error| Report::new(BuildError::Overlay).attach(error))
                        }
                    }),
                    token,
                    |error| {
                        Report::new(BuildError::Overlay)
                            .attach(format!("join error resolving crate: {error}"))
                    },
                    Report::new(BuildError::Cancelled).attach("crate build cancelled"),
                )
                .await??;
                (bytes, format!("crate:{identity}"))
            }
        };
        entries.push(BootOverlayEntry {
            path: path_string,
            kind: BootOverlayEntryKind::File {
                content: bytes,
                mode: file.mode(),
                origin,
            },
        });
    }

    Ok(entries)
}

/// Convert a builder path to the string form boot-image validates.
///
/// Non-UTF-8 paths are rejected here (boot-image receives only strings),
/// preserving the `NonRepresentable` guest-path error at the boundary.
fn overlay_path_string(path: &Path) -> Result<String, Report<BuildError>> {
    let shown = path.to_string_lossy().into_owned();
    let raw = path.to_str().ok_or_else(|| {
        Report::new(BuildError::InvalidGuestPath {
            path: shown,
            reason: GuestPathReason::NonRepresentable,
        })
    })?;
    Ok(raw.to_string())
}

/// Format a raw builder path the way the canonical overlay display does
/// (`/` + guest path) for content errors raised before boot-image can
/// canonicalize the path.
fn display_overlay_path(raw: &str) -> String {
    format!("/{}", raw.trim_start_matches(['/', '\\']))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::file::RustBinary;
    use tokio_util::sync::CancellationToken;

    /// A pre-cancelled token makes the crate-resolution closure bail at
    /// entry: the overlay build fails fast with `BuildError::Cancelled`
    /// without invoking escargot (spec capability `blocking-cancellation`).
    /// The manifest path is intentionally invalid — the closure must never
    /// reach it.
    #[tokio::test]
    async fn cancelled_token_returns_cancelled_fast_for_crate_entries() {
        let file = crate::builder::file::File::new()
            .path("/bin/tool")
            .content(RustBinary::new("does/not/matter/Cargo.toml"));
        let token = CancellationToken::new();
        token.cancel();

        let err = overlay_entries(&[file], &[], &token)
            .await
            .expect_err("a cancelled overlay build must fail");
        assert!(
            matches!(err.current_context(), BuildError::Cancelled),
            "expected Cancelled, got: {err:#}"
        );
    }

    /// Triangulation: an active token preserves the happy path for byte
    /// entries — cancellation checks add no behavior change.
    #[tokio::test]
    async fn active_token_preserves_byte_entries() {
        let file = crate::builder::file::File::new()
            .path("/etc/hostname")
            .content(b"guest".to_vec());
        let token = CancellationToken::new();

        let entries = overlay_entries(&[file], &[], &token)
            .await
            .expect("byte entries build with an active token");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].path, "/etc/hostname");
    }
}
