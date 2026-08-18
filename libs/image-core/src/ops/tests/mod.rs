//! Shared tests for the `image-core` operations.
//!
//! The integration tests for each operation live in dedicated submodules so
//! they can be addressed via `cargo test -p image-core ops::tests::<op>`
//! (e.g. `ops::tests::load`). Submodules use the in-crate helpers directly
//! because every operation's API is crate-internal by convention.

mod blueprint;
mod decompress;
mod flatten;
mod load;

/// A pre-cancelled token makes the `into_cpio` blocking closure bail at
/// entry: the operation fails fast with `OperationError::Cancelled` without
/// converting the TAR (spec capability `blocking-cancellation`).
#[tokio::test]
async fn into_cpio_cancelled_token_returns_cancelled_fast() {
    use tokio_util::sync::CancellationToken;

    let entry = crate::storage::file_ref::FileRef {
        uuid: uuid::Uuid::now_v7(),
        namespace: crate::storage::namespace::Namespace::Layers,
        file_digest: crate::digest::FileDigest {
            file_hash: blake3::hash(b"tar"),
            file_size: 3,
        },
        artifact_type: crate::artifact::ty::ArtifactType::ContainerTar,
        artifact_compression: crate::artifact::compression::ArtifactCompression::None,
    };
    let token = CancellationToken::new();
    token.cancel();

    let err = crate::ops::into_cpio(entry, &token)
        .await
        .expect_err("a cancelled operation must fail");
    assert!(
        matches!(
            err.current_context(),
            crate::ops::error::OperationError::Cancelled
        ),
        "expected Cancelled, got: {err:#}"
    );
}
