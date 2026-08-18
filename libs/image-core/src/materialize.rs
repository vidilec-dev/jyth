//! Shared layer-materialization helpers for the kernel and rootfs services.
//!
//! The three helpers here are the pipeline steps that both domain
//! materialization crates (`kernel`, `rootfs`) run against a blueprinted OCI
//! image: build or load the cached blueprint, materialize and flatten every
//! layer into one artifact, and normalize a raw artifact (decompress, then
//! convert TAR to CPIO). They are owned here so the two domain crates share
//! one implementation and one error category.

use std::path::PathBuf;

use error_stack::Report;
use thiserror::Error;
use tokio_util::sync::CancellationToken;
#[cfg(feature = "tracing")]
use tracing::instrument;

use crate::{
    artifact::{compression::ArtifactCompression, link::ArtifactLink, ty::ArtifactType},
    ops as core_ops,
    storage::{
        blueprint::{Blueprint, Layer},
        file_ref::FileRef,
        link_ref::LinkRef,
        namespace::{Namespace, NamespacedLinkDigest},
    },
    store::ImageStore,
    timing::{OpTimer, SourceKind},
};

/// Error category for the shared layer-materialization helpers.
///
/// The kernel and rootfs services map this category onto their own
/// use-case error surface, keeping the underlying context frames (store
/// transactions, operation failures) attached to the report.
#[derive(Debug, Error)]
pub enum LayerError {
    /// A layer or rootfs materialization step failed.
    #[error("could not materialize image layers")]
    Materialization,
}

/// Attach the shared layer-materialization category to an error report.
pub(crate) fn change_layer<E>(error: Report<E>) -> Report<LayerError> {
    error.change_context(LayerError::Materialization)
}

/// Return the blueprint cached for `target`, or build and publish it from
/// the OCI manifest reachable through `link`.
///
/// `target` carries the cache identity (which may be a request or source
/// digest derived by the caller's service); `expected_link_digest` is the
/// digest of the `link` snapshot the caller holds, verified by
/// [`crate::ops::blueprint`] so a link cannot be swapped between reservation
/// and use.
#[cfg_attr(feature = "tracing", instrument(skip_all, level = "debug"))]
pub async fn get_or_build_blueprint(
    store: &dyn ImageStore,
    target: &LinkRef,
    link: ArtifactLink,
    extract: Option<PathBuf>,
    expected_link_digest: crate::digest::LinkDigest,
) -> Result<Blueprint, Report<LayerError>> {
    let timer = OpTimer::start("layers.blueprint")
        .source(SourceKind::from(&link))
        .namespace("blueprint");
    match get_or_build_blueprint_inner(store, target, link, extract, expected_link_digest).await {
        Ok(value) => Ok(value),
        Err(error) => {
            timer.fail(format!("{error:#}"));
            Err(error)
        }
    }
}

/// The pipeline behind [`get_or_build_blueprint`], timed by the
/// `layers.blueprint` completion timer at the wrapper.
async fn get_or_build_blueprint_inner(
    store: &dyn ImageStore,
    target: &LinkRef,
    link: ArtifactLink,
    extract: Option<PathBuf>,
    expected_link_digest: crate::digest::LinkDigest,
) -> Result<Blueprint, Report<LayerError>> {
    match store
        .read_blueprint(NamespacedLinkDigest::from(target))
        .map_err(change_layer)?
    {
        Some(value) => Ok(value),
        None => store
            .publish_blueprint(
                core_ops::blueprint(target, link, extract, expected_link_digest)
                    .await
                    .map_err(change_layer)?,
            )
            .map_err(change_layer),
    }
}

/// Materialize every layer of a blueprint and flatten them into one
/// complete, uncompressed CPIO artifact at `destination`.
#[cfg_attr(
    feature = "tracing",
    instrument(skip_all, fields(layers = layers.len()), level = "debug")
)]
pub async fn materialize_layers(
    store: &dyn ImageStore,
    layers: Vec<Layer>,
    destination: &LinkRef,
    token: &CancellationToken,
) -> Result<FileRef, Report<LayerError>> {
    let timer = OpTimer::start("layers.materialize").namespace("layers");
    match materialize_layers_inner(store, layers, destination, token).await {
        Ok(value) => Ok(value),
        Err(error) => {
            timer.fail(format!("{error:#}"));
            Err(error)
        }
    }
}

/// The pipeline behind [`materialize_layers`], timed by the
/// `layers.materialize` completion timer at the wrapper. Each layer load is
/// additionally timed by its own `layer.load` event.
async fn materialize_layers_inner(
    store: &dyn ImageStore,
    layers: Vec<Layer>,
    destination: &LinkRef,
    token: &CancellationToken,
) -> Result<FileRef, Report<LayerError>> {
    let mut materialized = Vec::with_capacity(layers.len());
    for layer in layers {
        let layer_ref = store
            .reserve_link_ref(NamespacedLinkDigest {
                namespace: Namespace::Layers,
                link_digest: layer.link_digest,
            })
            .map_err(change_layer)?;
        let mut artifact = match store.read_file_ref(&layer_ref).map_err(change_layer)? {
            Some(entry) => entry,
            None => {
                let timer = OpTimer::start("layer.load")
                    .source(SourceKind::from(&layer.link))
                    .namespace("layers");
                let entry = match core_ops::load(
                    &layer.link,
                    &layer_ref,
                    Some(&layer.expected_digest),
                    layer.link_digest,
                    token,
                )
                .await
                {
                    Ok(entry) => {
                        timer.bytes(entry.file_digest.file_size as u64);
                        entry
                    }
                    Err(error) => {
                        let error = change_layer(error);
                        timer.fail(format!("{error:#}"));
                        return Err(error);
                    }
                };
                store
                    .publish_file_ref(&layer_ref, &entry)
                    .map_err(change_layer)?;
                entry
            }
        };
        artifact = normalize_artifact(store, artifact, token)
            .await
            .map_err(change_layer)?;
        if artifact.artifact_type != ArtifactType::ContainerCpio {
            return Err(Report::new(LayerError::Materialization).attach(format!(
                "layer materialized as unsupported artifact {:?}",
                artifact.artifact_type
            )));
        }
        materialized.push(artifact);
    }

    core_ops::flatten(&materialized, destination, token)
        .await
        .map_err(change_layer)
}

/// Normalize a raw materialized artifact in place: decompress it when
/// compressed, then convert an uncompressed TAR into a CPIO archive.
#[cfg_attr(
    feature = "tracing",
    instrument(skip_all, fields(artifact_type = ?artifact.artifact_type), level = "debug")
)]
pub async fn normalize_artifact(
    store: &dyn ImageStore,
    artifact: FileRef,
    token: &CancellationToken,
) -> Result<FileRef, Report<LayerError>> {
    let timer = OpTimer::start("layers.normalize").namespace("layers");
    match normalize_artifact_inner(store, artifact, token).await {
        Ok(value) => Ok(value),
        Err(error) => {
            timer.fail(format!("{error:#}"));
            Err(error)
        }
    }
}

/// The pipeline behind [`normalize_artifact`], timed by the
/// `layers.normalize` completion timer at the wrapper.
async fn normalize_artifact_inner(
    store: &dyn ImageStore,
    mut artifact: FileRef,
    token: &CancellationToken,
) -> Result<FileRef, Report<LayerError>> {
    if artifact.artifact_compression != ArtifactCompression::None {
        // Decompression is staged: the index update commits BEFORE the staged
        // bytes replace the compressed source, so the compressed source
        // survives until the index commit succeeds (M17/B8).
        let staged = core_ops::decompress(artifact, token)
            .await
            .map_err(change_layer)?;
        artifact = staged.file_ref().clone();
        store
            .replace_file_ref(artifact.clone())
            .map_err(change_layer)?;
        artifact = staged.publish().map_err(change_layer)?;
    }
    if artifact.artifact_type == ArtifactType::ContainerTar {
        artifact = store
            .replace_file_ref(
                core_ops::into_cpio(artifact, token)
                    .await
                    .map_err(change_layer)?,
            )
            .map_err(change_layer)?;
    }
    Ok(artifact)
}
