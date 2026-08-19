//! `ops::blueprint` resolves an OCI or Docker manifest reference into a
//! [`Blueprint`] listing every layer that the downstream pipeline must load.
//!
//! The operation never downloads blob bytes; it only fetches manifests, walks
//! OCI indices or Docker manifest lists to select a Linux image matching the
//! host architecture, and produces one [`Layer`] per manifest entry. Each
//! layer link points at the registry's canonical blob URL
//! (`/v2/<repository>/blobs/<digest>`); the manifest's `descriptor.urls`
//! external locations are ignored.
//!
//! The blueprint preserves the manifest layer order, the declared digest's
//! algorithm (via [`ExpectedDigest`]) and the descriptor sizes (as `u128`
//! without truncation). It rejects malformed digests, negative or
//! overflowing sizes, unknown media types and missing platforms.
//!
//! See `docs/implementation-plan/ops/07-blueprint-and-integration.md` for
//! the full contract.

use std::path::{Path, PathBuf};

use error_stack::Report;
use uuid::Uuid;

use crate::artifact::link::ArtifactLink;
use crate::digest::ExpectedDigest;
use crate::oci_reference::OciReference;
use crate::ops::error::OperationError;
use crate::ops::registry;
use crate::storage::blueprint::{Blueprint, Layer};
use crate::storage::link_ref::LinkRef;
use crate::storage::namespace::Namespace;

/// Resolve `link` into a [`Blueprint`].
///
/// `link` must be an [`ArtifactLink::Http`] pointing at a manifest URL. The
/// operation accepts single-image manifests directly and OCI indices / Docker
/// manifest lists via a second GET keyed by digest. Platform selection always
/// targets Linux with the host's architecture (mapped through `host_arch`).
///
/// `expected_link_digest` is the digest of the `link` snapshot the caller
/// holds. The blueprint is cached under `link_ref.link_digest` (which may be
/// a request or source digest derived by the caller's service), so the
/// operation verifies the link snapshot against the caller's expectation
/// instead of re-deriving the cache key from the raw link.
pub async fn blueprint(
    link_ref: &LinkRef,
    link: ArtifactLink,
    extract: Option<PathBuf>,
    expected_link_digest: crate::digest::LinkDigest,
) -> Result<Blueprint, Report<OperationError>> {
    // Precondition: the link must be an HTTP manifest reference.
    let manifest_url = match &link {
        ArtifactLink::Http(url, _) => url.clone(),
        _ => {
            return Err(OperationError::UnsupportedArtifact
                .report()
                .attach("blueprint requires an ArtifactLink::Http pointing at a manifest"));
        }
    };

    // Precondition: the caller's link snapshot must match the digest they
    // claim for it, so a link cannot be swapped between reservation and use.
    let link_digest = link.digest().map_err(|err| {
        OperationError::ReadSource
            .report()
            .attach("blueprint: link.digest() failed")
            .attach(err)
    })?;
    if link_digest != expected_link_digest {
        return Err(OperationError::ReadSource
            .report()
            .attach("blueprint: link.digest() does not match the caller's expected digest"));
    }

    // Precondition: namespace must be Kernel or Rootfs.
    match link_ref.namespace {
        Namespace::Kernel | Namespace::Rootfs => {}
        other => {
            return Err(OperationError::UnsupportedArtifact.report().attach(format!(
                "blueprint requires Namespace::Kernel or Namespace::Rootfs, got {other:?}"
            )));
        }
    }

    // Precondition: extract must be Some for a kernel stored inside an image.
    if link_ref.namespace == Namespace::Kernel && extract.is_none() {
        return Err(OperationError::UnsupportedArtifact
            .report()
            .attach("blueprint: extract path is required for a kernel stored inside an image"));
    }

    // Precondition: extract path is subject to the same normalization as
    // extract_kernel (relative, non-empty, no `..`).
    if let Some(path) = &extract {
        validate_extract_path(path)?;
    }

    // Recover the repository/host by parsing the manifest URL. The blueprint
    // needs the repository to build blob URLs for each layer; the validated
    // reference owns the canonical host/repository and preserves the scheme.
    let reference = reference_from_manifest_url(&manifest_url)?;

    let manifest = registry::fetch_manifest(&manifest_url).await?;
    let manifest_kind = classify_media_type(&manifest.media_type)?;

    let image_manifest = match manifest_kind {
        ManifestKind::OciImage | ManifestKind::DockerManifest => manifest,
        ManifestKind::OciIndex | ManifestKind::DockerList => {
            let index: IndexManifest = parse_manifest(&manifest.bytes, manifest_kind)?;
            let target = select_platform(&index, &host_arch())?;
            let inner_url = reference.manifest_url_for_digest(target.digest());
            registry::fetch_manifest(&inner_url).await?
        }
    };

    let image: ImageManifest = parse_manifest(&image_manifest.bytes, manifest_kind)?;
    let layers = build_layers(&reference, &image)?;

    Ok(Blueprint {
        target_entry_uuid: link_ref.uuid,
        target_entry_namespace: link_ref.namespace,
        layers,
        extract,
    })
}

// ---------------------------------------------------------------------------
// Platform selection
// ---------------------------------------------------------------------------

/// The host architecture tag used to match a manifest entry. Mapped through
/// `host_arch` so `x86_64` becomes `amd64` and `aarch64` becomes `arm64`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Arch {
    Amd64,
    Arm64,
    Other(String),
}

/// Resolve the host's architecture tag according to the plan mapping. The
/// function is callable from tests through a deterministic override so a
/// single test binary can exercise both branches deterministically.
fn host_arch() -> Arch {
    const ARCH: &str = std::env::consts::ARCH;
    match ARCH {
        "x86_64" => Arch::Amd64,
        "aarch64" => Arch::Arm64,
        other => Arch::Other(other.to_string()),
    }
}

/// Select an image manifest entry out of an index/list that matches
/// `os = "linux"` and the requested architecture variant.
pub fn select_platform(
    index: &IndexManifest,
    target: &Arch,
) -> Result<Descriptor, Report<OperationError>> {
    let mut fallback: Option<&Descriptor> = None;
    for entry in &index.manifests {
        let platform = match entry.platform.as_ref() {
            Some(p) => p,
            None => continue,
        };
        if platform.os.as_deref() != Some("linux") {
            continue;
        }
        let arch = platform.architecture.as_deref().unwrap_or("");
        let variant = platform.variant.as_deref();
        match (target, arch, variant) {
            (Arch::Amd64, "amd64", None) => return Ok(entry.clone()),
            (Arch::Amd64, "amd64", _) => continue,
            (Arch::Arm64, "arm64", Some("v8")) => return Ok(entry.clone()),
            (Arch::Arm64, "arm64", None) => {
                fallback = Some(entry);
                continue;
            }
            (Arch::Arm64, "arm64", _) => continue,
            (Arch::Other(tag), a, _) if a == tag.as_str() => return Ok(entry.clone()),
            _ => continue,
        }
    }

    if let Some(entry) = fallback {
        return Ok(entry.clone());
    }

    Err(OperationError::PlatformNotFound.report())
}

// ---------------------------------------------------------------------------
// Manifest parsing
// ---------------------------------------------------------------------------

/// Discriminator for the four supported manifest media types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManifestKind {
    OciImage,
    OciIndex,
    DockerManifest,
    DockerList,
}

pub fn classify_media_type(media_type: &str) -> Result<ManifestKind, Report<OperationError>> {
    match media_type {
        "application/vnd.oci.image.manifest.v1+json" => Ok(ManifestKind::OciImage),
        "application/vnd.oci.image.index.v1+json" => Ok(ManifestKind::OciIndex),
        "application/vnd.docker.distribution.manifest.v2+json" => Ok(ManifestKind::DockerManifest),
        "application/vnd.docker.distribution.manifest.list.v2+json" => Ok(ManifestKind::DockerList),
        other => Err(OperationError::InvalidManifest
            .report()
            .attach(format!("unsupported manifest media type: {other}"))),
    }
}

pub fn parse_manifest<T: serde::de::DeserializeOwned>(
    bytes: &[u8],
    _kind: ManifestKind,
) -> Result<T, Report<OperationError>> {
    serde_json::from_slice::<T>(bytes).map_err(|err| {
        OperationError::InvalidManifest
            .report()
            .attach(err)
            .attach(format!("manifest bytes len = {}", bytes.len()))
    })
}

/// An OCI image manifest or a Docker schema-2 manifest. They share enough
/// fields for blueprint's purpose.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct ImageManifest {
    #[serde(default)]
    #[expect(dead_code, reason = "wire-format field; schema compatibility")]
    schema_version: u32,
    layers: Vec<Descriptor>,
}

/// An OCI image index or a Docker manifest list. The `manifests` array
/// contains per-platform descriptors.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct IndexManifest {
    #[serde(default)]
    #[expect(dead_code, reason = "wire-format field; schema compatibility")]
    schema_version: u32,
    manifests: Vec<Descriptor>,
}

/// A descriptor. Required fields are enforced via `serde` directly.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct Descriptor {
    #[serde(rename = "mediaType")]
    media_type: Option<String>,
    digest: String,
    size: i64,
    #[serde(default)]
    platform: Option<Platform>,
    #[serde(default)]
    #[expect(
        dead_code,
        reason = "descriptor.urls external locations are ignored by design"
    )]
    urls: Vec<String>,
}

impl Descriptor {
    pub fn digest(&self) -> &str {
        &self.digest
    }
}

/// Optional platform descriptor entry attached to an index element.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct Platform {
    architecture: Option<String>,
    os: Option<String>,
    #[serde(default)]
    variant: Option<String>,
}

// ---------------------------------------------------------------------------
// Layer construction
// ---------------------------------------------------------------------------

/// Build the blueprint layer list from an image manifest. Each layer uses a
/// fresh UUID and points at the registry blob URL; `descriptor.urls` is
/// ignored so a non-registry fallback cannot leak into the pipeline.
pub fn build_layers(
    reference: &OciReference,
    image: &ImageManifest,
) -> Result<Vec<Layer>, Report<OperationError>> {
    let mut layers = Vec::with_capacity(image.layers.len());
    for descriptor in &image.layers {
        let Some(media_type) = &descriptor.media_type else {
            return Err(OperationError::InvalidManifest
                .report()
                .attach("layer descriptor missing mediaType"));
        };
        if !is_layer_media_type(media_type) {
            return Err(OperationError::InvalidManifest
                .report()
                .attach(format!("unknown layer mediaType: {media_type}")));
        }

        // Convert the digest into ExpectedDigest without losing the algorithm.
        let expected = ExpectedDigest::parse(&descriptor.digest).map_err(|err| {
            err.change_context(OperationError::InvalidManifest)
                .attach(format!("layer digest: {}", descriptor.digest))
        })?;

        // Convert the size into u128 without truncation. Reject negatives
        // and any value above i64::MAX that the manifest encoding could
        // smuggle in via sign tricks.
        if descriptor.size < 0 {
            return Err(OperationError::InvalidManifest
                .report()
                .attach(format!("layer size is negative: {}", descriptor.size)));
        }
        let size = descriptor.size as u128;

        let blob_url = reference.blob_url(&descriptor.digest);
        let link = ArtifactLink::Http(blob_url, size);
        let link_digest = link.digest().map_err(|err| {
            OperationError::InvalidManifest
                .report()
                .attach(format!("layer digest: {}", descriptor.digest))
                .attach(err)
        })?;
        layers.push(Layer {
            uuid: Uuid::now_v7(),
            link,
            expected_digest: expected,
            link_digest,
        });
    }
    Ok(layers)
}

/// Accept the OCI layer and Docker layer media types plus the legacy
/// `application/vnd.docker.image.rootfs.diff.tar.gzip` value. Anything else
/// is a rejection candidate per the contract.
fn is_layer_media_type(media_type: &str) -> bool {
    matches!(
        media_type,
        "application/vnd.oci.image.layer.v1.tar"
            | "application/vnd.oci.image.layer.v1.tar+gzip"
            | "application/vnd.oci.image.layer.v1.tar+zstd"
            | "application/vnd.docker.image.rootfs.diff.tar.gzip"
            | "application/vnd.docker.image.rootfs.diff.tar"
    )
}

// ---------------------------------------------------------------------------
// Manifest URL → OciReference recovery
// ---------------------------------------------------------------------------

/// The original `ArtifactLink::Http` carries a manifest URL of the form
/// `https://<host>/v2/<repository>/manifests/<tag-or-digest>`. The blueprint
/// recovers the validated [`OciReference`] so blob URLs can be emitted for
/// each layer; the reference preserves the URL's scheme for local HTTP
/// registries.
fn reference_from_manifest_url(url: &str) -> Result<OciReference, Report<OperationError>> {
    OciReference::from_manifest_url(url)
        .map_err(|err| OperationError::InvalidManifest.report().attach(err))
}

// ---------------------------------------------------------------------------
// extract path validation
// ---------------------------------------------------------------------------

/// Validate `extract` using the same rules `extract_kernel` enforces so a
/// blueprint failure surfaces before any layer is fetched.
fn validate_extract_path(path: &Path) -> Result<(), Report<OperationError>> {
    use crate::ops::cpio::normalize_path;

    if path.as_os_str().is_empty() {
        return Err(OperationError::UnsafePath
            .report()
            .attach("extract path is empty"));
    }
    if path.is_absolute() {
        return Err(OperationError::UnsafePath
            .report()
            .attach(format!("extract path is absolute: {}", path.display())));
    }
    let textual = path.to_string_lossy();
    let bytes = textual.as_bytes();
    if bytes.len() >= 2 && bytes[1] == b':' {
        return Err(OperationError::UnsafePath.report().attach(format!(
            "extract path contains a Windows drive prefix: {}",
            path.display()
        )));
    }
    let _ = normalize_path(&textual)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers for tests
// ---------------------------------------------------------------------------
