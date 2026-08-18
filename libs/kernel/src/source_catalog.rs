//! The embedded kernel source catalog.
//!
//! The catalog is the default source of trusted kernel releases for cacheable
//! custom builds. Every entry is a reviewed, immutable pin: an exact kernel
//! version, a canonical HTTPS URL, and the expected SHA-256 digest of the
//! archive. A catalog update is a reviewed source change; runtime builds
//! trust the reviewed digest, never a mutable upstream version listing.

use std::sync::OnceLock;

use image_core::digest::ExpectedDigest;
use image_core::http_url::HttpUrl;

use crate::{KernelSourcePin, KernelSpecError, KernelVersion};

/// The embedded catalog asset, compiled in so runtime builds never resolve a
/// mutable version listing.
pub(crate) const CATALOG_TOML: &str = include_str!("../assets/kernel-sources.toml");

/// The validated embedded catalog, parsed once.
pub(crate) fn catalog() -> &'static [KernelSourcePin] {
    static CATALOG: OnceLock<Result<Vec<KernelSourcePin>, KernelSpecError>> = OnceLock::new();
    match CATALOG.get_or_init(parse_catalog) {
        Ok(entries) => entries,
        // The catalog is a compiled-in asset; a parse failure is a build
        // defect, not a runtime condition. Panicking here surfaces the
        // defective asset at first use with the full reason.
        Err(error) => panic!("embedded kernel source catalog is invalid: {error:#}"),
    }
}

/// The highest version in the embedded catalog, selected through
/// [`KernelVersion`] numeric ordering.
pub(crate) fn latest() -> Option<&'static KernelSourcePin> {
    catalog().iter().max_by_key(|pin| pin.version())
}

/// Look up the reviewed pin for `version`.
pub(crate) fn get(version: &KernelVersion) -> Option<&'static KernelSourcePin> {
    catalog().iter().find(|pin| pin.version() == version)
}

/// Parse and validate the embedded catalog TOML.
fn parse_catalog() -> Result<Vec<KernelSourcePin>, KernelSpecError> {
    #[derive(serde::Deserialize)]
    struct CatalogFile {
        #[serde(rename = "schema_version")]
        schema_version: u32,
        #[serde(rename = "release")]
        releases: Vec<Release>,
    }

    #[derive(serde::Deserialize)]
    struct Release {
        version: String,
        url: String,
        sha256: String,
    }

    let file: CatalogFile = toml::from_str(CATALOG_TOML)
        .map_err(|error| KernelSpecError::InvalidSourceCatalog(error.to_string()))?;
    if file.schema_version != 1 {
        return Err(KernelSpecError::InvalidSourceCatalog(format!(
            "unsupported schema_version {}",
            file.schema_version
        )));
    }

    let mut pins = Vec::with_capacity(file.releases.len());
    let mut seen = std::collections::HashSet::new();
    for release in file.releases {
        let version = KernelVersion::parse(&release.version)?;
        if !seen.insert(version.clone()) {
            return Err(KernelSpecError::SourceVersionMismatch(format!(
                "duplicate catalog version {}",
                version.as_str()
            )));
        }

        // The URL's final file name must match the version.
        let expected_file = format!("linux-{}.tar.xz", version.as_str());
        let url = HttpUrl::parse(&release.url)?;
        if url.scheme() != "https" {
            return Err(KernelSpecError::InvalidSourceUrl(
                "catalog URLs must use https".to_string(),
            ));
        }
        let file_name = url
            .as_str()
            .rsplit('/')
            .next()
            .unwrap_or_default()
            .split('?')
            .next()
            .unwrap_or_default();
        if file_name != expected_file {
            return Err(KernelSpecError::SourceVersionMismatch(format!(
                "catalog URL for {} must end in {}, got {}",
                version.as_str(),
                expected_file,
                file_name
            )));
        }

        // Only SHA-256 is accepted for catalog pins; ExpectedDigest::parse
        // rejects any other length or algorithm.
        let digest =
            ExpectedDigest::parse(&format!("sha256:{}", release.sha256)).map_err(|_| {
                KernelSpecError::InvalidSourceDigest(
                    "catalog sha256 must be 64 hexadecimal characters".to_string(),
                )
            })?;

        let pin = KernelSourcePin::new(version, url, digest).map_err(|_| {
            KernelSpecError::InvalidSourceDigest("invalid catalog digest".to_string())
        })?;
        pins.push(pin);
    }

    Ok(pins)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_catalog_entry_is_a_validated_pin() {
        let pins = catalog();
        assert!(!pins.is_empty(), "the embedded catalog must not be empty");
        for pin in pins {
            assert_eq!(pin.url().scheme(), "https");
            assert!(pin.digest().digest_bytes().len() == 32);
            assert!(
                pin.url()
                    .as_str()
                    .ends_with(&format!("linux-{}.tar.xz", pin.version().as_str()))
            );
        }
    }

    #[test]
    fn latest_selects_the_highest_numeric_version() {
        let latest = latest().expect("catalog has a latest");
        assert_eq!(latest.version().as_str(), "7.1.8");
    }

    #[test]
    fn get_resolves_a_catalogued_version() {
        let version = KernelVersion::parse("7.1.7").expect("valid");
        let pin = get(&version).expect("7.1.7 is catalogued");
        assert_eq!(
            pin.digest().digest_bytes(),
            ExpectedDigest::parse(
                "sha256:ca8f2a6884a4d62043e9ab93ac1ab15efc2b6630fe8f768b2ef2ffdf4b5e26df"
            )
            .expect("digest")
            .digest_bytes()
        );
    }

    #[test]
    fn get_returns_none_for_an_uncatalogued_version() {
        let version = KernelVersion::parse("6.6.13").expect("valid");
        assert!(get(&version).is_none());
    }

    /// The catalog parses to a stable, sorted-by-version set: numeric order,
    /// never lexical string order.
    #[test]
    fn catalog_entries_are_numerically_ordered() {
        let versions: Vec<&str> = catalog().iter().map(|pin| pin.version().as_str()).collect();
        assert_eq!(versions, vec!["6.6.14", "7.1.6", "7.1.7", "7.1.8"]);
    }
}
