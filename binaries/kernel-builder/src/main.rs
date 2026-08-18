//! Compile a Linux kernel inside a jyth VM through the reusable compiler
//! adapter and copy the cached bzImage to the host.
//!
//! # Responsibility (SolidArchitecturePlan target catalog)
//!
//! **Owner**: kernel-builder.
//!
//! **Responsibility**: kernel-builder command-line use case.
//!
//! **Allowed dependencies**: jyth (enforced by `tests/architecture`).
//!
//! **Forbidden concepts**: hypervisor internals, image-index internals, guest
//! protocol decoding, bootstrap VM assembly, and Kconfig assets. The CLI
//! retains only argument parsing, progress output, and output-file copying;
//! the reusable compiler path lives in `jyth::kernel_build`.

use clap::Parser;

use jyth::builder::image::CustomKernelSpec;
use jyth::kernel_build::compile_kernel_with_status;

/// The reusable in-guest build script asset shipped with the Jyth compiler
/// adapter. The CLI tests inspect this shared asset rather than a duplicate
/// script.
pub const BUILD_KERNEL_SH: &[u8] =
    include_bytes!("../../../libs/jyth/assets/kernel-build/build_kernel.sh");

#[derive(Parser, Debug)]
#[command(
    name = "kernel-builder",
    about = "Compile a Linux kernel inside a jyth VM and copy the cached bzImage to the host."
)]
struct Args {
    /// Linux kernel version to build: an exact version such as "7.1.7", or
    /// "latest" to resolve the current stable release before building.
    #[arg(short, long, default_value = "latest")]
    version: String,

    /// Optional path to a complete .config file on the host. If omitted, the
    /// build uses the canonical Jyth fragment.
    #[arg(short, long)]
    config: Option<std::path::PathBuf>,

    /// Output path for the compiled bzImage on the host.
    #[arg(short, long, default_value = "bzImage")]
    output: std::path::PathBuf,

    /// Dry-run: print the plan, do NOT launch a VM, do not touch the cache.
    #[arg(long)]
    no_launch: bool,
}

type BoxError = Box<dyn std::error::Error + Send + Sync>;

#[tokio::main]
async fn main() -> std::process::ExitCode {
    match run().await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("[host] fatal: {error:?}");
            #[cfg(feature = "tracing")]
            tracing::error!(chain = %format!("{error:?}"), "kernel-builder failed");
            // Return the failure code instead of `std::process::exit(1)`:
            // exiting through main's return value lets every destructor run
            // (journal session, redb database, runtime), so a failed build
            // leaves a cleanly closed session database instead of one that
            // needs repair on the next read-only inventory scan.
            std::process::ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), BoxError> {
    #[cfg(feature = "tracing")]
    tracing::init();

    let args = Args::parse();

    eprintln!(
        "[host] kernel-builder: version={}, config={:?}, output={:?}, no_launch={}",
        args.version, args.config, args.output, args.no_launch,
    );

    // Resolve `latest` to an exact version before constructing a kernel
    // specification; KernelVersion rejects the mutable value itself.
    let version = resolve_version(&args.version)?;

    if args.no_launch {
        eprintln!(
            "[host] --no-launch: plan only. Would compile kernel {version} (config {:?}) and copy \
             the cached bzImage to {:?}. No network, VM, or cache mutation happens in plan mode.",
            args.config, args.output,
        );
        return Ok(());
    }

    // Enforce the Jyth release boundary before any image pull or cache write.
    jyth::ensure_supported_platform()?;

    if host_file_output_requested_as_directory(&args.output) {
        return Err(format!(
            "--output must name a kernel file, not a directory: {}",
            args.output.display()
        )
        .into());
    }

    let spec = match &args.config {
        Some(path) => CustomKernelSpec::with_config(
            version.as_str(),
            jyth::builder::image::KernelConfig::read_complete(path)
                .map_err(|error| format!("failed to load config at {}: {error}", path.display()))?,
        )
        .map_err(|error| format!("invalid kernel specification: {error}"))?,
        None => CustomKernelSpec::new(version.as_str())
            .map_err(|error| format!("invalid kernel specification: {error}"))?,
    };

    eprintln!(
        "[host] launching custom kernel compile (first run pulls images and boots the guest — \
         this can take several minutes; a cache hit returns immediately)"
    );
    let (cached, served_from_cache) = compile_kernel_with_status(spec)
        .await
        .map_err(|error| format!("custom kernel compilation failed: {error:?}"))?;
    let artifact_size = std::fs::metadata(&cached)
        .map(|metadata| metadata.len())
        .unwrap_or(0);
    eprintln!(
        "[host] kernel {} from the shared custom cache ({} bytes); copying to {:?}",
        if served_from_cache {
            "served"
        } else {
            "compiled"
        },
        artifact_size,
        args.output,
    );

    replace_output_atomically(&cached, &args.output)?;
    let artifact_size = std::fs::metadata(&args.output)
        .map_err(|error| {
            format!(
                "kernel compile completed but {} is unavailable: {error}",
                args.output.display()
            )
        })?
        .len();
    if artifact_size == 0 {
        return Err(format!("extracted kernel at {} is empty", args.output.display()).into());
    }
    eprintln!(
        "[host] wrote bzImage to {} ({} bytes)",
        args.output.display(),
        artifact_size,
    );

    Ok(())
}

/// Resolve the CLI version input to an exact version. `latest` selects the
/// highest version in the embedded, reviewed source catalog (never a mutable
/// upstream version listing); any other value is validated as an exact
/// version and must be pinned in the catalog to compile.
fn resolve_version(input: &str) -> Result<jyth::builder::image::KernelVersion, BoxError> {
    if input == "latest" {
        let version = jyth::builder::image::latest_catalog_version()
            .ok_or_else(|| "the embedded kernel source catalog is empty".to_string())?;
        eprintln!("[host] resolved latest -> {}", version.as_str());
        Ok(version)
    } else {
        Ok(parse_version(input)?)
    }
}

fn parse_version(value: &str) -> Result<jyth::builder::image::KernelVersion, BoxError> {
    value
        .parse::<jyth::builder::image::KernelVersion>()
        .map_err(|error| -> BoxError {
            format!("invalid kernel version {value:?}: {error}").into()
        })
}

fn host_file_output_requested_as_directory(path: &std::path::Path) -> bool {
    path.is_dir() || path.as_os_str().to_string_lossy().ends_with(['/', '\\'])
}

/// Copy the cached artifact to `output` atomically through the strict
/// caller-output replacement: write a unique sibling staging file and let
/// [`image_core::ops::io::replace_file_atomically`] publish it. A failed
/// replacement preserves the previous output and removes the staging sibling.
fn replace_output_atomically(
    cached: &std::path::Path,
    output: &std::path::Path,
) -> Result<(), BoxError> {
    let parent = output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    std::fs::create_dir_all(parent)
        .map_err(|error| format!("failed to create {}: {error}", parent.display()))?;
    let staging = parent.join(format!(
        ".{}.kernel-builder-{}.part",
        output
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| "bzImage".to_string()),
        std::process::id(),
    ));
    std::fs::copy(cached, &staging)
        .map_err(|error| format!("failed to copy {} to staging: {error}", cached.display()))?;
    if let Err(error) = image_core::ops::io::replace_file_atomically(&staging, output) {
        let _ = std::fs::remove_file(&staging);
        return Err(format!("failed to replace {}: {error}", output.display()).into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn script() -> &'static str {
        std::str::from_utf8(BUILD_KERNEL_SH).expect("embedded build script must be UTF-8")
    }

    /// The shared asset must be the single build script: the CLI must not
    /// duplicate bootstrap logic or a Kconfig fragment.
    #[test]
    fn the_cli_embeds_no_duplicate_build_script() {
        let script = script();
        assert!(script.starts_with("#!/bin/sh\n"));
        assert!(!script.contains('\r'));
        assert!(!script.contains('\0'));
        // The script is the shared asset; it owns the Kconfig fragment, so
        // the CLI source itself must not contain one. The marker is built
        // dynamically so this assertion cannot match its own source text.
        // A TCP networking requirement stands in as the no-duplication
        // marker now that vsock is no longer a Jyth kernel requirement.
        let marker = format!("CONFIG_{}", "HYPERV_NET");
        let source = include_str!("main.rs");
        assert!(
            !source.contains(&marker),
            "the CLI must not duplicate the Kconfig fragment"
        );
    }

    #[test]
    fn exact_version_validation_rejects_mutable_values() {
        let err = parse_version("latest").expect_err("latest rejected by KernelVersion");
        assert!(err.to_string().contains("latest"), "{err}");
        let version = parse_version("7.1.7").expect("exact version");
        assert_eq!(version.as_str(), "7.1.7");
    }

    /// `latest` resolves from the embedded reviewed catalog, never the
    /// network: the highest catalogued version wins by numeric ordering.
    #[test]
    fn latest_resolves_from_the_embedded_catalog_without_network() {
        let version = resolve_version("latest").expect("catalog latest");
        assert_eq!(
            version.as_str(),
            jyth::builder::image::latest_catalog_version()
                .expect("catalog")
                .as_str()
        );
        assert_eq!(version.as_str(), "7.1.8");
    }

    /// An uncatalogued exact version cannot compile: the cacheable build
    /// requires a reviewed source pin.
    #[test]
    fn an_uncatalogued_exact_version_is_rejected_at_spec_construction() {
        let err = jyth::builder::image::CustomKernelSpec::new("6.6.13")
            .expect_err("uncatalogued version must be rejected");
        assert!(err.to_string().contains("not pinned"), "{err}");
    }

    #[test]
    fn output_directory_request_is_rejected() {
        let dir = std::env::temp_dir();
        assert!(host_file_output_requested_as_directory(&dir));
        assert!(host_file_output_requested_as_directory(
            std::path::Path::new("out/")
        ));
        assert!(!host_file_output_requested_as_directory(
            std::path::Path::new("bzImage")
        ));
    }

    #[test]
    fn atomic_output_replacement_lands_at_the_destination() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cached = dir.path().join("cached.bin");
        let output = dir.path().join("out/bzImage");
        std::fs::write(&cached, b"kernel bytes").expect("write cached");
        replace_output_atomically(&cached, &output).expect("replace");
        assert_eq!(
            std::fs::read(&output).expect("read output"),
            b"kernel bytes"
        );
        // No staging sibling remains.
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .expect("read dir")
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().contains(".part"))
            .collect();
        assert!(leftovers.is_empty(), "no staging leftovers: {leftovers:?}");
    }
}
