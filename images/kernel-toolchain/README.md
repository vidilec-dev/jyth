# Jyth kernel-toolchain image

The immutable rootfs used to compile custom kernels inside the bootstrap VM.
This image contains the complete kernel build toolchain so a cacheable
custom-kernel build performs **no runtime package installation** and no
mutable `latest` resolution. The bootstrap VM downloads only the pinned kernel
source archive, verifies its SHA-256 digest, and compiles it.

## Contents

- `Containerfile` — the image recipe: a pinned Alpine base digest plus the
  exact package set, installed at build time.
- `packages.lock` — the exact package set, kept in sync with the Containerfile
  and with `libs/jyth/assets/kernel-build/build_kernel.sh`.

## Rebuild and publish procedure

The image is consumed only by OCI manifest digest, so every rebuild changes
the digest and requires a source change that records the new digest in
`libs/jyth/src/build/kernel_compile.rs` (`TOOLCHAIN_ROOTFS_OCI`).

Publication is automated by the GitHub Actions workflow
`.github/workflows/publish-toolchain.yml`, which owns the build and the
digest update:

1. The workflow triggers on any change under `images/kernel-toolchain/` (or
   via manual `workflow_dispatch`), builds the `Containerfile` with Buildx,
   and pushes the immutable manifest to the Jyth GHCR repository:

   ```text
   ghcr.io/vidilec-dev/jyth/kernel-toolchain:latest
   ```

2. The workflow opens a reviewed PR that records the new manifest digest in
   `TOOLCHAIN_ROOTFS_OCI` as `ghcr.io/vidilec-dev/jyth/kernel-toolchain@sha256:...`.

   The manifest digest (the `sha256:...` in the `Docker-Content-Digest`
   header of the push, or `docker manifest inspect` output) is the immutable
   identity; the tag is never used at runtime.

3. Merge that PR as a reviewed source change, and record the provenance in
   the implementation record: base digest, package set, build command, and
   the exact manifest digest used at runtime.

To rebuild manually without waiting for a source change, run the workflow
with `workflow_dispatch` on `main`.

## Verification

The Containerfile fails the build when a required tool is missing. The guest
build script repeats the same verification before any source download, so a
broken toolchain can never start a cacheable build.
