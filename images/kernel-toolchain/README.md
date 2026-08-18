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

1. Rebuild from the pinned base:

   ```sh
   docker build -t ksmc-quartz.local:5000/jyth/kernel-toolchain:latest images/kernel-toolchain
   ```

2. Publish the image to the Jyth registry and capture the manifest digest:

   ```sh
   docker push ksmc-quartz.local:5000/jyth/kernel-toolchain:latest
   docker manifest inspect ksmc-quartz.local:5000/jyth/kernel-toolchain:latest
   ```

   The manifest digest (the `sha256:...` in the `Docker-Content-Digest`
   header of the push, or `docker manifest inspect` output) is the immutable
   identity; the tag is never used at runtime.

3. Update `TOOLCHAIN_ROOTFS_OCI` in `libs/jyth/src/build/kernel_compile.rs`
   to the new `@sha256:` reference and land it as a reviewed source change.

4. Record the provenance in the implementation record: base digest, package
   set, build command, and the exact manifest digest used at runtime.

## Verification

The Containerfile fails the build when a required tool is missing. The guest
build script repeats the same verification before any source download, so a
broken toolchain can never start a cacheable build.
