#!/bin/sh
# Injected into the Jyth kernel-toolchain guest by kernel-builder; keep POSIX
# syntax and LF endings.
#
# Interface (Jyth review remediation WP2):
#   build-kernel.sh <version> <source-url> <sha256> [complete-config-path]
#
# The toolchain image already contains the complete package set: this script
# performs NO package installation and resolves NO mutable version listing.
# The source archive is selected only by the pinned SHA-256 digest and is
# verified before extraction.
set -eu

KERNEL_VERSION="${1:-}"
SOURCE_URL="${2:-}"
EXPECTED_SHA256="${3:-}"
HOST_CONFIG_PATH="${4:-}"

BUILD_DIR=/build
OUT="$BUILD_DIR/out"
ARTIFACTS="$BUILD_DIR/artifacts"

# The bootstrap process does not inherit a guaranteed PATH.
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# Every argument is validated before any network access.
case "$KERNEL_VERSION" in
    ''|.*|*.|*..*|*[!0-9.]*)
        echo "[build] invalid stable kernel version: $KERNEL_VERSION" >&2
        exit 1
        ;;
esac

case "$SOURCE_URL" in
    https://*) ;;
    *)
        echo "[build] source URL must be HTTPS: $SOURCE_URL" >&2
        exit 1
        ;;
esac

case "$EXPECTED_SHA256" in
    *[!0-9a-f]*)
        echo "[build] expected SHA-256 must be 64 lowercase hexadecimal characters" >&2
        exit 1
        ;;
esac
[ "${#EXPECTED_SHA256}" -eq 64 ] || {
    echo "[build] expected SHA-256 must be 64 lowercase hexadecimal characters" >&2
    exit 1
}

# The toolchain image is trusted only when it contains every required tool:
# fail before any source byte is downloaded when one is missing.
for tool in \
    gcc \
    make \
    bash \
    bc \
    bison \
    flex \
    perl \
    tar \
    wget \
    xz \
    sha256sum \
    getconf \
    grep \
    sed \
    awk
do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "[build] missing required tool: $tool" >&2
        exit 1
    }
done
[ -f /usr/include/asm/types.h ] || {
    echo "[build] missing required header: /usr/include/asm/types.h" >&2
    exit 1
}
[ -f /usr/include/libelf.h ] || {
    echo "[build] missing required header: /usr/include/libelf.h" >&2
    exit 1
}

MAJOR=${KERNEL_VERSION%%.*}
TARBALL="linux-$KERNEL_VERSION.tar.xz"
SRC="$BUILD_DIR/linux-$KERNEL_VERSION"

rm -rf "$SRC" "$OUT" "$ARTIFACTS"
mkdir -p "$OUT" "$ARTIFACTS"

echo "[build] downloading $SOURCE_URL"
wget -qO "$BUILD_DIR/$TARBALL" "$SOURCE_URL"

# The archive is verified before tar reads a single byte; a mismatch removes
# the archive and stops the build.
ACTUAL_SHA256=$(sha256sum "$BUILD_DIR/$TARBALL" | awk '{print $1}')
if [ "$ACTUAL_SHA256" != "$EXPECTED_SHA256" ]; then
    rm -f "$BUILD_DIR/$TARBALL"
    echo "[build] source digest mismatch: expected $EXPECTED_SHA256, got $ACTUAL_SHA256" >&2
    exit 1
fi
echo "[build] source digest verified"
tar -C "$BUILD_DIR" -xf "$BUILD_DIR/$TARBALL"
rm -f "$BUILD_DIR/$TARBALL"

if [ -n "$HOST_CONFIG_PATH" ]; then
    [ -f "$HOST_CONFIG_PATH" ] || {
        echo "[build] custom configuration not found: $HOST_CONFIG_PATH" >&2
        exit 1
    }
    echo "[build] using custom configuration from $HOST_CONFIG_PATH"
    cp "$HOST_CONFIG_PATH" "$OUT/.config"
    make -C "$SRC" O="$OUT" olddefconfig
else
    # Start from allnoconfig so the output contains only the facilities used by
    # Jyth's Windows/HCS backend, guest init, NAT NIC, and attached VHDX disks.
    CONFIG_FRAGMENT="$BUILD_DIR/jyth.config"
    cat > "$CONFIG_FRAGMENT" <<'EOF'
# Small, built-in-only x86_64 kernel.
CONFIG_64BIT=y
CONFIG_X86_64=y
CONFIG_CC_OPTIMIZE_FOR_SIZE=y
CONFIG_KERNEL_XZ=y
CONFIG_MODULES=n
CONFIG_RELOCATABLE=y
CONFIG_EXPERT=y

# ACPI is required for Hyper-V VMBus device enumeration: without it the
# VMBus root device is never discovered, channel offers never arrive, and
# the guest stalls before init (no hv_netvsc/hv_storvsc channels).
CONFIG_ACPI=y
# The Hyper-V DSDT declares PCI-config-space and PNP operation regions;
# without PCI/PNP support the ACPI tables fail to load (AE_BAD_PARAMETER
# during region initialization) and VMBus never negotiates.
CONFIG_PCI=y
CONFIG_PNP=y
CONFIG_PNPACPI=y
# devtmpfs auto-mount keeps /dev populated (the initramfs rootfs is ramfs;
# no tmpfs mount is needed by the guest).
CONFIG_DEVTMPFS_MOUNT=y
# Hyper-V utilities (hv_utils) keep the guest aligned with the host.
CONFIG_HYPERV_UTILS=y

# The default x86_64 ORC unwinder builds host objtool and needs libelf plus
# host UAPI headers. Jyth does not consume kernel stack traces; the no-overhead
# guess unwinder keeps those optional host dependencies out of the builder.
# objtool is still compiled by the x86 build for stack validation, so the
# toolchain installs linux-headers (asm/types.h) and elfutils-dev (libelf.h).
CONFIG_UNWINDER_ORC=n
CONFIG_UNWINDER_GUESS=y
CONFIG_STACK_VALIDATION=n

# Jyth's gzip-compressed initramfs and guest processes.
CONFIG_PRINTK=y
CONFIG_BLK_DEV_INITRD=y
CONFIG_RD_GZIP=y
CONFIG_BINFMT_ELF=y
CONFIG_BINFMT_SCRIPT=y
CONFIG_POSIX_TIMERS=y
CONFIG_FUTEX=y
CONFIG_EPOLL=y
CONFIG_EVENTFD=y
CONFIG_SIGNALFD=y
CONFIG_TIMERFD=y

# Filesystems mounted directly by libs/init.
CONFIG_SYSCTL=y
CONFIG_PROC_FS=y
CONFIG_PROC_SYSCTL=y
CONFIG_SYSFS=y
CONFIG_DEVTMPFS=y

# COM0 logs and the protected COM1 boot exchange.
CONFIG_TTY=y
CONFIG_SERIAL_8250=y
CONFIG_SERIAL_8250_CONSOLE=y
CONFIG_SERIAL_8250_NR_UARTS=4
CONFIG_SERIAL_8250_RUNTIME_UARTS=4

# Jyth's HCS guest drivers. These must be built in because the emitted
# artifact intentionally has no matching /lib/modules tree.
CONFIG_HYPERVISOR_GUEST=y
CONFIG_HYPERV=y
# Linux 7 split VMBus out of CONFIG_HYPERV. Older supported kernels ignore
# this unknown symbol and keep VMBus under CONFIG_HYPERV.
CONFIG_HYPERV_VMBUS=y
CONFIG_NET=y

# Jyth NAT networking and the TCP command transport (the guest binds the
# configured NIC address; the host connects over the virtual NIC).
CONFIG_INET=y
CONFIG_NETDEVICES=y
CONFIG_HYPERV_NET=y

# Jyth VHDX disks, mounted as ext4 by libs/init.
CONFIG_BLOCK=y
CONFIG_SCSI=y
CONFIG_BLK_DEV_SD=y
CONFIG_SCSI_LOWLEVEL=y
CONFIG_HYPERV_STORAGE=y
CONFIG_EXT4_FS=y
EOF

    echo "[build] generating minimal Jyth configuration"
    make \
        -C "$SRC" \
        O="$OUT" \
        KCONFIG_ALLCONFIG="$CONFIG_FRAGMENT" \
        allnoconfig
fi

# Kconfig silently ignores requests whose dependencies are unavailable. Fail
# before the expensive compile if a facility required by Jyth was dropped.
require_builtin_config() {
    option=$1
    grep -q "^${option}=y$" "$OUT/.config" || {
        echo "[build] required kernel option ${option}=y is missing" >&2
        exit 1
    }
}

for option in \
    CONFIG_64BIT \
    CONFIG_ACPI \
    CONFIG_PCI \
    CONFIG_RELOCATABLE \
    CONFIG_UNWINDER_GUESS \
    CONFIG_PRINTK \
    CONFIG_BLK_DEV_INITRD \
    CONFIG_RD_GZIP \
    CONFIG_BINFMT_ELF \
    CONFIG_BINFMT_SCRIPT \
    CONFIG_POSIX_TIMERS \
    CONFIG_FUTEX \
    CONFIG_EPOLL \
    CONFIG_EVENTFD \
    CONFIG_SIGNALFD \
    CONFIG_TIMERFD \
    CONFIG_SYSCTL \
    CONFIG_PROC_FS \
    CONFIG_PROC_SYSCTL \
    CONFIG_SYSFS \
    CONFIG_DEVTMPFS \
    CONFIG_TTY \
    CONFIG_SERIAL_8250 \
    CONFIG_SERIAL_8250_CONSOLE \
    CONFIG_HYPERVISOR_GUEST \
    CONFIG_HYPERV \
    CONFIG_NET \
    CONFIG_INET \
    CONFIG_NETDEVICES \
    CONFIG_HYPERV_NET \
    CONFIG_BLOCK \
    CONFIG_SCSI \
    CONFIG_BLK_DEV_SD \
    CONFIG_HYPERV_STORAGE \
    CONFIG_EXT4_FS
do
    require_builtin_config "$option"
done

if grep -q '^config HYPERV_VMBUS$' "$SRC/drivers/hv/Kconfig"; then
    require_builtin_config CONFIG_HYPERV_VMBUS
fi

JOBS=$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1)

# Linux 6.6's x86 boot code is not C23-clean. Alpine's GCC 15 defaults to
# GNU23, so append GNU11 after Kbuild's flags for every compiler invocation.
CC_WRAPPER="$BUILD_DIR/gcc-gnu11"
cat > "$CC_WRAPPER" <<'EOF'
#!/bin/sh
exec /usr/bin/gcc "$@" -std=gnu11
EOF
chmod +x "$CC_WRAPPER"

echo "[build] building bzImage with $JOBS jobs"
make \
    -C "$SRC" \
    O="$OUT" \
    -j"$JOBS" \
    CC="$CC_WRAPPER" \
    bzImage

cp "$OUT/arch/x86/boot/bzImage" "$ARTIFACTS/bzImage"
echo "[build] wrote $ARTIFACTS/bzImage"
