#[cfg(target_os = "linux")]
use std::{
    io,
    mem::{size_of, zeroed},
};

#[cfg(target_os = "linux")]
use error_stack::Report;
#[cfg(target_os = "linux")]
use libc::{AF_INET, IF_NAMESIZE, Ioctl, SOCK_DGRAM, c_short, close, socket};

use crate::errors::{InitError, InitResult};

/// Kernel ABI struct (`<linux/if.h>`), not conveniently exposed by the
/// `libc` crate for plain (non-Android) Linux targets — only the field
/// this needs (`ifr_flags`, inside the struct's union) is modeled; the
/// rest of the union's own 16-byte size (matching `struct sockaddr`, its
/// largest member) is kept as padding so the overall struct layout
/// matches the kernel's regardless of which union member the kernel
/// itself writes.
#[cfg(target_os = "linux")]
#[repr(C)]
struct IfReq {
    ifr_name: [u8; IF_NAMESIZE],
    ifr_flags: c_short,
    _ifru_padding: [u8; 16 - size_of::<c_short>()],
}

#[cfg(target_os = "linux")]
const SIOCGIFFLAGS: Ioctl = 0x8913;
#[cfg(target_os = "linux")]
const SIOCSIFFLAGS: Ioctl = 0x8914;

// Bring up the loopback interface. There's no conventional init
// system here to do this implicitly (no systemd/sysvinit/busybox
// networking scripts), and the kernel leaves `lo` administratively
// down by default — jyth's own port-forward mechanism never needed
// this (it bridges the host straight to the guest service's stdio
// over the command channel, never touching the guest's TCP stack at
// all), but any guest service that itself needs to reach
// another real TCP socket inside the guest via 127.0.0.1 — e.g. one
// process proxying to another that binds its own port, rather than
// speaking the forwarded protocol directly over stdio — silently
// can't connect at all until this runs (confirmed empirically:
// `/sys/class/net/lo/operstate` reads "down" without it, and a
// loopback connect attempt then never completes).
pub(crate) fn start_loopback() -> InitResult<()> {
    let mut ifr: IfReq = unsafe { zeroed() };
    let name = b"lo";
    ifr.ifr_name[..name.len()].copy_from_slice(name);

    let sock = unsafe { socket(AF_INET, SOCK_DGRAM, 0) };
    if sock < 0 {
        return Err(Report::new(io::Error::last_os_error()).change_context(InitError::Io));
    }
    if unsafe { libc::ioctl(sock, SIOCGIFFLAGS, &mut ifr) } < 0 {
        let error = io::Error::last_os_error();
        unsafe { close(sock) };
        return Err(Report::new(error).change_context(InitError::Io));
    }

    ifr.ifr_flags |= (libc::IFF_UP | libc::IFF_RUNNING) as c_short;

    if unsafe { libc::ioctl(sock, SIOCSIFFLAGS, &ifr) } < 0 {
        let error = io::Error::last_os_error();
        unsafe { close(sock) };
        return Err(Report::new(error).change_context(InitError::Io));
    }

    unsafe { close(sock) };
    Ok(())
}
