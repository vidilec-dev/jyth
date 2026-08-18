//! Native netlink NIC configuration for the guest (TcpTransportMigrationPlan
//! WP3 variation).
//!
//! The guest's mandatory network configuration must not depend on rootfs
//! tooling: live e2e fixtures such as `debian:trixie-slim` ship neither
//! `ip` (iproute2) nor busybox, so the strict bring-up cannot use external
//! commands. This module configures the link, address, and default route
//! through raw RTNETLINK messages (the same kernel interface `ip` uses),
//! with ACKed semantics and typed errors:
//!
//! - link up: `RTM_NEWLINK` with `IFF_UP` in `ifi_flags`/`ifi_change`;
//! - address: `RTM_NEWADDR` with `IFA_LOCAL`/`IFA_ADDRESS`;
//! - route: `RTM_NEWROUTE` default via gateway with `RTA_OIF`;
//! - idempotent `EEXIST` outcomes succeed only after the effective address
//!   or route is verified through `RTM_GETADDR`/`RTM_GETROUTE` dumps.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use error_stack::Report;

use crate::errors::{InitError, InitResult};

// linux/netlink.h
const NETLINK_ROUTE: i32 = 0;
const NLM_F_REQUEST: u16 = 0x0001;
const NLM_F_ACK: u16 = 0x0004;
const NLM_F_EXCL: u16 = 0x0200;
const NLM_F_CREATE: u16 = 0x0400;
const NLMSG_ERROR: u16 = 0x2;
const NLMSG_DONE: u16 = 0x3;

// linux/rtnetlink.h
const RTM_NEWLINK: u16 = 16;
const RTM_NEWADDR: u16 = 20;
const RTM_GETADDR: u16 = 22;
const RTM_NEWROUTE: u16 = 24;
const RTM_GETROUTE: u16 = 26;

// linux/if.h
const IFF_UP: u32 = 0x0001;

// linux/if_addr.h
const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;

// linux/rtnetlink.h attributes
const IFLA_IFNAME: u16 = 3;
const RTA_DST: u16 = 1;
const RTA_OIF: u16 = 4;
const RTA_GATEWAY: u16 = 5;

const RT_SCOPE_UNIVERSE: u8 = 0;
const RT_TABLE_MAIN: u8 = 254;
const RTN_UNICAST: u8 = 1;
const AF_INET: u8 = 2;

const NLMSG_HDRLEN: usize = 16;
const IFINFOMSG_LEN: usize = 16;
const IFADDRMSG_LEN: usize = 8;
const RTMSG_LEN: usize = 12;
const ATTR_HDRLEN: usize = 4;
const MAX_MSG: usize = 4096;

fn network_config_error(message: impl Into<String>) -> Report<InitError> {
    Report::new(InitError::NetworkConfig).attach(message.into())
}

fn nlmsg_align(len: usize) -> usize {
    (len + 3) & !3
}

/// Build one netlink message: `nlmsghdr` + payload. The payload must
/// already be 4-byte aligned (attributes are padded as they are appended).
fn build_message(msg_type: u16, flags: u16, seq: u32, payload: &[u8]) -> Vec<u8> {
    let len = NLMSG_HDRLEN + payload.len();
    let mut msg = Vec::with_capacity(len);
    msg.extend_from_slice(&(len as u32).to_ne_bytes());
    msg.extend_from_slice(&msg_type.to_ne_bytes());
    msg.extend_from_slice(&flags.to_ne_bytes());
    msg.extend_from_slice(&seq.to_ne_bytes());
    msg.extend_from_slice(&0u32.to_ne_bytes()); // pid
    msg.extend_from_slice(payload);
    msg
}

/// Append one attribute (2-byte length, 2-byte type, value) to a payload,
/// padded to a 4-byte boundary.
fn push_attr(payload: &mut Vec<u8>, attr_type: u16, value: &[u8]) {
    let len = ATTR_HDRLEN + value.len();
    payload.extend_from_slice(&(len as u16).to_ne_bytes());
    payload.extend_from_slice(&attr_type.to_ne_bytes());
    payload.extend_from_slice(value);
    payload.resize(nlmsg_align(payload.len()), 0);
}

/// `struct ifinfomsg` (16 bytes).
fn ifinfomsg(ifindex: i32, flags: u32, change: u32) -> Vec<u8> {
    let mut msg = Vec::with_capacity(IFINFOMSG_LEN);
    msg.push(AF_INET); // ifi_family
    msg.push(0); // __ifi_pad
    msg.extend_from_slice(&0u16.to_ne_bytes()); // ifi_type
    msg.extend_from_slice(&ifindex.to_ne_bytes());
    msg.extend_from_slice(&flags.to_ne_bytes());
    msg.extend_from_slice(&change.to_ne_bytes());
    msg
}

/// `struct ifaddrmsg` (8 bytes).
fn ifaddrmsg(ifindex: i32, prefix_len: u8) -> Vec<u8> {
    let mut msg = Vec::with_capacity(IFADDRMSG_LEN);
    msg.push(AF_INET); // ifa_family
    msg.push(prefix_len); // ifa_prefixlen
    msg.push(0); // ifa_flags
    msg.push(0); // ifa_scope
    msg.extend_from_slice(&ifindex.to_ne_bytes());
    msg
}

/// `struct rtmsg` (12 bytes): family, dst_len, src_len, tos, table,
/// protocol, scope, type, flags.
fn rtmsg() -> Vec<u8> {
    let mut msg = Vec::with_capacity(RTMSG_LEN);
    msg.push(AF_INET); // rtm_family
    msg.push(0); // rtm_dst_len
    msg.push(0); // rtm_src_len
    msg.push(0); // rtm_tos
    msg.push(RT_TABLE_MAIN); // rtm_table
    msg.push(0); // rtm_protocol
    msg.push(RT_SCOPE_UNIVERSE); // rtm_scope
    msg.push(RTN_UNICAST); // rtm_type
    msg.extend_from_slice(&0u32.to_ne_bytes()); // rtm_flags
    msg
}

/// A connected route netlink socket.
struct RouteSocket {
    fd: OwnedFd,
}

impl RouteSocket {
    fn open() -> InitResult<Self> {
        // SAFETY: the syscalls below own the returned fd; SOCK_CLOEXEC
        // keeps the guest's spawned children from inheriting it.
        let raw = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                NETLINK_ROUTE,
            )
        };
        if raw < 0 {
            return Err(network_config_error(format!(
                "failed to open the route netlink socket: {}",
                io::Error::last_os_error()
            )));
        }
        // SAFETY: `raw` is a fresh netlink fd with no other owner.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };

        #[repr(C)]
        struct SockAddrNl {
            family: u16,
            pad: u16,
            pid: u32,
            groups: u32,
        }
        let addr = SockAddrNl {
            family: libc::AF_NETLINK as u16,
            pad: 0,
            pid: 0,
            groups: 0,
        };
        // SAFETY: `addr` is a valid sockaddr_nl of the correct length.
        let bind_result = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                (&addr as *const SockAddrNl).cast(),
                std::mem::size_of::<SockAddrNl>() as u32,
            )
        };
        if bind_result < 0 {
            return Err(network_config_error(format!(
                "failed to bind the route netlink socket: {}",
                io::Error::last_os_error()
            )));
        }
        // SAFETY: connecting to the kernel (pid 0) of NETLINK_ROUTE.
        let connect_result = unsafe {
            libc::connect(
                fd.as_raw_fd(),
                (&addr as *const SockAddrNl).cast(),
                std::mem::size_of::<SockAddrNl>() as u32,
            )
        };
        if connect_result < 0 {
            return Err(network_config_error(format!(
                "failed to connect the route netlink socket: {}",
                io::Error::last_os_error()
            )));
        }
        Ok(Self { fd })
    }

    fn send(&self, message: &[u8]) -> InitResult<()> {
        // SAFETY: `message` is a complete netlink message.
        let sent = unsafe {
            libc::send(
                self.fd.as_raw_fd(),
                message.as_ptr().cast(),
                message.len(),
                0,
            )
        };
        if sent < 0 || sent as usize != message.len() {
            return Err(network_config_error(format!(
                "netlink send failed: {}",
                io::Error::last_os_error()
            )));
        }
        Ok(())
    }

    fn recv(&self, buffer: &mut [u8]) -> InitResult<usize> {
        // SAFETY: `buffer` is a writable byte buffer.
        let n = unsafe {
            libc::recv(
                self.fd.as_raw_fd(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                0,
            )
        };
        if n < 0 {
            return Err(network_config_error(format!(
                "netlink receive failed: {}",
                io::Error::last_os_error()
            )));
        }
        Ok(n as usize)
    }
}

/// Read one message and return its header plus the byte count.
fn read_message(sock: &RouteSocket, buffer: &mut [u8]) -> InitResult<(u16, u32, u32, usize)> {
    let n = sock.recv(buffer)?;
    if n < NLMSG_HDRLEN {
        return Err(network_config_error("truncated netlink header"));
    }
    let msg_type = u16::from_ne_bytes(buffer[4..6].try_into().unwrap());
    let seq = u32::from_ne_bytes(buffer[8..12].try_into().unwrap());
    let len = u32::from_ne_bytes(buffer[0..4].try_into().unwrap());
    Ok((msg_type, seq, len, n))
}

/// Wait for the reply to `seq`: a positive ACK yields `Ok(Some(0))`, a
/// kernel error yields `Ok(Some(positive_errno))` (e.g. `EEXIST`), and a
/// missing ACK yields `Ok(None)`.
fn await_ack(sock: &RouteSocket, seq: u32) -> InitResult<Option<i32>> {
    let mut buffer = [0u8; MAX_MSG];
    loop {
        let (msg_type, reply_seq, _len, n) = read_message(sock, &mut buffer)?;
        if reply_seq != seq {
            continue;
        }
        match msg_type {
            NLMSG_ERROR => {
                // `nlmsgerr.error` is 0 on success or a negative errno.
                if n < NLMSG_HDRLEN + 4 {
                    return Err(network_config_error("truncated netlink error reply"));
                }
                let raw =
                    i32::from_ne_bytes(buffer[NLMSG_HDRLEN..NLMSG_HDRLEN + 4].try_into().unwrap());
                if raw == 0 {
                    return Ok(Some(0));
                }
                return Ok(Some(raw.unsigned_abs() as i32));
            }
            NLMSG_DONE => return Ok(None),
            _ => continue,
        }
    }
}

/// Whether the effective `eth0` address matches `guest_ip` (RTM_GETADDR for
/// the interface). `RTM_NEWADDR` reports `EEXIST` on idempotent re-runs;
/// the plan requires verifying the effective address before treating that
/// as success.
fn effective_address_matches(
    sock: &RouteSocket,
    seq: u32,
    ifindex: i32,
    guest_ip: [u8; 4],
) -> bool {
    let request = build_message(RTM_GETADDR, NLM_F_REQUEST, seq, &ifaddrmsg(ifindex, 0));
    if sock.send(&request).is_err() {
        return false;
    }
    let mut buffer = [0u8; MAX_MSG];
    loop {
        let Ok((msg_type, reply_seq, len, n)) = read_message(sock, &mut buffer) else {
            return false;
        };
        if matches!(msg_type, NLMSG_ERROR | NLMSG_DONE) {
            return false;
        }
        if reply_seq != seq {
            continue;
        }
        let mut offset = NLMSG_HDRLEN + IFADDRMSG_LEN;
        let end = n.min(len as usize);
        while offset + ATTR_HDRLEN <= end {
            let attr_len =
                u16::from_ne_bytes(buffer[offset..offset + 2].try_into().unwrap()) as usize;
            let attr_type = u16::from_ne_bytes(buffer[offset + 2..offset + 4].try_into().unwrap());
            if attr_len < ATTR_HDRLEN || offset + attr_len > end {
                break;
            }
            let value = &buffer[offset + ATTR_HDRLEN..offset + attr_len];
            if matches!(attr_type, IFA_LOCAL | IFA_ADDRESS)
                && value.len() >= 4
                && value[..4] == guest_ip
            {
                return true;
            }
            offset += nlmsg_align(attr_len);
        }
    }
}

/// Whether the effective routing table has a default route via `gateway`
/// (RTM_GETROUTE dump). Mirrors the effective-address verification for
/// idempotent route `EEXIST` outcomes.
fn effective_default_route_matches(sock: &RouteSocket, seq: u32, gateway: [u8; 4]) -> bool {
    let request = build_message(RTM_GETROUTE, NLM_F_REQUEST, seq, &rtmsg());
    if sock.send(&request).is_err() {
        return false;
    }
    let mut buffer = [0u8; MAX_MSG];
    loop {
        let Ok((msg_type, reply_seq, len, n)) = read_message(sock, &mut buffer) else {
            return false;
        };
        if matches!(msg_type, NLMSG_ERROR | NLMSG_DONE) {
            return false;
        }
        if reply_seq != seq {
            continue;
        }
        let mut offset = NLMSG_HDRLEN + RTMSG_LEN;
        let end = n.min(len as usize);
        let mut has_dst = false;
        let mut via_matches = false;
        let mut has_oif = false;
        while offset + ATTR_HDRLEN <= end {
            let attr_len =
                u16::from_ne_bytes(buffer[offset..offset + 2].try_into().unwrap()) as usize;
            let attr_type = u16::from_ne_bytes(buffer[offset + 2..offset + 4].try_into().unwrap());
            if attr_len < ATTR_HDRLEN || offset + attr_len > end {
                break;
            }
            let value = &buffer[offset + ATTR_HDRLEN..offset + attr_len];
            match attr_type {
                RTA_DST => has_dst = true,
                RTA_GATEWAY if value.len() >= 4 && value[..4] == gateway => via_matches = true,
                RTA_OIF => has_oif = true,
                _ => {}
            }
            offset += nlmsg_align(attr_len);
        }
        if !has_dst && via_matches && has_oif {
            return true;
        }
    }
}

/// `SIOCGIFINDEX` as the platform ioctl request type
/// (`_IOR('s', 0x33, int)` — 0x8933, distinct from `SIOCGIFFLAGS` 0x8913).
const SIOCGIFINDEX: libc::Ioctl = 0x8933;

/// Look up the interface index of `name` through `SIOCGIFINDEX`.
fn ifindex_of(name: &str) -> InitResult<i32> {
    // SAFETY: standard AF_INET datagram socket for interface ioctls.
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if sock < 0 {
        return Err(network_config_error("failed to open a control socket"));
    }
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    let name_bytes = name.as_bytes();
    if name_bytes.len() >= ifr.ifr_name.len() {
        unsafe { libc::close(sock) };
        return Err(network_config_error(format!(
            "interface name too long: {name}"
        )));
    }
    for (dst, &src) in ifr.ifr_name.iter_mut().zip(name_bytes) {
        *dst = src as libc::c_char;
    }
    // SAFETY: `ifr` is a valid ifreq with the interface name set.
    let result = unsafe { libc::ioctl(sock, SIOCGIFINDEX, &mut ifr) };
    unsafe { libc::close(sock) };
    if result < 0 {
        return Err(network_config_error(format!(
            "failed to resolve the interface index of {name}"
        )));
    }
    // SAFETY: on success the ioctl filled `ifr_ifru.ifru_ifindex`.
    Ok(unsafe { ifr.ifr_ifru.ifru_ifindex })
}

/// Bring the interface up (`RTM_NEWLINK` with `IFF_UP` in flags and change).
pub(crate) fn link_up(name: &str) -> InitResult<()> {
    let sock = RouteSocket::open()?;
    let seq = 1;
    let ifindex = ifindex_of(name)?;
    let mut payload = ifinfomsg(ifindex, IFF_UP, IFF_UP);
    push_attr(&mut payload, IFLA_IFNAME, name.as_bytes());
    let request = build_message(RTM_NEWLINK, NLM_F_REQUEST | NLM_F_ACK, seq, &payload);
    sock.send(&request)?;
    let outcome = await_ack(&sock, seq)?;
    match outcome {
        Some(0) | None => Ok(()),
        Some(errno) => Err(network_config_error(format!(
            "failed to bring {name} up (netlink errno {errno})"
        ))),
    }
}

/// Assign `guest_ip/prefix` to the interface (idempotent).
pub(crate) fn assign_address(
    name: &str,
    guest_ip: std::net::Ipv4Addr,
    prefix_len: u8,
) -> InitResult<()> {
    let sock = RouteSocket::open()?;
    let seq = 2;
    let ifindex = ifindex_of(name)?;
    let ip_bytes = guest_ip.octets();
    let mut payload = ifaddrmsg(ifindex, prefix_len);
    push_attr(&mut payload, IFA_LOCAL, &ip_bytes);
    push_attr(&mut payload, IFA_ADDRESS, &ip_bytes);
    let request = build_message(
        RTM_NEWADDR,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        seq,
        &payload,
    );
    sock.send(&request)?;
    let outcome = await_ack(&sock, seq)?;
    match outcome {
        Some(0) | None => Ok(()),
        Some(errno) if errno == libc::EEXIST => {
            // Idempotent re-run: succeed only when the effective address is
            // present on the interface.
            if effective_address_matches(&sock, 3, ifindex, ip_bytes) {
                Ok(())
            } else {
                Err(network_config_error(format!(
                    "{guest_ip} is not effective on {name}"
                )))
            }
        }
        Some(_) => Err(network_config_error(format!(
            "failed to assign {guest_ip}/{prefix_len} to {name}"
        ))),
    }
}

/// Install the default route via `gateway` on `name` (idempotent).
pub(crate) fn set_default_route(name: &str, gateway: std::net::Ipv4Addr) -> InitResult<()> {
    let sock = RouteSocket::open()?;
    let seq = 4;
    let ifindex = ifindex_of(name)?;
    let gw_bytes = gateway.octets();
    let mut payload = rtmsg();
    // A default route is identified by the *absence* of RTA_DST; the
    // kernel rejects an empty RTA_DST as an invalid attribute length.
    push_attr(&mut payload, RTA_GATEWAY, &gw_bytes);
    push_attr(&mut payload, RTA_OIF, &ifindex.to_ne_bytes());
    let request = build_message(
        RTM_NEWROUTE,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        seq,
        &payload,
    );
    sock.send(&request)?;
    let outcome = await_ack(&sock, seq)?;
    match outcome {
        Some(0) | None => Ok(()),
        Some(errno) if errno == libc::EEXIST => {
            // Idempotent re-run: verify the effective default route.
            if effective_default_route_matches(&sock, 5, gw_bytes) {
                Ok(())
            } else {
                Err(network_config_error(format!(
                    "default route via {gateway} is not effective"
                )))
            }
        }
        Some(_) => Err(network_config_error(format!(
            "failed to install the default route via {gateway}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_builder_produces_an_aligned_frame() {
        let msg = build_message(RTM_NEWLINK, NLM_F_REQUEST, 7, &[0u8; 8]);
        assert_eq!(msg.len() % 4, 0, "netlink messages must stay aligned");
        let len = u32::from_ne_bytes(msg[0..4].try_into().unwrap());
        assert_eq!(len as usize, msg.len());
        let seq = u32::from_ne_bytes(msg[8..12].try_into().unwrap());
        assert_eq!(seq, 7);
    }

    #[test]
    fn attribute_append_keeps_payload_aligned() {
        let mut payload = ifaddrmsg(1, 24);
        push_attr(&mut payload, IFA_LOCAL, &[10, 77, 0, 10]);
        push_attr(&mut payload, IFA_ADDRESS, &[10, 77, 0, 10]);
        assert_eq!(payload.len() % 4, 0);
        let msg = build_message(RTM_NEWADDR, NLM_F_REQUEST, 9, &payload);
        assert_eq!(msg.len() % 4, 0);
    }

    #[test]
    fn wire_struct_sizes_match_the_kernel_layouts() {
        assert_eq!(ifinfomsg(1, 0, 0).len(), IFINFOMSG_LEN);
        assert_eq!(ifaddrmsg(1, 24).len(), IFADDRMSG_LEN);
        assert_eq!(rtmsg().len(), RTMSG_LEN);
    }
}
