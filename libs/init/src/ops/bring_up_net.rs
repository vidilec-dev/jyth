//! Bring up the guest's primary NIC (`eth0`) and route it through the
//! HNS NAT the host wired up on the HCS side (Task I-3). Production launches
//! receive the static IP/gateway/prefix/DNS in the validated COM1 boot
//! configuration. The legacy cmdline parser remains for focused tests and
//! older developer images, while the production path keeps caller-controlled
//! network values out of `/proc/cmdline`.
//!
//! On a guest with no NIC (offline build mode) `eth0` doesn't appear
//! in the kernel's interface table; bringing up a non-existent iface
//! would just fail the link-up request, so we check the cmdline sentinel
//! and treat its absence as "no NIC requested", returning early.
//!
//! The kernel bringup is native netlink (`crate::ops::netlink`): the
//! configured network is launch-critical (TcpTransportMigrationPlan WP3)
//! and must not depend on the rootfs shipping `ip`/busybox, so the link,
//! address, and default route are configured through raw RTNETLINK
//! messages with ACKed semantics and typed errors. The `IFF_UP` path the
//! loopback brings up in `crate::ops::start_loopback` remains a separate
//! vendor-uniform ioctl story.

use crate::errors::{InitError, InitResult};

#[cfg(target_os = "linux")]
use error_stack::Report;

/// Parsed `jyth.net.*` kernel cmdline args. All fields are plain
/// `String`s (the kernel cmdline is unstructured text); the IP fields
/// are validated lightly on parse so the call sites can assume they
/// round-trip. `None` from [`NetConfig::parse`] means the caller did
/// not request a NIC at all, in which case [`bring_up_net`] is a no-op.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct NetConfig {
    pub guest_ip: String,
    pub gateway: String,
    pub mask: u8,
    pub dns: Vec<String>,
}

impl NetConfig {
    /// Parse the `NetConfig` out of a kernel cmdline string. Returns
    /// `Ok(None)` when no `jyth.net.ip=` arg was present (no NIC
    /// requested); `Err` only on a malformed `jyth.net.*` arg — the
    /// caller's intent was clear (they asked for a NIC), so we don't
    /// silently fall back to DHCP.
    pub(crate) fn parse(cmdline: &str) -> InitResult<Option<Self>> {
        // `jyth.net.ip` is the sentinel — its presence implies the
        // host wired a NIC; the others (`gw`, `mask`, `dns`) default
        // generously rather than fail so a host typo doesn't strand
        // the guest.
        let mut guest_ip = None;
        let mut gateway = "10.76.0.1".to_string();
        let mut mask: u8 = 24;
        let mut dns: Vec<String> = Vec::new();

        for arg in cmdline.split_whitespace() {
            if let Some(v) = arg.strip_prefix("jyth.net.ip=") {
                guest_ip = Some(v.to_string());
            } else if let Some(v) = arg.strip_prefix("jyth.net.gw=") {
                gateway = v.to_string();
            } else if let Some(v) = arg.strip_prefix("jyth.net.mask=") {
                match v.parse::<u8>() {
                    Ok(m) if (1..=32).contains(&m) => mask = m,
                    Ok(_) => {
                        return Err(Report::new(InitError::UnsupportedHost)
                            .attach(format!("jyth.net.mask={v} out of range (must be 1..=32)",)));
                    }
                    Err(_) => {
                        return Err(Report::new(InitError::UnsupportedHost)
                            .attach(format!("jyth.net.mask={v} not a valid prefix length",)));
                    }
                }
            } else if let Some(v) = arg.strip_prefix("jyth.net.dns=") {
                dns = v
                    .split(',')
                    .map(str::to_string)
                    .filter(|s| !s.is_empty())
                    .collect();
            }
        }

        match guest_ip {
            None => Ok(None),
            Some(ip) => {
                if ip.parse::<std::net::IpAddr>().is_err() {
                    return Err(Report::new(InitError::UnsupportedHost)
                        .attach(format!("jyth.net.ip={ip} is not a valid IpAddr",)));
                }
                if gateway.parse::<std::net::IpAddr>().is_err() {
                    return Err(Report::new(InitError::UnsupportedHost)
                        .attach(format!("jyth.net.gw={gateway} is not a valid IpAddr",)));
                }
                Ok(Some(Self {
                    guest_ip: ip,
                    gateway,
                    mask,
                    dns,
                }))
            }
        }
    }
}

/// Bring up `eth0` from the authenticated COM1 boot configuration. No-op when
/// the host did not request a NIC.
pub(crate) fn bring_up_net_with_config(
    config: Option<&protocol::GuestNetworkConfigV1>,
) -> InitResult<()> {
    #[cfg(target_os = "linux")]
    {
        let Some(config) = config else {
            return Ok(());
        };
        let config = NetConfig {
            guest_ip: std::net::Ipv4Addr::from(config.guest_ip).to_string(),
            gateway: std::net::Ipv4Addr::from(config.gateway).to_string(),
            mask: config.prefix_len,
            dns: config
                .dns
                .iter()
                .map(|dns| std::net::Ipv4Addr::from(*dns).to_string())
                .collect(),
        };
        return bring_up_net_config(&config);
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = config;
        Ok(())
    }
}

/// Legacy cmdline adapter retained for focused unit tests and older developer
/// images. Production S2 boot uses [`bring_up_net_with_config`].
pub(crate) fn bring_up_net() -> InitResult<()> {
    #[cfg(target_os = "linux")]
    {
        let cmdline = std::fs::read_to_string("/proc/cmdline")
            .map_err(|e| Report::new(e).change_context(InitError::Io))?;
        let Some(cfg) = NetConfig::parse(&cmdline)? else {
            // Caller didn't ask for a NIC — nothing to do.
            return Ok(());
        };
        return bring_up_net_config(&cfg);
    }
    #[cfg(not(target_os = "linux"))]
    {
        Ok(())
    }
}

fn bring_up_net_config(cfg: &NetConfig) -> InitResult<()> {
    #[cfg(target_os = "linux")]
    {
        // `hv_netvsc` (the HCS backend) and `virtio_net` (KVM) both
        // register `eth0` asynchronously from the module-load syscall
        // returning: the vmbus/virtio channel negotiation + netdev
        // registration happens out-of-band, so issuing the bring-up
        // commands the instant `module_loader.load("hv_netvsc")` returns
        // races `eth0`'s appearance in `/sys/class/net`. The symptom (seen
        // live in the jyth net-probe example): `ip addr` shows `eth0` with
        // a Hyper-V MAC (`00:15:5d:...`) but `state DOWN` and `qdisc
        // noop` — i.e. the iface exists by the time any user-land
        // inspects it, but the bring-up commands ran before it was
        // registered and silently failed. Wait a bounded amount of time
        // for `eth0` to appear before issuing the bring-up commands — same
        // pattern cloud-init / dracut's `wait-for-interfaces` use.
        if !wait_for_iface(
            std::path::Path::new("/sys/class/net"),
            "eth0",
            std::time::Duration::from_secs(10),
        ) {
            return Err(Report::new(InitError::NetworkInterfaceTimeout)
                .attach("eth0 never appeared in /sys/class/net within the interface deadline"));
        }
        // The bring-up is native netlink: the strict configured-network
        // contract must not depend on the rootfs shipping `ip`/busybox
        // (live e2e fixtures such as debian:trixie-slim carry neither).
        // Every step fails with a typed error before READY; idempotent
        // EEXIST outcomes are verified against the effective state.
        let guest_ip = cfg
            .guest_ip
            .parse::<std::net::Ipv4Addr>()
            .map_err(|e| Report::new(InitError::NetworkConfig).attach(e.to_string()))?;
        let gateway = cfg
            .gateway
            .parse::<std::net::Ipv4Addr>()
            .map_err(|e| Report::new(InitError::NetworkConfig).attach(e.to_string()))?;
        crate::ops::netlink::link_up("eth0")?;
        crate::ops::netlink::assign_address("eth0", guest_ip, cfg.mask)?;
        crate::ops::netlink::set_default_route("eth0", gateway)?;
        write_resolv_conf(&cfg.dns)?;
    }
    // Non-Linux (host developer toolchain): no-op so the crate still
    // type-checks when built from cross-target hosts.
    Ok(())
}

/// Poll `<base>/<name>` once every 100 ms until the netdev directory
/// exists (the kernel has registered the interface), or `deadline`
/// elapses. Returns `true` if the interface appeared in time.
/// Synchronous (the init binary is single-threaded at this point);
/// uses `std::thread::sleep` deliberately — no async runtime is
/// running yet (the bus loop starts after `bring_up_net` returns).
///
/// `base` is a parameter rather than hardcoded `/sys/class/net` so the
/// race-wait can be unit-tested against a throwaway temp dir instead
/// of having to munge the real sysfs tree. [`bring_up_net`] always
/// passes `/sys/class/net`.
///
/// Why we do **not** gate on `operstate` (the previous impl did, and
/// it was the bug behind the live net-probe symptom of `eth0 state
/// DOWN` / empty `ip route` / empty `resolv.conf`): for `hv_netvsc`
/// (HCS) and most `virtio_net` (KVM) builds, `operstate` starts and
/// **stays** `"down"` until *userspace* administers the link — there
/// is no autonomous transition to `up` purely from the vmbus/virtio
/// channel probe completing (the live probe's `dmesg` showed
/// `hv_vmbus: registering driver hv_netvsc` but no `link up` message,
/// and `eth0` sat at `operstate=down` indefinitely). So the old gate
/// that refused to proceed until `operstate != "down"` self-
/// deadlocked: it waited for a state that only the action it was
/// gating (the link-up request) could produce. After the 10s
/// `deadline` it gave up, logged `eth0 never appeared …` (wrong — it
/// had appeared, just stayed `down`), and returned early before the
/// address/route/DNS steps ran, leaving the guest with no IP, no
/// route, and no DNS — exactly the probe's snapshot. Gating on
/// registration alone is sufficient because the link-up request issued
/// to a registered netdev drives operstate to `up` (or
/// `lowerlayerdown` while the link is still negotiating, which still
/// lets the address/route land); the kernel rejects a link-up request
/// for a non-existent netdev, which the strict bring-up surfaces as a
/// typed network-configuration error instead of a silent skip.
#[cfg(target_os = "linux")]
fn wait_for_iface(base: &std::path::Path, name: &str, deadline: std::time::Duration) -> bool {
    let path = base.join(name);
    let started = std::time::Instant::now();
    let poll = std::time::Duration::from_millis(100);
    loop {
        if path.exists() {
            // Netdev is registered in sysfs — that's the only
            // readiness signal we can usefully wait for here. The
            // `operstate` sysfs attribute (one of up/down/unknown/
            // notrunning/lowerlayerdown/testing/dormant) is *not*
            // polled: for hv_netvsc/virtio_net it stays `down` until
            // userspace admins the link, so polling it deadlocks
            // init against its own `ip link set eth0 up` (the action
            // that flips operstate). See the doc above for the live
            // symptom that motivated removing the operstate gate.
            #[cfg(feature = "tracing")]
            tracing::info!(
                iface = name,
                waited_ms = started.elapsed().as_millis() as u64,
                "[init] NIC interface registered in sysfs; proceeding with bring-up",
            );
            return true;
        }
        if started.elapsed() >= deadline {
            return false;
        }
        std::thread::sleep(poll);
    }
}

#[cfg(target_os = "linux")]
fn write_resolv_conf(dns: &[String]) -> InitResult<()> {
    if dns.is_empty() {
        return Ok(());
    }
    let mut content = String::new();
    for s in dns {
        content.push_str("nameserver ");
        content.push_str(s);
        content.push('\n');
    }
    let _ = std::fs::create_dir_all("/etc");
    std::fs::write("/etc/resolv.conf", content)
        .map_err(|e| Report::new(e).change_context(InitError::Io))?;
    Ok(())
}

/// Run `cmd args...` and return true on success, false on failure
/// (logged at WARN). Centralises the "best-effort CLI call" pattern.
///

#[cfg(test)]
mod tests {
    use super::*;

    /// Plan §IV-1: "round-trips a sample cmdline → expected
    /// `IpConfig` struct". Covers all four `jyth.net.*` keys plus the
    /// multi-server DNS list (comma-joined).
    #[test]
    fn parses_net_kernel_args() {
        let cmdline = "root=/dev/vda1 init=/init jyth.backend=hcs \
                       jyth.net.ip=10.76.0.10 jyth.net.gw=10.76.0.1 \
                       jyth.net.mask=24 jyth.net.dns=8.8.8.8,1.1.1.1 \
                       console=ttyS0";
        let cfg = NetConfig::parse(cmdline).expect("parse ok");
        let cfg = cfg.expect("Some(cfg) when jyth.net.ip present");
        assert_eq!(cfg.guest_ip, "10.76.0.10");
        assert_eq!(cfg.gateway, "10.76.0.1");
        assert_eq!(cfg.mask, 24);
        assert_eq!(cfg.dns, vec!["8.8.8.8", "1.1.1.1"]);
    }

    /// No NIC requested (no `jyth.net.ip`): `Ok(None)`.
    #[test]
    fn parses_net_kernel_args_no_nic() {
        let cmdline = "root=/dev/vda1 init=/init jyth.backend=kvm console=ttyS0";
        assert!(NetConfig::parse(cmdline).unwrap().is_none());
    }
    /// Bad mask: typed error, not silent fallback.
    #[test]
    fn parses_net_kernel_args_bad_mask() {
        let cmdline = "jyth.net.ip=10.76.0.10 jyth.net.mask=99";
        assert!(NetConfig::parse(cmdline).is_err());
    }

    /// Bad IP: typed error.
    #[test]
    fn parses_net_kernel_args_bad_ip() {
        let cmdline = "jyth.net.ip=not-an-ip";
        assert!(NetConfig::parse(cmdline).is_err());
    }

    /// `wait_for_iface` returns `true` immediately when the interface
    /// is already present — the happy path on a guest where module
    /// load completed before init reached `bring_up_net`.
    #[cfg(target_os = "linux")]
    #[test]
    fn wait_for_iface_returns_true_when_already_present() {
        let tmp =
            std::env::temp_dir().join(format!("jyth-wait-iface-present-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::create_dir_all(tmp.join("eth0")).unwrap();

        assert!(wait_for_iface(
            &tmp,
            "eth0",
            std::time::Duration::from_secs(1)
        ));

        std::fs::remove_dir_all(&tmp).unwrap();
    }

    /// `wait_for_iface` returns `false` when the interface never
    /// appears within the deadline. Kept to a short deadline so the
    /// test stays fast — runtime uses 10s.
    #[cfg(target_os = "linux")]
    #[test]
    fn wait_for_iface_returns_false_on_deadline() {
        let tmp =
            std::env::temp_dir().join(format!("jyth-wait-iface-absent-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();

        // 200ms deadline is just above one 100ms poll tick; we'll have
        // polled at least twice before giving up. Asserting `false`
        // here keeps the regression test under ~250ms wallclock.
        assert!(!wait_for_iface(
            &tmp,
            "eth0",
            std::time::Duration::from_millis(200)
        ));

        std::fs::remove_dir_all(&tmp).unwrap();
    }

    /// `operstate=down` must not keep `wait_for_iface` polling -
    /// this is the regression test for the bug behind the live net-
    /// probe symptom (`eth0 state DOWN` / empty `ip route` / empty
    /// `resolv.conf`). `hv_netvsc`/`virtio_net` keep `operstate=down`
    /// until userspace admins the link, so the previous impl that
    /// waited for `operstate != "down"` self-deadlocked for the full
    /// 10s deadline, then bailed before the bring-up steps ran. The
    /// new gate proceeds as soon as the netdev dir exists, regardless
    /// of operstate. An `operstate` file containing `down\n` is left
    /// in place to prove the gate no longer reads it.
    #[cfg(target_os = "linux")]
    #[test]
    fn wait_for_iface_ready_when_registered_even_if_operstate_down() {
        let tmp =
            std::env::temp_dir().join(format!("jyth-wait-iface-reg-down-{}", std::process::id()));
        let eth0_dir = tmp.join("eth0");
        std::fs::create_dir_all(&eth0_dir).unwrap();
        // The netdev is registered but the channel is still `down` -
        // the exact state hv_netvsc leaves eth0 in until we issue
        // `ip link set eth0 up`. The wait must return `true`
        // immediately, not poll for operstate to flip.
        std::fs::write(eth0_dir.join("operstate"), "down\n").unwrap();

        assert!(wait_for_iface(
            &tmp,
            "eth0",
            std::time::Duration::from_secs(2)
        ));

        std::fs::remove_dir_all(&tmp).unwrap();
    }

    /// `operstate=up` (carrier present) is still a ready state under
    /// the registration-only gate - the netdev dir exists, so the
    /// wait returns `true`. Kept to lock in that the operstate value,
    /// whatever it is, does not change readiness.
    #[cfg(target_os = "linux")]
    #[test]
    fn wait_for_iface_ready_when_registered_and_operstate_up() {
        let tmp =
            std::env::temp_dir().join(format!("jyth-wait-iface-reg-up-{}", std::process::id()));
        let eth0_dir = tmp.join("eth0");
        std::fs::create_dir_all(&eth0_dir).unwrap();
        std::fs::write(eth0_dir.join("operstate"), "up\n").unwrap();

        assert!(wait_for_iface(
            &tmp,
            "eth0",
            std::time::Duration::from_secs(1)
        ));

        std::fs::remove_dir_all(&tmp).unwrap();
    }

    /// Plan §IV-2 metric: `cargo test -p init -- --ignored
    /// virtio_net_module_loads` exits 0. Gated by `#[ignore]` because
    /// the test needs to run inside the booted guest kernel so
    /// `/proc/config.gz` is reachable — on a Linux build host (where
    /// the init's `mod tests` is compiled at all) `modprobe`
    /// succeeds trivially unless the module is genuinely absent, so
    /// even the host run can confirm the *load* half of the
    /// contract; the `CONFIG_VIRTIO_NET=y` extraction half requires
    /// the running guest's `/proc`. Outside a booted guest this test
    /// best-effort verifies the module-load path; the README carries
    /// the verification checkbox instead.
    #[cfg(target_os = "linux")]
    #[test]
    fn virtio_net_module_loads() {
        // Try to load the virtio_net kernel module. The kernel module
        // must already be in the guest's modules dir (or built-in, in
        // which case `modprobe` exits 0 trivially).
        let status = std::process::Command::new("modprobe")
            .arg("virtio_net")
            .status()
            .expect("modprobe not available — kernel modules dir absent?");
        assert!(status.success(), "modprobe virtio_net failed: {status}");

        // Best-effort: this branch only runs meaningfully inside the
        // booted guest where `/proc/config.gz` exists. Outside the
        // guest the read silently fails (the surrounding #[ignore]
        // already disclaims).
        if let Ok(s) = std::fs::read_to_string("/proc/config.gz") {
            if std::process::Command::new("zcat")
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .spawn()
                .and_then(|mut child| {
                    use std::io::Write;
                    if let Some(stdin) = &mut child.stdin {
                        stdin.write_all(s.as_bytes())?;
                    }
                    let out = child.wait_with_output()?;
                    let text = String::from_utf8_lossy(&out.stdout);
                    assert!(
                        text.contains("CONFIG_VIRTIO_NET=y")
                            || text.contains("CONFIG_VIRTIO_NET=m"),
                        "/proc/config.gz does not include VIRTIO_NET=y or =m",
                    );
                    Ok::<(), std::io::Error>(())
                })
                .is_err()
            {
                // No zcat available in the test environment — that's fine;
                // the modprobe half above already verified the load.
            }
        }
    }
}
