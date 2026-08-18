//! Guest-side init process for the Jyth command bus and process supervisor.
//!
//! # Responsibility (SolidArchitecturePlan target catalog)
//!
//! **Owner**: init.
//!
//! **Responsibility**: guest boot and guest command-service behavior.
//!
//! **Allowed dependencies**: protocol (enforced by `tests/architecture`).
//!
//! **Forbidden concepts**: host HCS APIs, host image stores, public Jyth
//! builders, and host scheduling.

#[cfg(target_os = "linux")]
pub(crate) mod bus;
#[cfg(target_os = "linux")]
pub(crate) mod components;
#[cfg(target_os = "linux")]
pub(crate) mod errors;
#[cfg(target_os = "linux")]
mod ops;
#[cfg(target_os = "linux")]
pub(crate) mod os;
#[cfg(target_os = "linux")]
use crate::components::com::Com;
#[cfg(target_os = "linux")]
use crate::components::tcp::TcpCommandListener;
#[cfg(target_os = "linux")]
use crate::errors::{InitError, InitResult};
#[cfg(target_os = "linux")]
use crate::ops::bootstrap::run_bootstrap;
#[cfg(target_os = "linux")]
use crate::ops::bring_up_net::bring_up_net_with_config;
#[cfg(target_os = "linux")]
use crate::ops::disks::mount_disks_with_config;
#[cfg(target_os = "linux")]
use crate::ops::fetch_params::Params;
#[cfg(target_os = "linux")]
use crate::ops::module_loader::ModuleLoader;
#[cfg(target_os = "linux")]
use crate::ops::start_loopback::start_loopback;
#[cfg(target_os = "linux")]
use crate::os::mount::mount;
#[cfg(target_os = "linux")]
use error_stack::Report;
#[cfg(target_os = "linux")]
use protocol::{BootConfigV1, COM1_READY_MAGIC, MAX_BOOT_CONFIG_FRAME};
#[cfg(target_os = "linux")]
use std::fs::create_dir_all;

#[cfg(target_os = "linux")]
fn run_init() -> InitResult<()> {
    // Install the deterministic env-filtered tracing subscriber (RUST_LOG),
    // so structured logs flow to the host's COM0 capture the same way the
    // old `logs::log!` (eprintln) output did.
    #[cfg(feature = "tracing")]
    tracing::init();
    #[cfg(feature = "tracing")]
    tracing::info!("[JythInit][Run] Starting minimal guest boot sequence...");

    let _ = create_dir_all("/proc");
    let _ = create_dir_all("/sys");
    let _ = create_dir_all("/dev");

    mount("proc", "/proc", "proc")?;
    mount("sysfs", "/sys", "sysfs")?;
    mount("devtmpfs", "/dev", "devtmpfs")?;

    let params = Params::fetch()?;

    let module_loader = ModuleLoader::new()?;

    params.backend.load_drivers(&module_loader)?;

    start_loopback()?;

    #[cfg(feature = "tracing")]
    tracing::info!("[JythInit] Opening TTYs...");
    let mut com1 =
        Com::open("/dev/ttyS1").map_err(|e| Report::new(e).change_context(InitError::Io))?;
    com1.send_frame(COM1_READY_MAGIC, MAX_BOOT_CONFIG_FRAME)
        .map_err(|e| Report::new(e).change_context(InitError::Io))?;
    // The host sends all caller-controlled boot configuration over the
    // protected COM1 exchange. It is deliberately absent from the deterministic
    // kernel command line and therefore from cached initrds and /proc/cmdline.
    let boot_frame = com1
        .recv_boot_frame()
        .map_err(|e| Report::new(e).change_context(InitError::BootProtocol))?;
    let boot_config = BootConfigV1::try_from(boot_frame.as_slice())
        .map_err(|e| e.change_context(InitError::BootProtocol))?;

    bring_up_net_with_config(boot_config.network.as_ref())?;
    mount_disks_with_config(&boot_config.disks)?;

    if boot_config.bootstrap.is_some() {
        run_bootstrap(com1, &boot_config, boot_frame)?;
        return Ok(());
    }

    // A normal HCS boot requires the configured virtual network: the TCP
    // command endpoint is derived from it, and the guest never sends READY
    // after a required network step fails.
    let network = boot_config.network.as_ref().ok_or_else(|| {
        Report::new(InitError::NetworkConfig)
            .attach("normal boot requires a configured virtual network")
    })?;
    let listener_address = std::net::SocketAddrV4::new(
        std::net::Ipv4Addr::from(network.guest_ip),
        protocol::COMMAND_PORT,
    );
    let tcp = TcpCommandListener::bind(listener_address)?;

    smol::block_on(crate::bus::run_bus(tcp, com1, boot_config, boot_frame))?;

    Ok(())
}

#[cfg(target_os = "linux")]
fn main() {
    let saved_stderr = unsafe { libc::dup(2) };
    if let Err(e) = run_init() {
        if saved_stderr >= 0 {
            let _ = unsafe { libc::dup2(saved_stderr, 2) };
        }
        eprintln!("Jyth InitBinary Critical Error: {:?}", e);
        loop {
            std::thread::sleep(std::time::Duration::from_secs(3600));
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("Jyth InitBinary is only supported on Linux target.");
    panic!("Unsupported platform");
}
