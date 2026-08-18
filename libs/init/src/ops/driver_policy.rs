//! Guest platform policy: the typed boot backend value and the exact driver
//! sequence each backend requires.

use std::str::FromStr;

use error_stack::Report;

use crate::errors::{InitError, InitResult};
use crate::ops::module_loader::ModuleLoader;

/// The host backend the guest was launched under, taken from the
/// `jyth.backend=` kernel cmdline parameter. The accepted names are a wire
/// contract with the host (`jyth-runtime` passes the cmdline string) and must
/// not change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BootBackend {
    /// Hyper-V socket guest with the full hyper-v driver set.
    Hcs,
    /// Hyper-V socket guest booting from a preloaded bootstrap environment.
    HcsBootstrap,
    /// Linux KVM guest with virtio drivers.
    Kvm,
}

impl FromStr for BootBackend {
    type Err = Report<InitError>;

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        match name {
            "hcs" => Ok(Self::Hcs),
            "hcs-bootstrap" => Ok(Self::HcsBootstrap),
            "kvm" => Ok(Self::Kvm),
            _ => Err(Report::new(InitError::UnsupportedHost)),
        }
    }
}

/// Port through which the driver policy loads kernel modules. The production
/// adapter is [`ModuleLoader`]; test doubles implement the same port.
pub(crate) trait DriverLoader {
    /// Try to load a kernel module, returning `Some(())` when the module is
    /// available (or already loaded) and `None` when it is not.
    fn load(&self, name: &str) -> InitResult<Option<()>>;
}

impl DriverLoader for ModuleLoader {
    fn load(&self, name: &str) -> InitResult<Option<()>> {
        ModuleLoader::load(self, name)
    }
}

impl BootBackend {
    /// Load the exact module set for this backend, failing when a required
    /// module is unavailable. Optional modules are tolerated when missing.
    ///
    /// No backend loads a vsock driver: the command transport is TCP over
    /// the virtual NIC, so `hv_netvsc` is a required command-transport
    /// dependency for HCS and `virtio_net` becomes required for KVM when
    /// that backend becomes launchable.
    pub(crate) fn load_drivers(&self, loader: &impl DriverLoader) -> InitResult<()> {
        match self {
            Self::Hcs => {
                loader.load("hv_vmbus")?;
                loader.load("hv_utils")?;
                require_driver(loader, "hv_netvsc")?;
                loader.load("hv_storvsc")?;
            }
            Self::HcsBootstrap => {
                loader.load("hv_vmbus")?;
                loader.load("hv_utils")?;
                loader.load("hv_netvsc")?;
                loader.load("hv_storvsc")?;
            }
            Self::Kvm => {
                loader.load("virtio_pci")?;
                loader.load("virtio_net")?;
            }
        }
        Ok(())
    }
}

/// Load a module that must be present for the backend to function.
fn require_driver(loader: &impl DriverLoader, name: &str) -> InitResult<()> {
    loader
        .load(name)?
        .ok_or_else(|| Report::new(InitError::RequiredModuleNotLoaded).attach(name.to_string()))
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    /// A `DriverLoader` double that records every load attempt and reports
    /// configured modules as unavailable.
    #[derive(Default)]
    struct RecordingLoader {
        loads: Mutex<Vec<String>>,
        missing: Vec<String>,
    }

    impl RecordingLoader {
        fn new(missing: &[&str]) -> Self {
            Self {
                loads: Mutex::new(Vec::new()),
                missing: missing.iter().map(|s| s.to_string()).collect(),
            }
        }

        fn loaded(&self) -> Vec<String> {
            self.loads.lock().unwrap().clone()
        }
    }

    impl DriverLoader for RecordingLoader {
        fn load(&self, name: &str) -> InitResult<Option<()>> {
            self.loads.lock().unwrap().push(name.to_string());
            if self.missing.iter().any(|m| m == name) {
                Ok(None)
            } else {
                Ok(Some(()))
            }
        }
    }

    #[test]
    fn hcs_loads_exact_module_set() {
        let loader = RecordingLoader::new(&[]);
        BootBackend::Hcs.load_drivers(&loader).unwrap();
        assert_eq!(
            loader.loaded(),
            ["hv_vmbus", "hv_utils", "hv_netvsc", "hv_storvsc"]
        );
    }

    #[test]
    fn hcs_bootstrap_loads_exact_module_set() {
        let loader = RecordingLoader::new(&[]);
        BootBackend::HcsBootstrap.load_drivers(&loader).unwrap();
        assert_eq!(
            loader.loaded(),
            ["hv_vmbus", "hv_utils", "hv_netvsc", "hv_storvsc"]
        );
    }

    #[test]
    fn kvm_loads_exact_module_set() {
        let loader = RecordingLoader::new(&[]);
        BootBackend::Kvm.load_drivers(&loader).unwrap();
        assert_eq!(loader.loaded(), ["virtio_pci", "virtio_net"]);
    }

    #[test]
    fn hcs_required_module_missing_fails() {
        let loader = RecordingLoader::new(&["hv_netvsc"]);
        let err = BootBackend::Hcs.load_drivers(&loader).unwrap_err();
        assert_eq!(*err.current_context(), InitError::RequiredModuleNotLoaded);
        assert!(
            err.frames()
                .any(|f| f.downcast_ref::<String>() == Some(&"hv_netvsc".to_string()))
        );
    }

    #[test]
    fn hcs_optional_module_missing_is_tolerated() {
        let loader = RecordingLoader::new(&["hv_utils"]);
        BootBackend::Hcs.load_drivers(&loader).unwrap();
        assert_eq!(loader.loaded().len(), 4);
    }

    #[test]
    fn no_backend_requires_a_vsock_driver() {
        for backend in [
            BootBackend::Hcs,
            BootBackend::HcsBootstrap,
            BootBackend::Kvm,
        ] {
            let loader = RecordingLoader::new(&[]);
            backend.load_drivers(&loader).unwrap();
            let loaded = loader.loaded();
            assert!(
                !loaded
                    .iter()
                    .any(|name| name == "vsock" || name == "hv_sock" || name == "virtio_vsock"),
                "backend {backend:?} must not require a vsock driver: {loaded:?}"
            );
        }
    }

    #[test]
    fn known_backend_names_parse() {
        assert_eq!("hcs".parse::<BootBackend>().unwrap(), BootBackend::Hcs);
        assert_eq!(
            "hcs-bootstrap".parse::<BootBackend>().unwrap(),
            BootBackend::HcsBootstrap
        );
        assert_eq!("kvm".parse::<BootBackend>().unwrap(), BootBackend::Kvm);
    }

    #[test]
    fn unknown_backend_name_is_unsupported_host() {
        let err = "hyperv".parse::<BootBackend>().unwrap_err();
        assert_eq!(*err.current_context(), InitError::UnsupportedHost);
    }
}
