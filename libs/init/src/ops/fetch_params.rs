use std::fs::read_to_string;

use error_stack::Report;

use crate::errors::{InitError, InitResult};
use crate::ops::driver_policy::BootBackend;

pub(crate) struct Params {
    pub(crate) backend: BootBackend,
}

impl Params {
    pub(crate) fn fetch() -> InitResult<Self> {
        let cmdline = read_to_string("/proc/cmdline")
            .map_err(|e| Report::new(e).change_context(InitError::Io))?;
        #[cfg(feature = "tracing")]
        tracing::info!("[JythInit][FetchParams]: Found cmdline: {}", cmdline);
        Self::parse(&cmdline)
    }
    fn parse(cmdline: &str) -> InitResult<Self> {
        let mut backend = None;
        for arg in cmdline.split_whitespace() {
            if let Some(val) = arg.strip_prefix("jyth.backend=") {
                backend = Some(val);
            }
        }

        let backend = backend.ok_or_else(|| Report::new(InitError::NotFoundCmdlineBackend))?;
        Ok(Self {
            backend: backend.parse()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cmdline() {
        let cmdline = "root=/dev/vda1 init=/init jyth.backend=kvm jyth.service=my-service foo=bar";
        let parsed = Params::parse(cmdline).unwrap();
        assert_eq!(parsed.backend, BootBackend::Kvm);
    }

    #[test]
    fn test_parse_cmdline_unsupported_backend() {
        let cmdline = "root=/dev/vda1 init=/init jyth.backend=hyperv foo=bar";
        if let Err(e) = Params::parse(cmdline) {
            let report = e.downcast_ref::<InitError>().unwrap();
            assert_eq!(*report, InitError::UnsupportedHost);
            return;
        }
        panic!("Expected InitError::UnsupportedHost");
    }

    #[test]
    fn test_parse_cmdline_missing() {
        let cmdline = "root=/dev/vda1 init=/init foo=bar";
        if let Err(e) = Params::parse(cmdline) {
            let report = e.downcast_ref::<InitError>().unwrap();
            assert_eq!(*report, InitError::NotFoundCmdlineBackend);
            return;
        }
        panic!("Expected InitError::NotFoundCmdlineBackend");
    }
}
