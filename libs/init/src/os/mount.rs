#[cfg(target_os = "linux")]
use crate::errors::{InitError, InitResult};
#[cfg(target_os = "linux")]
use error_stack::Report;
#[cfg(target_os = "linux")]
use std::ffi::CString;

#[cfg(target_os = "linux")]
pub(crate) fn mount(source: &str, target: &str, fstype: &str) -> InitResult<()> {
    let source_c =
        CString::new(source).map_err(|e| Report::new(e).change_context(InitError::MountNul))?;
    let target_c =
        CString::new(target).map_err(|e| Report::new(e).change_context(InitError::MountNul))?;
    let fstype_c =
        CString::new(fstype).map_err(|e| Report::new(e).change_context(InitError::MountNul))?;
    let ret = unsafe {
        libc::mount(
            source_c.as_ptr(),
            target_c.as_ptr(),
            fstype_c.as_ptr(),
            0,
            std::ptr::null(),
        )
    };
    if ret != 0 {
        // `libc::mount` reports failure as -1; the actual diagnosis lives in
        // errno, so capture it before it is clobbered by anything else.
        let error = std::io::Error::last_os_error();
        let errno = error
            .raw_os_error()
            .map(|n| n.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        return Err(Report::new(InitError::MountInternal)
            .attach(format!("mount syscall failed (errno {errno}): {error}")));
    }
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use crate::errors::InitError;

    #[test]
    fn mount_failure_attaches_errno_and_os_message() {
        // Nonexistent source + unsupported fstype: `mount(2)` fails
        // deterministically (EPERM unprivileged, ENOENT/EINVAL as root)
        // without touching the system.
        let error = super::mount(
            "/nonexistent/jyth-source",
            "/nonexistent/jyth-target",
            "no-such-fs",
        )
        .expect_err("mount must fail for a nonexistent source");
        assert_eq!(error.current_context(), &InitError::MountInternal);
        let message = error.to_string();
        assert!(message.contains("errno"), "missing errno in: {message}");
        assert!(
            message.contains("mount syscall failed"),
            "missing syscall message in: {message}"
        );
    }
}
