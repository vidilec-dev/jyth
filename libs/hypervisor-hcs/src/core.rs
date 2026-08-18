use crate::error::HcsError;
use error_stack::Report;
use std::path::Path;

use crate::ext::LocalFree;

/// Cap for scanning a `NUL`-terminated Win32 wide string: 64 KiB of code
/// units. Win32 strings of interest (HCS result documents, SID strings,
/// known-folder paths, HNS diagnostics) are all far below this; a buffer
/// without a terminator within the cap is treated as corrupt instead of
/// being read out of bounds.
pub(crate) const MAX_WIDE_STRING_UNITS: usize = 64 * 1024;

/// The wide string at the pointer was not `NUL`-terminated within
/// [`MAX_WIDE_STRING_UNITS`] code units.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct WideStringOverflow;

impl std::fmt::Display for WideStringOverflow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("unterminated wide string exceeded the scan cap")
    }
}

impl std::error::Error for WideStringOverflow {}

/// Measure the length in code units of the `NUL`-terminated wide string at
/// `ptr`, capped at [`MAX_WIDE_STRING_UNITS`]. A buffer whose terminator is
/// not found within the cap is an error, never an out-of-bounds read.
///
/// # Safety
/// `ptr` must be readable for at least `MAX_WIDE_STRING_UNITS` `u16`s.
pub(crate) unsafe fn wide_strlen(ptr: *const u16) -> Result<usize, WideStringOverflow> {
    let mut len = 0;
    while len < MAX_WIDE_STRING_UNITS && unsafe { *ptr.add(len) } != 0 {
        len += 1;
    }
    if len == MAX_WIDE_STRING_UNITS {
        Err(WideStringOverflow)
    } else {
        Ok(len)
    }
}

/// Encode a path as a `NUL`-terminated wide (WTF-16) buffer for the Win32
/// APIs. The path is used as opaque code units — `encode_wide` on
/// `as_os_str()` — so identity-critical conversions (security descriptors,
/// journal records) never mangle surrogate code points the way a lossy
/// UTF-8 round trip would.
pub(crate) fn wide_path(path: &Path) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    path.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// An owned, null-terminated wide (UTF-16) string.
///
/// The inner `Vec<u16>` is kept alive for as long as this value exists,
/// so pointers obtained via [`as_ptr`](Self::as_ptr) remain valid until
/// the `WideString` is dropped — no leak, no dangling pointer.
pub struct WideString(Vec<u16>);

impl WideString {
    /// The `NUL`-terminated wide buffer; valid until the `WideString` is
    /// dropped.
    pub fn as_ptr(&self) -> *const u16 {
        self.0.as_ptr()
    }
}

/// Encode a `str` as an owned `NUL`-terminated wide (UTF-16) buffer.
pub trait ToWide {
    fn to_wide(&self) -> WideString;
}

pub(crate) trait ToOptionalString {
    fn to_optional_string(self) -> Result<Option<String>, Report<HcsError>>;
}

impl ToWide for str {
    fn to_wide(&self) -> WideString {
        use std::os::windows::ffi::OsStrExt;
        WideString(
            std::ffi::OsStr::new(self)
                .encode_wide()
                .chain(std::iter::once(0))
                .collect(),
        )
    }
}

impl ToOptionalString for *mut u16 {
    fn to_optional_string(self) -> Result<Option<String>, Report<HcsError>> {
        if self.is_null() {
            return Ok(None);
        }
        // SAFETY: HCS documents that result buffers are `LocalAlloc`-backed
        // and null-terminated. The scan is capped at
        // `MAX_WIDE_STRING_UNITS`, so a corrupt buffer is an error rather
        // than an out-of-bounds read.
        let len = unsafe { wide_strlen(self) }.map_err(|error| {
            Report::new(HcsError::OperationResult).attach(format!("HCS result document: {error}"))
        })?;
        let slice = unsafe { std::slice::from_raw_parts(self, len) };
        let s = String::from_utf16_lossy(slice);
        unsafe { LocalFree(self as *mut _) };
        Ok(Some(s))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wide_scan_reports_lengths_and_is_capped() {
        let terminated = [0x0041u16, 0x0042, 0];
        assert_eq!(unsafe { wide_strlen(terminated.as_ptr()) }, Ok(2));
        let empty = [0u16];
        assert_eq!(unsafe { wide_strlen(empty.as_ptr()) }, Ok(0));

        let unterminated = vec![0x0041u16; MAX_WIDE_STRING_UNITS];
        assert_eq!(
            unsafe { wide_strlen(unterminated.as_ptr()) },
            Err(WideStringOverflow),
            "a buffer with no terminator within the cap is an error"
        );
        let terminator_beyond_cap = vec![0x0041u16; MAX_WIDE_STRING_UNITS + 1];
        assert_eq!(
            unsafe { wide_strlen(terminator_beyond_cap.as_ptr()) },
            Err(WideStringOverflow),
            "a terminator at the cap boundary is still an overflow"
        );
    }
}
