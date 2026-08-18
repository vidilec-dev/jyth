//! Hyper-V Administrators membership gating for HCS access.
//!
//! HCS rejects every call with HRESULT 0x8037011B unless the caller's token
//! belongs to the local "Hyper-V Administrators" group (S-1-5-32-578). This
//! module owns the detection and, with one UAC consent prompt, the
//! remediation of missing membership. It is part of the HCS backend's
//! security surface (it gates `Vm::from_conf` and the compute-system
//! enumeration tests), so it stays inside `hypervisor-hcs` rather than
//! moving with the operator administration surface into `hcs-admin`.

use crate::error::HcsError;
use error_stack::Report;
use std::ffi::c_void;

use crate::{core::ToWide, ext::*};

/// HCS rejects every call with HRESULT 0x8037011B unless the caller's
/// token belongs to the local "Hyper-V Administrators" group
/// (S-1-5-32-578) — being an Administrator alone isn't sufficient.
/// Detects missing membership and, with one UAC consent prompt, adds
/// the current user to that group. Group membership changes don't
/// apply to the *current* logon token (Windows computes it at logon
/// time), so this always returns an actionable error telling the user
/// to log out and back in — there's no way to make this fully
/// transparent within a single run.
pub fn ensure_hyperv_admin_membership() -> Result<(), Report<HcsError>> {
    if is_hyperv_admin_member() {
        return Ok(());
    }

    let username = get_current_username().ok_or_else(|| {
        Report::new(HcsError::HyperVAdmin).attach("Could not determine current Windows username")
    })?;
    let manual_command = format!(
        "Add-LocalGroupMember -Group 'Hyper-V Administrators' -Member '{}'",
        username
    );
    let ps_command = format!(
        "Add-LocalGroupMember -Group 'Hyper-V Administrators' -Member '{}'; exit $LASTEXITCODE",
        username.replace('\'', "''")
    );
    // `ps_command` is embedded as a single argv element in the process
    // command line handed to ShellExecuteExW, so it must be quoted per
    // the Win32 argv-splitting rules (the same ones CommandLineToArgvW
    // and every CRT use) — not just wrapped in a literal `"..."`. A
    // naive wrap only happens to be safe today because Windows
    // usernames can't contain `"`; quoting it properly removes that
    // reliance on an OS-level restriction that isn't this code's to
    // depend on.
    let params = &format!(
        "-NoProfile -NonInteractive -Command {}",
        quote_windows_command_line_arg(&ps_command)
    );

    // Try Windows PowerShell first, then PowerShell Core — some hosts
    // (locked-down enterprise images, Server Core) may lack one or the
    // other. ERROR_FILE_NOT_FOUND specifically means "try the next
    // candidate"; any other failure (e.g. the user declining the UAC
    // prompt) is a real failure, not a missing-binary issue, and stops
    // the search immediately rather than re-prompting with a different
    // shell.
    const ERROR_FILE_NOT_FOUND: i32 = 2;
    let mut last_not_found_err: Option<std::io::Error> = None;
    for shell in ["powershell.exe", "pwsh.exe"] {
        let exit_code = match launch_elevated(shell, params, ELEVATED_WAIT_MS) {
            Ok(code) => code,
            Err(e) if e.raw_os_error() == Some(ERROR_FILE_NOT_FOUND) => {
                last_not_found_err = Some(e);
                continue;
            }
            Err(e) => {
                return Err(Report::new(HcsError::HyperVAdmin).attach(format!(
                    "Could not start the elevation prompt to join the Hyper-V Administrators \
                         group via {shell} (declined the UAC prompt?): {e}. You can also do it \
                         manually in an elevated terminal: {manual_command}"
                )));
            }
        };

        if exit_code != 0 {
            return Err(Report::new(HcsError::HyperVAdmin).attach(format!(
                "Adding {username} to the Hyper-V Administrators group via {shell} failed \
                     (exit code {exit_code}). You can do it manually in an elevated terminal: \
                     {manual_command}"
            )));
        }

        return Err(Report::new(HcsError::HyperVAdmin).attach(format!(
            "Added {username} to the Hyper-V Administrators group. Windows computes group \
                 membership at logon time, so this only takes effect after you log out and \
                 back in (or reboot) — then retry."
        )));
    }

    // Neither powershell.exe nor pwsh.exe is available on this host —
    // no automatic path left, so hand the user the exact command.
    Err(Report::new(HcsError::HyperVAdmin).attach(format!(
        "Could not find powershell.exe or pwsh.exe to automatically join the Hyper-V \
             Administrators group ({}). Run this yourself in an elevated terminal, then log \
             out and back in: {manual_command}",
        last_not_found_err
            .map(|e| e.to_string())
            .unwrap_or_else(|| "neither shell found".to_string()),
    )))
}

/// Quotes `arg` as a single Win32 command-line argument, following the
/// same backslash/quote escaping rules as `CommandLineToArgvW` (and
/// every CRT's argv parser). Needed anywhere a string of unknown
/// origin — like a username — is interpolated into a command line
/// string passed to `CreateProcess`/`ShellExecuteExW`, since a literal
/// `"..."` wrap only round-trips correctly when the content has no
/// embedded quotes or trailing backslashes.
pub fn quote_windows_command_line_arg(arg: &str) -> String {
    if !arg.is_empty()
        && !arg
            .chars()
            .any(|c| matches!(c, ' ' | '\t' | '\n' | '\x0B' | '"'))
    {
        return arg.to_string();
    }
    let mut result = String::from("\"");
    let mut chars = arg.chars().peekable();
    loop {
        let mut backslashes = 0;
        while chars.peek() == Some(&'\\') {
            chars.next();
            backslashes += 1;
        }
        match chars.next() {
            Some('"') => {
                result.extend(std::iter::repeat_n('\\', backslashes * 2 + 1));
                result.push('"');
            }
            Some(c) => {
                result.extend(std::iter::repeat_n('\\', backslashes));
                result.push(c);
            }
            None => {
                result.extend(std::iter::repeat_n('\\', backslashes * 2));
                break;
            }
        }
    }
    result.push('"');
    result
}

/// Maximum time the elevated (UAC) process may run before the launch is
/// reported as still pending.
const ELEVATED_WAIT_MS: u32 = 30_000;
const WAIT_OBJECT_0: u32 = 0;
const WAIT_TIMEOUT: u32 = 0x0000_0102;

/// Launches `exe` elevated (UAC) with `params`, waits up to `wait_ms`,
/// and returns its exit code. This is the UAC-consented elevated
/// launcher shared by the HCS admin steps: the Hyper-V Administrators
/// membership gate in this module and the operator steps in `hcs-admin`.
/// Errors from `ShellExecuteExW` itself (declined prompt, missing shell)
/// surface as `Err` via `last_os_error()` rather than a fabricated exit
/// code. A process still running after `wait_ms` is reported as such
/// instead of surfacing its transient `STILL_ACTIVE` (259) exit code.
pub fn launch_elevated(exe: &str, params: &str, wait_ms: u32) -> Result<u32, std::io::Error> {
    let wide_verb = "runas".to_wide();
    let wide_file = exe.to_wide();
    let wide_params = params.to_wide();
    let mut info = ShellExecuteInfoW {
        cb_size: std::mem::size_of::<ShellExecuteInfoW>() as u32,
        f_mask: SEE_MASK_NOCLOSEPROCESS,
        hwnd: std::ptr::null_mut(),
        lp_verb: wide_verb.as_ptr(),
        lp_file: wide_file.as_ptr(),
        lp_parameters: wide_params.as_ptr(),
        lp_directory: std::ptr::null(),
        n_show: SW_SHOWNORMAL,
        h_inst_app: std::ptr::null_mut(),
        lp_id_list: std::ptr::null_mut(),
        lp_class: std::ptr::null(),
        hkey_class: std::ptr::null_mut(),
        dw_hot_key: 0,
        h_icon_or_monitor: std::ptr::null_mut(),
        h_process: std::ptr::null_mut(),
    };

    let ok = unsafe { ShellExecuteExW(&mut info) };
    if ok == 0 {
        return Err(std::io::Error::last_os_error());
    }
    if info.h_process.is_null() {
        return Err(std::io::Error::other(
            "ShellExecuteExW reported success but returned no process handle",
        ));
    }

    let wait = unsafe { WaitForSingleObject(info.h_process, wait_ms) };
    let mut exit_code: u32 = 1;
    unsafe { GetExitCodeProcess(info.h_process, &mut exit_code) };
    unsafe { CloseHandle(info.h_process) };
    if wait != WAIT_OBJECT_0 {
        let message = if wait == WAIT_TIMEOUT {
            format!("elevation prompt still running after {wait_ms} ms")
        } else {
            format!("wait for the elevated process failed (result {wait})")
        };
        return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, message));
    }
    Ok(exit_code)
}

fn is_hyperv_admin_member() -> bool {
    let sid_str = "S-1-5-32-578";
    let mut sid: *mut c_void = std::ptr::null_mut();
    let wide_sid = sid_str.to_wide();
    let ok = unsafe { ConvertStringSidToSidW(wide_sid.as_ptr(), &mut sid) };
    if ok == 0 || sid.is_null() {
        return false;
    }
    let mut is_member: i32 = 0;
    let res = unsafe { CheckTokenMembership(std::ptr::null_mut(), sid, &mut is_member) };
    unsafe { LocalFree(sid) };
    res != 0 && is_member != 0
}

fn get_current_username() -> Option<String> {
    // Query the required size instead of guessing a fixed buffer:
    // per GetUserNameW's own docs, passing a null buffer always fails
    // but reports the exact size needed (including the null
    // terminator) in `len`. A hardcoded 256-char buffer would silently
    // truncate/fail for a UPN-style username right at that boundary
    // (Windows' own UNLEN limit is 256, needing 257 to fit the null
    // terminator) instead of just handling whatever length shows up.
    let mut len: u32 = 0;
    unsafe { GetUserNameW(std::ptr::null_mut(), &mut len) };
    if len == 0 {
        return None;
    }
    let mut buf = vec![0u16; len as usize];
    let ok = unsafe { GetUserNameW(buf.as_mut_ptr(), &mut len) };
    if ok == 0 {
        return None;
    }
    let actual_len = (len as usize).saturating_sub(1);
    Some(String::from_utf16_lossy(&buf[..actual_len]))
}
