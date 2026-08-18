//! Windows token/SID lookup, least-privilege named-pipe descriptors, and
//! explicit named-pipe security.

use crate::core::{wide_path, wide_strlen};
use crate::error::HcsError;
use error_stack::Report;
use std::ffi::c_void;
use std::os::windows::io::{FromRawHandle, OwnedHandle};
use std::path::Path;
use std::ptr;
use uuid::Uuid;

#[cfg(test)]
pub(crate) const DENY_BY_DEFAULT_SDDL: &str = "D:P";

const SDDL_REVISION_1: u32 = 1;
const TOKEN_QUERY: u32 = 0x0008;
const TOKEN_USER_CLASS: u32 = 1;
const TOKEN_LOGON_SID_CLASS: u32 = 28;
const SE_GROUP_LOGON_ID: u32 = 0xC000_0000;
const PIPE_ACCESS_DUPLEX: u32 = 0x0000_0003;
const FILE_FLAG_FIRST_PIPE_INSTANCE: u32 = 0x0008_0000;
const FILE_FLAG_OVERLAPPED: u32 = 0x4000_0000;
const PIPE_TYPE_BYTE: u32 = 0x0000_0000;
const PIPE_READMODE_BYTE: u32 = 0x0000_0000;
const PIPE_WAIT: u32 = 0x0000_0000;
const PIPE_REJECT_REMOTE_CLIENTS: u32 = 0x0000_0008;
const INVALID_HANDLE_VALUE: *mut c_void = -1isize as *mut c_void;
#[cfg(test)]
const GENERIC_ALL: u32 = 0x1000_0000;
const ACL_SIZE_INFORMATION_CLASS: u32 = 2;
const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
const SE_KERNEL_OBJECT: u32 = 6;
/// `SE_FILE_OBJECT = 1` (0 is `SE_UNKNOWN`, which
/// `GetNamedSecurityInfoW`/`SetNamedSecurityInfoW` reject with
/// `ERROR_INVALID_PARAMETER`).
const SE_FILE_OBJECT: u32 = 1;
const DACL_SECURITY_INFORMATION: u32 = 0x0000_0004;
const ACL_REVISION: u32 = 2;
const MAXDWORD: u32 = u32::MAX;
/// `GENERIC_READ | GENERIC_WRITE` — the file rights the per-VM identity
/// needs to open its VHDX backing file (the `(R,W)` mask the previous
/// `icacls` grant used).
const VM_DISK_ACCESS_MASK: u32 = 0xC000_0000;
#[cfg(test)]
const READ_CONTROL: u32 = 0x0002_0000;
#[cfg(test)]
const FILE_SHARE_READ: u32 = 0x0000_0001;
#[cfg(test)]
const FILE_SHARE_WRITE: u32 = 0x0000_0002;
#[cfg(test)]
const OPEN_EXISTING: u32 = 3;
#[cfg(test)]
const FILE_ATTRIBUTE_NORMAL: u32 = 0x0000_0080;
const ERROR_SUCCESS: u32 = 0;

#[cfg(test)]
fn allow_sid_descriptor(sid: &str) -> Result<String, Report<HcsError>> {
    let descriptor = format!("D:P(A;;FA;;;{sid})");
    validate_sddl(&descriptor)?;
    Ok(descriptor)
}

/// The current process logon SID, the principal this host session uses for
/// every least-privilege grant. A logon session always carries exactly one
/// logon SID; a token without one is an error, never a silent fallback to a
/// different principal.
pub(crate) fn current_logon_sid() -> Result<String, Report<HcsError>> {
    let token = open_current_token()?;
    let logon_buffer = query_token(token.0, TOKEN_LOGON_SID_CLASS)?;
    unsafe { logon_sid_from_buffer(&logon_buffer) }
}

/// The current process user SID (the journal owner identity). Shares the
/// token-query FFI with [`current_logon_sid`].
pub(crate) fn current_user_sid() -> Result<String, Report<HcsError>> {
    let token = open_current_token()?;
    let user_buffer = query_token(token.0, TOKEN_USER_CLASS)?;
    let token_user = unsafe { &*(user_buffer.as_ptr().cast::<TokenUser>()) };
    unsafe { sid_to_string(token_user.user.sid) }
}

fn security_report(message: impl Into<String>) -> Report<HcsError> {
    Report::new(HcsError::SecurityDescriptor).attach(message.into())
}

/// Index of the group whose attributes carry `SE_GROUP_LOGON_ID`, if any.
/// The decision is extracted so the fail-closed rule (a missing logon SID
/// is an error, never a wrong-principal fallback) is unit-testable without
/// a live token.
fn logon_sid_group_index(groups: &[SidAndAttributes]) -> Option<usize> {
    groups
        .iter()
        .position(|group| group.attributes & SE_GROUP_LOGON_ID != 0)
}

/// Extract the logon SID string from a `TokenGroups` buffer returned by a
/// `TokenLogonSid` query. Missing logon SID group is an error.
///
/// # Safety
/// `buffer` must be a live `GetTokenInformation(TokenLogonSid)` result
/// whose `TokenGroups` count matches the allocation size.
unsafe fn logon_sid_from_buffer(buffer: &[u64]) -> Result<String, Report<HcsError>> {
    // SAFETY: the caller guarantees `buffer` is a live `TokenLogonSid`
    // query result whose `TokenGroups` layout matches the allocation.
    let groups = unsafe { &*(buffer.as_ptr().cast::<TokenGroups>()) };
    let groups_ptr = groups.groups.as_ptr();
    // SAFETY: `groups.group_count` describes the array of `SidAndAttributes`
    // entries inside the buffer returned by `GetTokenInformation`.
    let group_count = groups.group_count as usize;
    let index =
        logon_sid_group_index(unsafe { std::slice::from_raw_parts(groups_ptr, group_count) })
            .ok_or_else(|| security_report("no logon SID group found in the current token"))?;
    // SAFETY: `index` is a valid group index by construction.
    let sid = unsafe { (*groups_ptr.add(index)).sid };
    unsafe { sid_to_string(sid) }
}

/// Derive the per-VM SID for `NT VIRTUAL MACHINE\<vm-guid>`:
/// `S-1-5-83-1-<r1>-<r2>-<r3>-<r4>` — a fixed identity RID `1` followed by
/// four little-endian u32 RIDs taken from the four 4-byte windows of
/// `vm_id.to_bytes_le()`. This is the SID the VMMS-created account
/// resolves to: verified empirically against live per-VM accounts on a
/// Hyper-V host (`NT VIRTUAL MACHINE\<guid>` translated via
/// `SecurityIdentifier` always yields the leading `1` RID). Granting it
/// grants the single VM's worker process access without touching the
/// machine-wide `NT VIRTUAL MACHINE\Virtual Machines` group
/// (`S-1-5-83-0`).
pub(crate) fn vm_identity_sid(vm_id: Uuid) -> String {
    let bytes = vm_id.to_bytes_le();
    let rid = |start: usize| {
        u32::from_le_bytes(
            bytes[start..start + 4]
                .try_into()
                .expect("a 16-byte LE GUID has four 4-byte RID windows"),
        )
    };
    format!("S-1-5-83-1-{}-{}-{}-{}", rid(0), rid(4), rid(8), rid(12))
}

/// Validate that a derived per-VM SID parses as a real Windows SID inside a
/// valid security descriptor. Called before any ACL uses the SID.
pub(crate) fn validate_vm_identity_sid(sid: &str) -> Result<(), Report<HcsError>> {
    validate_sddl(&format!("D:P(A;;GRGW;;;{sid})"))
}

/// Build the deny-by-default named-pipe descriptor for one VM.
///
/// The pipe is reachable ONLY by:
///
/// 1. the exact per-VM identity `NT VIRTUAL MACHINE\<vm-guid>` (so the VM
///    worker can bind the guest COM ports);
/// 2. the current host logon SID (so the host process and its logon session
///    can use the pipe);
/// 3. `SYSTEM` (the required HCS system principal; documented v0.1 choice —
///    may be tightened after the live HCS test proves which principals the
///    worker actually needs).
///
/// The DACL is protected (`D:P`) so inherited ACEs cannot widen it, and it
/// never contains `WD` (`Everyone`) or `BA` (`Builtin Administrators`).
pub(crate) fn named_pipe_sddl(vm_id: Uuid) -> Result<String, Report<HcsError>> {
    let logon_sid = current_logon_sid()?;
    let vm_sid = vm_identity_sid(vm_id);
    validate_vm_identity_sid(&vm_sid)?;
    let sddl = format!("D:P(A;;GA;;;{logon_sid})(A;;GA;;;{vm_sid})(A;;GA;;;SY)");
    validate_sddl(&sddl)?;
    Ok(sddl)
}

/// Create a named-pipe server instance carrying an explicit security
/// descriptor, replacing the default-ACL Tokio `ServerOptions::create` path.
///
/// The SDDL is converted and validated before `CreateNamedPipeW` runs, so a
/// malformed descriptor can never reach the kernel. The pipe is created
/// with:
///
/// - `PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE |
///   FILE_FLAG_OVERLAPPED` — first-instance semantics prevent namespace
///   pre-creation, and OVERLAPPED is required for the Tokio handle
///   transfer;
/// - byte-mode blocking semantics plus `PIPE_REJECT_REMOTE_CLIENTS` (the
///   Tokio defaults this path replaces);
/// - one instance and the same 64 KiB buffer sizes Tokio used;
/// - `bInheritHandle = FALSE`.
///
/// The returned handle is the caller's sole reference; transfer it into
/// `NamedPipeServer::from_raw_handle` to hand closing responsibility to
/// Tokio.
pub(crate) fn create_pipe_with_security(name: &str, sddl: &str) -> std::io::Result<OwnedHandle> {
    let descriptor = validated_descriptor(sddl).map_err(|report| {
        // error-stack renders only the top context via Display; pull the
        // first printable attachment so the rejection names the SDDL.
        let message = report
            .frames()
            .filter_map(|frame| match frame.kind() {
                error_stack::FrameKind::Attachment(error_stack::AttachmentKind::Printable(
                    value,
                )) => Some(value.to_string()),
                _ => None,
            })
            .next()
            .unwrap_or_else(|| report.to_string());
        std::io::Error::new(std::io::ErrorKind::InvalidInput, message)
    })?;

    let security_attributes = SecurityAttributes {
        n_length: std::mem::size_of::<SecurityAttributes>() as u32,
        lp_security_descriptor: descriptor.0,
        b_inherit_handle: 0,
    };

    let wide: Vec<u16> = name.encode_utf16().chain([0]).collect();
    let handle = unsafe {
        CreateNamedPipeW(
            wide.as_ptr(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1,
            65536,
            65536,
            0,
            (&security_attributes as *const SecurityAttributes)
                .cast_mut()
                .cast(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: the returned handle is a fresh pipe instance created above
    // and never referenced elsewhere, so transferring sole ownership into
    // `OwnedHandle` cannot create a duplicate owner.
    Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
}

pub(crate) fn validate_sddl(sddl: &str) -> Result<(), Report<HcsError>> {
    let _descriptor = validated_descriptor(sddl)?;
    Ok(())
}

fn validated_descriptor(sddl: &str) -> Result<LocalFreeGuard, Report<HcsError>> {
    let wide: Vec<u16> = sddl.encode_utf16().chain([0]).collect();
    let mut descriptor = ptr::null_mut();
    let mut descriptor_size = 0u32;
    let converted = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            &mut descriptor_size,
        )
    };
    if converted == 0 || descriptor.is_null() || descriptor_size == 0 {
        return Err(security_report(format!(
            "ConvertStringSecurityDescriptorToSecurityDescriptorW failed for {sddl:?}"
        )));
    }

    let guard = LocalFreeGuard(descriptor);
    if unsafe { IsValidSecurityDescriptor(guard.0) } == 0 {
        return Err(security_report(format!(
            "IsValidSecurityDescriptor rejected {sddl:?}"
        )));
    }
    Ok(guard)
}

fn open_current_token() -> Result<HandleGuard, Report<HcsError>> {
    let mut token = ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(security_report("OpenProcessToken failed"));
    }
    Ok(HandleGuard(token))
}

fn query_token(token: *mut c_void, information_class: u32) -> Result<Vec<u64>, Report<HcsError>> {
    let mut required = 0u32;
    unsafe {
        GetTokenInformation(token, information_class, ptr::null_mut(), 0, &mut required);
    }
    if required == 0 {
        return Err(security_report(format!(
            "GetTokenInformation size query failed for class {information_class}"
        )));
    }

    let word_size = std::mem::size_of::<u64>();
    let word_count = (required as usize).div_ceil(word_size);
    let mut buffer = vec![0u64; word_count];
    if unsafe {
        GetTokenInformation(
            token,
            information_class,
            buffer.as_mut_ptr().cast::<c_void>(),
            (buffer.len() * word_size) as u32,
            &mut required,
        )
    } == 0
    {
        return Err(security_report(format!(
            "GetTokenInformation failed for class {information_class}"
        )));
    }
    Ok(buffer)
}

unsafe fn sid_to_string(sid: *mut c_void) -> Result<String, Report<HcsError>> {
    if sid.is_null() {
        return Err(security_report("token SID pointer was null"));
    }
    let mut sid_text = ptr::null_mut();
    if unsafe { ConvertSidToStringSidW(sid, &mut sid_text) } == 0 || sid_text.is_null() {
        return Err(security_report("ConvertSidToStringSidW failed"));
    }
    let _sid_text = LocalFreeGuard(sid_text.cast());
    // SAFETY: `sid_text` is the buffer returned by `ConvertSidToStringSidW`;
    // the capped scan bounds the read.
    let length = unsafe { wide_strlen(sid_text) }
        .map_err(|error| security_report(format!("SID string: {error}")))?;
    Ok(String::from_utf16_lossy(unsafe {
        std::slice::from_raw_parts(sid_text, length)
    }))
}

#[repr(C)]
struct SidAndAttributes {
    sid: *mut c_void,
    attributes: u32,
}

#[repr(C)]
struct SecurityAttributes {
    n_length: u32,
    lp_security_descriptor: *mut c_void,
    b_inherit_handle: i32,
}

#[repr(C)]
struct TokenUser {
    user: SidAndAttributes,
}

#[repr(C)]
struct TokenGroups {
    group_count: u32,
    groups: [SidAndAttributes; 1],
}

#[repr(C)]
struct AclSizeInformation {
    ace_count: u32,
    acl_bytes_in_use: u32,
    acl_bytes_free: u32,
}

#[repr(C)]
struct AceHeader {
    ace_type: u8,
    ace_flags: u8,
    ace_size: u16,
}

struct HandleGuard(*mut c_void);

impl Drop for HandleGuard {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}

struct LocalFreeGuard(*mut c_void);

impl Drop for LocalFreeGuard {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0);
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ParsedAce {
    pub(crate) ace_type: u8,
    pub(crate) access_mask: u32,
    pub(crate) sid: String,
}

#[cfg(test)]
fn parsed_allowed_aces(sddl: &str) -> Result<Vec<ParsedAce>, Report<HcsError>> {
    let descriptor = validated_descriptor(sddl)?;
    parsed_allowed_aces_from_descriptor(descriptor.0)
}

fn parsed_allowed_aces_from_descriptor(
    descriptor: *const c_void,
) -> Result<Vec<ParsedAce>, Report<HcsError>> {
    let mut dacl_present = 0i32;
    let mut dacl = ptr::null_mut();
    let mut dacl_defaulted = 0i32;
    if unsafe {
        GetSecurityDescriptorDacl(
            descriptor,
            &mut dacl_present,
            &mut dacl,
            &mut dacl_defaulted,
        )
    } == 0
    {
        return Err(security_report("GetSecurityDescriptorDacl failed"));
    }
    if dacl_present == 0 || dacl.is_null() {
        return Err(security_report(
            "security descriptor does not contain an explicit DACL",
        ));
    }

    let mut information = AclSizeInformation {
        ace_count: 0,
        acl_bytes_in_use: 0,
        acl_bytes_free: 0,
    };
    if unsafe {
        GetAclInformation(
            dacl,
            (&mut information as *mut AclSizeInformation).cast(),
            std::mem::size_of::<AclSizeInformation>() as u32,
            ACL_SIZE_INFORMATION_CLASS,
        )
    } == 0
    {
        return Err(security_report("GetAclInformation failed"));
    }

    let mut aces = Vec::with_capacity(information.ace_count as usize);
    for index in 0..information.ace_count {
        let mut ace = ptr::null_mut();
        if unsafe { GetAce(dacl, index, &mut ace) } == 0 || ace.is_null() {
            return Err(security_report(format!("GetAce failed for index {index}")));
        }
        let header = unsafe { &*(ace.cast::<AceHeader>()) };
        if header.ace_type != ACCESS_ALLOWED_ACE_TYPE {
            return Err(security_report(format!(
                "unexpected non-allow ACE type {}",
                header.ace_type
            )));
        }
        let access_mask = unsafe { (ace.cast::<u8>().add(4).cast::<u32>()).read_unaligned() };
        let sid = unsafe { sid_to_string(ace.cast::<u8>().add(8).cast())? };
        aces.push(ParsedAce {
            ace_type: header.ace_type,
            access_mask,
            sid,
        });
    }
    Ok(aces)
}

/// Read the DACL of an already-open kernel-object handle (e.g. a named
/// pipe server handle) and return its allow ACEs. Used at pipe-creation
/// time to snapshot the descriptor that was actually applied: a
/// single-instance named pipe cannot be reopened for inspection once the
/// guest worker has connected to it.
pub(crate) fn dacl_aces_from_handle(
    handle: *mut c_void,
) -> Result<Vec<ParsedAce>, Report<HcsError>> {
    let mut descriptor = ptr::null_mut();
    let result = unsafe {
        GetSecurityInfo(
            handle,
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut descriptor,
        )
    };
    if result != ERROR_SUCCESS || descriptor.is_null() {
        return Err(security_report(format!(
            "GetSecurityInfo failed on handle: error {result}"
        )));
    }
    let _descriptor = LocalFreeGuard(descriptor);
    parsed_allowed_aces_from_descriptor(descriptor)
}

/// Read the DACL of an EXISTING named pipe (by name) and return its allow
/// ACEs. Opens the client end with `READ_CONTROL` only — permitted by the
/// descriptor itself when the calling logon SID holds an allow ACE — and
/// closes it immediately. Test-only; used by the in-crate pipe tests and
/// the `#[ignore]`d live HCS test that verifies the COM1 bus pipe after a
/// real launch.
#[cfg(test)]
pub(crate) fn named_pipe_dacl_aces(name: &str) -> Result<Vec<ParsedAce>, Report<HcsError>> {
    let wide: Vec<u16> = name.encode_utf16().chain([0]).collect();
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            READ_CONTROL,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            ptr::null_mut(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(security_report(format!(
            "CreateFileW open for DACL inspection failed for {name}: {}",
            std::io::Error::last_os_error()
        )));
    }
    let _handle = HandleGuard(handle);

    dacl_aces_from_handle(handle)
}

/// Append an allow ACE for the raw `sid` with the per-VM disk access mask
/// to `path`'s DACL, preserving every existing ACE.
///
/// The SID is used as opaque bytes — never resolved through
/// `LookupAccountSid` — because the per-VM `NT VIRTUAL MACHINE\<vm-guid>`
/// identity has no account record until VMMS creates the compute system
/// (which happens *after* the disk grant in the provisioning order). This
/// is why `icacls /grant *S-1-5-83-...` fails with ERROR_NONE_MAPPED (1332)
/// here while the same SID works as an SDDL/ACE principal.
pub(crate) fn grant_file_identity_access(path: &Path, sid: &str) -> Result<(), Report<HcsError>> {
    edit_file_dacl(path, sid, true)
}

/// Remove exactly the ACE granting `sid` on `path`, preserving every other
/// ACE (including ACEs added by other tools). A missing file is an
/// idempotent success (the ACE cannot exist without the file).
pub(crate) fn revoke_file_identity_access(path: &Path, sid: &str) -> Result<(), Report<HcsError>> {
    if !path.exists() {
        return Ok(());
    }
    edit_file_dacl(path, sid, false)
}

/// Read `path`'s current DACL, rebuild it with the `sid` ACE added
/// (`grant`) or removed (`revoke`), and write the modified DACL back with
/// `SetNamedSecurityInfoW`. The edit never replaces the whole descriptor
/// from a snapshot: the current ACL is read live and every unrelated ACE
/// is copied byte-for-byte.
fn edit_file_dacl(path: &Path, sid: &str, grant: bool) -> Result<(), Report<HcsError>> {
    // The wide conversion keeps every code unit of the real path: a lossy
    // round trip here could name a different file for the ACE grant/revoke.
    let wide_path = wide_path(path);
    let (old_dacl, _old_descriptor) = dacl_by_path(&wide_path, path)?;

    let mut information = AclSizeInformation {
        ace_count: 0,
        acl_bytes_in_use: 0,
        acl_bytes_free: 0,
    };
    if !old_dacl.is_null()
        && unsafe {
            GetAclInformation(
                old_dacl,
                (&mut information as *mut AclSizeInformation).cast(),
                std::mem::size_of::<AclSizeInformation>() as u32,
                ACL_SIZE_INFORMATION_CLASS,
            )
        } == 0
    {
        return Err(security_report("GetAclInformation failed on file DACL"));
    }

    let sid_ptr = convert_sid(sid)?;
    let sid_bytes = unsafe { GetLengthSid(sid_ptr.0) } as usize;
    // ACCESS_ALLOWED_ACE = 4-byte ACE_HEADER + 4-byte ACCESS_MASK + SID.
    let added_ace_size = 8 + sid_bytes;
    // A NULL DACL grants everyone; an ACL always carries an 8-byte header.
    let existing_bytes = information.acl_bytes_in_use.max(8) as usize;
    let new_acl_size = existing_bytes + usize::from(grant) * added_ace_size;
    let mut new_acl = vec![0u64; new_acl_size.div_ceil(8)];
    let new_acl_ptr = new_acl.as_mut_ptr().cast::<c_void>();
    if unsafe { InitializeAcl(new_acl_ptr, new_acl_size as u32, ACL_REVISION) } == 0 {
        return Err(security_report("InitializeAcl failed"));
    }

    let mut already_present = false;
    if !old_dacl.is_null() {
        for index in 0..information.ace_count {
            let mut ace = ptr::null_mut();
            if unsafe { GetAce(old_dacl, index, &mut ace) } == 0 || ace.is_null() {
                return Err(security_report(format!("GetAce failed for index {index}")));
            }
            let ace_sid = unsafe { ace_sid_to_string(ace) }?;
            if ace_sid == sid {
                if grant {
                    // Keep the existing ACE (re-granting is a no-op) but do
                    // not append a duplicate below.
                    already_present = true;
                } else {
                    continue;
                }
            }
            let header = unsafe { &*(ace.cast::<AceHeader>()) };
            if unsafe {
                AddAce(
                    new_acl_ptr,
                    ACL_REVISION,
                    MAXDWORD,
                    ace,
                    u32::from(header.ace_size),
                )
            } == 0
            {
                return Err(security_report(format!("AddAce failed for index {index}")));
            }
        }
    }
    if grant
        && !already_present
        && unsafe {
            AddAccessAllowedAceEx(new_acl_ptr, ACL_REVISION, 0, VM_DISK_ACCESS_MASK, sid_ptr.0)
        } == 0
    {
        return Err(security_report("AddAccessAllowedAceEx failed"));
    }

    let result = unsafe {
        SetNamedSecurityInfoW(
            wide_path.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            new_acl_ptr,
            ptr::null_mut(),
        )
    };
    if result != ERROR_SUCCESS {
        return Err(security_report(format!(
            "SetNamedSecurityInfoW failed on {}: error {result}",
            path.display()
        )));
    }
    Ok(())
}

/// Read `path`'s security descriptor and return its DACL pointer. The
/// returned ACL points into the descriptor allocation, so the returned
/// guard must stay alive while the ACL is used.
fn dacl_by_path(
    wide_path: &[u16],
    path: &Path,
) -> Result<(*mut c_void, LocalFreeGuard), Report<HcsError>> {
    let mut dacl = ptr::null_mut();
    let mut descriptor = ptr::null_mut();
    let result = unsafe {
        GetNamedSecurityInfoW(
            wide_path.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut dacl,
            ptr::null_mut(),
            &mut descriptor,
        )
    };
    if result != ERROR_SUCCESS || descriptor.is_null() {
        return Err(security_report(format!(
            "GetNamedSecurityInfoW failed on {}: error {result}",
            path.display()
        )));
    }
    Ok((dacl, LocalFreeGuard(descriptor)))
}

/// Parse a SID string into a binary SID the ACL APIs accept.
fn convert_sid(sid: &str) -> Result<LocalFreeGuard, Report<HcsError>> {
    let wide: Vec<u16> = sid.encode_utf16().chain([0]).collect();
    let mut converted = ptr::null_mut();
    if unsafe { ConvertStringSidToSidW(wide.as_ptr(), &mut converted) } == 0 || converted.is_null()
    {
        return Err(security_report(format!(
            "ConvertStringSidToSidW failed for {sid:?}"
        )));
    }
    Ok(LocalFreeGuard(converted))
}

/// The SID string of an ACE (`ACE_HEADER` is 4 bytes, `ACCESS_MASK` 4 bytes,
/// so the SID starts at offset 8).
unsafe fn ace_sid_to_string(ace: *mut c_void) -> Result<String, Report<HcsError>> {
    // SAFETY: callers hand in a valid ACE pointer whose SID is in bounds.
    let sid = unsafe { ace.cast::<u8>().add(8).cast() };
    // SAFETY: `sid` is a valid SID inside a live ACE.
    unsafe { sid_to_string(sid) }
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn CloseHandle(handle: *mut c_void) -> i32;
    fn GetCurrentProcess() -> *mut c_void;
    fn LocalFree(memory: *mut c_void) -> *mut c_void;
    fn CreateNamedPipeW(
        lp_name: *const u16,
        dw_open_mode: u32,
        dw_pipe_mode: u32,
        n_max_instances: u32,
        n_out_buffer_size: u32,
        n_in_buffer_size: u32,
        n_default_time_out: u32,
        lp_security_attributes: *mut c_void,
    ) -> *mut c_void;
}

#[link(name = "advapi32")]
unsafe extern "system" {
    fn OpenProcessToken(process: *mut c_void, desired_access: u32, token: *mut *mut c_void) -> i32;
    fn GetTokenInformation(
        token: *mut c_void,
        information_class: u32,
        information: *mut c_void,
        information_length: u32,
        return_length: *mut u32,
    ) -> i32;
    fn ConvertSidToStringSidW(sid: *mut c_void, string_sid: *mut *mut u16) -> i32;
    fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
        string_security_descriptor: *const u16,
        string_sd_revision: u32,
        security_descriptor: *mut *mut c_void,
        security_descriptor_size: *mut u32,
    ) -> i32;
    fn IsValidSecurityDescriptor(security_descriptor: *const c_void) -> i32;
}

#[link(name = "advapi32")]
unsafe extern "system" {
    fn GetSecurityDescriptorDacl(
        security_descriptor: *const c_void,
        dacl_present: *mut i32,
        dacl: *mut *mut c_void,
        dacl_defaulted: *mut i32,
    ) -> i32;
    fn GetAclInformation(
        acl: *const c_void,
        information: *mut c_void,
        information_length: u32,
        information_class: u32,
    ) -> i32;
    fn GetAce(acl: *const c_void, ace_index: u32, ace: *mut *mut c_void) -> i32;
    fn GetSecurityInfo(
        handle: *mut c_void,
        object_type: u32,
        security_information: u32,
        ppsid_owner: *mut *mut c_void,
        ppsid_group: *mut *mut c_void,
        pp_dacl: *mut *mut c_void,
        pp_sacl: *mut *mut c_void,
        pp_security_descriptor: *mut *mut c_void,
    ) -> u32;
    fn GetNamedSecurityInfoW(
        object_name: *const u16,
        object_type: u32,
        security_information: u32,
        ppsid_owner: *mut *mut c_void,
        ppsid_group: *mut *mut c_void,
        pp_dacl: *mut *mut c_void,
        pp_sacl: *mut *mut c_void,
        pp_security_descriptor: *mut *mut c_void,
    ) -> u32;
    fn SetNamedSecurityInfoW(
        object_name: *const u16,
        object_type: u32,
        security_information: u32,
        psid_owner: *mut c_void,
        psid_group: *mut c_void,
        p_dacl: *mut c_void,
        p_sacl: *mut c_void,
    ) -> u32;
    fn InitializeAcl(pacl: *mut c_void, acl_length: u32, acl_revision: u32) -> i32;
    fn AddAce(
        pacl: *mut c_void,
        dw_ace_revision: u32,
        dw_starting_ace_index: u32,
        p_ace_list: *const c_void,
        n_ace_list_length: u32,
    ) -> i32;
    fn AddAccessAllowedAceEx(
        pacl: *mut c_void,
        dw_ace_revision: u32,
        ace_flags: u32,
        access_mask: u32,
        p_sid: *mut c_void,
    ) -> i32;
    fn ConvertStringSidToSidW(string_sid: *const u16, sid: *mut *mut c_void) -> i32;
    fn GetLengthSid(sid: *const c_void) -> u32;
}

#[cfg(test)]
#[link(name = "kernel32")]
unsafe extern "system" {
    fn CreateFileW(
        lp_file_name: *const u16,
        dw_desired_access: u32,
        dw_share_mode: u32,
        lp_security_attributes: *mut c_void,
        dw_creation_disposition: u32,
        dw_flags_and_attributes: u32,
        h_template_file: *mut c_void,
    ) -> *mut c_void;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deny_by_default_descriptor_has_no_allow_aces() {
        let aces = parsed_allowed_aces(DENY_BY_DEFAULT_SDDL).expect("valid deny ACL");
        assert!(aces.is_empty());
    }

    #[test]
    fn missing_logon_sid_group_is_an_error_not_a_wrong_principal() {
        let empty: [SidAndAttributes; 0] = [];
        assert_eq!(logon_sid_group_index(&empty), None);

        let no_logon = [
            SidAndAttributes {
                sid: ptr::null_mut(),
                attributes: 0x0000_0004,
            },
            SidAndAttributes {
                sid: ptr::null_mut(),
                attributes: 0x0000_0002,
            },
        ];
        assert_eq!(
            logon_sid_group_index(&no_logon),
            None,
            "a token without a logon SID group must not fall back to group 0"
        );

        let with_logon = [
            SidAndAttributes {
                sid: ptr::null_mut(),
                attributes: 0x0000_0004,
            },
            SidAndAttributes {
                sid: ptr::null_mut(),
                attributes: SE_GROUP_LOGON_ID,
            },
        ];
        assert_eq!(logon_sid_group_index(&with_logon), Some(1));
    }

    #[test]
    fn service_descriptor_grants_only_the_logon_sid() {
        let sid = "S-1-5-5-123-456";
        let descriptor = allow_sid_descriptor(sid).expect("valid service ACL");
        let aces = parsed_allowed_aces(&descriptor).expect("parse service ACL");
        assert_eq!(aces.len(), 1);
        assert_eq!(aces[0].ace_type, ACCESS_ALLOWED_ACE_TYPE);
        assert_ne!(aces[0].access_mask, 0);
        assert_eq!(aces[0].sid, sid);
        assert!(!descriptor.contains("WD"));
        assert!(!descriptor.contains("BA"));
    }

    #[test]
    fn malformed_sddl_is_rejected_by_windows() {
        assert!(validate_sddl("D:P(A;;FA;;;not-a-sid)").is_err());
    }

    #[test]
    fn per_vm_sid_derives_from_the_vm_guid_le_rids() {
        // GUID 11223344-5566-7788-99aa-bbccddeeff00; the LE byte layout is
        // 44 33 22 11 | 66 55 | 88 77 | 99 aa bb cc dd ee ff 00, giving
        // RIDs 0x11223344, 0x77885566, 0xccbbaa99, 0x00ffeedd. The fixed
        // identity RID 1 leads (verified against live per-VM accounts).
        let vm_id =
            Uuid::parse_str("11223344-5566-7788-99aa-bbccddeeff00").expect("valid test GUID");
        assert_eq!(
            vm_identity_sid(vm_id),
            "S-1-5-83-1-287454020-2005423462-3434850969-16772829"
        );
        // The nil GUID maps to the all-zero RIDs under the identity RID.
        assert_eq!(vm_identity_sid(Uuid::nil()), "S-1-5-83-1-0-0-0-0");
        // Distinct GUIDs produce distinct SIDs.
        assert_ne!(vm_identity_sid(vm_id), vm_identity_sid(Uuid::nil()));
    }

    #[test]
    fn derived_per_vm_sid_round_trips_through_windows_sddl_validation() {
        for vm_id in [
            Uuid::nil(),
            Uuid::now_v7(),
            Uuid::parse_str("11223344-5566-7788-99aa-bbccddeeff00").expect("valid GUID"),
        ] {
            let sid = vm_identity_sid(vm_id);
            validate_vm_identity_sid(&sid).unwrap_or_else(|error| {
                panic!("derived SID {sid} must be accepted by Windows: {error}")
            });
        }
    }

    #[test]
    fn named_pipe_descriptor_grants_logon_vm_identity_and_system_only() {
        let vm_id =
            Uuid::parse_str("11223344-5566-7788-99aa-bbccddeeff00").expect("valid test GUID");
        let sddl = named_pipe_sddl(vm_id).expect("build named-pipe SDDL");
        let aces = parsed_allowed_aces(&sddl).expect("parse named-pipe DACL");
        let logon_sid = current_logon_sid().expect("read current logon SID");
        let expected = [
            logon_sid.as_str(),
            "S-1-5-83-1-287454020-2005423462-3434850969-16772829",
            "S-1-5-18",
        ];
        let actual: Vec<&str> = aces.iter().map(|ace| ace.sid.as_str()).collect();
        assert_eq!(
            actual, expected,
            "the DACL must contain exactly logon, per-VM identity, and SYSTEM ACEs"
        );
        assert!(aces.iter().all(|ace| ace.access_mask == GENERIC_ALL));
        assert!(!sddl.contains("WD"));
        assert!(!sddl.contains("BA"));
    }

    #[test]
    fn created_pipe_dacl_contains_exactly_three_expected_aces() {
        let vm_id = Uuid::new_v4();
        let sddl = named_pipe_sddl(vm_id).expect("build named-pipe SDDL");
        let name = format!(r"\\.\pipe\jyth-test-{}", Uuid::now_v7());
        let handle = create_pipe_with_security(&name, &sddl).expect("create secured pipe");

        let aces = named_pipe_dacl_aces(&name).expect("read pipe DACL from the live handle");
        let logon_sid = current_logon_sid().expect("read current logon SID");
        let vm_sid = vm_identity_sid(vm_id);
        let expected = [logon_sid.as_str(), vm_sid.as_str(), "S-1-5-18"];
        let actual: Vec<&str> = aces.iter().map(|ace| ace.sid.as_str()).collect();
        assert_eq!(
            actual, expected,
            "the created pipe must carry exactly the logon, per-VM identity, and SYSTEM ACEs"
        );
        assert!(
            aces.iter()
                .all(|ace| ace.ace_type == ACCESS_ALLOWED_ACE_TYPE)
        );
        assert!(
            aces.iter().all(|ace| ace.access_mask != 0),
            "applied ACE masks must grant rights: {aces:?}"
        );
        drop(handle);
    }

    #[test]
    fn second_pipe_instance_of_same_name_is_rejected() {
        let sddl = named_pipe_sddl(Uuid::nil()).expect("build named-pipe SDDL");
        let name = format!(r"\\.\pipe\jyth-test-{}", Uuid::now_v7());
        let first = create_pipe_with_security(&name, &sddl).expect("first instance");

        let error = create_pipe_with_security(&name, &sddl)
            .expect_err("a second instance of the same name must be rejected");
        // With FILE_FLAG_FIRST_PIPE_INSTANCE the second create fails with
        // ERROR_ACCESS_DENIED; ERROR_PIPE_BUSY is the error when the
        // instance count is exhausted without the flag. Either proves the
        // namespace cannot be pre-created.
        let code = error.raw_os_error();
        assert!(
            matches!(code, Some(5) | Some(231)),
            "unexpected second-create error: {error} ({code:?})"
        );
        drop(first);
    }

    /// Parses the allow ACEs of a file's live DACL (test helper).
    fn file_dacl_aces(path: &Path) -> Vec<ParsedAce> {
        let wide = wide_path(path);
        let (dacl, _descriptor) = dacl_by_path(&wide, path).expect("read file DACL");
        if dacl.is_null() {
            return Vec::new();
        }
        let mut information = AclSizeInformation {
            ace_count: 0,
            acl_bytes_in_use: 0,
            acl_bytes_free: 0,
        };
        assert_ne!(
            unsafe {
                GetAclInformation(
                    dacl,
                    (&mut information as *mut AclSizeInformation).cast(),
                    std::mem::size_of::<AclSizeInformation>() as u32,
                    ACL_SIZE_INFORMATION_CLASS,
                )
            },
            0,
            "GetAclInformation failed"
        );
        let mut aces = Vec::with_capacity(information.ace_count as usize);
        for index in 0..information.ace_count {
            let mut ace = ptr::null_mut();
            assert_ne!(unsafe { GetAce(dacl, index, &mut ace) }, 0, "GetAce failed");
            let header = unsafe { &*(ace.cast::<AceHeader>()) };
            let access_mask = unsafe { (ace.cast::<u8>().add(4).cast::<u32>()).read_unaligned() };
            aces.push(ParsedAce {
                ace_type: header.ace_type,
                access_mask,
                sid: unsafe { ace_sid_to_string(ace) }.expect("parse ACE SID"),
            });
        }
        aces
    }

    /// A synthetic per-VM SID (no account record exists — the exact
    /// condition under which `icacls /grant *<sid>` fails with
    /// ERROR_NONE_MAPPED).
    const SYNTHETIC_VM_SID: &str = "S-1-5-83-111-222-333-444";

    #[test]
    fn file_grant_adds_only_the_target_ace_and_revoke_removes_it() {
        let dir = std::env::temp_dir().join(format!("jyth-security-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create test dir");
        let file = dir.join("grant-probe.vhdx");
        std::fs::write(&file, b"x").expect("write probe file");
        let baseline_count = file_dacl_aces(&file).len();

        grant_file_identity_access(&file, SYNTHETIC_VM_SID).expect("grant per-VM SID");
        let aces = file_dacl_aces(&file);
        let granted = aces
            .iter()
            .find(|ace| ace.sid == SYNTHETIC_VM_SID)
            .unwrap_or_else(|| panic!("granted SID must appear in the DACL: {aces:?}"));
        // The kernel maps the generic read/write bits to the concrete file
        // rights (FILE_GENERIC_READ | FILE_GENERIC_WRITE = 0x12019F).
        const FILE_GENERIC_READ_WRITE: u32 = 0x12019F;
        assert_eq!(
            granted.access_mask & FILE_GENERIC_READ_WRITE,
            FILE_GENERIC_READ_WRITE,
            "the ACE must grant read+write on the backing file"
        );
        assert_eq!(
            aces.len(),
            baseline_count + 1,
            "the grant must add exactly one ACE and preserve the rest"
        );

        // Re-granting is a no-op.
        grant_file_identity_access(&file, SYNTHETIC_VM_SID).expect("re-grant per-VM SID");
        assert_eq!(
            file_dacl_aces(&file).len(),
            baseline_count + 1,
            "re-grant must not duplicate the ACE"
        );

        revoke_file_identity_access(&file, SYNTHETIC_VM_SID).expect("revoke per-VM SID");
        let aces = file_dacl_aces(&file);
        assert!(
            !aces.iter().any(|ace| ace.sid == SYNTHETIC_VM_SID),
            "revoked SID must leave the DACL: {aces:?}"
        );
        assert_eq!(
            aces.len(),
            baseline_count,
            "revoke must remove exactly the target ACE"
        );

        std::fs::remove_dir_all(&dir).expect("remove test dir");
    }

    #[test]
    fn create_pipe_rejects_malformed_sddl_without_creating() {
        let name = format!(r"\\.\pipe\jyth-test-{}", Uuid::now_v7());
        let error = create_pipe_with_security(&name, "D:P(A;;FA;;;not-a-sid)")
            .expect_err("malformed SDDL must be rejected before CreateNamedPipeW");
        assert!(
            error.to_string().contains("not-a-sid"),
            "the rejection must name the malformed descriptor: {error}"
        );
    }
}
