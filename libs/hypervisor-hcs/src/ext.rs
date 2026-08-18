use std::ffi::c_void;

#[allow(non_camel_case_types)]
pub type HCS_SYSTEM = *mut c_void;
#[allow(non_camel_case_types)]
pub type HCS_OPERATION = *mut c_void;
#[allow(non_camel_case_types)]
pub type HCS_OPERATION_COMPLETION =
    unsafe extern "system" fn(operation: HCS_OPERATION, context: *mut c_void);

#[link(name = "kernel32")]
unsafe extern "system" {
    pub fn LocalFree(p: *mut c_void) -> *mut c_void;
    pub fn CloseHandle(handle: *mut c_void) -> i32;
    pub fn WaitForSingleObject(handle: *mut c_void, timeout_ms: u32) -> u32;
    pub fn GetExitCodeProcess(handle: *mut c_void, exit_code: *mut u32) -> i32;
}

#[link(name = "advapi32")]
unsafe extern "system" {
    pub fn CheckTokenMembership(
        token_handle: *mut c_void,
        sid_to_check: *mut c_void,
        is_member: *mut i32,
    ) -> i32;
    pub fn ConvertStringSidToSidW(string_sid: *const u16, sid: *mut *mut c_void) -> i32;
    pub fn GetUserNameW(buffer: *mut u16, size: *mut u32) -> i32;
}

#[link(name = "shell32")]
unsafe extern "system" {
    pub fn ShellExecuteExW(info: *mut ShellExecuteInfoW) -> i32;
}

#[repr(C)]
pub struct ShellExecuteInfoW {
    pub cb_size: u32,
    pub f_mask: u32,
    pub hwnd: *mut c_void,
    pub lp_verb: *const u16,
    pub lp_file: *const u16,
    pub lp_parameters: *const u16,
    pub lp_directory: *const u16,
    pub n_show: i32,
    pub h_inst_app: *mut c_void,
    pub lp_id_list: *mut c_void,
    pub lp_class: *const u16,
    pub hkey_class: *mut c_void,
    pub dw_hot_key: u32,
    pub h_icon_or_monitor: *mut c_void,
    pub h_process: *mut c_void,
}

pub const SEE_MASK_NOCLOSEPROCESS: u32 = 0x00000040;
pub const SW_SHOWNORMAL: i32 = 1;

#[link(name = "computecore")]
unsafe extern "system" {
    #[allow(dead_code)]
    pub fn HcsEnumerateComputeSystems(query: *const u16, operation: HCS_OPERATION) -> i32;
    pub fn HcsOpenComputeSystem(
        id: *const u16,
        requested_access: u32,
        system: *mut HCS_SYSTEM,
    ) -> i32;
    pub fn HcsCreateOperation(
        context: *const c_void,
        callback: Option<HCS_OPERATION_COMPLETION>,
    ) -> HCS_OPERATION;
    pub fn HcsCloseOperation(operation: HCS_OPERATION);
    pub fn HcsWaitForOperationResult(
        operation: HCS_OPERATION,
        timeout_ms: u32,
        result_document: *mut *mut u16,
    ) -> i32;
    /// Fetch the result of an operation that has already completed (typically
    /// observed via the operation's registered completion callback). Unlike
    /// `HcsWaitForOperationResult`, this call never blocks: it returns the
    /// current result immediately. Used by the callback-driven async path in
    /// `operation::hcs_operation`.
    pub fn HcsGetOperationResult(operation: HCS_OPERATION, result_document: *mut *mut u16) -> i32;
    pub fn HcsCreateComputeSystem(
        id: *const u16,
        configuration: *const u16,
        operation: HCS_OPERATION,
        security_descriptor: *const c_void,
        system: *mut HCS_SYSTEM,
    ) -> i32;
    pub fn HcsStartComputeSystem(
        system: HCS_SYSTEM,
        operation: HCS_OPERATION,
        options: *const u16,
    ) -> i32;
    pub fn HcsTerminateComputeSystem(
        system: HCS_SYSTEM,
        operation: HCS_OPERATION,
        options: *const u16,
    ) -> i32;
    pub fn HcsCloseComputeSystem(system: HCS_SYSTEM);
}

pub const GENERIC_ALL: u32 = 0x10000000;

/// HCS HRESULT indicating the requested operation is still in progress
/// (returned by `HcsWaitForOperationResult` when `timeout_ms` elapses
/// before completion, and sometimes returned synchronously by the steering
/// APIs themselves when the call's async work has been queued). Matches the
/// canonical `HCS_E_OPERATION_PENDING` value.
pub const HCS_E_OPERATION_PENDING: i32 = 0x80370120_u32 as i32;
