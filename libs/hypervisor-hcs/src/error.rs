/// Error context for the Windows HCS (Host Compute Service) FFI boundary.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum HcsError {
    /// Caller is not a member of the "Hyper-V Administrators" group (and
    /// elevation/add-membership failed or requires a logoff to take effect).
    HyperVAdmin,
    /// Failed to create / configure a named COM port pipe.
    ComPortSetup,
    /// `HcsCreateComputeSystem` (or the `ComputeSystem` constructor) failed.
    ComputeSystemCreate,
    /// `HcsOpenComputeSystem` failed.
    ComputeSystemOpen,
    /// `HcsStartComputeSystem` failed.
    ComputeSystemStart,
    /// `HcsTerminateComputeSystem` failed.
    ComputeSystemTerminate,
    /// `HcsCreateOperation` returned a null handle.
    OperationCreate,
    /// The synchronous `HcsWaitForOperationResult` path reported failure.
    OperationSyncFailed,
    /// An HCS steering call failed synchronously (non-zero immediate HRESULT).
    OperationFailed,
    /// The async HCS callback was never invoked (the `oneshot` was dropped).
    OperationCallbackMissing,
    /// `HcsGetOperationResult` returned a non-zero HRESULT.
    OperationResult,
    /// `HcsEnumerateComputeSystems` failed.
    Enumeration,
    /// Named-pipe server setup / accept failed.
    NamedPipe,
    /// A pipe connection was cancelled.
    ConnectionCancelled,
    /// Serializing an HCS configuration document failed.
    Serialize,
    /// Deserializing an HCS result / enumeration document failed.
    Deserialize,
    /// An HNS network/endpoint operation failed — create, close, or
    /// delete on a `jyth-nat-*` network. Surfaced by the HNS lifecycle
    /// module in Task I-3.
    Network,
    /// A disk path or mount/size value failed validation (path attached).
    DiskInvalidPath,
    /// The parent directory of a disk path is missing or not a directory.
    DiskParentMissing,
    /// A disk path traverses a reparse point and was rejected.
    DiskReparsePointRejected,
    /// The disk path already exists under `ExistingDiskPolicy::Error`.
    DiskPathExists,
    /// Creating a new VHDX backing file failed.
    DiskCreateFailed,
    /// An existing path is not a valid writable VHDX.
    DiskNotValidWritableVhdx,
    /// The per-path lock for a disk path could not be acquired.
    DiskPathAlreadyClaimed,
    /// The file at a disk path changed identity before deletion.
    DiskIdentityChanged,
    /// A created disk was not initialized by the guest before publication.
    DiskInitializationFailed,
    /// A disk could not be mounted by the guest.
    DiskMountFailed,
    /// A Windows security descriptor could not be built or validated.
    SecurityDescriptor,
    /// The durable runtime journal could not be opened, read, or committed.
    Journal,
    /// The runtime journal contains an unsupported schema version.
    JournalSchemaMismatch,
    /// A journaled resource could not be recovered or cleaned up exactly.
    Cleanup,
}

impl std::fmt::Display for HcsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = match self {
            HcsError::HyperVAdmin => "caller is not a member of the Hyper-V Administrators group",
            HcsError::ComPortSetup => "failed to set up a COM port named pipe",
            HcsError::ComputeSystemCreate => "failed to create the HCS compute system",
            HcsError::ComputeSystemOpen => "failed to open the HCS compute system",
            HcsError::ComputeSystemStart => "failed to start the HCS compute system",
            HcsError::ComputeSystemTerminate => "failed to terminate the HCS compute system",
            HcsError::OperationCreate => "HcsCreateOperation returned a null handle",
            HcsError::OperationSyncFailed => "HcsWaitForOperationResult failed",
            HcsError::OperationFailed => "HCS operation failed synchronously",
            HcsError::OperationCallbackMissing => "HCS operation callback was never invoked",
            HcsError::OperationResult => "HcsGetOperationResult returned a non-zero HRESULT",
            HcsError::Enumeration => "HcsEnumerateComputeSystems failed",
            HcsError::NamedPipe => "named pipe server setup failed",
            HcsError::ConnectionCancelled => "connection cancelled",
            HcsError::Serialize => "failed to serialize an HCS document",
            HcsError::Deserialize => "failed to deserialize an HCS document",
            HcsError::Network => "an HNS network/endpoint operation failed",
            HcsError::DiskInvalidPath => "invalid disk path, mount, or size",
            HcsError::DiskParentMissing => "disk parent directory is missing",
            HcsError::DiskReparsePointRejected => "disk path traverses a reparse point",
            HcsError::DiskPathExists => "disk path already exists and the policy rejects reuse",
            HcsError::DiskCreateFailed => "failed to create the disk backing file",
            HcsError::DiskNotValidWritableVhdx => "existing path is not a valid writable VHDX",
            HcsError::DiskPathAlreadyClaimed => "disk path is already claimed by another operation",
            HcsError::DiskIdentityChanged => "disk file identity changed since it was recorded",
            HcsError::DiskInitializationFailed => "created disk was not initialized by the guest",
            HcsError::DiskMountFailed => "disk could not be mounted by the guest",
            HcsError::SecurityDescriptor => "a Windows security descriptor was invalid",
            HcsError::Journal => "the durable HCS runtime journal failed",
            HcsError::JournalSchemaMismatch => "the HCS runtime journal schema is unsupported",
            HcsError::Cleanup => "journaled HCS resource cleanup failed",
        };
        f.write_str(msg)
    }
}

impl std::error::Error for HcsError {}
