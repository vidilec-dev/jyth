use crate::error::HcsError;
use crate::security;
use error_stack::Report;
use std::os::windows::io::IntoRawHandle;
use uuid::Uuid;

use tokio::{
    io::{AsyncBufRead, BufReader},
    net::windows::named_pipe::NamedPipeServer,
    select,
};
use tokio_util::sync::CancellationToken;

pub(crate) async fn connect_pipe(
    vm_id: Uuid,
    pipe_name: &str,
    cancel_token: CancellationToken,
) -> Result<impl AsyncBufRead, Report<HcsError>> {
    // The COM0 logs pipe carries an explicit deny-by-default descriptor
    // (current logon SID, exact per-VM identity, SYSTEM) instead of the
    // default ACL; FILE_FLAG_FIRST_PIPE_INSTANCE still prevents namespace
    // pre-creation.
    let sddl = security::named_pipe_sddl(vm_id)?;
    let handle = security::create_pipe_with_security(pipe_name, &sddl)
        .map_err(|e| Report::new(e).change_context(HcsError::NamedPipe))?;
    // SAFETY: `handle` is the sole reference to a fresh pipe instance
    // created with FILE_FLAG_OVERLAPPED; the transfer hands the closing
    // responsibility to Tokio.
    let pipe = unsafe { NamedPipeServer::from_raw_handle(handle.into_raw_handle()) }
        .map_err(|e| Report::new(e).change_context(HcsError::NamedPipe))?;

    select! {
        _ = cancel_token.cancelled() => {
            Err(Report::new(HcsError::ConnectionCancelled)
                .attach(format!("pipe {pipe_name}")))
        }
        _ = pipe.connect() => {
            Ok(BufReader::new(pipe))
        }
    }
}
