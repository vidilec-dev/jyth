pub mod dispatch;

use crate::bus::dispatch::Dispatcher;
use crate::components::com::Com;
use crate::components::tcp::TcpCommandListener;
use crate::errors::InitResult;
use protocol::auth::{BootConfigV1, MAX_AUTH_FRAME, ReadyV1};
use std::sync::Arc;

/// Run the guest command bus: start the dispatcher over the bound TCP
/// listener, then send the authenticated READY proof on COM1. READY is
/// deliberately sent only after the listener and dispatcher are active, so a
/// bind failure or a missing network always prevents READY.
pub async fn run_bus(
    tcp: TcpCommandListener,
    mut com: Com,
    boot_config: BootConfigV1,
    boot_frame: Vec<u8>,
) -> InitResult<()> {
    let capability = Arc::new(boot_config.capability);
    let dispatcher = Dispatcher::new(tcp, boot_config.vm_id, capability.clone());
    let dispatcher_task = smol::spawn(dispatcher.run());

    let ready = ReadyV1::for_boot(&capability, &boot_frame)
        .map_err(|error| error.change_context(crate::errors::InitError::BootProtocol))?;
    let ready_frame: Vec<u8> =
        ready
            .try_into()
            .map_err(|error: error_stack::Report<protocol::ProtocolError>| {
                error.change_context(crate::errors::InitError::BootProtocol)
            })?;
    com.send_frame(&ready_frame, MAX_AUTH_FRAME)
        .map_err(|error| {
            error_stack::Report::new(error).change_context(crate::errors::InitError::Io)
        })?;

    dispatcher_task.await?;

    Ok(())
}
