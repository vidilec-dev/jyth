use crate::cs::ComputeSystem;
use crate::error::HcsError;
use crate::{ext::HcsStartComputeSystem, operation::hcs_operation};
use error_stack::Report;

pub(crate) async fn start_compute_system(sys: &ComputeSystem) -> Result<(), Report<HcsError>> {
    let handle = crate::cs::SendHandle(sys.handle);
    hcs_operation(move |op| unsafe { HcsStartComputeSystem(handle.as_raw(), op, std::ptr::null()) })
        .await
        .map(|_| ())
}
