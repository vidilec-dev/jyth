//! COM1-only bootstrap execution for the kernel-builder guest.
//!
//! This path intentionally does not configure a network or bind the TCP
//! command listener. It keeps the authenticated COM1 boot/READY exchange,
//! runs one host-declared executable directly, and streams its declared
//! artifact back over the same serial channel. Normal guests configure the
//! NIC and bind the TCP command listener at their configured guest address.

use std::fs::File;
use std::io::{Error, Read};
use std::path::Path;
use std::process::Command;

use error_stack::Report;
use protocol::auth::{
    BootConfigV1, BootstrapResultV1, MAX_AUTH_FRAME, MAX_BOOTSTRAP_ARTIFACT_BYTES,
    MAX_BOOTSTRAP_CHUNK, ReadyV1,
};

use crate::components::com::Com;
use crate::errors::{InitError, InitResult};

/// Run the single authenticated COM1 bootstrap operation.
pub(crate) fn run_bootstrap(
    mut com1: Com,
    boot_config: &BootConfigV1,
    boot_frame: Vec<u8>,
) -> InitResult<()> {
    let bootstrap = boot_config.bootstrap.as_ref().ok_or_else(|| {
        Report::new(InitError::Bootstrap).attach("bootstrap mode did not receive a command")
    })?;

    let ready = ReadyV1::for_boot(&boot_config.capability, &boot_frame)
        .map_err(|error| error.change_context(InitError::BootProtocol))?;
    let ready_frame: Vec<u8> =
        ready
            .try_into()
            .map_err(|error: Report<protocol::ProtocolError>| {
                error.change_context(InitError::BootProtocol)
            })?;
    send_frame(&mut com1, &ready_frame, MAX_AUTH_FRAME)?;

    #[cfg(feature = "tracing")]
    tracing::info!(
        "[JythInit][Bootstrap]: running {} with {} arguments",
        bootstrap.program,
        bootstrap.args.len()
    );
    let status = match Command::new(&bootstrap.program)
        .args(&bootstrap.args)
        .status()
    {
        Ok(status) => status,
        Err(error) => {
            send_result(&mut com1, BootstrapResultV1::command_failed(None))?;
            return Err(Report::new(error)
                .change_context(InitError::ProcessSpawn)
                .attach(bootstrap.program.clone()));
        }
    };

    if !status.success() {
        let result = BootstrapResultV1::command_failed(
            status.code().and_then(|code| u32::try_from(code).ok()),
        );
        send_result(&mut com1, result)?;
        return Err(Report::new(InitError::Bootstrap).attach(format!(
            "bootstrap command exited unsuccessfully: {}",
            status
        )));
    }

    let artifact_path = Path::new(&bootstrap.artifact);
    let metadata = match std::fs::metadata(artifact_path) {
        Ok(metadata) if metadata.is_file() && metadata.len() > 0 => metadata,
        Ok(metadata) => {
            send_result(&mut com1, BootstrapResultV1::artifact_unavailable())?;
            return Err(Report::new(InitError::Bootstrap).attach(format!(
                "bootstrap artifact is not a non-empty file: {} ({} bytes)",
                artifact_path.display(),
                metadata.len()
            )));
        }
        Err(error) => {
            send_result(&mut com1, BootstrapResultV1::artifact_unavailable())?;
            return Err(Report::new(error)
                .change_context(InitError::Bootstrap)
                .attach(format!("bootstrap artifact: {}", artifact_path.display())));
        }
    };

    if metadata.len() > MAX_BOOTSTRAP_ARTIFACT_BYTES {
        send_result(&mut com1, BootstrapResultV1::artifact_unavailable())?;
        return Err(Report::new(InitError::Bootstrap).attach(format!(
            "bootstrap artifact exceeds {} bytes: {}",
            MAX_BOOTSTRAP_ARTIFACT_BYTES,
            artifact_path.display()
        )));
    }

    let digest = match digest_file(artifact_path) {
        Ok(digest) => digest,
        Err(error) => {
            send_result(&mut com1, BootstrapResultV1::artifact_unavailable())?;
            return Err(error);
        }
    };
    let mut artifact = match File::open(artifact_path) {
        Ok(artifact) => artifact,
        Err(error) => {
            send_result(&mut com1, BootstrapResultV1::artifact_unavailable())?;
            return Err(Report::new(error)
                .change_context(InitError::Io)
                .attach(format!("bootstrap artifact: {}", artifact_path.display())));
        }
    };
    let result = BootstrapResultV1::success(metadata.len(), digest)
        .map_err(|error| error.change_context(InitError::BootProtocol))?;
    send_result(&mut com1, result)?;

    let mut chunk = vec![0u8; MAX_BOOTSTRAP_CHUNK];
    loop {
        let read = artifact.read(&mut chunk).map_err(|error| {
            Report::new(error)
                .change_context(InitError::Io)
                .attach(format!("bootstrap artifact: {}", artifact_path.display()))
        })?;
        if read == 0 {
            break;
        }
        send_frame(&mut com1, &chunk[..read], MAX_BOOTSTRAP_CHUNK)?;
    }

    #[cfg(feature = "tracing")]
    tracing::info!(
        "[JythInit][Bootstrap]: streamed {} bytes from {}",
        metadata.len(),
        artifact_path.display()
    );
    Ok(())
}

fn digest_file(path: &Path) -> InitResult<[u8; 32]> {
    let mut file = File::open(path).map_err(|error| {
        Report::new(error)
            .change_context(InitError::Io)
            .attach(format!("bootstrap artifact: {}", path.display()))
    })?;
    let mut hasher = blake3::Hasher::new();
    let mut chunk = [0u8; MAX_BOOTSTRAP_CHUNK];
    loop {
        let read = file.read(&mut chunk).map_err(|error| {
            Report::new(error)
                .change_context(InitError::Io)
                .attach(format!("bootstrap artifact: {}", path.display()))
        })?;
        if read == 0 {
            break;
        }
        hasher.update(&chunk[..read]);
    }
    Ok(*hasher.finalize().as_bytes())
}

fn send_result(com1: &mut Com, result: BootstrapResultV1) -> InitResult<()> {
    let frame = result
        .to_bytes()
        .map_err(|error| error.change_context(InitError::BootProtocol))?;
    send_frame(com1, &frame, MAX_AUTH_FRAME)
}

fn send_frame(com1: &mut Com, frame: &[u8], maximum: usize) -> InitResult<()> {
    com1.send_frame(frame, maximum)
        .map_err(|error: Error| Report::new(error).change_context(InitError::Io))
}
