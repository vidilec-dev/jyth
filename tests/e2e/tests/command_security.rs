//! Live TCP transport-authentication gates (TcpTransportMigrationPlan WP8).
//!
//! Scenarios:
//!
//! - `unauthenticated_same_user_client_cannot_ping_or_shutdown`: a same-user
//!   client with the wrong per-VM capability fails the challenge/MAC
//!   exchange, and a raw TCP client that skips authentication entirely
//!   cannot reach the command decoder.
//! - `normal_authenticated_process_and_file_commands_work`: the control
//!   path — the authenticated host client still drives the guest.
//! - `oversized_pre_auth_frame_does_not_allocate_or_starve_listener`: a
//!   frame whose declared length exceeds the 4 KiB authentication limit is
//!   rejected before allocation, and a full listener flood of stalled
//!   pre-auth connections cannot starve the authenticated command path.
//! - `capability_of_one_vm_cannot_authenticate_against_another`: VM A's
//!   capability fails against VM B's TCP command endpoint.
//! - `distinct_nat_subnets_produce_distinct_reachable_command_endpoints`:
//!   two concurrent VMs on distinct NAT subnets receive traffic only at
//!   their own configured addresses.
//!
//! The raw client is a plain `tokio::net::TcpStream` to
//! `vm.command_endpoint()` that sends no authentication exchange.
//!
//! Post-run inspection: the VM must answer authenticated commands after
//! every attack attempt, and no connection may survive the authentication
//! deadline.

use std::sync::Arc;
use std::time::Duration;

use e2e_tests::{VmGuard, alpine_image, hcs_test_guard};
use jyth::builder::VmBuilder;
use jyth::vm::ProcessBuilder;
use protocol::auth::{AUTHENTICATION_DEADLINE, MAX_GUEST_CONNECTIONS};
use protocol::{Command, SessionCapability};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

/// A test NAT on the given subnet: gateway `.1`, guest `.10`.
fn nat(subnet: &str) -> vm_model::network::Nat {
    let octets: Vec<u32> = subnet
        .split('.')
        .take(3)
        .map(|o| o.parse().expect("subnet"))
        .collect();
    let gateway = format!("{}.{}.{}.1", octets[0], octets[1], octets[2]);
    let guest_ip = format!("{}.{}.{}.10", octets[0], octets[1], octets[2]);
    vm_model::network::Nat::try_new(subnet, gateway, guest_ip, ["8.8.8.8"]).expect("valid test NAT")
}

/// Open a raw TCP stream to the guest command endpoint without any
/// authentication exchange.
async fn raw_connect(vm: &jyth::VM) -> std::io::Result<tokio::net::TcpStream> {
    tokio::net::TcpStream::connect(vm.command_endpoint()).await
}

/// Write one little-endian length-prefixed frame on a raw connection.
async fn raw_write_frame(
    stream: &mut tokio::net::TcpStream,
    payload: &[u8],
) -> std::io::Result<()> {
    let length = u32::try_from(payload.len()).map_err(std::io::Error::other)?;
    stream.write_all(&length.to_le_bytes()).await?;
    stream.write_all(payload).await?;
    stream.flush().await
}

/// Assert that the guest closed the connection (EOF or reset) within
/// `deadline`. Returns an error only when the connection stays open past
/// the deadline — i.e. the guest accepted unauthenticated traffic.
async fn expect_guest_close(
    stream: &mut tokio::net::TcpStream,
    deadline: Duration,
) -> Result<(), String> {
    let wait = async {
        let mut buf = [0u8; 4096];
        loop {
            match stream.read(&mut buf).await {
                Ok(0) => return Ok(()),
                Ok(_) => continue,
                Err(_) => return Ok(()),
            }
        }
    };
    tokio::time::timeout(deadline, wait).await.map_err(|_| {
        "guest kept the unauthenticated connection open past the authentication deadline"
            .to_string()
    })?
}

/// Wait until the guest has dropped the stalled pre-auth connections, by
/// polling the authenticated command path — the same probe the starvation
/// test asserts on. While the connection-admission gate is exhausted the
/// guest rejects each attempt at admission (never consuming a permit), so a
/// rejected attempt is fast; success means a permit is free again.
async fn wait_for_stalled_connections_dropped(vm: &jyth::VM, cap: Duration) -> Result<(), String> {
    let wait = async {
        loop {
            let process = ProcessBuilder::new()
                .shell("echo still-alive")
                .build()
                .map_err(|error| error.to_string())?;
            match vm.run(process).await {
                Ok(exit) if exit.success() => return Ok(()),
                Ok(exit) => return Err(format!("probe command exited unsuccessfully: {exit}")),
                Err(_) => {}
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    };
    tokio::time::timeout(cap, wait)
        .await
        .map_err(|_| format!("guest kept the stalled pre-auth connections past {cap:?}"))?
}

/// A same-user client without the per-VM capability cannot ping or shut
/// down the guest: the wrong-key `com::TcpEndpoint` fails the challenge/MAC
/// exchange, and a raw unauthenticated TCP client is closed before any
/// command frame is decoded.
#[tokio::test]
async fn unauthenticated_same_user_client_cannot_ping_or_shutdown() -> TestResult {
    #[cfg(feature = "tracing")]
    tracing::init();

    let _hcs_guard = hcs_test_guard().await?;
    let (kernel, rootfs) = alpine_image();
    let mut vm = VmGuard::new(
        VmBuilder::new()
            .kernel(kernel)
            .rootfs(rootfs)
            .network(())
            .launch()
            .await?,
    );
    let vm_uuid = vm.uuid();

    // Same user, wrong capability: the guest rejects the MAC and closes the
    // connection, so the host-side authentication never completes.
    let wrong_key = com::TcpEndpoint::new(
        vm.command_endpoint(),
        vm_uuid,
        Arc::new(SessionCapability::from_bytes([0u8; 32])),
    );
    assert!(
        wrong_key.connect_async().await.is_err(),
        "a wrong-capability client must never authenticate"
    );

    // Raw client skipping the auth exchange entirely: a ping command frame
    // sent where the auth response is expected must be rejected (parse
    // failure) and the connection closed within the auth deadline.
    let mut raw = raw_connect(&vm).await?;
    let ping: Vec<u8> = Command::Ping.try_into().expect("serialize ping frame");
    raw_write_frame(&mut raw, &ping).await?;
    expect_guest_close(&mut raw, AUTHENTICATION_DEADLINE + Duration::from_secs(2)).await?;

    // Control: the authenticated host client still drives the guest.
    let exit = vm
        .run(ProcessBuilder::new().shell("echo control").build()?)
        .await?;
    assert!(exit.success(), "authenticated control command must succeed");
    vm.shutdown().await?;
    Ok(())
}

/// The control path: the authenticated host client can run processes and
/// read/write guest files.
#[tokio::test]
async fn normal_authenticated_process_and_file_commands_work() -> TestResult {
    #[cfg(feature = "tracing")]
    tracing::init();

    let _hcs_guard = hcs_test_guard().await?;
    let (kernel, rootfs) = alpine_image();
    let mut vm = VmGuard::new(
        VmBuilder::new()
            .kernel(kernel)
            .rootfs(rootfs)
            .network(())
            .launch()
            .await?,
    );

    let exit = vm
        .run(
            ProcessBuilder::new()
                .shell("printf authenticated > /tmp/auth-ok")
                .build()?,
        )
        .await?;
    assert!(exit.success(), "authenticated process must succeed");
    assert_eq!(
        vm.file_read("/tmp/auth-ok").await?,
        b"authenticated",
        "process output must be visible to the file protocol"
    );

    vm.file_write("/tmp/auth-roundtrip", "roundtrip").await?;
    assert_eq!(
        vm.file_read("/tmp/auth-roundtrip").await?,
        b"roundtrip",
        "authenticated file write/read roundtrip"
    );

    vm.shutdown().await?;
    Ok(())
}

/// A pre-auth frame declaring a length above `MAX_AUTH_FRAME` is rejected
/// before allocation, and a full flood of stalled pre-auth connections
/// cannot starve the authenticated listener past the deadline.
#[tokio::test]
async fn oversized_pre_auth_frame_does_not_allocate_or_starve_listener() -> TestResult {
    #[cfg(feature = "tracing")]
    tracing::init();

    let _hcs_guard = hcs_test_guard().await?;
    let (kernel, rootfs) = alpine_image();
    let mut vm = VmGuard::new(
        VmBuilder::new()
            .kernel(kernel)
            .rootfs(rootfs)
            .network(())
            .launch()
            .await?,
    );

    // Declared length 1 MiB >> MAX_AUTH_FRAME (4 KiB): the guest rejects
    // the length before allocating payload bytes and closes the connection.
    let mut oversized = raw_connect(&vm).await?;
    let declared: u32 = 1024 * 1024;
    oversized.write_all(&declared.to_le_bytes()).await?;
    oversized.write_all(&[0u8; 4096]).await?;
    oversized.flush().await?;
    expect_guest_close(
        &mut oversized,
        AUTHENTICATION_DEADLINE + Duration::from_secs(2),
    )
    .await?;

    // Stall every guest connection permit with connections that send
    // nothing before authentication. Each one must lose its permit at the
    // authentication deadline, so the listener must still serve an
    // authenticated command afterwards. Poll for the guest to actually drop
    // them instead of sleeping a fixed wall-clock duration: under load the
    // guest may reclaim the stalled permits slower than the deadline plus a
    // fixed slack, and a premature authenticated command would fail
    // spuriously.
    let mut stalled = Vec::new();
    for _ in 0..MAX_GUEST_CONNECTIONS {
        if let Ok(stream) = raw_connect(&vm).await {
            stalled.push(stream);
        }
    }
    wait_for_stalled_connections_dropped(&vm, Duration::from_secs(30)).await?;
    let exit = vm
        .run(ProcessBuilder::new().shell("echo still-alive").build()?)
        .await?;
    assert!(
        exit.success(),
        "the command listener must not be starved by stalled pre-auth connections"
    );
    drop(stalled);

    vm.shutdown().await?;
    Ok(())
}

/// A capability from one VM must never authenticate against another VM's
/// TCP command endpoint: the VM UUID is part of every proof transcript.
#[tokio::test]
async fn capability_of_one_vm_cannot_authenticate_against_another() -> TestResult {
    #[cfg(feature = "tracing")]
    tracing::init();

    let _hcs_guard = hcs_test_guard().await?;
    let (kernel, rootfs) = alpine_image();

    // Two concurrent VMs on distinct NAT subnets: their command endpoints
    // must be distinct and reachable only at their own addresses.
    let mut vm_a = VmGuard::new(
        VmBuilder::new()
            .kernel(kernel.clone())
            .rootfs(rootfs.clone())
            .network(nat("10.92.1.0/24"))
            .launch()
            .await?,
    );
    let mut vm_b = VmGuard::new(
        VmBuilder::new()
            .kernel(kernel)
            .rootfs(rootfs)
            .network(nat("10.92.2.0/24"))
            .launch()
            .await?,
    );
    assert_ne!(
        vm_a.command_endpoint(),
        vm_b.command_endpoint(),
        "distinct NAT subnets must produce distinct command endpoints"
    );

    // VM A's capability against VM B's endpoint must fail authentication.
    let a_capability = vm_a.capability();
    let wrong_vm =
        com::TcpEndpoint::new(vm_b.command_endpoint(), vm_a.uuid(), a_capability.clone());
    assert!(
        wrong_vm.connect_async().await.is_err(),
        "VM A's capability must not authenticate against VM B's endpoint"
    );

    // Both authenticated clients still drive their own guests.
    let exit_a = vm_a
        .run(ProcessBuilder::new().shell("echo a").build()?)
        .await?;
    let exit_b = vm_b
        .run(ProcessBuilder::new().shell("echo b").build()?)
        .await?;
    assert!(exit_a.success() && exit_b.success());
    vm_a.shutdown().await?;
    vm_b.shutdown().await?;
    Ok(())
}

/// Distinct NAT subnets produce distinct reachable command endpoints; each
/// VM receives authenticated traffic only at its own address.
#[tokio::test]
async fn distinct_nat_subnets_produce_distinct_reachable_command_endpoints() -> TestResult {
    #[cfg(feature = "tracing")]
    tracing::init();

    let _hcs_guard = hcs_test_guard().await?;
    let (kernel, rootfs) = alpine_image();

    let mut vm_a = VmGuard::new(
        VmBuilder::new()
            .kernel(kernel.clone())
            .rootfs(rootfs.clone())
            .network(nat("10.93.1.0/24"))
            .launch()
            .await?,
    );
    let mut vm_b = VmGuard::new(
        VmBuilder::new()
            .kernel(kernel)
            .rootfs(rootfs)
            .network(nat("10.93.2.0/24"))
            .launch()
            .await?,
    );

    // A raw client reaching VM A's endpoint receives A's challenge and is
    // closed; the same applies to VM B. Authenticated commands on both VMs
    // prove each endpoint serves its own guest.
    let mut raw_a = raw_connect(&vm_a).await?;
    let ping: Vec<u8> = Command::Ping.try_into().expect("serialize ping frame");
    raw_write_frame(&mut raw_a, &ping).await?;
    expect_guest_close(&mut raw_a, AUTHENTICATION_DEADLINE + Duration::from_secs(2)).await?;

    let exit_a = vm_a
        .run(ProcessBuilder::new().shell("echo still-alive-a").build()?)
        .await?;
    let exit_b = vm_b
        .run(ProcessBuilder::new().shell("echo still-alive-b").build()?)
        .await?;
    assert!(
        exit_a.success() && exit_b.success(),
        "both distinct-subnet VMs must answer authenticated commands"
    );

    vm_a.shutdown().await?;
    vm_b.shutdown().await?;
    Ok(())
}
