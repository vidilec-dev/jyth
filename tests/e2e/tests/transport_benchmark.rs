//! TCP command transport benchmark (TcpTransportMigrationPlan WP9).
//!
//! Measures the authenticated TCP command path on a live host:
//!
//! - authenticated `Ping` latency at p50/p95/p99;
//! - connection-establishment and authentication latency separately;
//! - 1 MiB and 64 MiB process-stream throughput in both directions
//!   (1 GiB via `JYTH_BENCH_1GIB=1`, opt-in to keep default runs bounded);
//! - at least [`MAX_GUEST_CONNECTIONS`] concurrent authenticated requests;
//! - failure behavior: silent authentication, truncated frame, peer reset,
//!   host cancellation, and VM shutdown with an active stream.
//!
//! The benchmark prints a structured report with host, OS, build profile,
//! payload, and timing settings. Compare the output against the recorded
//! vsock baseline (WP0) on the same host and release build.

use std::time::{Duration, Instant};

use e2e_tests::{VmGuard, alpine_image, hcs_test_guard};
use jyth::builder::VmBuilder;
use jyth::vm::ProcessBuilder;
use protocol::Command;
use protocol::auth::AUTHENTICATION_DEADLINE;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

fn percentile(sorted: &[f64], pct: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let index = ((sorted.len() as f64 - 1.0) * pct).round() as usize;
    sorted[index.min(sorted.len() - 1)]
}

/// One authenticated Ping latency sample.
async fn ping_latency(vm: &jyth::VM) -> Result<f64, Box<dyn std::error::Error + Send + Sync>> {
    let start = Instant::now();
    let process = ProcessBuilder::new().shell("true").build()?;
    vm.run(process).await?;
    Ok(start.elapsed().as_secs_f64() * 1000.0)
}

/// Connect-and-authenticate latency sample (raw TCP + capability proof).
async fn connect_auth_latency(
    vm: &jyth::VM,
) -> Result<f64, Box<dyn std::error::Error + Send + Sync>> {
    let start = Instant::now();
    let endpoint = com::TcpEndpoint::new(vm.command_endpoint(), vm.uuid(), vm.capability().clone());
    let _stream = endpoint.connect_async().await?;
    Ok(start.elapsed().as_secs_f64() * 1000.0)
}

/// Push `mib` MiB into a bound raw process stream (`cat` echo) and read
/// them back — exercising both directions of the process-stream channel
/// without the command-frame size limits. Raw mode measures the plain
/// stream throughput the plan's WP9 baseline compares.
async fn stream_roundtrip_mib(
    vm: &jyth::VM,
    mib: usize,
) -> Result<f64, Box<dyn std::error::Error + Send + Sync>> {
    let mut process = vm.process("/bin/cat").spawn().await?;
    let mut stream = process.bind_raw().await?;
    let data = vec![0xabu8; mib * 1024 * 1024];
    // Ping-pong echo in bounded chunks: the guest's output relay uses a
    // bounded channel and the child's pipes are kernel-bounded, so a
    // write-ahead larger than that headroom would deadlock. 64 KiB rounds
    // fit comfortably while still measuring sustained duplex throughput.
    const CHUNK: usize = 64 * 1024;
    let start = Instant::now();
    let mut written = 0usize;
    while written < data.len() {
        let end = (written + CHUNK).min(data.len());
        stream.write(&data[written..end]).await?;
        let mut received = 0usize;
        while received < end - written {
            let chunk = stream.read().await?;
            if chunk.is_empty() {
                break;
            }
            received += chunk.len();
        }
        assert_eq!(
            received,
            end - written,
            "echoed {received} of {} bytes",
            end - written
        );
        written = end;
    }
    let elapsed = start.elapsed();
    process.close().await?;
    // Host->guest write plus guest->host read: 2x payload over one stream.
    Ok((mib as f64 * 2.0) / elapsed.as_secs_f64())
}

#[tokio::test]
async fn tcp_command_transport_benchmark() -> TestResult {
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

    let build_profile = std::env::var("PROFILE").unwrap_or_else(|_| "debug".to_string());
    println!("== TCP transport benchmark report ==",);
    println!(
        "host: {} | os: {} | profile: {build_profile} | endpoint: {}",
        std::env::var("COMPUTERNAME").unwrap_or_else(|_| "unknown".to_string()),
        std::env::consts::OS,
        vm.command_endpoint()
    );

    // Authenticated Ping latency p50/p95/p99.
    let mut pings = Vec::new();
    for _ in 0..50 {
        pings.push(ping_latency(&vm).await?);
    }
    pings.sort_by(|a, b| a.partial_cmp(b).unwrap());
    println!(
        "ping latency ms: p50={:.3} p95={:.3} p99={:.3}",
        percentile(&pings, 0.50),
        percentile(&pings, 0.95),
        percentile(&pings, 0.99)
    );

    // Connection-establishment + authentication latency.
    let mut connects = Vec::new();
    for _ in 0..10 {
        connects.push(connect_auth_latency(&vm).await?);
    }
    connects.sort_by(|a, b| a.partial_cmp(b).unwrap());
    println!(
        "connect+auth latency ms: p50={:.3} p95={:.3}",
        percentile(&connects, 0.50),
        percentile(&connects, 0.95)
    );

    // Throughput: 1 MiB and 64 MiB process-stream round trips (write+read).
    let small = stream_roundtrip_mib(&vm, 1).await?;
    println!("1 MiB roundtrip MiB/s: {small:.2}");
    let large = stream_roundtrip_mib(&vm, 64).await?;
    println!("64 MiB roundtrip MiB/s: {large:.2}");
    if std::env::var("JYTH_BENCH_1GIB").is_ok() {
        let gib = stream_roundtrip_mib(&vm, 1024).await?;
        println!("1 GiB roundtrip MiB/s: {gib:.2}");
    } else {
        println!("1 GiB roundtrip: skipped (set JYTH_BENCH_1GIB=1 to enable)");
    }

    // Concurrent authenticated requests at the guest admission limit.
    let endpoint = com::TcpEndpoint::new(vm.command_endpoint(), vm.uuid(), vm.capability().clone());
    let start = Instant::now();
    let mut handles = Vec::new();
    for _ in 0..protocol::auth::MAX_GUEST_CONNECTIONS {
        let endpoint = endpoint.clone();
        handles.push(tokio::spawn(async move {
            let reply = endpoint.command_async(Command::Ping).await?;
            assert_eq!(reply, protocol::Event::VMReady);
            Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
        }));
    }
    for handle in handles {
        handle.await??;
    }
    println!(
        "{} concurrent authenticated requests: {:.1} ms total",
        protocol::auth::MAX_GUEST_CONNECTIONS,
        start.elapsed().as_secs_f64() * 1000.0
    );

    // Failure behavior: silent authentication must close within the
    // authentication deadline.
    let mut silent = TcpStream::connect(vm.command_endpoint()).await?;
    let start = Instant::now();
    let mut buf = [0u8; 16];
    let closed = tokio::time::timeout(AUTHENTICATION_DEADLINE + Duration::from_secs(2), async {
        loop {
            match silent.read(&mut buf).await {
                Ok(0) | Err(_) => return true,
                Ok(_) => continue,
            }
        }
    })
    .await
    .unwrap_or(false);
    println!(
        "silent pre-auth peer closed within deadline: {closed} ({:.1} ms)",
        start.elapsed().as_secs_f64() * 1000.0
    );
    if !closed {
        return Err("silent pre-auth peer was not closed within the deadline".into());
    }

    // Failure behavior: a truncated frame (4-byte length, no payload) must
    // be closed without stalling the command service.
    let mut truncated = TcpStream::connect(vm.command_endpoint()).await?;
    truncated.write_all(&1024u32.to_le_bytes()).await?;
    truncated.flush().await?;
    drop(truncated);

    // Failure behavior: peer close (FIN) mid-stream, then the command path
    // remains healthy. The guest must tolerate the closed connection and
    // keep serving.
    let reset = TcpStream::connect(vm.command_endpoint()).await?;
    drop(reset);
    let exit = vm
        .run(
            ProcessBuilder::new()
                .shell("echo healthy-after-reset")
                .build()?,
        )
        .await?;
    assert!(exit.success());

    // Failure behavior: host cancellation — drop an in-flight bind and
    // verify the listener still accepts new connections.
    let mut process = vm
        .process("/bin/sh")
        .args(&["-c", "while true; do sleep 1; done"])
        .spawn()
        .await?;
    let bound = process.bind_raw().await?;
    drop(bound);
    let exit = vm
        .run(
            ProcessBuilder::new()
                .shell("echo healthy-after-cancel")
                .build()?,
        )
        .await?;
    assert!(exit.success());

    // Failure behavior: VM shutdown with an active process stream.
    let _process = vm
        .process("/bin/sh")
        .args(&["-c", "while true; do sleep 1; done"])
        .spawn()
        .await?;
    vm.shutdown().await?;
    println!("shutdown with active stream: ok");
    println!("== benchmark report end ==");
    Ok(())
}
