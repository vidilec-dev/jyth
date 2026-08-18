use std::time::Duration;

use e2e_tests::{VmGuard, alpine_image, hcs_test_guard};
use jyth::builder::VmBuilder;
use jyth::vm::{CaptureOptions, Output, OutputStream, ProcessBuilder, ProcessError, ProcessState};

#[tokio::test]
async fn direct_execution_publishes_success_timeout_and_cancellation()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
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

    let (success_observer, success_builder) = ProcessBuilder::with_observer();
    let success = success_builder
        .shell("printf direct > /tmp/direct-process")
        .build()?;
    let exit = vm.run(success).await?;

    assert!(exit.success());
    assert_eq!(success_observer.finished().await?, exit);
    assert_eq!(success_observer.state(), ProcessState::Finished(exit),);
    assert_eq!(vm.file_read("/tmp/direct-process").await?, b"direct");

    let (timeout_observer, timeout_builder) = ProcessBuilder::with_observer();
    let timed = timeout_builder
        .shell("sleep 60")
        .timeout(Duration::from_millis(50))
        .build()?;
    let timeout_error = vm
        .run(timed)
        .await
        .expect_err("long process should time out");
    assert!(matches!(timeout_error, ProcessError::TimedOut { .. }));
    assert_eq!(timeout_observer.finished().await, Err(timeout_error));

    let (cancel_observer, cancel_builder) = ProcessBuilder::with_observer();
    let cancelled = cancel_builder.shell("exit 0").build()?;
    cancel_observer.cancel();
    let cancel_error = vm
        .run(cancelled)
        .await
        .expect_err("pre-cancelled process should not spawn");
    assert!(matches!(cancel_error, ProcessError::Cancelled { .. }));
    assert_eq!(cancel_observer.finished().await, Err(cancel_error));

    vm.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn bounded_capture_stops_floods_and_propagates_routing_failures()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
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

    let (flood_observer, flood_builder) = ProcessBuilder::with_observer();
    let flood = flood_builder
        .shell("yes flood")
        .stdout(Output::Capture(CaptureOptions::new().with_limit(4096)))
        .build()?;
    let flood_error = vm
        .run(flood)
        .await
        .expect_err("stdout flood should exceed the capture limit");
    assert!(matches!(
        flood_error,
        ProcessError::OutputLimitExceeded {
            stream: OutputStream::Stdout,
            limit: 4096,
            ..
        }
    ));
    assert_eq!(flood_observer.finished().await, Err(flood_error));
    assert!(matches!(
        flood_observer.stdout().await,
        Err(ProcessError::OutputUnavailable)
    ));

    let (stderr_observer, stderr_builder) = ProcessBuilder::with_observer();
    let stderr_limited = stderr_builder
        .shell("printf ok; printf error >&2")
        .stdout(Output::Capture(CaptureOptions::new().with_limit(32)))
        .stderr(Output::Capture(CaptureOptions::new().with_limit(4)))
        .build()?;
    let stderr_error = vm
        .run(stderr_limited)
        .await
        .expect_err("stderr should use its own capture limit");
    assert!(matches!(
        stderr_error,
        ProcessError::OutputLimitExceeded {
            stream: OutputStream::Stderr,
            limit: 4,
            ..
        }
    ));
    assert_eq!(stderr_observer.finished().await, Err(stderr_error));

    let blocked_parent =
        std::env::temp_dir().join(format!("jyth-output-parent-{}", std::process::id()));
    std::fs::write(&blocked_parent, b"not a directory")?;
    let (host_file_observer, host_file_builder) = ProcessBuilder::with_observer();
    let host_file = host_file_builder
        .shell("printf host-failure; sleep 60")
        .stdout(Output::HostFile(blocked_parent.join("nested/output")))
        .build()?;
    let host_file_error = vm
        .run(host_file)
        .await
        .expect_err("host-file routing failure should stop the guest");
    assert!(matches!(
        host_file_error,
        ProcessError::Output {
            stream: OutputStream::Stdout,
            ..
        }
    ));
    assert_eq!(host_file_observer.finished().await, Err(host_file_error));
    std::fs::remove_file(blocked_parent)?;

    let (timeout_observer, timeout_builder) = ProcessBuilder::with_observer();
    let timed = timeout_builder
        .shell("sleep 60")
        .stdout(Output::Capture(CaptureOptions::new()))
        .timeout(Duration::from_millis(50))
        .build()?;
    let timeout_error = vm
        .run(timed)
        .await
        .expect_err("timeout should clean up active output drains");
    assert!(matches!(timeout_error, ProcessError::TimedOut { .. }));
    assert_eq!(timeout_observer.finished().await, Err(timeout_error));

    vm.shutdown().await?;
    Ok(())
}
