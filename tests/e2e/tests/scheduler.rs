//! Live scheduler tests for the public Jyth builder API.
//!
//! Each scenario boots a fresh Alpine guest, schedules processes through the
//! builder's dependency triggers, observes every terminal result, and lets the
//! scheduler request guest shutdown after the scenario's completion condition.
//! The tests use one in-process HCS lock so a default test run cannot create
//! competing compute systems on the same host.

use e2e_tests::{VmGuard, alpine_image, hcs_test_guard};
use jyth::builder::{Cpu, Memory, On, VmBuilder};
use jyth::vm::{
    CaptureOptions, Executable, Output, ProcessBuilder, ProcessError, ProcessState, VmFinish,
};
use std::path::{Path, PathBuf};
use std::time::Duration;

type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

fn host_marker(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("jyth-scheduler-{name}-{}.out", std::process::id()))
}

fn remove_if_present(path: &Path) -> Result<(), std::io::Error> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

async fn wait_for_host_output(path: PathBuf, expected: &'static [u8]) -> Result<(), String> {
    let wait = async {
        loop {
            match tokio::fs::read(&path).await {
                Ok(bytes) if bytes == expected => return Ok(()),
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(format!("failed reading {}: {error}", path.display()));
                }
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    };

    tokio::time::timeout(Duration::from_secs(30), wait)
        .await
        .map_err(|_| format!("timed out waiting for {}", path.display()))?
}

fn assert_success(exit: jyth::ProcessExit, name: &str) {
    assert!(exit.success(), "{name} exited unsuccessfully: {exit}");
}

// ---
// Linear pipeline: `a -> b -> c`. The final process reads the bytes written
// by its predecessors, so the assertion covers both dependency order and the
// captured result.
// ---
#[tokio::test]
async fn linear_pipeline_executes_in_topological_order() -> TestResult {
    #[cfg(feature = "tracing")]
    tracing::init();

    let _hcs_guard = hcs_test_guard().await?;

    let (vm_observer, vm_builder) = VmBuilder::with_observer();
    let (a_observer, a_builder) = ProcessBuilder::with_observer();
    let (b_observer, b_builder) = ProcessBuilder::with_observer();
    let (c_observer, c_builder) = ProcessBuilder::with_observer();

    let (kernel, rootfs) = alpine_image();
    let mut _vm = VmGuard::new(
        vm_builder
            .kernel(kernel)
            .rootfs(rootfs)
            .cpu(Cpu::Units(2))
            .mem(Memory::MB(512))
            .run_on(
                On::Success(vm_observer.started()),
                a_builder
                    .shell("printf a > /tmp/jyth-scheduler-linear")
                    .build()?,
            )
            .run_on(
                On::Success(a_observer.finished()),
                b_builder
                    .shell("printf b >> /tmp/jyth-scheduler-linear")
                    .build()?,
            )
            .run_on(
                On::Success(b_observer.finished()),
                c_builder
                    .shell("cat /tmp/jyth-scheduler-linear")
                    .stdout(Output::Capture(CaptureOptions::default()))
                    .build()?,
            )
            .shutdown_on(On::Resolve(c_observer.finished()))
            .network(())
            .launch()
            .await?,
    );

    let (a_result, b_result, c_result, vm_result) = tokio::join!(
        a_observer.finished(),
        b_observer.finished(),
        c_observer.finished(),
        vm_observer.finished(),
    );
    let a_exit = a_result?;
    let b_exit = b_result?;
    let c_exit = c_result?;
    assert_success(a_exit, "linear a");
    assert_success(b_exit, "linear b");
    assert_success(c_exit, "linear c");
    assert_eq!(c_observer.stdout().await?, b"ab");
    assert_eq!(vm_result?, VmFinish::Shutdown);
    Ok(())
}

// ---
// Fan-out and fan-in: `root -> (left, right) -> join`. The join's `All`
// trigger must wait for both branches before it reads their output files.
// ---
#[tokio::test]
async fn pipeline_fans_out_and_back_in() -> TestResult {
    #[cfg(feature = "tracing")]
    tracing::init();

    let _hcs_guard = hcs_test_guard().await?;

    let (vm_observer, vm_builder) = VmBuilder::with_observer();
    let (root_observer, root_builder) = ProcessBuilder::with_observer();
    let (left_observer, left_builder) = ProcessBuilder::with_observer();
    let (right_observer, right_builder) = ProcessBuilder::with_observer();
    let (join_observer, join_builder) = ProcessBuilder::with_observer();

    let (kernel, rootfs) = alpine_image();
    let mut _vm = VmGuard::new(
        vm_builder
            .kernel(kernel)
            .rootfs(rootfs)
            .cpu(Cpu::Units(2))
            .mem(Memory::MB(512))
            .run_on(
                On::Success(vm_observer.started()),
                root_builder.shell("true").build()?,
            )
            .run_on(
                On::Success(root_observer.finished()),
                left_builder
                    .shell("printf left > /tmp/jyth-scheduler-left")
                    .build()?,
            )
            .run_on(
                On::Success(root_observer.finished()),
                right_builder
                    .shell("printf right > /tmp/jyth-scheduler-right")
                    .build()?,
            )
            .run_on(
                On::All(vec![
                    On::Success(left_observer.finished()),
                    On::Success(right_observer.finished()),
                ]),
                join_builder
                    .shell("cat /tmp/jyth-scheduler-left /tmp/jyth-scheduler-right")
                    .stdout(Output::Capture(CaptureOptions::default()))
                    .build()?,
            )
            .shutdown_on(On::Resolve(join_observer.finished()))
            .network(())
            .launch()
            .await?,
    );

    let (root_result, left_result, right_result, join_result, vm_result) = tokio::join!(
        root_observer.finished(),
        left_observer.finished(),
        right_observer.finished(),
        join_observer.finished(),
        vm_observer.finished(),
    );
    assert_success(root_result?, "fan-in root");
    assert_success(left_result?, "fan-out left");
    assert_success(right_result?, "fan-out right");
    assert_success(join_result?, "fan-in join");
    assert_eq!(join_observer.stdout().await?, b"leftright");
    assert_eq!(vm_result?, VmFinish::Shutdown);
    Ok(())
}

// ---
// A timed-out process must publish its typed timeout failure and still let
// the scheduler reach its declared shutdown condition.
// ---
#[tokio::test]
async fn scheduled_process_timeout_is_observable() -> TestResult {
    #[cfg(feature = "tracing")]
    tracing::init();

    let _hcs_guard = hcs_test_guard().await?;
    let timeout_after = Duration::from_millis(500);

    let (vm_observer, vm_builder) = VmBuilder::with_observer();
    let (timeout_observer, timeout_builder) = ProcessBuilder::with_observer();

    let (kernel, rootfs) = alpine_image();
    let mut _vm = VmGuard::new(
        vm_builder
            .kernel(kernel)
            .rootfs(rootfs)
            .cpu(Cpu::Units(2))
            .mem(Memory::MB(512))
            .run_on(
                On::Success(vm_observer.started()),
                timeout_builder
                    .shell("sleep 60")
                    .timeout(timeout_after)
                    .build()?,
            )
            .shutdown_on(On::Resolve(timeout_observer.finished()))
            .network(())
            .launch()
            .await?,
    );

    let (timeout_result, vm_result) =
        tokio::join!(timeout_observer.finished(), vm_observer.finished());
    let timeout_error = timeout_result.expect_err("sleep should exceed its process deadline");
    assert!(matches!(
        &timeout_error,
        ProcessError::TimedOut { after, .. } if *after == timeout_after
    ));
    assert_eq!(
        timeout_observer.state(),
        ProcessState::Failed(timeout_error)
    );
    assert_eq!(vm_result?, VmFinish::Shutdown);
    Ok(())
}

// ---
// A failed predecessor must prevent its success-dependent child from
// starting. The child has a host-file output route as an additional external
// proof that it never spawned.
// ---
#[tokio::test]
async fn failed_dependency_cancels_dependent_before_start() -> TestResult {
    #[cfg(feature = "tracing")]
    tracing::init();

    let _hcs_guard = hcs_test_guard().await?;
    let child_marker = host_marker("failed-dependency");
    remove_if_present(&child_marker)?;

    let (vm_observer, vm_builder) = VmBuilder::with_observer();
    let (dependency_observer, dependency_builder) = ProcessBuilder::with_observer();
    let (child_observer, child_builder) = ProcessBuilder::with_observer();

    let (kernel, rootfs) = alpine_image();
    let mut _vm = VmGuard::new(
        vm_builder
            .kernel(kernel)
            .rootfs(rootfs)
            .cpu(Cpu::Units(2))
            .mem(Memory::MB(512))
            .run_on(
                On::Success(vm_observer.started()),
                dependency_builder
                    .process(Executable::Exec(PathBuf::from(
                        "/no/such/jyth-scheduler-program",
                    )))
                    .build()?,
            )
            .run_on(
                On::Success(dependency_observer.finished()),
                child_builder
                    .shell("printf child-ran")
                    .stdout(Output::HostFile(child_marker.clone()))
                    .build()?,
            )
            .shutdown_on(On::All(vec![
                On::Resolve(dependency_observer.finished()),
                On::Resolve(child_observer.finished()),
            ]))
            .network(())
            .launch()
            .await?,
    );

    let (dependency_result, child_result, vm_result) = tokio::join!(
        dependency_observer.finished(),
        child_observer.finished(),
        vm_observer.finished(),
    );
    let dependency_error = dependency_result.expect_err("missing program should fail to spawn");
    assert!(matches!(&dependency_error, ProcessError::Spawn(_)));
    assert_eq!(
        dependency_observer.state(),
        ProcessState::Failed(dependency_error.clone())
    );

    let child_error = child_result.expect_err("success-dependent child should be cancelled");
    assert!(matches!(&child_error, ProcessError::Cancelled { .. }));
    assert_eq!(
        child_observer.state(),
        ProcessState::Failed(child_error.clone())
    );
    assert_eq!(vm_result?, VmFinish::Shutdown);
    assert!(
        !child_marker.exists(),
        "cancelled child unexpectedly wrote {}",
        child_marker.display()
    );
    remove_if_present(&child_marker)?;
    Ok(())
}

// ---
// ProcessObserver is the public lifecycle hook for scheduled work. Every
// node in this linear plan must publish a retained terminal state, including
// observers read after the VM has shut down.
// ---
#[tokio::test]
async fn lifecycle_hooks_fire_for_every_scheduled_process() -> TestResult {
    #[cfg(feature = "tracing")]
    tracing::init();

    let _hcs_guard = hcs_test_guard().await?;

    let (vm_observer, vm_builder) = VmBuilder::with_observer();
    let (first_observer, first_builder) = ProcessBuilder::with_observer();
    let (second_observer, second_builder) = ProcessBuilder::with_observer();
    let (third_observer, third_builder) = ProcessBuilder::with_observer();

    let (kernel, rootfs) = alpine_image();
    let mut _vm = VmGuard::new(
        vm_builder
            .kernel(kernel)
            .rootfs(rootfs)
            .cpu(Cpu::Units(2))
            .mem(Memory::MB(512))
            .run_on(
                On::Success(vm_observer.started()),
                first_builder.shell("true").build()?,
            )
            .run_on(
                On::Success(first_observer.finished()),
                second_builder.shell("true").build()?,
            )
            .run_on(
                On::Success(second_observer.finished()),
                third_builder.shell("true").build()?,
            )
            .shutdown_on(On::Resolve(third_observer.finished()))
            .network(())
            .launch()
            .await?,
    );

    let (first_result, second_result, third_result, vm_result) = tokio::join!(
        first_observer.finished(),
        second_observer.finished(),
        third_observer.finished(),
        vm_observer.finished(),
    );
    let first_exit = first_result?;
    let second_exit = second_result?;
    let third_exit = third_result?;
    assert_success(first_exit, "hook first");
    assert_success(second_exit, "hook second");
    assert_success(third_exit, "hook third");
    assert!(matches!(
        first_observer.state(),
        ProcessState::Finished(exit) if exit.success()
    ));
    assert!(matches!(
        second_observer.state(),
        ProcessState::Finished(exit) if exit.success()
    ));
    assert!(matches!(
        third_observer.state(),
        ProcessState::Finished(exit) if exit.success()
    ));
    assert_eq!(vm_result?, VmFinish::Shutdown);
    Ok(())
}

// ---
// A scheduled process can run without a ProcessObserver or captured output.
// Its host-file route is only a completion sentinel for the shutdown trigger;
// no process lifecycle hook is installed or asserted for this scenario.
// ---
#[tokio::test]
async fn scheduler_runs_silent_pipeline() -> TestResult {
    #[cfg(feature = "tracing")]
    tracing::init();

    let _hcs_guard = hcs_test_guard().await?;
    let marker = host_marker("silent");
    remove_if_present(&marker)?;

    let (vm_observer, vm_builder) = VmBuilder::with_observer();
    let silent_process = ProcessBuilder::new()
        .shell("printf silent")
        .stdout(Output::HostFile(marker.clone()))
        .build()?;
    let completion = wait_for_host_output(marker.clone(), b"silent");

    let (kernel, rootfs) = alpine_image();
    let mut _vm = VmGuard::new(
        vm_builder
            .kernel(kernel)
            .rootfs(rootfs)
            .cpu(Cpu::Units(2))
            .mem(Memory::MB(512))
            .run_on(On::Success(vm_observer.started()), silent_process)
            .shutdown_on(On::Resolve(completion))
            .network(())
            .launch()
            .await?,
    );

    assert_eq!(vm_observer.finished().await?, VmFinish::Shutdown);
    assert_eq!(tokio::fs::read(&marker).await?, b"silent");
    remove_if_present(&marker)?;
    Ok(())
}
