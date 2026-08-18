use e2e_tests::{VmGuard, hcs_test_guard, linuxkit_image};
use jyth::AsyncStream;
use jyth::builder::VmBuilder;
use jyth::builder::dir::Dir;
use jyth::builder::file::{File, FileContent, RustBinary};
use jyth::builder::permissions::Permissions;

fn file_check_manifest() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../fixtures/file-check/Cargo.toml")
}

async fn read_until_terminator(
    stream: &mut AsyncStream,
    timeout_secs: u64,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    use tokio::time::timeout;

    let deadline = tokio::time::Duration::from_secs(timeout_secs);
    let mut accum: Vec<u8> = Vec::new();

    loop {
        let chunk =
            match timeout(deadline, stream.read()).await {
                Ok(Ok(c)) => c,
                Ok(Err(e)) => return Err(format!("read error while waiting for ---: {e}").into()),
                Err(_) => return Err(format!(
                    "timed out after {timeout_secs}s waiting for --- terminator; got so far: {:?}",
                    String::from_utf8_lossy(&accum)
                )
                .into()),
            };
        if chunk.is_empty() {
            return Err("file-check stream closed before --- terminator arrived".into());
        }
        accum.extend_from_slice(&chunk);
        if accum.windows(4).any(|w| w == b"---\n") {
            let end = accum.windows(4).position(|w| w == b"---\n").unwrap();
            accum.truncate(end);
            return Ok(accum);
        }
    }
}

#[tokio::test]
async fn guest_process_can_read_host_injected_files()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    #[cfg(feature = "tracing")]
    tracing::init();

    let _hcs_guard = hcs_test_guard().await?;
    let (kernel, rootfs) = linuxkit_image("alpine:3.24");
    let mut vm = VmGuard::new(
        VmBuilder::new()
            .kernel(kernel)
            .rootfs(rootfs)
            .add_file(
                File::new()
                    .path("/bin/file-check")
                    .content(FileContent::Crate(RustBinary::new(file_check_manifest())))
                    .permissions(Permissions::ALL),
            )
            .add_file(
                File::new()
                    .path("/etc/greeting.txt")
                    .content(b"hola desde el host".as_slice())
                    .group_permissions(
                        Permissions::READ | Permissions::WRITE | Permissions::EXECUTE,
                    )
                    .user_permissions(
                        Permissions::READ | Permissions::WRITE | Permissions::EXECUTE,
                    ),
            )
            .add_dir(Dir::new().path("/var/data").permissions(Permissions::ALL))
            .network(())
            .launch()
            .await?,
    );

    let mut process = vm.process_start("/bin/file-check").await?;
    let mut stream = process.bind_raw().await?;

    // Verify the CONTENT of an injected file survived the cpio/initrd
    // trip and is readable from inside the guest. This is the primary
    // assertion that file injection actually worked: the exact bytes the
    // host registered with add_file must match what the guest observes.
    stream.write(b"GET /etc/greeting.txt\n").await?;
    let greeting_bytes = read_until_terminator(&mut stream, 60).await?;
    let greeting_str = String::from_utf8_lossy(&greeting_bytes);
    assert!(
        greeting_str.contains("hola desde el host"),
        "injected /etc/greeting.txt content not found in guest response: {:?}",
        greeting_str,
    );

    // Verify the injected DIRECTORY appears in the guest's own listing
    // of its parent. Each entry from file-check is now on its own line
    // (see fixtures/file-check/src/main.rs), so contains() can't match
    // a substring that spans across two entries.
    stream.write(b"GET /var/\n").await?;
    let var_bytes = read_until_terminator(&mut stream, 60).await?;
    let var_listing = String::from_utf8_lossy(&var_bytes);
    assert!(
        var_listing.lines().any(|line| line == "data"),
        "injected /var/data dir not present in guest's GET /var/ response: {:?}",
        var_listing,
    );

    // Cross-check that the host's bus-protocol DirRead and the guest's
    // own file-check agree on the SET of entry names under /var/. Both
    // ultimately observe the same guest filesystem, so they must agree —
    // but compare as sets of line-delimited names, not as a raw byte
    // concatenation, because file-check now line-delimits entries and
    // the host's DirListing serializes them via DirEntryRef::path.
    let via_host = vm.dir_read("/var/").await?;
    let host_names: std::collections::HashSet<&str> = via_host.iter().map(|e| e.as_str()).collect();
    let guest_names: std::collections::HashSet<&str> = var_listing
        .lines()
        .filter(|l| !l.is_empty() && *l != "---")
        .collect();
    assert_eq!(
        host_names, guest_names,
        "host bus DirRead and guest file-check disagree on /var/ entries: \
         host={:?}, guest={:?}",
        host_names, guest_names,
    );

    process.close().await?;
    vm.shutdown().await?;

    Ok(())
}

#[tokio::test]
async fn host_file_and_dir_crud_roundtrip() -> Result<(), Box<dyn std::error::Error + Send + Sync>>
{
    #[cfg(feature = "tracing")]
    tracing::init();

    let _hcs_guard = hcs_test_guard().await?;
    let (kernel, rootfs) = linuxkit_image("debian:trixie-slim");
    let mut vm = VmGuard::new(
        VmBuilder::new()
            .kernel(kernel)
            .rootfs(rootfs)
            .add_file(
                File::new()
                    .path("/etc/greeting.txt")
                    .content(b"hola desde el host".as_slice())
                    .permissions(Permissions::ALL),
            )
            .add_dir(Dir::new().path("/var/data").permissions(Permissions::ALL))
            .network(())
            .launch()
            .await?,
    );

    vm.file_write("/etc/saludo.txt", "hello from the host")
        .await?;
    vm.file_remove("/etc/greeting.txt").await?;
    vm.dir_create("/tmp/jyth_test").await?;
    vm.dir_remove("/var/data").await?;

    assert_eq!(
        vm.file_read("/etc/saludo.txt").await?,
        b"hello from the host",
        "written file content did not match"
    );

    assert!(
        !vm.dir_read("/etc/").await?.has("greeting.txt"),
        "/etc/ still contains greeting.txt after removal"
    );
    assert!(
        vm.dir_read("/tmp/").await?.has("jyth_test"),
        "/tmp/ does not contain jyth_test after creation"
    );
    assert!(
        !vm.dir_read("/var/").await?.has("data"),
        "/var/ still contains data after removal"
    );

    vm.shutdown().await?;

    Ok(())
}
