use std::{
    fs::{File, read_dir, read_to_string},
    io,
    path::{Path, PathBuf},
};

use error_stack::Report;

use crate::errors::{InitError, InitResult};

pub(crate) struct ModuleLoader {
    modules_dir: Option<PathBuf>,
}

impl ModuleLoader {
    const MAX_SEARCH_DEPTH: u32 = 32;

    pub(crate) fn new() -> InitResult<Self> {
        let release = read_to_string("/proc/sys/kernel/osrelease")
            .map_err(|e| Report::new(e).change_context(InitError::Io))?
            .trim()
            .to_string();
        #[cfg(feature = "tracing")]
        tracing::info!(
            "[JythInit][ModuleLoader::New]: Kernel release version is {}",
            release
        );

        let modules_dir = ["/lib/modules", "/usr/lib/modules"]
            .into_iter()
            .map(|root| Path::new(root).join(&release))
            .find(|dir| dir.exists());

if modules_dir.is_none() {
            #[cfg(feature = "tracing")]
            tracing::info!(
                "[JythInit][ModuleLoader::New]: no module tree for {}; using built-in drivers only",
                release
            );
        }

        Ok(Self { modules_dir })
    }

    pub(crate) fn load(&self, name: &str) -> InitResult<Option<()>> {
        use std::os::unix::io::IntoRawFd;

if Self::is_builtin(name) {
            #[cfg(feature = "tracing")]
            tracing::info!(
                "[JythInit][ModuleLoader::Load]: {} is built into the kernel",
                name
            );
            return Ok(Some(()));
        }

        let Some(path) = self.find(name)? else {
            return Ok(None);
        };
        #[cfg(feature = "tracing")]
        tracing::info!(
            "[JythInit][ModuleLoader::Load]: Loading module {} from {:?}",
            name,
            path
        );

        let file = File::open(&path)
            .map_err(|e| Report::new(e).change_context(InitError::Io))?
            .into_raw_fd();
        let ret = unsafe {
            libc::syscall(
                libc::SYS_finit_module,
                file,
                b"\0".as_ptr() as *const libc::c_char,
                0,
            )
        };
        if ret < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EEXIST) {
                #[cfg(feature = "tracing")]
                tracing::info!(
                    "[JythInit][ModuleLoader::Load]: Module {} already loaded",
                    name
                );
                return Ok(Some(()));
            }
            #[cfg(feature = "tracing")]
            tracing::info!(
                "[JythInit][ModuleLoader::Load]: Failed to load module {}: {}",
                name,
                err
            );
            return Ok(None);
        }
        #[cfg(feature = "tracing")]
        tracing::info!(
            "[JythInit][ModuleLoader::Load]: Successfully loaded module {}",
            name
        );
        Ok(Some(()))
    }

    fn find(&self, name: &str) -> InitResult<Option<PathBuf>> {
        let target_normalized = name.replace('-', "_");
        let Some(modules_dir) = &self.modules_dir else {
            return Ok(None);
        };

        Self::search(modules_dir, &target_normalized, 0)
    }

    fn is_builtin(name: &str) -> bool {
        Path::new("/sys/module")
            .join(name.replace('-', "_"))
            .is_dir()
    }

    fn search(dir: &Path, target: &str, depth: u32) -> InitResult<Option<PathBuf>> {
        // `Path::is_dir()` follows symlinks, so a symlink cycle inside
        // lib/modules/ (e.g. from a corrupted or malicious kernel.tar) would
        // otherwise recurse without bound and stack-overflow-abort PID 1 — a
        // crash the "never exit" loop in `main()` can't catch, since abort
        // skips normal unwinding entirely. A depth cap turns that into an
        // ordinary "module not found" error instead.
        if depth > Self::MAX_SEARCH_DEPTH {
            return Ok(None);
        }
        if !dir.is_dir() {
            return Ok(None);
        }
        for entry in read_dir(dir).map_err(|e| Report::new(e).change_context(InitError::Io))? {
            let path = entry
                .map_err(|e| Report::new(e).change_context(InitError::Io))?
                .path();
            if path.is_dir() {
                if let Some(p) = Self::search(&path, target, depth + 1)? {
                    return Ok(Some(p));
                }
            } else if path.is_file() {
                if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                    let stem_clean = if stem.ends_with(".ko") {
                        &stem[..stem.len() - 3]
                    } else {
                        stem
                    };
                    let stem_normalized = stem_clean.replace('-', "_");
                    if stem_normalized == target {
                        return Ok(Some(path));
                    }
                }
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use crate::ops::module_loader::ModuleLoader;
    #[cfg(target_os = "linux")]
    #[test]
    fn test_find_module_finds_shallow_module() {
        let tmp = std::env::temp_dir().join(format!("jyth-test-shallow-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::write(tmp.join("my-module.ko"), b"fake module").unwrap();

        let found = ModuleLoader::search(&tmp, "my_module", 0).unwrap();
        assert_eq!(found, Some(tmp.join("my-module.ko")));

        std::fs::remove_dir_all(&tmp).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_find_module_depth_cap_prevents_unbounded_recursion() {
        // A symlink cycle (dir/self -> dir) would otherwise make `search`
        // recurse forever and stack-overflow-abort the process; the depth
        // cap must turn that into an ordinary "not found" error instead.

        let tmp = std::env::temp_dir().join(format!("jyth-test-cycle-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        std::os::unix::fs::symlink(&tmp, tmp.join("self")).unwrap();

        let result = ModuleLoader::search(&tmp, "nonexistent", 0);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());

        std::fs::remove_dir_all(&tmp).unwrap();
    }
}
