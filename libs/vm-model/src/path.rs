//! Pure lexical path normalization shared by model validation and backends.
//!
//! This is a pure computation: no filesystem access, no environment access.
//! Both the disk model (above-root rejection at construction) and the HCS
//! journal (duplicate-path identity) consume it so the normalization rule
//! exists in exactly one place.

use std::path::{Path, PathBuf};

/// Why a path could not be normalized.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathError {
    /// The path is not absolute.
    NotAbsolute,
    /// A `..` component escapes above the root.
    EscapesRoot,
}

/// Lexically normalize an absolute path: collapse `.` and `..` components
/// and stop at the root.
///
/// A `..` that would pop the drive prefix or UNC root is an error — silently
/// popping past the root produces a drive-relative path (e.g.
/// `C:\..\disks\x.vhdx` → `C:disks\x.vhdx`) that Windows resolves against
/// the current directory of drive C.
pub fn normalize_lexically(absolute: &Path) -> Result<PathBuf, PathError> {
    if !absolute.is_absolute() {
        return Err(PathError::NotAbsolute);
    }
    let mut normalized = PathBuf::new();
    for component in absolute.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                let at_root = normalized.components().next_back().is_none_or(|last| {
                    matches!(
                        last,
                        std::path::Component::RootDir | std::path::Component::Prefix(_)
                    )
                });
                if at_root {
                    return Err(PathError::EscapesRoot);
                }
                normalized.pop();
            }
            _ => normalized.push(component.as_os_str()),
        }
    }
    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_absolute_path_is_unchanged() {
        assert_eq!(
            normalize_lexically(Path::new(r"C:\disks\x.vhdx")).expect("plain path"),
            Path::new(r"C:\disks\x.vhdx")
        );
    }

    #[test]
    fn dot_components_collapse() {
        assert_eq!(
            normalize_lexically(Path::new(r"C:\disks\.\x.vhdx")).expect("dot path"),
            Path::new(r"C:\disks\x.vhdx")
        );
        assert_eq!(
            normalize_lexically(Path::new(r"C:\disks\..\x.vhdx")).expect("parent pop"),
            Path::new(r"C:\x.vhdx")
        );
    }

    #[test]
    fn over_root_parent_pop_is_rejected() {
        assert_eq!(
            normalize_lexically(Path::new(r"C:\..\x.vhdx")).unwrap_err(),
            PathError::EscapesRoot
        );
        assert_eq!(
            normalize_lexically(Path::new(r"C:\disks\..\..\x.vhdx")).unwrap_err(),
            PathError::EscapesRoot
        );
    }

    #[test]
    fn unc_roots_are_protected() {
        assert_eq!(
            normalize_lexically(Path::new(r"\\server\share\disks\..\x.vhdx"))
                .expect("UNC parent pop"),
            Path::new(r"\\server\share\x.vhdx")
        );
        assert_eq!(
            normalize_lexically(Path::new(r"\\server\share\..\..\x.vhdx")).unwrap_err(),
            PathError::EscapesRoot
        );
    }

    #[test]
    fn relative_paths_are_rejected() {
        assert_eq!(
            normalize_lexically(Path::new(r"..\x.vhdx")).unwrap_err(),
            PathError::NotAbsolute
        );
        assert_eq!(
            normalize_lexically(Path::new(r"x.vhdx")).unwrap_err(),
            PathError::NotAbsolute
        );
    }
}
