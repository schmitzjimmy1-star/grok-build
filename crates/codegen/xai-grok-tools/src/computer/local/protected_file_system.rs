use std::path::{Component, Path, PathBuf};

use crate::computer::types::{AsyncFileSystem, ComputerError};

use super::LocalFs;

/// Local filesystem backend that makes hard-budget authority directories
/// unreachable to model-facing file tools.
///
/// Both lexical and canonical ancestors are checked so a workspace symlink
/// cannot turn an innocent-looking path into the manifest or ledger directory.
#[derive(Debug, Clone)]
pub struct ProtectedLocalFs {
    protected_roots: Vec<PathBuf>,
    allowed_root: PathBuf,
}

impl ProtectedLocalFs {
    pub fn new(
        roots: impl IntoIterator<Item = PathBuf>,
        allowed_root: PathBuf,
    ) -> Result<Self, ComputerError> {
        let mut protected_roots = Vec::new();
        for root in roots {
            if !root.is_absolute() {
                return Err(ComputerError::io_with_kind(
                    "hard-budget protected root must be absolute",
                    std::io::ErrorKind::InvalidInput,
                ));
            }
            let canonical = std::fs::canonicalize(&root).map_err(ComputerError::from)?;
            validate_authority_tree(&canonical)?;
            if !protected_roots.contains(&canonical) {
                protected_roots.push(canonical);
            }
        }
        if protected_roots.is_empty() {
            return Err(ComputerError::io_with_kind(
                "hard-budget protected root is required",
                std::io::ErrorKind::InvalidInput,
            ));
        }
        if !allowed_root.is_absolute() {
            return Err(ComputerError::io_with_kind(
                "hard-budget allowed root must be absolute",
                std::io::ErrorKind::InvalidInput,
            ));
        }
        let allowed_root = std::fs::canonicalize(allowed_root).map_err(ComputerError::from)?;
        if protected_roots
            .iter()
            .any(|root| root.starts_with(&allowed_root) || allowed_root.starts_with(root))
        {
            return Err(ComputerError::io_with_kind(
                "hard-budget authority and allowed roots must be disjoint",
                std::io::ErrorKind::InvalidInput,
            ));
        }
        Ok(Self {
            protected_roots,
            allowed_root,
        })
    }

    fn absolute_path(&self, path: &Path) -> PathBuf {
        if path.is_absolute() {
            normalize(path)
        } else {
            normalize(&self.allowed_root.join(path))
        }
    }

    async fn refuses(&self, absolute: &Path) -> bool {
        let mut cursor = Some(absolute);
        while let Some(candidate) = cursor {
            match tokio::fs::canonicalize(candidate).await {
                Ok(canonical) => {
                    let protected = self
                        .protected_roots
                        .iter()
                        .any(|root| canonical.starts_with(root));
                    return protected || !canonical.starts_with(&self.allowed_root);
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    cursor = candidate.parent();
                }
                Err(_) => return true,
            }
        }
        true
    }

    async fn require_allowed(&self, path: &Path) -> Result<PathBuf, ComputerError> {
        let absolute = self.absolute_path(path);
        if self.refuses(&absolute).await {
            return Err(ComputerError::io_with_kind(
                "hard-budget authority path is unavailable to model-facing tools",
                std::io::ErrorKind::PermissionDenied,
            ));
        }
        Ok(absolute)
    }
}

fn validate_authority_tree(root: &Path) -> Result<(), ComputerError> {
    let mut pending = vec![root.to_path_buf()];
    while let Some(path) = pending.pop() {
        for entry in std::fs::read_dir(&path).map_err(ComputerError::from)? {
            let entry = entry.map_err(ComputerError::from)?;
            let metadata = std::fs::symlink_metadata(entry.path()).map_err(ComputerError::from)?;
            if metadata.file_type().is_symlink() {
                return Err(ComputerError::io_with_kind(
                    "hard-budget authority directory must not contain symlinks",
                    std::io::ErrorKind::PermissionDenied,
                ));
            }
            if metadata.is_dir() {
                pending.push(entry.path());
                continue;
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt as _;
                if metadata.nlink() != 1 {
                    return Err(ComputerError::io_with_kind(
                        "hard-budget authority file must have exactly one link",
                        std::io::ErrorKind::PermissionDenied,
                    ));
                }
            }
        }
    }
    Ok(())
}

fn normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

#[async_trait::async_trait]
impl AsyncFileSystem for ProtectedLocalFs {
    async fn read_file(&self, path: &Path) -> Result<Vec<u8>, ComputerError> {
        let path = self.require_allowed(path).await?;
        LocalFs.read_file(&path).await
    }

    async fn write_file(&self, path: &Path, data: &[u8]) -> Result<(), ComputerError> {
        let path = self.require_allowed(path).await?;
        LocalFs.write_file(&path, data).await
    }

    async fn delete_file(&self, path: &Path) -> Result<(), ComputerError> {
        let path = self.require_allowed(path).await?;
        LocalFs.delete_file(&path).await
    }

    async fn file_exists(&self, path: &Path) -> Result<bool, ComputerError> {
        let path = self.require_allowed(path).await?;
        LocalFs.file_exists(&path).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn denies_direct_and_symlinked_authority_paths() {
        let temp = tempfile::tempdir().unwrap();
        let authority = temp.path().join("authority");
        let workspace = temp.path().join("workspace");
        std::fs::create_dir_all(&authority).unwrap();
        std::fs::create_dir_all(&workspace).unwrap();
        let ledger = authority.join("ledger.json");
        std::fs::write(&ledger, b"secret authority").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&authority, workspace.join("innocent")).unwrap();

        let fs = ProtectedLocalFs::new([authority.clone()], workspace.clone()).unwrap();
        assert_eq!(
            fs.read_file(&ledger).await.unwrap_err().io_error_kind(),
            Some(std::io::ErrorKind::PermissionDenied)
        );
        #[cfg(unix)]
        assert_eq!(
            fs.read_file(&workspace.join("innocent/ledger.json"))
                .await
                .unwrap_err()
                .io_error_kind(),
            Some(std::io::ErrorKind::PermissionDenied)
        );
    }

    #[tokio::test]
    async fn permits_an_unrelated_file() {
        let temp = tempfile::tempdir().unwrap();
        let authority = temp.path().join("authority");
        let workspace = temp.path().join("workspace");
        std::fs::create_dir_all(&authority).unwrap();
        std::fs::create_dir_all(&workspace).unwrap();
        let fixture = workspace.join("ONE.txt");
        std::fs::write(&fixture, b"one").unwrap();

        let fs = ProtectedLocalFs::new([authority], workspace).unwrap();
        assert_eq!(fs.read_file(&fixture).await.unwrap(), b"one");
        assert_eq!(fs.read_file(Path::new("ONE.txt")).await.unwrap(), b"one");
    }

    #[tokio::test]
    async fn denies_paths_outside_the_workspace_and_symlink_escapes() {
        let temp = tempfile::tempdir().unwrap();
        let authority = temp.path().join("authority");
        let workspace = temp.path().join("workspace");
        let outside = temp.path().join("outside");
        std::fs::create_dir_all(&authority).unwrap();
        std::fs::create_dir_all(&workspace).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        let secret = outside.join("credential.txt");
        std::fs::write(&secret, b"do not read").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&outside, workspace.join("escape")).unwrap();

        let fs = ProtectedLocalFs::new([authority], workspace.clone()).unwrap();
        assert_eq!(
            fs.read_file(&secret).await.unwrap_err().io_error_kind(),
            Some(std::io::ErrorKind::PermissionDenied)
        );
        assert_eq!(
            fs.read_file(Path::new("../outside/credential.txt"))
                .await
                .unwrap_err()
                .io_error_kind(),
            Some(std::io::ErrorKind::PermissionDenied)
        );
        #[cfg(unix)]
        assert_eq!(
            fs.read_file(&workspace.join("escape/credential.txt"))
                .await
                .unwrap_err()
                .io_error_kind(),
            Some(std::io::ErrorKind::PermissionDenied)
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn rejects_preexisting_hardlink_aliases_into_the_workspace() {
        let temp = tempfile::tempdir().unwrap();
        let authority = temp.path().join("authority");
        let workspace = temp.path().join("workspace");
        std::fs::create_dir_all(&authority).unwrap();
        std::fs::create_dir_all(&workspace).unwrap();
        let ledger = authority.join("ledger.json");
        std::fs::write(&ledger, b"secret authority").unwrap();
        std::fs::hard_link(&ledger, workspace.join("fixture.txt")).unwrap();

        let error = ProtectedLocalFs::new([authority], workspace).unwrap_err();
        assert_eq!(
            error.io_error_kind(),
            Some(std::io::ErrorKind::PermissionDenied)
        );
    }
}
