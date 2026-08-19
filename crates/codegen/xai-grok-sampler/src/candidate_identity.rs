//! Independently measured candidate identity for Slice 4B.3.
//!
//! The child hashes a stable inherited descriptor of the inspected executable
//! bytes. It does not hash `current_exe()` through a replaceable pathname.

use std::sync::{Mutex, OnceLock};

use sha2::{Digest, Sha256};

use crate::hard_budget_provenance::CandidateIdentityV1;

#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

#[cfg(unix)]
pub const CANDIDATE_IDENTITY_FD: RawFd = 197;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CandidateIdentityError {
    #[error("measured candidate identity descriptor is missing")]
    MissingDescriptor,
    #[error("measured candidate identity descriptor is not a private read-only regular file")]
    UnsafeDescriptor,
    #[error("measured candidate identity is invalid")]
    InvalidIdentity,
    #[error("measured candidate identity is already installed or has already been claimed")]
    AlreadyInstalled,
    #[error("measured candidate identity is not installed")]
    Missing,
}

static MEASURED_CANDIDATE: OnceLock<Mutex<Option<CandidateIdentityV1>>> = OnceLock::new();

fn measured_slot() -> &'static Mutex<Option<CandidateIdentityV1>> {
    MEASURED_CANDIDATE.get_or_init(|| Mutex::new(None))
}

/// Store one independently measured candidate identity. Bind later claims it.
pub fn install_measured_candidate_identity(
    identity: CandidateIdentityV1,
) -> Result<(), CandidateIdentityError> {
    validate_identity(&identity)?;
    let mut slot = measured_slot()
        .lock()
        .expect("measured candidate identity lock poisoned");
    if slot.is_some() {
        return Err(CandidateIdentityError::AlreadyInstalled);
    }
    *slot = Some(identity);
    Ok(())
}

pub fn claim_measured_candidate_identity() -> Result<CandidateIdentityV1, CandidateIdentityError> {
    let mut slot = measured_slot()
        .lock()
        .expect("measured candidate identity lock poisoned");
    slot.take().ok_or(CandidateIdentityError::Missing)
}

pub fn discard_unclaimed_measured_candidate_identity() {
    if let Ok(mut slot) = measured_slot().lock() {
        *slot = None;
    }
}

fn validate_identity(identity: &CandidateIdentityV1) -> Result<(), CandidateIdentityError> {
    if identity.cli_build.is_empty() || identity.cli_build.len() > 256 {
        return Err(CandidateIdentityError::InvalidIdentity);
    }
    if identity.source_commit_sha.len() != 40
        || !identity
            .source_commit_sha
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(CandidateIdentityError::InvalidIdentity);
    }
    if identity.binary_sha256.len() != 64
        || !identity
            .binary_sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(CandidateIdentityError::InvalidIdentity);
    }
    Ok(())
}

/// First post-credential pager action for armed Darwin launches. Unarmed
/// launches do not inspect or close FD 197.
#[cfg(unix)]
pub fn consume_measured_candidate_if_armed(
    armed: bool,
    cli_build: &str,
    source_commit_sha: &str,
) -> Result<Option<CandidateIdentityV1>, CandidateIdentityError> {
    consume_measured_candidate_from_fd(armed, CANDIDATE_IDENTITY_FD, cli_build, source_commit_sha)
}

#[cfg(unix)]
fn consume_measured_candidate_from_fd(
    armed: bool,
    descriptor: RawFd,
    cli_build: &str,
    source_commit_sha: &str,
) -> Result<Option<CandidateIdentityV1>, CandidateIdentityError> {
    if !armed {
        return Ok(None);
    }
    if descriptor < 0 || unsafe { libc::fcntl(descriptor, libc::F_GETFD) } < 0 {
        return Err(CandidateIdentityError::MissingDescriptor);
    }
    let descriptor = unsafe { OwnedFd::from_raw_fd(descriptor) };
    let flags = unsafe { libc::fcntl(descriptor.as_raw_fd(), libc::F_GETFL) };
    if flags < 0 || flags & libc::O_ACCMODE != libc::O_RDONLY {
        return Err(CandidateIdentityError::UnsafeDescriptor);
    }
    let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
    if unsafe { libc::fstat(descriptor.as_raw_fd(), &mut stat) } != 0
        || stat.st_mode & libc::S_IFMT != libc::S_IFREG
        || stat.st_uid != unsafe { libc::geteuid() }
        || stat.st_mode & 0o077 != 0
        || stat.st_nlink != 1
        || stat.st_size < 0
    {
        return Err(CandidateIdentityError::UnsafeDescriptor);
    }
    let digest = sha256_descriptor(descriptor.as_raw_fd(), stat.st_size as u64)?;
    let mut restat = unsafe { std::mem::zeroed::<libc::stat>() };
    if unsafe { libc::fstat(descriptor.as_raw_fd(), &mut restat) } != 0
        || restat.st_dev != stat.st_dev
        || restat.st_ino != stat.st_ino
        || restat.st_size != stat.st_size
        || restat.st_nlink != 1
    {
        return Err(CandidateIdentityError::UnsafeDescriptor);
    }
    drop(descriptor);
    let identity = CandidateIdentityV1 {
        cli_build: cli_build.to_string(),
        binary_sha256: digest,
        source_commit_sha: source_commit_sha.to_string(),
    };
    validate_identity(&identity)?;
    Ok(Some(identity))
}

#[cfg(unix)]
fn sha256_descriptor(descriptor: RawFd, size: u64) -> Result<String, CandidateIdentityError> {
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 65_536];
    let mut offset: libc::off_t = 0;
    let total =
        libc::off_t::try_from(size).map_err(|_| CandidateIdentityError::UnsafeDescriptor)?;
    while offset < total {
        let want = std::cmp::min((total - offset) as usize, buffer.len());
        let read = unsafe { libc::pread(descriptor, buffer.as_mut_ptr().cast(), want, offset) };
        if read <= 0 {
            return Err(CandidateIdentityError::UnsafeDescriptor);
        }
        hasher.update(&buffer[..read as usize]);
        offset += read as libc::off_t;
    }
    Ok(format!("{:x}", hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn unarmed_does_not_touch_missing_identity_fd() {
        assert_eq!(
            consume_measured_candidate_from_fd(
                false,
                CANDIDATE_IDENTITY_FD,
                "build",
                &"b".repeat(40)
            )
            .unwrap(),
            None
        );
    }

    #[cfg(unix)]
    #[test]
    fn armed_missing_identity_fd_refuses() {
        let fd = CANDIDATE_IDENTITY_FD;
        unsafe {
            libc::close(fd);
        }
        assert_eq!(
            consume_measured_candidate_from_fd(true, fd, "build", &"b".repeat(40)),
            Err(CandidateIdentityError::MissingDescriptor)
        );
    }

    #[cfg(unix)]
    #[test]
    fn armed_read_only_regular_file_hashes_and_closes() {
        use std::os::fd::IntoRawFd;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

        let dir = std::env::temp_dir().join(format!(
            "grok-candidate-identity-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = dir.join("candidate");
        std::fs::write(&path, b"inspected-bytes").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&path)
            .unwrap();
        let fd = file.into_raw_fd();
        let identity = consume_measured_candidate_from_fd(
            true,
            fd,
            "1.0.5 (003f955)",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        )
        .unwrap()
        .unwrap();
        assert_eq!(identity.cli_build, "1.0.5 (003f955)");
        assert_eq!(
            identity.binary_sha256,
            format!("{:x}", Sha256::digest(b"inspected-bytes"))
        );
        assert_eq!(unsafe { libc::fcntl(fd, libc::F_GETFD) }, -1);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn armed_hard_linked_identity_fd_refuses() {
        use std::os::fd::IntoRawFd;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

        let dir = std::env::temp_dir().join(format!(
            "grok-candidate-identity-link-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = dir.join("candidate");
        std::fs::write(&path, b"linked").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::hard_link(&path, dir.join("alias")).unwrap();
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&path)
            .unwrap();
        let fd = file.into_raw_fd();
        assert_eq!(
            consume_measured_candidate_from_fd(
                true,
                fd,
                "1.0.5 (003f955)",
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            ),
            Err(CandidateIdentityError::UnsafeDescriptor)
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn measured_identity_installs_once_and_claims() {
        discard_unclaimed_measured_candidate_identity();
        let identity = CandidateIdentityV1 {
            cli_build: "1.0.5 (003f955)".to_string(),
            binary_sha256: "a".repeat(64),
            source_commit_sha: "b".repeat(40),
        };
        install_measured_candidate_identity(identity.clone()).unwrap();
        assert_eq!(
            install_measured_candidate_identity(identity.clone()),
            Err(CandidateIdentityError::AlreadyInstalled)
        );
        assert_eq!(claim_measured_candidate_identity().unwrap(), identity);
        assert_eq!(
            claim_measured_candidate_identity(),
            Err(CandidateIdentityError::Missing)
        );
    }
}
