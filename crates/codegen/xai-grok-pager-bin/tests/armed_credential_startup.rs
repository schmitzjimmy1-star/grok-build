#![cfg(target_os = "macos")]

use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};

const RECEIVER_FD: libc::c_int = 198;
const IDENTITY_FD: libc::c_int = 197;
const HEADER_BYTES: usize = 48;
const MAGIC: [u8; 8] = [0x47, 0x42, 0x43, 0x54, 0, 0, 0, 1];
const CREDENTIAL: u8 = 1;
const ACKNOWLEDGEMENT: u8 = 2;
const COMMIT: u8 = 3;
const READY: u8 = 4;

fn pager_binary() -> std::path::PathBuf {
    if let Ok(path) = std::env::var("PAGER_BINARY") {
        return std::path::absolute(&path)
            .unwrap_or_else(|error| panic!("failed to absolutize PAGER_BINARY: {error}"));
    }
    option_env!("CARGO_BIN_EXE_xai-grok-pager")
        .map(std::path::PathBuf::from)
        .expect("PAGER_BINARY is unset and this build is not `cargo test`")
}

fn header(kind: u8, nonce: &[u8; 32], payload_length: usize) -> [u8; HEADER_BYTES] {
    let mut bytes = [0_u8; HEADER_BYTES];
    bytes[..8].copy_from_slice(&MAGIC);
    bytes[8] = kind;
    bytes[12..44].copy_from_slice(nonce);
    bytes[44..48].copy_from_slice(&(payload_length as u32).to_be_bytes());
    bytes
}

fn socket_pair() -> (UnixStream, OwnedFd) {
    let mut descriptors = [-1; 2];
    assert_eq!(
        unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_STREAM,
                0,
                descriptors.as_mut_ptr(),
            )
        },
        0
    );
    (unsafe { UnixStream::from_raw_fd(descriptors[0]) }, unsafe {
        OwnedFd::from_raw_fd(descriptors[1])
    })
}

fn private_identity_copy(source: &std::path::Path) -> (std::path::PathBuf, OwnedFd) {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let dir = std::env::temp_dir().join(format!(
        "grok-pager-identity-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = dir.join("candidate");
    std::fs::copy(source, &path).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&path)
        .unwrap();
    (dir, OwnedFd::from(file))
}

fn parent_handshake(mut peer: UnixStream, payload: &[u8]) {
    let nonce = [7_u8; 32];
    peer.write_all(&header(CREDENTIAL, &nonce, payload.len()))
        .unwrap();
    peer.write_all(payload).unwrap();
    let mut acknowledgement = [0_u8; HEADER_BYTES];
    peer.read_exact(&mut acknowledgement).unwrap();
    assert_eq!(&acknowledgement[..8], &MAGIC);
    assert_eq!(acknowledgement[8], ACKNOWLEDGEMENT);
    peer.write_all(&header(COMMIT, &nonce, 0)).unwrap();
    peer.shutdown(std::net::Shutdown::Write).unwrap();
    let mut ready = [0_u8; HEADER_BYTES];
    peer.read_exact(&mut ready).unwrap();
    assert_eq!(&ready[..8], &MAGIC);
    assert_eq!(ready[8], READY);
}

#[test]
fn armed_credential_missing_fd_refuses_before_version_path() {
    let mut command = Command::new(pager_binary());
    command
        .arg("--version")
        .env_clear()
        .env("GROK_HARD_TOKEN_BUDGET_LEDGER", "armed-test");
    unsafe {
        command.pre_exec(|| {
            libc::close(RECEIVER_FD);
            Ok(())
        });
    }

    let output = command.output().expect("spawn pager binary");
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty(), "version ran after armed refusal");
    assert!(output.stderr.is_empty(), "armed refusal must not log");
}

#[test]
fn armed_credential_valid_fd_without_identity_refuses_before_version_path() {
    let (local, remote) = socket_pair();
    let remote_fd = remote.as_raw_fd();
    unsafe {
        libc::fcntl(remote_fd, libc::F_SETFD, 0);
        libc::close(IDENTITY_FD);
    }

    let mut command = Command::new(pager_binary());
    command
        .arg("--version")
        .env_clear()
        .env("GROK_HARD_TOKEN_BUDGET_LEDGER", "armed-test")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    unsafe {
        command.pre_exec(move || {
            if remote_fd != RECEIVER_FD {
                if libc::dup2(remote_fd, RECEIVER_FD) != RECEIVER_FD {
                    return Err(std::io::Error::last_os_error());
                }
                libc::close(remote_fd);
            }
            libc::close(IDENTITY_FD);
            Ok(())
        });
    }

    let child = command.spawn().expect("spawn pager binary");
    drop(remote);
    parent_handshake(local, b"fake-sentinel");
    let output = child.wait_with_output().expect("wait pager binary");
    assert_eq!(output.status.code(), Some(2));
    assert!(
        output.stdout.is_empty(),
        "version ran after identity refusal"
    );
    assert!(
        output.stderr.is_empty(),
        "identity refusal must not log: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn armed_credential_valid_fd_installs_then_refuses_non_stdio_without_leaking() {
    let (local, remote) = socket_pair();
    let remote_fd = remote.as_raw_fd();
    let (identity_dir, identity) = private_identity_copy(&pager_binary());
    let identity_fd = identity.as_raw_fd();
    unsafe {
        libc::fcntl(remote_fd, libc::F_SETFD, 0);
    }

    let mut command = Command::new(pager_binary());
    command
        .arg("--version")
        .env_clear()
        .env("GROK_HARD_TOKEN_BUDGET_LEDGER", "armed-test")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    unsafe {
        command.pre_exec(move || {
            if remote_fd != RECEIVER_FD {
                if libc::dup2(remote_fd, RECEIVER_FD) != RECEIVER_FD {
                    return Err(std::io::Error::last_os_error());
                }
                libc::close(remote_fd);
            }
            if identity_fd != IDENTITY_FD {
                if libc::dup2(identity_fd, IDENTITY_FD) != IDENTITY_FD {
                    return Err(std::io::Error::last_os_error());
                }
                libc::close(identity_fd);
            }
            Ok(())
        });
    }

    let child = command.spawn().expect("spawn pager binary");
    drop(remote);
    drop(identity);
    parent_handshake(local, b"fake-sentinel");
    let output = child.wait_with_output().expect("wait pager binary");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let _ = std::fs::remove_dir_all(identity_dir);
    assert_eq!(output.status.code(), Some(2));
    assert!(
        stdout.is_empty(),
        "version ran after armed install: {stdout}"
    );
    assert!(
        stderr.contains("requires `grok agent stdio`"),
        "armed install must still refuse non-stdio: {stderr}"
    );
    assert!(
        !stdout.contains("fake-sentinel") && !stderr.contains("fake-sentinel"),
        "fake credential leaked"
    );
}
