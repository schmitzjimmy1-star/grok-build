//! Darwin-only one-shot receipt of the app-owned armed credential channel.
//!
//! This module deliberately knows nothing about config, provider routing, or
//! sampling. Its job is much smaller: when hard-budget mode is armed, consume
//! the inherited descriptor before any of those systems start, then transfer
//! the bounded bytes into the sampler's one-shot owner. `main` installs that
//! owner immediately; later exits must wipe it because `process::exit` skips
//! destructors. The armed sampler may claim it only after `bind_actual`.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

pub(crate) const RECEIVER_FD: RawFd = 198;
const MAXIMUM_CREDENTIAL_BYTES: usize = 4_096;
const HEADER_BYTES: usize = 48;
const DEADLINE: Duration = Duration::from_secs(2);
const MAGIC: [u8; 8] = [0x47, 0x42, 0x43, 0x54, 0, 0, 0, 1];
const CREDENTIAL: u8 = 1;
const ACKNOWLEDGEMENT: u8 = 2;
const COMMIT: u8 = 3;
const READY: u8 = 4;

/// Single-owner credential bytes. Production converts this into the sampler's
/// `ArmedCredentialOwner` exactly once. The payload cannot become a `String`,
/// configuration, or generic auth data.
pub(crate) struct ArmedCredential {
    bytes: Zeroizing<Vec<u8>>,
}

impl ArmedCredential {
    pub(crate) fn into_owner(
        self,
    ) -> Result<xai_grok_sampler::ArmedCredentialOwner, xai_grok_sampler::ArmedCredentialError>
    {
        xai_grok_sampler::ArmedCredentialOwner::from_receiver(self.bytes)
    }

    #[cfg(test)]
    fn into_test_sink(self) -> Zeroizing<Vec<u8>> {
        self.bytes
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReceiveError {
    MissingDescriptor,
    WrongPeer,
    Timeout,
    MalformedFrame,
    OversizedFrame,
    Io,
}

/// First pager-bin action for armed launches. Unarmed launches do not inspect
/// or close FD 198, including if a caller happens to own that descriptor.
pub(crate) fn consume_if_armed(armed: bool) -> Result<Option<ArmedCredential>, ReceiveError> {
    consume_from_fd(armed, RECEIVER_FD, DEADLINE)
}

fn consume_from_fd(
    armed: bool,
    descriptor: RawFd,
    deadline: Duration,
) -> Result<Option<ArmedCredential>, ReceiveError> {
    if !armed {
        return Ok(None);
    }
    if descriptor < 0 || unsafe { libc::fcntl(descriptor, libc::F_GETFD) } < 0 {
        return Err(ReceiveError::MissingDescriptor);
    }

    // From this point every return closes the inherited descriptor exactly once.
    let descriptor = unsafe { OwnedFd::from_raw_fd(descriptor) };
    verify_same_user_peer(descriptor.as_raw_fd())?;
    let end = Instant::now()
        .checked_add(deadline)
        .ok_or(ReceiveError::Timeout)?;

    let credential_header = read_exact(descriptor.as_raw_fd(), HEADER_BYTES, end)?;
    let (nonce, payload_length) = parse_header(&credential_header, CREDENTIAL)?;
    if payload_length == 0 {
        return Err(ReceiveError::MalformedFrame);
    }
    if payload_length > MAXIMUM_CREDENTIAL_BYTES {
        return Err(ReceiveError::OversizedFrame);
    }
    let payload = read_exact_zeroizing(descriptor.as_raw_fd(), payload_length, end)?;

    let acknowledgement = header(ACKNOWLEDGEMENT, &nonce, payload_length);
    write_exact(descriptor.as_raw_fd(), &acknowledgement, end)?;

    let commit = read_exact(descriptor.as_raw_fd(), HEADER_BYTES, end)?;
    let (commit_nonce, commit_length) = parse_header(&commit, COMMIT)?;
    if commit_nonce != nonce || commit_length != 0 {
        return Err(ReceiveError::MalformedFrame);
    }
    require_peer_write_closed(descriptor.as_raw_fd(), end)?;

    let ready = header(READY, &nonce, 0);
    write_exact(descriptor.as_raw_fd(), &ready, end)?;
    // `descriptor` drops here, before the caller can reach config, hooks,
    // tools, subprocesses, network, or a fork-capable runtime.
    drop(descriptor);

    Ok(Some(ArmedCredential { bytes: payload }))
}

#[cfg(target_os = "macos")]
fn verify_same_user_peer(descriptor: RawFd) -> Result<(), ReceiveError> {
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    let result = unsafe { libc::getpeereid(descriptor, &mut uid, &mut gid) };
    if result != 0 || uid != unsafe { libc::geteuid() } {
        return Err(ReceiveError::WrongPeer);
    }
    Ok(())
}

fn parse_header(header: &[u8], expected_type: u8) -> Result<([u8; 32], usize), ReceiveError> {
    if header.len() != HEADER_BYTES
        || header[..8] != MAGIC
        || header[8] != expected_type
        || header[9..12] != [0, 0, 0]
    {
        return Err(ReceiveError::MalformedFrame);
    }
    let mut nonce = [0_u8; 32];
    nonce.copy_from_slice(&header[12..44]);
    let length = u32::from_be_bytes(
        header[44..48]
            .try_into()
            .map_err(|_| ReceiveError::MalformedFrame)?,
    );
    Ok((nonce, length as usize))
}

fn header(kind: u8, nonce: &[u8; 32], payload_length: usize) -> [u8; HEADER_BYTES] {
    let mut bytes = [0_u8; HEADER_BYTES];
    bytes[..8].copy_from_slice(&MAGIC);
    bytes[8] = kind;
    bytes[12..44].copy_from_slice(nonce);
    bytes[44..48].copy_from_slice(&(payload_length as u32).to_be_bytes());
    bytes
}

fn read_exact(descriptor: RawFd, count: usize, end: Instant) -> Result<Vec<u8>, ReceiveError> {
    let mut bytes = vec![0_u8; count];
    let mut offset = 0;
    while offset < count {
        wait(descriptor, libc::POLLIN, end)?;
        let read = unsafe {
            libc::read(
                descriptor,
                bytes[offset..].as_mut_ptr().cast(),
                bytes.len() - offset,
            )
        };
        if read <= 0 {
            return Err(ReceiveError::MalformedFrame);
        }
        offset += read as usize;
    }
    Ok(bytes)
}

fn read_exact_zeroizing(
    descriptor: RawFd,
    count: usize,
    end: Instant,
) -> Result<Zeroizing<Vec<u8>>, ReceiveError> {
    let mut bytes = Zeroizing::new(vec![0_u8; count]);
    let mut offset = 0;
    while offset < count {
        wait(descriptor, libc::POLLIN, end)?;
        let read = unsafe {
            libc::read(
                descriptor,
                bytes[offset..].as_mut_ptr().cast(),
                bytes.len() - offset,
            )
        };
        if read <= 0 {
            return Err(ReceiveError::MalformedFrame);
        }
        offset += read as usize;
    }
    Ok(bytes)
}

fn write_exact(descriptor: RawFd, bytes: &[u8], end: Instant) -> Result<(), ReceiveError> {
    let mut offset = 0;
    while offset < bytes.len() {
        wait(descriptor, libc::POLLOUT, end)?;
        let written = unsafe {
            libc::send(
                descriptor,
                bytes[offset..].as_ptr().cast(),
                bytes.len() - offset,
                libc::MSG_NOSIGNAL,
            )
        };
        if written <= 0 {
            return Err(ReceiveError::Io);
        }
        offset += written as usize;
    }
    Ok(())
}

/// Desktop closes its write half immediately after COMMIT.  Treat any byte
/// after that frame as a protocol violation before releasing READY, so a
/// duplicated or appended frame cannot be smuggled through this handoff.
fn require_peer_write_closed(descriptor: RawFd, end: Instant) -> Result<(), ReceiveError> {
    loop {
        wait(descriptor, libc::POLLIN, end)?;
        let mut byte = 0_u8;
        let read = unsafe { libc::read(descriptor, std::ptr::from_mut(&mut byte).cast(), 1) };
        if read == 0 {
            return Ok(());
        }
        if read > 0 {
            return Err(ReceiveError::MalformedFrame);
        }
        if io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
            return Err(ReceiveError::Io);
        }
    }
}

fn wait(descriptor: RawFd, events: i16, end: Instant) -> Result<(), ReceiveError> {
    let mut pollfd = libc::pollfd {
        fd: descriptor,
        events,
        revents: 0,
    };
    loop {
        let remaining = end
            .checked_duration_since(Instant::now())
            .ok_or(ReceiveError::Timeout)?;
        let millis = remaining.as_millis().clamp(1, i32::MAX as u128) as i32;
        let result = unsafe { libc::poll(&mut pollfd, 1, millis) };
        if result == 0 {
            return Err(ReceiveError::Timeout);
        }
        if result < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(ReceiveError::Io);
        }
        if pollfd.revents & (libc::POLLERR | libc::POLLNVAL) != 0 {
            return Err(ReceiveError::Io);
        }
        if pollfd.revents & events != 0 {
            return Ok(());
        }
        if events & libc::POLLIN != 0 && pollfd.revents & libc::POLLHUP != 0 {
            return Ok(());
        }
        return Err(ReceiveError::MalformedFrame);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;

    fn socket_pair() -> (OwnedFd, OwnedFd) {
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
        unsafe {
            (
                OwnedFd::from_raw_fd(descriptors[0]),
                OwnedFd::from_raw_fd(descriptors[1]),
            )
        }
    }

    fn peer_handshake(peer: OwnedFd, payload: Vec<u8>) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            let nonce = [7_u8; 32];
            write_exact(
                peer.as_raw_fd(),
                &header(CREDENTIAL, &nonce, payload.len()),
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap();
            write_exact(
                peer.as_raw_fd(),
                &payload,
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap();
            let acknowledgement = read_exact(
                peer.as_raw_fd(),
                HEADER_BYTES,
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap();
            assert_eq!(
                parse_header(&acknowledgement, ACKNOWLEDGEMENT).unwrap(),
                (nonce, payload.len())
            );
            write_exact(
                peer.as_raw_fd(),
                &header(COMMIT, &nonce, 0),
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap();
            assert_eq!(
                unsafe { libc::shutdown(peer.as_raw_fd(), libc::SHUT_WR) },
                0
            );
            let ready = read_exact(
                peer.as_raw_fd(),
                HEADER_BYTES,
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap();
            assert_eq!(parse_header(&ready, READY).unwrap(), (nonce, 0));
            let mut byte = 0_u8;
            assert_eq!(
                unsafe { libc::read(peer.as_raw_fd(), std::ptr::from_mut(&mut byte).cast(), 1,) },
                0
            );
        })
    }

    /// Temporarily makes a test socket occupy the production receiver number
    /// without clobbering an FD held by the test harness.
    struct ReceiverFdGuard {
        saved: RawFd,
    }

    impl ReceiverFdGuard {
        fn replace_with(descriptor: RawFd) -> Self {
            let saved = if unsafe { libc::fcntl(RECEIVER_FD, libc::F_GETFD) } >= 0 {
                let duplicate = unsafe { libc::fcntl(RECEIVER_FD, libc::F_DUPFD_CLOEXEC, 512) };
                assert!(duplicate >= 0);
                duplicate
            } else {
                -1
            };
            assert_eq!(unsafe { libc::dup2(descriptor, RECEIVER_FD) }, RECEIVER_FD);
            Self { saved }
        }
    }

    impl Drop for ReceiverFdGuard {
        fn drop(&mut self) {
            if self.saved >= 0 {
                assert_eq!(unsafe { libc::dup2(self.saved, RECEIVER_FD) }, RECEIVER_FD);
                unsafe { libc::close(self.saved) };
            } else {
                unsafe { libc::close(RECEIVER_FD) };
            }
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn unarmed_does_not_touch_fd() {
        let (receiver, peer) = socket_pair();
        assert!(
            consume_from_fd(false, receiver.as_raw_fd(), Duration::ZERO)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            unsafe { libc::send(peer.as_raw_fd(), b"x".as_ptr().cast(), 1, 0) },
            1
        );
        let mut byte = 0_u8;
        assert_eq!(
            unsafe {
                libc::read(
                    receiver.as_raw_fd(),
                    std::ptr::from_mut(&mut byte).cast(),
                    1,
                )
            },
            1
        );
        assert_eq!(byte, b'x');
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn armed_receiver_converts_to_sampler_owner() {
        let (receiver, peer) = socket_pair();
        let sender = peer_handshake(peer, b"fake-sentinel".to_vec());
        let credential = consume_from_fd(true, receiver.into_raw_fd(), Duration::from_secs(1))
            .unwrap()
            .unwrap();
        credential
            .into_owner()
            .expect("received fake credential must become the sampler owner");
        sender.join().unwrap();
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn armed_receiver_delivers_once_to_test_sink_and_closes() {
        let (receiver, peer) = socket_pair();
        let sender = peer_handshake(peer, b"fake-sentinel".to_vec());
        let credential = consume_from_fd(true, receiver.into_raw_fd(), Duration::from_secs(1))
            .unwrap()
            .unwrap();
        let payload = credential.into_test_sink();
        assert_eq!(&*payload, b"fake-sentinel");
        sender.join().unwrap();
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn armed_rejects_absent_wrong_malformed_truncated_oversized_trailing_and_timeout() {
        assert!(matches!(
            consume_from_fd(true, -1, Duration::ZERO),
            Err(ReceiveError::MissingDescriptor)
        ));

        let mut pipe_fds = [-1; 2];
        assert_eq!(unsafe { libc::pipe(pipe_fds.as_mut_ptr()) }, 0);
        let read_end = unsafe { OwnedFd::from_raw_fd(pipe_fds[0]) };
        let write_end = unsafe { OwnedFd::from_raw_fd(pipe_fds[1]) };
        drop(write_end);
        assert!(matches!(
            consume_from_fd(true, read_end.into_raw_fd(), Duration::ZERO),
            Err(ReceiveError::WrongPeer)
        ));

        for bytes in [
            vec![0_u8; HEADER_BYTES],
            header(CREDENTIAL, &[1_u8; 32], 0).to_vec(),
            header(CREDENTIAL, &[1_u8; 32], 2)
                .into_iter()
                .take(12)
                .collect(),
            header(CREDENTIAL, &[1_u8; 32], MAXIMUM_CREDENTIAL_BYTES + 1).to_vec(),
        ] {
            let (receiver, peer) = socket_pair();
            assert_eq!(
                unsafe { libc::send(peer.as_raw_fd(), bytes.as_ptr().cast(), bytes.len(), 0) },
                bytes.len() as isize
            );
            drop(peer);
            let result = consume_from_fd(true, receiver.into_raw_fd(), Duration::from_millis(50));
            assert!(matches!(
                result,
                Err(ReceiveError::MalformedFrame | ReceiveError::OversizedFrame)
            ));
        }

        let (receiver, peer) = socket_pair();
        let sender = std::thread::spawn(move || {
            let nonce = [3_u8; 32];
            write_exact(
                peer.as_raw_fd(),
                &header(CREDENTIAL, &nonce, 1),
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap();
            write_exact(
                peer.as_raw_fd(),
                b"x",
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap();
            let _ = read_exact(
                peer.as_raw_fd(),
                HEADER_BYTES,
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap();
            write_exact(
                peer.as_raw_fd(),
                b"!",
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap();
        });
        assert!(matches!(
            consume_from_fd(true, receiver.into_raw_fd(), Duration::from_secs(1)),
            Err(ReceiveError::MalformedFrame)
        ));
        sender.join().unwrap();

        let (receiver, _peer) = socket_pair();
        assert!(matches!(
            consume_from_fd(true, receiver.into_raw_fd(), Duration::ZERO),
            Err(ReceiveError::Timeout)
        ));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn armed_rejects_valid_commit_with_trailing_bytes() {
        let (receiver, peer) = socket_pair();
        let sender = std::thread::spawn(move || {
            let nonce = [4_u8; 32];
            write_exact(
                peer.as_raw_fd(),
                &header(CREDENTIAL, &nonce, 1),
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap();
            write_exact(
                peer.as_raw_fd(),
                b"x",
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap();
            let acknowledgement = read_exact(
                peer.as_raw_fd(),
                HEADER_BYTES,
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap();
            assert_eq!(
                parse_header(&acknowledgement, ACKNOWLEDGEMENT).unwrap(),
                (nonce, 1)
            );
            write_exact(
                peer.as_raw_fd(),
                &header(COMMIT, &nonce, 0),
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap();
            write_exact(
                peer.as_raw_fd(),
                b"!",
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap();
            assert_eq!(
                unsafe { libc::shutdown(peer.as_raw_fd(), libc::SHUT_WR) },
                0
            );
        });
        assert!(matches!(
            consume_from_fd(true, receiver.into_raw_fd(), Duration::from_secs(1)),
            Err(ReceiveError::MalformedFrame)
        ));
        sender.join().unwrap();
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn receiver_closes_fd_before_raw_fork_and_setsid_descendant() {
        let (receiver, peer) = socket_pair();
        let sender = peer_handshake(peer, b"fork-proof".to_vec());
        let _fd_guard = ReceiverFdGuard::replace_with(receiver.as_raw_fd());
        drop(receiver);
        let credential = consume_from_fd(true, RECEIVER_FD, Duration::from_secs(1))
            .unwrap()
            .unwrap();
        let mut pipe_fds = [-1; 2];
        assert_eq!(unsafe { libc::pipe(pipe_fds.as_mut_ptr()) }, 0);
        let child = unsafe { libc::fork() };
        assert!(child >= 0);
        if child == 0 {
            unsafe {
                libc::close(pipe_fds[0]);
                let detached = libc::setsid() >= 0;
                let fd_closed = libc::fcntl(RECEIVER_FD, libc::F_GETFD) == -1
                    && *libc::__error() == libc::EBADF;
                let byte = u8::from(detached && fd_closed);
                let _ = libc::write(pipe_fds[1], std::ptr::from_ref(&byte).cast(), 1);
                libc::_exit(0);
            }
        }
        unsafe { libc::close(pipe_fds[1]) };
        let mut result = 0_u8;
        assert_eq!(
            unsafe { libc::read(pipe_fds[0], std::ptr::from_mut(&mut result).cast(), 1,) },
            1
        );
        unsafe { libc::close(pipe_fds[0]) };
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
        assert_eq!(result, 1);
        drop(credential.into_test_sink());
        sender.join().unwrap();
    }
}
