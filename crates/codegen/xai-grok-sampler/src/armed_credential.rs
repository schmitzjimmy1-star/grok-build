//! The only authoritative in-process storage for a 4B.3 credential.
//!
//! The owner never exposes `String` data. HTTP header construction necessarily
//! makes a reqwest/header-owned byte copy; that is the sole downstream copy and
//! is bounded to the lifetime of the sampling client.

use std::sync::{Mutex, OnceLock};

use zeroize::Zeroizing;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ArmedCredentialError {
    #[error("armed credential is already installed or has already been claimed")]
    AlreadyInstalled,
    #[error("armed credential is not installed")]
    Missing,
    #[error("armed credential is empty or too large")]
    Invalid,
    #[error("armed credential cannot be claimed before v3 authority is active")]
    AuthorityInactive,
}

/// Opaque, consuming credential owner. No cloning or string conversion exists.
pub struct ArmedCredentialOwner {
    bytes: Zeroizing<Vec<u8>>,
}

impl ArmedCredentialOwner {
    pub fn from_receiver(bytes: Zeroizing<Vec<u8>>) -> Result<Self, ArmedCredentialError> {
        if bytes.is_empty() || bytes.len() > 4_096 {
            return Err(ArmedCredentialError::Invalid);
        }
        Ok(Self { bytes })
    }

    pub(crate) fn into_bytes(self) -> Zeroizing<Vec<u8>> {
        self.bytes
    }
}

struct OwnerSlot {
    installed: bool,
    owner: Option<ArmedCredentialOwner>,
}
static OWNER: OnceLock<Mutex<OwnerSlot>> = OnceLock::new();

fn slot() -> &'static Mutex<OwnerSlot> {
    OWNER.get_or_init(|| {
        Mutex::new(OwnerSlot {
            installed: false,
            owner: None,
        })
    })
}

/// Install exactly once. A claim consumes the owner permanently; it cannot be
/// reinstalled for a later route or a retry.
pub fn install_armed_credential_owner(
    owner: ArmedCredentialOwner,
) -> Result<(), ArmedCredentialError> {
    let mut slot = slot().lock().expect("armed credential owner lock poisoned");
    if slot.installed {
        return Err(ArmedCredentialError::AlreadyInstalled);
    }
    slot.installed = true;
    slot.owner = Some(owner);
    Ok(())
}

pub(crate) fn claim_armed_credential_owner() -> Result<ArmedCredentialOwner, ArmedCredentialError> {
    if crate::hard_budget::active_v3_authority().is_none() {
        return Err(ArmedCredentialError::AuthorityInactive);
    }
    let mut slot = slot().lock().expect("armed credential owner lock poisoned");
    slot.owner.take().ok_or(ArmedCredentialError::Missing)
}

/// Wipe an unclaimed owner. `process::exit` skips destructors, so every
/// armed pager exit path must call this before leaving the process.
pub fn discard_unclaimed_armed_credential_owner() {
    if let Some(slot) = OWNER.get() {
        let mut slot = slot.lock().expect("armed credential owner lock poisoned");
        slot.owner.take();
    }
}

#[cfg(test)]
pub(crate) fn reset_armed_credential_owner_for_test() {
    if let Some(slot) = OWNER.get() {
        let mut slot = slot.lock().expect("armed credential owner lock poisoned");
        slot.installed = false;
        slot.owner = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroizing;

    #[test]
    fn claim_requires_active_v3_authority_and_is_one_shot() {
        let _guard = crate::hard_budget::v3_test_support::lock();
        let owner =
            ArmedCredentialOwner::from_receiver(Zeroizing::new(b"fake-sentinel".to_vec())).unwrap();
        install_armed_credential_owner(owner).unwrap();
        assert_eq!(
            claim_armed_credential_owner().err(),
            Some(ArmedCredentialError::AuthorityInactive)
        );

        let dir = crate::hard_budget::v3_test_support::private_dir("claim-once");
        let _authority = crate::hard_budget::v3_test_support::activate(&dir);
        let claimed = claim_armed_credential_owner().unwrap();
        assert_eq!(&*claimed.into_bytes(), b"fake-sentinel");
        assert_eq!(
            claim_armed_credential_owner().err(),
            Some(ArmedCredentialError::Missing)
        );
        assert_eq!(
            install_armed_credential_owner(
                ArmedCredentialOwner::from_receiver(Zeroizing::new(b"again".to_vec())).unwrap()
            ),
            Err(ArmedCredentialError::AlreadyInstalled)
        );
        std::fs::remove_dir_all(dir).unwrap();
    }
}
