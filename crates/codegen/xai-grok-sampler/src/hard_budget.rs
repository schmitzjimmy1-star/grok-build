//! Durable, process-shared admission control for opt-in hard token budgets.
//!
//! The budget is deliberately below the shell/session layer: every sampling
//! client, including auxiliary and child-agent clients, must reserve before an
//! HTTP dispatch. A reservation remains charged until complete provider usage
//! settles it. Dropped streams, cancellation, crashes, and ambiguous transport
//! failures therefore consume the full reservation instead of refunding money
//! the runtime cannot prove was unspent.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use fs2::FileExt;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

const LEDGER_VERSION: u32 = 1;
const ENV_LEDGER: &str = "GROK_HARD_TOKEN_BUDGET_LEDGER";
const ENV_CAMPAIGN: &str = "GROK_HARD_TOKEN_BUDGET_CAMPAIGN";
const ENV_CEILING: &str = "GROK_HARD_TOKEN_BUDGET_CEILING";

#[derive(Debug, thiserror::Error)]
pub enum HardTokenBudgetError {
    #[error("hard-token-budget environment is incomplete")]
    IncompleteEnvironment,
    #[error("hard-token-budget ledger path must be absolute")]
    RelativeLedgerPath,
    #[error("hard-token-budget campaign id is invalid")]
    InvalidCampaign,
    #[error("hard-token-budget ceiling is invalid")]
    InvalidCeiling,
    #[error("hard-token-budget parent directory is not private and owner-controlled")]
    UnsafeParent,
    #[error("hard-token-budget artifact is not a private owner-controlled regular file")]
    UnsafeArtifact,
    #[error("hard-token-budget ledger identity does not match this process")]
    IdentityMismatch,
    #[error("hard-token-budget ledger is marked violated")]
    Violated,
    #[error("hard-token-budget reservation exceeds the remaining ceiling")]
    Exhausted,
    #[error("hard-token-budget reservation was not found")]
    ReservationMissing,
    #[error("hard-token-budget reservation is already settled")]
    AlreadySettled,
    #[error("hard-token-budget arithmetic overflow")]
    Overflow,
    #[error("hard-token-budget I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("hard-token-budget ledger is malformed: {0}")]
    Malformed(#[from] serde_json::Error),
}

#[derive(Clone, Debug)]
pub struct HardTokenBudget {
    inner: Arc<HardTokenBudgetInner>,
}

#[derive(Debug)]
struct HardTokenBudgetInner {
    ledger_path: PathBuf,
    lock_path: PathBuf,
    campaign_id: String,
    ceiling_tokens: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HardTokenBudgetStatus {
    pub campaign_id: String,
    pub ceiling_tokens: u64,
    pub settled_tokens: u64,
    pub outstanding_tokens: u64,
    pub remaining_tokens: u64,
    pub violated: bool,
    pub next_sequence: u64,
}

#[derive(Debug)]
pub struct BudgetReservation {
    budget: HardTokenBudget,
    id: String,
    pub sequence: u64,
    pub reserved_tokens: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LedgerState {
    version: u32,
    campaign_id: String,
    ceiling_tokens: u64,
    next_sequence: u64,
    settled_tokens: u64,
    #[serde(default)]
    violated: bool,
    #[serde(default)]
    reservations: Vec<ReservationRecord>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReservationRecord {
    id: String,
    sequence: u64,
    request_id: String,
    model: String,
    reserved_tokens: u64,
    actual_tokens: Option<u64>,
}

impl HardTokenBudget {
    /// Resolve the all-or-nothing process contract. Ordinary CLI use sees no
    /// budget when all three variables are absent; a partial contract fails.
    pub fn from_env() -> Result<Option<Self>, HardTokenBudgetError> {
        let ledger = std::env::var_os(ENV_LEDGER);
        let campaign = std::env::var(ENV_CAMPAIGN).ok();
        let ceiling = std::env::var(ENV_CEILING).ok();
        match (ledger, campaign, ceiling) {
            (None, None, None) => Ok(None),
            (Some(path), Some(campaign_id), Some(raw_ceiling)) => {
                let ceiling_tokens = raw_ceiling
                    .parse::<u64>()
                    .map_err(|_| HardTokenBudgetError::InvalidCeiling)?;
                Self::open(PathBuf::from(path), campaign_id, ceiling_tokens).map(Some)
            }
            _ => Err(HardTokenBudgetError::IncompleteEnvironment),
        }
    }

    pub fn open(
        ledger_path: PathBuf,
        campaign_id: String,
        ceiling_tokens: u64,
    ) -> Result<Self, HardTokenBudgetError> {
        if !ledger_path.is_absolute() {
            return Err(HardTokenBudgetError::RelativeLedgerPath);
        }
        if campaign_id.is_empty()
            || campaign_id.len() > 128
            || !campaign_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
        {
            return Err(HardTokenBudgetError::InvalidCampaign);
        }
        if ceiling_tokens == 0 {
            return Err(HardTokenBudgetError::InvalidCeiling);
        }
        let parent = ledger_path
            .parent()
            .ok_or(HardTokenBudgetError::UnsafeParent)?;
        validate_private_directory(parent)?;
        let file_name = ledger_path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(HardTokenBudgetError::UnsafeArtifact)?;
        let lock_path = parent.join(format!(".{file_name}.lock"));
        let budget = Self {
            inner: Arc::new(HardTokenBudgetInner {
                ledger_path,
                lock_path,
                campaign_id,
                ceiling_tokens,
            }),
        };
        budget.with_locked_state(|_| Ok(()))?;
        Ok(budget)
    }

    pub fn reserve(
        &self,
        reserved_tokens: u64,
        request_id: &str,
        model: &str,
    ) -> Result<BudgetReservation, HardTokenBudgetError> {
        if reserved_tokens == 0 {
            return Err(HardTokenBudgetError::InvalidCeiling);
        }
        let reservation_id = Uuid::new_v4().to_string();
        let mut sequence = 0;
        self.with_locked_state(|state| {
            if state.violated {
                return Err(HardTokenBudgetError::Violated);
            }
            let outstanding = outstanding_tokens(state)?;
            let charged = state
                .settled_tokens
                .checked_add(outstanding)
                .ok_or(HardTokenBudgetError::Overflow)?;
            let projected = charged
                .checked_add(reserved_tokens)
                .ok_or(HardTokenBudgetError::Overflow)?;
            if projected > state.ceiling_tokens {
                return Err(HardTokenBudgetError::Exhausted);
            }
            sequence = state.next_sequence;
            state.next_sequence = state
                .next_sequence
                .checked_add(1)
                .ok_or(HardTokenBudgetError::Overflow)?;
            state.reservations.push(ReservationRecord {
                id: reservation_id.clone(),
                sequence,
                request_id: request_id.to_string(),
                model: model.to_string(),
                reserved_tokens,
                actual_tokens: None,
            });
            Ok(())
        })?;
        Ok(BudgetReservation {
            budget: self.clone(),
            id: reservation_id,
            sequence,
            reserved_tokens,
        })
    }

    pub fn status(&self) -> Result<HardTokenBudgetStatus, HardTokenBudgetError> {
        let mut result = None;
        self.with_locked_state(|state| {
            let outstanding_tokens = outstanding_tokens(state)?;
            let charged = state
                .settled_tokens
                .checked_add(outstanding_tokens)
                .ok_or(HardTokenBudgetError::Overflow)?;
            result = Some(HardTokenBudgetStatus {
                campaign_id: state.campaign_id.clone(),
                ceiling_tokens: state.ceiling_tokens,
                settled_tokens: state.settled_tokens,
                outstanding_tokens,
                remaining_tokens: state.ceiling_tokens.saturating_sub(charged),
                violated: state.violated,
                next_sequence: state.next_sequence,
            });
            Ok(())
        })?;
        result.ok_or(HardTokenBudgetError::Malformed(serde_json::Error::io(
            std::io::Error::other("missing status"),
        )))
    }

    fn settle(&self, id: &str, actual_tokens: u64) -> Result<(), HardTokenBudgetError> {
        self.with_locked_state(|state| {
            let record = state
                .reservations
                .iter_mut()
                .find(|record| record.id == id)
                .ok_or(HardTokenBudgetError::ReservationMissing)?;
            if record.actual_tokens.is_some() {
                return Err(HardTokenBudgetError::AlreadySettled);
            }
            record.actual_tokens = Some(actual_tokens);
            if actual_tokens > record.reserved_tokens {
                state.violated = true;
            }
            state.settled_tokens = state
                .settled_tokens
                .checked_add(actual_tokens)
                .ok_or(HardTokenBudgetError::Overflow)?;
            Ok(())
        })
    }

    fn with_locked_state<T>(
        &self,
        operation: impl FnOnce(&mut LedgerState) -> Result<T, HardTokenBudgetError>,
    ) -> Result<T, HardTokenBudgetError> {
        let lock = open_private_file(&self.inner.lock_path, true)?;
        lock.lock_exclusive()?;
        let mut state = self.read_or_initialize_state()?;
        let result = operation(&mut state)?;
        self.persist_state(&state)?;
        FileExt::unlock(&lock)?;
        Ok(result)
    }

    fn read_or_initialize_state(&self) -> Result<LedgerState, HardTokenBudgetError> {
        match open_private_file(&self.inner.ledger_path, false) {
            Ok(mut file) => {
                let mut bytes = Vec::new();
                file.read_to_end(&mut bytes)?;
                let state: LedgerState = serde_json::from_slice(&bytes)?;
                if state.version != LEDGER_VERSION
                    || state.campaign_id != self.inner.campaign_id
                    || state.ceiling_tokens != self.inner.ceiling_tokens
                {
                    return Err(HardTokenBudgetError::IdentityMismatch);
                }
                Ok(state)
            }
            Err(HardTokenBudgetError::Io(error))
                if error.kind() == std::io::ErrorKind::NotFound =>
            {
                Ok(LedgerState {
                    version: LEDGER_VERSION,
                    campaign_id: self.inner.campaign_id.clone(),
                    ceiling_tokens: self.inner.ceiling_tokens,
                    next_sequence: 1,
                    settled_tokens: 0,
                    violated: false,
                    reservations: Vec::new(),
                })
            }
            Err(error) => Err(error),
        }
    }

    fn persist_state(&self, state: &LedgerState) -> Result<(), HardTokenBudgetError> {
        let parent = self
            .inner
            .ledger_path
            .parent()
            .ok_or(HardTokenBudgetError::UnsafeParent)?;
        let temp_path = parent.join(format!(".hard-budget-{}.tmp", Uuid::new_v4()));
        let bytes = serde_json::to_vec(state)?;
        let mut temp = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&temp_path)?;
        let write_result = (|| -> Result<(), HardTokenBudgetError> {
            temp.write_all(&bytes)?;
            temp.write_all(b"\n")?;
            temp.sync_all()?;
            fs::rename(&temp_path, &self.inner.ledger_path)?;
            File::open(parent)?.sync_all()?;
            Ok(())
        })();
        if write_result.is_err() {
            let _ = fs::remove_file(&temp_path);
        }
        write_result
    }
}

impl BudgetReservation {
    /// Release only the provably unused remainder. If this is never called the
    /// durable ledger keeps the complete reservation charged.
    pub fn settle(self, actual_tokens: u64) -> Result<(), HardTokenBudgetError> {
        self.budget.settle(&self.id, actual_tokens)
    }
}

fn outstanding_tokens(state: &LedgerState) -> Result<u64, HardTokenBudgetError> {
    state
        .reservations
        .iter()
        .filter(|record| record.actual_tokens.is_none())
        .try_fold(0_u64, |sum, record| {
            sum.checked_add(record.reserved_tokens)
                .ok_or(HardTokenBudgetError::Overflow)
        })
}

fn validate_private_directory(path: &Path) -> Result<(), HardTokenBudgetError> {
    let metadata = fs::symlink_metadata(path).map_err(HardTokenBudgetError::Io)?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
    {
        return Err(HardTokenBudgetError::UnsafeParent);
    }
    Ok(())
}

fn open_private_file(path: &Path, create: bool) -> Result<File, HardTokenBudgetError> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create(create)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let mut file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
    {
        return Err(HardTokenBudgetError::UnsafeArtifact);
    }
    file.seek(SeekFrom::Start(0))?;
    Ok(file)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::sync::{Arc, Barrier};

    use super::*;

    fn private_dir(label: &str) -> PathBuf {
        let path =
            std::env::temp_dir().join(format!("grok-hard-budget-{label}-{}", Uuid::new_v4()));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

    #[test]
    fn concurrent_reservations_cannot_oversubscribe() {
        let dir = private_dir("race");
        let ledger = dir.join("ledger.json");
        let budget = Arc::new(HardTokenBudget::open(ledger, "race".into(), 1_000).unwrap());
        let barrier = Arc::new(Barrier::new(3));
        let mut joins = Vec::new();
        for index in 0..2 {
            let budget = Arc::clone(&budget);
            let barrier = Arc::clone(&barrier);
            joins.push(std::thread::spawn(move || {
                barrier.wait();
                budget.reserve(600, &format!("req-{index}"), "model")
            }));
        }
        barrier.wait();
        let results: Vec<_> = joins.into_iter().map(|join| join.join().unwrap()).collect();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Err(HardTokenBudgetError::Exhausted)))
                .count(),
            1
        );
        let status = budget.status().unwrap();
        assert_eq!(status.outstanding_tokens, 600);
        assert_eq!(status.remaining_tokens, 400);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn dropped_reservation_stays_charged_across_reopen() {
        let dir = private_dir("crash");
        let ledger = dir.join("ledger.json");
        {
            let budget = HardTokenBudget::open(ledger.clone(), "crash".into(), 1_000).unwrap();
            let _ambiguous = budget.reserve(750, "req", "model").unwrap();
        }
        let reopened = HardTokenBudget::open(ledger, "crash".into(), 1_000).unwrap();
        assert!(matches!(
            reopened.reserve(251, "next", "model"),
            Err(HardTokenBudgetError::Exhausted)
        ));
        assert_eq!(reopened.status().unwrap().outstanding_tokens, 750);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn complete_usage_releases_only_the_proven_remainder() {
        let dir = private_dir("settle");
        let ledger = dir.join("ledger.json");
        let budget = HardTokenBudget::open(ledger, "settle".into(), 1_000).unwrap();
        budget
            .reserve(800, "req", "model")
            .unwrap()
            .settle(125)
            .unwrap();
        let status = budget.status().unwrap();
        assert_eq!(status.settled_tokens, 125);
        assert_eq!(status.outstanding_tokens, 0);
        assert_eq!(status.remaining_tokens, 875);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn usage_above_reservation_marks_ledger_violated() {
        let dir = private_dir("violation");
        let ledger = dir.join("ledger.json");
        let budget = HardTokenBudget::open(ledger, "violation".into(), 1_000).unwrap();
        budget
            .reserve(100, "req", "model")
            .unwrap()
            .settle(101)
            .unwrap();
        assert!(budget.status().unwrap().violated);
        assert!(matches!(
            budget.reserve(1, "next", "model"),
            Err(HardTokenBudgetError::Violated)
        ));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn symlink_ledger_is_refused() {
        let dir = private_dir("symlink");
        let target = dir.join("target.json");
        fs::write(&target, b"protected").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        let ledger = dir.join("ledger.json");
        symlink(&target, &ledger).unwrap();
        assert!(HardTokenBudget::open(ledger, "symlink".into(), 1_000).is_err());
        assert_eq!(fs::read(&target).unwrap(), b"protected");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn group_readable_parent_is_refused() {
        let dir = private_dir("mode");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o750)).unwrap();
        assert!(matches!(
            HardTokenBudget::open(dir.join("ledger.json"), "mode".into(), 1_000),
            Err(HardTokenBudgetError::UnsafeParent)
        ));
        fs::remove_dir_all(dir).unwrap();
    }
}
