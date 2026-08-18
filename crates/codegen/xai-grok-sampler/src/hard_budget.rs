//! Durable, process-shared admission control for opt-in hard token budgets.
//!
//! The budget is deliberately below the shell/session layer: every sampling
//! client, including auxiliary and child-agent clients, must reserve before an
//! HTTP dispatch. Complete provider usage is retained as reconciliation
//! evidence, but an untrusted endpoint cannot refund the conservative charge.
//! Dropped streams, cancellation, crashes, and ambiguous transport failures
//! likewise consume the full reservation instead of refunding money the
//! runtime cannot prove was unspent.

use std::fs::File;
#[cfg(unix)]
use std::fs::{self, OpenOptions};
use std::io::Read;
#[cfg(unix)]
use std::io::{Seek, SeekFrom, Write};
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

const LEDGER_VERSION: u32 = 4;
const MANIFEST_VERSION: u32 = 1;
const ENV_LEDGER: &str = "GROK_HARD_TOKEN_BUDGET_LEDGER";
const ENV_MANIFEST: &str = "GROK_HARD_TOKEN_BUDGET_MANIFEST";
const ENV_ALLOCATION: &str = "GROK_HARD_TOKEN_BUDGET_ALLOCATION";

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
    #[error("hard-token-budget manifest is invalid")]
    InvalidManifest,
    #[error("hard-token-budget allocation is unavailable")]
    AllocationUnavailable,
    #[error("hard-token-budget allocation call ceiling is exhausted")]
    CallCeilingExhausted,
    #[error("hard-token-budget provider request identity is invalid")]
    InvalidRequestIdentity,
    #[error("hard-token-budget route contract is invalid")]
    InvalidRouteContract,
    #[error("hard-token-budget route does not match the frozen contract")]
    RouteMismatch,
    #[error("hard-token-budget route contract is required for provider dispatch")]
    RouteContractRequired,
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
    #[error("hard-token-budget receipt query does not match this immutable contract")]
    ReceiptContractMismatch,
    #[error("hard-token-budget receipt baseline is invalid for the current ledger")]
    ReceiptBaselineInvalid,
    #[error("hard-token-budget arithmetic overflow")]
    Overflow,
    #[error("hard-token-budget enforcement is unsupported on this platform")]
    UnsupportedPlatform,
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
    manifest_sha256: String,
    allocation: Option<HardTokenAllocationContract>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HardTokenRouteContract {
    pub model: String,
    pub endpoint_sha256: String,
    pub api_backend: String,
    pub request_bound_tokens: u64,
    pub max_payload_bytes: u64,
    pub max_output_tokens: u64,
    pub bound_provenance_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HardTokenAllocationContract {
    pub id: String,
    pub packet_id: String,
    pub prompt_sha256: String,
    pub token_ceiling: u64,
    pub max_model_calls: u64,
    pub route: HardTokenRouteContract,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct HardTokenCampaignManifest {
    version: u32,
    campaign_id: String,
    ceiling_tokens: u64,
    allocations: Vec<HardTokenAllocationContract>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HardTokenBudgetStatus {
    pub campaign_id: String,
    pub ceiling_tokens: u64,
    pub settled_tokens: u64,
    pub outstanding_tokens: u64,
    pub remaining_tokens: u64,
    pub violated: bool,
    /// Durable observation revision paired with `next_sequence` for receipt
    /// cursors. Both values are read while the shared ledger lock is held.
    pub ledger_revision: u64,
    pub next_sequence: u64,
    pub manifest_sha256: String,
    pub allocation_id: Option<String>,
    pub allocation_remaining_tokens: Option<u64>,
    pub allocation_remaining_calls: Option<u64>,
}

/// A caller-supplied cursor is accepted only for the immutable contract this
/// process has already loaded. It is an observation cursor, never a file or
/// campaign selector.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct HardTokenReceiptQuery {
    pub campaign_id: String,
    pub manifest_sha256: String,
    pub allocation_id: String,
    pub packet_id: String,
    pub baseline_sequence: u64,
    pub baseline_revision: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HardTokenReservationReceipt {
    pub reservation_id: String,
    pub sequence: u64,
    pub provider_request_id: String,
    pub model: String,
    pub endpoint_sha256: String,
    pub api_backend: String,
    pub payload_bytes: u64,
    pub max_output_tokens: u64,
    pub reserved_tokens: u64,
    /// Provider usage is deliberately absent until a complete terminal usage
    /// packet has been observed. A missing value is charged conservatively.
    pub actual_tokens: Option<u64>,
    pub charged_tokens: u64,
    pub terminal_state: HardTokenReceiptTerminalState,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HardTokenReceiptTerminalState {
    /// The provider dispatch still owns this reservation. It remains fully
    /// charged for admission purposes, but is not a terminal outcome.
    Reserved,
    SettledUsageReported,
    AmbiguousFullReservationCharged,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HardTokenReceiptSnapshot {
    pub campaign_id: String,
    pub manifest_sha256: String,
    pub allocation_id: String,
    pub packet_id: String,
    pub ledger_revision: u64,
    pub next_sequence: u64,
    pub receipts: Vec<HardTokenReservationReceipt>,
}

#[derive(Debug)]
pub struct BudgetReservation {
    budget: HardTokenBudget,
    id: String,
    pub sequence: u64,
    pub reserved_tokens: u64,
    active: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LedgerState {
    version: u32,
    campaign_id: String,
    ceiling_tokens: u64,
    manifest_sha256: String,
    next_sequence: u64,
    #[serde(default)]
    revision: u64,
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
    #[serde(default)]
    last_updated_revision: u64,
    request_id: String,
    allocation_id: Option<String>,
    packet_id: Option<String>,
    model: String,
    endpoint_sha256: Option<String>,
    api_backend: Option<String>,
    payload_bytes: Option<u64>,
    max_output_tokens: Option<u64>,
    reserved_tokens: u64,
    actual_tokens: Option<u64>,
    /// Older ledgers predate lifecycle evidence. Their in-flight/terminal
    /// distinction is unknowable after restart, so serde defaults them to the
    /// conservative terminal state rather than claiming a live dispatch.
    #[serde(default)]
    lifecycle: ReservationLifecycle,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ReservationLifecycle {
    Reserved,
    SettledUsageReported,
    TerminalAmbiguous,
}

impl Default for ReservationLifecycle {
    fn default() -> Self {
        Self::TerminalAmbiguous
    }
}

impl HardTokenReservationReceipt {
    fn from_record(record: &ReservationRecord) -> Self {
        let (charged_tokens, terminal_state) = match record.lifecycle {
            ReservationLifecycle::Reserved => (
                record.reserved_tokens,
                HardTokenReceiptTerminalState::Reserved,
            ),
            ReservationLifecycle::SettledUsageReported => (
                record
                    .actual_tokens
                    .unwrap_or(record.reserved_tokens)
                    .max(record.reserved_tokens),
                HardTokenReceiptTerminalState::SettledUsageReported,
            ),
            ReservationLifecycle::TerminalAmbiguous => (
                record.reserved_tokens,
                HardTokenReceiptTerminalState::AmbiguousFullReservationCharged,
            ),
        };
        // Records without these fields originate only from the non-contract
        // test helper. They can never be projected because `receipts` requires
        // a loaded allocation, so defaults here cannot turn an unknown route
        // into a claim about a governed provider dispatch.
        Self {
            reservation_id: record.id.clone(),
            sequence: record.sequence,
            provider_request_id: record.request_id.clone(),
            model: record.model.clone(),
            endpoint_sha256: record.endpoint_sha256.clone().unwrap_or_default(),
            api_backend: record.api_backend.clone().unwrap_or_default(),
            payload_bytes: record.payload_bytes.unwrap_or_default(),
            max_output_tokens: record.max_output_tokens.unwrap_or_default(),
            reserved_tokens: record.reserved_tokens,
            actual_tokens: record.actual_tokens,
            charged_tokens,
            terminal_state,
        }
    }
}

impl HardTokenBudget {
    /// Resolve the all-or-nothing process contract. Ordinary CLI use sees no
    /// budget when all three variables are absent; a partial contract fails.
    pub fn from_env() -> Result<Option<Self>, HardTokenBudgetError> {
        let values = (
            std::env::var_os(ENV_LEDGER),
            std::env::var_os(ENV_MANIFEST),
            std::env::var(ENV_ALLOCATION).ok(),
        );
        match values {
            (None, None, None) => Ok(None),
            (Some(ledger), Some(manifest), Some(allocation_id)) => Self::open_with_manifest(
                PathBuf::from(ledger),
                PathBuf::from(manifest),
                &allocation_id,
            )
            .map(Some),
            _ => Err(HardTokenBudgetError::IncompleteEnvironment),
        }
    }

    pub fn open_with_manifest(
        ledger_path: PathBuf,
        manifest_path: PathBuf,
        allocation_id: &str,
    ) -> Result<Self, HardTokenBudgetError> {
        let (manifest, manifest_sha256) = load_manifest(&manifest_path)?;
        let allocation = manifest
            .allocations
            .iter()
            .find(|allocation| allocation.id == allocation_id)
            .cloned()
            .ok_or(HardTokenBudgetError::AllocationUnavailable)?;
        Self::open_inner(
            ledger_path,
            manifest.campaign_id,
            manifest.ceiling_tokens,
            manifest_sha256,
            Some(allocation),
        )
    }

    #[cfg(test)]
    pub(crate) fn open_for_test(
        ledger_path: PathBuf,
        campaign_id: String,
        ceiling_tokens: u64,
    ) -> Result<Self, HardTokenBudgetError> {
        Self::open_inner(
            ledger_path,
            campaign_id,
            ceiling_tokens,
            "0".repeat(64),
            None,
        )
    }

    #[cfg(test)]
    pub(crate) fn open_with_allocation_for_test(
        ledger_path: PathBuf,
        campaign_id: String,
        ceiling_tokens: u64,
        manifest_sha256: String,
        allocation: HardTokenAllocationContract,
    ) -> Result<Self, HardTokenBudgetError> {
        validate_allocation(&allocation)?;
        Self::open_inner(
            ledger_path,
            campaign_id,
            ceiling_tokens,
            manifest_sha256,
            Some(allocation),
        )
    }

    fn open_inner(
        ledger_path: PathBuf,
        campaign_id: String,
        ceiling_tokens: u64,
        manifest_sha256: String,
        allocation: Option<HardTokenAllocationContract>,
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
        validate_sha256(&manifest_sha256).map_err(|_| HardTokenBudgetError::InvalidManifest)?;
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
                manifest_sha256,
                allocation,
            }),
        };
        // Opening validates the authority-owned ledger without materializing a
        // pristine empty `O_EXCL` file. The first reservation is the first
        // mutation that writes canonical ledger JSON.
        budget.with_locked_read_state(|_| Ok(()))?;
        Ok(budget)
    }

    pub fn route_contract(&self) -> Option<&HardTokenRouteContract> {
        self.inner
            .allocation
            .as_ref()
            .map(|allocation| &allocation.route)
    }

    /// Immutable packet/allocation authority loaded from the private campaign
    /// manifest. This contains no credential or raw prompt; the prompt is bound
    /// by its SHA-256 digest so an ACP client can verify that it is presenting
    /// the exact authorized packet rather than merely a route with spare budget.
    pub fn allocation_contract(&self) -> Option<&HardTokenAllocationContract> {
        self.inner.allocation.as_ref()
    }

    /// Admit one provider dispatch only when its exact live route matches the
    /// immutable process contract. The reservation size comes from the frozen
    /// independent bound, never from informational model metadata.
    pub fn reserve_authorized_request(
        &self,
        request_id: &str,
        model: &str,
        endpoint_sha256: &str,
        api_backend: &str,
        payload_bytes: u64,
        max_output_tokens: u64,
    ) -> Result<BudgetReservation, HardTokenBudgetError> {
        let allocation = self
            .inner
            .allocation
            .as_ref()
            .ok_or(HardTokenBudgetError::RouteContractRequired)?;
        let contract = &allocation.route;
        if model != contract.model
            || endpoint_sha256 != contract.endpoint_sha256
            || api_backend != contract.api_backend
            || payload_bytes > contract.max_payload_bytes
            || max_output_tokens > contract.max_output_tokens
        {
            return Err(HardTokenBudgetError::RouteMismatch);
        }
        self.reserve_inner(
            contract.request_bound_tokens,
            request_id,
            model,
            Some(allocation),
            Some(endpoint_sha256),
            Some(api_backend),
            Some(payload_bytes),
            Some(max_output_tokens),
        )
    }

    #[cfg(test)]
    pub fn reserve(
        &self,
        reserved_tokens: u64,
        request_id: &str,
        model: &str,
    ) -> Result<BudgetReservation, HardTokenBudgetError> {
        self.reserve_inner(
            reserved_tokens,
            request_id,
            model,
            None,
            None,
            None,
            None,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn reserve_inner(
        &self,
        reserved_tokens: u64,
        request_id: &str,
        model: &str,
        allocation: Option<&HardTokenAllocationContract>,
        endpoint_sha256: Option<&str>,
        api_backend: Option<&str>,
        payload_bytes: Option<u64>,
        max_output_tokens: Option<u64>,
    ) -> Result<BudgetReservation, HardTokenBudgetError> {
        if reserved_tokens == 0 {
            return Err(HardTokenBudgetError::InvalidCeiling);
        }
        if request_id.is_empty() || request_id.len() > 256 {
            return Err(HardTokenBudgetError::InvalidRequestIdentity);
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
            if let Some(allocation) = allocation {
                let (allocation_charged, allocation_calls) =
                    allocation_charged(state, &allocation.id)?;
                if allocation_calls >= allocation.max_model_calls {
                    return Err(HardTokenBudgetError::CallCeilingExhausted);
                }
                if allocation_charged
                    .checked_add(reserved_tokens)
                    .ok_or(HardTokenBudgetError::Overflow)?
                    > allocation.token_ceiling
                {
                    return Err(HardTokenBudgetError::Exhausted);
                }
            }
            sequence = state.next_sequence;
            state.next_sequence = state
                .next_sequence
                .checked_add(1)
                .ok_or(HardTokenBudgetError::Overflow)?;
            state.revision = state
                .revision
                .checked_add(1)
                .ok_or(HardTokenBudgetError::Overflow)?;
            state.reservations.push(ReservationRecord {
                id: reservation_id.clone(),
                sequence,
                last_updated_revision: state.revision,
                request_id: request_id.to_string(),
                allocation_id: allocation.map(|value| value.id.clone()),
                packet_id: allocation.map(|value| value.packet_id.clone()),
                model: model.to_string(),
                endpoint_sha256: endpoint_sha256.map(str::to_owned),
                api_backend: api_backend.map(str::to_owned),
                payload_bytes,
                max_output_tokens,
                reserved_tokens,
                actual_tokens: None,
                lifecycle: ReservationLifecycle::Reserved,
            });
            Ok(())
        })?;
        Ok(BudgetReservation {
            budget: self.clone(),
            id: reservation_id,
            sequence,
            reserved_tokens,
            active: true,
        })
    }

    pub fn status(&self) -> Result<HardTokenBudgetStatus, HardTokenBudgetError> {
        let mut result = None;
        self.with_locked_read_state(|state| {
            let outstanding_tokens = outstanding_tokens(state)?;
            let charged = state
                .settled_tokens
                .checked_add(outstanding_tokens)
                .ok_or(HardTokenBudgetError::Overflow)?;
            let allocation_status = self
                .inner
                .allocation
                .as_ref()
                .map(|allocation| {
                    allocation_charged(state, &allocation.id).map(
                        |(allocation_charged, allocation_calls)| {
                            (
                                allocation.token_ceiling.saturating_sub(allocation_charged),
                                allocation.max_model_calls.saturating_sub(allocation_calls),
                            )
                        },
                    )
                })
                .transpose()?;
            result = Some(HardTokenBudgetStatus {
                campaign_id: state.campaign_id.clone(),
                ceiling_tokens: state.ceiling_tokens,
                settled_tokens: state.settled_tokens,
                outstanding_tokens,
                remaining_tokens: state.ceiling_tokens.saturating_sub(charged),
                violated: state.violated,
                ledger_revision: state.revision,
                next_sequence: state.next_sequence,
                manifest_sha256: state.manifest_sha256.clone(),
                allocation_id: self
                    .inner
                    .allocation
                    .as_ref()
                    .map(|allocation| allocation.id.clone()),
                allocation_remaining_tokens: allocation_status.map(|value| value.0),
                allocation_remaining_calls: allocation_status.map(|value| value.1),
            });
            Ok(())
        })?;
        result.ok_or(HardTokenBudgetError::Malformed(serde_json::Error::io(
            std::io::Error::other("missing status"),
        )))
    }

    /// Project durable reservation evidence for only this process's loaded
    /// campaign manifest and packet allocation. This never accepts a path,
    /// exposes prompt text, or exposes credential material.
    pub fn receipts(
        &self,
        query: &HardTokenReceiptQuery,
    ) -> Result<HardTokenReceiptSnapshot, HardTokenBudgetError> {
        let allocation = self
            .inner
            .allocation
            .as_ref()
            .ok_or(HardTokenBudgetError::RouteContractRequired)?;
        if query.campaign_id != self.inner.campaign_id
            || query.manifest_sha256 != self.inner.manifest_sha256
            || query.allocation_id != allocation.id
            || query.packet_id != allocation.packet_id
        {
            return Err(HardTokenBudgetError::ReceiptContractMismatch);
        }
        let mut result = None;
        self.with_locked_read_state(|state| {
            // `next_sequence` is the snapshot's exclusive high-water cursor:
            // a later reservation is assigned exactly this value. Accepting it
            // makes a snapshot directly reusable, while `>=` below ensures
            // that later reservation is not skipped.
            if query.baseline_sequence > state.next_sequence
                || query.baseline_revision > state.revision
            {
                return Err(HardTokenBudgetError::ReceiptBaselineInvalid);
            }
            let receipts = state
                .reservations
                .iter()
                .filter(|record| {
                    record.allocation_id.as_deref() == Some(allocation.id.as_str())
                        && record.packet_id.as_deref() == Some(allocation.packet_id.as_str())
                        && (record.sequence >= query.baseline_sequence
                            || record.last_updated_revision > query.baseline_revision)
                })
                .map(HardTokenReservationReceipt::from_record)
                .collect();
            result = Some(HardTokenReceiptSnapshot {
                campaign_id: state.campaign_id.clone(),
                manifest_sha256: state.manifest_sha256.clone(),
                allocation_id: allocation.id.clone(),
                packet_id: allocation.packet_id.clone(),
                ledger_revision: state.revision,
                next_sequence: state.next_sequence,
                receipts,
            });
            Ok(())
        })?;
        result.ok_or(HardTokenBudgetError::Malformed(serde_json::Error::io(
            std::io::Error::other("missing receipts"),
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
            record.lifecycle = ReservationLifecycle::SettledUsageReported;
            state.revision = state
                .revision
                .checked_add(1)
                .ok_or(HardTokenBudgetError::Overflow)?;
            record.last_updated_revision = state.revision;
            if actual_tokens > record.reserved_tokens {
                state.violated = true;
            }
            // Provider usage is valuable reconciliation evidence, but it is
            // not an authenticated lower bound. Never let a remote endpoint
            // refund the conservative reservation by under-reporting usage.
            // An over-report remains fail-closed and is charged as observed.
            let charged_tokens = actual_tokens.max(record.reserved_tokens);
            state.settled_tokens = state
                .settled_tokens
                .checked_add(charged_tokens)
                .ok_or(HardTokenBudgetError::Overflow)?;
            Ok(())
        })
    }

    /// Once a reservation-owning stream/request disappears without a complete
    /// provider usage packet, durably record that terminal ambiguity. The
    /// accounting was already fail-closed at the full reservation; this only
    /// makes its lifecycle truthful to receipt consumers.
    fn mark_ambiguous(&self, id: &str) -> Result<(), HardTokenBudgetError> {
        self.with_locked_state(|state| {
            let record = state
                .reservations
                .iter_mut()
                .find(|record| record.id == id)
                .ok_or(HardTokenBudgetError::ReservationMissing)?;
            if record.actual_tokens.is_some()
                || record.lifecycle == ReservationLifecycle::TerminalAmbiguous
            {
                return Ok(());
            }
            record.lifecycle = ReservationLifecycle::TerminalAmbiguous;
            state.revision = state
                .revision
                .checked_add(1)
                .ok_or(HardTokenBudgetError::Overflow)?;
            record.last_updated_revision = state.revision;
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

    /// Execute an observational ledger read under the same cross-process lock
    /// as mutation, but never rewrite the ledger as a side effect of asking
    /// for receipts.
    fn with_locked_read_state<T>(
        &self,
        operation: impl FnOnce(&LedgerState) -> Result<T, HardTokenBudgetError>,
    ) -> Result<T, HardTokenBudgetError> {
        let lock = open_private_file(&self.inner.lock_path, true)?;
        lock.lock_exclusive()?;
        let state = self.read_or_initialize_state()?;
        let result = operation(&state);
        FileExt::unlock(&lock)?;
        result
    }

    fn read_or_initialize_state(&self) -> Result<LedgerState, HardTokenBudgetError> {
        match open_private_file(&self.inner.ledger_path, false) {
            Ok(mut file) => {
                let mut bytes = Vec::new();
                file.read_to_end(&mut bytes)?;
                // The authority may pre-create the private ledger with
                // `O_EXCL` before the CLI has a mutation to persist. Only an
                // exactly empty regular private file is a pristine ledger;
                // whitespace and every non-empty malformed payload remain
                // rejected by serde below.
                if bytes.is_empty() {
                    return Ok(self.pristine_state());
                }
                let state: LedgerState = serde_json::from_slice(&bytes)?;
                if state.version != LEDGER_VERSION
                    || state.campaign_id != self.inner.campaign_id
                    || state.ceiling_tokens != self.inner.ceiling_tokens
                    || state.manifest_sha256 != self.inner.manifest_sha256
                {
                    return Err(HardTokenBudgetError::IdentityMismatch);
                }
                Ok(state)
            }
            Err(HardTokenBudgetError::Io(error))
                if error.kind() == std::io::ErrorKind::NotFound =>
            {
                Ok(self.pristine_state())
            }
            Err(error) => Err(error),
        }
    }

    fn pristine_state(&self) -> LedgerState {
        LedgerState {
            version: LEDGER_VERSION,
            campaign_id: self.inner.campaign_id.clone(),
            ceiling_tokens: self.inner.ceiling_tokens,
            manifest_sha256: self.inner.manifest_sha256.clone(),
            next_sequence: 1,
            revision: 0,
            settled_tokens: 0,
            violated: false,
            reservations: Vec::new(),
        }
    }

    #[cfg(unix)]
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

    #[cfg(not(unix))]
    fn persist_state(&self, _state: &LedgerState) -> Result<(), HardTokenBudgetError> {
        Err(HardTokenBudgetError::UnsupportedPlatform)
    }
}

impl BudgetReservation {
    /// Persist provider-reported usage without allowing an untrusted endpoint
    /// to refund any part of the conservative reservation. If this is never
    /// called the durable ledger keeps the complete reservation charged and
    /// records an ambiguous terminal lifecycle on drop.
    pub fn settle(mut self, actual_tokens: u64) -> Result<(), HardTokenBudgetError> {
        self.budget.settle(&self.id, actual_tokens)?;
        self.active = false;
        Ok(())
    }
}

impl Drop for BudgetReservation {
    fn drop(&mut self) {
        if self.active {
            // Drop cannot surface an I/O error. Leaving the reservation in its
            // durable `reserved` state still charges it in full, so a failed
            // lifecycle transition cannot weaken crash accounting.
            let _ = self.budget.mark_ambiguous(&self.id);
        }
    }
}

fn validate_route_contract(contract: &HardTokenRouteContract) -> Result<(), HardTokenBudgetError> {
    let conservative_bound = contract
        .max_payload_bytes
        .checked_add(contract.max_output_tokens)
        .ok_or(HardTokenBudgetError::InvalidRouteContract)?;
    if contract.model.is_empty()
        || contract.model.len() > 256
        || contract.request_bound_tokens == 0
        || contract.max_payload_bytes == 0
        || contract.max_output_tokens == 0
        // One serialized UTF-8 byte is charged as at most one input token by
        // this conservative bound. The output cap is additive and sent in the
        // exact provider payload. A manifest may reserve more, never less.
        || conservative_bound > contract.request_bound_tokens
        || contract.endpoint_sha256.len() != 64
        || validate_sha256(&contract.endpoint_sha256).is_err()
        || validate_sha256(&contract.bound_provenance_sha256).is_err()
        || !matches!(
            contract.api_backend.as_str(),
            "chat_completions" | "responses" | "messages"
        )
    {
        return Err(HardTokenBudgetError::InvalidRouteContract);
    }
    Ok(())
}

fn validate_allocation(
    allocation: &HardTokenAllocationContract,
) -> Result<(), HardTokenBudgetError> {
    validate_identifier(&allocation.id).map_err(|_| HardTokenBudgetError::InvalidManifest)?;
    validate_identifier(&allocation.packet_id)
        .map_err(|_| HardTokenBudgetError::InvalidManifest)?;
    validate_sha256(&allocation.prompt_sha256)
        .map_err(|_| HardTokenBudgetError::InvalidManifest)?;
    validate_route_contract(&allocation.route)?;
    if allocation.token_ceiling == 0
        || allocation.max_model_calls == 0
        || allocation.route.request_bound_tokens > allocation.token_ceiling
    {
        return Err(HardTokenBudgetError::InvalidManifest);
    }
    Ok(())
}

fn load_manifest(path: &Path) -> Result<(HardTokenCampaignManifest, String), HardTokenBudgetError> {
    if !path.is_absolute() {
        return Err(HardTokenBudgetError::RelativeLedgerPath);
    }
    let parent = path.parent().ok_or(HardTokenBudgetError::UnsafeParent)?;
    validate_private_directory(parent)?;
    let mut file = open_private_file(path, false)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    let manifest_sha256 = sha256_bytes(&bytes);
    let manifest: HardTokenCampaignManifest = serde_json::from_slice(&bytes)?;
    if manifest.version != MANIFEST_VERSION
        || validate_identifier(&manifest.campaign_id).is_err()
        || manifest.ceiling_tokens == 0
        || manifest.allocations.is_empty()
    {
        return Err(HardTokenBudgetError::InvalidManifest);
    }
    let mut ids = std::collections::HashSet::new();
    let mut packet_ids = std::collections::HashSet::new();
    let mut allocated = 0_u64;
    for allocation in &manifest.allocations {
        validate_allocation(allocation)?;
        if !ids.insert(allocation.id.as_str()) || !packet_ids.insert(allocation.packet_id.as_str())
        {
            return Err(HardTokenBudgetError::InvalidManifest);
        }
        allocated = allocated
            .checked_add(allocation.token_ceiling)
            .ok_or(HardTokenBudgetError::Overflow)?;
    }
    if allocated > manifest.ceiling_tokens {
        return Err(HardTokenBudgetError::InvalidManifest);
    }
    Ok((manifest, manifest_sha256))
}

fn validate_identifier(value: &str) -> Result<(), ()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(());
    }
    Ok(())
}

fn validate_sha256(value: &str) -> Result<(), ()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(());
    }
    Ok(())
}

fn sha256_bytes(value: &[u8]) -> String {
    Sha256::digest(value)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
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

fn allocation_charged(
    state: &LedgerState,
    allocation_id: &str,
) -> Result<(u64, u64), HardTokenBudgetError> {
    let mut charged = 0_u64;
    let mut calls = 0_u64;
    for record in state
        .reservations
        .iter()
        .filter(|record| record.allocation_id.as_deref() == Some(allocation_id))
    {
        calls = calls.checked_add(1).ok_or(HardTokenBudgetError::Overflow)?;
        charged = charged
            .checked_add(
                record
                    .actual_tokens
                    .unwrap_or(record.reserved_tokens)
                    .max(record.reserved_tokens),
            )
            .ok_or(HardTokenBudgetError::Overflow)?;
    }
    Ok((charged, calls))
}

#[cfg(unix)]
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

#[cfg(not(unix))]
fn validate_private_directory(_path: &Path) -> Result<(), HardTokenBudgetError> {
    Err(HardTokenBudgetError::UnsupportedPlatform)
}

#[cfg(unix)]
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

#[cfg(not(unix))]
fn open_private_file(_path: &Path, _create: bool) -> Result<File, HardTokenBudgetError> {
    Err(HardTokenBudgetError::UnsupportedPlatform)
}

#[cfg(all(test, unix))]
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

    fn route(model: &str, bound: u64) -> HardTokenRouteContract {
        HardTokenRouteContract {
            model: model.into(),
            endpoint_sha256: "a".repeat(64),
            api_backend: "responses".into(),
            request_bound_tokens: bound,
            max_payload_bytes: bound - 100,
            max_output_tokens: 100,
            bound_provenance_sha256: "b".repeat(64),
        }
    }

    fn allocation(id: &str, model: &str, bound: u64) -> HardTokenAllocationContract {
        HardTokenAllocationContract {
            id: id.into(),
            packet_id: format!("packet-{id}"),
            prompt_sha256: "c".repeat(64),
            token_ceiling: 1_000,
            max_model_calls: 2,
            route: route(model, bound),
        }
    }

    fn receipt_query(budget: &HardTokenBudget) -> HardTokenReceiptQuery {
        let allocation = budget.inner.allocation.as_ref().unwrap();
        HardTokenReceiptQuery {
            campaign_id: budget.inner.campaign_id.clone(),
            manifest_sha256: budget.inner.manifest_sha256.clone(),
            allocation_id: allocation.id.clone(),
            packet_id: allocation.packet_id.clone(),
            baseline_sequence: 0,
            baseline_revision: 0,
        }
    }

    fn write_manifest(
        dir: &Path,
        ceiling_tokens: u64,
        allocations: Vec<HardTokenAllocationContract>,
    ) -> PathBuf {
        let path = dir.join("manifest.json");
        let manifest = HardTokenCampaignManifest {
            version: MANIFEST_VERSION,
            campaign_id: "campaign".into(),
            ceiling_tokens,
            allocations,
        };
        fs::write(&path, serde_json::to_vec(&manifest).unwrap()).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        path
    }

    #[test]
    fn concurrent_reservations_cannot_oversubscribe() {
        let dir = private_dir("race");
        let ledger = dir.join("ledger.json");
        let budget =
            Arc::new(HardTokenBudget::open_for_test(ledger, "race".into(), 1_000).unwrap());
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
            let budget =
                HardTokenBudget::open_for_test(ledger.clone(), "crash".into(), 1_000).unwrap();
            let _ambiguous = budget.reserve(750, "req", "model").unwrap();
        }
        let reopened = HardTokenBudget::open_for_test(ledger, "crash".into(), 1_000).unwrap();
        assert!(matches!(
            reopened.reserve(251, "next", "model"),
            Err(HardTokenBudgetError::Exhausted)
        ));
        assert_eq!(reopened.status().unwrap().outstanding_tokens, 750);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn empty_private_authority_ledger_is_pristine_until_first_reservation() {
        let dir = private_dir("empty-authority-ledger");
        let ledger = dir.join("ledger.json");
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&ledger)
            .unwrap();
        let budget = HardTokenBudget::open_with_allocation_for_test(
            ledger.clone(),
            "empty-authority-ledger".into(),
            1_000,
            "d".repeat(64),
            allocation("a", "model-a", 300),
        )
        .unwrap();

        let status = budget.status().unwrap();
        assert_eq!(status.next_sequence, 1);
        assert_eq!(status.ledger_revision, 0);
        assert!(fs::read(&ledger).unwrap().is_empty());

        let reservation = budget
            .reserve_authorized_request(
                "first-dispatch",
                "model-a",
                &"a".repeat(64),
                "responses",
                100,
                100,
            )
            .unwrap();
        let persisted: LedgerState = serde_json::from_slice(&fs::read(&ledger).unwrap()).unwrap();
        assert_eq!(persisted.next_sequence, 2);
        assert_eq!(persisted.revision, 1);
        drop(reservation);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn nonempty_authority_ledger_is_not_treated_as_pristine() {
        let dir = private_dir("nonempty-authority-ledger");
        let ledger = dir.join("ledger.json");
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&ledger)
            .unwrap()
            .write_all(b" \n")
            .unwrap();
        let result = HardTokenBudget::open_with_allocation_for_test(
            ledger,
            "nonempty-authority-ledger".into(),
            1_000,
            "d".repeat(64),
            allocation("a", "model-a", 300),
        );
        assert!(matches!(result, Err(HardTokenBudgetError::Malformed(_))));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn provider_usage_cannot_refund_the_conservative_reservation() {
        let dir = private_dir("settle");
        let ledger = dir.join("ledger.json");
        let budget = HardTokenBudget::open_for_test(ledger, "settle".into(), 1_000).unwrap();
        budget
            .reserve(800, "req", "model")
            .unwrap()
            .settle(125)
            .unwrap();
        let status = budget.status().unwrap();
        assert_eq!(status.settled_tokens, 800);
        assert_eq!(status.outstanding_tokens, 0);
        assert_eq!(status.remaining_tokens, 200);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn usage_above_reservation_marks_ledger_violated() {
        let dir = private_dir("violation");
        let ledger = dir.join("ledger.json");
        let budget = HardTokenBudget::open_for_test(ledger, "violation".into(), 1_000).unwrap();
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
        assert!(HardTokenBudget::open_for_test(ledger, "symlink".into(), 1_000).is_err());
        assert_eq!(fs::read(&target).unwrap(), b"protected");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn group_readable_parent_is_refused() {
        let dir = private_dir("mode");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o750)).unwrap();
        assert!(matches!(
            HardTokenBudget::open_for_test(dir.join("ledger.json"), "mode".into(), 1_000),
            Err(HardTokenBudgetError::UnsafeParent)
        ));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn manifest_is_identity_while_multiple_routes_share_one_ledger() {
        let dir = private_dir("route-identity");
        let ledger = dir.join("ledger.json");
        let first = HardTokenBudget::open_with_allocation_for_test(
            ledger.clone(),
            "route-identity".into(),
            2_000,
            "d".repeat(64),
            allocation("a", "model-a", 600),
        )
        .unwrap();
        first
            .reserve_authorized_request(
                "request-a",
                "model-a",
                &"a".repeat(64),
                "responses",
                100,
                100,
            )
            .unwrap();
        let second = HardTokenBudget::open_with_allocation_for_test(
            ledger.clone(),
            "route-identity".into(),
            2_000,
            "d".repeat(64),
            allocation("b", "model-b", 600),
        )
        .unwrap();
        second
            .reserve_authorized_request(
                "request-b",
                "model-b",
                &"a".repeat(64),
                "responses",
                100,
                100,
            )
            .unwrap();
        assert_eq!(second.status().unwrap().outstanding_tokens, 1_200);
        assert!(matches!(
            HardTokenBudget::open_with_allocation_for_test(
                ledger,
                "route-identity".into(),
                2_000,
                "e".repeat(64),
                allocation("b", "model-b", 600),
            ),
            Err(HardTokenBudgetError::IdentityMismatch)
        ));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn authorized_reservation_requires_exact_route() {
        let dir = private_dir("route-match");
        let budget = HardTokenBudget::open_with_allocation_for_test(
            dir.join("ledger.json"),
            "route-match".into(),
            1_000,
            "d".repeat(64),
            allocation("a", "model-a", 600),
        )
        .unwrap();
        assert!(matches!(
            budget.reserve_authorized_request(
                "request",
                "model-a",
                &"b".repeat(64),
                "responses",
                100,
                100,
            ),
            Err(HardTokenBudgetError::RouteMismatch)
        ));
        let reservation = budget
            .reserve_authorized_request(
                "request",
                "model-a",
                &"a".repeat(64),
                "responses",
                100,
                100,
            )
            .unwrap();
        assert_eq!(reservation.reserved_tokens, 600);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn manifest_enforces_global_allocation_and_call_ceilings() {
        let dir = private_dir("manifest");
        let mut first = allocation("a", "model-a", 300);
        first.token_ceiling = 600;
        first.max_model_calls = 2;
        let mut second = allocation("b", "model-b", 300);
        second.token_ceiling = 600;
        let manifest = write_manifest(&dir, 1_200, vec![first, second]);
        let ledger = dir.join("ledger.json");
        let budget_a =
            HardTokenBudget::open_with_manifest(ledger.clone(), manifest.clone(), "a").unwrap();
        let budget_b = HardTokenBudget::open_with_manifest(ledger, manifest, "b").unwrap();

        for index in 0..2 {
            budget_a
                .reserve_authorized_request(
                    &format!("a-{index}"),
                    "model-a",
                    &"a".repeat(64),
                    "responses",
                    100,
                    100,
                )
                .unwrap()
                .settle(50)
                .unwrap();
        }
        assert!(matches!(
            budget_a.reserve_authorized_request(
                "a-3",
                "model-a",
                &"a".repeat(64),
                "responses",
                100,
                100,
            ),
            Err(HardTokenBudgetError::CallCeilingExhausted)
        ));
        budget_b
            .reserve_authorized_request("b-1", "model-b", &"a".repeat(64), "responses", 100, 100)
            .unwrap();
        let status = budget_b.status().unwrap();
        assert_eq!(status.settled_tokens, 600);
        assert_eq!(status.outstanding_tokens, 300);
        assert_eq!(status.remaining_tokens, 300);
        assert_eq!(status.allocation_remaining_tokens, Some(300));
        assert_eq!(status.allocation_remaining_calls, Some(1));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn repeated_provider_turn_id_gets_unique_reservations_for_tool_loop_calls() {
        let dir = private_dir("same-turn-tool-loop");
        let mut contract = allocation("a", "model-a", 300);
        contract.token_ceiling = 600;
        contract.max_model_calls = 2;
        let budget = HardTokenBudget::open_with_allocation_for_test(
            dir.join("ledger.json"),
            "same-turn-tool-loop".into(),
            900,
            "d".repeat(64),
            contract,
        )
        .unwrap();

        let first = budget
            .reserve_authorized_request(
                "same-acp-turn-id",
                "model-a",
                &"a".repeat(64),
                "responses",
                100,
                100,
            )
            .unwrap();
        let second = budget
            .reserve_authorized_request(
                "same-acp-turn-id",
                "model-a",
                &"a".repeat(64),
                "responses",
                100,
                100,
            )
            .unwrap();
        assert_ne!(first.id, second.id);
        assert_ne!(first.sequence, second.sequence);
        first.settle(50).unwrap();
        second.settle(50).unwrap();
        assert!(matches!(
            budget.reserve_authorized_request(
                "same-acp-turn-id",
                "model-a",
                &"a".repeat(64),
                "responses",
                100,
                100,
            ),
            Err(HardTokenBudgetError::CallCeilingExhausted)
        ));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn receipts_are_contract_scoped_and_preserve_tool_loop_correlations() {
        let dir = private_dir("receipts-tool-loop");
        let mut contract = allocation("a", "model-a", 300);
        contract.token_ceiling = 600;
        contract.max_model_calls = 2;
        let budget = HardTokenBudget::open_with_allocation_for_test(
            dir.join("ledger.json"),
            "receipts-tool-loop".into(),
            600,
            "d".repeat(64),
            contract,
        )
        .unwrap();
        let first = budget
            .reserve_authorized_request(
                "same-provider-turn",
                "model-a",
                &"a".repeat(64),
                "responses",
                123,
                100,
            )
            .unwrap();
        let second = budget
            .reserve_authorized_request(
                "same-provider-turn",
                "model-a",
                &"a".repeat(64),
                "responses",
                124,
                100,
            )
            .unwrap();
        first.settle(41).unwrap();

        let snapshot = budget.receipts(&receipt_query(&budget)).unwrap();
        assert_eq!(snapshot.receipts.len(), 2);
        assert_ne!(
            snapshot.receipts[0].reservation_id,
            snapshot.receipts[1].reservation_id
        );
        assert_ne!(snapshot.receipts[0].sequence, snapshot.receipts[1].sequence);
        assert_eq!(
            snapshot.receipts[0].provider_request_id,
            "same-provider-turn"
        );
        assert_eq!(snapshot.receipts[0].actual_tokens, Some(41));
        assert_eq!(snapshot.receipts[0].charged_tokens, 300);
        assert_eq!(
            snapshot.receipts[0].terminal_state,
            HardTokenReceiptTerminalState::SettledUsageReported
        );
        assert_eq!(snapshot.receipts[1].actual_tokens, None);
        assert_eq!(snapshot.receipts[1].charged_tokens, 300);
        assert_eq!(
            snapshot.receipts[1].terminal_state,
            HardTokenReceiptTerminalState::Reserved
        );
        drop(second); // cancellation, stream drop, and transport error share this conservative state.
        let after_drop = budget
            .receipts(&HardTokenReceiptQuery {
                baseline_sequence: snapshot.next_sequence,
                baseline_revision: snapshot.ledger_revision,
                ..receipt_query(&budget)
            })
            .unwrap();
        assert_eq!(after_drop.receipts.len(), 1);
        assert_eq!(
            after_drop.receipts[0].terminal_state,
            HardTokenReceiptTerminalState::AmbiguousFullReservationCharged
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn receipts_reject_wrong_contract_and_report_settlement_since_baseline() {
        let dir = private_dir("receipts-baseline");
        let budget = HardTokenBudget::open_with_allocation_for_test(
            dir.join("ledger.json"),
            "receipts-baseline".into(),
            1_000,
            "d".repeat(64),
            allocation("a", "model-a", 300),
        )
        .unwrap();
        let reservation = budget
            .reserve_authorized_request(
                "provider-turn",
                "model-a",
                &"a".repeat(64),
                "responses",
                101,
                100,
            )
            .unwrap();
        let initial = budget.receipts(&receipt_query(&budget)).unwrap();
        assert_eq!(initial.ledger_revision, 1);
        let mut wrong = receipt_query(&budget);
        wrong.packet_id = "wrong-packet".into();
        assert!(matches!(
            budget.receipts(&wrong),
            Err(HardTokenBudgetError::ReceiptContractMismatch)
        ));
        let mut invalid_baseline = receipt_query(&budget);
        invalid_baseline.baseline_sequence = 3;
        assert!(matches!(
            budget.receipts(&invalid_baseline),
            Err(HardTokenBudgetError::ReceiptBaselineInvalid)
        ));

        let empty_delta = budget
            .receipts(&HardTokenReceiptQuery {
                baseline_sequence: initial.next_sequence,
                baseline_revision: initial.ledger_revision,
                ..receipt_query(&budget)
            })
            .unwrap();
        assert!(
            empty_delta.receipts.is_empty(),
            "a snapshot cursor must be usable immediately"
        );

        reservation.settle(77).unwrap();
        let delta = budget
            .receipts(&HardTokenReceiptQuery {
                baseline_sequence: initial.next_sequence,
                baseline_revision: initial.ledger_revision,
                ..receipt_query(&budget)
            })
            .unwrap();
        assert_eq!(
            delta.receipts.len(),
            1,
            "settlement updates survive a sequence cursor"
        );
        assert_eq!(delta.receipts[0].actual_tokens, Some(77));
        assert_eq!(delta.receipts[0].sequence, 1);
        assert_eq!(delta.ledger_revision, 2);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn status_cursor_projects_only_later_reservation_and_settlement() {
        let dir = private_dir("status-receipt-cursor");
        let budget = HardTokenBudget::open_with_allocation_for_test(
            dir.join("ledger.json"),
            "status-receipt-cursor".into(),
            1_000,
            "d".repeat(64),
            allocation("a", "model-a", 300),
        )
        .unwrap();
        budget
            .reserve_authorized_request(
                "before-status",
                "model-a",
                &"a".repeat(64),
                "responses",
                100,
                100,
            )
            .unwrap()
            .settle(50)
            .unwrap();

        let cursor = budget.status().unwrap();
        assert_eq!(cursor.next_sequence, 2);
        assert_eq!(cursor.ledger_revision, 2);

        budget
            .reserve_authorized_request(
                "after-status",
                "model-a",
                &"a".repeat(64),
                "responses",
                100,
                100,
            )
            .unwrap()
            .settle(75)
            .unwrap();

        let delta = budget
            .receipts(&HardTokenReceiptQuery {
                baseline_sequence: cursor.next_sequence,
                baseline_revision: cursor.ledger_revision,
                ..receipt_query(&budget)
            })
            .unwrap();
        assert_eq!(delta.receipts.len(), 1);
        assert_eq!(delta.receipts[0].sequence, 2);
        assert_eq!(delta.receipts[0].provider_request_id, "after-status");
        assert_eq!(delta.receipts[0].actual_tokens, Some(75));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn receipts_are_credential_and_prompt_free() {
        let dir = private_dir("receipts-redaction");
        let ledger = dir.join("ledger.json");
        let budget = HardTokenBudget::open_with_allocation_for_test(
            ledger.clone(),
            "receipts-redaction".into(),
            1_000,
            "d".repeat(64),
            allocation("a", "model-a", 300),
        )
        .unwrap();
        budget
            .reserve_authorized_request(
                "opaque-provider-turn",
                "model-a",
                &"a".repeat(64),
                "responses",
                99,
                100,
            )
            .unwrap();
        let before = fs::read(&ledger).unwrap();
        let serialized =
            serde_json::to_string(&budget.receipts(&receipt_query(&budget)).unwrap()).unwrap();
        assert_eq!(
            fs::read(&ledger).unwrap(),
            before,
            "receipt projection is read-only"
        );
        assert!(!serialized.contains("prompt"));
        assert!(!serialized.contains("credential"));
        assert!(!serialized.contains("access_token"));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn receipt_query_rejects_path_and_unknown_selectors() {
        let value = serde_json::json!({
            "campaignId": "campaign",
            "manifestSha256": "d".repeat(64),
            "allocationId": "a",
            "packetId": "packet-a",
            "baselineSequence": 0,
            "baselineRevision": 0,
            "ledgerPath": "/tmp/not-accepted.json",
        });
        assert!(serde_json::from_value::<HardTokenReceiptQuery>(value).is_err());
    }

    #[test]
    fn manifest_rejects_allocations_whose_sum_exceeds_campaign() {
        let dir = private_dir("manifest-overflow");
        let manifest = write_manifest(
            &dir,
            1_000,
            vec![
                allocation("a", "model-a", 600),
                allocation("b", "model-b", 600),
            ],
        );
        assert!(matches!(
            HardTokenBudget::open_with_manifest(dir.join("ledger.json"), manifest, "a"),
            Err(HardTokenBudgetError::InvalidManifest)
        ));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn manifest_rejects_duplicate_packet_identity() {
        let dir = private_dir("manifest-duplicate-packet");
        let first = allocation("a", "model-a", 400);
        let mut second = allocation("b", "model-b", 400);
        second.packet_id = first.packet_id.clone();
        let manifest = write_manifest(&dir, 1_000, vec![first, second]);
        assert!(matches!(
            HardTokenBudget::open_with_manifest(dir.join("ledger.json"), manifest, "a"),
            Err(HardTokenBudgetError::InvalidManifest)
        ));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn route_bound_must_cover_maximum_payload_bytes_plus_output_tokens() {
        let mut contract = route("model-a", 600);
        contract.max_payload_bytes = 501;
        contract.max_output_tokens = 100;
        assert!(matches!(
            validate_route_contract(&contract),
            Err(HardTokenBudgetError::InvalidRouteContract)
        ));
    }
}
