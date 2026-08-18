//! xai-grok-sampler - Actor-based sampling layer for xAI grok.
//!
//! This crate extracts the HTTP streaming + retry logic out of
//! `xai-grok-shell`'s session actor into a standalone, reusable
//! component built on the same actor pattern as `xai-hunk-tracker`.
//!
//! ## Layered API
//!
//! - **Layer 1**: [`client::SamplingClient`] returns raw chunk streams.
//! - **Layer 2**: [`stream`] transforms raw streams into [`SamplingEvent`]s.
//! - **Layer 3**: [`SamplerHandle`] manages concurrent requests with retry,
//!   cancellation, and event-based coordination via the actor.
//!
//! The type skeleton, the pure retry / metrics / client logic, the
//! Layer-2 stream transforms ([`stream_chat_completions`],
//! [`stream_responses`], [`stream_messages`], [`collect_response`]),
//! and the actor with its per-request task tie these layers together.

pub mod actor;
pub mod armed_credential;
pub mod attribution;
pub mod candidate_identity;
pub mod client;
pub mod commands;
pub mod config;
pub mod doom_loop;
pub mod events;
pub mod handle;
pub mod hard_budget;
pub mod hard_budget_provenance;
pub mod hard_budget_runtime;
pub mod metrics;
pub mod retry;
pub mod sampling_log;
mod shared_http;
pub mod stream;
pub mod types;

// Public re-exports — the API surface consumers see.
pub use actor::SamplerActor;
pub use armed_credential::{
    ArmedCredentialError, ArmedCredentialOwner, discard_unclaimed_armed_credential_owner,
    install_armed_credential_owner,
};
pub use candidate_identity::{
    CandidateIdentityError, claim_measured_candidate_identity,
    discard_unclaimed_measured_candidate_identity, install_measured_candidate_identity,
};
#[cfg(unix)]
pub use candidate_identity::{
    CANDIDATE_IDENTITY_FD, consume_measured_candidate_if_armed,
};
pub use attribution::{
    Auth401AttributionCallback, BEARER_SUFFIX_LEN, SamplingConsumer, SharedAttributionCallback,
};
pub use client::{ApiBackend, SamplingClient, user_agent_string_for};
pub use config::{
    AuthScheme, BearerResolver, HeaderInjector, OriginClientInfo, RetryPolicy, SamplerConfig,
    SharedBearerResolver, SharedHeaderInjector,
};
pub use doom_loop::DoomLoopSignalCollector;
pub use events::{
    SamplingChannel, SamplingErrorInfo, SamplingErrorKind, SamplingEvent, StripReason,
};
pub use handle::SamplerHandle;
pub use hard_budget::{
    ActiveHardTokenV3Authority, BudgetReservation, HardTokenAllocationContract, HardTokenBudget,
    HardTokenBudgetError, HardTokenBudgetStatus, HardTokenReceiptQuery, HardTokenReceiptSnapshot,
    HardTokenReceiptTerminalState, HardTokenReservationReceipt, HardTokenRouteContract,
    HardTokenV3RuntimeBinding, V3AuthorityBuilder, active_v3_authority,
    bind_and_install_v3_authority, install_active_v3_authority, require_registered_v3_authority,
};
pub use hard_budget_provenance::{
    CampaignPolicyV3, CandidateIdentityV1, HardTokenBoundProvenanceV1, HardTokenProvenanceError,
    ResolvedConfigIdentityV1, ResolvedRouteBoundV1, ToolIsolationContractV1,
    canonical_auth_header_names,
};
pub use hard_budget_runtime::{
    ARMED_V3_LIVE_SERIALIZER_PAYLOAD_CEILING_BYTES, ArmedV3LiveRouteCore,
    ArmedV3PacketBoundsObservation, ArmedV3ResolutionError, ArmedV3ResolvedSnapshot,
    ArmedV3RouteCoreObservation, ArmedV3SnapshotObservation, LIVE_HARD_BUDGET_ISOLATED_TOOL_IDS,
    RESOLVED_MANAGED_PROVIDER_SOURCE_KIND, ResolvedConfigIdentityTracker, TrackedConfigGeneration,
    armed_v3_tool_isolation, deterministic_route_id, live_api_backend_label,
    live_auth_scheme_label, live_hard_budget_isolated_tool_ids,
    live_serializer_payload_ceiling_bytes, observed_managed_source_kind,
    observed_max_output_tokens,
};
pub use metrics::{InferenceLatencyStats, compute_percentiles};
pub use retry::{
    DEFAULT_MAX_RETRIES, RATE_LIMIT_RETRY_THRESHOLD, RetryDecision, classify_error,
    format_sampling_error, resolve_max_retries, retry_backoff_with_jitter,
};
pub use sampling_log::AuthInfo;
pub use stream::{collect_response, stream_chat_completions, stream_messages, stream_responses};
pub use types::RequestId;
