//! Fail-closed armed v3 snapshot types.
//!
//! This module does not load config, talk to AuthManager, or call
//! `bind_actual`. It only accepts independently observed fields and refuses
//! invented identity: empty defaults, golden OpenRouter fixtures, remote
//! hosts, and secret-bearing sampler configs. Live route observation measures
//! loopback endpoint SHA, a deterministic route id, the serializer ceiling,
//! Darwin `fd_v1`, and isolated tool IDs. Packet ceilings stay caller-supplied.

use sha2::{Digest, Sha256};

use crate::client::{exact_loopback_endpoint_sha256, is_exact_loopback_base_url};
use crate::config::{AuthScheme, SamplerConfig};
use crate::hard_budget::HardTokenV3RuntimeBinding;
use crate::hard_budget_provenance::{
    ALLOCATABLE_TOKEN_CEILING, CandidateIdentityV1, HardTokenBoundProvenanceV1,
    ResolvedConfigIdentityV1, ResolvedRouteBoundV1, ToolIsolationContractV1,
    canonical_auth_header_names, validate_identifier, validate_tool_isolation,
};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ArmedV3ResolutionError {
    #[error("armed v3 snapshot is missing independently observed identity")]
    MissingObservedIdentity,
    #[error("armed v3 snapshot identity is invalid")]
    InvalidIdentity,
    #[error("armed v3 snapshot permits only an exact loopback base URL")]
    RemoteEndpoint,
    #[error("armed v3 snapshot sampler config is not credential-free")]
    SecretBearingConfig,
}

/// Caller-supplied observations. Every field is optional so a partial producer
/// cannot compile its way into a successful snapshot.
#[derive(Clone, Debug, Default)]
pub struct ArmedV3SnapshotObservation {
    pub candidate: Option<CandidateIdentityV1>,
    pub source_kind: Option<String>,
    pub generation: Option<u64>,
    pub managed_provider_id: Option<String>,
    pub config_projection: Option<Vec<u8>>,
    pub route: Option<ResolvedRouteBoundV1>,
    pub catalog_key: Option<String>,
    pub sampler: Option<SamplerConfig>,
}

/// One immutable credential-free snapshot. Production startup still must not
/// bind this until a tracked config producer exists.
#[derive(Clone, Debug)]
pub struct ArmedV3ResolvedSnapshot {
    binding: HardTokenV3RuntimeBinding,
    sampler_config: SamplerConfig,
    catalog_key: String,
    config_projection: Vec<u8>,
}

impl ArmedV3ResolvedSnapshot {
    pub fn try_resolve(
        observation: ArmedV3SnapshotObservation,
    ) -> Result<Self, ArmedV3ResolutionError> {
        let candidate = observation
            .candidate
            .ok_or(ArmedV3ResolutionError::MissingObservedIdentity)?;
        let source_kind = observation
            .source_kind
            .ok_or(ArmedV3ResolutionError::MissingObservedIdentity)?;
        let generation = observation
            .generation
            .ok_or(ArmedV3ResolutionError::MissingObservedIdentity)?;
        let managed_provider_id = observation
            .managed_provider_id
            .ok_or(ArmedV3ResolutionError::MissingObservedIdentity)?;
        let config_projection = observation
            .config_projection
            .ok_or(ArmedV3ResolutionError::MissingObservedIdentity)?;
        let route = observation
            .route
            .ok_or(ArmedV3ResolutionError::MissingObservedIdentity)?;
        let catalog_key = observation
            .catalog_key
            .ok_or(ArmedV3ResolutionError::MissingObservedIdentity)?;
        let sampler = observation
            .sampler
            .ok_or(ArmedV3ResolutionError::MissingObservedIdentity)?;

        if source_kind != "resolved-managed-provider" || generation == 0 {
            return Err(ArmedV3ResolutionError::InvalidIdentity);
        }
        if catalog_key.is_empty()
            || catalog_key.len() > 128
            || !catalog_key
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            return Err(ArmedV3ResolutionError::InvalidIdentity);
        }
        if config_projection.is_empty()
            || config_projection.len() > 32 * 1024
            || !config_projection
                .iter()
                .all(|byte| (0x20..=0x7e).contains(byte) || *byte == b'\n')
        {
            return Err(ArmedV3ResolutionError::InvalidIdentity);
        }
        let config_projection_sha256 = sha256_hex(&config_projection);
        let config_identity = ResolvedConfigIdentityV1 {
            source_kind,
            generation,
            managed_provider_id: managed_provider_id.clone(),
            config_projection_sha256,
        };
        if managed_provider_id != route.provider_id {
            return Err(ArmedV3ResolutionError::InvalidIdentity);
        }
        HardTokenBoundProvenanceV1::from_resolved_route(
            "snapshot-campaign".into(),
            "snapshot-allocation".into(),
            candidate.clone(),
            config_identity.clone(),
            route.clone(),
        )
        .map_err(|_| ArmedV3ResolutionError::InvalidIdentity)?;

        let Some(expected_endpoint) =
            exact_loopback_endpoint_sha256(&sampler.base_url, &route.api_backend)
        else {
            return Err(ArmedV3ResolutionError::RemoteEndpoint);
        };
        if expected_endpoint != route.endpoint_sha256
            || !is_exact_loopback_base_url(&sampler.base_url)
        {
            return Err(ArmedV3ResolutionError::RemoteEndpoint);
        }
        if sampler.model != route.provider_facing_model {
            return Err(ArmedV3ResolutionError::InvalidIdentity);
        }
        let sampler_config = sanitize_sampler_config(sampler, &route)?;
        Ok(Self {
            binding: HardTokenV3RuntimeBinding {
                candidate,
                config_identity,
                route,
            },
            sampler_config,
            catalog_key,
            config_projection,
        })
    }

    pub fn binding(&self) -> &HardTokenV3RuntimeBinding {
        &self.binding
    }

    pub fn sampler_config(&self) -> &SamplerConfig {
        &self.sampler_config
    }

    pub fn catalog_key(&self) -> &str {
        &self.catalog_key
    }

    pub fn config_projection(&self) -> &[u8] {
        &self.config_projection
    }
}

fn sanitize_sampler_config(
    sampler: SamplerConfig,
    route: &ResolvedRouteBoundV1,
) -> Result<SamplerConfig, ArmedV3ResolutionError> {
    if sampler.api_key.is_some()
        || sampler.bearer_resolver.is_some()
        || sampler.header_injector.is_some()
        || sampler.attribution_callback.is_some()
        || !sampler.extra_headers.is_empty()
        || !sampler.query_params.is_empty()
        || !sampler.env_http_headers.is_empty()
        || sampler.supports_backend_search
        || sampler.max_retries.unwrap_or(0) != 0
    {
        return Err(ArmedV3ResolutionError::SecretBearingConfig);
    }
    let names = canonical_auth_header_names(&route.auth_scheme)
        .map_err(|_| ArmedV3ResolutionError::InvalidIdentity)?;
    let expected_scheme = if names == ["x-api-key"] {
        AuthScheme::XApiKey
    } else {
        AuthScheme::Bearer
    };
    if sampler.auth_scheme != expected_scheme {
        return Err(ArmedV3ResolutionError::InvalidIdentity);
    }
    let expected_backend = match route.api_backend.as_str() {
        "chat_completions" => xai_grok_sampling_types::ApiBackend::ChatCompletions,
        "responses" => xai_grok_sampling_types::ApiBackend::Responses,
        "messages" => xai_grok_sampling_types::ApiBackend::Messages,
        _ => return Err(ArmedV3ResolutionError::InvalidIdentity),
    };
    if sampler.api_backend != expected_backend {
        return Err(ArmedV3ResolutionError::InvalidIdentity);
    }
    let mut sanitized = sampler;
    sanitized.max_retries = Some(0);
    Ok(sanitized)
}

/// Live armed serializer ceiling. Armed `serialize_provider_payload` enforces
/// this same constant once v3 authority is active, min'd with the bound
/// contract payload. This is not the golden fixture's 8192-byte field.
pub const ARMED_V3_LIVE_SERIALIZER_PAYLOAD_CEILING_BYTES: u64 = 65_536;

pub fn live_serializer_payload_ceiling_bytes() -> u64 {
    ARMED_V3_LIVE_SERIALIZER_PAYLOAD_CEILING_BYTES
}

pub const RESOLVED_MANAGED_PROVIDER_SOURCE_KIND: &str = "resolved-managed-provider";

/// Source kind is `resolved-managed-provider` only when the selected model
/// has a non-empty `model_provider`. Missing provider is a refusal, not `toml`.
pub fn observed_managed_source_kind(model_provider: Option<&str>) -> Option<&'static str> {
    model_provider
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|_| RESOLVED_MANAGED_PROVIDER_SOURCE_KIND)
}

pub fn observed_max_output_tokens(max_completion_tokens: Option<u32>) -> Option<u64> {
    max_completion_tokens
        .map(u64::from)
        .filter(|tokens| *tokens > 0)
}

pub fn live_auth_scheme_label(scheme: AuthScheme) -> &'static str {
    match scheme {
        AuthScheme::Bearer => "bearer",
        AuthScheme::XApiKey => "x_api_key",
    }
}

pub fn live_api_backend_label(backend: &xai_grok_sampling_types::ApiBackend) -> &'static str {
    match backend {
        xai_grok_sampling_types::ApiBackend::ChatCompletions => "chat_completions",
        xai_grok_sampling_types::ApiBackend::Responses => "responses",
        xai_grok_sampling_types::ApiBackend::Messages => "messages",
    }
}

/// Live armed isolation IDs. Must stay aligned with `xai-grok-agent`
/// `hard_budget_tool_allowed`. Lexical order is the provenance contract.
/// This is not the golden two-tool fixture.
pub const LIVE_HARD_BUDGET_ISOLATED_TOOL_IDS: &[&str] = &[
    "GrokBuild:get_task_output",
    "GrokBuild:kill_task",
    "GrokBuild:read_file",
    "GrokBuild:task",
    "GrokBuild:wait_tasks",
];

pub fn live_hard_budget_isolated_tool_ids() -> Vec<String> {
    LIVE_HARD_BUDGET_ISOLATED_TOOL_IDS
        .iter()
        .map(|id| (*id).to_string())
        .collect()
}

pub fn deterministic_route_id(
    provider_id: &str,
    provider_facing_model: &str,
    endpoint_sha256: &str,
    api_backend: &str,
    auth_scheme: &str,
) -> String {
    let joined = [
        provider_id,
        provider_facing_model,
        endpoint_sha256,
        api_backend,
        auth_scheme,
    ]
    .join("\0");
    format!("v3.{}", sha256_hex(joined.as_bytes()))
}

pub fn armed_v3_tool_isolation(
    mut allowed_tool_ids: Vec<String>,
) -> Result<ToolIsolationContractV1, ArmedV3ResolutionError> {
    allowed_tool_ids.sort();
    allowed_tool_ids.dedup();
    let isolation = ToolIsolationContractV1 {
        auth_provider_helpers_disabled: true,
        terminal_disabled: true,
        external_mcp_disabled: true,
        hooks_disabled: true,
        plugins_disabled: true,
        lsp_disabled: true,
        workflows_disabled: true,
        scheduler_disabled: true,
        protected_authority_fs: true,
        workspace_fs_confined: true,
        sampler_transport_retries_disabled: true,
        allowed_tool_ids,
    };
    validate_tool_isolation(&isolation).map_err(|_| ArmedV3ResolutionError::InvalidIdentity)?;
    Ok(isolation)
}

/// Caller-supplied live route observations. Packet ceilings stay unset until a
/// frozen packet envelope is observed separately. This type does not call
/// `bind_actual`.
#[derive(Clone, Debug, Default)]
pub struct ArmedV3RouteCoreObservation {
    pub provider_id: Option<String>,
    pub provider_facing_model: Option<String>,
    pub base_url: Option<String>,
    pub api_backend: Option<String>,
    pub auth_scheme: Option<String>,
    pub allowed_tool_ids: Option<Vec<String>>,
}

/// Frozen packet envelope plus the selected model's output cap. Conservative
/// request bound is derived live as payload ceiling + output cap. Do not copy
/// golden 12288/20000/1 into these fields.
#[derive(Clone, Debug, Default)]
pub struct ArmedV3PacketBoundsObservation {
    pub max_output_tokens: Option<u64>,
    pub allocation_token_ceiling: Option<u64>,
    pub max_model_calls: Option<u64>,
}

/// Independently measured loopback route core: route id, endpoint SHA, live
/// serializer ceiling, Darwin `fd_v1` transport, and observed tool isolation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArmedV3LiveRouteCore {
    pub route_id: String,
    pub provider_id: String,
    pub provider_facing_model: String,
    pub endpoint_sha256: String,
    pub api_backend: String,
    pub credential_transport: String,
    pub auth_scheme: String,
    pub max_final_serialized_payload_bytes: u64,
    pub text_only: bool,
    pub remote_context_forbidden: bool,
    pub multimodal_forbidden: bool,
    pub redirect_disabled: bool,
    pub retry_disabled: bool,
    pub tool_isolation: ToolIsolationContractV1,
}

impl ArmedV3LiveRouteCore {
    pub fn try_observe(
        observation: ArmedV3RouteCoreObservation,
    ) -> Result<Self, ArmedV3ResolutionError> {
        let provider_id = observation
            .provider_id
            .ok_or(ArmedV3ResolutionError::MissingObservedIdentity)?;
        let provider_facing_model = observation
            .provider_facing_model
            .ok_or(ArmedV3ResolutionError::MissingObservedIdentity)?;
        let base_url = observation
            .base_url
            .ok_or(ArmedV3ResolutionError::MissingObservedIdentity)?;
        let api_backend = observation
            .api_backend
            .ok_or(ArmedV3ResolutionError::MissingObservedIdentity)?;
        let auth_scheme = observation
            .auth_scheme
            .ok_or(ArmedV3ResolutionError::MissingObservedIdentity)?;
        let allowed_tool_ids = observation
            .allowed_tool_ids
            .ok_or(ArmedV3ResolutionError::MissingObservedIdentity)?;

        validate_identifier(&provider_id).map_err(|_| ArmedV3ResolutionError::InvalidIdentity)?;
        if provider_facing_model.is_empty()
            || provider_facing_model.len() > 256
            || !provider_facing_model.is_ascii()
        {
            return Err(ArmedV3ResolutionError::InvalidIdentity);
        }
        canonical_auth_header_names(&auth_scheme)
            .map_err(|_| ArmedV3ResolutionError::InvalidIdentity)?;
        let Some(endpoint_sha256) = exact_loopback_endpoint_sha256(&base_url, &api_backend) else {
            return Err(ArmedV3ResolutionError::RemoteEndpoint);
        };
        let tool_isolation = armed_v3_tool_isolation(allowed_tool_ids)?;
        let route_id = deterministic_route_id(
            &provider_id,
            &provider_facing_model,
            &endpoint_sha256,
            &api_backend,
            &auth_scheme,
        );
        Ok(Self {
            route_id,
            provider_id,
            provider_facing_model,
            endpoint_sha256,
            api_backend,
            credential_transport: "fd_v1".into(),
            auth_scheme,
            max_final_serialized_payload_bytes: live_serializer_payload_ceiling_bytes(),
            text_only: true,
            remote_context_forbidden: true,
            multimodal_forbidden: true,
            redirect_disabled: true,
            retry_disabled: true,
            tool_isolation,
        })
    }

    /// Attach independently observed packet ceilings. Golden 12288/20000/1
    /// values are not defaults; they fail against the live serializer ceiling.
    pub fn with_packet_bounds(
        self,
        max_output_tokens: u64,
        conservative_request_bound_tokens: u64,
        allocation_token_ceiling: u64,
        max_model_calls: u64,
    ) -> Result<ResolvedRouteBoundV1, ArmedV3ResolutionError> {
        if max_output_tokens == 0 || max_model_calls == 0 {
            return Err(ArmedV3ResolutionError::InvalidIdentity);
        }
        let lower_bound = self
            .max_final_serialized_payload_bytes
            .checked_add(max_output_tokens)
            .ok_or(ArmedV3ResolutionError::InvalidIdentity)?;
        if lower_bound > conservative_request_bound_tokens
            || conservative_request_bound_tokens > allocation_token_ceiling
            || allocation_token_ceiling > ALLOCATABLE_TOKEN_CEILING
        {
            return Err(ArmedV3ResolutionError::InvalidIdentity);
        }
        Ok(ResolvedRouteBoundV1 {
            route_id: self.route_id,
            provider_id: self.provider_id,
            provider_facing_model: self.provider_facing_model,
            endpoint_sha256: self.endpoint_sha256,
            api_backend: self.api_backend,
            credential_transport: self.credential_transport,
            auth_scheme: self.auth_scheme,
            max_final_serialized_payload_bytes: self.max_final_serialized_payload_bytes,
            max_output_tokens,
            conservative_request_bound_tokens,
            allocation_token_ceiling,
            max_model_calls,
            text_only: self.text_only,
            remote_context_forbidden: self.remote_context_forbidden,
            multimodal_forbidden: self.multimodal_forbidden,
            redirect_disabled: self.redirect_disabled,
            retry_disabled: self.retry_disabled,
            tool_isolation: self.tool_isolation,
        })
    }

    /// Derive the conservative request bound from the live serializer ceiling
    /// plus the selected model's output cap. Allocation ceiling and max model
    /// calls must come from the frozen packet envelope, not golden route fields.
    /// This does not call `bind_actual`.
    pub fn with_observed_packet_bounds(
        self,
        observation: ArmedV3PacketBoundsObservation,
    ) -> Result<ResolvedRouteBoundV1, ArmedV3ResolutionError> {
        let max_output_tokens = observation
            .max_output_tokens
            .ok_or(ArmedV3ResolutionError::MissingObservedIdentity)?;
        let allocation_token_ceiling = observation
            .allocation_token_ceiling
            .ok_or(ArmedV3ResolutionError::MissingObservedIdentity)?;
        let max_model_calls = observation
            .max_model_calls
            .ok_or(ArmedV3ResolutionError::MissingObservedIdentity)?;
        let conservative_request_bound_tokens = self
            .max_final_serialized_payload_bytes
            .checked_add(max_output_tokens)
            .ok_or(ArmedV3ResolutionError::InvalidIdentity)?;
        self.with_packet_bounds(
            max_output_tokens,
            conservative_request_bound_tokens,
            allocation_token_ceiling,
            max_model_calls,
        )
    }
}

/// Monotonic generation for a frozen credential-free config projection.
///
/// Zero is unset. Callers bump only when the independently resolved projection
/// actually mutates. Do not copy `ManagedConfigCache.synced_at`, wall-clock
/// time, or a snapshot-time invention into this value.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TrackedConfigGeneration {
    value: u64,
}

impl TrackedConfigGeneration {
    pub const fn new() -> Self {
        Self { value: 0 }
    }

    pub fn current(&self) -> Option<u64> {
        (self.value > 0).then_some(self.value)
    }

    pub fn bump(&mut self) -> u64 {
        self.value = self.value.saturating_add(1);
        self.value
    }
}

/// Tracks a credential-free config projection by content hash.
///
/// Identical bytes do not bump. Empty bytes stay unset. This is not
/// `ManagedConfigCache.synced_at` and does not call `bind_actual`.
#[derive(Clone, Debug, Default)]
pub struct ResolvedConfigIdentityTracker {
    generation: TrackedConfigGeneration,
    last_sha256: Option<String>,
}

impl ResolvedConfigIdentityTracker {
    pub const fn new() -> Self {
        Self {
            generation: TrackedConfigGeneration::new(),
            last_sha256: None,
        }
    }

    pub fn current(&self) -> Option<u64> {
        self.generation.current()
    }

    pub fn last_projection_sha256(&self) -> Option<&str> {
        self.last_sha256.as_deref()
    }

    pub fn observe(&mut self, projection: &[u8]) -> Option<u64> {
        if projection.is_empty() {
            return self.generation.current();
        }
        let sha = sha256_hex(projection);
        if self.last_sha256.as_deref() == Some(sha.as_str()) {
            return self.generation.current();
        }
        self.last_sha256 = Some(sha);
        self.generation.bump();
        self.generation.current()
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hard_budget::v3_test_support;
    use crate::hard_budget_provenance::ResolvedRouteBoundV1;
    use xai_grok_sampling_types::ApiBackend;

    fn loopback_route(base_url: &str, backend: &str) -> ResolvedRouteBoundV1 {
        let mut route = v3_test_support::route();
        route.api_backend = backend.into();
        route.provider_facing_model = "test-model".into();
        route.endpoint_sha256 = exact_loopback_endpoint_sha256(base_url, backend).unwrap();
        route
    }

    fn complete_observation() -> ArmedV3SnapshotObservation {
        let base_url = "http://127.0.0.1:9/v1".to_string();
        let route = loopback_route(&base_url, "responses");
        let projection = br#"{"generation":7,"provider":"loopback-test"}"#.to_vec();
        ArmedV3SnapshotObservation {
            candidate: Some(CandidateIdentityV1 {
                cli_build: "1.0.5 (003f955)".into(),
                binary_sha256: "a".repeat(64),
                source_commit_sha: "b".repeat(40),
            }),
            source_kind: Some("resolved-managed-provider".into()),
            generation: Some(7),
            managed_provider_id: Some(route.provider_id.clone()),
            config_projection: Some(projection),
            route: Some(route.clone()),
            catalog_key: Some("loopback-test".into()),
            sampler: Some(SamplerConfig {
                base_url,
                model: route.provider_facing_model,
                api_backend: ApiBackend::Responses,
                auth_scheme: AuthScheme::Bearer,
                max_retries: Some(0),
                ..SamplerConfig::default()
            }),
        }
    }

    #[test]
    fn empty_or_default_observation_is_refused() {
        assert_eq!(
            ArmedV3ResolvedSnapshot::try_resolve(ArmedV3SnapshotObservation::default())
                .unwrap_err(),
            ArmedV3ResolutionError::MissingObservedIdentity
        );
        let mut default_sampler = complete_observation();
        default_sampler.sampler = Some(SamplerConfig::default());
        assert_eq!(
            ArmedV3ResolvedSnapshot::try_resolve(default_sampler).unwrap_err(),
            ArmedV3ResolutionError::RemoteEndpoint
        );
    }

    #[test]
    fn observed_loopback_snapshot_does_not_invent_openrouter_or_bind() {
        let snapshot = ArmedV3ResolvedSnapshot::try_resolve(complete_observation()).unwrap();
        assert_eq!(snapshot.catalog_key(), "loopback-test");
        assert_eq!(
            snapshot.binding().config_identity.managed_provider_id,
            "openrouter"
        );
        assert_eq!(
            snapshot.binding().route.provider_facing_model,
            "test-model"
        );
        assert!(snapshot.sampler_config().api_key.is_none());
        assert_eq!(snapshot.sampler_config().max_retries, Some(0));
        assert!(crate::hard_budget::active_v3_authority().is_none());
    }

    #[test]
    fn missing_candidate_generation_and_secret_configs_are_refused() {
        let mut missing_candidate = complete_observation();
        missing_candidate.candidate = None;
        assert_eq!(
            ArmedV3ResolvedSnapshot::try_resolve(missing_candidate).unwrap_err(),
            ArmedV3ResolutionError::MissingObservedIdentity
        );

        let mut missing_generation = complete_observation();
        missing_generation.generation = None;
        assert_eq!(
            ArmedV3ResolvedSnapshot::try_resolve(missing_generation).unwrap_err(),
            ArmedV3ResolutionError::MissingObservedIdentity
        );

        let mut toml_kind = complete_observation();
        toml_kind.source_kind = Some("toml".into());
        assert_eq!(
            ArmedV3ResolvedSnapshot::try_resolve(toml_kind).unwrap_err(),
            ArmedV3ResolutionError::InvalidIdentity
        );

        let mut keyed = complete_observation();
        keyed.sampler.as_mut().unwrap().api_key = Some("sk-test".into());
        assert_eq!(
            ArmedV3ResolvedSnapshot::try_resolve(keyed).unwrap_err(),
            ArmedV3ResolutionError::SecretBearingConfig
        );

        let mut extra = complete_observation();
        extra
            .sampler
            .as_mut()
            .unwrap()
            .extra_headers
            .insert("x-debug".into(), "1".into());
        assert_eq!(
            ArmedV3ResolvedSnapshot::try_resolve(extra).unwrap_err(),
            ArmedV3ResolutionError::SecretBearingConfig
        );
    }

    #[test]
    fn remote_host_and_golden_endpoint_mismatch_are_refused() {
        let mut remote = complete_observation();
        remote.sampler.as_mut().unwrap().base_url = "https://openrouter.ai/api/v1".into();
        assert_eq!(
            ArmedV3ResolvedSnapshot::try_resolve(remote).unwrap_err(),
            ArmedV3ResolutionError::RemoteEndpoint
        );

        let mut drifted = complete_observation();
        drifted.route.as_mut().unwrap().endpoint_sha256 = "c".repeat(64);
        assert_eq!(
            ArmedV3ResolvedSnapshot::try_resolve(drifted).unwrap_err(),
            ArmedV3ResolutionError::RemoteEndpoint
        );
    }

    #[test]
    fn tracked_generation_starts_unset_and_is_not_a_cache_timestamp() {
        let mut generation = TrackedConfigGeneration::new();
        assert_eq!(generation.current(), None);
        assert_eq!(generation.bump(), 1);
        assert_eq!(generation.current(), Some(1));
        assert_eq!(generation.bump(), 2);
        assert_eq!(generation.current(), Some(2));

        let mut unset = complete_observation();
        unset.generation = TrackedConfigGeneration::new().current();
        assert_eq!(
            ArmedV3ResolvedSnapshot::try_resolve(unset).unwrap_err(),
            ArmedV3ResolutionError::MissingObservedIdentity
        );

        let mut tracked = TrackedConfigGeneration::new();
        tracked.bump();
        let mut observed = complete_observation();
        observed.generation = tracked.current();
        let snapshot = ArmedV3ResolvedSnapshot::try_resolve(observed).unwrap();
        assert_eq!(snapshot.binding().config_identity.generation, 1);
        assert!(crate::hard_budget::active_v3_authority().is_none());
    }

    #[test]
    fn identity_tracker_bumps_only_when_projection_bytes_change() {
        let mut tracker = ResolvedConfigIdentityTracker::new();
        assert_eq!(tracker.current(), None);
        assert_eq!(tracker.observe(b""), None);

        let first = br#"{"catalogKey":"loopback","modelProvider":"gateway"}"#;
        assert_eq!(tracker.observe(first), Some(1));
        assert_eq!(tracker.observe(first), Some(1));
        let second = br#"{"catalogKey":"loopback","modelProvider":"other"}"#;
        assert_eq!(tracker.observe(second), Some(2));
        assert_eq!(
            tracker.last_projection_sha256(),
            Some(sha256_hex(second).as_str())
        );
        assert!(crate::hard_budget::active_v3_authority().is_none());
    }

    fn loopback_core_observation() -> ArmedV3RouteCoreObservation {
        ArmedV3RouteCoreObservation {
            provider_id: Some("gateway".into()),
            provider_facing_model: Some("loopback-model".into()),
            base_url: Some("http://127.0.0.1:9/v1".into()),
            api_backend: Some("responses".into()),
            auth_scheme: Some("bearer".into()),
            allowed_tool_ids: Some(live_hard_budget_isolated_tool_ids()),
        }
    }

    #[test]
    fn selected_model_source_kind_is_not_invented_toml() {
        assert_eq!(observed_managed_source_kind(None), None);
        assert_eq!(observed_managed_source_kind(Some("")), None);
        assert_eq!(observed_managed_source_kind(Some("   ")), None);
        assert_eq!(
            observed_managed_source_kind(Some("gateway")),
            Some(RESOLVED_MANAGED_PROVIDER_SOURCE_KIND)
        );
        assert_eq!(observed_max_output_tokens(None), None);
        assert_eq!(observed_max_output_tokens(Some(0)), None);
        assert_eq!(observed_max_output_tokens(Some(1024)), Some(1024));
        assert!(crate::hard_budget::active_v3_authority().is_none());
    }

    #[test]
    fn live_route_core_measures_loopback_not_golden_route_or_payload() {
        let core = ArmedV3LiveRouteCore::try_observe(loopback_core_observation()).unwrap();
        assert!(core.route_id.starts_with("v3."));
        assert_eq!(core.route_id.len(), 67);
        assert_ne!(core.route_id, "route-1");
        assert_ne!(core.route_id, "route-a");
        assert_eq!(
            core.max_final_serialized_payload_bytes,
            live_serializer_payload_ceiling_bytes()
        );
        assert_ne!(core.max_final_serialized_payload_bytes, 8192);
        assert_eq!(core.credential_transport, "fd_v1");
        assert_eq!(core.provider_id, "gateway");
        assert_eq!(
            core.tool_isolation.allowed_tool_ids,
            live_hard_budget_isolated_tool_ids()
        );
        assert_ne!(
            core.tool_isolation.allowed_tool_ids,
            vec!["GrokBuild:read_file".to_string(), "GrokBuild:task".into()]
        );
        assert_eq!(
            core.endpoint_sha256,
            exact_loopback_endpoint_sha256("http://127.0.0.1:9/v1", "responses").unwrap()
        );
        let again = ArmedV3LiveRouteCore::try_observe(loopback_core_observation()).unwrap();
        assert_eq!(core.route_id, again.route_id);

        assert_eq!(
            ArmedV3LiveRouteCore::try_observe(ArmedV3RouteCoreObservation::default()).unwrap_err(),
            ArmedV3ResolutionError::MissingObservedIdentity
        );

        let mut remote = loopback_core_observation();
        remote.base_url = Some("https://openrouter.ai/api/v1".into());
        assert_eq!(
            ArmedV3LiveRouteCore::try_observe(remote).unwrap_err(),
            ArmedV3ResolutionError::RemoteEndpoint
        );

        let mut xai = loopback_core_observation();
        xai.base_url = Some("https://api.x.ai/v1".into());
        assert_eq!(
            ArmedV3LiveRouteCore::try_observe(xai).unwrap_err(),
            ArmedV3ResolutionError::RemoteEndpoint
        );

        let mut missing_provider = loopback_core_observation();
        missing_provider.provider_id = None;
        assert_eq!(
            ArmedV3LiveRouteCore::try_observe(missing_provider).unwrap_err(),
            ArmedV3ResolutionError::MissingObservedIdentity
        );

        let mut unsorted = loopback_core_observation();
        unsorted.allowed_tool_ids = Some(vec![
            "GrokBuild:wait_tasks".into(),
            "GrokBuild:read_file".into(),
            "GrokBuild:kill_task".into(),
            "GrokBuild:task".into(),
            "GrokBuild:get_task_output".into(),
        ]);
        let sorted = ArmedV3LiveRouteCore::try_observe(unsorted).unwrap();
        assert_eq!(
            sorted.tool_isolation.allowed_tool_ids,
            live_hard_budget_isolated_tool_ids()
        );
        assert!(crate::hard_budget::active_v3_authority().is_none());
    }

    #[test]
    fn golden_packet_bounds_fail_against_live_serializer_ceiling() {
        let core = ArmedV3LiveRouteCore::try_observe(loopback_core_observation()).unwrap();
        assert_eq!(
            core.clone()
                .with_packet_bounds(4096, 12_288, 20_000, 1)
                .unwrap_err(),
            ArmedV3ResolutionError::InvalidIdentity
        );
        let route = core
            .with_packet_bounds(1_024, 70_000, 80_000, 2)
            .expect("arithmetic that actually covers the live ceiling");
        assert_eq!(route.max_final_serialized_payload_bytes, 65_536);
        assert_eq!(route.max_output_tokens, 1_024);
        assert_eq!(route.route_id.chars().take(3).collect::<String>(), "v3.");
        assert!(crate::hard_budget::active_v3_authority().is_none());
    }

    #[test]
    fn observed_packet_bounds_derive_conservative_and_refuse_golden_envelope() {
        let core = ArmedV3LiveRouteCore::try_observe(loopback_core_observation()).unwrap();
        assert_eq!(
            core.clone()
                .with_observed_packet_bounds(ArmedV3PacketBoundsObservation::default())
                .unwrap_err(),
            ArmedV3ResolutionError::MissingObservedIdentity
        );
        assert_eq!(
            core.clone()
                .with_observed_packet_bounds(ArmedV3PacketBoundsObservation {
                    max_output_tokens: Some(4_096),
                    allocation_token_ceiling: Some(20_000),
                    max_model_calls: Some(1),
                })
                .unwrap_err(),
            ArmedV3ResolutionError::InvalidIdentity
        );

        let route = core
            .with_observed_packet_bounds(ArmedV3PacketBoundsObservation {
                max_output_tokens: Some(1_024),
                allocation_token_ceiling: Some(80_000),
                max_model_calls: Some(2),
            })
            .expect("covering packet envelope");
        assert_eq!(route.max_output_tokens, 1_024);
        assert_eq!(route.conservative_request_bound_tokens, 65_536 + 1_024);
        assert_eq!(route.allocation_token_ceiling, 80_000);
        assert_eq!(route.max_model_calls, 2);
        assert_ne!(route.conservative_request_bound_tokens, 12_288);
        assert!(crate::hard_budget::active_v3_authority().is_none());
    }

    #[test]
    fn unarmed_serialize_is_not_capped_at_golden_8192() {
        let payload = serde_json::json!({ "prompt": "x".repeat(70_000) });
        let bytes = crate::client::serialize_provider_payload(&payload).unwrap();
        assert!(bytes.len() as u64 > 8192);
        assert!(bytes.len() as u64 > live_serializer_payload_ceiling_bytes());
        assert!(crate::hard_budget::active_v3_authority().is_none());
    }
}
