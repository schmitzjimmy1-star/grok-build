//! Actor-internal state.
//!
//! All fields are touched only from the actor task, so no mutex /
//! atomic synchronization is needed -- the actor's command-loop
//! serialization gives us a "single-threaded with shared state"
//! discipline matching the hunk-tracker pattern.

use std::collections::HashMap;

use tokio_util::sync::CancellationToken;

use crate::client::SamplingClient;
use crate::config::{RetryPolicy, SamplerConfig};
use crate::types::RequestId;

/// In-flight request bookkeeping.
///
/// `cancel_token` is owned by the actor (cloned into the spawned
/// per-request task). The completion oneshot is moved into the
/// per-request task at spawn time and is therefore not stored here.
pub(crate) struct ActiveRequest {
    pub(crate) cancel_token: CancellationToken,
}

/// Actor-owned state.
pub(crate) struct ActorState {
    pub(crate) active_requests: HashMap<RequestId, ActiveRequest>,
    pub(crate) config: SamplerConfig,
    pub(crate) retry_policy: RetryPolicy,
    /// One lazily constructed armed client. Unarmed requests never populate
    /// this; a second armed request clones it instead of reclaiming the
    /// one-shot credential.
    pub(crate) armed_client: Option<SamplingClient>,
    pub(crate) armed_config: Option<SamplerConfig>,
}

impl ActorState {
    pub(crate) fn new(config: SamplerConfig, retry_policy: RetryPolicy) -> Self {
        Self {
            active_requests: HashMap::new(),
            config,
            retry_policy,
            armed_client: None,
            armed_config: None,
        }
    }

    /// Register a newly-spawned request. Returns the previous entry if
    /// the same `request_id` was already in flight (callers should
    /// cancel the previous token before overwriting).
    pub(crate) fn register(
        &mut self,
        request_id: RequestId,
        active: ActiveRequest,
    ) -> Option<ActiveRequest> {
        self.active_requests.insert(request_id, active)
    }

    /// Remove a request from the active set without cancelling its
    /// token. Used by the cleanup signal sent from per-request tasks
    /// when they exit normally.
    pub(crate) fn remove(&mut self, request_id: &RequestId) -> Option<ActiveRequest> {
        self.active_requests.remove(request_id)
    }

    /// Cancel and remove an in-flight request.
    pub(crate) fn cancel(&mut self, request_id: &RequestId) -> bool {
        if let Some(active) = self.active_requests.remove(request_id) {
            active.cancel_token.cancel();
            true
        } else {
            false
        }
    }

    /// Replace the default config. The next request submitted without
    /// an override will use this. Armed v3 ignores route-changing updates
    /// so a later model/host switch cannot replace the bound client.
    pub(crate) fn update_config(&mut self, config: SamplerConfig) {
        if self.armed_client.is_some()
            && self
                .armed_config
                .as_ref()
                .is_some_and(|armed| armed_route_drifted(armed, &config))
        {
            tracing::warn!("armed v3 ignored a route-changing sampler config update");
            return;
        }
        self.config = config;
    }
}

pub(crate) fn armed_route_drifted(bound: &SamplerConfig, incoming: &SamplerConfig) -> bool {
    bound.base_url != incoming.base_url
        || bound.model != incoming.model
        || bound.api_backend != incoming.api_backend
        || bound.auth_scheme != incoming.auth_scheme
        || bound.api_key.is_some() != incoming.api_key.is_some()
        || bound.extra_headers != incoming.extra_headers
        || bound.query_params != incoming.query_params
        || bound.env_http_headers != incoming.env_http_headers
}

pub(crate) fn acquire_request_client(
    state: &mut ActorState,
    config: SamplerConfig,
) -> Result<SamplingClient, xai_grok_sampling_types::SamplingError> {
    if crate::hard_budget::active_v3_authority().is_some() {
        if let Some(client) = &state.armed_client {
            if state
                .armed_config
                .as_ref()
                .is_some_and(|bound| armed_route_drifted(bound, &config))
            {
                return Err(xai_grok_sampling_types::SamplingError::InvalidConfiguration(
                    "armed v3 rejects route-changing sampler updates",
                ));
            }
            return Ok(client.clone());
        }
        let client = SamplingClient::from_process_config(config.clone())?;
        state.armed_client = Some(client.clone());
        state.armed_config = Some(config);
        return Ok(client);
    }
    SamplingClient::from_process_config(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::{ApiBackend, SamplingClient};
    use indexmap::IndexMap;

    /// Minimal config builder for tests in this module.
    fn cfg() -> SamplerConfig {
        SamplerConfig {
            api_key: None,
            base_url: "https://example.test".into(),
            model: "test-model".into(),
            max_completion_tokens: None,
            temperature: None,
            top_p: None,
            api_backend: ApiBackend::ChatCompletions,
            auth_scheme: Default::default(),
            extra_headers: IndexMap::new(),
            extra_response_includes: Vec::new(),
            query_params: IndexMap::new(),
            env_http_headers: IndexMap::new(),
            context_window: 8192,
            force_http1: false,
            max_retries: None,
            stream_tool_calls: false,
            idle_timeout_secs: None,
            reasoning_effort: None,
            origin_client: None,
            client_identifier: None,
            deployment_id: None,
            user_id: None,
            client_version: None,
            attribution_callback: None,
            bearer_resolver: None,
            supports_backend_search: false,
            compactions_remaining: None,
            compaction_at_tokens: None,
            doom_loop_recovery: None,
            header_injector: None,
        }
    }

    #[test]
    fn cancel_unknown_request_returns_false() {
        let mut state = ActorState::new(cfg(), RetryPolicy::default());
        assert!(!state.cancel(&RequestId::from("unknown")));
    }

    #[test]
    fn register_then_cancel_removes() {
        let mut state = ActorState::new(cfg(), RetryPolicy::default());
        let id = RequestId::from("req-1");
        state.register(
            id.clone(),
            ActiveRequest {
                cancel_token: CancellationToken::new(),
            },
        );
        assert_eq!(state.active_requests.len(), 1);
        assert!(state.cancel(&id));
        assert_eq!(state.active_requests.len(), 0);
    }

    #[test]
    fn register_returns_previous_when_same_id() {
        let mut state = ActorState::new(cfg(), RetryPolicy::default());
        let id = RequestId::from("req-1");
        let first = ActiveRequest {
            cancel_token: CancellationToken::new(),
        };
        let second = ActiveRequest {
            cancel_token: CancellationToken::new(),
        };
        assert!(state.register(id.clone(), first).is_none());
        assert!(state.register(id.clone(), second).is_some());
    }

    #[cfg(unix)]
    #[test]
    fn armed_acquire_caches_one_client_and_rejects_route_drift() {
        use crate::armed_credential::{ArmedCredentialOwner, install_armed_credential_owner};
        use crate::client::exact_loopback_endpoint_sha256;
        use crate::config::AuthScheme;
        use crate::hard_budget::v3_test_support;
        use zeroize::Zeroizing;

        let _guard = v3_test_support::lock();
        let dir = v3_test_support::private_dir("actor-armed-cache");
        let loopback = "http://127.0.0.1:9/v1".to_string();
        let mut route = v3_test_support::route();
        route.api_backend = "responses".into();
        route.provider_facing_model = "test-model".into();
        route.endpoint_sha256 = exact_loopback_endpoint_sha256(&loopback, "responses").unwrap();
        install_armed_credential_owner(
            ArmedCredentialOwner::from_receiver(Zeroizing::new(b"fake-sentinel".to_vec())).unwrap(),
        )
        .unwrap();
        let _authority = v3_test_support::activate_with_route(&dir, route);
        let cfg = SamplerConfig {
            base_url: loopback.clone(),
            model: "test-model".into(),
            api_backend: ApiBackend::Responses,
            auth_scheme: AuthScheme::Bearer,
            max_retries: Some(0),
            ..SamplerConfig::default()
        };
        let mut state = ActorState::new(cfg.clone(), RetryPolicy::default());
        let first = acquire_request_client(&mut state, cfg.clone()).expect("first armed client");
        assert!(first.hard_token_budget_enabled());
        let _second = acquire_request_client(&mut state, cfg.clone()).expect("cached clone");
        assert!(SamplingClient::from_process_config(cfg.clone()).is_err());

        let mut drifted = cfg.clone();
        drifted.base_url = "http://127.0.0.1:8/v1".into();
        assert!(acquire_request_client(&mut state, drifted.clone()).is_err());
        state.update_config(drifted);
        assert_eq!(state.config.base_url, loopback);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
