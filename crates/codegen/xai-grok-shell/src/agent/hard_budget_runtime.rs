//! Credential-free resolved-config identity for armed v3.
//!
//! This module does not call `bind_actual`. It projects catalog fields that
//! survive model resolve, including `model_provider`, observes the selected
//! model's live loopback route core and packet bounds, and never copies `api_key`, env keys,
//! extra headers, or golden route/payload/tool fixtures.

use indexmap::IndexMap;
use serde::Serialize;

use super::config::ModelEntry;
use xai_grok_sampler::{
    ArmedV3LiveRouteCore, ArmedV3PacketBoundsObservation, ArmedV3ResolutionError,
    ArmedV3RouteCoreObservation, live_api_backend_label, live_auth_scheme_label,
    live_hard_budget_isolated_tool_ids, observed_managed_source_kind, observed_max_output_tokens,
};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CredentialFreeModelRow {
    catalog_key: String,
    model: String,
    model_provider: String,
    api_backend: String,
    auth_scheme: String,
    base_url: String,
}

/// Stable printable projection of resolved catalog identity. Empty when the
/// catalog has no rows. Secrets are omitted.
pub(crate) fn credential_free_model_projection(models: &IndexMap<String, ModelEntry>) -> Vec<u8> {
    if models.is_empty() {
        return Vec::new();
    }
    let mut keys: Vec<&String> = models.keys().collect();
    keys.sort();
    let rows: Vec<CredentialFreeModelRow> = keys
        .into_iter()
        .filter_map(|key| {
            let entry = models.get(key)?;
            Some(CredentialFreeModelRow {
                catalog_key: key.clone(),
                model: entry.info.model.clone(),
                model_provider: entry.model_provider.clone().unwrap_or_default(),
                api_backend: serde_json::to_value(&entry.info.api_backend)
                    .ok()
                    .and_then(|value| value.as_str().map(str::to_owned))
                    .unwrap_or_default(),
                auth_scheme: serde_json::to_value(&entry.info.auth_scheme)
                    .ok()
                    .and_then(|value| value.as_str().map(str::to_owned))
                    .unwrap_or_default(),
                base_url: entry.info.base_url.clone(),
            })
        })
        .collect();
    serde_json::to_vec(&rows).unwrap_or_default()
}

/// Source kind for the selected model only. Catalog-wide emptiness is not a
/// substitute, and this never invents `toml`.
///
/// Production `bind_actual` is still unauthorized; spawn only requires an
/// already-active authority.
#[allow(dead_code)]
pub(crate) fn selected_model_source_kind(entry: &ModelEntry) -> Option<&'static str> {
    observed_managed_source_kind(entry.model_provider.as_deref())
}

#[allow(dead_code)]
pub(crate) fn selected_model_max_output_tokens(entry: &ModelEntry) -> Option<u64> {
    observed_max_output_tokens(entry.info.max_completion_tokens)
}

/// Live loopback route core from the selected model. Does not copy golden
/// route-id, payload, or two-tool isolation, and does not call `bind_actual`.
#[allow(dead_code)]
pub(crate) fn observe_live_route_core(
    entry: &ModelEntry,
) -> Result<ArmedV3LiveRouteCore, ArmedV3ResolutionError> {
    ArmedV3LiveRouteCore::try_observe(ArmedV3RouteCoreObservation {
        provider_id: entry.model_provider.clone(),
        provider_facing_model: Some(entry.info.model.clone()),
        base_url: Some(entry.info.base_url.clone()),
        api_backend: Some(live_api_backend_label(&entry.info.api_backend).to_string()),
        auth_scheme: Some(live_auth_scheme_label(entry.info.auth_scheme).to_string()),
        allowed_tool_ids: Some(live_hard_budget_isolated_tool_ids()),
    })
}

/// Compose live route core with a frozen packet envelope. Conservative bound is
/// derived; golden 20000/1 envelopes that cannot cover the live ceiling refuse.
/// This does not call `bind_actual`.
#[allow(dead_code)]
pub(crate) fn observe_live_resolved_route(
    entry: &ModelEntry,
    allocation_token_ceiling: Option<u64>,
    max_model_calls: Option<u64>,
) -> Result<xai_grok_sampler::ResolvedRouteBoundV1, ArmedV3ResolutionError> {
    observe_live_route_core(entry)?.with_observed_packet_bounds(ArmedV3PacketBoundsObservation {
        max_output_tokens: selected_model_max_output_tokens(entry),
        allocation_token_ceiling,
        max_model_calls,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::config::{EndpointsConfig, ModelEntry};
    use xai_grok_sampler::{ResolvedConfigIdentityTracker, live_serializer_payload_ceiling_bytes};

    #[test]
    fn resolved_gateway_model_keeps_provider_and_omits_secrets() {
        let raw: toml::Value = toml::from_str(
            r#"
            [model_providers.gateway]
            base_url = "http://127.0.0.1:9/v1"
            api_key = "sk-must-not-appear"

            [model.via-gateway]
            model = "loopback-model"
            model_provider = "gateway"
            "#,
        )
        .unwrap();
        let cfg = crate::agent::config::Config::new_from_toml_cfg(&raw).unwrap();
        let resolved = crate::agent::config::resolve_model_list(&cfg, None);
        let entry = resolved.get("via-gateway").expect("resolved model");
        assert_eq!(entry.model_provider.as_deref(), Some("gateway"));
        assert_eq!(entry.api_key.as_deref(), Some("sk-must-not-appear"));

        let projection = credential_free_model_projection(&resolved);
        let text = String::from_utf8(projection.clone()).unwrap();
        assert!(text.contains("\"modelProvider\":\"gateway\""));
        assert!(text.contains("\"catalogKey\":\"via-gateway\""));
        assert!(!text.contains("sk-must-not-appear"));
        assert!(!text.contains("apiKey"));
        assert!(!text.contains("api_key"));

        let mut tracker = ResolvedConfigIdentityTracker::new();
        assert_eq!(tracker.observe(&projection), Some(1));
        assert_eq!(tracker.observe(&projection), Some(1));

        let mut drifted = resolved.clone();
        drifted.get_mut("via-gateway").unwrap().model_provider = Some("other".into());
        let drifted_projection = credential_free_model_projection(&drifted);
        assert_eq!(tracker.observe(&drifted_projection), Some(2));
    }

    #[test]
    fn selected_gateway_model_observes_live_route_core_not_golden() {
        let raw: toml::Value = toml::from_str(
            r#"
            [model_providers.gateway]
            base_url = "http://127.0.0.1:9/v1"
            api_key = "sk-must-not-appear"

            [model.via-gateway]
            model = "loopback-model"
            model_provider = "gateway"
            max_completion_tokens = 1024
            "#,
        )
        .unwrap();
        let cfg = crate::agent::config::Config::new_from_toml_cfg(&raw).unwrap();
        let resolved = crate::agent::config::resolve_model_list(&cfg, None);
        let entry = resolved.get("via-gateway").expect("resolved model");
        assert_eq!(
            selected_model_source_kind(entry),
            Some(xai_grok_sampler::RESOLVED_MANAGED_PROVIDER_SOURCE_KIND)
        );
        assert_eq!(selected_model_max_output_tokens(entry), Some(1024));

        let core = observe_live_route_core(entry).expect("loopback route core");
        assert!(core.route_id.starts_with("v3."));
        assert_ne!(core.route_id, "route-1");
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
        assert_eq!(
            core.clone()
                .with_packet_bounds(4096, 12_288, 20_000, 1)
                .unwrap_err(),
            xai_grok_sampler::ArmedV3ResolutionError::InvalidIdentity
        );
        assert_eq!(
            observe_live_resolved_route(entry, Some(20_000), Some(1)).unwrap_err(),
            xai_grok_sampler::ArmedV3ResolutionError::InvalidIdentity
        );
        let route = observe_live_resolved_route(entry, Some(80_000), Some(2))
            .expect("covering packet envelope");
        assert_eq!(route.conservative_request_bound_tokens, 65_536 + 1_024);
        assert_eq!(route.max_output_tokens, 1_024);
        assert_eq!(route.max_model_calls, 2);
        assert!(xai_grok_sampler::active_v3_authority().is_none());
    }

    #[test]
    fn catalog_without_model_provider_projects_empty_provider_field() {
        let entry = ModelEntry::fallback("plain", &EndpointsConfig::default());
        assert!(entry.model_provider.is_none());
        let mut models = IndexMap::new();
        models.insert("plain".into(), entry);
        let text = String::from_utf8(credential_free_model_projection(&models)).unwrap();
        assert!(text.contains("\"modelProvider\":\"\""));
        assert_eq!(selected_model_source_kind(&models["plain"]), None);
        assert_eq!(
            observe_live_route_core(&models["plain"]).unwrap_err(),
            xai_grok_sampler::ArmedV3ResolutionError::MissingObservedIdentity
        );
    }
}
