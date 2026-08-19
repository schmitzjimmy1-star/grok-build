//! Credential-free resolved-config identity for armed v3.
//!
//! This module observes catalog fields that survive model resolve, including
//! `model_provider`, the selected model's live loopback route core and packet
//! bounds, and binds v3 authority from a measured snapshot at bootstrap when
//! the armed environment carries a schema v3 manifest. It never invents
//! identity, copies `api_key`, env keys, extra headers, or golden route/payload/tool
//! fixtures, and does not call `sampling_config_for_model` or
//! `resolve_credentials`.

use indexmap::IndexMap;

use super::config::ModelEntry;
use xai_grok_sampler::{
    ArmedV3ResolutionError, ArmedV3ResolvedSnapshot, ArmedV3RouteCoreObservation,
    ArmedV3SnapshotObservation, HardTokenBudgetError, SamplerConfig, V3AuthorityBuilder,
    bind_and_install_v3_authority, claim_measured_candidate_identity, live_api_backend_label,
    live_auth_scheme_label, live_hard_budget_isolated_tool_ids, observed_managed_source_kind,
    observed_max_output_tokens,
};

#[derive(serde::Serialize)]
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
pub(crate) fn selected_model_source_kind(entry: &ModelEntry) -> Option<&'static str> {
    observed_managed_source_kind(entry.model_provider.as_deref())
}

pub(crate) fn selected_model_max_output_tokens(entry: &ModelEntry) -> Option<u64> {
    observed_max_output_tokens(entry.info.max_completion_tokens)
}

/// Live loopback route core from the selected model. Does not copy golden
/// route-id, payload, or two-tool isolation.
pub(crate) fn observe_live_route_core(
    entry: &ModelEntry,
) -> Result<xai_grok_sampler::ArmedV3LiveRouteCore, ArmedV3ResolutionError> {
    xai_grok_sampler::ArmedV3LiveRouteCore::try_observe(ArmedV3RouteCoreObservation {
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
pub(crate) fn observe_live_resolved_route(
    entry: &ModelEntry,
    allocation_token_ceiling: Option<u64>,
    max_model_calls: Option<u64>,
) -> Result<xai_grok_sampler::ResolvedRouteBoundV1, ArmedV3ResolutionError> {
    observe_live_route_core(entry)?.with_observed_packet_bounds(
        xai_grok_sampler::ArmedV3PacketBoundsObservation {
            max_output_tokens: selected_model_max_output_tokens(entry),
            allocation_token_ceiling,
            max_model_calls,
        },
    )
}

/// Credential-free sampler projection from catalog non-secrets only.
pub(crate) fn credential_free_sampler_config(entry: &ModelEntry) -> SamplerConfig {
    SamplerConfig {
        api_key: None,
        base_url: entry.info.base_url.clone(),
        model: entry.info.model.clone(),
        max_completion_tokens: entry.info.max_completion_tokens,
        api_backend: entry.info.api_backend.clone(),
        auth_scheme: entry.info.auth_scheme,
        extra_headers: IndexMap::new(),
        query_params: IndexMap::new(),
        env_http_headers: IndexMap::new(),
        max_retries: Some(0),
        supports_backend_search: false,
        ..SamplerConfig::default()
    }
}

/// Bind measured v3 authority when the armed environment carries a complete
/// schema v3 manifest. Legacy v1 manifests skip bind without failing bootstrap.
pub(crate) fn bind_measured_v3_authority_if_present(
    models: &IndexMap<String, ModelEntry>,
    current_model_id: &str,
    tracked_generation: Option<u64>,
) -> Result<(), String> {
    if !xai_grok_tools::util::hard_budget_environment_present() {
        return Ok(());
    }

    let builder = match V3AuthorityBuilder::from_env() {
        Ok(None) | Err(HardTokenBudgetError::IncompleteEnvironment) => return Ok(()),
        Err(HardTokenBudgetError::LegacyManifestRefused) => return Ok(()),
        Err(error) => return Err(error.to_string()),
        Ok(Some(builder)) => builder,
    };

    let entry = models.get(current_model_id).ok_or_else(|| {
        format!("selected model {current_model_id:?} is missing from resolved catalog")
    })?;

    let config_projection = credential_free_model_projection(models);
    let source_kind = selected_model_source_kind(entry)
        .ok_or_else(|| ArmedV3ResolutionError::MissingObservedIdentity.to_string())?
        .to_string();
    let managed_provider_id = entry
        .model_provider
        .clone()
        .filter(|provider| !provider.trim().is_empty())
        .ok_or_else(|| ArmedV3ResolutionError::MissingObservedIdentity.to_string())?;
    let route = observe_live_resolved_route(
        entry,
        Some(builder.allocation_token_ceiling()),
        Some(builder.max_model_calls()),
    )
    .map_err(|error| error.to_string())?;
    let sampler = credential_free_sampler_config(entry);

    let candidate = claim_measured_candidate_identity().map_err(|error| error.to_string())?;

    let snapshot = ArmedV3ResolvedSnapshot::try_resolve(ArmedV3SnapshotObservation {
        candidate: Some(candidate),
        source_kind: Some(source_kind),
        generation: tracked_generation,
        managed_provider_id: Some(managed_provider_id),
        config_projection: Some(config_projection),
        route: Some(route),
        catalog_key: Some(current_model_id.to_string()),
        sampler: Some(sampler),
    })
    .map_err(|error| error.to_string())?;

    bind_and_install_v3_authority(snapshot.binding().clone()).map_err(|error| error.to_string())?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::config::{EndpointsConfig, ModelEntry};
    use xai_grok_sampler::{
        CandidateIdentityV1, HardTokenAllocationContract, HardTokenRouteContract,
        HardTokenV3RuntimeBinding, ResolvedConfigIdentityTracker, active_v3_authority,
        discard_unclaimed_measured_candidate_identity, install_measured_candidate_identity,
        live_serializer_payload_ceiling_bytes, reset_active_v3_authority_for_test,
    };

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

    #[test]
    fn bind_measured_v3_authority_if_present_is_noop_without_env() {
        reset_active_v3_authority_for_test();
        discard_unclaimed_measured_candidate_identity();
        assert!(
            bind_measured_v3_authority_if_present(&IndexMap::new(), "via-gateway", None).is_ok()
        );
        assert!(active_v3_authority().is_none());
    }

    #[cfg(unix)]
    mod unix_tests {
        use super::*;
        use std::os::unix::fs::PermissionsExt;
        use std::path::{Path, PathBuf};

        use serial_test::serial;
        use xai_grok_sampler::{CampaignPolicyV3, HardTokenV3RuntimeBinding};

        struct EnvRestore {
            ledger: Option<std::ffi::OsString>,
            manifest: Option<std::ffi::OsString>,
            allocation: Option<std::ffi::OsString>,
        }

        impl Drop for EnvRestore {
            fn drop(&mut self) {
                unsafe {
                    match &self.ledger {
                        Some(value) => std::env::set_var("GROK_HARD_TOKEN_BUDGET_LEDGER", value),
                        None => std::env::remove_var("GROK_HARD_TOKEN_BUDGET_LEDGER"),
                    }
                    match &self.manifest {
                        Some(value) => std::env::set_var("GROK_HARD_TOKEN_BUDGET_MANIFEST", value),
                        None => std::env::remove_var("GROK_HARD_TOKEN_BUDGET_MANIFEST"),
                    }
                    match &self.allocation {
                        Some(value) => {
                            std::env::set_var("GROK_HARD_TOKEN_BUDGET_ALLOCATION", value)
                        }
                        None => std::env::remove_var("GROK_HARD_TOKEN_BUDGET_ALLOCATION"),
                    }
                }
            }
        }

        struct TestCleanup;

        impl Drop for TestCleanup {
            fn drop(&mut self) {
                reset_active_v3_authority_for_test();
                discard_unclaimed_measured_candidate_identity();
            }
        }

        fn private_dir(label: &str) -> PathBuf {
            let path = std::env::temp_dir().join(format!(
                "grok-shell-hard-budget-{label}-{}",
                uuid::Uuid::new_v4()
            ));
            std::fs::create_dir(&path).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
            path
        }

        fn gateway_catalog() -> IndexMap<String, ModelEntry> {
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
            crate::agent::config::resolve_model_list(&cfg, None)
        }

        fn measured_candidate() -> CandidateIdentityV1 {
            CandidateIdentityV1 {
                cli_build: "1.0.5 (003f955)".into(),
                binary_sha256: "a".repeat(64),
                source_commit_sha: "b".repeat(40),
            }
        }

        fn observed_gateway_binding(
            resolved: &IndexMap<String, ModelEntry>,
            generation: u64,
            envelope_ceiling: u64,
            envelope_calls: u64,
            candidate: CandidateIdentityV1,
        ) -> HardTokenV3RuntimeBinding {
            let entry = resolved.get("via-gateway").expect("gateway model");
            let projection = credential_free_model_projection(resolved);
            let route =
                observe_live_resolved_route(entry, Some(envelope_ceiling), Some(envelope_calls))
                    .expect("live route");
            let sampler = credential_free_sampler_config(entry);
            let source_kind = selected_model_source_kind(entry)
                .expect("managed provider source kind")
                .to_string();
            let managed_provider_id = entry.model_provider.clone().expect("model provider");
            let snapshot = ArmedV3ResolvedSnapshot::try_resolve(ArmedV3SnapshotObservation {
                candidate: Some(candidate),
                source_kind: Some(source_kind),
                generation: Some(generation),
                managed_provider_id: Some(managed_provider_id),
                config_projection: Some(projection),
                route: Some(route),
                catalog_key: Some("via-gateway".into()),
                sampler: Some(sampler),
            })
            .expect("observed snapshot");
            snapshot.binding().clone()
        }

        fn write_v3_manifest(
            dir: &Path,
            binding: &HardTokenV3RuntimeBinding,
            allocation_id: &str,
        ) -> PathBuf {
            let path = dir.join("manifest-v3.json");
            let manifest = serde_json::json!({
                "schemaVersion": 3,
                "campaignId": "campaign-v3",
                "campaignPolicy": CampaignPolicyV3::exact(),
                "candidateExpectation": binding.candidate,
                "configExpectation": binding.config_identity,
                "allocations": [{
                    "id": allocation_id,
                    "packetId": "packet-v3",
                    "promptSha256": "e".repeat(64),
                    "tokenCeiling": binding.route.allocation_token_ceiling,
                    "maxModelCalls": binding.route.max_model_calls,
                    "routeExpectation": binding.route,
                }]
            });
            std::fs::write(&path, serde_json::to_vec(&manifest).unwrap()).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            path
        }

        fn v1_route(model: &str, bound: u64) -> HardTokenRouteContract {
            HardTokenRouteContract {
                model: model.into(),
                endpoint_sha256: "a".repeat(64),
                api_backend: "responses".into(),
                request_bound_tokens: bound,
                max_payload_bytes: bound.saturating_sub(100),
                max_output_tokens: 100,
                bound_provenance_sha256: "b".repeat(64),
            }
        }

        fn v1_allocation(id: &str, model: &str, bound: u64) -> HardTokenAllocationContract {
            HardTokenAllocationContract {
                id: id.into(),
                packet_id: format!("packet-{id}"),
                prompt_sha256: "c".repeat(64),
                token_ceiling: 1_000,
                max_model_calls: 2,
                route: v1_route(model, bound),
            }
        }

        fn write_v1_manifest(
            dir: &Path,
            ceiling_tokens: u64,
            allocations: Vec<HardTokenAllocationContract>,
        ) -> PathBuf {
            let path = dir.join("manifest.json");
            let manifest = serde_json::json!({
                "version": 1,
                "campaignId": "campaign",
                "ceilingTokens": ceiling_tokens,
                "allocations": allocations,
            });
            std::fs::write(&path, serde_json::to_vec(&manifest).unwrap()).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            path
        }

        #[test]
        #[serial]
        fn bind_measured_v3_authority_if_present_skips_legacy_v1_manifest() {
            let _cleanup = TestCleanup;
            let dir = private_dir("skip-v1");
            let mut live = v1_allocation("packet-a", "model-a", 600);
            live.token_ceiling = 3_000_000;
            live.max_model_calls = 1;
            let manifest = write_v1_manifest(&dir, 4_000_000, vec![live]);
            let ledger = dir.join("ledger.json");
            let _env = EnvRestore {
                ledger: std::env::var_os("GROK_HARD_TOKEN_BUDGET_LEDGER"),
                manifest: std::env::var_os("GROK_HARD_TOKEN_BUDGET_MANIFEST"),
                allocation: std::env::var_os("GROK_HARD_TOKEN_BUDGET_ALLOCATION"),
            };
            unsafe {
                std::env::set_var("GROK_HARD_TOKEN_BUDGET_LEDGER", &ledger);
                std::env::set_var("GROK_HARD_TOKEN_BUDGET_MANIFEST", &manifest);
                std::env::set_var("GROK_HARD_TOKEN_BUDGET_ALLOCATION", "packet-a");
            }

            let candidate = measured_candidate();
            install_measured_candidate_identity(candidate.clone()).unwrap();

            assert!(
                bind_measured_v3_authority_if_present(&IndexMap::new(), "via-gateway", Some(1))
                    .is_ok()
            );
            assert!(active_v3_authority().is_none());
            assert_eq!(claim_measured_candidate_identity().unwrap(), candidate);

            std::fs::remove_dir_all(dir).unwrap();
        }

        #[test]
        #[serial]
        fn bind_measured_v3_authority_if_present_refuses_missing_measured_candidate() {
            let _cleanup = TestCleanup;
            let resolved = gateway_catalog();
            let binding = observed_gateway_binding(&resolved, 1, 80_000, 2, measured_candidate());
            let dir = private_dir("missing-candidate");
            let manifest = write_v3_manifest(&dir, &binding, "allocation-v3");
            let ledger = dir.join("ledger.json");
            let _env = EnvRestore {
                ledger: std::env::var_os("GROK_HARD_TOKEN_BUDGET_LEDGER"),
                manifest: std::env::var_os("GROK_HARD_TOKEN_BUDGET_MANIFEST"),
                allocation: std::env::var_os("GROK_HARD_TOKEN_BUDGET_ALLOCATION"),
            };
            unsafe {
                std::env::set_var("GROK_HARD_TOKEN_BUDGET_LEDGER", &ledger);
                std::env::set_var("GROK_HARD_TOKEN_BUDGET_MANIFEST", &manifest);
                std::env::set_var("GROK_HARD_TOKEN_BUDGET_ALLOCATION", "allocation-v3");
            }

            let error = bind_measured_v3_authority_if_present(&resolved, "via-gateway", Some(1))
                .unwrap_err();
            assert!(error.contains("measured candidate identity is not installed"));
            assert!(active_v3_authority().is_none());

            std::fs::remove_dir_all(dir).unwrap();
        }

        #[test]
        #[serial]
        fn bind_measured_v3_authority_if_present_binds_matching_measured_snapshot_once() {
            let _cleanup = TestCleanup;
            let resolved = gateway_catalog();
            let candidate = measured_candidate();
            let binding = observed_gateway_binding(&resolved, 1, 80_000, 2, candidate.clone());
            let dir = private_dir("bind-once");
            let manifest = write_v3_manifest(&dir, &binding, "allocation-v3");
            let ledger = dir.join("ledger.json");
            let _env = EnvRestore {
                ledger: std::env::var_os("GROK_HARD_TOKEN_BUDGET_LEDGER"),
                manifest: std::env::var_os("GROK_HARD_TOKEN_BUDGET_MANIFEST"),
                allocation: std::env::var_os("GROK_HARD_TOKEN_BUDGET_ALLOCATION"),
            };
            unsafe {
                std::env::set_var("GROK_HARD_TOKEN_BUDGET_LEDGER", &ledger);
                std::env::set_var("GROK_HARD_TOKEN_BUDGET_MANIFEST", &manifest);
                std::env::set_var("GROK_HARD_TOKEN_BUDGET_ALLOCATION", "allocation-v3");
            }

            install_measured_candidate_identity(candidate.clone()).unwrap();
            bind_measured_v3_authority_if_present(&resolved, "via-gateway", Some(1)).unwrap();
            assert!(active_v3_authority().is_some());

            let projection =
                String::from_utf8(credential_free_model_projection(&resolved)).unwrap();
            assert!(!projection.contains("sk-must-not-appear"));
            assert!(!projection.contains("apiKey"));
            let sampler = credential_free_sampler_config(resolved.get("via-gateway").unwrap());
            assert!(sampler.api_key.is_none());

            install_measured_candidate_identity(candidate).unwrap();
            assert!(matches!(
                bind_measured_v3_authority_if_present(&resolved, "via-gateway", Some(1)),
                Err(error) if error.contains("hard-token-budget v3 authority is already active in this process")
            ));

            std::fs::remove_dir_all(dir).unwrap();
        }
    }
}
