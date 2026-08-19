//! GrokBuild-fork hard-budget capability and status projection.
//!
//! This is deliberately not an `x.ai/*` method: the governor is a downstream
//! GrokBuild extension, not an upstream xAI capability. The sampler remains the
//! enforcement owner; ACP only exposes credential-free typed state.

use agent_client_protocol as acp;
use serde::Serialize;

use super::{ExtResult, to_raw_response};

pub const METHOD: &str = "com.grokbuild/budget/status";
pub const RECEIPTS_METHOD: &str = "com.grokbuild/budget/receipts";
pub const CAPABILITY_KEY: &str = "com.grokbuild/hardTokenBudget";
pub const CAPABILITY_VERSION: u32 = 3;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct BudgetCapability {
    capability_version: u32,
    armed: bool,
    configuration_valid: bool,
    enforcement_point: &'static str,
    ledger_version: u32,
    bound_method_version: u32,
    durable: bool,
    process_shared: bool,
    receipt_projection: bool,
    cancel_conservative: bool,
    crash_conservative: bool,
    no_automatic_retry: bool,
    sampler_transport_retries_disabled: bool,
    auth_provider_helpers_disabled: bool,
    terminal_disabled: bool,
    external_mcp_disabled: bool,
    hooks_disabled: bool,
    plugins_disabled: bool,
    lsp_disabled: bool,
    workflows_disabled: bool,
    scheduler_disabled: bool,
    protected_authority_fs: bool,
    workspace_fs_confined: bool,
    allowed_tool_ids: Vec<String>,
    cli_build: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    v3_authority: Option<V3AuthorityProjection>,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<xai_grok_sampler::HardTokenBudgetStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    route: Option<xai_grok_sampler::HardTokenRouteContract>,
    #[serde(skip_serializing_if = "Option::is_none")]
    allocation: Option<xai_grok_sampler::HardTokenAllocationContract>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<&'static str>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct V3AuthorityProjection {
    authority_version: u32,
    provenance: xai_grok_sampler::HardTokenBoundProvenanceV1,
    provenance_sha256: String,
}

fn v3_authority_from_provenance(
    provenance: &xai_grok_sampler::HardTokenBoundProvenanceV1,
) -> Option<V3AuthorityProjection> {
    Some(V3AuthorityProjection {
        authority_version: CAPABILITY_VERSION,
        provenance: provenance.clone(),
        provenance_sha256: provenance.sha256().ok()?,
    })
}

pub fn capability_value() -> serde_json::Value {
    serde_json::to_value(capability()).unwrap_or_else(|_| {
        serde_json::json!({
            "capabilityVersion": CAPABILITY_VERSION,
            "armed": false,
            "configurationValid": false,
            "error": "serialization-failed"
        })
    })
}

fn capability() -> BudgetCapability {
    let base = |armed: bool,
                configuration_valid: bool,
                status: Option<xai_grok_sampler::HardTokenBudgetStatus>,
                route: Option<xai_grok_sampler::HardTokenRouteContract>,
                allocation: Option<xai_grok_sampler::HardTokenAllocationContract>,
                provenance: Option<xai_grok_sampler::HardTokenBoundProvenanceV1>,
                error: Option<&'static str>| BudgetCapability {
        capability_version: CAPABILITY_VERSION,
        armed,
        configuration_valid,
        enforcement_point: "sampler-pre-dispatch",
        ledger_version: 4,
        bound_method_version: if provenance.is_some() {
            3
        } else if armed {
            1
        } else {
            3
        },
        durable: true,
        process_shared: true,
        receipt_projection: armed,
        cancel_conservative: true,
        crash_conservative: true,
        no_automatic_retry: provenance
            .as_ref()
            .is_some_and(|value| value.route.retry_disabled),
        sampler_transport_retries_disabled: provenance.as_ref().map_or(armed, |value| {
            value
                .route
                .tool_isolation
                .sampler_transport_retries_disabled
        }),
        auth_provider_helpers_disabled: provenance.as_ref().map_or(armed, |value| {
            value.route.tool_isolation.auth_provider_helpers_disabled
        }),
        terminal_disabled: provenance
            .as_ref()
            .map_or(armed, |value| value.route.tool_isolation.terminal_disabled),
        external_mcp_disabled: provenance.as_ref().map_or(armed, |value| {
            value.route.tool_isolation.external_mcp_disabled
        }),
        hooks_disabled: provenance
            .as_ref()
            .map_or(armed, |value| value.route.tool_isolation.hooks_disabled),
        plugins_disabled: provenance
            .as_ref()
            .map_or(armed, |value| value.route.tool_isolation.plugins_disabled),
        lsp_disabled: provenance
            .as_ref()
            .map_or(armed, |value| value.route.tool_isolation.lsp_disabled),
        workflows_disabled: provenance
            .as_ref()
            .map_or(armed, |value| value.route.tool_isolation.workflows_disabled),
        scheduler_disabled: provenance
            .as_ref()
            .map_or(armed, |value| value.route.tool_isolation.scheduler_disabled),
        protected_authority_fs: provenance.as_ref().map_or(armed, |value| {
            value.route.tool_isolation.protected_authority_fs
        }),
        workspace_fs_confined: provenance.as_ref().map_or(armed, |value| {
            value.route.tool_isolation.workspace_fs_confined
        }),
        allowed_tool_ids: provenance
            .as_ref()
            .map(|value| value.route.tool_isolation.allowed_tool_ids.clone())
            .unwrap_or_else(|| {
                if armed {
                    vec![
                        "GrokBuild:read_file".into(),
                        "GrokBuild:task".into(),
                        "GrokBuild:get_task_output".into(),
                        "GrokBuild:wait_tasks".into(),
                        "GrokBuild:kill_task".into(),
                    ]
                } else {
                    Vec::new()
                }
            }),
        cli_build: xai_grok_version::full_version().to_string(),
        v3_authority: provenance.as_ref().and_then(v3_authority_from_provenance),
        status,
        route,
        allocation,
        error,
    };
    match xai_grok_sampler::active_v3_authority() {
        Some(authority) => match authority.budget().status() {
            Ok(status) => base(
                true,
                true,
                Some(status),
                authority.budget().route_contract().cloned(),
                authority.budget().allocation_contract().cloned(),
                Some(authority.provenance().clone()),
                None,
            ),
            Err(_) => base(
                true,
                false,
                None,
                authority.budget().route_contract().cloned(),
                authority.budget().allocation_contract().cloned(),
                Some(authority.provenance().clone()),
                Some("status-unavailable"),
            ),
        },
        None => match xai_grok_sampler::HardTokenBudget::from_env() {
            Ok(Some(budget)) => match budget.status() {
                Ok(status) => base(
                    true,
                    true,
                    Some(status),
                    budget.route_contract().cloned(),
                    budget.allocation_contract().cloned(),
                    None,
                    None,
                ),
                Err(_) => base(
                    true,
                    false,
                    None,
                    None,
                    None,
                    None,
                    Some("status-unavailable"),
                ),
            },
            Ok(None) => base(false, true, None, None, None, None, None),
            Err(xai_grok_sampler::HardTokenBudgetError::ActiveAuthorityUnavailable) => base(
                false,
                false,
                None,
                None,
                None,
                None,
                Some("authority-not-active"),
            ),
            Err(_) if xai_grok_tools::util::hard_budget_environment_present() => base(
                false,
                false,
                None,
                None,
                None,
                None,
                Some("configuration-invalid"),
            ),
            Err(_) => base(false, true, None, None, None, None, None),
        },
    }
}

#[tracing::instrument(skip_all, fields(method = %args.method))]
pub async fn handle(args: &acp::ExtRequest) -> ExtResult {
    match args.method.as_ref() {
        METHOD => to_raw_response(&capability()),
        RECEIPTS_METHOD => {
            let query: xai_grok_sampler::HardTokenReceiptQuery =
                serde_json::from_str(args.params.get()).map_err(|_| {
                    acp::Error::invalid_params().data(
                    "receipt query must bind campaign, manifest, allocation, packet, and baseline",
                )
                })?;
            let budget = if let Some(authority) = xai_grok_sampler::active_v3_authority() {
                authority.budget().clone()
            } else {
                xai_grok_sampler::HardTokenBudget::from_env()
                    .map_err(|_| {
                        acp::Error::invalid_request().data("hard-token budget is unavailable")
                    })?
                    .ok_or_else(|| {
                        acp::Error::invalid_request().data("hard-token budget is not armed")
                    })?
            };
            let snapshot = budget.receipts(&query).map_err(|error| match error {
                xai_grok_sampler::HardTokenBudgetError::ReceiptContractMismatch => {
                    acp::Error::invalid_request().data(
                        "receipt query does not match the immutable hard-token budget contract",
                    )
                }
                xai_grok_sampler::HardTokenBudgetError::ReceiptBaselineInvalid => {
                    acp::Error::invalid_request().data(
                        "receipt baseline is invalid for the current hard-token budget ledger",
                    )
                }
                _ => {
                    acp::Error::invalid_request().data("hard-token budget receipts are unavailable")
                }
            })?;
            to_raw_response(&snapshot)
        }
        _ => Err(acp::Error::method_not_found()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_is_honestly_namespaced_and_unarmed_by_default() {
        let value = capability_value();
        assert_eq!(CAPABILITY_KEY, "com.grokbuild/hardTokenBudget");
        assert_eq!(value["capabilityVersion"], 3);
        assert_eq!(value["armed"], false);
        assert_eq!(value["enforcementPoint"], "sampler-pre-dispatch");
        assert_eq!(value["noAutomaticRetry"], false);
        assert_eq!(value["terminalDisabled"], false);
        assert_eq!(value["externalMcpDisabled"], false);
    }

    #[test]
    fn capability_stays_unarmed_when_budget_env_is_present_without_active_authority() {
        struct EnvRestore(Option<std::ffi::OsString>);
        impl Drop for EnvRestore {
            fn drop(&mut self) {
                unsafe {
                    match &self.0 {
                        Some(value) => std::env::set_var("GROK_HARD_TOKEN_BUDGET_LEDGER", value),
                        None => std::env::remove_var("GROK_HARD_TOKEN_BUDGET_LEDGER"),
                    }
                }
            }
        }
        let _env = EnvRestore(std::env::var_os("GROK_HARD_TOKEN_BUDGET_LEDGER"));
        unsafe {
            std::env::set_var(
                "GROK_HARD_TOKEN_BUDGET_LEDGER",
                "/tmp/grokbuild-v3-unregistered",
            );
        }
        let value = capability_value();
        assert_eq!(value["armed"], serde_json::json!(false));
        assert_eq!(value["configurationValid"], serde_json::json!(false));
        assert_eq!(value["error"], "configuration-invalid");
        assert!(value.get("v3Authority").is_none() || value["v3Authority"].is_null());
        assert!(value.get("provenance").is_none() || value["provenance"].is_null());
        assert!(value.get("campaignPolicy").is_none() || value["campaignPolicy"].is_null());
        assert!(value.get("provenanceSha256").is_none() || value["provenanceSha256"].is_null());
    }

    #[test]
    fn v3_authority_projection_is_exactly_three_nested_fields() {
        let provenance = xai_grok_sampler::HardTokenBoundProvenanceV1::from_canonical_json(
            br#"{"allocationId":"allocation-1","campaignId":"campaign-v3","campaignPolicy":{"absoluteTokenCeiling":20000000,"allocatableTokenCeiling":19000000,"schemaVersion":3,"unreachableReserveTokens":1000000},"candidate":{"binarySha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","cliBuild":"1.0.5 (003f955)","sourceCommitSha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},"configIdentity":{"configProjectionSha256":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","generation":7,"managedProviderId":"openrouter","sourceKind":"resolved-managed-provider"},"route":{"allocationTokenCeiling":20000,"apiBackend":"responses","authScheme":"bearer","conservativeRequestBoundTokens":12288,"credentialTransport":"fd_v1","endpointSha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","maxFinalSerializedPayloadBytes":8192,"maxModelCalls":1,"maxOutputTokens":4096,"multimodalForbidden":true,"providerFacingModel":"openai/gpt-4.1-mini","providerId":"openrouter","redirectDisabled":true,"remoteContextForbidden":true,"retryDisabled":true,"routeId":"route-1","textOnly":true,"toolIsolation":{"allowedToolIds":["GrokBuild:read_file","GrokBuild:task"],"authProviderHelpersDisabled":true,"externalMcpDisabled":true,"hooksDisabled":true,"lspDisabled":true,"pluginsDisabled":true,"protectedAuthorityFs":true,"samplerTransportRetriesDisabled":true,"schedulerDisabled":true,"terminalDisabled":true,"workflowsDisabled":true,"workspaceFsConfined":true}},"schemaVersion":1,"serializerVersion":1}"#,
        )
        .unwrap();
        let projection = v3_authority_from_provenance(&provenance).unwrap();
        let value = serde_json::to_value(&projection).unwrap();
        let object = value.as_object().unwrap();
        assert_eq!(
            object.keys().collect::<Vec<_>>(),
            vec!["authorityVersion", "provenance", "provenanceSha256"]
        );
        assert_eq!(value["authorityVersion"], 3);
        assert_eq!(
            value["provenanceSha256"],
            "5052a5285a35ea96151340259475a69351ed162c8308a8f2166b453a5720f950"
        );
        assert!(value.get("provenanceCanonicalJson").is_none());
        assert!(value.get("authHeaderNames").is_none());
        let default = capability_value();
        assert!(default.get("v3Authority").is_none() || default["v3Authority"].is_null());
        assert!(default.get("provenance").is_none() || default["provenance"].is_null());
    }
}
