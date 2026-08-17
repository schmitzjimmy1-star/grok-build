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
pub const CAPABILITY_VERSION: u32 = 2;

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
    allowed_tool_ids: &'static [&'static str],
    cli_build: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<xai_grok_sampler::HardTokenBudgetStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    route: Option<xai_grok_sampler::HardTokenRouteContract>,
    #[serde(skip_serializing_if = "Option::is_none")]
    allocation: Option<xai_grok_sampler::HardTokenAllocationContract>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<&'static str>,
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
    let base = |armed, configuration_valid, status, route, allocation, error| BudgetCapability {
        capability_version: CAPABILITY_VERSION,
        armed,
        configuration_valid,
        enforcement_point: "sampler-pre-dispatch",
        ledger_version: 3,
        bound_method_version: 1,
        durable: true,
        process_shared: true,
        receipt_projection: armed,
        cancel_conservative: true,
        crash_conservative: true,
        // Retained for schema compatibility. The fork proves sampler transport
        // retries are disabled, not that every shell-level auxiliary sample is
        // globally impossible.
        no_automatic_retry: false,
        sampler_transport_retries_disabled: armed,
        auth_provider_helpers_disabled: armed,
        terminal_disabled: armed,
        external_mcp_disabled: armed,
        hooks_disabled: armed,
        plugins_disabled: armed,
        lsp_disabled: armed,
        workflows_disabled: armed,
        scheduler_disabled: armed,
        protected_authority_fs: armed,
        workspace_fs_confined: armed,
        allowed_tool_ids: if armed {
            &[
                "GrokBuild:read_file",
                "GrokBuild:task",
                "GrokBuild:get_task_output",
                "GrokBuild:wait_tasks",
                "GrokBuild:kill_task",
            ]
        } else {
            &[]
        },
        cli_build: xai_grok_version::full_version().to_string(),
        status,
        route,
        allocation,
        error,
    };
    match xai_grok_sampler::HardTokenBudget::from_env() {
        Ok(None) => base(false, true, None, None, None, None),
        Ok(Some(budget)) => match budget.status() {
            Ok(status) => base(
                true,
                true,
                Some(status),
                budget.route_contract().cloned(),
                budget.allocation_contract().cloned(),
                None,
            ),
            Err(_) => base(true, false, None, None, None, Some("status-unavailable")),
        },
        Err(_) => base(
            xai_grok_tools::util::hard_budget_environment_present(),
            false,
            None,
            None,
            None,
            Some("configuration-invalid"),
        ),
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
            let budget = xai_grok_sampler::HardTokenBudget::from_env()
                .map_err(|_| {
                    acp::Error::invalid_request().data("hard-token budget is unavailable")
                })?
                .ok_or_else(|| {
                    acp::Error::invalid_request().data("hard-token budget is not armed")
                })?;
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
        assert_eq!(value["capabilityVersion"], 2);
        assert_eq!(value["armed"], false);
        assert_eq!(value["enforcementPoint"], "sampler-pre-dispatch");
        assert_eq!(value["noAutomaticRetry"], false);
        assert_eq!(value["terminalDisabled"], false);
        assert_eq!(value["externalMcpDisabled"], false);
    }
}
