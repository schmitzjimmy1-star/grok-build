//! GrokBuild-fork hard-budget capability and status projection.
//!
//! This is deliberately not an `x.ai/*` method: the governor is a downstream
//! GrokBuild extension, not an upstream xAI capability. The sampler remains the
//! enforcement owner; ACP only exposes credential-free typed state.

use agent_client_protocol as acp;
use serde::Serialize;

use super::{ExtResult, to_raw_response};

pub const METHOD: &str = "com.grokbuild/budget/status";
pub const CAPABILITY_KEY: &str = "com.grokbuild/hardTokenBudget";
pub const CAPABILITY_VERSION: u32 = 1;

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
    cancel_conservative: bool,
    crash_conservative: bool,
    no_automatic_retry: bool,
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
        cancel_conservative: true,
        crash_conservative: true,
        no_automatic_retry: true,
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
            false,
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
    if args.method.as_ref() != METHOD {
        return Err(acp::Error::method_not_found());
    }
    to_raw_response(&capability())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_is_honestly_namespaced_and_unarmed_by_default() {
        let value = capability_value();
        assert_eq!(CAPABILITY_KEY, "com.grokbuild/hardTokenBudget");
        assert_eq!(value["capabilityVersion"], 1);
        assert_eq!(value["armed"], false);
        assert_eq!(value["enforcementPoint"], "sampler-pre-dispatch");
        assert_eq!(value["noAutomaticRetry"], true);
    }
}
