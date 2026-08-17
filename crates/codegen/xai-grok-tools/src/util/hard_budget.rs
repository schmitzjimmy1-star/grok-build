//! Process-wide hard-budget mode detection shared by runtime surfaces that can
//! otherwise create ungoverned network or child-process egress.

pub const LEDGER_ENV: &str = "GROK_HARD_TOKEN_BUDGET_LEDGER";
pub const MANIFEST_ENV: &str = "GROK_HARD_TOKEN_BUDGET_MANIFEST";
pub const ALLOCATION_ENV: &str = "GROK_HARD_TOKEN_BUDGET_ALLOCATION";

/// True when any part of the hard-budget contract is present.
///
/// A partial contract is intentionally treated as armed here. The sampler owns
/// full contract validation; ancillary execution surfaces only need the stricter
/// question: must potentially ungoverned work be refused?
pub fn hard_budget_environment_present() -> bool {
    [LEDGER_ENV, MANIFEST_ENV, ALLOCATION_ENV]
        .iter()
        .any(|name| std::env::var_os(name).is_some())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn environment_names_are_exact_and_namespaced() {
        assert_eq!(LEDGER_ENV, "GROK_HARD_TOKEN_BUDGET_LEDGER");
        assert_eq!(MANIFEST_ENV, "GROK_HARD_TOKEN_BUDGET_MANIFEST");
        assert_eq!(ALLOCATION_ENV, "GROK_HARD_TOKEN_BUDGET_ALLOCATION");
    }
}
