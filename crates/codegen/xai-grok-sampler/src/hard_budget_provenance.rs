//! Canonical, credential-free provenance for the Slice 4B.3 hard-token boundary.
//!
//! This module deliberately has no configuration, credential, environment, or
//! network access. The eventual CLI integration must construct these values from
//! its already-resolved route and final request serializer; callers are not
//! allowed to supply an opaque provenance digest in place of the document.
//! This is a dormant foundation: no active loader, reservation path, or route
//! resolver is wired to it in this slice, so it makes no TOCTOU guarantee.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub const CAMPAIGN_POLICY_V3_SCHEMA_VERSION: u32 = 3;
pub const HARD_TOKEN_BOUND_PROVENANCE_V1_SCHEMA_VERSION: u32 = 1;
pub const HARD_TOKEN_BOUND_PROVENANCE_V1_SERIALIZER_VERSION: u32 = 1;
pub const ABSOLUTE_TOKEN_CEILING: u64 = 20_000_000;
pub const ALLOCATABLE_TOKEN_CEILING: u64 = 19_000_000;
pub const UNREACHABLE_RESERVE_TOKENS: u64 = 1_000_000;

#[derive(Debug, thiserror::Error)]
pub enum HardTokenProvenanceError {
    #[error("unsupported campaign policy v3 document")]
    UnsupportedPolicy,
    #[error("campaign policy v3 invariant failed")]
    InvalidPolicy,
    #[error("hard-token bound provenance v1 invariant failed")]
    InvalidProvenance,
    #[error("hard-token provenance JSON is malformed or not canonical")]
    NonCanonicalJson,
    #[error("hard-token provenance digest does not match canonical bytes")]
    DigestMismatch,
    #[error("hard-token provenance JSON failed strict decoding: {0}")]
    Json(#[from] serde_json::Error),
}

impl PartialEq for HardTokenProvenanceError {
    fn eq(&self, other: &Self) -> bool {
        matches!(
            (self, other),
            (Self::UnsupportedPolicy, Self::UnsupportedPolicy)
                | (Self::InvalidPolicy, Self::InvalidPolicy)
                | (Self::InvalidProvenance, Self::InvalidProvenance)
                | (Self::NonCanonicalJson, Self::NonCanonicalJson)
                | (Self::DigestMismatch, Self::DigestMismatch)
                | (Self::Json(_), Self::Json(_))
        )
    }
}

impl Eq for HardTokenProvenanceError {}

/// The only campaign authority accepted by the new 4B.3 loader.  The old
/// 4M/3M/1M manifest is intentionally not represented here, so it cannot be
/// accidentally upgraded by adding a version field.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CampaignPolicyV3 {
    pub schema_version: u32,
    pub absolute_token_ceiling: u64,
    pub allocatable_token_ceiling: u64,
    pub unreachable_reserve_tokens: u64,
}

impl CampaignPolicyV3 {
    pub fn exact() -> Self {
        Self {
            schema_version: CAMPAIGN_POLICY_V3_SCHEMA_VERSION,
            absolute_token_ceiling: ABSOLUTE_TOKEN_CEILING,
            allocatable_token_ceiling: ALLOCATABLE_TOKEN_CEILING,
            unreachable_reserve_tokens: UNREACHABLE_RESERVE_TOKENS,
        }
    }

    pub fn validate(&self) -> Result<(), HardTokenProvenanceError> {
        if self.schema_version != CAMPAIGN_POLICY_V3_SCHEMA_VERSION {
            return Err(HardTokenProvenanceError::UnsupportedPolicy);
        }
        let total = self
            .allocatable_token_ceiling
            .checked_add(self.unreachable_reserve_tokens)
            .ok_or(HardTokenProvenanceError::InvalidPolicy)?;
        if self.absolute_token_ceiling != ABSOLUTE_TOKEN_CEILING
            || self.allocatable_token_ceiling != ALLOCATABLE_TOKEN_CEILING
            || self.unreachable_reserve_tokens != UNREACHABLE_RESERVE_TOKENS
            || total != self.absolute_token_ceiling
        {
            return Err(HardTokenProvenanceError::UnsupportedPolicy);
        }
        Ok(())
    }

    /// Rejects v1/v2 policy or manifest-shaped JSON before it can become a
    /// 4B.3 authority.  The historical decoders remain in `hard_budget`.
    pub fn from_canonical_json(bytes: &[u8]) -> Result<Self, HardTokenProvenanceError> {
        let policy: Self = serde_json::from_slice(bytes)?;
        policy.validate()?;
        if canonical_json_bytes(&policy)? != bytes {
            return Err(HardTokenProvenanceError::NonCanonicalJson);
        }
        Ok(policy)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, HardTokenProvenanceError> {
        self.validate()?;
        canonical_json_bytes(self)
    }

    pub fn sha256(&self) -> Result<String, HardTokenProvenanceError> {
        Ok(sha256_hex(&self.canonical_bytes()?))
    }
}

/// Candidate identity contains only independently observable build metadata.
/// It deliberately excludes signing blobs and any credential-derived material.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CandidateIdentityV1 {
    pub cli_build: String,
    pub binary_sha256: String,
    /// The exact 40-hex source commit identifier shared with the app-side
    /// candidate record. It is source identity, not a substitute for the
    /// independently measured binary SHA-256.
    pub source_commit_sha: String,
}

/// This is an identity of the resolved non-secret binding, not a hash of the
/// configuration file.  Config files may contain credentials; hashing them
/// would turn secret material into a durable provenance value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResolvedConfigIdentityV1 {
    pub source_kind: String,
    pub generation: u64,
    pub managed_provider_id: String,
    /// SHA-256 of the canonical credential-free resolved configuration
    /// projection. Never hash raw TOML or any secret-bearing configuration.
    pub config_projection_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ToolIsolationContractV1 {
    pub auth_provider_helpers_disabled: bool,
    pub terminal_disabled: bool,
    pub external_mcp_disabled: bool,
    pub hooks_disabled: bool,
    pub plugins_disabled: bool,
    pub lsp_disabled: bool,
    pub workflows_disabled: bool,
    pub scheduler_disabled: bool,
    pub protected_authority_fs: bool,
    pub workspace_fs_confined: bool,
    pub sampler_transport_retries_disabled: bool,
    pub allowed_tool_ids: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResolvedRouteBoundV1 {
    pub route_id: String,
    pub provider_id: String,
    pub provider_facing_model: String,
    pub endpoint_sha256: String,
    pub api_backend: String,
    /// The app/CLI boundary transport, intentionally distinct from the HTTP
    /// authentication scheme and headers.
    pub credential_transport: String,
    /// A strict scheme enum. Header names are derived canonically from this
    /// field: bearer -> authorization; x_api_key -> x-api-key;
    /// bearer_and_x_api_key -> authorization, x-api-key. They are not an
    /// independently supplied mutable list.
    pub auth_scheme: String,
    pub max_final_serialized_payload_bytes: u64,
    pub max_output_tokens: u64,
    pub conservative_request_bound_tokens: u64,
    pub allocation_token_ceiling: u64,
    pub max_model_calls: u64,
    pub text_only: bool,
    pub remote_context_forbidden: bool,
    pub multimodal_forbidden: bool,
    pub redirect_disabled: bool,
    pub retry_disabled: bool,
    pub tool_isolation: ToolIsolationContractV1,
}

/// The canonical output of the CLI's resolved-route and serializer boundary.
/// The builder has no caller-provided digest field: its digest is always the
/// SHA-256 of these canonical bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HardTokenBoundProvenanceV1 {
    pub schema_version: u32,
    pub serializer_version: u32,
    pub campaign_policy: CampaignPolicyV3,
    pub campaign_id: String,
    pub allocation_id: String,
    pub candidate: CandidateIdentityV1,
    pub config_identity: ResolvedConfigIdentityV1,
    pub route: ResolvedRouteBoundV1,
}

impl HardTokenBoundProvenanceV1 {
    /// The production CLI must call this only after it has resolved the actual
    /// route and computed final serializer limits.  This pure foundation does
    /// not claim to solve config TOCTOU until that integration exists.
    pub fn from_resolved_route(
        campaign_id: String,
        allocation_id: String,
        candidate: CandidateIdentityV1,
        config_identity: ResolvedConfigIdentityV1,
        route: ResolvedRouteBoundV1,
    ) -> Result<Self, HardTokenProvenanceError> {
        let document = Self {
            schema_version: HARD_TOKEN_BOUND_PROVENANCE_V1_SCHEMA_VERSION,
            serializer_version: HARD_TOKEN_BOUND_PROVENANCE_V1_SERIALIZER_VERSION,
            campaign_policy: CampaignPolicyV3::exact(),
            campaign_id,
            allocation_id,
            candidate,
            config_identity,
            route,
        };
        document.validate()?;
        Ok(document)
    }

    pub fn validate(&self) -> Result<(), HardTokenProvenanceError> {
        if self.schema_version != HARD_TOKEN_BOUND_PROVENANCE_V1_SCHEMA_VERSION
            || self.serializer_version != HARD_TOKEN_BOUND_PROVENANCE_V1_SERIALIZER_VERSION
        {
            return Err(HardTokenProvenanceError::InvalidProvenance);
        }
        self.campaign_policy.validate()?;
        validate_identifier(&self.campaign_id)?;
        validate_identifier(&self.allocation_id)?;
        validate_nonempty(&self.candidate.cli_build, 256)?;
        validate_sha256(&self.candidate.binary_sha256)?;
        validate_git_commit_sha(&self.candidate.source_commit_sha)?;
        validate_nonempty(&self.config_identity.source_kind, 128)?;
        if self.config_identity.source_kind != "resolved-managed-provider" {
            return Err(HardTokenProvenanceError::InvalidProvenance);
        }
        if self.config_identity.generation == 0 {
            return Err(HardTokenProvenanceError::InvalidProvenance);
        }
        validate_identifier(&self.config_identity.managed_provider_id)?;
        if self.config_identity.managed_provider_id != self.route.provider_id {
            return Err(HardTokenProvenanceError::InvalidProvenance);
        }
        validate_sha256(&self.config_identity.config_projection_sha256)?;
        validate_identifier(&self.route.route_id)?;
        validate_identifier(&self.route.provider_id)?;
        validate_nonempty(&self.route.provider_facing_model, 256)?;
        validate_sha256(&self.route.endpoint_sha256)?;
        if !matches!(
            self.route.api_backend.as_str(),
            "chat_completions" | "responses" | "messages"
        ) || self.route.credential_transport != "fd_v1"
            || self.route.max_final_serialized_payload_bytes == 0
            || self.route.max_output_tokens == 0
            || self.route.max_model_calls == 0
            || self.route.allocation_token_ceiling == 0
            || !self.route.text_only
            || !self.route.remote_context_forbidden
            || !self.route.multimodal_forbidden
            || !self.route.redirect_disabled
            || !self.route.retry_disabled
        {
            return Err(HardTokenProvenanceError::InvalidProvenance);
        }
        let lower_bound = self
            .route
            .max_final_serialized_payload_bytes
            .checked_add(self.route.max_output_tokens)
            .ok_or(HardTokenProvenanceError::InvalidProvenance)?;
        if lower_bound > self.route.conservative_request_bound_tokens
            || self.route.conservative_request_bound_tokens > self.route.allocation_token_ceiling
            || self.route.allocation_token_ceiling > ALLOCATABLE_TOKEN_CEILING
        {
            return Err(HardTokenProvenanceError::InvalidProvenance);
        }
        canonical_auth_header_names(&self.route.auth_scheme)?;
        validate_tool_isolation(&self.route.tool_isolation)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, HardTokenProvenanceError> {
        self.validate()?;
        canonical_json_bytes(self)
    }

    pub fn sha256(&self) -> Result<String, HardTokenProvenanceError> {
        Ok(sha256_hex(&self.canonical_bytes()?))
    }

    pub fn verify_sha256(&self, expected: &str) -> Result<(), HardTokenProvenanceError> {
        validate_sha256(expected)?;
        if self.sha256()? != expected {
            return Err(HardTokenProvenanceError::DigestMismatch);
        }
        Ok(())
    }

    pub fn from_canonical_json(bytes: &[u8]) -> Result<Self, HardTokenProvenanceError> {
        let document: Self = serde_json::from_slice(bytes)?;
        document.validate()?;
        if document.canonical_bytes()? != bytes {
            return Err(HardTokenProvenanceError::NonCanonicalJson);
        }
        Ok(document)
    }
}

pub(crate) fn validate_tool_isolation(
    value: &ToolIsolationContractV1,
) -> Result<(), HardTokenProvenanceError> {
    if !value.auth_provider_helpers_disabled
        || !value.terminal_disabled
        || !value.external_mcp_disabled
        || !value.hooks_disabled
        || !value.plugins_disabled
        || !value.lsp_disabled
        || !value.workflows_disabled
        || !value.scheduler_disabled
        || !value.protected_authority_fs
        || !value.workspace_fs_confined
        || !value.sampler_transport_retries_disabled
        || value.allowed_tool_ids.is_empty()
        || value
            .allowed_tool_ids
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        || value.allowed_tool_ids.iter().any(|id| {
            !id.is_ascii()
                || !id.starts_with("GrokBuild:")
                || id.len() <= "GrokBuild:".len()
                || id.len() > 256
        })
    {
        return Err(HardTokenProvenanceError::InvalidProvenance);
    }
    Ok(())
}

/// The CLI must materialize request headers from this authoritative contract,
/// never from a caller-controlled header-name collection.
pub fn canonical_auth_header_names(
    auth_scheme: &str,
) -> Result<&'static [&'static str], HardTokenProvenanceError> {
    match auth_scheme {
        "bearer" => Ok(&["authorization"]),
        "x_api_key" => Ok(&["x-api-key"]),
        "bearer_and_x_api_key" => Ok(&["authorization", "x-api-key"]),
        _ => Err(HardTokenProvenanceError::InvalidProvenance),
    }
}

pub(crate) fn validate_identifier(value: &str) -> Result<(), HardTokenProvenanceError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(HardTokenProvenanceError::InvalidProvenance);
    }
    Ok(())
}

fn validate_nonempty(value: &str, maximum: usize) -> Result<(), HardTokenProvenanceError> {
    if value.is_empty()
        || value.len() > maximum
        || !value.is_ascii()
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(HardTokenProvenanceError::InvalidProvenance);
    }
    Ok(())
}

fn validate_git_commit_sha(value: &str) -> Result<(), HardTokenProvenanceError> {
    if value.len() != 40
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(HardTokenProvenanceError::InvalidProvenance);
    }
    Ok(())
}

fn validate_sha256(value: &str) -> Result<(), HardTokenProvenanceError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(HardTokenProvenanceError::InvalidProvenance);
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// JSON serializer with a deliberately tiny, fixed canonical surface:
/// UTF-8, lexicographically sorted object keys, no whitespace, and arrays in
/// their validated semantic order.  Provenance contains no floats, avoiding
/// cross-runtime number-format ambiguity.
fn canonical_json_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, HardTokenProvenanceError> {
    let value = serde_json::to_value(value)?;
    let mut output = String::new();
    write_canonical_json(&value, &mut output)?;
    Ok(output.into_bytes())
}

fn write_canonical_json(
    value: &Value,
    output: &mut String,
) -> Result<(), HardTokenProvenanceError> {
    match value {
        Value::Null => output.push_str("null"),
        Value::Bool(value) => output.push_str(if *value { "true" } else { "false" }),
        Value::Number(number) => {
            if number.is_f64() {
                return Err(HardTokenProvenanceError::InvalidProvenance);
            }
            output.push_str(&number.to_string());
        }
        Value::String(value) => output.push_str(&serde_json::to_string(value)?),
        Value::Array(values) => {
            output.push('[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.push(',');
                }
                write_canonical_json(value, output)?;
            }
            output.push(']');
        }
        Value::Object(values) => {
            let mut entries = values.iter().collect::<Vec<_>>();
            entries.sort_unstable_by(|(left, _), (right, _)| left.cmp(right));
            output.push('{');
            for (index, (key, value)) in entries.into_iter().enumerate() {
                if index != 0 {
                    output.push(',');
                }
                output.push_str(&serde_json::to_string(key)?);
                output.push(':');
                write_canonical_json(value, output)?;
            }
            output.push('}');
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sha(letter: char) -> String {
        std::iter::repeat_n(letter, 64).collect()
    }

    fn provenance() -> HardTokenBoundProvenanceV1 {
        HardTokenBoundProvenanceV1::from_resolved_route(
            "campaign-v3".into(),
            "allocation-1".into(),
            CandidateIdentityV1 {
                cli_build: "1.0.5 (003f955)".into(),
                binary_sha256: sha('a'),
                source_commit_sha: std::iter::repeat_n('b', 40).collect(),
            },
            ResolvedConfigIdentityV1 {
                source_kind: "resolved-managed-provider".into(),
                generation: 7,
                managed_provider_id: "openrouter".into(),
                config_projection_sha256: sha('d'),
            },
            ResolvedRouteBoundV1 {
                route_id: "route-1".into(),
                provider_id: "openrouter".into(),
                provider_facing_model: "openai/gpt-4.1-mini".into(),
                endpoint_sha256: sha('c'),
                api_backend: "responses".into(),
                credential_transport: "fd_v1".into(),
                auth_scheme: "bearer".into(),
                max_final_serialized_payload_bytes: 8192,
                max_output_tokens: 4096,
                conservative_request_bound_tokens: 12288,
                allocation_token_ceiling: 20000,
                max_model_calls: 1,
                text_only: true,
                remote_context_forbidden: true,
                multimodal_forbidden: true,
                redirect_disabled: true,
                retry_disabled: true,
                tool_isolation: ToolIsolationContractV1 {
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
                    allowed_tool_ids: vec!["GrokBuild:read_file".into(), "GrokBuild:task".into()],
                },
            },
        )
        .unwrap()
    }

    #[test]
    fn policy_v3_is_exact_and_checked() {
        let policy = CampaignPolicyV3::exact();
        assert_eq!(policy.absolute_token_ceiling, 20_000_000);
        assert_eq!(policy.allocatable_token_ceiling, 19_000_000);
        assert_eq!(policy.unreachable_reserve_tokens, 1_000_000);
        policy.validate().unwrap();
        let mut bad = policy.clone();
        bad.absolute_token_ceiling = 4_000_000;
        assert_eq!(
            bad.validate(),
            Err(HardTokenProvenanceError::UnsupportedPolicy)
        );
        let mut overflow = policy;
        overflow.allocatable_token_ceiling = u64::MAX;
        assert_eq!(
            overflow.validate(),
            Err(HardTokenProvenanceError::InvalidPolicy)
        );
    }

    #[test]
    fn old_policy_or_manifest_authority_is_rejected() {
        let old_policy = br#"{\"schemaVersion\":2,\"campaignTokenCeiling\":4000000,\"emergencyReserveTokens\":1000000}"#;
        assert!(CampaignPolicyV3::from_canonical_json(old_policy).is_err());
        let old_manifest = br#"{\"version\":1,\"campaignId\":\"old\",\"ceilingTokens\":3000000,\"allocations\":[]}"#;
        assert!(HardTokenBoundProvenanceV1::from_canonical_json(old_manifest).is_err());
    }

    #[test]
    fn provenance_golden_bytes_and_hash_are_stable() {
        let bytes = provenance().canonical_bytes().unwrap();
        let text = std::str::from_utf8(&bytes).unwrap();
        assert_eq!(
            text,
            "{\"allocationId\":\"allocation-1\",\"campaignId\":\"campaign-v3\",\"campaignPolicy\":{\"absoluteTokenCeiling\":20000000,\"allocatableTokenCeiling\":19000000,\"schemaVersion\":3,\"unreachableReserveTokens\":1000000},\"candidate\":{\"binarySha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"cliBuild\":\"1.0.5 (003f955)\",\"sourceCommitSha\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\"},\"configIdentity\":{\"configProjectionSha256\":\"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd\",\"generation\":7,\"managedProviderId\":\"openrouter\",\"sourceKind\":\"resolved-managed-provider\"},\"route\":{\"allocationTokenCeiling\":20000,\"apiBackend\":\"responses\",\"authScheme\":\"bearer\",\"conservativeRequestBoundTokens\":12288,\"credentialTransport\":\"fd_v1\",\"endpointSha256\":\"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\",\"maxFinalSerializedPayloadBytes\":8192,\"maxModelCalls\":1,\"maxOutputTokens\":4096,\"multimodalForbidden\":true,\"providerFacingModel\":\"openai/gpt-4.1-mini\",\"providerId\":\"openrouter\",\"redirectDisabled\":true,\"remoteContextForbidden\":true,\"retryDisabled\":true,\"routeId\":\"route-1\",\"textOnly\":true,\"toolIsolation\":{\"allowedToolIds\":[\"GrokBuild:read_file\",\"GrokBuild:task\"],\"authProviderHelpersDisabled\":true,\"externalMcpDisabled\":true,\"hooksDisabled\":true,\"lspDisabled\":true,\"pluginsDisabled\":true,\"protectedAuthorityFs\":true,\"samplerTransportRetriesDisabled\":true,\"schedulerDisabled\":true,\"terminalDisabled\":true,\"workflowsDisabled\":true,\"workspaceFsConfined\":true}},\"schemaVersion\":1,\"serializerVersion\":1}"
        );
        assert_eq!(
            provenance().sha256().unwrap(),
            "5052a5285a35ea96151340259475a69351ed162c8308a8f2166b453a5720f950"
        );
    }

    #[test]
    fn reordered_json_is_normalized_but_not_accepted_as_authority_bytes() {
        let document = provenance();
        let canonical = document.canonical_bytes().unwrap();
        let mut value: Value = serde_json::from_slice(&canonical).unwrap();
        let object = value.as_object_mut().unwrap();
        let campaign = object.remove("campaignId").unwrap();
        object.insert("campaignId".into(), campaign);
        let reordered = serde_json::to_vec(&value).unwrap();
        let decoded: HardTokenBoundProvenanceV1 = serde_json::from_slice(&reordered).unwrap();
        assert_eq!(decoded.canonical_bytes().unwrap(), canonical);
        assert_eq!(
            HardTokenBoundProvenanceV1::from_canonical_json(&reordered),
            Err(HardTokenProvenanceError::NonCanonicalJson)
        );
    }

    #[test]
    fn strict_decoding_rejects_extra_missing_versions_and_opaque_digest() {
        let canonical = provenance().canonical_bytes().unwrap();
        let mut extra: Value = serde_json::from_slice(&canonical).unwrap();
        extra
            .as_object_mut()
            .unwrap()
            .insert("boundProvenanceSha256".into(), Value::String(sha('d')));
        assert!(serde_json::from_value::<HardTokenBoundProvenanceV1>(extra).is_err());

        let mut missing: Value = serde_json::from_slice(&canonical).unwrap();
        missing.as_object_mut().unwrap().remove("route");
        assert!(serde_json::from_value::<HardTokenBoundProvenanceV1>(missing).is_err());

        let mut wrong_version = provenance();
        wrong_version.serializer_version = 2;
        assert_eq!(
            wrong_version.validate(),
            Err(HardTokenProvenanceError::InvalidProvenance)
        );

        assert_eq!(
            provenance().verify_sha256(&sha('d')),
            Err(HardTokenProvenanceError::DigestMismatch)
        );
    }

    #[test]
    fn checked_bound_overflow_and_unbounded_policy_are_rejected() {
        let mut document = provenance();
        document.route.max_final_serialized_payload_bytes = u64::MAX;
        assert_eq!(
            document.validate(),
            Err(HardTokenProvenanceError::InvalidProvenance)
        );

        let mut document = provenance();
        document.route.text_only = false;
        assert_eq!(
            document.validate(),
            Err(HardTokenProvenanceError::InvalidProvenance)
        );

        let mut document = provenance();
        document.route.allocation_token_ceiling = 12_000;
        assert_eq!(
            document.validate(),
            Err(HardTokenProvenanceError::InvalidProvenance)
        );

        let mut document = provenance();
        document.candidate.source_commit_sha = sha('b');
        assert_eq!(
            document.validate(),
            Err(HardTokenProvenanceError::InvalidProvenance)
        );

        let mut document = provenance();
        document.candidate.cli_build = "build-\u{00e9}".into();
        assert_eq!(
            document.validate(),
            Err(HardTokenProvenanceError::InvalidProvenance)
        );

        let mut document = provenance();
        document.route.auth_scheme = "invalid".into();
        assert_eq!(
            document.validate(),
            Err(HardTokenProvenanceError::InvalidProvenance)
        );

        let mut api_key_route = provenance();
        api_key_route.route.api_backend = "chat_completions".into();
        api_key_route.route.auth_scheme = "x_api_key".into();
        api_key_route.validate().unwrap();
        assert_eq!(
            canonical_auth_header_names(&api_key_route.route.auth_scheme).unwrap(),
            &["x-api-key"]
        );

        let mut combined_route = provenance();
        combined_route.route.api_backend = "messages".into();
        combined_route.route.auth_scheme = "bearer_and_x_api_key".into();
        combined_route.validate().unwrap();
        assert_eq!(
            canonical_auth_header_names(&combined_route.route.auth_scheme).unwrap(),
            &["authorization", "x-api-key"]
        );

        let mut wrong_kind = provenance();
        wrong_kind.config_identity.source_kind = "toml".into();
        assert_eq!(
            wrong_kind.validate(),
            Err(HardTokenProvenanceError::InvalidProvenance)
        );

        let mut provider_mismatch = provenance();
        provider_mismatch.config_identity.managed_provider_id = "other-provider".into();
        assert_eq!(
            provider_mismatch.validate(),
            Err(HardTokenProvenanceError::InvalidProvenance)
        );
    }
}
