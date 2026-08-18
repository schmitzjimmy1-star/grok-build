#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use xai_grok_sampler::{
    CandidateIdentityV1, HardTokenBudgetError, HardTokenV3RuntimeBinding, ResolvedConfigIdentityV1,
    ResolvedRouteBoundV1, ToolIsolationContractV1, V3AuthorityBuilder,
};

fn wait_for(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !path.exists() {
        assert!(Instant::now() < deadline, "timed out waiting for {path:?}");
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn private_dir() -> PathBuf {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "grok-hard-budget-process-{}-{unique}",
        std::process::id()
    ));
    std::fs::create_dir(&path).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    path
}

fn v3_binding() -> HardTokenV3RuntimeBinding {
    HardTokenV3RuntimeBinding {
        candidate: CandidateIdentityV1 {
            cli_build: "1.0.5 (003f955)".into(),
            binary_sha256: "a".repeat(64),
            source_commit_sha: "b".repeat(40),
        },
        config_identity: ResolvedConfigIdentityV1 {
            source_kind: "resolved-managed-provider".into(),
            generation: 7,
            managed_provider_id: "openrouter".into(),
            config_projection_sha256: "d".repeat(64),
        },
        route: ResolvedRouteBoundV1 {
            route_id: "route-a".into(),
            provider_id: "openrouter".into(),
            provider_facing_model: "openai/gpt-4.1-mini".into(),
            endpoint_sha256: "c".repeat(64),
            api_backend: "responses".into(),
            credential_transport: "fd_v1".into(),
            auth_scheme: "bearer".into(),
            max_final_serialized_payload_bytes: 500,
            max_output_tokens: 100,
            conservative_request_bound_tokens: 600,
            allocation_token_ceiling: 1_000,
            max_model_calls: 2,
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
    }
}

fn write_v3_manifest(dir: &Path) -> PathBuf {
    let binding = v3_binding();
    let path = dir.join("manifest-v3.json");
    let manifest = serde_json::json!({
        "schemaVersion": 3,
        "campaignId": "campaign-v3",
        "campaignPolicy": {
            "schemaVersion": 3,
            "absoluteTokenCeiling": 20_000_000,
            "allocatableTokenCeiling": 19_000_000,
            "unreachableReserveTokens": 1_000_000
        },
        "candidateExpectation": binding.candidate,
        "configExpectation": binding.config_identity,
        "allocations": [{
            "id": "allocation-v3",
            "packetId": "packet-v3",
            "promptSha256": "e".repeat(64),
            "tokenCeiling": binding.route.allocation_token_ceiling,
            "maxModelCalls": binding.route.max_model_calls,
            "routeExpectation": binding.route
        }]
    });
    std::fs::write(&path, serde_json::to_vec(&manifest).unwrap()).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    path
}

#[test]
fn child_reserve() {
    if std::env::var_os("GROK_HARD_TOKEN_BUDGET_TEST_CHILD").is_none() {
        return;
    }
    let ready = PathBuf::from(std::env::var_os("TEST_READY").unwrap());
    let go = PathBuf::from(std::env::var_os("TEST_GO").unwrap());
    let result = PathBuf::from(std::env::var_os("TEST_RESULT").unwrap());
    std::fs::write(&ready, b"ready").unwrap();
    wait_for(&go);

    let builder = V3AuthorityBuilder::from_env().unwrap().unwrap();
    let authority = builder.bind_actual(v3_binding()).unwrap();
    xai_grok_sampler::install_active_v3_authority(&authority).unwrap();
    let outcome = authority.budget().reserve_authorized_request(
        &std::env::var("TEST_REQUEST_ID").unwrap(),
        "openai/gpt-4.1-mini",
        &"c".repeat(64),
        "responses",
        100,
        100,
    );
    let text = match outcome {
        Ok(_) => "ok",
        Err(HardTokenBudgetError::Exhausted) => "exhausted",
        Err(error) => panic!("unexpected reservation result: {error}"),
    };
    std::fs::write(result, text).unwrap();
}

#[test]
fn separate_processes_cannot_oversubscribe_one_v3_manifest_ledger() {
    if std::env::var_os("GROK_HARD_TOKEN_BUDGET_TEST_CHILD").is_some() {
        return;
    }
    let dir = private_dir();
    let manifest = write_v3_manifest(&dir);
    let ledger = dir.join("ledger.json");
    let go = dir.join("go");

    let exe = std::env::current_exe().unwrap();
    let mut children = Vec::new();
    for index in 0..2 {
        let ready = dir.join(format!("ready-{index}"));
        let result = dir.join(format!("result-{index}"));
        let child = Command::new(&exe)
            .args(["--exact", "child_reserve", "--nocapture"])
            .env("GROK_HARD_TOKEN_BUDGET_TEST_CHILD", "1")
            .env("GROK_HARD_TOKEN_BUDGET_LEDGER", &ledger)
            .env("GROK_HARD_TOKEN_BUDGET_MANIFEST", &manifest)
            .env("GROK_HARD_TOKEN_BUDGET_ALLOCATION", "allocation-v3")
            .env("TEST_READY", &ready)
            .env("TEST_GO", &go)
            .env("TEST_RESULT", &result)
            .env("TEST_REQUEST_ID", format!("request-{index}"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        children.push((child, ready, result));
    }
    for (_, ready, _) in &children {
        wait_for(ready);
    }
    std::fs::write(&go, b"go").unwrap();

    let mut results = Vec::new();
    for (mut child, _, result) in children {
        assert!(child.wait().unwrap().success());
        results.push(std::fs::read_to_string(result).unwrap());
    }
    results.sort();
    assert_eq!(results, vec!["exhausted", "ok"]);

    let authority = V3AuthorityBuilder::open_with_manifest(ledger, manifest, "allocation-v3")
        .unwrap()
        .bind_actual(v3_binding())
        .unwrap();
    let status = authority.budget().status().unwrap();
    assert_eq!(status.outstanding_tokens, 600);
    assert_eq!(status.allocation_remaining_tokens, Some(400));
    std::fs::remove_dir_all(dir).unwrap();
}
