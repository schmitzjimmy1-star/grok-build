#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use xai_grok_sampler::{HardTokenBudget, HardTokenBudgetError};

fn wait_for(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !path.exists() {
        assert!(Instant::now() < deadline, "timed out waiting for {path:?}");
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn private_dir() -> PathBuf {
    let path =
        std::env::temp_dir().join(format!("grok-hard-budget-process-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&path).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
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

    let budget = HardTokenBudget::from_env().unwrap().unwrap();
    let outcome = budget.reserve_authorized_request(
        &std::env::var("TEST_REQUEST_ID").unwrap(),
        "model-a",
        &"a".repeat(64),
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
fn separate_processes_cannot_oversubscribe_one_manifest_ledger() {
    if std::env::var_os("GROK_HARD_TOKEN_BUDGET_TEST_CHILD").is_some() {
        return;
    }
    let dir = private_dir();
    let manifest = dir.join("manifest.json");
    let ledger = dir.join("ledger.json");
    let go = dir.join("go");
    let manifest_json = serde_json::json!({
        "version": 1,
        "campaignId": "process-race",
        "ceilingTokens": 1000,
        "allocations": [{
            "id": "allocation-a",
            "packetId": "packet-a",
            "promptSha256": "c".repeat(64),
            "tokenCeiling": 1000,
            "maxModelCalls": 2,
            "route": {
                "model": "model-a",
                "endpointSha256": "a".repeat(64),
                "apiBackend": "responses",
                "requestBoundTokens": 600,
                "maxPayloadBytes": 500,
                "maxOutputTokens": 100,
                "boundProvenanceSha256": "b".repeat(64)
            }
        }]
    });
    std::fs::write(&manifest, serde_json::to_vec(&manifest_json).unwrap()).unwrap();
    std::fs::set_permissions(&manifest, std::fs::Permissions::from_mode(0o600)).unwrap();

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
            .env("GROK_HARD_TOKEN_BUDGET_ALLOCATION", "allocation-a")
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

    let budget = HardTokenBudget::open_with_manifest(ledger, manifest, "allocation-a").unwrap();
    let status = budget.status().unwrap();
    assert_eq!(status.outstanding_tokens, 600);
    assert_eq!(status.remaining_tokens, 400);
    std::fs::remove_dir_all(dir).unwrap();
}
