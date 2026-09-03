use serde_json::Value;
use std::{
    fs,
    path::PathBuf,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

const MANIFEST: &str = include_str!("../examples/research.jfp");
const PROFILE: &str = include_str!("../examples/research-profile.toml");

fn temp_case(name: &str) -> (PathBuf, PathBuf, PathBuf) {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock must be after UNIX epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("viper-boxd-{name}-{nonce}"));
    fs::create_dir_all(&dir).expect("create temporary test directory");
    (
        dir.clone(),
        dir.join("manifest.jfp"),
        dir.join("profile.toml"),
    )
}

fn run_case(name: &str, manifest: &str, profile: &str) -> (i32, Value) {
    let (dir, manifest_path, profile_path) = temp_case(name);
    fs::write(&manifest_path, manifest).expect("write test manifest");
    fs::write(&profile_path, profile).expect("write test profile");

    let output = Command::new(env!("CARGO_BIN_EXE_viper-boxd"))
        .args([
            "plan",
            "--manifest",
            manifest_path.to_str().expect("UTF-8 manifest path"),
            "--profile",
            profile_path.to_str().expect("UTF-8 profile path"),
            "--workspace-id",
            "TEST_WORKSPACE",
        ])
        .output()
        .expect("run simulator");
    let status = output
        .status
        .code()
        .expect("simulator must return an exit code");
    let json = if output.stdout.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&output.stdout).expect("simulator stdout must be valid JSON")
    };
    fs::remove_dir_all(dir).expect("remove temporary test directory");
    (status, json)
}

#[test]
fn rejects_manifest_with_inconsistent_gateway_policy() {
    let manifest = MANIFEST.replace(
        "F:GATEWAY_POLICY_ID:OSINT_PUBLIC_WEB_V1;",
        "F:GATEWAY_POLICY_ID:APPROVED_API_V1;",
    );
    let (status, report) = run_case("policy-mismatch", &manifest, PROFILE);

    assert_eq!(status, 1);
    assert_eq!(report["plan_status"], "PLAN_REJECTED");
    assert!(report["errors"]
        .as_array()
        .expect("errors array")
        .iter()
        .any(|error| error == "ERR_POLICY_MODE_MISMATCH"));
    assert_eq!(report["side_effects"], false);
}

#[test]
fn rejects_profile_with_missing_required_field() {
    let profile = PROFILE.replace("memory_limit_bytes = 1073741824\n", "");
    let (status, report) = run_case("profile-missing-field", MANIFEST, &profile);

    assert_eq!(status, 2);
    assert!(
        report.is_null(),
        "profile parse failures must not emit a plan"
    );
}

#[test]
fn rejects_manifest_that_does_not_match_profile() {
    let manifest = MANIFEST.replace("F:NETWORK_MODE:RESEARCH;", "F:NETWORK_MODE:MODEL_ONLY;");
    let (status, report) = run_case("profile-mismatch", &manifest, PROFILE);

    assert_eq!(status, 1);
    assert_eq!(report["plan_status"], "PLAN_REJECTED");
    assert!(report["errors"]
        .as_array()
        .expect("errors array")
        .iter()
        .any(|error| error == "ERR_PROFILE_MODE_MISMATCH"));
}

#[test]
fn handles_maximum_u64_memory_limit_without_side_effects() {
    let profile = PROFILE.replace(
        "memory_limit_bytes = 1073741824",
        "memory_limit_bytes = 9223372036854775807",
    );
    let (status, report) = run_case("maximum-memory", MANIFEST, &profile);

    assert_eq!(status, 0);
    assert_eq!(report["plan_status"], "PLAN_ACCEPTED");
    assert_eq!(report["side_effects"], false);
    assert_eq!(
        report["would_apply"]["memory_limit_bytes"],
        9223372036854775807u64
    );
}

#[test]
fn rejects_malformed_manifest_without_panicking() {
    let manifest = "F:SPEC_VERSION:0.1;\nF:NETWORK_MODE:RESEARCH;\nnot-a-field\n";
    let (status, report) = run_case("malformed-manifest", manifest, PROFILE);

    assert_eq!(status, 1);
    assert_eq!(report["plan_status"], "PLAN_REJECTED");
    assert!(!report["errors"]
        .as_array()
        .expect("errors array")
        .is_empty());
}
