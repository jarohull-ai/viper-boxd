use serde_json::json;
use std::{
    fs,
    io::Write,
    os::unix::net::UnixListener,
    path::PathBuf,
    process::Command,
    thread,
    time::{SystemTime, UNIX_EPOCH},
};
use viper_boxd::ipc::{send_request, Request, IPC_VERSION};

const VALID_MANIFEST: &str = include_str!("../examples/research.jfp");
const VALID_PROFILE: &str = include_str!("../examples/research-profile.toml");

fn nonce() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock must be after UNIX epoch")
        .as_nanos()
}

fn temp_dir(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("viper-adversarial-{name}-{}", nonce()));
    fs::create_dir(&path).expect("create temp test dir");
    path
}

fn write_case(name: &str, manifest: &str, profile: &str) -> (PathBuf, PathBuf, PathBuf) {
    let dir = temp_dir(name);
    let manifest_path = dir.join("manifest.jfp");
    let profile_path = dir.join("profile.toml");
    fs::write(&manifest_path, manifest).expect("write manifest");
    fs::write(&profile_path, profile).expect("write profile");
    (dir, manifest_path, profile_path)
}

fn run_plan(manifest: &PathBuf, profile: &PathBuf) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_viper-boxd"))
        .args(["plan", "--manifest"])
        .arg(manifest)
        .arg("--profile")
        .arg(profile)
        .args(["--workspace-id", "WORKSPACE_TEST", "--json"])
        .output()
        .expect("run viper-boxd plan")
}

#[test]
fn overlong_manifest_path_fails_without_panic() {
    let profile_dir = temp_dir("long-path-profile");
    let profile = profile_dir.join("profile.toml");
    fs::write(&profile, VALID_PROFILE).expect("write profile");
    let manifest = PathBuf::from(format!("/tmp/{}", "a".repeat(5000)));

    let output = run_plan(&manifest, &profile);

    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("read manifest"));
    let _ = fs::remove_dir_all(profile_dir);
}

#[test]
fn manifest_with_null_newline_and_control_chars_is_rejected() {
    let manifest = "F:SPEC_VERSION:0.1;\nF:TASK_ID:BAD\0ID;\nF:BOX_ID:BOX\x1fBAD;\n";
    let (dir, manifest_path, profile_path) = write_case("control-chars", manifest, VALID_PROFILE);

    let output = run_plan(&manifest_path, &profile_path);

    assert_eq!(output.status.code(), Some(1));
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("plan emits JSON rejection");
    assert_eq!(report["plan_status"], "PLAN_REJECTED");
    assert!(report["errors"].as_array().unwrap().iter().any(|value| {
        value
            .as_str()
            .map(|code| code.starts_with("ERR_"))
            .unwrap_or(false)
    }));
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn large_repetitive_malicious_manifest_is_rejected_without_hanging() {
    let mut manifest = String::from("F:SPEC_VERSION:0.1;\n");
    for index in 0..10_000 {
        manifest.push_str(&format!("not-a-field-{index}\n"));
    }
    let (dir, manifest_path, profile_path) =
        write_case("repetitive-malicious-manifest", &manifest, VALID_PROFILE);

    let output = run_plan(&manifest_path, &profile_path);

    assert_eq!(output.status.code(), Some(1));
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("plan emits JSON rejection");
    assert_eq!(report["plan_status"], "PLAN_REJECTED");
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn missing_manifest_file_is_a_configuration_error() {
    let dir = temp_dir("missing-manifest");
    let manifest = dir.join("missing.jfp");
    let profile = dir.join("profile.toml");
    fs::write(&profile, VALID_PROFILE).expect("write profile");

    let output = run_plan(&manifest, &profile);

    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("read manifest"));
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn corrupt_profile_toml_is_rejected_before_plan_execution() {
    let (dir, manifest_path, profile_path) = write_case(
        "corrupt-profile",
        VALID_MANIFEST,
        "schema = [not valid toml\n",
    );

    let output = run_plan(&manifest_path, &profile_path);

    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("parse profile"));
    let _ = fs::remove_dir_all(dir);
}

#[cfg(unix)]
#[test]
fn unreadable_profile_file_fails_closed() {
    use std::os::unix::fs::PermissionsExt;

    let (dir, manifest_path, profile_path) =
        write_case("unreadable-profile", VALID_MANIFEST, VALID_PROFILE);
    fs::set_permissions(&profile_path, fs::Permissions::from_mode(0o000))
        .expect("make profile unreadable");

    let output = run_plan(&manifest_path, &profile_path);

    let _ = fs::set_permissions(&profile_path, fs::Permissions::from_mode(0o600));
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("read profile"));
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn gateway_that_closes_connection_is_reported_as_invalid_response() {
    let socket = std::env::temp_dir().join(format!("viper-close-gateway-{}.sock", nonce()));
    let _ = fs::remove_file(&socket);
    let listener = UnixListener::bind(&socket).expect("bind mock socket");
    let worker = thread::spawn(move || {
        let _ = listener.accept();
    });

    let error = send_request(
        socket.to_str().expect("UTF-8 socket path"),
        &Request {
            version: IPC_VERSION.into(),
            request_id: "closed".into(),
            method: "PING".into(),
            params: json!({}),
        },
    )
    .expect_err("closed gateway must not produce a valid response");

    assert!(
        error.to_string().contains("IPC"),
        "unexpected error shape: {error}"
    );
    worker.join().expect("mock gateway thread exits");
    let _ = fs::remove_file(socket);
}

#[test]
fn gateway_response_with_wrong_field_types_is_rejected() {
    let socket = std::env::temp_dir().join(format!("viper-bad-type-gateway-{}.sock", nonce()));
    let _ = fs::remove_file(&socket);
    let listener = UnixListener::bind(&socket).expect("bind mock socket");
    let worker = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept one client");
        let _ = stream.write_all(
            br#"{"version":"1.0","request_id":"bad","audit_trace_id":"trace","ok":"yes"}"#,
        );
        let _ = stream.write_all(b"\n");
    });

    let error = send_request(
        socket.to_str().expect("UTF-8 socket path"),
        &Request {
            version: IPC_VERSION.into(),
            request_id: "bad".into(),
            method: "PING".into(),
            params: json!({}),
        },
    )
    .expect_err("wrong JSON field types must be rejected");

    assert!(error.to_string().contains("IPC JSON error"));
    worker.join().expect("mock gateway thread exits");
    let _ = fs::remove_file(socket);
}
