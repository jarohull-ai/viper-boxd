use serde_json::json;
use std::{
    fs,
    path::PathBuf,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use viper_boxd::{
    ipc::{send_request, Request, IPC_VERSION},
    research_fetcher::validate_response,
    research_policy::ResearchPolicy,
};

struct GatewayProcess(Child);

impl Drop for GatewayProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn nonce() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock must be after UNIX epoch")
        .as_nanos()
}

fn temp_path(name: &str, extension: &str) -> PathBuf {
    std::env::temp_dir().join(format!("viper-boxd-test-limits-{name}-{}.{extension}", nonce()))
}

fn write_config(name: &str, max_requests: u32, timeout_seconds: u64, max_redirects: u8) -> PathBuf {
    let path = temp_path(name, "toml");
    let body = format!(
        "schema = \"viper-boxd.research-gateway.v0\"\n\
gateway_id = \"TEST_LIMITS_{name}\"\n\
allowed_domains = [\"example.invalid\"]\n\
max_requests = {max_requests}\n\
max_fetch_bytes = 5242880\n\
max_redirects = {max_redirects}\n\
timeout_seconds = {timeout_seconds}\n"
    );
    fs::write(&path, body).expect("write test gateway config");
    path
}

fn spawn_gateway(socket: &PathBuf, config: &PathBuf) -> GatewayProcess {
    let child = Command::new(env!("CARGO_BIN_EXE_viper-research-gateway"))
        .arg(socket)
        .arg(config)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn viper-research-gateway");
    GatewayProcess(child)
}

fn wait_for_socket(socket: &PathBuf) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !socket.exists() {
        if Instant::now() > deadline {
            panic!("gateway socket {socket:?} did not appear in time");
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn fetch_request(id: &str, url: &str) -> Request {
    Request {
        version: IPC_VERSION.into(),
        request_id: id.into(),
        method: "FETCH".into(),
        params: json!({ "url": url }),
    }
}

/// `max_requests` must be enforced by the live gateway process over the real
/// socket, not only by the in-process `handle` unit tests. Both requests
/// target an unallowlisted domain so the budget check is what fails first,
/// with no DNS lookup involved.
#[test]
fn max_requests_budget_is_enforced_across_the_socket() {
    let socket = temp_path("max-requests", "sock");
    let config = write_config("max-requests", 1, 5, 0);
    let gateway = spawn_gateway(&socket, &config);
    wait_for_socket(&socket);
    let socket_str = socket.to_str().expect("UTF-8 socket path");

    let first = send_request(socket_str, &fetch_request("r1", "https://not-allowed.invalid"))
        .expect("first request round-trips");
    assert!(!first.ok);
    assert_ne!(first.error.unwrap().code, "ERR_REQUEST_LIMIT_EXCEEDED");

    let second = send_request(socket_str, &fetch_request("r2", "https://not-allowed.invalid"))
        .expect("second request round-trips");
    assert!(!second.ok);
    assert_eq!(second.error.unwrap().code, "ERR_REQUEST_LIMIT_EXCEEDED");

    drop(gateway);
    let _ = fs::remove_file(&socket);
    let _ = fs::remove_file(&config);
}

#[test]
fn max_fetch_bytes_rejects_only_the_oversized_body() {
    let policy = ResearchPolicy {
        max_fetch_bytes: 4,
        ..ResearchPolicy::mock()
    };
    assert!(policy.validate_fetch_size(4).is_ok());
    let error = policy.validate_fetch_size(5).unwrap_err();
    assert_eq!(error.code, "ERR_FETCH_LIMIT_EXCEEDED");
}

#[test]
fn redirect_responses_are_denied_before_evidence_is_built() {
    let error = validate_response(
        &ResearchPolicy::mock(),
        "https://example.invalid/redirected",
        302,
        "text/plain",
        b"moved",
    )
    .unwrap_err();
    assert_eq!(error.code, "ERR_REDIRECT_DENIED");
}

/// Every outbound fetch must run under a bounded timeout, so a gateway
/// configured with `timeout_seconds = 0` must fail closed at config load,
/// before it ever binds a socket or opens a connection.
#[test]
fn zero_timeout_config_is_rejected_before_the_socket_binds() {
    let socket = temp_path("zero-timeout", "sock");
    let config = write_config("zero-timeout", 30, 0, 0);

    let output = Command::new(env!("CARGO_BIN_EXE_viper-research-gateway"))
        .arg(&socket)
        .arg(&config)
        .output()
        .expect("run viper-research-gateway with an invalid config");

    assert!(!output.status.success());
    assert!(
        !socket.exists(),
        "gateway must not bind a socket for an invalid config"
    );
    let _ = fs::remove_file(&config);
}
