//! Controlled probe proving a Box can reach exactly its bind-mounted gateway
//! socket and nothing else. It never accepts a URL, host, or arbitrary
//! command from its caller: the socket path is the one property injected by
//! the helper, and `--call` selects from a fixed, built-in set of
//! deterministic requests rather than accepting caller-supplied params.

use serde_json::{json, Value};
use std::{env, net::TcpStream, process::ExitCode, time::Duration};
use viper_boxd::ipc::{send_request, Request, IPC_VERSION};

/// Fixed, non-configurable prompt: this probe proves connectivity and
/// response shape, not model quality, so the input is deliberately static.
const PROBE_PROMPT: &str = "Reply with exactly the two words: hello world";

fn network_blocked(address: &str) -> bool {
    TcpStream::connect_timeout(
        &address.parse().expect("probe address is a fixed literal"),
        Duration::from_secs(2),
    )
    .is_err()
}

fn call(socket: &str, request_id: &str, method: &str, params: Value) -> Option<viper_boxd::ipc::Response> {
    let request = Request {
        version: IPC_VERSION.into(),
        request_id: request_id.into(),
        method: method.into(),
        params,
    };
    send_request(socket, &request).ok()
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let (socket, call_method) = match args.as_slice() {
        [flag, path] if flag == "--socket" => (path.clone(), "PING".to_owned()),
        [flag, path, call_flag, method] if flag == "--socket" && call_flag == "--call" => {
            (path.clone(), method.clone())
        }
        _ => {
            eprintln!("usage: viper-gateway-probe --socket PATH [--call PING|MODEL_GENERATE]");
            return ExitCode::from(2);
        }
    };

    // An unsupported method must still round-trip a well-formed, versioned
    // IPC response with a default-deny error, regardless of which gateway
    // implementation (mock, research, or model) answers this socket. This
    // check always runs, regardless of --call, and never consumes the
    // gateway's request budget since no real gateway matches "PROBE_PING".
    let ping = call(&socket, "gateway-probe-ping", "PROBE_PING", json!({}));
    let (gateway_reachable, gateway_denies_unknown_method) = match &ping {
        Some(response) => (
            response.version == IPC_VERSION,
            !response.ok
                && response
                    .error
                    .as_ref()
                    .map(|error| error.code == "ERR_TOOL_NOT_ALLOWED")
                    .unwrap_or(false),
        ),
        None => (false, false),
    };

    // With --call MODEL_GENERATE, also prove a real functional round trip:
    // Box -> bind-mounted gateway socket -> real model backend -> a real
    // classified answer, under the exact same isolation properties as the
    // PING check above.
    let model_generate_result = if call_method == "MODEL_GENERATE" {
        call(
            &socket,
            "gateway-probe-generate",
            "MODEL_GENERATE",
            json!({"prompt": PROBE_PROMPT}),
        )
    } else {
        None
    };
    let model_generate_ok = model_generate_result
        .as_ref()
        .map(|response| {
            response.ok
                && response
                    .result
                    .as_ref()
                    .and_then(|r| r.get("classification"))
                    .and_then(Value::as_str)
                    == Some("MODEL_OUTPUT")
                && response
                    .result
                    .as_ref()
                    .and_then(|r| r.get("text"))
                    .and_then(Value::as_str)
                    .is_some_and(|text| !text.is_empty())
        })
        .unwrap_or(false);

    let external_network_blocked = network_blocked("1.1.1.1:443");
    let local_network_blocked = network_blocked("127.0.0.1:8080");

    let call_succeeded = call_method != "MODEL_GENERATE" || model_generate_ok;

    println!(
        "{}",
        serde_json::to_string(&json!({
            "schema": "viper-boxd.gateway-probe.v0",
            "call": call_method,
            "gateway_reachable": gateway_reachable,
            "gateway_denies_unknown_method": gateway_denies_unknown_method,
            "model_generate_response": model_generate_result,
            "external_network_blocked": external_network_blocked,
            "local_network_blocked": local_network_blocked,
        }))
        .expect("probe JSON serialization cannot fail")
    );

    if gateway_reachable
        && gateway_denies_unknown_method
        && external_network_blocked
        && local_network_blocked
        && call_succeeded
    {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}
