//! Controlled probe proving a Box can reach exactly its bind-mounted gateway
//! socket and nothing else. It never accepts a URL, host, or command from
//! its caller; the socket path is the one property injected by the helper.

use serde_json::json;
use std::{env, net::TcpStream, process::ExitCode, time::Duration};
use viper_boxd::ipc::{send_request, Request, IPC_VERSION};

fn network_blocked(address: &str) -> bool {
    TcpStream::connect_timeout(
        &address.parse().expect("probe address is a fixed literal"),
        Duration::from_secs(2),
    )
    .is_err()
}

fn main() -> ExitCode {
    let socket = match env::args().skip(1).collect::<Vec<_>>().as_slice() {
        [flag, path] if flag == "--socket" => path.clone(),
        _ => {
            eprintln!("usage: viper-gateway-probe --socket PATH");
            return ExitCode::from(2);
        }
    };

    // An unsupported method must still round-trip a well-formed, versioned
    // IPC response with a default-deny error, regardless of which gateway
    // implementation (mock or research) answers this socket.
    let request = Request {
        version: IPC_VERSION.into(),
        request_id: format!("gateway-probe-{}", std::process::id()),
        method: "PROBE_PING".into(),
        params: json!({}),
    };
    let (gateway_reachable, gateway_denies_unknown_method) = match send_request(&socket, &request)
    {
        Ok(response) => (
            response.version == IPC_VERSION,
            !response.ok
                && response
                    .error
                    .as_ref()
                    .map(|error| error.code == "ERR_TOOL_NOT_ALLOWED")
                    .unwrap_or(false),
        ),
        Err(_) => (false, false),
    };

    let external_network_blocked = network_blocked("1.1.1.1:443");
    let local_network_blocked = network_blocked("127.0.0.1:8080");

    println!(
        "{}",
        serde_json::to_string(&json!({
            "schema": "viper-boxd.gateway-probe.v0",
            "gateway_reachable": gateway_reachable,
            "gateway_denies_unknown_method": gateway_denies_unknown_method,
            "external_network_blocked": external_network_blocked,
            "local_network_blocked": local_network_blocked,
        }))
        .expect("probe JSON serialization cannot fail")
    );

    if gateway_reachable
        && gateway_denies_unknown_method
        && external_network_blocked
        && local_network_blocked
    {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}
