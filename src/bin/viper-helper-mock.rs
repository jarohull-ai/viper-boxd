use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    env,
    io::{BufRead, BufReader, Read, Write},
    os::unix::net::UnixStream,
};
use viper_boxd::{
    capabilities::CapabilityReport,
    ipc::{ipc_error as error, respond as response, Request, Response, IPC_VERSION},
};

fn handle(
    request: Request,
    states: &mut BTreeMap<String, String>,
    capability_report: &CapabilityReport,
) -> Response {
    if request.version != IPC_VERSION {
        return response(
            request.request_id,
            Err(error("ERR_UNSUPPORTED_SCHEMA", "unsupported IPC version")),
        );
    }
    let id = request.request_id;
    let result = match request.method.as_str() {
        "capabilities" => match serde_json::to_value(capability_report) {
            Ok(mut value) => {
                value["backend"] = json!("mock");
                Ok(value)
            }
            Err(serialization) => Err(error("ERR_INTERNAL", serialization.to_string())),
        },
        "spawn" => {
            let box_id = request
                .params
                .get("box_id")
                .and_then(Value::as_str)
                .unwrap_or("");
            let unsupported = request
                .params
                .get("required_backend")
                .and_then(Value::as_array)
                .into_iter()
                .flat_map(|items| items.iter())
                .filter_map(Value::as_str)
                .filter(|requirement| {
                    !capability_report
                        .capabilities
                        .supports_enforceable(requirement)
                })
                .collect::<Vec<_>>();
            if box_id.is_empty() {
                Err(error("ERR_INVALID_REQUEST", "params.box_id is required"))
            } else if !unsupported.is_empty() {
                Err(error(
                    "FAIL_CLOSED",
                    format!(
                        "required capabilities are not enforceable: {}",
                        unsupported.join(", ")
                    ),
                ))
            } else if states.contains_key(box_id) {
                Err(error("ERR_DUPLICATE_BOX", "box already exists"))
            } else {
                states.insert(box_id.into(), "RUNNING".into());
                Ok(
                    json!({"box_id": box_id, "handle": format!("mock:{box_id}"), "status": "RUNNING"}),
                )
            }
        }
        "status" | "kill" | "cleanup" => {
            let handle = request
                .params
                .get("handle")
                .and_then(Value::as_str)
                .unwrap_or("");
            let box_id = handle.strip_prefix("mock:").unwrap_or("");
            let state = states
                .get_mut(box_id)
                .ok_or_else(|| error("ERR_HANDLE_UNKNOWN", "unknown mock handle"));
            match (request.method.as_str(), state) {
                (_, Err(e)) => Err(e),
                ("status", Ok(state)) => Ok(json!({"handle": handle, "status": state})),
                ("kill", Ok(state)) => {
                    if state == "RUNNING" {
                        *state = "KILLED".into();
                    }
                    Ok(json!({"handle": handle, "status": state}))
                }
                ("cleanup", Ok(state)) if state == "RUNNING" => Err(error(
                    "ERR_CLEANUP_FAILED",
                    "box must be stopped before cleanup",
                )),
                ("cleanup", Ok(state)) => {
                    *state = "CLEANED".into();
                    Ok(json!({"handle": handle, "status": state}))
                }
                _ => unreachable!(),
            }
        }
        _ => Err(error("ERR_INVALID_REQUEST", "unsupported method")),
    };
    response(id, result)
}

fn serve_connection(
    mut stream: UnixStream,
    states: &mut BTreeMap<String, String>,
    capability_report: &CapabilityReport,
) -> std::io::Result<()> {
    let mut line = String::new();
    BufReader::new(stream.try_clone()?)
        .take(viper_boxd::ipc::MAX_LINE_BYTES)
        .read_line(&mut line)?;
    let response = match serde_json::from_str::<Request>(&line) {
        Ok(request) => handle(request, states, capability_report),
        Err(parse_error) => response(
            "unknown".into(),
            Err(error("ERR_INVALID_REQUEST", parse_error.to_string())),
        ),
    };
    serde_json::to_writer(&mut stream, &response).map_err(std::io::Error::other)?;
    stream.write_all(b"\n")?;
    stream.flush()
}

fn main() -> std::io::Result<()> {
    let socket = env::args()
        .nth(1)
        .unwrap_or_else(|| "/tmp/viper-helper-mock.sock".into());
    let listener = viper_boxd::ipc::bind_unix_socket(&socket)?;
    eprintln!("viper-helper-mock listening on {socket}");
    let mut states = BTreeMap::new();
    let capability_report = viper_boxd::capabilities::probe();
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                if viper_boxd::ipc::configure_server_stream(&stream).is_err() {
                    continue;
                }
                if let Err(error) = serve_connection(stream, &mut states, &capability_report) {
                    eprintln!("mock helper connection error: {error}");
                }
            }
            Err(error) => eprintln!("mock helper accept error: {error}"),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{handle, Request};
    use serde_json::json;
    use std::collections::BTreeMap;
    use viper_boxd::capabilities::probe;

    fn request(version: &str, method: &str, params: serde_json::Value) -> Request {
        Request {
            version: version.into(),
            request_id: format!("test-{method}"),
            method: method.into(),
            params,
        }
    }

    fn error_code(response: &viper_boxd::ipc::Response) -> &str {
        response
            .error
            .as_ref()
            .expect("response should contain an error")
            .code
            .as_str()
    }

    #[test]
    fn unknown_handle_is_rejected_by_status_kill_and_cleanup() {
        let mut states = BTreeMap::new();
        let capabilities = probe();
        for method in ["status", "kill", "cleanup"] {
            let response = handle(
                request("1.0", method, json!({"handle": "mock:DOES_NOT_EXIST"})),
                &mut states,
                &capabilities,
            );
            assert!(!response.ok);
            assert_eq!(error_code(&response), "ERR_HANDLE_UNKNOWN");
        }
    }

    #[test]
    fn cleanup_of_an_active_box_is_rejected() {
        let mut states = BTreeMap::new();
        let capabilities = probe();
        let spawn = handle(
            request(
                "1.0",
                "spawn",
                json!({"box_id": "ACTIVE", "required_backend": []}),
            ),
            &mut states,
            &capabilities,
        );
        let handle_id = spawn.result.expect("spawn result")["handle"]
            .as_str()
            .expect("handle string")
            .to_owned();
        let response = handle(
            request("1.0", "cleanup", json!({"handle": handle_id})),
            &mut states,
            &capabilities,
        );
        assert!(!response.ok);
        assert_eq!(error_code(&response), "ERR_CLEANUP_FAILED");
    }

    #[test]
    fn unsupported_protocol_version_is_rejected() {
        let mut states = BTreeMap::new();
        let response = handle(request("0.9", "status", json!({})), &mut states, &probe());
        assert!(!response.ok);
        assert_eq!(error_code(&response), "ERR_UNSUPPORTED_SCHEMA");
    }

    #[test]
    fn missing_enforceable_capability_fails_closed() {
        let mut states = BTreeMap::new();
        let response = handle(
            request(
                "1.0",
                "spawn",
                json!({"box_id": "NETWORK_BOX", "required_backend": ["network_namespace"]}),
            ),
            &mut states,
            &probe(),
        );
        assert!(!response.ok);
        assert_eq!(error_code(&response), "FAIL_CLOSED");
        assert!(states.is_empty(), "failed spawn must not create state");
    }
}
