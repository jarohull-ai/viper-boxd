use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    env, fs,
    io::{BufRead, BufReader, Write},
    os::unix::net::{UnixListener, UnixStream},
};
use viper_boxd::{
    capabilities::CapabilityReport,
    ipc::{IpcErrorBody, Request, Response, IPC_VERSION},
};

fn response(request_id: String, result: Result<Value, IpcErrorBody>) -> Response {
    match result {
        Ok(value) => Response {
            version: IPC_VERSION.into(),
            request_id,
            ok: true,
            result: Some(value),
            error: None,
        },
        Err(error) => Response {
            version: IPC_VERSION.into(),
            request_id,
            ok: false,
            result: None,
            error: Some(error),
        },
    }
}

fn error(code: &str, message: impl Into<String>) -> IpcErrorBody {
    IpcErrorBody {
        code: code.into(),
        message: message.into(),
    }
}

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
        "capabilities" => serde_json::to_value(capability_report)
            .map_err(|serialization| error("ERR_INTERNAL", serialization.to_string())),
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
    BufReader::new(stream.try_clone()?).read_line(&mut line)?;
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
    let _ = fs::remove_file(&socket);
    let listener = UnixListener::bind(&socket)?;
    eprintln!("viper-helper-mock listening on {socket}");
    let mut states = BTreeMap::new();
    let capability_report = viper_boxd::capabilities::probe();
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                if let Err(error) = serve_connection(stream, &mut states, &capability_report) {
                    eprintln!("mock helper connection error: {error}");
                }
            }
            Err(error) => eprintln!("mock helper accept error: {error}"),
        }
    }
    Ok(())
}
