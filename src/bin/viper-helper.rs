use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    env, fs,
    io::{BufRead, BufReader, Write},
    os::unix::net::{UnixListener, UnixStream},
    process::Command,
    thread,
    time::{Duration, Instant},
};
use viper_boxd::ipc::{IpcErrorBody, Request, Response, IPC_VERSION};

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

fn safe_unit_name(box_id: &str) -> Option<String> {
    if box_id.is_empty()
        || box_id.len() > 48
        || !box_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_".contains(&byte))
    {
        return None;
    }
    Some(format!("viper-box-{box_id}"))
}

fn command_available(command: &str) -> bool {
    env::var_os("PATH")
        .into_iter()
        .flat_map(|paths| env::split_paths(&paths).collect::<Vec<_>>())
        .map(|directory| directory.join(command))
        .any(|candidate| candidate.is_file())
}

fn systemd_error(output: std::process::Output, operation: &str, code: &str) -> IpcErrorBody {
    let detail = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    error(
        code,
        format!(
            "{operation} failed{}",
            if detail.is_empty() {
                String::new()
            } else {
                format!(": {detail}")
            }
        ),
    )
}

fn start_systemd_unit(unit: &str) -> Result<(), IpcErrorBody> {
    let unit_arg = format!("--unit={unit}");
    let mut child = Command::new("systemd-run")
        .args(["--user", "--no-block", &unit_arg, "/usr/bin/sleep", "10"])
        .spawn()
        .map_err(|spawn_error| error("ERR_EXECUTION_START", spawn_error.to_string()))?;
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => return Ok(()),
            Ok(Some(_)) => {
                return Err(error("ERR_EXECUTION_START", "systemd-run returned failure"))
            }
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(25)),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error("ERR_EXECUTION_START", "systemd-run timed out"));
            }
            Err(wait_error) => return Err(error("ERR_EXECUTION_START", wait_error.to_string())),
        }
    }
}

fn handle(request: Request, units: &mut BTreeMap<String, String>) -> Response {
    if request.version != IPC_VERSION {
        return response(
            request.request_id,
            Err(error("ERR_UNSUPPORTED_SCHEMA", "unsupported IPC version")),
        );
    }
    let id = request.request_id;
    let result = match request.method.as_str() {
        "capabilities" => Ok(json!({
            "schema": "viper-boxd.capabilities.v0",
            "probe_mode": "READ_ONLY",
            "backend_ready": command_available("systemd-run") && command_available("systemctl"),
            "backend": "systemd-user",
            "supported_operations": ["spawn", "status", "kill", "cleanup"]
        })),
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
                    *requirement != "systemd_run"
                        && *requirement != "systemd"
                        && !command_available(requirement)
                })
                .collect::<Vec<_>>();
            let unit = safe_unit_name(box_id).ok_or_else(|| {
                error(
                    "ERR_INVALID_REQUEST",
                    "box_id must contain only ASCII letters, digits, '-' or '_'",
                )
            });
            match unit {
                Err(e) => Err(e),
                Ok(_) if !unsupported.is_empty() => Err(error(
                    "FAIL_CLOSED",
                    format!(
                        "required capabilities are not enforceable: {}",
                        unsupported.join(", ")
                    ),
                )),
                Ok(_unit) if units.contains_key(box_id) => {
                    Err(error("ERR_DUPLICATE_BOX", "box already exists"))
                }
                Ok(_unit) if !command_available("systemd-run") => Err(error(
                    "ERR_CAPABILITY_UNAVAILABLE",
                    "systemd-run is not available",
                )),
                Ok(unit) => match start_systemd_unit(&unit) {
                    Ok(()) => {
                        units.insert(box_id.into(), unit.clone());
                        Ok(
                            json!({"box_id": box_id, "unit": unit, "handle": format!("systemd:{unit}"), "status": "STARTING"}),
                        )
                    }
                    Err(error) => Err(error),
                },
            }
        }
        "status" | "kill" | "cleanup" => {
            let handle = request
                .params
                .get("handle")
                .and_then(Value::as_str)
                .unwrap_or("");
            let unit = handle
                .strip_prefix("systemd:")
                .filter(|value| !value.is_empty());
            let unit = unit.ok_or_else(|| error("ERR_HANDLE_UNKNOWN", "unknown systemd handle"));
            match (request.method.as_str(), unit) {
                (_, Err(e)) => Err(e),
                ("status", Ok(unit)) => {
                    let output = Command::new("systemctl")
                        .args(["--user", "show", "--value", "--property=ActiveState", unit])
                        .output();
                    match output {
                        Ok(output) if output.status.success() => Ok(
                            json!({"handle": handle, "unit": unit, "status": String::from_utf8_lossy(&output.stdout).trim()}),
                        ),
                        Ok(output) => Err(systemd_error(output, "systemctl show", "ERR_INTERNAL")),
                        Err(e) => Err(error("ERR_INTERNAL", e.to_string())),
                    }
                }
                ("kill", Ok(unit)) => {
                    let output = Command::new("systemctl")
                        .args(["--user", "stop", unit])
                        .output();
                    match output {
                        Ok(output) if output.status.success() => {
                            Ok(json!({"handle": handle, "unit": unit, "status": "KILLED"}))
                        }
                        Ok(output) => {
                            Err(systemd_error(output, "systemctl stop", "ERR_KILL_FAILED"))
                        }
                        Err(e) => Err(error("ERR_KILL_FAILED", e.to_string())),
                    }
                }
                ("cleanup", Ok(unit)) => {
                    let service_unit = format!("{unit}.service");
                    let output = Command::new("systemctl")
                        .args(["--user", "reset-failed", &service_unit])
                        .output();
                    match output {
                        Ok(output) if output.status.success() => {
                            Ok(json!({"handle": handle, "unit": unit, "status": "CLEANED"}))
                        }
                        Ok(output) => {
                            let detail = String::from_utf8_lossy(&output.stderr);
                            if detail.contains("not loaded") {
                                Ok(json!({"handle": handle, "unit": unit, "status": "CLEANED"}))
                            } else {
                                Err(systemd_error(
                                    output,
                                    "systemctl reset-failed",
                                    "ERR_CLEANUP_FAILED",
                                ))
                            }
                        }
                        Err(e) => Err(error("ERR_CLEANUP_FAILED", e.to_string())),
                    }
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
    units: &mut BTreeMap<String, String>,
) -> std::io::Result<()> {
    let mut line = String::new();
    BufReader::new(stream.try_clone()?).read_line(&mut line)?;
    let response = match serde_json::from_str::<Request>(&line) {
        Ok(request) => handle(request, units),
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
        .unwrap_or_else(|| "/tmp/viper-helper.sock".into());
    let _ = fs::remove_file(&socket);
    let listener = UnixListener::bind(&socket)?;
    eprintln!("viper-helper listening on {socket}");
    let mut units = BTreeMap::new();
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                if let Err(error) = serve_connection(stream, &mut units) {
                    eprintln!("helper connection error: {error}");
                }
            }
            Err(error) => eprintln!("helper accept error: {error}"),
        }
    }
    Ok(())
}
