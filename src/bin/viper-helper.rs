use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    env, fs,
    io::{BufRead, BufReader, Write},
    os::unix::net::{UnixListener, UnixStream},
    process::Command,
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};
use viper_boxd::ipc::{IpcErrorBody, Request, Response, IPC_VERSION};

#[derive(Debug, Clone)]
struct UnitState {
    unit: String,
    status: String,
    scratch_path: String,
}
type States = Arc<Mutex<BTreeMap<String, UnitState>>>;
fn response(request_id: String, result: Result<Value, IpcErrorBody>) -> Response {
    match result {
        Ok(result) => Response {
            version: IPC_VERSION.into(),
            request_id,
            ok: true,
            result: Some(result),
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
fn command_available(command: &str) -> bool {
    env::var_os("PATH")
        .into_iter()
        .flat_map(|p| env::split_paths(&p).collect::<Vec<_>>())
        .map(|d| d.join(command))
        .any(|p| p.is_file())
}
fn safe_unit_name(id: &str) -> Option<String> {
    if id.is_empty()
        || id.len() > 48
        || !id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
    {
        None
    } else {
        Some(format!("viper-box-{id}"))
    }
}
fn command_error(output: std::process::Output, operation: &str, code: &str) -> IpcErrorBody {
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
fn resource_limits(params: &Value) -> Result<(u64, u64), IpcErrorBody> {
    let cpu = params
        .get("cpu_quota_percent")
        .and_then(Value::as_u64)
        .ok_or_else(|| error("ERR_LIMIT_SETUP", "cpu_quota_percent is required"))?;
    let memory = params
        .get("memory_limit_bytes")
        .and_then(Value::as_u64)
        .ok_or_else(|| error("ERR_LIMIT_SETUP", "memory_limit_bytes is required"))?;
    if !(1..=100).contains(&cpu) {
        return Err(error(
            "ERR_LIMIT_SETUP",
            "cpu_quota_percent must be between 1 and 100",
        ));
    }
    if memory == 0 || memory > (1u64 << 50) {
        return Err(error(
            "ERR_LIMIT_SETUP",
            "memory_limit_bytes must be between 1 and 2^50",
        ));
    }
    Ok((cpu, memory))
}
fn filesystem_policy(params: &Value, unit: &str) -> Result<String, IpcErrorBody> {
    if params.get("filesystem_mode").and_then(Value::as_str) != Some("STRICT") {
        return Err(error("ERR_MOUNT_SETUP", "filesystem_mode must be STRICT"));
    }
    if params.get("write_target").and_then(Value::as_str) != Some("scratch") {
        return Err(error("ERR_MOUNT_SETUP", "write_target must be scratch"));
    }
    let path = format!("/tmp/viper-boxd-scratch-{unit}");
    fs::create_dir(&path).map_err(|e| error("ERR_MOUNT_SETUP", e.to_string()))?;
    Ok(path)
}
fn start_unit(
    unit: &str,
    ttl: u64,
    sleep_seconds: u64,
    cpu: u64,
    memory: u64,
    scratch: &str,
) -> Result<(), IpcErrorBody> {
    let unit_arg = format!("--unit={unit}");
    let runtime = format!("RuntimeMaxSec={ttl}s");
    let cpu_limit = format!("CPUQuota={cpu}%");
    let memory_limit = format!("MemoryMax={memory}");
    let writable = format!("ReadWritePaths={scratch}");
    let sleep_arg = sleep_seconds.to_string();
    let mut child = Command::new("systemd-run")
        .args([
            "--user",
            "--no-block",
            &unit_arg,
            "--property",
            &runtime,
            "--property",
            &cpu_limit,
            "--property",
            &memory_limit,
            "--property",
            "PrivateTmp=yes",
            "--property",
            "ProtectHome=yes",
            "--property",
            "ProtectSystem=strict",
            "--property",
            &writable,
            "/usr/bin/sleep",
            &sleep_arg,
        ])
        .spawn()
        .map_err(|e| error("ERR_EXECUTION_START", e.to_string()))?;
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
            Err(e) => return Err(error("ERR_EXECUTION_START", e.to_string())),
        }
    }
}
fn handle(request: Request, states: &States) -> Response {
    if request.version != IPC_VERSION {
        return response(
            request.request_id,
            Err(error("ERR_UNSUPPORTED_SCHEMA", "unsupported IPC version")),
        );
    }
    let id = request.request_id;
    let result = match request.method.as_str() {
        "capabilities" => Ok(
            json!({"schema":"viper-boxd.capabilities.v0","probe_mode":"READ_ONLY","backend_ready":command_available("systemd-run") && command_available("systemctl"),"backend":"systemd-user","supported_operations":["spawn","status","kill","cleanup"]}),
        ),
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
                .flat_map(|v| v.iter())
                .filter_map(Value::as_str)
                .filter(|r| *r != "systemd" && *r != "systemd_run")
                .collect::<Vec<_>>();
            let ttl = request
                .params
                .get("ttl_seconds")
                .and_then(Value::as_u64)
                .unwrap_or(10);
            let sleep_seconds = request
                .params
                .get("sleep_seconds")
                .and_then(Value::as_u64)
                .unwrap_or(10);
            let limits = match resource_limits(&request.params) {
                Ok(limits) => limits,
                Err(limit_error) => return response(id, Err(limit_error)),
            };
            match safe_unit_name(box_id) {
                None => Err(error("ERR_INVALID_REQUEST", "invalid box_id")),
                Some(_) if !unsupported.is_empty() => Err(error(
                    "FAIL_CLOSED",
                    format!(
                        "required capabilities are not enforceable: {}",
                        unsupported.join(", ")
                    ),
                )),
                Some(_) if ttl == 0 || ttl > 86400 => Err(error(
                    "ERR_INVALID_REQUEST",
                    "ttl_seconds must be between 1 and 86400",
                )),
                Some(_) if sleep_seconds == 0 || sleep_seconds > 300 => Err(error(
                    "ERR_INVALID_REQUEST",
                    "sleep_seconds must be between 1 and 300",
                )),
                Some(_) if states.lock().expect("state lock").contains_key(box_id) => {
                    Err(error("ERR_DUPLICATE_BOX", "box already exists"))
                }
                Some(_unit) if !command_available("systemd-run") => Err(error(
                    "ERR_CAPABILITY_UNAVAILABLE",
                    "systemd-run is not available",
                )),
                Some(unit) => {
                    let (cpu, memory) = limits;
                    let scratch = match filesystem_policy(&request.params, &unit) {
                        Ok(path) => path,
                        Err(e) => return response(id, Err(e)),
                    };
                    match start_unit(&unit, ttl, sleep_seconds, cpu, memory, &scratch) {
                        Err(e) => Err(e),
                        Ok(()) => {
                            states.lock().expect("state lock").insert(
                                box_id.into(),
                                UnitState {
                                    unit: unit.clone(),
                                    status: "STARTING".into(),
                                    scratch_path: scratch.clone(),
                                },
                            );
                            let watchdog_states = Arc::clone(states);
                            let watchdog_box = box_id.to_owned();
                            let watchdog_unit = unit.clone();
                            thread::spawn(move || {
                                thread::sleep(Duration::from_secs(ttl.saturating_add(2)));
                                let timed_out = watchdog_states
                                    .lock()
                                    .ok()
                                    .and_then(|s| {
                                        s.get(&watchdog_box)
                                            .map(|v| v.status == "STARTING" || v.status == "active")
                                    })
                                    .unwrap_or(false);
                                if timed_out {
                                    let _ = Command::new("systemctl")
                                        .args(["--user", "stop", &watchdog_unit])
                                        .output();
                                    if let Ok(mut s) = watchdog_states.lock() {
                                        if let Some(v) = s.get_mut(&watchdog_box) {
                                            v.status = "TIMED_OUT".into();
                                        }
                                    }
                                }
                            });
                            Ok(
                                json!({"box_id":box_id,"unit":unit,"handle":format!("systemd:{unit}"),"status":"STARTING","ttl_seconds":ttl,"cpu_quota_percent":cpu,"memory_limit_bytes":memory,"filesystem_mode":"STRICT","scratch_path":scratch}),
                            )
                        }
                    }
                }
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
                .filter(|v| !v.is_empty())
                .ok_or_else(|| error("ERR_HANDLE_UNKNOWN", "unknown systemd handle"));
            match (request.method.as_str(), unit) {
                (_, Err(e)) => Err(e),
                ("status", Ok(unit)) => {
                    if states
                        .lock()
                        .ok()
                        .and_then(|s| {
                            s.values()
                                .find(|v| v.unit == unit)
                                .map(|v| v.status == "TIMED_OUT")
                        })
                        .unwrap_or(false)
                    {
                        return response(
                            id,
                            Ok(json!({"handle":handle,"unit":unit,"status":"TIMED_OUT"})),
                        );
                    }
                    match Command::new("systemctl")
                        .args(["--user", "show", "--value", "--property=ActiveState", unit])
                        .output()
                    {
                        Ok(o) if o.status.success() => Ok(
                            json!({"handle":handle,"unit":unit,"status":String::from_utf8_lossy(&o.stdout).trim()}),
                        ),
                        Ok(o) => Err(command_error(o, "systemctl show", "ERR_INTERNAL")),
                        Err(e) => Err(error("ERR_INTERNAL", e.to_string())),
                    }
                }
                ("kill", Ok(unit)) => match Command::new("systemctl")
                    .args(["--user", "stop", unit])
                    .output()
                {
                    Ok(o) if o.status.success() => {
                        if let Ok(mut s) = states.lock() {
                            if let Some(v) = s.values_mut().find(|v| v.unit == unit) {
                                v.status = "KILLED".into();
                            }
                        }
                        Ok(json!({"handle":handle,"unit":unit,"status":"KILLED"}))
                    }
                    Ok(o) => Err(command_error(o, "systemctl stop", "ERR_KILL_FAILED")),
                    Err(e) => Err(error("ERR_KILL_FAILED", e.to_string())),
                },
                ("cleanup", Ok(unit)) => {
                    let service = format!("{unit}.service");
                    match Command::new("systemctl")
                        .args(["--user", "reset-failed", &service])
                        .output()
                    {
                        Ok(o)
                            if o.status.success()
                                || String::from_utf8_lossy(&o.stderr).contains("not loaded") =>
                        {
                            let scratch = states.lock().ok().and_then(|s| {
                                s.values()
                                    .find(|v| v.unit == unit)
                                    .map(|v| v.scratch_path.clone())
                            });
                            if let Some(path) = scratch {
                                if let Err(e) = fs::remove_dir_all(&path) {
                                    return response(
                                        id,
                                        Err(error("ERR_CLEANUP_FAILED", e.to_string())),
                                    );
                                }
                            }
                            if let Ok(mut s) = states.lock() {
                                s.retain(|_, v| v.unit != unit);
                            }
                            Ok(json!({"handle":handle,"unit":unit,"status":"CLEANED"}))
                        }
                        Ok(o) => Err(command_error(
                            o,
                            "systemctl reset-failed",
                            "ERR_CLEANUP_FAILED",
                        )),
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
fn serve(mut stream: UnixStream, states: &States) -> std::io::Result<()> {
    let mut line = String::new();
    BufReader::new(stream.try_clone()?).read_line(&mut line)?;
    let reply = match serde_json::from_str::<Request>(&line) {
        Ok(req) => handle(req, states),
        Err(e) => response(
            "unknown".into(),
            Err(error("ERR_INVALID_REQUEST", e.to_string())),
        ),
    };
    serde_json::to_writer(&mut stream, &reply).map_err(std::io::Error::other)?;
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
    let states: States = Arc::new(Mutex::new(BTreeMap::new()));
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                if let Err(e) = serve(stream, &states) {
                    eprintln!("helper connection error: {e}");
                }
            }
            Err(e) => eprintln!("helper accept error: {e}"),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{filesystem_policy, resource_limits};
    use serde_json::json;

    #[test]
    fn accepts_valid_cpu_and_memory_limits() {
        assert_eq!(
            resource_limits(&json!({"cpu_quota_percent": 50, "memory_limit_bytes": 536870912}))
                .expect("valid limits"),
            (50, 536870912)
        );
    }

    #[test]
    fn rejects_cpu_above_one_hundred_percent() {
        assert!(resource_limits(
            &json!({"cpu_quota_percent": 101, "memory_limit_bytes": 536870912})
        )
        .is_err());
    }

    #[test]
    fn rejects_zero_or_excessive_memory() {
        assert!(
            resource_limits(&json!({"cpu_quota_percent": 50, "memory_limit_bytes": 0})).is_err()
        );
        assert!(resource_limits(
            &json!({"cpu_quota_percent": 50, "memory_limit_bytes": 1u64 << 51})
        )
        .is_err());
    }

    #[test]
    fn rejects_non_strict_filesystem_policy() {
        assert!(filesystem_policy(
            &json!({"filesystem_mode": "OPEN", "write_target": "scratch"}),
            "UNIT_TEST"
        )
        .is_err());
        assert!(filesystem_policy(
            &json!({"filesystem_mode": "STRICT", "write_target": "work"}),
            "UNIT_TEST"
        )
        .is_err());
    }
}
