use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    env, fs,
    io::{BufRead, BufReader, Read, Write},
    os::unix::{
        fs::FileTypeExt,
        net::UnixStream,
    },
    process::Command,
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};
use viper_boxd::ipc::{ipc_error as error, respond as response, IpcErrorBody, Request, Response, IPC_VERSION};

#[derive(Debug, Clone)]
struct UnitState {
    unit: String,
    status: String,
    scratch_path: String,
}
type States = Arc<Mutex<BTreeMap<String, UnitState>>>;

/// Administrator-owned mapping from a stable gateway reference to the local
/// socket of a running gateway process. A spawn request may only name a
/// reference from this map; it never supplies a raw socket path.
type GatewayRegistry = BTreeMap<String, String>;

#[derive(Debug, Deserialize)]
struct GatewayRegistryFile {
    schema: String,
    #[serde(default)]
    gateways: GatewayRegistry,
}

fn load_gateway_registry(path: &str) -> Result<GatewayRegistry, String> {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(_) => {
            eprintln!(
                "viper-helper: no gateway registry at {path}; GATEWAY_ONLY spawns will be rejected"
            );
            return Ok(GatewayRegistry::new());
        }
    };
    let file: GatewayRegistryFile =
        toml::from_str(&text).map_err(|e| format!("parse gateway registry: {e}"))?;
    if file.schema != "viper-boxd.gateway-registry.v0" {
        return Err("unsupported gateway registry schema".into());
    }
    Ok(file.gateways)
}

#[derive(Debug)]
struct NetworkPlan {
    mode: &'static str,
    gateway_sockets: Vec<(String, String)>,
}

fn resolve_network(
    params: &Value,
    gateways: &GatewayRegistry,
) -> Result<NetworkPlan, IpcErrorBody> {
    let mode = params
        .get("network_mode")
        .and_then(Value::as_str)
        .unwrap_or("DENY");
    match mode {
        "DENY" => Ok(NetworkPlan {
            mode: "DENY",
            gateway_sockets: Vec::new(),
        }),
        "GATEWAY_ONLY" => {
            let refs: Vec<String> = params
                .get("gateway_refs")
                .and_then(Value::as_array)
                .into_iter()
                .flat_map(|v| v.iter())
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect();
            if refs.is_empty() {
                return Err(error(
                    "ERR_NETWORK_SETUP",
                    "GATEWAY_ONLY requires at least one gateway_refs entry",
                ));
            }
            let mut gateway_sockets = Vec::with_capacity(refs.len());
            for gateway_ref in refs {
                let socket = gateways.get(&gateway_ref).ok_or_else(|| {
                    error(
                        "ERR_NETWORK_SETUP",
                        format!("unknown gateway reference: {gateway_ref}"),
                    )
                })?;
                if !gateway_socket_is_live(socket) {
                    return Err(error(
                        "ERR_NETWORK_SETUP",
                        format!("gateway {gateway_ref} socket is not available at {socket}"),
                    ));
                }
                gateway_sockets.push((gateway_ref, socket.clone()));
            }
            Ok(NetworkPlan {
                mode: "GATEWAY_ONLY",
                gateway_sockets,
            })
        }
        _ => Err(error(
            "FAIL_CLOSED",
            format!("network_mode {mode} is not enforceable by this helper"),
        )),
    }
}

fn gateway_socket_is_live(path: &str) -> bool {
    fs::metadata(path)
        .map(|metadata| metadata.file_type().is_socket())
        .unwrap_or(false)
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
    let runtime = env::var("XDG_RUNTIME_DIR").unwrap_or_else(|_| "/run/user/1000".to_owned());
    let path = format!("{runtime}/viper-boxd-scratch-{unit}");
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
    gateway_sockets: &[(String, String)],
) -> Result<(), IpcErrorBody> {
    let unit_arg = format!("--unit={unit}");
    let runtime = format!("RuntimeMaxSec={ttl}s");
    let cpu_limit = format!("CPUQuota={cpu}%");
    let memory_limit = format!("MemoryMax={memory}");
    let writable = format!("ReadWritePaths={scratch}");
    let sleep_arg = sleep_seconds.to_string();
    // Every gateway socket is bind-mounted at its own host path so the Box
    // can reach exactly the gateways its profile resolved to, nothing else.
    // PrivateNetwork=yes always stays set: a Unix socket bind does not grant
    // any IP networking, so real network access remains fully denied.
    let bind_paths: Vec<String> = gateway_sockets
        .iter()
        .map(|(_, socket)| format!("BindPaths={socket}:{socket}"))
        .collect();

    let mut command = Command::new("systemd-run");
    command.args([
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
        "--property",
        "PrivateNetwork=yes",
    ]);
    for bind_path in &bind_paths {
        command.arg("--property").arg(bind_path);
    }
    command.args(["/usr/bin/sleep", &sleep_arg]);

    let mut child = command
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

fn run_filesystem_probe(scratch: &str) -> Result<Value, IpcErrorBody> {
    let probe = env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(|dir| dir.join("viper-fs-probe")))
        .filter(|path| path.is_file())
        .ok_or_else(|| {
            error(
                "ERR_PROBE_UNAVAILABLE",
                "viper-fs-probe binary is not built",
            )
        })?;
    let unit = format!("viper-boxd-probe-{}", std::process::id());
    let writable = format!("ReadWritePaths={scratch}");
    let output = Command::new("systemd-run")
        .args([
            "--user",
            "--wait",
            "--pipe",
            &format!("--unit={unit}"),
            "--property",
            "PrivateTmp=yes",
            "--property",
            // The probe binary is built in the repository under $HOME. Keep
            // home read-only for this test so systemd can execute it while the
            // attempted write to /root still verifies a denied host write.
            "ProtectHome=read-only",
            "--property",
            "ProtectSystem=strict",
            "--property",
            &writable,
        ])
        .arg(&probe)
        .args(["--scratch", scratch])
        .output()
        .map_err(|e| error("ERR_PROBE_EXECUTION", e.to_string()))?;
    if !output.status.success() {
        return Err(command_error(
            output,
            "filesystem probe",
            "ERR_PROBE_FAILED",
        ));
    }
    serde_json::from_slice::<Value>(&output.stdout)
        .map_err(|e| error("ERR_PROBE_OUTPUT", e.to_string()))
}

fn run_network_probe() -> Result<Value, IpcErrorBody> {
    let probe = env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(|dir| dir.join("viper-network-probe")))
        .filter(|path| path.is_file())
        .ok_or_else(|| {
            error(
                "ERR_PROBE_UNAVAILABLE",
                "viper-network-probe binary is not built",
            )
        })?;
    let unit = format!("viper-boxd-network-probe-{}", std::process::id());
    let output = Command::new("systemd-run")
        .args([
            "--user",
            "--wait",
            "--pipe",
            &format!("--unit={unit}"),
            "--property",
            "PrivateNetwork=yes",
            "--property",
            "ProtectHome=read-only",
            "--property",
            "ProtectSystem=strict",
        ])
        .arg(&probe)
        .output()
        .map_err(|e| error("ERR_PROBE_EXECUTION", e.to_string()))?;
    if !output.status.success() {
        return Err(command_error(output, "network probe", "ERR_PROBE_FAILED"));
    }
    serde_json::from_slice::<Value>(&output.stdout)
        .map_err(|e| error("ERR_PROBE_OUTPUT", e.to_string()))
}

/// `call_method` selects one of the probe binary's fixed, built-in request
/// kinds (`PING` or `MODEL_GENERATE`); it is never a caller-supplied
/// arbitrary string passed through to the gateway.
fn run_gateway_probe(
    gateway_ref: &str,
    socket: &str,
    call_method: &str,
) -> Result<Value, IpcErrorBody> {
    if !gateway_socket_is_live(socket) {
        return Err(error(
            "ERR_NETWORK_SETUP",
            format!("gateway {gateway_ref} socket is not available at {socket}"),
        ));
    }
    let probe = env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(|dir| dir.join("viper-gateway-probe")))
        .filter(|path| path.is_file())
        .ok_or_else(|| {
            error(
                "ERR_PROBE_UNAVAILABLE",
                "viper-gateway-probe binary is not built",
            )
        })?;
    let unit = format!("viper-boxd-gateway-probe-{}", std::process::id());
    let bind_path = format!("BindPaths={socket}:{socket}");
    let mut command = Command::new("systemd-run");
    command.args([
        "--user",
        "--wait",
        "--pipe",
        &format!("--unit={unit}"),
        "--property",
        "PrivateNetwork=yes",
        "--property",
        "ProtectHome=read-only",
        "--property",
        "ProtectSystem=strict",
        "--property",
        &bind_path,
    ]);
    command.arg(&probe).args(["--socket", socket]);
    if call_method != "PING" {
        command.args(["--call", call_method]);
    }
    let output = command
        .output()
        .map_err(|e| error("ERR_PROBE_EXECUTION", e.to_string()))?;
    if !output.status.success() {
        return Err(command_error(output, "gateway probe", "ERR_PROBE_FAILED"));
    }
    serde_json::from_slice::<Value>(&output.stdout)
        .map_err(|e| error("ERR_PROBE_OUTPUT", e.to_string()))
}

fn handle(request: Request, states: &States, gateways: &GatewayRegistry) -> Response {
    if request.version != IPC_VERSION {
        return response(
            request.request_id,
            Err(error("ERR_UNSUPPORTED_SCHEMA", "unsupported IPC version")),
        );
    }
    let id = request.request_id;
    let result = match request.method.as_str() {
        "capabilities" => Ok(
            json!({"schema":"viper-boxd.capabilities.v0","probe_mode":"READ_ONLY","backend_ready":command_available("systemd-run") && command_available("systemctl"),"backend":"systemd-user","supported_operations":["spawn","status","kill","cleanup","filesystem_probe","network_probe","gateway_probe"]}),
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
            let network_plan = match resolve_network(&request.params, gateways) {
                Ok(plan) => plan,
                Err(network_error) => return response(id, Err(network_error)),
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
                // status/kill/cleanup and the spawn watchdog all shell out
                // to systemctl directly, unconditionally - a Box must not
                // be allowed to start unless the full lifecycle, not just
                // the initial spawn, can be enforced.
                Some(_unit) if !command_available("systemd-run") => Err(error(
                    "ERR_CAPABILITY_UNAVAILABLE",
                    "systemd-run is not available",
                )),
                Some(_unit) if !command_available("systemctl") => Err(error(
                    "ERR_CAPABILITY_UNAVAILABLE",
                    "systemctl is not available",
                )),
                Some(unit) => {
                    let (cpu, memory) = limits;
                    let scratch = match filesystem_policy(&request.params, &unit) {
                        Ok(path) => path,
                        Err(e) => return response(id, Err(e)),
                    };
                    match start_unit(
                        &unit,
                        ttl,
                        sleep_seconds,
                        cpu,
                        memory,
                        &scratch,
                        &network_plan.gateway_sockets,
                    ) {
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
                            let gateway_refs: Vec<&str> = network_plan
                                .gateway_sockets
                                .iter()
                                .map(|(gateway_ref, _)| gateway_ref.as_str())
                                .collect();
                            Ok(
                                json!({"box_id":box_id,"unit":unit,"handle":format!("systemd:{unit}"),"status":"STARTING","ttl_seconds":ttl,"cpu_quota_percent":cpu,"memory_limit_bytes":memory,"filesystem_mode":"STRICT","scratch_path":scratch,"network_mode":network_plan.mode,"gateway_refs":gateway_refs,"private_network":true}),
                            )
                        }
                    }
                }
            }
        }
        "filesystem_probe" => {
            let runtime =
                env::var("XDG_RUNTIME_DIR").unwrap_or_else(|_| "/run/user/1000".to_owned());
            let scratch = format!("{runtime}/viper-boxd-probe-{}", std::process::id());
            if let Err(e) = fs::create_dir(&scratch) {
                return response(id, Err(error("ERR_PROBE_SETUP", e.to_string())));
            }
            let probe = run_filesystem_probe(&scratch);
            let _ = fs::remove_dir_all(&scratch);
            probe.map(|probe| {
                json!({
                    "status": "PROBE_COMPLETED",
                    "probe": probe,
                    "side_effects": true,
                    "scratch_path": scratch,
                })
            })
        }
        "network_probe" => run_network_probe().map(|probe| {
            json!({
                "status": "PROBE_COMPLETED",
                "probe": probe,
                "network_mode": "DENY",
                "private_network": true,
                "side_effects": true,
            })
        }),
        "gateway_probe" => {
            let gateway_ref = request
                .params
                .get("gateway_ref")
                .and_then(Value::as_str)
                .unwrap_or("");
            let call_method = request
                .params
                .get("call")
                .and_then(Value::as_str)
                .unwrap_or("PING");
            if gateway_ref.is_empty() {
                Err(error("ERR_INVALID_REQUEST", "gateway_ref is required"))
            } else if call_method != "PING" && call_method != "MODEL_GENERATE" {
                Err(error(
                    "ERR_INVALID_REQUEST",
                    "call must be PING or MODEL_GENERATE",
                ))
            } else {
                match gateways.get(gateway_ref) {
                    None => Err(error(
                        "ERR_NETWORK_SETUP",
                        format!("unknown gateway reference: {gateway_ref}"),
                    )),
                    Some(socket) => {
                        run_gateway_probe(gateway_ref, socket, call_method).map(|probe| {
                            json!({
                                "status": "PROBE_COMPLETED",
                                "probe": probe,
                                "gateway_ref": gateway_ref,
                                "network_mode": "GATEWAY_ONLY",
                                "private_network": true,
                                "side_effects": true,
                            })
                        })
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
fn serve(mut stream: UnixStream, states: &States, gateways: &GatewayRegistry) -> std::io::Result<()> {
    let mut line = String::new();
    BufReader::new(stream.try_clone()?)
        .take(viper_boxd::ipc::MAX_LINE_BYTES)
        .read_line(&mut line)?;
    let reply = match serde_json::from_str::<Request>(&line) {
        Ok(req) => handle(req, states, gateways),
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
    let registry_path = env::args()
        .nth(2)
        .unwrap_or_else(|| "examples/gateway-registry.toml".into());
    let gateways = load_gateway_registry(&registry_path).map_err(std::io::Error::other)?;
    let listener = viper_boxd::ipc::bind_unix_socket(&socket)?;
    eprintln!("viper-helper listening on {socket}");
    let states: States = Arc::new(Mutex::new(BTreeMap::new()));
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                if viper_boxd::ipc::configure_server_stream(&stream).is_err() {
                    continue;
                }
                if let Err(e) = serve(stream, &states, &gateways) {
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
    use super::{filesystem_policy, resolve_network, resource_limits, GatewayRegistry};
    use serde_json::json;
    use std::os::unix::net::UnixListener;

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

    #[test]
    fn rejects_network_modes_other_than_deny_and_gateway_only() {
        let gateways = GatewayRegistry::new();
        assert!(resolve_network(&json!({"network_mode": "RESEARCH"}), &gateways).is_err());
        assert!(resolve_network(&json!({"network_mode": "MODEL_ONLY"}), &gateways).is_err());
        assert!(resolve_network(&json!({}), &gateways).is_ok());
        assert!(resolve_network(&json!({"network_mode": "DENY"}), &gateways).is_ok());
    }

    #[test]
    fn gateway_only_requires_at_least_one_ref() {
        let gateways = GatewayRegistry::new();
        let error = resolve_network(
            &json!({"network_mode": "GATEWAY_ONLY", "gateway_refs": []}),
            &gateways,
        )
        .unwrap_err();
        assert_eq!(error.code, "ERR_NETWORK_SETUP");
    }

    #[test]
    fn gateway_only_rejects_unknown_reference() {
        let gateways = GatewayRegistry::new();
        let error = resolve_network(
            &json!({"network_mode": "GATEWAY_ONLY", "gateway_refs": ["NOPE"]}),
            &gateways,
        )
        .unwrap_err();
        assert_eq!(error.code, "ERR_NETWORK_SETUP");
    }

    #[test]
    fn gateway_only_rejects_a_registered_but_dead_socket() {
        let mut gateways = GatewayRegistry::new();
        gateways.insert(
            "DEAD".into(),
            "/tmp/viper-helper-test-nonexistent.sock".into(),
        );
        let error = resolve_network(
            &json!({"network_mode": "GATEWAY_ONLY", "gateway_refs": ["DEAD"]}),
            &gateways,
        )
        .unwrap_err();
        assert_eq!(error.code, "ERR_NETWORK_SETUP");
    }

    #[test]
    fn gateway_only_resolves_a_live_registered_socket() {
        let path = std::env::temp_dir().join(format!(
            "viper-helper-test-live-{}.sock",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let _listener = UnixListener::bind(&path).expect("bind test gateway socket");

        let mut gateways = GatewayRegistry::new();
        gateways.insert("LIVE".into(), path.to_str().unwrap().to_owned());
        let plan = resolve_network(
            &json!({"network_mode": "GATEWAY_ONLY", "gateway_refs": ["LIVE"]}),
            &gateways,
        )
        .expect("live socket resolves");
        assert_eq!(plan.mode, "GATEWAY_ONLY");
        assert_eq!(plan.gateway_sockets, vec![("LIVE".to_owned(), path.to_str().unwrap().to_owned())]);

        let _ = std::fs::remove_file(&path);
    }
}
