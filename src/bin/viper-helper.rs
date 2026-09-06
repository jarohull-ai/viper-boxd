use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    env, fs,
    io::{BufRead, BufReader, Read, Write},
    os::unix::{fs::FileTypeExt, net::UnixStream},
    process::Command,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};
use viper_boxd::admission::{AdmissionController, AdmissionDecision};
use viper_boxd::ipc::{
    ipc_error as error, respond as response, IpcErrorBody, Request, Response, IPC_VERSION,
};
use viper_boxd::lineage::LineageStore;
use viper_boxd::observability::{append_jsonl, Metrics};

#[derive(Debug, Clone)]
struct UnitState {
    unit: String,
    status: String,
    scratch_path: String,
    cpu_quota_percent: u64,
    memory_limit_bytes: u64,
}
type States = Arc<Mutex<BTreeMap<String, UnitState>>>;
#[derive(Debug)]
struct AdmissionState {
    controller: AdmissionController,
    pending: BTreeMap<String, Value>,
}
type Admissions = Arc<Mutex<AdmissionState>>;
static PROBE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn reconcile_orphaned_boxes(lineage_dir: &std::path::Path) -> Result<usize, String> {
    let store = LineageStore::open(lineage_dir).map_err(|error| error.to_string())?;
    let output = Command::new("systemctl")
        .args([
            "--user",
            "list-units",
            "--type=service",
            "--state=active",
            "viper-box-*.service",
            "--no-legend",
            "--plain",
        ])
        .output()
        .map_err(|error| format!("list active Box units: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "list active Box units failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let mut reconciled = 0;
    for unit in String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .filter(|unit| unit.starts_with("viper-box-") && unit.ends_with(".service"))
    {
        let box_id = unit
            .strip_prefix("viper-box-")
            .and_then(|value| value.strip_suffix(".service"))
            .unwrap_or_default();
        if store.get(box_id).is_some() {
            continue;
        }
        let started_at = Instant::now();
        let stop = Command::new("systemctl")
            .args(["--user", "stop", unit])
            .status()
            .map_err(|error| format!("stop orphan {unit}: {error}"))?;
        let reset = Command::new("systemctl")
            .args(["--user", "reset-failed", unit])
            .output()
            .map_err(|error| format!("cleanup orphan {unit}: {error}"))?;
        let reset_ok =
            reset.status.success() || String::from_utf8_lossy(&reset.stderr).contains("not loaded");
        let scratch = env::var("XDG_RUNTIME_DIR").unwrap_or_else(|_| "/run/user/1000".to_owned());
        let unit_name = unit.strip_suffix(".service").unwrap_or(unit);
        let scratch =
            std::path::Path::new(&scratch).join(format!("viper-boxd-scratch-{unit_name}"));
        let scratch_cleanup = match fs::remove_dir_all(&scratch) {
            Ok(()) => true,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
            Err(_) => false,
        };
        let fields = json!({
            "box_id": box_id,
            "unit": unit,
            "action": "kill_cleanup",
            "stop_ok": stop.success(),
            "reset_failed_ok": reset_ok,
            "scratch_cleanup_ok": scratch_cleanup,
        });
        if let Some(path) = env::var_os("VIPER_AUDIT_LOG") {
            append_jsonl(
                std::path::Path::new(&path),
                "orphan_box_reconciled",
                &fields,
                started_at.elapsed().as_millis(),
            )
            .map_err(|error| format!("write orphan audit: {error}"))?;
        }
        eprintln!(
            "viper-helper: reconciled orphan Box {box_id} (stop={}, cleanup={})",
            stop.success(),
            reset_ok && scratch_cleanup
        );
        if !stop.success() || !reset_ok || !scratch_cleanup {
            return Err(format!(
                "orphan {unit} did not reconcile cleanly (stop={}, reset_failed={}, scratch_cleanup={})",
                stop.success(),
                reset_ok,
                scratch_cleanup
            ));
        }
        reconciled += 1;
    }
    Ok(reconciled)
}

/// Fixed test limits for the resource-limit probe. Not caller-configurable,
/// same as the filesystem and network probes' fixed policy.
const RESOURCE_PROBE_CPU_QUOTA_PERCENT: u64 = 20;
const RESOURCE_PROBE_MEMORY_LIMIT_BYTES: u64 = 64 * 1024 * 1024;

/// A user-manager unit cannot give every Box a distinct host UID.  These
/// deny-list entries block all signal delivery from the Box; systemd controls
/// Box lifecycle through its cgroup instead.
const SIGNAL_FILTER_PROPERTIES: [&str; 12] = [
    "--property",
    "SystemCallFilter=~kill",
    "--property",
    "SystemCallFilter=~tkill",
    "--property",
    "SystemCallFilter=~tgkill",
    "--property",
    "SystemCallFilter=~rt_sigqueueinfo",
    "--property",
    "SystemCallFilter=~rt_tgsigqueueinfo",
    "--property",
    "SystemCallFilter=~pidfd_send_signal",
];

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

/// The daemon speaks in policy capabilities, never in systemd properties.
/// Keep this list deliberately small and tied to the properties that this
/// helper actually sets for every spawned Box.
fn enforceable_backend_requirement(requirement: &str) -> bool {
    matches!(
        requirement,
        "systemd" | "systemd_run" | "mount_namespace" | "network_policy" | "cgroup_limits"
    )
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

fn probe_unit_name(kind: &str) -> String {
    let sequence = PROBE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    format!("viper-boxd-{kind}-{}-{sequence}", std::process::id())
}
fn command_error(output: std::process::Output, operation: &str, code: &str) -> IpcErrorBody {
    let detail = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    let probe_output = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    error(
        code,
        format!(
            "{operation} failed{}{}",
            if detail.is_empty() {
                String::new()
            } else {
                format!(": {detail}")
            },
            if probe_output.is_empty() {
                String::new()
            } else {
                format!("; probe output: {probe_output}")
            },
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
        // A user namespace gives the child credentials which cannot signal
        // same-UID host processes.  If a host disallows this systemd must
        // fail the spawn; there is no weaker fallback.
        "PrivateUsers=yes",
        "--property",
        &writable,
        "--property",
        "PrivateNetwork=yes",
    ]);
    command.args(SIGNAL_FILTER_PROPERTIES);
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
    let unit = probe_unit_name("filesystem-probe");
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
            "PrivateUsers=yes",
            "--property",
            &writable,
        ])
        .args(SIGNAL_FILTER_PROPERTIES)
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
    let unit = probe_unit_name("network-probe");
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
            "--property",
            "PrivateUsers=yes",
        ])
        .args(SIGNAL_FILTER_PROPERTIES)
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
    let unit = probe_unit_name("gateway-probe");
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
        "PrivateUsers=yes",
        "--property",
        &bind_path,
    ]);
    command.args(SIGNAL_FILTER_PROPERTIES);
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

fn run_signal_probe() -> Result<Value, IpcErrorBody> {
    let probe = env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(|dir| dir.join("viper-signal-probe")))
        .filter(|path| path.is_file())
        .ok_or_else(|| {
            error(
                "ERR_PROBE_UNAVAILABLE",
                "viper-signal-probe binary is not built",
            )
        })?;
    let unit = probe_unit_name("signal-probe");
    // The target is this helper's own PID: same UID as the probed unit,
    // but a process the unit must not be able to affect.
    let target_pid = std::process::id().to_string();
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
            "--property",
            "PrivateUsers=yes",
        ])
        .args(SIGNAL_FILTER_PROPERTIES)
        .arg(&probe)
        .args(["--target-pid", &target_pid])
        .output()
        .map_err(|e| error("ERR_PROBE_EXECUTION", e.to_string()))?;
    if !output.status.success() {
        return Err(command_error(output, "signal probe", "ERR_PROBE_FAILED"));
    }
    serde_json::from_slice::<Value>(&output.stdout)
        .map_err(|e| error("ERR_PROBE_OUTPUT", e.to_string()))
}

fn run_resource_probe() -> Result<Value, IpcErrorBody> {
    let probe = env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(|dir| dir.join("viper-resource-probe")))
        .filter(|path| path.is_file())
        .ok_or_else(|| {
            error(
                "ERR_PROBE_UNAVAILABLE",
                "viper-resource-probe binary is not built",
            )
        })?;
    let unit = probe_unit_name("resource-probe");
    let cpu_limit = format!("CPUQuota={RESOURCE_PROBE_CPU_QUOTA_PERCENT}%");
    let memory_limit = format!("MemoryMax={RESOURCE_PROBE_MEMORY_LIMIT_BYTES}");
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
            "--property",
            "PrivateUsers=yes",
            "--property",
            &cpu_limit,
            "--property",
            &memory_limit,
            "--property",
            // Systemd's default OOMPolicy tears down every process in the
            // unit once the kernel OOM-kills any one of them. The memory
            // check relies on only its disposable child dying, so the
            // parent survives to report the result.
            "OOMPolicy=continue",
        ])
        .args(SIGNAL_FILTER_PROPERTIES)
        .arg(&probe)
        .args([
            "--cpu-quota-percent",
            &RESOURCE_PROBE_CPU_QUOTA_PERCENT.to_string(),
            "--memory-limit-bytes",
            &RESOURCE_PROBE_MEMORY_LIMIT_BYTES.to_string(),
        ])
        .output()
        .map_err(|e| error("ERR_PROBE_EXECUTION", e.to_string()))?;
    if !output.status.success() {
        return Err(command_error(output, "resource probe", "ERR_PROBE_FAILED"));
    }
    serde_json::from_slice::<Value>(&output.stdout)
        .map_err(|e| error("ERR_PROBE_OUTPUT", e.to_string()))
}

fn spawn_box(
    params: &Value,
    states: &States,
    gateways: &GatewayRegistry,
    admissions: &Admissions,
) -> Result<Value, IpcErrorBody> {
    let box_id = params.get("box_id").and_then(Value::as_str).unwrap_or("");
    let unsupported = params
        .get("required_backend")
        .and_then(Value::as_array)
        .into_iter()
        .flat_map(|values| values.iter())
        .filter_map(Value::as_str)
        .filter(|requirement| !enforceable_backend_requirement(requirement))
        .collect::<Vec<_>>();
    let ttl = params
        .get("ttl_seconds")
        .and_then(Value::as_u64)
        .unwrap_or(10);
    let sleep_seconds = params
        .get("sleep_seconds")
        .and_then(Value::as_u64)
        .unwrap_or(10);
    let (cpu, memory) = resource_limits(params)?;
    let network_plan = resolve_network(params, gateways)?;
    let unit =
        safe_unit_name(box_id).ok_or_else(|| error("ERR_INVALID_REQUEST", "invalid box_id"))?;
    if !unsupported.is_empty() {
        return Err(error(
            "FAIL_CLOSED",
            format!(
                "required capabilities are not enforceable: {}",
                unsupported.join(", ")
            ),
        ));
    }
    if ttl == 0 || ttl > 86400 {
        return Err(error(
            "ERR_INVALID_REQUEST",
            "ttl_seconds must be between 1 and 86400",
        ));
    }
    if sleep_seconds == 0 || sleep_seconds > 300 {
        return Err(error(
            "ERR_INVALID_REQUEST",
            "sleep_seconds must be between 1 and 300",
        ));
    }
    if states.lock().expect("state lock").contains_key(box_id) {
        return Err(error("ERR_DUPLICATE_BOX", "box already exists"));
    }
    if !command_available("systemd-run") || !command_available("systemctl") {
        return Err(error(
            "ERR_CAPABILITY_UNAVAILABLE",
            "systemd-run and systemctl are required for full lifecycle enforcement",
        ));
    }
    let scratch = filesystem_policy(params, &unit)?;
    start_unit(
        &unit,
        ttl,
        sleep_seconds,
        cpu,
        memory,
        &scratch,
        &network_plan.gateway_sockets,
    )?;
    states.lock().expect("state lock").insert(
        box_id.into(),
        UnitState {
            unit: unit.clone(),
            status: "STARTING".into(),
            scratch_path: scratch.clone(),
            cpu_quota_percent: cpu,
            memory_limit_bytes: memory,
        },
    );
    let watchdog_states = Arc::clone(states);
    let watchdog_gateways = gateways.clone();
    let watchdog_admissions = Arc::clone(admissions);
    let watchdog_box = box_id.to_owned();
    let watchdog_unit = unit.clone();
    thread::spawn(move || {
        thread::sleep(Duration::from_secs(ttl.saturating_add(2)));
        let timed_out = watchdog_states
            .lock()
            .ok()
            .and_then(|state| {
                state
                    .get(&watchdog_box)
                    .map(|value| value.status == "STARTING" || value.status == "active")
            })
            .unwrap_or(false);
        if timed_out {
            let _ = Command::new("systemctl")
                .args(["--user", "stop", &watchdog_unit])
                .output();
            if let Ok(mut state) = watchdog_states.lock() {
                if let Some(value) = state.get_mut(&watchdog_box) {
                    value.status = "TIMED_OUT".into();
                }
            }
            if watchdog_admissions
                .lock()
                .expect("admission lock")
                .controller
                .release(&watchdog_box)
            {
                let _ = drain_queue(&watchdog_states, &watchdog_gateways, &watchdog_admissions);
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

fn queueable_spawn(
    params: &Value,
    states: &States,
    gateways: &GatewayRegistry,
) -> Result<(String, String), IpcErrorBody> {
    let box_id = params.get("box_id").and_then(Value::as_str).unwrap_or("");
    let unit =
        safe_unit_name(box_id).ok_or_else(|| error("ERR_INVALID_REQUEST", "invalid box_id"))?;
    if states.lock().expect("state lock").contains_key(box_id) {
        return Err(error("ERR_DUPLICATE_BOX", "box already exists"));
    }
    let ttl = params
        .get("ttl_seconds")
        .and_then(Value::as_u64)
        .unwrap_or(10);
    let sleep = params
        .get("sleep_seconds")
        .and_then(Value::as_u64)
        .unwrap_or(10);
    if ttl == 0 || ttl > 86400 || sleep == 0 || sleep > 300 {
        return Err(error(
            "ERR_INVALID_REQUEST",
            "invalid TTL or runner duration",
        ));
    }
    resource_limits(params)?;
    resolve_network(params, gateways)?;
    if params.get("filesystem_mode").and_then(Value::as_str) != Some("STRICT")
        || params.get("write_target").and_then(Value::as_str) != Some("scratch")
    {
        return Err(error(
            "ERR_MOUNT_SETUP",
            "filesystem must be STRICT with scratch output",
        ));
    }
    Ok((box_id.to_owned(), unit))
}

fn admit_spawn(
    params: &Value,
    states: &States,
    gateways: &GatewayRegistry,
    admissions: &Admissions,
) -> Result<Value, IpcErrorBody> {
    let (box_id, unit) = queueable_spawn(params, states, gateways)?;
    let decision = admissions
        .lock()
        .expect("admission lock")
        .controller
        .admit(&box_id)
        .map_err(|message| error("ERR_DUPLICATE_BOX", message))?;
    match decision {
        AdmissionDecision::Start => match spawn_box(params, states, gateways, admissions) {
            Ok(result) => Ok(result),
            Err(start_error) => {
                admissions
                    .lock()
                    .expect("admission lock")
                    .controller
                    .release(&box_id);
                Err(start_error)
            }
        },
        AdmissionDecision::Queued { position } => {
            let mut admission = admissions.lock().expect("admission lock");
            admission.pending.insert(box_id.clone(), params.clone());
            drop(admission);
            states.lock().expect("state lock").insert(
                box_id.clone(),
                UnitState {
                    unit: unit.clone(),
                    status: "QUEUED".into(),
                    scratch_path: String::new(),
                    cpu_quota_percent: 0,
                    memory_limit_bytes: 0,
                },
            );
            Ok(
                json!({"box_id":box_id,"unit":unit,"handle":format!("systemd:{unit}"),"status":"QUEUED","queue_position":position}),
            )
        }
    }
}

fn drain_queue(states: &States, gateways: &GatewayRegistry, admissions: &Admissions) -> Vec<Value> {
    let mut started = Vec::new();
    loop {
        let next = admissions
            .lock()
            .expect("admission lock")
            .controller
            .start_next();
        let Some(box_id) = next else { break };
        let params = admissions
            .lock()
            .expect("admission lock")
            .pending
            .remove(&box_id);
        let Some(params) = params else { continue };
        states.lock().expect("state lock").remove(&box_id);
        match spawn_box(&params, states, gateways, admissions) {
            Ok(result) => started.push(result),
            Err(error_value) => {
                admissions
                    .lock()
                    .expect("admission lock")
                    .controller
                    .release(&box_id);
                started.push(json!({"box_id":box_id,"status":"REJECTED_FROM_QUEUE","error":{"code":error_value.code,"message":error_value.message}}));
            }
        }
    }
    started
}

fn runtime_metrics(states: &States, admissions: &Admissions) -> Metrics {
    let state = states.lock().expect("state lock");
    let admission = admissions.lock().expect("admission lock");
    let mut metrics = Metrics {
        active_boxes: admission.controller.active_count() as u64,
        queued_boxes: admission.controller.queued_count() as u64,
        ..Metrics::default()
    };
    for value in state.values().filter(|value| {
        value.status != "QUEUED" && value.status != "KILLED" && value.status != "TIMED_OUT"
    }) {
        metrics.cpu_quota_percent += value.cpu_quota_percent;
        metrics.memory_limit_bytes += value.memory_limit_bytes;
    }
    metrics
}

fn handle(
    request: Request,
    states: &States,
    gateways: &GatewayRegistry,
    admissions: &Admissions,
) -> Response {
    if request.version != IPC_VERSION {
        return response(
            request.request_id,
            Err(error("ERR_UNSUPPORTED_SCHEMA", "unsupported IPC version")),
        );
    }
    let id = request.request_id;
    let result = match request.method.as_str() {
        "capabilities" => Ok(
            json!({"schema":"viper-boxd.capabilities.v0","probe_mode":"READ_ONLY","backend_ready":command_available("systemd-run") && command_available("systemctl"),"backend":"systemd-user","supported_operations":["spawn","status","kill","cleanup","admission/status","admission/drain","metrics","filesystem_probe","network_probe","gateway_probe","signal_probe","resource_probe"]}),
        ),
        "spawn" => admit_spawn(&request.params, states, gateways, admissions),
        "admission/status" => {
            let admission = admissions.lock().expect("admission lock");
            Ok(json!({
                "schema":"viper-boxd.admission.v0",
                "max_active_boxes": admission.controller.limit(),
                "active_boxes": admission.controller.active_count(),
                "queued_boxes": admission.controller.queued_count(),
            }))
        }
        "admission/drain" => Ok(json!({
            "status":"DRAINED",
            "started":drain_queue(states, gateways, admissions),
        })),
        "metrics" => {
            let metrics = runtime_metrics(states, admissions);
            Ok(json!({"schema":"viper-boxd.metrics.v0","prometheus":metrics.prometheus()}))
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
        "signal_probe" => run_signal_probe().map(|probe| {
            json!({
                "status": "PROBE_COMPLETED",
                "probe": probe,
                "side_effects": true,
            })
        }),
        "resource_probe" => run_resource_probe().map(|probe| {
            json!({
                "status": "PROBE_COMPLETED",
                "probe": probe,
                "cpu_quota_percent": RESOURCE_PROBE_CPU_QUOTA_PERCENT,
                "memory_limit_bytes": RESOURCE_PROBE_MEMORY_LIMIT_BYTES,
                "side_effects": true,
            })
        }),
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
                ("status", Ok(unit))
                    if states
                        .lock()
                        .ok()
                        .and_then(|s| {
                            s.values()
                                .find(|v| v.unit == unit)
                                .map(|v| v.status == "QUEUED")
                        })
                        .unwrap_or(false) =>
                {
                    Ok(json!({"handle":handle,"unit":unit,"status":"QUEUED"}))
                }
                ("kill" | "cleanup", Ok(unit))
                    if states
                        .lock()
                        .ok()
                        .and_then(|s| {
                            s.iter().find_map(|(box_id, value)| {
                                (value.unit == unit && value.status == "QUEUED")
                                    .then(|| box_id.clone())
                            })
                        })
                        .is_some() =>
                {
                    let box_id = states
                        .lock()
                        .expect("state lock")
                        .iter()
                        .find_map(|(box_id, value)| {
                            (value.unit == unit && value.status == "QUEUED").then(|| box_id.clone())
                        })
                        .expect("queued state was checked above");
                    let cancelled = admissions
                        .lock()
                        .expect("admission lock")
                        .controller
                        .cancel_queued(&box_id);
                    admissions
                        .lock()
                        .expect("admission lock")
                        .pending
                        .remove(&box_id);
                    states.lock().expect("state lock").remove(&box_id);
                    Ok(
                        json!({"handle":handle,"unit":unit,"status":"CANCELLED","box_id":box_id,"cancelled":cancelled}),
                    )
                }
                (_, Ok(unit))
                    if !states
                        .lock()
                        .ok()
                        .map(|s| s.values().any(|value| value.unit == unit))
                        .unwrap_or(false) =>
                {
                    Err(error("ERR_HANDLE_UNKNOWN", "unknown systemd handle"))
                }
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
                        let box_id = states.lock().ok().and_then(|s| {
                            s.iter().find_map(|(box_id, value)| {
                                (value.unit == unit).then(|| box_id.clone())
                            })
                        });
                        if let Ok(mut s) = states.lock() {
                            if let Some(v) = s.values_mut().find(|v| v.unit == unit) {
                                v.status = "KILLED".into();
                            }
                        }
                        let started = box_id
                            .as_deref()
                            .filter(|box_id| {
                                admissions
                                    .lock()
                                    .expect("admission lock")
                                    .controller
                                    .release(box_id)
                            })
                            .map(|_| drain_queue(states, gateways, admissions))
                            .unwrap_or_default();
                        Ok(json!({"handle":handle,"unit":unit,"status":"KILLED","started":started}))
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
                            let started = drain_queue(states, gateways, admissions);
                            Ok(
                                json!({"handle":handle,"unit":unit,"status":"CLEANED","started":started}),
                            )
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
fn serve(
    mut stream: UnixStream,
    states: &States,
    gateways: &GatewayRegistry,
    admissions: &Admissions,
) -> std::io::Result<()> {
    let mut line = String::new();
    let started_at = Instant::now();
    BufReader::new(stream.try_clone()?)
        .take(viper_boxd::ipc::MAX_LINE_BYTES)
        .read_line(&mut line)?;
    let (reply, method) = match serde_json::from_str::<Request>(&line) {
        Ok(req) => {
            let method = req.method.clone();
            (handle(req, states, gateways, admissions), method)
        }
        Err(e) => (
            response(
                "unknown".into(),
                Err(error("ERR_INVALID_REQUEST", e.to_string())),
            ),
            "invalid".into(),
        ),
    };
    if let Some(path) = env::var_os("VIPER_AUDIT_LOG") {
        let fields = json!({
            "request_id": reply.request_id,
            "method": method,
            "ok": reply.ok,
            "audit_trace_id": reply.audit_trace_id,
            "error_code": reply.error.as_ref().map(|value| value.code.as_str()),
        });
        if let Err(error) = append_jsonl(
            std::path::Path::new(&path),
            "helper_ipc",
            &fields,
            started_at.elapsed().as_millis(),
        ) {
            eprintln!("viper-helper: audit JSONL write failed: {error}");
        }
    }
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
    let lineage_dir = env::var_os("VIPER_LINEAGE_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| "/var/lib/viper-boxd/lineage".into());
    if lineage_dir.exists() {
        let reconciled = reconcile_orphaned_boxes(&lineage_dir).map_err(std::io::Error::other)?;
        eprintln!("viper-helper: startup reconciliation completed ({reconciled} orphaned Boxes)");
    } else {
        eprintln!(
            "viper-helper: lineage directory {} is absent; startup reconciliation skipped",
            lineage_dir.display()
        );
    }
    let listener = viper_boxd::ipc::bind_unix_socket(&socket)?;
    eprintln!("viper-helper listening on {socket}");
    let states: States = Arc::new(Mutex::new(BTreeMap::new()));
    let limit = env::var("VIPER_MAX_ACTIVE_BOXES")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(50);
    let admissions: Admissions = Arc::new(Mutex::new(AdmissionState {
        controller: AdmissionController::new(limit).map_err(std::io::Error::other)?,
        pending: BTreeMap::new(),
    }));
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                if viper_boxd::ipc::configure_server_stream(&stream).is_err() {
                    continue;
                }
                if let Err(e) = serve(stream, &states, &gateways, &admissions) {
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
    use super::{
        enforceable_backend_requirement, filesystem_policy, handle, probe_unit_name,
        resolve_network, resource_limits, safe_unit_name, AdmissionState, Admissions,
        GatewayRegistry, States,
    };
    use serde_json::json;
    use serde_json::Value;
    use std::os::unix::net::UnixListener;
    use std::{
        collections::BTreeMap,
        sync::{Arc, Mutex},
    };
    use viper_boxd::{
        admission::AdmissionController,
        ipc::{Request, IPC_VERSION},
    };

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
    fn rejects_overlong_or_control_character_box_ids() {
        assert!(safe_unit_name(&"A".repeat(49)).is_none());
        assert!(safe_unit_name("BOX\nEVIL").is_none());
        assert!(safe_unit_name("BOX\0EVIL").is_none());
        assert!(safe_unit_name("BOX\tEVIL").is_none());
        assert!(safe_unit_name("BOX_OK-123").is_some());
    }

    #[test]
    fn accepts_only_declared_backend_capabilities() {
        for requirement in [
            "systemd",
            "systemd_run",
            "mount_namespace",
            "network_policy",
            "cgroup_limits",
        ] {
            assert!(
                enforceable_backend_requirement(requirement),
                "{requirement}"
            );
        }
        assert!(!enforceable_backend_requirement("arbitrary_command"));
        assert!(!enforceable_backend_requirement("host_network"));
    }

    #[test]
    fn probe_unit_names_do_not_collide_in_one_helper_process() {
        assert_ne!(
            probe_unit_name("resource-probe"),
            probe_unit_name("resource-probe")
        );
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
    fn rejects_attempts_to_raise_or_disable_resource_limits() {
        assert!(
            resource_limits(&json!({"cpu_quota_percent": 0, "memory_limit_bytes": 536870912}))
                .is_err()
        );
        assert!(resource_limits(
            &json!({"cpu_quota_percent": 10_000, "memory_limit_bytes": 536870912})
        )
        .is_err());
        assert!(resource_limits(&json!({"memory_limit_bytes": 536870912})).is_err());
        assert!(resource_limits(&json!({"cpu_quota_percent": 50})).is_err());
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
        assert_eq!(
            plan.gateway_sockets,
            vec![("LIVE".to_owned(), path.to_str().unwrap().to_owned())]
        );

        let _ = std::fs::remove_file(&path);
    }

    fn request(method: &str, params: Value) -> Request {
        Request {
            version: IPC_VERSION.into(),
            request_id: "test".into(),
            method: method.into(),
            params,
        }
    }

    #[test]
    fn rejects_forged_systemd_handles_before_calling_systemctl() {
        let states: States = Arc::new(Mutex::new(BTreeMap::new()));
        let gateways = GatewayRegistry::new();
        let admissions: Admissions = Arc::new(Mutex::new(AdmissionState {
            controller: AdmissionController::new(50).unwrap(),
            pending: BTreeMap::new(),
        }));
        let response = handle(
            request("kill", json!({"handle": "systemd:dbus.service"})),
            &states,
            &gateways,
            &admissions,
        );
        assert!(!response.ok);
        assert_eq!(response.error.unwrap().code, "ERR_HANDLE_UNKNOWN");
    }
}
