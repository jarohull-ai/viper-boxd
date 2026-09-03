#[cfg(test)]
mod noop_backend;

use jfp_box::{parse_manifest, sha256_hex, validate};
use serde::Deserialize;
use serde_json::json;
use std::{env, fs, process::ExitCode, thread, time::Duration};
use viper_boxd::ipc::{send_request, Request, IPC_VERSION};

#[derive(Debug, Deserialize)]
struct Profile {
    schema: String,
    profile_id: String,
    network_mode: String,
    direct_network: String,
    #[serde(default)]
    allowed_gateways: Vec<String>,
    #[serde(default)]
    tool_bindings: Vec<String>,
    #[serde(default)]
    required_backend: Vec<String>,
    write_target: String,
    filesystem_mode: String,
    execution_ttl_seconds: u64,
    cpu_quota_percent: u64,
    memory_limit_bytes: u64,
}

fn usage() {
    eprintln!("Usage:");
    eprintln!("  viper-boxd plan --manifest FILE --profile FILE --workspace-id ID [--json]");
    eprintln!("  viper-boxd capabilities");
    eprintln!("  viper-boxd backend-self-test --socket PATH");
}

fn arg_value(args: &[String], name: &str) -> Option<String> {
    args.windows(2)
        .find(|pair| pair[0] == name)
        .map(|pair| pair[1].clone())
}

fn parse_list(value: &str) -> Result<Vec<String>, String> {
    let trimmed = value.trim();
    let inner = trimmed
        .strip_prefix('[')
        .and_then(|v| v.strip_suffix(']'))
        .ok_or_else(|| "expected bracketed list".to_owned())?;
    if inner.trim().is_empty() {
        return Ok(Vec::new());
    }
    inner
        .split(',')
        .map(|item| item.trim().to_owned())
        .collect::<Vec<_>>()
        .into_iter()
        .map(|item| {
            if item.is_empty() {
                Err("empty list item".to_owned())
            } else {
                Ok(item)
            }
        })
        .collect()
}

fn compare_list(manifest_value: Option<&str>, profile_values: &[String]) -> Result<bool, String> {
    let mut expected = profile_values.to_vec();
    expected.sort();
    let mut actual = parse_list(manifest_value.ok_or_else(|| "field missing".to_owned())?)?;
    actual.sort();
    Ok(actual == expected)
}

fn run_plan(args: &[String]) -> Result<(serde_json::Value, u8), String> {
    let manifest_path =
        arg_value(args, "--manifest").ok_or_else(|| "missing --manifest".to_owned())?;
    let profile_path =
        arg_value(args, "--profile").ok_or_else(|| "missing --profile".to_owned())?;
    let workspace_id =
        arg_value(args, "--workspace-id").ok_or_else(|| "missing --workspace-id".to_owned())?;
    let manifest_bytes = fs::read(&manifest_path).map_err(|e| format!("read manifest: {e}"))?;
    let manifest_text =
        std::str::from_utf8(&manifest_bytes).map_err(|e| format!("manifest is not UTF-8: {e}"))?;
    let profile_text =
        fs::read_to_string(&profile_path).map_err(|e| format!("read profile: {e}"))?;
    let profile: Profile =
        toml::from_str(&profile_text).map_err(|e| format!("parse profile: {e}"))?;

    let mut errors = Vec::new();
    let manifest = match parse_manifest(manifest_text) {
        Ok(value) => Some(value),
        Err(violations) => {
            errors.extend(violations.iter().map(|v| v.code().to_owned()));
            None
        }
    };
    if let Some(ref manifest) = manifest {
        errors.extend(validate(manifest).iter().map(|v| v.code().to_owned()));
        if manifest.get("NETWORK_MODE") != Some(profile.network_mode.as_str()) {
            errors.push("ERR_PROFILE_MODE_MISMATCH".to_owned());
        }
        if manifest.get("DIRECT_NETWORK") != Some(profile.direct_network.as_str()) {
            errors.push("ERR_PROFILE_NETWORK_MISMATCH".to_owned());
        }
        if !compare_list(manifest.get("ALLOWED_GATEWAYS"), &profile.allowed_gateways)
            .unwrap_or(false)
        {
            errors.push("ERR_PROFILE_GATEWAYS_MISMATCH".to_owned());
        }
        if !compare_list(manifest.get("TOOL_BINDINGS"), &profile.tool_bindings).unwrap_or(false) {
            errors.push("ERR_PROFILE_TOOLS_MISMATCH".to_owned());
        }
    }

    let accepted = errors.is_empty();
    let task_id = manifest
        .as_ref()
        .and_then(|m| m.get("TASK_ID"))
        .unwrap_or("UNKNOWN");
    let output = json!({
        "schema": "viper-boxd.plan.v0",
        "plan_status": if accepted { "PLAN_ACCEPTED" } else { "PLAN_REJECTED" },
        "execution_mode": "SIMULATION_ONLY",
        "side_effects": false,
        "task_id": task_id,
        "workspace_id": workspace_id,
        "profile_id": profile.profile_id,
        "profile_schema": profile.schema,
        "manifest_sha256": sha256_hex(&manifest_bytes),
        "would_apply": {
            "backend_capabilities": profile.required_backend,
            "network_mode": profile.network_mode,
            "direct_network": profile.direct_network,
            "allowed_gateways": profile.allowed_gateways,
            "tool_bindings": profile.tool_bindings,
            "write_target": profile.write_target,
            "filesystem_mode": profile.filesystem_mode,
            "execution_ttl_seconds": profile.execution_ttl_seconds,
            "cpu_quota_percent": profile.cpu_quota_percent,
            "memory_limit_bytes": profile.memory_limit_bytes
        },
        "errors": errors
    });
    Ok((output, if accepted { 0 } else { 1 }))
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    if args.get(1).map(String::as_str) == Some("capabilities") {
        println!(
            "{}",
            serde_json::to_string_pretty(&viper_boxd::capabilities::probe())
                .expect("JSON serialization cannot fail")
        );
        return ExitCode::SUCCESS;
    }
    if args.get(1).map(String::as_str) == Some("backend-self-test") {
        let socket = arg_value(&args[2..], "--socket")
            .unwrap_or_else(|| "/tmp/viper-helper-mock.sock".into());
        let selftest_box = format!("SELFTEST_BOX_{}", std::process::id());
        let result = (|| {
            let request = |request_id: &str, method: &str, params: serde_json::Value| Request {
                version: IPC_VERSION.into(),
                request_id: request_id.into(),
                method: method.into(),
                params,
            };
            let capabilities = send_request(&socket, &request("req-0", "capabilities", json!({})))
                .map_err(|error| error.to_string())?;
            if !capabilities.ok
                || capabilities
                    .result
                    .as_ref()
                    .and_then(|result| result.get("schema"))
                    .and_then(|schema| schema.as_str())
                    != Some("viper-boxd.capabilities.v0")
            {
                return Err("helper returned an invalid capabilities response".into());
            }
            let helper_backend = capabilities
                .result
                .as_ref()
                .and_then(|result| result.get("backend"))
                .and_then(|backend| backend.as_str())
                .unwrap_or("unknown");
            let refused = send_request(
                &socket,
                &request(
                    "req-1",
                    "spawn",
                    json!({"box_id": format!("UNSUPPORTED_BOX_{}", std::process::id()), "required_backend": ["mount_namespace"], "cpu_quota_percent": 50, "memory_limit_bytes": 268435456}),
                ),
            )
            .map_err(|error| error.to_string())?;
            if refused.ok
                || refused.error.as_ref().map(|error| error.code.as_str()) != Some("FAIL_CLOSED")
            {
                return Err("mock helper accepted an unenforceable capability request".into());
            }
            let ttl_test = helper_backend != "mock";
            let spawn_params = if ttl_test {
                json!({"box_id": selftest_box, "required_backend": [], "ttl_seconds": 2, "sleep_seconds": 30, "cpu_quota_percent": 50, "memory_limit_bytes": 268435456, "filesystem_mode": "STRICT", "write_target": "scratch"})
            } else {
                json!({"box_id": selftest_box, "required_backend": [], "cpu_quota_percent": 50, "memory_limit_bytes": 268435456, "filesystem_mode": "STRICT", "write_target": "scratch"})
            };
            let spawn = send_request(&socket, &request("req-2", "spawn", spawn_params))
                .map_err(|error| error.to_string())?;
            let handle = spawn
                .result
                .as_ref()
                .and_then(|result| result.get("handle"))
                .and_then(|value| value.as_str())
                .ok_or_else(|| "spawn did not return a handle".to_owned())?
                .to_owned();
            if ttl_test {
                thread::sleep(Duration::from_secs(6));
            }
            let running = send_request(
                &socket,
                &request("req-3", "status", json!({"handle": handle})),
            )
            .map_err(|error| error.to_string())?;
            if ttl_test
                && running
                    .result
                    .as_ref()
                    .and_then(|result| result.get("status"))
                    .and_then(|status| status.as_str())
                    != Some("TIMED_OUT")
            {
                return Err("systemd helper did not report TIMED_OUT".into());
            }
            let killed = send_request(
                &socket,
                &request("req-4", "kill", json!({"handle": handle})),
            )
            .map_err(|error| error.to_string())?;
            let cleaned = send_request(
                &socket,
                &request("req-5", "cleanup", json!({"handle": handle})),
            )
            .map_err(|error| error.to_string())?;
            Ok::<_, String>(json!({
                "schema": "viper-boxd.backend.ipc-self-test.v0",
                "ipc_version": IPC_VERSION,
                "execution_mode": if helper_backend == "mock" { "MOCK_HELPER_OVER_UNIX_SOCKET" } else { "SYSTEMD_HELPER_OVER_UNIX_SOCKET" },
                "side_effects": helper_backend != "mock",
                "helper_backend": helper_backend,
                "socket": socket,
                "responses": [capabilities, refused, spawn, running, killed, cleaned]
            }))
        })();
        match result {
            Ok(output) => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&output).expect("JSON serialization cannot fail")
                );
                return ExitCode::SUCCESS;
            }
            Err(error) => {
                eprintln!("backend self-test error: {error}");
                return ExitCode::from(2);
            }
        }
    }
    if args.get(1).map(String::as_str) != Some("plan") {
        usage();
        return ExitCode::from(2);
    }
    match run_plan(&args[2..]) {
        Ok((output, code)) => {
            println!(
                "{}",
                serde_json::to_string_pretty(&output).expect("JSON serialization cannot fail")
            );
            ExitCode::from(code)
        }
        Err(error) => {
            eprintln!("viper-boxd plan error: {error}");
            usage();
            ExitCode::from(2)
        }
    }
}
