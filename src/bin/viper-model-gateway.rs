use serde::Deserialize;
use serde_json::Value;
use std::{
    env, fs,
    io::{BufRead, BufReader, Write},
    os::unix::net::{UnixListener, UnixStream},
    sync::atomic::{AtomicU32, Ordering},
};
use viper_boxd::{
    ipc::{ipc_error as error, respond as response, Request, Response, IPC_VERSION},
    model_provider::{self, OllamaTransport},
};

#[derive(Debug, Deserialize)]
struct GatewayConfig {
    schema: String,
    gateway_id: String,
    provider: String,
    endpoint: String,
    model: String,
    max_requests: u32,
    max_prompt_chars: usize,
    max_output_tokens: u32,
    timeout_seconds: u64,
}

impl GatewayConfig {
    fn load(path: &str) -> Result<Self, String> {
        let text = fs::read_to_string(path).map_err(|e| format!("read config: {e}"))?;
        let config: Self = toml::from_str(&text).map_err(|e| format!("parse config: {e}"))?;
        if config.schema != "viper-boxd.model-gateway.v0" {
            return Err("unsupported gateway config schema".into());
        }
        if config.provider != "ollama" {
            return Err(format!("unsupported model provider: {}", config.provider));
        }
        if config.gateway_id.is_empty()
            || config.endpoint.is_empty()
            || config.model.is_empty()
            || config.max_requests == 0
            || config.max_prompt_chars == 0
            || config.max_output_tokens == 0
            || config.timeout_seconds == 0
        {
            return Err("gateway config contains empty or zero policy values".into());
        }
        Ok(config)
    }
}

fn handle(request: Request, config: &GatewayConfig, remaining: &AtomicU32) -> Response {
    if request.version != IPC_VERSION {
        return response(
            request.request_id,
            Err(error(
                "ERR_UNSUPPORTED_SCHEMA",
                "unsupported gateway version",
            )),
        );
    }
    let id = request.request_id;
    let result = match request.method.as_str() {
        "MODEL_GENERATE" => {
            if remaining
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                    value.checked_sub(1)
                })
                .is_err()
            {
                return response(
                    id,
                    Err(error(
                        "ERR_REQUEST_LIMIT_EXCEEDED",
                        "model request budget exhausted",
                    )),
                );
            }
            request
                .params
                .get("prompt")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    error("ERR_INVALID_REQUEST", "MODEL_GENERATE requires params.prompt")
                })
                .and_then(|prompt| {
                    model_provider::generate(
                        &OllamaTransport,
                        &config.endpoint,
                        &config.model,
                        prompt,
                        config.max_prompt_chars,
                        config.max_output_tokens,
                        config.timeout_seconds,
                    )
                    .map(|result| {
                        serde_json::to_value(result).expect("generate result serializes")
                    })
                    .map_err(|v| error(v.code, v.message))
                })
        }
        _ => Err(error(
            "ERR_TOOL_NOT_ALLOWED",
            "only MODEL_GENERATE is enabled by this gateway",
        )),
    };
    response(id, result)
}

fn serve(
    mut stream: UnixStream,
    config: &GatewayConfig,
    remaining: &AtomicU32,
) -> std::io::Result<()> {
    let mut line = String::new();
    BufReader::new(stream.try_clone()?).read_line(&mut line)?;
    let reply = match serde_json::from_str::<Request>(&line) {
        Ok(request) => handle(request, config, remaining),
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
        .unwrap_or_else(|| "/tmp/viper-model-gateway.sock".into());
    let config_path = env::args()
        .nth(2)
        .unwrap_or_else(|| "examples/model-gateway.toml".into());
    let config = GatewayConfig::load(&config_path).map_err(std::io::Error::other)?;
    let _ = fs::remove_file(&socket);
    let listener = UnixListener::bind(&socket)?;
    eprintln!(
        "viper-model-gateway listening on {socket} ({})",
        config.gateway_id
    );
    let remaining = AtomicU32::new(config.max_requests);
    for stream in listener.incoming().flatten() {
        let _ = serve(stream, &config, &remaining);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{handle, GatewayConfig};
    use serde_json::json;
    use std::sync::atomic::AtomicU32;
    use viper_boxd::ipc::{Request, IPC_VERSION};

    #[test]
    fn rejects_unknown_schema() {
        let path = "/tmp/viper-invalid-model-gateway.toml";
        std::fs::write(path, "schema='bad'\ngateway_id='x'\nprovider='ollama'\nendpoint='http://127.0.0.1:11434'\nmodel='m'\nmax_requests=1\nmax_prompt_chars=1\nmax_output_tokens=1\ntimeout_seconds=1\n").unwrap();
        assert!(GatewayConfig::load(path).is_err());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn rejects_unsupported_provider() {
        let path = "/tmp/viper-unsupported-model-gateway.toml";
        std::fs::write(path, "schema='viper-boxd.model-gateway.v0'\ngateway_id='x'\nprovider='openai'\nendpoint='http://127.0.0.1:11434'\nmodel='m'\nmax_requests=1\nmax_prompt_chars=1\nmax_output_tokens=1\ntimeout_seconds=1\n").unwrap();
        assert!(GatewayConfig::load(path).is_err());
        let _ = std::fs::remove_file(path);
    }

    fn config() -> GatewayConfig {
        GatewayConfig {
            schema: "viper-boxd.model-gateway.v0".into(),
            gateway_id: "TEST".into(),
            provider: "ollama".into(),
            endpoint: "http://127.0.0.1:11434".into(),
            model: "test-model".into(),
            max_requests: 2,
            max_prompt_chars: 1000,
            max_output_tokens: 128,
            timeout_seconds: 5,
        }
    }

    fn request(method: &str, params: serde_json::Value) -> Request {
        Request {
            version: IPC_VERSION.into(),
            request_id: "test".into(),
            method: method.into(),
            params,
        }
    }

    #[test]
    fn rejects_unknown_tool() {
        let budget = AtomicU32::new(2);
        let response = handle(request("SHELL", json!({})), &config(), &budget);
        assert_eq!(response.error.unwrap().code, "ERR_TOOL_NOT_ALLOWED");
    }

    #[test]
    fn rejects_missing_prompt() {
        let budget = AtomicU32::new(2);
        let response = handle(request("MODEL_GENERATE", json!({})), &config(), &budget);
        assert_eq!(response.error.unwrap().code, "ERR_INVALID_REQUEST");
    }

    #[test]
    fn enforces_request_budget_before_transport() {
        let budget = AtomicU32::new(1);
        let first = handle(
            request("MODEL_GENERATE", json!({})),
            &config(),
            &budget,
        );
        assert!(!first.ok);
        assert_eq!(budget.load(std::sync::atomic::Ordering::Acquire), 0);
        let second = handle(
            request("MODEL_GENERATE", json!({"prompt": "hi"})),
            &config(),
            &budget,
        );
        assert_eq!(second.error.unwrap().code, "ERR_REQUEST_LIMIT_EXCEEDED");
    }

    #[test]
    fn rejects_wrong_version() {
        let mut r = request("MODEL_GENERATE", json!({"prompt": "hi"}));
        r.version = "0.9".into();
        let budget = AtomicU32::new(2);
        assert_eq!(
            handle(r, &config(), &budget).error.unwrap().code,
            "ERR_UNSUPPORTED_SCHEMA"
        );
    }
}
