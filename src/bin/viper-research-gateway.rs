use serde::Deserialize;
use serde_json::Value;
use std::{
    env, fs,
    io::{BufRead, BufReader, Write},
    os::unix::net::{UnixListener, UnixStream},
    sync::atomic::{AtomicU32, Ordering},
};
use viper_boxd::{
    ipc::{IpcErrorBody, Request, Response, IPC_VERSION},
    research_fetcher,
    research_policy::ResearchPolicy,
};

#[derive(Debug, Deserialize)]
struct GatewayConfig {
    schema: String,
    gateway_id: String,
    allowed_domains: Vec<String>,
    max_requests: u32,
    max_fetch_bytes: usize,
    max_redirects: u8,
    timeout_seconds: u64,
}

impl GatewayConfig {
    fn load(path: &str) -> Result<Self, String> {
        let text = fs::read_to_string(path).map_err(|e| format!("read config: {e}"))?;
        let config: Self = toml::from_str(&text).map_err(|e| format!("parse config: {e}"))?;
        if config.schema != "viper-boxd.research-gateway.v0" {
            return Err("unsupported gateway config schema".into());
        }
        if config.gateway_id.is_empty()
            || config.allowed_domains.is_empty()
            || config.max_requests == 0
            || config.max_fetch_bytes == 0
            || config.timeout_seconds == 0
        {
            return Err("gateway config contains empty or zero policy values".into());
        }
        if config.max_redirects != 0 {
            return Err("redirects must remain disabled in v0".into());
        }
        Ok(config)
    }
    fn policy(&self) -> ResearchPolicy {
        ResearchPolicy {
            allowed_domains: self.allowed_domains.clone(),
            max_requests: self.max_requests,
            max_fetch_bytes: self.max_fetch_bytes,
            max_redirects: self.max_redirects,
            timeout_seconds: self.timeout_seconds,
        }
    }
}

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

fn handle(request: Request, policy: &ResearchPolicy, remaining: &AtomicU32) -> Response {
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
        "FETCH" => {
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
                        "research request budget exhausted",
                    )),
                );
            }
            request
                .params
                .get("url")
                .and_then(Value::as_str)
                .ok_or_else(|| error("ERR_INVALID_REQUEST", "FETCH requires params.url"))
                .and_then(|url| {
                    research_fetcher::fetch(policy, url)
                        .map(|result| {
                            serde_json::to_value(result).expect("fetch result serializes")
                        })
                        .map_err(|v| error(v.code, v.message))
                })
        }
        "SEARCH" => Err(error(
            "ERR_NOT_IMPLEMENTED",
            "SEARCH provider is not configured yet",
        )),
        _ => Err(error(
            "ERR_TOOL_NOT_ALLOWED",
            "only FETCH is enabled by this gateway",
        )),
    };
    response(id, result)
}

fn serve(
    mut stream: UnixStream,
    policy: &ResearchPolicy,
    remaining: &AtomicU32,
) -> std::io::Result<()> {
    let mut line = String::new();
    BufReader::new(stream.try_clone()?).read_line(&mut line)?;
    let reply = match serde_json::from_str::<Request>(&line) {
        Ok(request) => handle(request, policy, remaining),
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
        .unwrap_or_else(|| "/tmp/viper-research-gateway.sock".into());
    let config_path = env::args()
        .nth(2)
        .unwrap_or_else(|| "examples/research-gateway.toml".into());
    let config = GatewayConfig::load(&config_path).map_err(std::io::Error::other)?;
    let _ = fs::remove_file(&socket);
    let listener = UnixListener::bind(&socket)?;
    eprintln!(
        "viper-research-gateway listening on {socket} ({})",
        config.gateway_id
    );
    let policy = config.policy();
    let remaining = AtomicU32::new(config.max_requests);
    for stream in listener.incoming().flatten() {
        let _ = serve(stream, &policy, &remaining);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::GatewayConfig;
    #[test]
    fn rejects_unknown_schema() {
        let path = "/tmp/viper-invalid-gateway.toml";
        std::fs::write(path, "schema='bad'\ngateway_id='x'\nallowed_domains=['x']\nmax_requests=1\nmax_fetch_bytes=1\nmax_redirects=0\ntimeout_seconds=1\n").unwrap();
        assert!(GatewayConfig::load(path).is_err());
        let _ = std::fs::remove_file(path);
    }
}
