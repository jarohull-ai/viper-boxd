use serde::Deserialize;
use serde_json::Value;
use std::{
    env, fs,
    io::{BufRead, BufReader, Read, Write},
    os::unix::net::UnixStream,
    sync::atomic::{AtomicU32, Ordering},
};
use viper_boxd::{
    ipc::{ipc_error as error, respond as response, Request, Response, IPC_VERSION},
    research_fetcher,
    research_policy::ResearchPolicy,
    search_provider::{self, BraveSearchTransport},
};

#[derive(Debug, Deserialize)]
struct SearchConfig {
    provider: String,
    api_key_env: String,
}

#[derive(Debug, Deserialize)]
struct GatewayConfig {
    schema: String,
    gateway_id: String,
    allowed_domains: Vec<String>,
    max_requests: u32,
    max_fetch_bytes: usize,
    max_redirects: u8,
    timeout_seconds: u64,
    #[serde(default)]
    search: Option<SearchConfig>,
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
    /// Resolves the configured search provider's API key from its named
    /// environment variable. The key never lives in the config file itself,
    /// and a configured-but-unresolvable provider is a startup error rather
    /// than a silently disabled feature.
    fn resolved_search_key(&self) -> Result<Option<String>, String> {
        let Some(search) = &self.search else {
            return Ok(None);
        };
        if search.provider != "brave" {
            return Err(format!("unsupported search provider: {}", search.provider));
        }
        let key = env::var(&search.api_key_env).map_err(|_| {
            format!(
                "search is configured but environment variable {} is not set",
                search.api_key_env
            )
        })?;
        if key.is_empty() {
            return Err(format!(
                "environment variable {} is set but empty",
                search.api_key_env
            ));
        }
        Ok(Some(key))
    }
}

fn handle(
    request: Request,
    policy: &ResearchPolicy,
    remaining: &AtomicU32,
    search_key: Option<&str>,
) -> Response {
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
        "SEARCH" => {
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
            match search_key {
                None => Err(error(
                    "ERR_NOT_IMPLEMENTED",
                    "SEARCH provider is not configured",
                )),
                Some(api_key) => request
                    .params
                    .get("query")
                    .and_then(Value::as_str)
                    .ok_or_else(|| error("ERR_INVALID_REQUEST", "SEARCH requires params.query"))
                    .and_then(|query| {
                        search_provider::search(&BraveSearchTransport, api_key, query)
                            .map(|result| {
                                serde_json::to_value(result).expect("search result serializes")
                            })
                            .map_err(|v| error(v.code, v.message))
                    }),
            }
        }
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
    search_key: Option<&str>,
) -> std::io::Result<()> {
    let mut line = String::new();
    BufReader::new(stream.try_clone()?)
        .take(viper_boxd::ipc::MAX_LINE_BYTES)
        .read_line(&mut line)?;
    let reply = match serde_json::from_str::<Request>(&line) {
        Ok(request) => handle(request, policy, remaining, search_key),
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
    let search_key = config
        .resolved_search_key()
        .map_err(std::io::Error::other)?;
    let listener = viper_boxd::ipc::bind_unix_socket(&socket)?;
    eprintln!(
        "viper-research-gateway listening on {socket} ({})",
        config.gateway_id
    );
    let policy = config.policy();
    let remaining = AtomicU32::new(config.max_requests);
    for stream in listener.incoming().flatten() {
        if viper_boxd::ipc::configure_server_stream(&stream).is_err() {
            continue;
        }
        let _ = serve(stream, &policy, &remaining, search_key.as_deref());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{handle, GatewayConfig};
    use serde_json::json;
    use std::sync::atomic::AtomicU32;
    use viper_boxd::{
        ipc::{Request, IPC_VERSION},
        research_policy::ResearchPolicy,
    };
    #[test]
    fn rejects_unknown_schema() {
        let path = "/tmp/viper-invalid-gateway.toml";
        std::fs::write(path, "schema='bad'\ngateway_id='x'\nallowed_domains=['x']\nmax_requests=1\nmax_fetch_bytes=1\nmax_redirects=0\ntimeout_seconds=1\n").unwrap();
        assert!(GatewayConfig::load(path).is_err());
        let _ = std::fs::remove_file(path);
    }

    fn base_config(name: &str, search_table: &str) -> GatewayConfig {
        let path = format!(
            "/tmp/viper-search-config-test-{name}-{}.toml",
            std::process::id()
        );
        std::fs::write(
            &path,
            format!(
                "schema='viper-boxd.research-gateway.v0'\ngateway_id='x'\nallowed_domains=['x']\nmax_requests=1\nmax_fetch_bytes=1\nmax_redirects=0\ntimeout_seconds=1\n{search_table}"
            ),
        )
        .unwrap();
        let config = GatewayConfig::load(&path).expect("valid base config");
        let _ = std::fs::remove_file(&path);
        config
    }

    #[test]
    fn no_search_table_resolves_to_none() {
        let config = base_config("no-search", "");
        assert!(config.resolved_search_key().expect("resolves").is_none());
    }

    #[test]
    fn unsupported_search_provider_is_rejected() {
        let config = base_config(
            "bad-provider",
            "[search]\nprovider='google'\napi_key_env='X'\n",
        );
        assert!(config.resolved_search_key().is_err());
    }

    #[test]
    fn configured_search_without_the_env_var_set_is_rejected() {
        let env_var = "VIPER_TEST_SEARCH_KEY_UNSET";
        std::env::remove_var(env_var);
        let config = base_config(
            "key-unset",
            &format!("[search]\nprovider='brave'\napi_key_env='{env_var}'\n"),
        );
        assert!(config.resolved_search_key().is_err());
    }

    #[test]
    fn configured_search_reads_the_key_from_its_named_env_var() {
        let env_var = "VIPER_TEST_SEARCH_KEY_SET";
        std::env::set_var(env_var, "test-key-value");
        let config = base_config(
            "key-set",
            &format!("[search]\nprovider='brave'\napi_key_env='{env_var}'\n"),
        );
        assert_eq!(
            config.resolved_search_key().expect("resolves"),
            Some("test-key-value".to_owned())
        );
        std::env::remove_var(env_var);
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
    fn rejects_missing_url_and_unsupported_search() {
        let policy = ResearchPolicy::mock();
        let budget = AtomicU32::new(2);
        assert_eq!(
            handle(request("FETCH", json!({})), &policy, &budget, None)
                .error
                .unwrap()
                .code,
            "ERR_INVALID_REQUEST"
        );
        assert_eq!(
            handle(request("SEARCH", json!({"query":"x"})), &policy, &budget, None)
                .error
                .unwrap()
                .code,
            "ERR_NOT_IMPLEMENTED"
        );
    }

    #[test]
    fn enforces_request_budget_before_transport() {
        let policy = ResearchPolicy::mock();
        let budget = AtomicU32::new(1);
        let first = handle(
            request("FETCH", json!({"url":"https://not-allowlisted.invalid"})),
            &policy,
            &budget,
            None,
        );
        assert!(!first.ok);
        assert_eq!(budget.load(std::sync::atomic::Ordering::Acquire), 0);
        let second = handle(
            request("FETCH", json!({"url":"https://example.invalid"})),
            &policy,
            &budget,
            None,
        );
        assert_eq!(second.error.unwrap().code, "ERR_REQUEST_LIMIT_EXCEEDED");
    }

    #[test]
    fn search_also_consumes_the_shared_request_budget() {
        let policy = ResearchPolicy::mock();
        let budget = AtomicU32::new(1);
        let first = handle(request("SEARCH", json!({"query":"x"})), &policy, &budget, None);
        assert!(!first.ok);
        assert_eq!(budget.load(std::sync::atomic::Ordering::Acquire), 0);
        let second = handle(request("SEARCH", json!({"query":"x"})), &policy, &budget, None);
        assert_eq!(second.error.unwrap().code, "ERR_REQUEST_LIMIT_EXCEEDED");
    }

    #[test]
    fn configured_search_still_validates_the_query_before_any_transport_call() {
        let policy = ResearchPolicy::mock();
        let budget = AtomicU32::new(2);
        let response = handle(
            request("SEARCH", json!({})),
            &policy,
            &budget,
            Some("fake-key-never-sent"),
        );
        assert_eq!(response.error.unwrap().code, "ERR_INVALID_REQUEST");
    }

    #[test]
    fn rejects_unknown_tool_and_client_options() {
        let policy = ResearchPolicy::mock();
        let budget = AtomicU32::new(2);
        let response = handle(
            request(
                "SHELL",
                json!({"proxy":"http://evil.invalid", "max_fetch_bytes": 1}),
            ),
            &policy,
            &budget,
            None,
        );
        assert_eq!(response.error.unwrap().code, "ERR_TOOL_NOT_ALLOWED");
    }
}
