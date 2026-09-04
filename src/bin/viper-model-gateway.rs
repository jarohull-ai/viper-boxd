use serde::Deserialize;
use serde_json::Value;
use std::{
    env, fs,
    io::{BufRead, BufReader, Write},
    os::unix::net::{UnixListener, UnixStream},
    sync::atomic::{AtomicU32, Ordering},
};
use viper_boxd::{
    ipc::{ipc_error as error, respond as response, stream_chunk, Request, Response, IPC_VERSION},
    model_provider::{
        self, AnthropicTransport, OllamaEmbedTransport, OllamaStreamTransport, OllamaTransport,
        OpenAiCompatibleEmbedTransport, OpenAiCompatibleStreamTransport, OpenAiCompatibleTransport,
    },
};

const SUPPORTED_PROVIDERS: &[&str] = &["ollama", "openai", "anthropic", "openrouter"];

#[derive(Debug, Deserialize)]
struct EmbedConfig {
    model: String,
    max_input_chars: usize,
}

/// Opt-in, `ollama`-only (STREAM_PLAN.md). Its absence keeps
/// `params.stream: true` returning `ERR_NOT_IMPLEMENTED`, same pattern as
/// `[embed]`.
#[derive(Debug, Deserialize)]
struct StreamConfig {
    idle_timeout_seconds: u64,
    max_stream_duration_seconds: u64,
}

#[derive(Debug, Deserialize)]
struct GatewayConfig {
    schema: String,
    gateway_id: String,
    provider: String,
    endpoint: String,
    model: String,
    #[serde(default)]
    api_key_env: Option<String>,
    max_requests: u32,
    max_prompt_chars: usize,
    max_output_tokens: u32,
    timeout_seconds: u64,
    #[serde(default)]
    embed: Option<EmbedConfig>,
    #[serde(default)]
    stream: Option<StreamConfig>,
}

impl GatewayConfig {
    fn load(path: &str) -> Result<Self, String> {
        let text = fs::read_to_string(path).map_err(|e| format!("read config: {e}"))?;
        let config: Self = toml::from_str(&text).map_err(|e| format!("parse config: {e}"))?;
        if config.schema != "viper-boxd.model-gateway.v0" {
            return Err("unsupported gateway config schema".into());
        }
        if !SUPPORTED_PROVIDERS.contains(&config.provider.as_str()) {
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
        let requires_key = config.provider != "ollama";
        if requires_key && config.api_key_env.as_deref().unwrap_or("").is_empty() {
            return Err(format!(
                "provider {} requires api_key_env",
                config.provider
            ));
        }
        if let Some(embed) = &config.embed {
            if config.provider == "anthropic" {
                return Err("anthropic has no embeddings API; remove [embed]".into());
            }
            if embed.model.is_empty() || embed.max_input_chars == 0 {
                return Err("embed config contains empty or zero policy values".into());
            }
        }
        if let Some(stream) = &config.stream {
            if config.provider == "anthropic" {
                return Err(
                    "streaming is not yet implemented for provider anthropic".into(),
                );
            }
            if stream.idle_timeout_seconds == 0 || stream.max_stream_duration_seconds == 0 {
                return Err("stream config contains empty or zero policy values".into());
            }
            if stream.idle_timeout_seconds > stream.max_stream_duration_seconds {
                return Err(
                    "stream idle_timeout_seconds must not exceed max_stream_duration_seconds"
                        .into(),
                );
            }
        }
        Ok(config)
    }

    /// Resolves the configured provider's API key from its named
    /// environment variable. The key never lives in the config file, and a
    /// keyed provider with an unset or empty key is a startup error rather
    /// than a silently disabled feature. `ollama` needs no key.
    fn resolved_api_key(&self) -> Result<Option<String>, String> {
        let Some(env_var) = &self.api_key_env else {
            return Ok(None);
        };
        let key = env::var(env_var).map_err(|_| {
            format!("provider is configured but environment variable {env_var} is not set")
        })?;
        if key.is_empty() {
            return Err(format!("environment variable {env_var} is set but empty"));
        }
        Ok(Some(key))
    }
}

fn handle(
    request: Request,
    config: &GatewayConfig,
    remaining: &AtomicU32,
    api_key: Option<&str>,
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
                    let outcome = match config.provider.as_str() {
                        "ollama" => model_provider::generate(
                            &OllamaTransport,
                            &config.endpoint,
                            &config.model,
                            prompt,
                            config.max_prompt_chars,
                            config.max_output_tokens,
                            config.timeout_seconds,
                        ),
                        "openai" | "openrouter" => model_provider::generate_openai_compatible(
                            &OpenAiCompatibleTransport {
                                api_key: api_key
                                    .expect("keyed provider validated at config load")
                                    .to_owned(),
                            },
                            &config.endpoint,
                            &config.model,
                            prompt,
                            config.max_prompt_chars,
                            config.max_output_tokens,
                            config.timeout_seconds,
                        ),
                        "anthropic" => model_provider::generate_anthropic(
                            &AnthropicTransport {
                                api_key: api_key
                                    .expect("keyed provider validated at config load")
                                    .to_owned(),
                            },
                            &config.endpoint,
                            &config.model,
                            prompt,
                            config.max_prompt_chars,
                            config.max_output_tokens,
                            config.timeout_seconds,
                        ),
                        other => unreachable!("provider {other} validated at config load"),
                    };
                    outcome
                        .map(|result| {
                            serde_json::to_value(result).expect("generate result serializes")
                        })
                        .map_err(|v| error(v.code, v.message))
                })
        }
        "EMBED" => {
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
            match &config.embed {
                None => Err(error(
                    "ERR_NOT_IMPLEMENTED",
                    "EMBED provider is not configured",
                )),
                Some(embed_config) => request
                    .params
                    .get("input")
                    .and_then(Value::as_str)
                    .ok_or_else(|| error("ERR_INVALID_REQUEST", "EMBED requires params.input"))
                    .and_then(|input| {
                        let result = match config.provider.as_str() {
                            "ollama" => model_provider::embed(
                                &OllamaEmbedTransport,
                                &config.endpoint,
                                &embed_config.model,
                                input,
                                embed_config.max_input_chars,
                                config.timeout_seconds,
                            ),
                            "openai" | "openrouter" => model_provider::embed_openai_compatible(
                                &OpenAiCompatibleEmbedTransport {
                                    api_key: api_key
                                        .expect("keyed provider validated at config load")
                                        .to_owned(),
                                },
                                &config.endpoint,
                                &embed_config.model,
                                input,
                                embed_config.max_input_chars,
                                config.timeout_seconds,
                            ),
                            other => unreachable!("provider {other} validated at config load"),
                        };
                        result
                            .map(|result| {
                                serde_json::to_value(result).expect("embed result serializes")
                            })
                            .map_err(|v| error(v.code, v.message))
                    }),
            }
        }
        _ => Err(error(
            "ERR_TOOL_NOT_ALLOWED",
            "only MODEL_GENERATE and EMBED are enabled by this gateway",
        )),
    };
    response(id, result)
}

fn write_stream_chunk(
    stream: &mut UnixStream,
    chunk: &viper_boxd::ipc::StreamChunk,
) -> std::io::Result<()> {
    serde_json::to_writer(&mut *stream, chunk).map_err(std::io::Error::other)?;
    stream.write_all(b"\n")?;
    stream.flush()
}

/// Handles one `MODEL_GENERATE` request with `params.stream: true`: writes a
/// sequence of `StreamChunk` frames instead of the single `Response` the
/// non-streaming path in `handle` writes. See STREAM_PLAN.md.
fn serve_stream(
    mut stream: UnixStream,
    request: Request,
    config: &GatewayConfig,
    remaining: &AtomicU32,
    api_key: Option<&str>,
) -> std::io::Result<()> {
    let request_id = request.request_id;

    if request.version != IPC_VERSION {
        let chunk = stream_chunk(
            request_id,
            0,
            String::new(),
            true,
            Some(error("ERR_UNSUPPORTED_SCHEMA", "unsupported gateway version")),
        );
        return write_stream_chunk(&mut stream, &chunk);
    }

    if remaining
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
            value.checked_sub(1)
        })
        .is_err()
    {
        let chunk = stream_chunk(
            request_id,
            0,
            String::new(),
            true,
            Some(error(
                "ERR_REQUEST_LIMIT_EXCEEDED",
                "model request budget exhausted",
            )),
        );
        return write_stream_chunk(&mut stream, &chunk);
    }

    let Some(stream_config) = &config.stream else {
        let chunk = stream_chunk(
            request_id,
            0,
            String::new(),
            true,
            Some(error("ERR_NOT_IMPLEMENTED", "streaming is not configured")),
        );
        return write_stream_chunk(&mut stream, &chunk);
    };

    let prompt = match request.params.get("prompt").and_then(Value::as_str) {
        Some(prompt) => prompt.to_owned(),
        None => {
            let chunk = stream_chunk(
                request_id,
                0,
                String::new(),
                true,
                Some(error(
                    "ERR_INVALID_REQUEST",
                    "MODEL_GENERATE requires params.prompt",
                )),
            );
            return write_stream_chunk(&mut stream, &chunk);
        }
    };

    let transport: Box<dyn model_provider::ModelStreamTransport> = match config.provider.as_str() {
        "ollama" => Box::new(OllamaStreamTransport),
        "openai" | "openrouter" => Box::new(OpenAiCompatibleStreamTransport {
            api_key: api_key
                .expect("keyed provider validated at config load")
                .to_owned(),
        }),
        other => unreachable!("provider {other} validated at config load for streaming"),
    };

    let mut sequence: u64 = 0;
    let mut io_result: std::io::Result<()> = Ok(());
    let outcome = model_provider::generate_stream(
        transport.as_ref(),
        &config.endpoint,
        &config.model,
        &prompt,
        config.max_prompt_chars,
        config.max_output_tokens,
        stream_config.idle_timeout_seconds,
        stream_config.max_stream_duration_seconds,
        &mut |delta, done| {
            let chunk = stream_chunk(request_id.clone(), sequence, delta.to_owned(), done, None);
            sequence += 1;
            if let Err(e) = write_stream_chunk(&mut stream, &chunk) {
                io_result = Err(e);
            }
        },
    );
    io_result?;

    if let Err(violation) = outcome {
        let chunk = stream_chunk(
            request_id,
            sequence,
            String::new(),
            true,
            Some(error(violation.code, violation.message)),
        );
        write_stream_chunk(&mut stream, &chunk)?;
    }
    Ok(())
}

fn serve(
    mut stream: UnixStream,
    config: &GatewayConfig,
    remaining: &AtomicU32,
    api_key: Option<&str>,
) -> std::io::Result<()> {
    let mut line = String::new();
    BufReader::new(stream.try_clone()?).read_line(&mut line)?;
    let request: Request = match serde_json::from_str(&line) {
        Ok(request) => request,
        Err(e) => {
            let reply = response(
                "unknown".into(),
                Err(error("ERR_INVALID_REQUEST", e.to_string())),
            );
            serde_json::to_writer(&mut stream, &reply).map_err(std::io::Error::other)?;
            stream.write_all(b"\n")?;
            return stream.flush();
        }
    };

    let is_streaming = request.method == "MODEL_GENERATE"
        && request.params.get("stream").and_then(Value::as_bool) == Some(true);
    if is_streaming {
        return serve_stream(stream, request, config, remaining, api_key);
    }

    let reply = handle(request, config, remaining, api_key);
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
    let api_key = config.resolved_api_key().map_err(std::io::Error::other)?;
    let _ = fs::remove_file(&socket);
    let listener = UnixListener::bind(&socket)?;
    eprintln!(
        "viper-model-gateway listening on {socket} ({})",
        config.gateway_id
    );
    let remaining = AtomicU32::new(config.max_requests);
    for stream in listener.incoming().flatten() {
        let _ = serve(stream, &config, &remaining, api_key.as_deref());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{handle, EmbedConfig, GatewayConfig};
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
        std::fs::write(path, "schema='viper-boxd.model-gateway.v0'\ngateway_id='x'\nprovider='blackbox'\nendpoint='http://127.0.0.1:11434'\nmodel='m'\nmax_requests=1\nmax_prompt_chars=1\nmax_output_tokens=1\ntimeout_seconds=1\n").unwrap();
        assert!(GatewayConfig::load(path).is_err());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn keyed_provider_without_api_key_env_is_rejected() {
        let path = "/tmp/viper-keyed-no-env-model-gateway.toml";
        std::fs::write(path, "schema='viper-boxd.model-gateway.v0'\ngateway_id='x'\nprovider='openai'\nendpoint='https://api.openai.com/v1'\nmodel='gpt-4o-mini'\nmax_requests=1\nmax_prompt_chars=1\nmax_output_tokens=1\ntimeout_seconds=1\n").unwrap();
        assert!(GatewayConfig::load(path).is_err());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn keyed_provider_with_api_key_env_loads() {
        let path = "/tmp/viper-keyed-with-env-model-gateway.toml";
        std::fs::write(path, "schema='viper-boxd.model-gateway.v0'\ngateway_id='x'\nprovider='anthropic'\nendpoint='https://api.anthropic.com'\nmodel='claude-sonnet-5'\napi_key_env='VIPER_TEST_ANTHROPIC_KEY'\nmax_requests=1\nmax_prompt_chars=1\nmax_output_tokens=1\ntimeout_seconds=1\n").unwrap();
        assert!(GatewayConfig::load(path).is_ok());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn resolved_api_key_is_none_for_ollama() {
        assert!(config().resolved_api_key().expect("resolves").is_none());
    }

    #[test]
    fn resolved_api_key_fails_closed_without_the_env_var_set() {
        let path = "/tmp/viper-resolve-key-unset-model-gateway.toml";
        let env_var = "VIPER_TEST_MODEL_KEY_UNSET";
        std::env::remove_var(env_var);
        std::fs::write(
            path,
            format!("schema='viper-boxd.model-gateway.v0'\ngateway_id='x'\nprovider='openai'\nendpoint='https://api.openai.com/v1'\nmodel='gpt-4o-mini'\napi_key_env='{env_var}'\nmax_requests=1\nmax_prompt_chars=1\nmax_output_tokens=1\ntimeout_seconds=1\n"),
        )
        .unwrap();
        let config = GatewayConfig::load(path).expect("valid config");
        let _ = std::fs::remove_file(path);
        assert!(config.resolved_api_key().is_err());
    }

    #[test]
    fn resolved_api_key_reads_the_named_env_var() {
        let path = "/tmp/viper-resolve-key-set-model-gateway.toml";
        let env_var = "VIPER_TEST_MODEL_KEY_SET";
        std::env::set_var(env_var, "test-key-value");
        std::fs::write(
            path,
            format!("schema='viper-boxd.model-gateway.v0'\ngateway_id='x'\nprovider='openai'\nendpoint='https://api.openai.com/v1'\nmodel='gpt-4o-mini'\napi_key_env='{env_var}'\nmax_requests=1\nmax_prompt_chars=1\nmax_output_tokens=1\ntimeout_seconds=1\n"),
        )
        .unwrap();
        let config = GatewayConfig::load(path).expect("valid config");
        let _ = std::fs::remove_file(path);
        assert_eq!(
            config.resolved_api_key().expect("resolves"),
            Some("test-key-value".to_owned())
        );
        std::env::remove_var(env_var);
    }

    #[test]
    fn embed_table_is_rejected_for_anthropic() {
        let path = "/tmp/viper-embed-anthropic-model-gateway.toml";
        std::fs::write(path, "schema='viper-boxd.model-gateway.v0'\ngateway_id='x'\nprovider='anthropic'\nendpoint='https://api.anthropic.com'\nmodel='claude-sonnet-5'\napi_key_env='X'\nmax_requests=1\nmax_prompt_chars=1\nmax_output_tokens=1\ntimeout_seconds=1\n[embed]\nmodel='m'\nmax_input_chars=1\n").unwrap();
        assert!(GatewayConfig::load(path).is_err());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn embed_table_loads_for_openai() {
        let path = "/tmp/viper-embed-openai-model-gateway.toml";
        std::fs::write(path, "schema='viper-boxd.model-gateway.v0'\ngateway_id='x'\nprovider='openai'\nendpoint='https://api.openai.com/v1'\nmodel='gpt-4o-mini'\napi_key_env='X'\nmax_requests=1\nmax_prompt_chars=1\nmax_output_tokens=1\ntimeout_seconds=1\n[embed]\nmodel='text-embedding-3-small'\nmax_input_chars=8000\n").unwrap();
        assert!(GatewayConfig::load(path).is_ok());
        let _ = std::fs::remove_file(path);
    }

    fn config() -> GatewayConfig {
        GatewayConfig {
            schema: "viper-boxd.model-gateway.v0".into(),
            gateway_id: "TEST".into(),
            provider: "ollama".into(),
            endpoint: "http://127.0.0.1:11434".into(),
            model: "test-model".into(),
            api_key_env: None,
            max_requests: 2,
            max_prompt_chars: 1000,
            max_output_tokens: 128,
            timeout_seconds: 5,
            embed: None,
            stream: None,
        }
    }

    fn config_with_embed() -> GatewayConfig {
        GatewayConfig {
            embed: Some(EmbedConfig {
                model: "nomic-embed-text".into(),
                max_input_chars: 1000,
            }),
            ..config()
        }
    }

    fn base_toml() -> String {
        "schema='viper-boxd.model-gateway.v0'\ngateway_id='x'\nprovider='ollama'\nendpoint='http://127.0.0.1:11434'\nmodel='m'\nmax_requests=1\nmax_prompt_chars=1\nmax_output_tokens=1\ntimeout_seconds=1\n".to_owned()
    }

    fn load_with(name: &str, extra_toml: &str) -> Result<GatewayConfig, String> {
        let path = format!("/tmp/viper-stream-config-test-{name}.toml");
        std::fs::write(&path, format!("{}{extra_toml}", base_toml())).unwrap();
        let result = GatewayConfig::load(&path);
        let _ = std::fs::remove_file(&path);
        result
    }

    #[test]
    fn stream_table_loads_for_ollama() {
        let config = load_with(
            "ok",
            "[stream]\nidle_timeout_seconds=5\nmax_stream_duration_seconds=30\n",
        )
        .expect("valid stream config loads");
        let stream = config.stream.expect("stream config present");
        assert_eq!(stream.idle_timeout_seconds, 5);
        assert_eq!(stream.max_stream_duration_seconds, 30);
    }

    #[test]
    fn stream_table_rejected_for_anthropic() {
        let path = "/tmp/viper-stream-anthropic.toml";
        std::fs::write(path, "schema='viper-boxd.model-gateway.v0'\ngateway_id='x'\nprovider='anthropic'\nendpoint='https://api.anthropic.com'\nmodel='claude-sonnet-5'\napi_key_env='X'\nmax_requests=1\nmax_prompt_chars=1\nmax_output_tokens=1\ntimeout_seconds=1\n[stream]\nidle_timeout_seconds=5\nmax_stream_duration_seconds=30\n").unwrap();
        assert!(GatewayConfig::load(path).is_err());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn stream_table_loads_for_openai() {
        let path = "/tmp/viper-stream-openai.toml";
        std::fs::write(path, "schema='viper-boxd.model-gateway.v0'\ngateway_id='x'\nprovider='openai'\nendpoint='https://api.openai.com/v1'\nmodel='gpt-4o-mini'\napi_key_env='X'\nmax_requests=1\nmax_prompt_chars=1\nmax_output_tokens=1\ntimeout_seconds=1\n[stream]\nidle_timeout_seconds=5\nmax_stream_duration_seconds=30\n").unwrap();
        assert!(GatewayConfig::load(path).is_ok());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn stream_table_rejects_zero_timeouts() {
        assert!(load_with(
            "zero-idle",
            "[stream]\nidle_timeout_seconds=0\nmax_stream_duration_seconds=30\n"
        )
        .is_err());
        assert!(load_with(
            "zero-max",
            "[stream]\nidle_timeout_seconds=5\nmax_stream_duration_seconds=0\n"
        )
        .is_err());
    }

    #[test]
    fn stream_table_rejects_idle_timeout_exceeding_max_duration() {
        assert!(load_with(
            "idle-too-big",
            "[stream]\nidle_timeout_seconds=60\nmax_stream_duration_seconds=30\n"
        )
        .is_err());
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
        let response = handle(request("SHELL", json!({})), &config(), &budget, None);
        assert_eq!(response.error.unwrap().code, "ERR_TOOL_NOT_ALLOWED");
    }

    #[test]
    fn rejects_missing_prompt() {
        let budget = AtomicU32::new(2);
        let response = handle(request("MODEL_GENERATE", json!({})), &config(), &budget, None);
        assert_eq!(response.error.unwrap().code, "ERR_INVALID_REQUEST");
    }

    #[test]
    fn enforces_request_budget_before_transport() {
        let budget = AtomicU32::new(1);
        let first = handle(
            request("MODEL_GENERATE", json!({})),
            &config(),
            &budget,
            None,
        );
        assert!(!first.ok);
        assert_eq!(budget.load(std::sync::atomic::Ordering::Acquire), 0);
        let second = handle(
            request("MODEL_GENERATE", json!({"prompt": "hi"})),
            &config(),
            &budget,
            None,
        );
        assert_eq!(second.error.unwrap().code, "ERR_REQUEST_LIMIT_EXCEEDED");
    }

    #[test]
    fn embed_without_config_returns_not_implemented() {
        let budget = AtomicU32::new(2);
        let response = handle(
            request("EMBED", json!({"input": "hi"})),
            &config(),
            &budget,
            None,
        );
        assert_eq!(response.error.unwrap().code, "ERR_NOT_IMPLEMENTED");
    }

    #[test]
    fn configured_embed_still_validates_input_before_any_transport_call() {
        let budget = AtomicU32::new(2);
        let response = handle(
            request("EMBED", json!({})),
            &config_with_embed(),
            &budget,
            None,
        );
        assert_eq!(response.error.unwrap().code, "ERR_INVALID_REQUEST");
    }

    #[test]
    fn embed_also_consumes_the_shared_request_budget() {
        let budget = AtomicU32::new(1);
        let first = handle(
            request("EMBED", json!({"input": "hi"})),
            &config(),
            &budget,
            None,
        );
        assert!(!first.ok);
        assert_eq!(budget.load(std::sync::atomic::Ordering::Acquire), 0);
        let second = handle(
            request("EMBED", json!({"input": "hi"})),
            &config(),
            &budget,
            None,
        );
        assert_eq!(second.error.unwrap().code, "ERR_REQUEST_LIMIT_EXCEEDED");
    }

    #[test]
    fn rejects_wrong_version() {
        let mut r = request("MODEL_GENERATE", json!({"prompt": "hi"}));
        r.version = "0.9".into();
        let budget = AtomicU32::new(2);
        assert_eq!(
            handle(r, &config(), &budget, None).error.unwrap().code,
            "ERR_UNSUPPORTED_SCHEMA"
        );
    }
}
