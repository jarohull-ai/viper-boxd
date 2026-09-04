use crate::research_policy::PolicyViolation;
use reqwest::{blocking::Client, redirect::Policy};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::time::Duration;

#[derive(Debug, Serialize)]
pub struct GenerateResponse {
    pub gateway: &'static str,
    pub classification: &'static str,
    pub model: String,
    pub text: String,
}

/// Isolates the real HTTP call to the model provider from prompt validation
/// and response parsing, so those are unit-tested with a canned transport
/// and no live provider instance.
pub trait ModelTransport {
    fn generate(
        &self,
        endpoint: &str,
        model: &str,
        prompt: &str,
        max_output_tokens: u32,
        timeout_seconds: u64,
    ) -> Result<Vec<u8>, PolicyViolation>;
}

pub struct OllamaTransport;

impl ModelTransport for OllamaTransport {
    fn generate(
        &self,
        endpoint: &str,
        model: &str,
        prompt: &str,
        max_output_tokens: u32,
        timeout_seconds: u64,
    ) -> Result<Vec<u8>, PolicyViolation> {
        let client = Client::builder()
            .redirect(Policy::none())
            .no_proxy()
            .timeout(Duration::from_secs(timeout_seconds))
            .user_agent("viper-model-gateway/0.1")
            .build()
            .map_err(|e| violation("ERR_MODEL_FAILED", e.to_string()))?;
        let url = format!("{}/api/generate", endpoint.trim_end_matches('/'));
        let response = client
            .post(url)
            .json(&json!({
                "model": model,
                "prompt": prompt,
                "stream": false,
                "options": {"num_predict": max_output_tokens},
            }))
            .send()
            .map_err(|e| violation("ERR_MODEL_FAILED", e.to_string()))?;
        if !response.status().is_success() {
            return Err(violation(
                "ERR_MODEL_FAILED",
                format!("model provider returned HTTP {}", response.status()),
            ));
        }
        response
            .bytes()
            .map(|b| b.to_vec())
            .map_err(|e| violation("ERR_MODEL_FAILED", e.to_string()))
    }
}

/// One line of Ollama's own streaming `/api/generate` response body, which
/// is itself newline-delimited JSON — symmetric with our own wire format,
/// per STREAM_PLAN.md.
#[derive(Debug, Deserialize)]
struct OllamaStreamLine {
    #[serde(default)]
    response: String,
    #[serde(default)]
    done: bool,
}

/// Isolates the real streaming HTTP call from prompt validation and chunk
/// sequencing, mirroring `ModelTransport`. `on_delta` is called once per
/// line the provider sends; the last call always has `done: true` and
/// happens only on success — a mid-stream failure is reported through the
/// `Result`, never through a synthetic final `on_delta` call.
pub trait ModelStreamTransport {
    #[allow(clippy::too_many_arguments)]
    fn generate_stream(
        &self,
        endpoint: &str,
        model: &str,
        prompt: &str,
        max_output_tokens: u32,
        idle_timeout_seconds: u64,
        max_stream_duration_seconds: u64,
        on_delta: &mut dyn FnMut(&str, bool),
    ) -> Result<(), PolicyViolation>;
}

pub struct OllamaStreamTransport;

impl ModelStreamTransport for OllamaStreamTransport {
    fn generate_stream(
        &self,
        endpoint: &str,
        model: &str,
        prompt: &str,
        max_output_tokens: u32,
        idle_timeout_seconds: u64,
        max_stream_duration_seconds: u64,
        on_delta: &mut dyn FnMut(&str, bool),
    ) -> Result<(), PolicyViolation> {
        // The blocking HTTP call runs on a background thread so the idle
        // gap between chunks can be enforced with a plain recv_timeout,
        // rather than needing per-read socket timeout plumbing through
        // reqwest's blocking body reader. reqwest's own client-level
        // timeout is the absolute cap: it bounds the background thread
        // even if this function returns early on an idle timeout, so an
        // abandoned request cannot run unbounded, though it is not
        // actively joined in that case (a reqwest blocking Client has no
        // request-cancellation handle to join it early).
        let endpoint = endpoint.to_owned();
        let model_owned = model.to_owned();
        let prompt = prompt.to_owned();
        let (tx, rx) = std::sync::mpsc::channel::<Result<OllamaStreamLine, String>>();

        std::thread::spawn(move || {
            let outcome = (|| -> Result<(), String> {
                let client = Client::builder()
                    .redirect(Policy::none())
                    .no_proxy()
                    .timeout(Duration::from_secs(max_stream_duration_seconds))
                    .user_agent("viper-model-gateway/0.1")
                    .build()
                    .map_err(|e| e.to_string())?;
                let url = format!("{}/api/generate", endpoint.trim_end_matches('/'));
                let response = client
                    .post(url)
                    .json(&json!({
                        "model": model_owned,
                        "prompt": prompt,
                        "stream": true,
                        "options": {"num_predict": max_output_tokens},
                    }))
                    .send()
                    .map_err(|e| e.to_string())?;
                if !response.status().is_success() {
                    return Err(format!("model provider returned HTTP {}", response.status()));
                }
                use std::io::BufRead;
                for line in std::io::BufReader::new(response).lines() {
                    let line = line.map_err(|e| e.to_string())?;
                    if line.trim().is_empty() {
                        continue;
                    }
                    let parsed: OllamaStreamLine =
                        serde_json::from_str(&line).map_err(|e| e.to_string())?;
                    let done = parsed.done;
                    if tx.send(Ok(parsed)).is_err() {
                        return Ok(()); // receiver gave up (idle timeout); stop reading
                    }
                    if done {
                        return Ok(());
                    }
                }
                Err("stream ended before a done line".into())
            })();
            if let Err(message) = outcome {
                let _ = tx.send(Err(message));
            }
        });

        loop {
            match rx.recv_timeout(Duration::from_secs(idle_timeout_seconds)) {
                Ok(Ok(line)) => {
                    on_delta(&line.response, line.done);
                    if line.done {
                        return Ok(());
                    }
                }
                Ok(Err(message)) => return Err(violation("ERR_MODEL_FAILED", message)),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    return Err(violation(
                        "ERR_MODEL_FAILED",
                        format!("no chunk received within {idle_timeout_seconds}s (idle timeout)"),
                    ));
                }
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(violation(
                        "ERR_MODEL_RESPONSE_INVALID",
                        "stream ended unexpectedly",
                    ));
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub fn generate_stream(
    transport: &dyn ModelStreamTransport,
    endpoint: &str,
    model: &str,
    prompt: &str,
    max_prompt_chars: usize,
    max_output_tokens: u32,
    idle_timeout_seconds: u64,
    max_stream_duration_seconds: u64,
    on_delta: &mut dyn FnMut(&str, bool),
) -> Result<(), PolicyViolation> {
    validate_prompt(prompt, max_prompt_chars)?;
    transport.generate_stream(
        endpoint,
        model,
        prompt,
        max_output_tokens,
        idle_timeout_seconds,
        max_stream_duration_seconds,
        on_delta,
    )
}

/// Shared by the `openai` and `openrouter` providers: OpenRouter's API is a
/// drop-in-compatible proxy over the same Chat Completions request/response
/// shape, differing only in `endpoint` (base URL) and which environment
/// variable supplies the key.
pub struct OpenAiCompatibleTransport {
    pub api_key: String,
}

impl ModelTransport for OpenAiCompatibleTransport {
    fn generate(
        &self,
        endpoint: &str,
        model: &str,
        prompt: &str,
        max_output_tokens: u32,
        timeout_seconds: u64,
    ) -> Result<Vec<u8>, PolicyViolation> {
        let client = Client::builder()
            .redirect(Policy::none())
            .no_proxy()
            .timeout(Duration::from_secs(timeout_seconds))
            .user_agent("viper-model-gateway/0.1")
            .build()
            .map_err(|e| violation("ERR_MODEL_FAILED", e.to_string()))?;
        let url = format!("{}/chat/completions", endpoint.trim_end_matches('/'));
        let response = client
            .post(url)
            .bearer_auth(&self.api_key)
            .json(&json!({
                "model": model,
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": max_output_tokens,
            }))
            .send()
            .map_err(|e| violation("ERR_MODEL_FAILED", e.to_string()))?;
        if !response.status().is_success() {
            return Err(violation(
                "ERR_MODEL_FAILED",
                format!("model provider returned HTTP {}", response.status()),
            ));
        }
        response
            .bytes()
            .map(|b| b.to_vec())
            .map_err(|e| violation("ERR_MODEL_FAILED", e.to_string()))
    }
}

pub struct AnthropicTransport {
    pub api_key: String,
}

impl ModelTransport for AnthropicTransport {
    fn generate(
        &self,
        endpoint: &str,
        model: &str,
        prompt: &str,
        max_output_tokens: u32,
        timeout_seconds: u64,
    ) -> Result<Vec<u8>, PolicyViolation> {
        let client = Client::builder()
            .redirect(Policy::none())
            .no_proxy()
            .timeout(Duration::from_secs(timeout_seconds))
            .user_agent("viper-model-gateway/0.1")
            .build()
            .map_err(|e| violation("ERR_MODEL_FAILED", e.to_string()))?;
        let url = format!("{}/v1/messages", endpoint.trim_end_matches('/'));
        let response = client
            .post(url)
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", "2023-06-01")
            .json(&json!({
                "model": model,
                "max_tokens": max_output_tokens,
                "messages": [{"role": "user", "content": prompt}],
            }))
            .send()
            .map_err(|e| violation("ERR_MODEL_FAILED", e.to_string()))?;
        if !response.status().is_success() {
            return Err(violation(
                "ERR_MODEL_FAILED",
                format!("model provider returned HTTP {}", response.status()),
            ));
        }
        response
            .bytes()
            .map(|b| b.to_vec())
            .map_err(|e| violation("ERR_MODEL_FAILED", e.to_string()))
    }
}

#[derive(Debug, Serialize)]
pub struct EmbedResponse {
    pub gateway: &'static str,
    pub classification: &'static str,
    pub model: String,
    pub embedding: Vec<f32>,
    pub dimensions: usize,
}

/// Isolates the real HTTP call to the embedding provider from input
/// validation and response parsing, mirroring `ModelTransport`.
pub trait EmbedTransport {
    fn embed(
        &self,
        endpoint: &str,
        model: &str,
        input: &str,
        timeout_seconds: u64,
    ) -> Result<Vec<u8>, PolicyViolation>;
}

pub struct OllamaEmbedTransport;

impl EmbedTransport for OllamaEmbedTransport {
    fn embed(
        &self,
        endpoint: &str,
        model: &str,
        input: &str,
        timeout_seconds: u64,
    ) -> Result<Vec<u8>, PolicyViolation> {
        let client = Client::builder()
            .redirect(Policy::none())
            .no_proxy()
            .timeout(Duration::from_secs(timeout_seconds))
            .user_agent("viper-model-gateway/0.1")
            .build()
            .map_err(|e| violation("ERR_EMBED_FAILED", e.to_string()))?;
        let url = format!("{}/api/embed", endpoint.trim_end_matches('/'));
        let response = client
            .post(url)
            .json(&json!({"model": model, "input": input}))
            .send()
            .map_err(|e| violation("ERR_EMBED_FAILED", e.to_string()))?;
        if !response.status().is_success() {
            return Err(violation(
                "ERR_EMBED_FAILED",
                format!("embedding provider returned HTTP {}", response.status()),
            ));
        }
        response
            .bytes()
            .map(|b| b.to_vec())
            .map_err(|e| violation("ERR_EMBED_FAILED", e.to_string()))
    }
}

/// Shared by `openai` and `openrouter`: OpenRouter's own OpenAPI spec
/// (`POST /embeddings`, `{"model", "input"}` body, `data[].embedding`
/// response) matches OpenAI's `/v1/embeddings` shape exactly, not merely
/// approximately, so one transport serves both — mirrors
/// `OpenAiCompatibleTransport` for `MODEL_GENERATE`.
pub struct OpenAiCompatibleEmbedTransport {
    pub api_key: String,
}

impl EmbedTransport for OpenAiCompatibleEmbedTransport {
    fn embed(
        &self,
        endpoint: &str,
        model: &str,
        input: &str,
        timeout_seconds: u64,
    ) -> Result<Vec<u8>, PolicyViolation> {
        let client = Client::builder()
            .redirect(Policy::none())
            .no_proxy()
            .timeout(Duration::from_secs(timeout_seconds))
            .user_agent("viper-model-gateway/0.1")
            .build()
            .map_err(|e| violation("ERR_EMBED_FAILED", e.to_string()))?;
        let url = format!("{}/embeddings", endpoint.trim_end_matches('/'));
        let response = client
            .post(url)
            .bearer_auth(&self.api_key)
            .json(&json!({"model": model, "input": input}))
            .send()
            .map_err(|e| violation("ERR_EMBED_FAILED", e.to_string()))?;
        if !response.status().is_success() {
            return Err(violation(
                "ERR_EMBED_FAILED",
                format!("embedding provider returned HTTP {}", response.status()),
            ));
        }
        response
            .bytes()
            .map(|b| b.to_vec())
            .map_err(|e| violation("ERR_EMBED_FAILED", e.to_string()))
    }
}

#[derive(Debug, Deserialize)]
struct OllamaResponse {
    response: Option<String>,
    #[serde(default)]
    done: bool,
}

#[derive(Debug, Deserialize)]
struct OpenAiChatResponse {
    #[serde(default)]
    choices: Vec<OpenAiChoice>,
}

#[derive(Debug, Deserialize)]
struct OpenAiChoice {
    message: OpenAiMessage,
}

#[derive(Debug, Deserialize)]
struct OpenAiMessage {
    content: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AnthropicMessagesResponse {
    #[serde(default)]
    content: Vec<AnthropicContentBlock>,
}

#[derive(Debug, Deserialize)]
struct AnthropicContentBlock {
    #[serde(rename = "type")]
    block_type: String,
    #[serde(default)]
    text: String,
}

#[derive(Debug, Deserialize)]
struct OllamaEmbedResponse {
    #[serde(default)]
    embeddings: Vec<Vec<f32>>,
}

#[derive(Debug, Deserialize)]
struct OpenAiEmbedResponse {
    #[serde(default)]
    data: Vec<OpenAiEmbedDatum>,
}

#[derive(Debug, Deserialize)]
struct OpenAiEmbedDatum {
    #[serde(default)]
    embedding: Vec<f32>,
}

fn validate_prompt(prompt: &str, max_prompt_chars: usize) -> Result<(), PolicyViolation> {
    if prompt.trim().is_empty() {
        return Err(violation("ERR_MODEL_PROMPT_INVALID", "prompt is empty"));
    }
    if prompt.len() > max_prompt_chars {
        return Err(violation(
            "ERR_MODEL_PROMPT_INVALID",
            format!("prompt exceeds {max_prompt_chars} characters"),
        ));
    }
    Ok(())
}

fn parse_ollama_response(model: &str, body: &[u8]) -> Result<GenerateResponse, PolicyViolation> {
    let parsed: OllamaResponse = serde_json::from_slice(body)
        .map_err(|e| violation("ERR_MODEL_RESPONSE_INVALID", e.to_string()))?;
    let text = parsed
        .response
        .filter(|_| parsed.done)
        .ok_or_else(|| violation("ERR_MODEL_RESPONSE_INVALID", "incomplete model response"))?;
    Ok(GenerateResponse {
        gateway: "ollama-model-v0",
        classification: "MODEL_OUTPUT",
        model: model.to_owned(),
        text,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn generate(
    transport: &dyn ModelTransport,
    endpoint: &str,
    model: &str,
    prompt: &str,
    max_prompt_chars: usize,
    max_output_tokens: u32,
    timeout_seconds: u64,
) -> Result<GenerateResponse, PolicyViolation> {
    validate_prompt(prompt, max_prompt_chars)?;
    let body = transport.generate(endpoint, model, prompt, max_output_tokens, timeout_seconds)?;
    parse_ollama_response(model, &body)
}

fn parse_openai_response(model: &str, body: &[u8]) -> Result<GenerateResponse, PolicyViolation> {
    let parsed: OpenAiChatResponse = serde_json::from_slice(body)
        .map_err(|e| violation("ERR_MODEL_RESPONSE_INVALID", e.to_string()))?;
    let text = parsed
        .choices
        .into_iter()
        .next()
        .and_then(|choice| choice.message.content)
        .filter(|text| !text.is_empty())
        .ok_or_else(|| violation("ERR_MODEL_RESPONSE_INVALID", "no completion returned"))?;
    Ok(GenerateResponse {
        gateway: "openai-compatible-model-v0",
        classification: "MODEL_OUTPUT",
        model: model.to_owned(),
        text,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn generate_openai_compatible(
    transport: &dyn ModelTransport,
    endpoint: &str,
    model: &str,
    prompt: &str,
    max_prompt_chars: usize,
    max_output_tokens: u32,
    timeout_seconds: u64,
) -> Result<GenerateResponse, PolicyViolation> {
    validate_prompt(prompt, max_prompt_chars)?;
    let body = transport.generate(endpoint, model, prompt, max_output_tokens, timeout_seconds)?;
    parse_openai_response(model, &body)
}

fn parse_anthropic_response(model: &str, body: &[u8]) -> Result<GenerateResponse, PolicyViolation> {
    let parsed: AnthropicMessagesResponse = serde_json::from_slice(body)
        .map_err(|e| violation("ERR_MODEL_RESPONSE_INVALID", e.to_string()))?;
    let text = parsed
        .content
        .into_iter()
        .filter(|block| block.block_type == "text")
        .map(|block| block.text)
        .collect::<Vec<_>>()
        .join("");
    if text.is_empty() {
        return Err(violation(
            "ERR_MODEL_RESPONSE_INVALID",
            "no text content block returned",
        ));
    }
    Ok(GenerateResponse {
        gateway: "anthropic-model-v0",
        classification: "MODEL_OUTPUT",
        model: model.to_owned(),
        text,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn generate_anthropic(
    transport: &dyn ModelTransport,
    endpoint: &str,
    model: &str,
    prompt: &str,
    max_prompt_chars: usize,
    max_output_tokens: u32,
    timeout_seconds: u64,
) -> Result<GenerateResponse, PolicyViolation> {
    validate_prompt(prompt, max_prompt_chars)?;
    let body = transport.generate(endpoint, model, prompt, max_output_tokens, timeout_seconds)?;
    parse_anthropic_response(model, &body)
}

fn validate_embed_input(input: &str, max_input_chars: usize) -> Result<(), PolicyViolation> {
    if input.trim().is_empty() {
        return Err(violation("ERR_EMBED_INPUT_INVALID", "input is empty"));
    }
    if input.len() > max_input_chars {
        return Err(violation(
            "ERR_EMBED_INPUT_INVALID",
            format!("input exceeds {max_input_chars} characters"),
        ));
    }
    Ok(())
}

fn parse_ollama_embed_response(model: &str, body: &[u8]) -> Result<EmbedResponse, PolicyViolation> {
    let parsed: OllamaEmbedResponse = serde_json::from_slice(body)
        .map_err(|e| violation("ERR_EMBED_RESPONSE_INVALID", e.to_string()))?;
    let embedding = parsed
        .embeddings
        .into_iter()
        .next()
        .filter(|embedding| !embedding.is_empty())
        .ok_or_else(|| violation("ERR_EMBED_RESPONSE_INVALID", "no embedding returned"))?;
    let dimensions = embedding.len();
    Ok(EmbedResponse {
        gateway: "ollama-model-v0",
        classification: "MODEL_OUTPUT",
        model: model.to_owned(),
        embedding,
        dimensions,
    })
}

pub fn embed(
    transport: &dyn EmbedTransport,
    endpoint: &str,
    model: &str,
    input: &str,
    max_input_chars: usize,
    timeout_seconds: u64,
) -> Result<EmbedResponse, PolicyViolation> {
    validate_embed_input(input, max_input_chars)?;
    let body = transport.embed(endpoint, model, input, timeout_seconds)?;
    parse_ollama_embed_response(model, &body)
}

fn parse_openai_embed_response(model: &str, body: &[u8]) -> Result<EmbedResponse, PolicyViolation> {
    let parsed: OpenAiEmbedResponse = serde_json::from_slice(body)
        .map_err(|e| violation("ERR_EMBED_RESPONSE_INVALID", e.to_string()))?;
    let embedding = parsed
        .data
        .into_iter()
        .next()
        .map(|datum| datum.embedding)
        .filter(|embedding| !embedding.is_empty())
        .ok_or_else(|| violation("ERR_EMBED_RESPONSE_INVALID", "no embedding returned"))?;
    let dimensions = embedding.len();
    Ok(EmbedResponse {
        gateway: "openai-compatible-model-v0",
        classification: "MODEL_OUTPUT",
        model: model.to_owned(),
        embedding,
        dimensions,
    })
}

pub fn embed_openai_compatible(
    transport: &dyn EmbedTransport,
    endpoint: &str,
    model: &str,
    input: &str,
    max_input_chars: usize,
    timeout_seconds: u64,
) -> Result<EmbedResponse, PolicyViolation> {
    validate_embed_input(input, max_input_chars)?;
    let body = transport.embed(endpoint, model, input, timeout_seconds)?;
    parse_openai_embed_response(model, &body)
}

fn violation(code: &'static str, message: impl Into<String>) -> PolicyViolation {
    PolicyViolation {
        code,
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::{generate, ModelTransport, PolicyViolation};

    struct CannedTransport(Result<Vec<u8>, PolicyViolation>);

    impl ModelTransport for CannedTransport {
        fn generate(
            &self,
            _endpoint: &str,
            _model: &str,
            _prompt: &str,
            _max_output_tokens: u32,
            _timeout_seconds: u64,
        ) -> Result<Vec<u8>, PolicyViolation> {
            match &self.0 {
                Ok(body) => Ok(body.clone()),
                Err(e) => Err(e.clone()),
            }
        }
    }

    fn must_not_be_called() -> CannedTransport {
        CannedTransport(Err(PolicyViolation {
            code: "ERR_MODEL_FAILED",
            message: "must not be called".into(),
        }))
    }

    #[test]
    fn rejects_empty_prompt_before_any_transport_call() {
        let error = generate(&must_not_be_called(), "http://x", "m", "  ", 100, 128, 5)
            .unwrap_err();
        assert_eq!(error.code, "ERR_MODEL_PROMPT_INVALID");
    }

    #[test]
    fn rejects_oversized_prompt_before_any_transport_call() {
        let prompt = "a".repeat(101);
        let error = generate(&must_not_be_called(), "http://x", "m", &prompt, 100, 128, 5)
            .unwrap_err();
        assert_eq!(error.code, "ERR_MODEL_PROMPT_INVALID");
    }

    #[test]
    fn maps_a_canned_successful_response_to_the_documented_shape() {
        let body = br#"{"response":"hello world","done":true}"#.to_vec();
        let transport = CannedTransport(Ok(body));
        let response = generate(&transport, "http://x", "mistral:7b", "hi", 1000, 128, 5)
            .expect("canned response parses");
        assert_eq!(response.classification, "MODEL_OUTPUT");
        assert_eq!(response.model, "mistral:7b");
        assert_eq!(response.text, "hello world");
    }

    #[test]
    fn rejects_an_incomplete_response() {
        let body = br#"{"response":"partial","done":false}"#.to_vec();
        let transport = CannedTransport(Ok(body));
        let error = generate(&transport, "http://x", "m", "hi", 1000, 128, 5).unwrap_err();
        assert_eq!(error.code, "ERR_MODEL_RESPONSE_INVALID");
    }

    #[test]
    fn rejects_malformed_json_from_the_provider() {
        let transport = CannedTransport(Ok(b"not json".to_vec()));
        let error = generate(&transport, "http://x", "m", "hi", 1000, 128, 5).unwrap_err();
        assert_eq!(error.code, "ERR_MODEL_RESPONSE_INVALID");
    }

    #[test]
    fn propagates_a_transport_failure_unchanged() {
        let transport = CannedTransport(Err(PolicyViolation {
            code: "ERR_MODEL_FAILED",
            message: "connection refused".into(),
        }));
        let error = generate(&transport, "http://x", "m", "hi", 1000, 128, 5).unwrap_err();
        assert_eq!(error.code, "ERR_MODEL_FAILED");
    }

    mod streaming {
        use super::super::{generate_stream, ModelStreamTransport, PolicyViolation};
        use std::sync::Mutex;

        struct CannedStreamTransport {
            lines: Mutex<Vec<(String, bool)>>,
            fail: Option<PolicyViolation>,
        }

        impl ModelStreamTransport for CannedStreamTransport {
            fn generate_stream(
                &self,
                _endpoint: &str,
                _model: &str,
                _prompt: &str,
                _max_output_tokens: u32,
                _idle_timeout_seconds: u64,
                _max_stream_duration_seconds: u64,
                on_delta: &mut dyn FnMut(&str, bool),
            ) -> Result<(), PolicyViolation> {
                for (delta, done) in self.lines.lock().unwrap().iter() {
                    on_delta(delta, *done);
                }
                match &self.fail {
                    Some(violation) => Err(violation.clone()),
                    None => Ok(()),
                }
            }
        }

        fn must_not_be_called() -> CannedStreamTransport {
            CannedStreamTransport {
                lines: Mutex::new(Vec::new()),
                fail: Some(PolicyViolation {
                    code: "ERR_MODEL_FAILED",
                    message: "must not be called".into(),
                }),
            }
        }

        #[test]
        fn rejects_empty_prompt_before_any_transport_call() {
            let error =
                generate_stream(&must_not_be_called(), "http://x", "m", "  ", 100, 128, 5, 30, &mut |_, _| {
                    panic!("on_delta must not be called");
                })
                .unwrap_err();
            assert_eq!(error.code, "ERR_MODEL_PROMPT_INVALID");
        }

        #[test]
        fn delivers_deltas_in_order_and_succeeds_on_a_done_line() {
            let transport = CannedStreamTransport {
                lines: Mutex::new(vec![
                    ("Hello".to_owned(), false),
                    (" world".to_owned(), true),
                ]),
                fail: None,
            };
            let mut deltas = Vec::new();
            generate_stream(
                &transport,
                "http://x",
                "mistral:7b",
                "hi",
                1000,
                128,
                5,
                30,
                &mut |delta, done| deltas.push((delta.to_owned(), done)),
            )
            .expect("canned stream succeeds");
            assert_eq!(
                deltas,
                vec![("Hello".to_owned(), false), (" world".to_owned(), true)]
            );
        }

        #[test]
        fn propagates_a_mid_stream_transport_failure() {
            let transport = CannedStreamTransport {
                lines: Mutex::new(vec![("partial".to_owned(), false)]),
                fail: Some(PolicyViolation {
                    code: "ERR_MODEL_FAILED",
                    message: "connection reset".into(),
                }),
            };
            let mut deltas = Vec::new();
            let error = generate_stream(
                &transport,
                "http://x",
                "m",
                "hi",
                1000,
                128,
                5,
                30,
                &mut |delta, done| deltas.push((delta.to_owned(), done)),
            )
            .unwrap_err();
            assert_eq!(error.code, "ERR_MODEL_FAILED");
            assert_eq!(deltas, vec![("partial".to_owned(), false)]);
        }
    }

    mod openai_compatible {
        use super::super::{generate_openai_compatible, ModelTransport, PolicyViolation};

        struct CannedTransport(Result<Vec<u8>, PolicyViolation>);

        impl ModelTransport for CannedTransport {
            fn generate(
                &self,
                _endpoint: &str,
                _model: &str,
                _prompt: &str,
                _max_output_tokens: u32,
                _timeout_seconds: u64,
            ) -> Result<Vec<u8>, PolicyViolation> {
                match &self.0 {
                    Ok(body) => Ok(body.clone()),
                    Err(e) => Err(e.clone()),
                }
            }
        }

        fn must_not_be_called() -> CannedTransport {
            CannedTransport(Err(PolicyViolation {
                code: "ERR_MODEL_FAILED",
                message: "must not be called".into(),
            }))
        }

        #[test]
        fn rejects_empty_prompt_before_any_transport_call() {
            let error =
                generate_openai_compatible(&must_not_be_called(), "http://x", "m", "  ", 100, 128, 5)
                    .unwrap_err();
            assert_eq!(error.code, "ERR_MODEL_PROMPT_INVALID");
        }

        #[test]
        fn maps_a_canned_successful_response_to_the_documented_shape() {
            let body =
                br#"{"choices":[{"message":{"role":"assistant","content":"hello world"}}]}"#
                    .to_vec();
            let transport = CannedTransport(Ok(body));
            let response =
                generate_openai_compatible(&transport, "http://x", "gpt-4o-mini", "hi", 1000, 128, 5)
                    .expect("canned response parses");
            assert_eq!(response.classification, "MODEL_OUTPUT");
            assert_eq!(response.model, "gpt-4o-mini");
            assert_eq!(response.text, "hello world");
        }

        #[test]
        fn rejects_a_response_with_no_choices() {
            let body = br#"{"choices":[]}"#.to_vec();
            let transport = CannedTransport(Ok(body));
            let error =
                generate_openai_compatible(&transport, "http://x", "m", "hi", 1000, 128, 5)
                    .unwrap_err();
            assert_eq!(error.code, "ERR_MODEL_RESPONSE_INVALID");
        }

        #[test]
        fn rejects_malformed_json_from_the_provider() {
            let transport = CannedTransport(Ok(b"not json".to_vec()));
            let error =
                generate_openai_compatible(&transport, "http://x", "m", "hi", 1000, 128, 5)
                    .unwrap_err();
            assert_eq!(error.code, "ERR_MODEL_RESPONSE_INVALID");
        }

        #[test]
        fn propagates_a_transport_failure_unchanged() {
            let transport = CannedTransport(Err(PolicyViolation {
                code: "ERR_MODEL_FAILED",
                message: "invalid api key".into(),
            }));
            let error =
                generate_openai_compatible(&transport, "http://x", "m", "hi", 1000, 128, 5)
                    .unwrap_err();
            assert_eq!(error.code, "ERR_MODEL_FAILED");
        }
    }

    mod anthropic {
        use super::super::{generate_anthropic, ModelTransport, PolicyViolation};

        struct CannedTransport(Result<Vec<u8>, PolicyViolation>);

        impl ModelTransport for CannedTransport {
            fn generate(
                &self,
                _endpoint: &str,
                _model: &str,
                _prompt: &str,
                _max_output_tokens: u32,
                _timeout_seconds: u64,
            ) -> Result<Vec<u8>, PolicyViolation> {
                match &self.0 {
                    Ok(body) => Ok(body.clone()),
                    Err(e) => Err(e.clone()),
                }
            }
        }

        fn must_not_be_called() -> CannedTransport {
            CannedTransport(Err(PolicyViolation {
                code: "ERR_MODEL_FAILED",
                message: "must not be called".into(),
            }))
        }

        #[test]
        fn rejects_empty_prompt_before_any_transport_call() {
            let error = generate_anthropic(&must_not_be_called(), "http://x", "m", "  ", 100, 128, 5)
                .unwrap_err();
            assert_eq!(error.code, "ERR_MODEL_PROMPT_INVALID");
        }

        #[test]
        fn maps_a_canned_successful_response_to_the_documented_shape() {
            let body = br#"{"content":[{"type":"text","text":"hello world"}],"role":"assistant"}"#
                .to_vec();
            let transport = CannedTransport(Ok(body));
            let response = generate_anthropic(
                &transport,
                "http://x",
                "claude-sonnet-5",
                "hi",
                1000,
                128,
                5,
            )
            .expect("canned response parses");
            assert_eq!(response.classification, "MODEL_OUTPUT");
            assert_eq!(response.model, "claude-sonnet-5");
            assert_eq!(response.text, "hello world");
        }

        #[test]
        fn joins_multiple_text_blocks_and_skips_non_text_blocks() {
            let body = br#"{"content":[{"type":"text","text":"a"},{"type":"tool_use","text":""},{"type":"text","text":"b"}]}"#.to_vec();
            let transport = CannedTransport(Ok(body));
            let response = generate_anthropic(&transport, "http://x", "m", "hi", 1000, 128, 5)
                .expect("canned response parses");
            assert_eq!(response.text, "ab");
        }

        #[test]
        fn rejects_a_response_with_no_text_blocks() {
            let body = br#"{"content":[]}"#.to_vec();
            let transport = CannedTransport(Ok(body));
            let error = generate_anthropic(&transport, "http://x", "m", "hi", 1000, 128, 5)
                .unwrap_err();
            assert_eq!(error.code, "ERR_MODEL_RESPONSE_INVALID");
        }

        #[test]
        fn rejects_malformed_json_from_the_provider() {
            let transport = CannedTransport(Ok(b"not json".to_vec()));
            let error = generate_anthropic(&transport, "http://x", "m", "hi", 1000, 128, 5)
                .unwrap_err();
            assert_eq!(error.code, "ERR_MODEL_RESPONSE_INVALID");
        }

        #[test]
        fn propagates_a_transport_failure_unchanged() {
            let transport = CannedTransport(Err(PolicyViolation {
                code: "ERR_MODEL_FAILED",
                message: "invalid api key".into(),
            }));
            let error = generate_anthropic(&transport, "http://x", "m", "hi", 1000, 128, 5)
                .unwrap_err();
            assert_eq!(error.code, "ERR_MODEL_FAILED");
        }
    }

    mod embed {
        use super::super::{embed, EmbedTransport, PolicyViolation};

        struct CannedEmbedTransport(Result<Vec<u8>, PolicyViolation>);

        impl EmbedTransport for CannedEmbedTransport {
            fn embed(
                &self,
                _endpoint: &str,
                _model: &str,
                _input: &str,
                _timeout_seconds: u64,
            ) -> Result<Vec<u8>, PolicyViolation> {
                match &self.0 {
                    Ok(body) => Ok(body.clone()),
                    Err(e) => Err(e.clone()),
                }
            }
        }

        fn must_not_be_called() -> CannedEmbedTransport {
            CannedEmbedTransport(Err(PolicyViolation {
                code: "ERR_EMBED_FAILED",
                message: "must not be called".into(),
            }))
        }

        #[test]
        fn rejects_empty_input_before_any_transport_call() {
            let error = embed(&must_not_be_called(), "http://x", "m", "  ", 100, 5).unwrap_err();
            assert_eq!(error.code, "ERR_EMBED_INPUT_INVALID");
        }

        #[test]
        fn rejects_oversized_input_before_any_transport_call() {
            let input = "a".repeat(101);
            let error =
                embed(&must_not_be_called(), "http://x", "m", &input, 100, 5).unwrap_err();
            assert_eq!(error.code, "ERR_EMBED_INPUT_INVALID");
        }

        #[test]
        fn maps_a_canned_successful_response_to_the_documented_shape() {
            let body = br#"{"model":"nomic-embed-text","embeddings":[[0.1,-0.2,0.3]]}"#.to_vec();
            let transport = CannedEmbedTransport(Ok(body));
            let response = embed(&transport, "http://x", "nomic-embed-text", "hi", 1000, 5)
                .expect("canned response parses");
            assert_eq!(response.classification, "MODEL_OUTPUT");
            assert_eq!(response.model, "nomic-embed-text");
            assert_eq!(response.dimensions, 3);
            assert_eq!(response.embedding, vec![0.1, -0.2, 0.3]);
        }

        #[test]
        fn rejects_a_response_with_no_embeddings() {
            let body = br#"{"embeddings":[]}"#.to_vec();
            let transport = CannedEmbedTransport(Ok(body));
            let error = embed(&transport, "http://x", "m", "hi", 1000, 5).unwrap_err();
            assert_eq!(error.code, "ERR_EMBED_RESPONSE_INVALID");
        }

        #[test]
        fn rejects_an_empty_embedding_vector() {
            let body = br#"{"embeddings":[[]]}"#.to_vec();
            let transport = CannedEmbedTransport(Ok(body));
            let error = embed(&transport, "http://x", "m", "hi", 1000, 5).unwrap_err();
            assert_eq!(error.code, "ERR_EMBED_RESPONSE_INVALID");
        }

        #[test]
        fn rejects_malformed_json_from_the_provider() {
            let transport = CannedEmbedTransport(Ok(b"not json".to_vec()));
            let error = embed(&transport, "http://x", "m", "hi", 1000, 5).unwrap_err();
            assert_eq!(error.code, "ERR_EMBED_RESPONSE_INVALID");
        }

        #[test]
        fn propagates_a_transport_failure_unchanged() {
            let transport = CannedEmbedTransport(Err(PolicyViolation {
                code: "ERR_EMBED_FAILED",
                message: "connection refused".into(),
            }));
            let error = embed(&transport, "http://x", "m", "hi", 1000, 5).unwrap_err();
            assert_eq!(error.code, "ERR_EMBED_FAILED");
        }
    }

    mod embed_openai_compatible {
        use super::super::{embed_openai_compatible, EmbedTransport, PolicyViolation};

        struct CannedEmbedTransport(Result<Vec<u8>, PolicyViolation>);

        impl EmbedTransport for CannedEmbedTransport {
            fn embed(
                &self,
                _endpoint: &str,
                _model: &str,
                _input: &str,
                _timeout_seconds: u64,
            ) -> Result<Vec<u8>, PolicyViolation> {
                match &self.0 {
                    Ok(body) => Ok(body.clone()),
                    Err(e) => Err(e.clone()),
                }
            }
        }

        fn must_not_be_called() -> CannedEmbedTransport {
            CannedEmbedTransport(Err(PolicyViolation {
                code: "ERR_EMBED_FAILED",
                message: "must not be called".into(),
            }))
        }

        #[test]
        fn rejects_empty_input_before_any_transport_call() {
            let error = embed_openai_compatible(&must_not_be_called(), "http://x", "m", "  ", 100, 5)
                .unwrap_err();
            assert_eq!(error.code, "ERR_EMBED_INPUT_INVALID");
        }

        #[test]
        fn maps_a_canned_successful_response_to_the_documented_shape() {
            let body = br#"{"object":"list","data":[{"object":"embedding","index":0,"embedding":[0.1,-0.2,0.3]}],"model":"text-embedding-3-small"}"#.to_vec();
            let transport = CannedEmbedTransport(Ok(body));
            let response = embed_openai_compatible(
                &transport,
                "http://x",
                "text-embedding-3-small",
                "hi",
                1000,
                5,
            )
            .expect("canned response parses");
            assert_eq!(response.classification, "MODEL_OUTPUT");
            assert_eq!(response.model, "text-embedding-3-small");
            assert_eq!(response.dimensions, 3);
            assert_eq!(response.embedding, vec![0.1, -0.2, 0.3]);
        }

        #[test]
        fn rejects_a_response_with_no_data() {
            let body = br#"{"object":"list","data":[]}"#.to_vec();
            let transport = CannedEmbedTransport(Ok(body));
            let error = embed_openai_compatible(&transport, "http://x", "m", "hi", 1000, 5)
                .unwrap_err();
            assert_eq!(error.code, "ERR_EMBED_RESPONSE_INVALID");
        }

        #[test]
        fn rejects_malformed_json_from_the_provider() {
            let transport = CannedEmbedTransport(Ok(b"not json".to_vec()));
            let error = embed_openai_compatible(&transport, "http://x", "m", "hi", 1000, 5)
                .unwrap_err();
            assert_eq!(error.code, "ERR_EMBED_RESPONSE_INVALID");
        }

        #[test]
        fn propagates_a_transport_failure_unchanged() {
            let transport = CannedEmbedTransport(Err(PolicyViolation {
                code: "ERR_EMBED_FAILED",
                message: "invalid api key".into(),
            }));
            let error = embed_openai_compatible(&transport, "http://x", "m", "hi", 1000, 5)
                .unwrap_err();
            assert_eq!(error.code, "ERR_EMBED_FAILED");
        }
    }
}
