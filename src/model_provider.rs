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

#[derive(Debug, Deserialize)]
struct OllamaResponse {
    response: Option<String>,
    #[serde(default)]
    done: bool,
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
}
