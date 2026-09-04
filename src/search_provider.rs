use crate::research_policy::{sanitize_html, PolicyViolation};
use reqwest::{blocking::Client, redirect::Policy};
use serde::{Deserialize, Serialize};
use std::time::Duration;

const MAX_QUERY_LEN: usize = 400;
const MAX_RESULTS: u8 = 10;
const TIMEOUT_SECONDS: u64 = 10;

#[derive(Debug, Serialize)]
pub struct SearchResult {
    pub title: String,
    pub url: String,
    pub snippet: String,
}

#[derive(Debug, Serialize)]
pub struct SearchResponse {
    pub gateway: &'static str,
    pub evidence_class: &'static str,
    pub query: String,
    pub results: Vec<SearchResult>,
}

/// Isolates the real HTTP call from response parsing so parsing and error
/// mapping are unit-testable without a live key or network access.
pub trait SearchTransport {
    fn search(&self, api_key: &str, query: &str, count: u8) -> Result<Vec<u8>, PolicyViolation>;
}

pub struct BraveSearchTransport;

impl SearchTransport for BraveSearchTransport {
    fn search(&self, api_key: &str, query: &str, count: u8) -> Result<Vec<u8>, PolicyViolation> {
        let client = Client::builder()
            .redirect(Policy::none())
            .no_proxy()
            .timeout(Duration::from_secs(TIMEOUT_SECONDS))
            .user_agent("viper-research-gateway/0.1")
            .build()
            .map_err(|e| violation("ERR_SEARCH_FAILED", e.to_string()))?;
        let response = client
            .get("https://api.search.brave.com/res/v1/web/search")
            .header("Accept", "application/json")
            .header("X-Subscription-Token", api_key)
            .query(&[("q", query), ("count", &count.to_string())])
            .send()
            .map_err(|e| violation("ERR_SEARCH_FAILED", e.to_string()))?;
        if !response.status().is_success() {
            return Err(violation(
                "ERR_SEARCH_FAILED",
                format!("Brave Search returned HTTP {}", response.status()),
            ));
        }
        response
            .bytes()
            .map(|b| b.to_vec())
            .map_err(|e| violation("ERR_SEARCH_FAILED", e.to_string()))
    }
}

#[derive(Debug, Deserialize)]
struct BraveResponse {
    #[serde(default)]
    web: Option<BraveWeb>,
}

#[derive(Debug, Deserialize)]
struct BraveWeb {
    #[serde(default)]
    results: Vec<BraveResult>,
}

#[derive(Debug, Deserialize)]
struct BraveResult {
    title: Option<String>,
    url: Option<String>,
    #[serde(default)]
    description: Option<String>,
}

fn validate_query(query: &str) -> Result<(), PolicyViolation> {
    if query.trim().is_empty() {
        return Err(violation("ERR_SEARCH_QUERY_INVALID", "query is empty"));
    }
    if query.len() > MAX_QUERY_LEN {
        return Err(violation(
            "ERR_SEARCH_QUERY_INVALID",
            format!("query exceeds {MAX_QUERY_LEN} bytes"),
        ));
    }
    Ok(())
}

fn parse_brave_response(query: &str, body: &[u8]) -> Result<SearchResponse, PolicyViolation> {
    let parsed: BraveResponse = serde_json::from_slice(body)
        .map_err(|e| violation("ERR_SEARCH_RESPONSE_INVALID", e.to_string()))?;
    let results = parsed
        .web
        .map(|web| web.results)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|entry| {
            let title = entry.title?;
            let url = entry.url?;
            Some(SearchResult {
                title: sanitize_html(&title),
                url,
                snippet: sanitize_html(&entry.description.unwrap_or_default()),
            })
        })
        .take(MAX_RESULTS as usize)
        .collect();
    Ok(SearchResponse {
        gateway: "brave-search-v0",
        evidence_class: "UNTRUSTED_EVIDENCE",
        query: query.to_owned(),
        results,
    })
}

pub fn search(
    transport: &dyn SearchTransport,
    api_key: &str,
    query: &str,
) -> Result<SearchResponse, PolicyViolation> {
    validate_query(query)?;
    let body = transport.search(api_key, query, MAX_RESULTS)?;
    parse_brave_response(query, &body)
}

fn violation(code: &'static str, message: impl Into<String>) -> PolicyViolation {
    PolicyViolation {
        code,
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::{search, PolicyViolation, SearchTransport};

    struct CannedTransport(Result<Vec<u8>, PolicyViolation>);

    impl SearchTransport for CannedTransport {
        fn search(&self, _api_key: &str, _query: &str, _count: u8) -> Result<Vec<u8>, PolicyViolation> {
            match &self.0 {
                Ok(body) => Ok(body.clone()),
                Err(e) => Err(e.clone()),
            }
        }
    }

    #[test]
    fn rejects_empty_query_before_any_transport_call() {
        let transport = CannedTransport(Err(PolicyViolation {
            code: "ERR_SEARCH_FAILED",
            message: "must not be called".into(),
        }));
        let error = search(&transport, "key", "  ").unwrap_err();
        assert_eq!(error.code, "ERR_SEARCH_QUERY_INVALID");
    }

    #[test]
    fn rejects_oversized_query_before_any_transport_call() {
        let transport = CannedTransport(Err(PolicyViolation {
            code: "ERR_SEARCH_FAILED",
            message: "must not be called".into(),
        }));
        let query = "a".repeat(401);
        let error = search(&transport, "key", &query).unwrap_err();
        assert_eq!(error.code, "ERR_SEARCH_QUERY_INVALID");
    }

    #[test]
    fn maps_a_canned_successful_response_to_the_documented_shape() {
        let body = br#"{"web":{"results":[
            {"title":"Rust <script>alert(1)</script>Lang","url":"https://rust-lang.org","description":"Systems programming"},
            {"title":"No URL","description":"skipped, missing url"},
            {"title":"No description","url":"https://example.invalid"}
        ]}}"#
            .to_vec();
        let transport = CannedTransport(Ok(body));
        let response = search(&transport, "key", "rust").expect("canned response parses");
        assert_eq!(response.evidence_class, "UNTRUSTED_EVIDENCE");
        assert_eq!(response.query, "rust");
        assert_eq!(response.results.len(), 2);
        assert_eq!(response.results[0].title, "Rust Lang");
        assert_eq!(response.results[0].url, "https://rust-lang.org");
        assert_eq!(response.results[0].snippet, "Systems programming");
        assert_eq!(response.results[1].url, "https://example.invalid");
        assert_eq!(response.results[1].snippet, "");
    }

    #[test]
    fn maps_missing_web_field_to_empty_results_not_an_error() {
        let transport = CannedTransport(Ok(b"{}".to_vec()));
        let response = search(&transport, "key", "rust").expect("empty web is valid");
        assert!(response.results.is_empty());
    }

    #[test]
    fn rejects_malformed_json_from_the_provider() {
        let transport = CannedTransport(Ok(b"not json".to_vec()));
        let error = search(&transport, "key", "rust").unwrap_err();
        assert_eq!(error.code, "ERR_SEARCH_RESPONSE_INVALID");
    }

    #[test]
    fn propagates_a_transport_failure_unchanged() {
        let transport = CannedTransport(Err(PolicyViolation {
            code: "ERR_SEARCH_FAILED",
            message: "connection refused".into(),
        }));
        let error = search(&transport, "key", "rust").unwrap_err();
        assert_eq!(error.code, "ERR_SEARCH_FAILED");
    }

    #[test]
    fn caps_results_at_the_fixed_maximum() {
        let mut results = String::new();
        for i in 0..(super::MAX_RESULTS as usize + 5) {
            if i > 0 {
                results.push(',');
            }
            results.push_str(&format!(
                r#"{{"title":"T{i}","url":"https://example.invalid/{i}","description":"d"}}"#
            ));
        }
        let body = format!(r#"{{"web":{{"results":[{results}]}}}}"#).into_bytes();
        let transport = CannedTransport(Ok(body));
        let response = search(&transport, "key", "rust").expect("valid response");
        assert_eq!(response.results.len(), super::MAX_RESULTS as usize);
    }
}
