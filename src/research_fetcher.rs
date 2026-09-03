use crate::research_policy::{PolicyViolation, ResearchPolicy};
use reqwest::{blocking::Client, redirect::Policy};
use serde::Serialize;
use std::{
    io::Read,
    net::{IpAddr, SocketAddr, ToSocketAddrs},
};

#[derive(Debug, Serialize)]
pub struct FetchResult {
    pub url: String,
    pub status: u16,
    pub content_type: String,
    pub bytes: usize,
    pub content_sha256: String,
    pub evidence_class: &'static str,
    pub text: String,
}

pub fn fetch(policy: &ResearchPolicy, raw_url: &str) -> Result<FetchResult, PolicyViolation> {
    let url = policy.validate_fetch_url(raw_url)?;
    let host = url
        .host_str()
        .ok_or_else(|| violation("ERR_URL_HOST_REQUIRED", "URL hostname is required"))?;
    let address = resolve_public_address(host).ok_or_else(|| {
        violation(
            "ERR_PRIVATE_ADDRESS_DENIED",
            "hostname did not resolve to a permitted public address",
        )
    })?;
    let client = Client::builder()
        .redirect(Policy::none())
        .no_proxy()
        .timeout(std::time::Duration::from_secs(policy.timeout_seconds))
        .user_agent("viper-research-gateway/0.1")
        .resolve(host, SocketAddr::new(address, 443))
        .build()
        .map_err(|e| violation("ERR_FETCH_CLIENT", e.to_string()))?;
    let response = client
        .get(url)
        .send()
        .map_err(|e| violation("ERR_FETCH_FAILED", e.to_string()))?;
    if response.status().is_redirection() {
        return Err(violation(
            "ERR_REDIRECT_DENIED",
            "redirects are disabled by policy",
        ));
    }
    if !response.status().is_success() {
        return Err(violation(
            "ERR_HTTP_STATUS",
            format!("upstream returned HTTP {}", response.status()),
        ));
    }
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if !(content_type.starts_with("text/") || matches!(content_type.as_str(), "application/json")) {
        return Err(violation(
            "ERR_CONTENT_TYPE_DENIED",
            format!("content type {content_type:?} is not allowed"),
        ));
    }
    let status = response.status().as_u16();
    let mut limited = response.take(policy.max_fetch_bytes as u64 + 1);
    let mut body = Vec::new();
    limited
        .read_to_end(&mut body)
        .map_err(|e| violation("ERR_FETCH_READ", e.to_string()))?;
    policy.validate_fetch_size(body.len())?;
    let text = String::from_utf8_lossy(&body).into_owned();
    Ok(FetchResult {
        url: raw_url.to_owned(),
        status,
        content_type,
        bytes: body.len(),
        content_sha256: jfp_box::sha256_hex(&body),
        evidence_class: "UNTRUSTED_EVIDENCE",
        text: crate::research_policy::sanitize_html(&text),
    })
}

fn resolve_public_address(host: &str) -> Option<IpAddr> {
    (host, 443)
        .to_socket_addrs()
        .ok()?
        .find(|address| !is_private_or_local(address.ip()))
        .map(|address| address.ip())
}

fn is_private_or_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_multicast()
                || ip.is_unspecified()
                || ip.octets()[0] == 100 && (64..=127).contains(&ip.octets()[1])
                || ip.octets()[0] == 192 && ip.octets()[1] == 0 && ip.octets()[2] == 0
        }
        IpAddr::V6(ip) => {
            ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_multicast()
                || (ip.segments()[0] & 0xfe00) == 0xfc00
                || (ip.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

fn violation(code: &'static str, message: impl Into<String>) -> PolicyViolation {
    PolicyViolation {
        code,
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::fetch;
    use crate::research_policy::ResearchPolicy;
    #[test]
    fn rejects_policy_before_opening_network() {
        let error = fetch(&ResearchPolicy::mock(), "http://example.invalid").unwrap_err();
        assert_eq!(error.code, "ERR_URL_SCHEME_DENIED");
    }
    #[test]
    fn rejects_unallowlisted_host_before_dns() {
        let error = fetch(&ResearchPolicy::mock(), "https://not-allowed.invalid").unwrap_err();
        assert_eq!(error.code, "ERR_DOMAIN_NOT_ALLOWED");
    }
    #[test]
    fn rejects_private_ip_before_fetch() {
        let error = fetch(&ResearchPolicy::mock(), "https://127.0.0.1").unwrap_err();
        assert_eq!(error.code, "ERR_PRIVATE_ADDRESS_DENIED");
    }
}
