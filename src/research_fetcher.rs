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

#[derive(Debug)]
pub struct TransportResponse {
    pub status: u16,
    pub content_type: String,
    pub body: Vec<u8>,
}

pub trait HttpTransport {
    fn get(
        &self,
        url: &url::Url,
        host: &str,
        address: SocketAddr,
        policy: &ResearchPolicy,
    ) -> Result<TransportResponse, PolicyViolation>;
}

pub struct ReqwestTransport;

impl HttpTransport for ReqwestTransport {
    fn get(
        &self,
        url: &url::Url,
        host: &str,
        address: SocketAddr,
        policy: &ResearchPolicy,
    ) -> Result<TransportResponse, PolicyViolation> {
        let client = Client::builder()
            .redirect(Policy::none())
            .no_proxy()
            .timeout(std::time::Duration::from_secs(policy.timeout_seconds))
            .user_agent("viper-research-gateway/0.1")
            .resolve(host, address)
            .build()
            .map_err(|e| violation("ERR_FETCH_CLIENT", e.to_string()))?;
        let response = client
            .get(url.clone())
            .send()
            .map_err(|e| violation("ERR_FETCH_FAILED", e.to_string()))?;
        let status = response.status().as_u16();
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_owned();
        let mut body = Vec::new();
        response
            .take(policy.max_fetch_bytes as u64 + 1)
            .read_to_end(&mut body)
            .map_err(|e| violation("ERR_FETCH_READ", e.to_string()))?;
        Ok(TransportResponse {
            status,
            content_type,
            body,
        })
    }
}

pub fn validate_response(
    policy: &ResearchPolicy,
    raw_url: &str,
    status: u16,
    content_type: &str,
    body: &[u8],
) -> Result<FetchResult, PolicyViolation> {
    if (300..400).contains(&status) {
        return Err(violation(
            "ERR_REDIRECT_DENIED",
            "redirects are disabled by policy",
        ));
    }
    if !(200..300).contains(&status) {
        return Err(violation(
            "ERR_HTTP_STATUS",
            format!("upstream returned HTTP {status}"),
        ));
    }
    let content_type = content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if !(content_type.starts_with("text/") || content_type == "application/json") {
        return Err(violation(
            "ERR_CONTENT_TYPE_DENIED",
            format!("content type {content_type:?} is not allowed"),
        ));
    }
    policy.validate_fetch_size(body.len())?;
    let text = String::from_utf8_lossy(body).into_owned();
    Ok(FetchResult {
        url: raw_url.to_owned(),
        status,
        content_type,
        bytes: body.len(),
        content_sha256: jfp_box::sha256_hex(body),
        evidence_class: "UNTRUSTED_EVIDENCE",
        text: crate::research_policy::sanitize_html(&text),
    })
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
    let response = ReqwestTransport.get(&url, host, SocketAddr::new(address, 443), policy)?;
    validate_response(
        policy,
        raw_url,
        response.status,
        &response.content_type,
        &response.body,
    )
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
    use super::{fetch, validate_response};
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

    #[test]
    fn validates_success_hash_and_untrusted_evidence() {
        let result = validate_response(
            &ResearchPolicy::mock(),
            "https://example.invalid",
            200,
            "text/html; charset=utf-8",
            b"<p>safe</p>",
        )
        .unwrap();
        assert_eq!(result.evidence_class, "UNTRUSTED_EVIDENCE");
        assert_eq!(result.bytes, 11);
        assert_eq!(result.content_sha256.len(), 64);
        assert_eq!(result.text, "safe");
    }

    #[test]
    fn rejects_redirect_wrong_type_and_oversize() {
        let policy = ResearchPolicy::mock();
        assert_eq!(
            validate_response(&policy, "https://example.invalid", 302, "text/plain", b"x")
                .unwrap_err()
                .code,
            "ERR_REDIRECT_DENIED"
        );
        assert_eq!(
            validate_response(
                &policy,
                "https://example.invalid",
                200,
                "application/octet-stream",
                b"x"
            )
            .unwrap_err()
            .code,
            "ERR_CONTENT_TYPE_DENIED"
        );
        assert_eq!(
            validate_response(
                &ResearchPolicy {
                    max_fetch_bytes: 1,
                    ..policy
                },
                "https://example.invalid",
                200,
                "text/plain",
                b"xx"
            )
            .unwrap_err()
            .code,
            "ERR_FETCH_LIMIT_EXCEEDED"
        );
    }
}
