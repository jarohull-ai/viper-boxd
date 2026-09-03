use std::net::{IpAddr, Ipv4Addr};
use url::Url;

#[derive(Debug, Clone)]
pub struct ResearchPolicy {
    pub allowed_domains: Vec<String>,
    pub max_requests: u32,
    pub max_fetch_bytes: usize,
    pub max_redirects: u8,
    pub timeout_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyViolation {
    pub code: &'static str,
    pub message: String,
}

impl ResearchPolicy {
    pub fn mock() -> Self {
        Self {
            allowed_domains: vec!["example.invalid".into()],
            max_requests: 30,
            max_fetch_bytes: 5 * 1024 * 1024,
            max_redirects: 0,
            timeout_seconds: 10,
        }
    }

    pub fn validate_fetch_url(&self, raw: &str) -> Result<Url, PolicyViolation> {
        let url = Url::parse(raw).map_err(|e| violation("ERR_INVALID_URL", e.to_string()))?;
        if url.scheme() != "https" {
            return Err(violation(
                "ERR_URL_SCHEME_DENIED",
                "only HTTPS URLs are allowed",
            ));
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(violation(
                "ERR_URL_CREDENTIALS_DENIED",
                "URL credentials are not allowed",
            ));
        }
        if url.port().is_some_and(|port| port != 443) {
            return Err(violation(
                "ERR_URL_PORT_DENIED",
                "only the default HTTPS port is allowed",
            ));
        }
        let host = url
            .host_str()
            .ok_or_else(|| violation("ERR_URL_HOST_REQUIRED", "URL hostname is required"))?;
        if host
            .parse::<IpAddr>()
            .map(is_private_or_local)
            .unwrap_or(false)
        {
            return Err(violation(
                "ERR_PRIVATE_ADDRESS_DENIED",
                "private, loopback, or local addresses are not allowed",
            ));
        }
        if host.parse::<IpAddr>().is_ok() {
            return Err(violation(
                "ERR_IP_LITERAL_DENIED",
                "IP-literal URLs are not allowed; use an allowlisted domain",
            ));
        }
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        if !self
            .allowed_domains
            .iter()
            .any(|allowed| host == allowed.as_str() || host.ends_with(&format!(".{allowed}")))
        {
            return Err(violation(
                "ERR_DOMAIN_NOT_ALLOWED",
                format!("domain {host} is not in the gateway allowlist"),
            ));
        }
        Ok(url)
    }

    pub fn validate_fetch_size(&self, bytes: usize) -> Result<(), PolicyViolation> {
        if bytes > self.max_fetch_bytes {
            Err(violation(
                "ERR_FETCH_LIMIT_EXCEEDED",
                format!(
                    "response is {bytes} bytes; limit is {}",
                    self.max_fetch_bytes
                ),
            ))
        } else {
            Ok(())
        }
    }
}

pub fn sanitize_html(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let mut source = input;
    while let Some(start) = source.find('<') {
        output.push_str(&source[..start]);
        let rest = &source[start..];
        if rest.len() >= 8 && rest[..8].eq_ignore_ascii_case("<script>") {
            if let Some(end) = rest.to_ascii_lowercase().find("</script>") {
                source = &rest[end + 9..];
                continue;
            }
            break;
        }
        if rest.len() >= 7 && rest[..7].eq_ignore_ascii_case("<style>") {
            if let Some(end) = rest.to_ascii_lowercase().find("</style>") {
                source = &rest[end + 8..];
                continue;
            }
            break;
        }
        if let Some(end) = rest.find('>') {
            source = &rest[end + 1..];
        } else {
            break;
        }
    }
    output.push_str(source);
    output.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn violation(code: &'static str, message: impl Into<String>) -> PolicyViolation {
    PolicyViolation {
        code,
        message: message.into(),
    }
}

fn is_private_or_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_multicast()
                || ip.is_unspecified()
                || ip == Ipv4Addr::new(169, 254, 169, 254)
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

#[cfg(test)]
mod tests {
    use super::{sanitize_html, ResearchPolicy};
    #[test]
    fn accepts_allowlisted_https_domain() {
        assert!(ResearchPolicy::mock()
            .validate_fetch_url("https://example.invalid/path")
            .is_ok());
    }
    #[test]
    fn rejects_non_https_and_private_urls() {
        let p = ResearchPolicy::mock();
        assert_eq!(
            p.validate_fetch_url("http://example.invalid")
                .unwrap_err()
                .code,
            "ERR_URL_SCHEME_DENIED"
        );
        assert_eq!(
            p.validate_fetch_url("https://127.0.0.1").unwrap_err().code,
            "ERR_PRIVATE_ADDRESS_DENIED"
        );
    }
    #[test]
    fn rejects_credentials_ports_and_unknown_domains() {
        let p = ResearchPolicy::mock();
        assert!(p
            .validate_fetch_url("https://user:pass@example.invalid")
            .is_err());
        assert!(p
            .validate_fetch_url("https://example.invalid:8443")
            .is_err());
        assert!(p.validate_fetch_url("https://evil.example").is_err());
    }
    #[test]
    fn strips_active_html_and_tags() {
        assert_eq!(
            sanitize_html("<p>Hello <script>alert(1)</script><b>world</b></p>"),
            "Hello world"
        );
    }
    #[test]
    fn enforces_fetch_size() {
        assert!(ResearchPolicy::mock()
            .validate_fetch_size(5 * 1024 * 1024 + 1)
            .is_err());
    }
}
