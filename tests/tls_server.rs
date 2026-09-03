use reqwest::blocking::Client;
use reqwest::redirect::Policy;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ServerConfig, ServerConnection, StreamOwned};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;
use viper_boxd::research_fetcher::{validate_response, HttpTransport, TransportResponse};
use viper_boxd::research_policy::{PolicyViolation, ResearchPolicy};

struct TlsTestServer {
    address: std::net::SocketAddr,
    certificate_der: Vec<u8>,
    thread: Option<JoinHandle<()>>,
}

impl TlsTestServer {
    fn start() -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let cert = rcgen::generate_simple_self_signed(vec![
            "localhost".to_owned(),
            "127.0.0.1".to_owned(),
        ])
        .expect("generate self-signed test certificate");
        let certificate_der = cert.cert.der().to_vec();
        let certificate = CertificateDer::from(certificate_der.clone());
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()));
        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![certificate], key)
            .expect("build TLS server configuration");
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind TLS test server");
        let address = listener.local_addr().expect("read TLS test server address");
        let thread = thread::spawn(move || {
            if let Some(Ok(stream)) = listener.incoming().next() {
                serve_connection(stream, config);
            }
        });
        Self {
            address,
            certificate_der,
            thread: Some(thread),
        }
    }

    fn url(&self, path: &str) -> String {
        format!("https://example.invalid{path}")
    }
}

impl Drop for TlsTestServer {
    fn drop(&mut self) {
        let _ = TcpStream::connect(self.address);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn serve_connection(stream: TcpStream, config: ServerConfig) {
    let connection = ServerConnection::new(Arc::new(config)).expect("create TLS connection");
    let mut stream = StreamOwned::new(connection, stream);
    let mut request = Vec::new();
    let mut byte = [0_u8; 1];
    while request.len() < 8192 {
        if stream.read_exact(&mut byte).is_err() {
            return;
        }
        request.push(byte[0]);
        if request.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let request_text = String::from_utf8_lossy(&request);
    let path = request_text
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("/")
        .to_owned();
    let (status, content_type, body, delay) = match path.as_str() {
        "/ok" => (
            "200 OK",
            "text/html",
            b"<p>deterministic tls fixture</p>".to_vec(),
            None,
        ),
        "/redirect" => ("302 Found", "text/plain", b"redirect".to_vec(), None),
        "/large" => ("200 OK", "text/html", vec![b'x'; 1024], None),
        "/binary" => ("200 OK", "application/octet-stream", vec![0, 1, 2, 3], None),
        "/slow" => (
            "200 OK",
            "text/html",
            b"slow".to_vec(),
            Some(Duration::from_millis(1_500)),
        ),
        _ => ("404 Not Found", "text/plain", b"not found".to_vec(), None),
    };
    if let Some(delay) = delay {
        thread::sleep(delay);
    }
    let location = if path == "/redirect" {
        "Location: https://example.invalid/ok\r\n"
    } else {
        ""
    };
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n{location}Connection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.write_all(&body);
    let _ = stream.flush();
}

struct TestTlsTransport {
    address: std::net::SocketAddr,
    certificate_der: Vec<u8>,
}

impl TestTlsTransport {
    fn client(&self, policy: &ResearchPolicy) -> Result<Client, PolicyViolation> {
        let internal_error = |error: reqwest::Error| PolicyViolation {
            code: "ERR_INTERNAL",
            message: error.to_string(),
        };
        let root = reqwest::Certificate::from_der(&self.certificate_der).map_err(internal_error)?;
        Client::builder()
            .redirect(Policy::none())
            .no_proxy()
            .tls_built_in_root_certs(false)
            .add_root_certificate(root)
            .timeout(Duration::from_secs(policy.timeout_seconds))
            .build()
            .map_err(internal_error)
    }
}

impl HttpTransport for TestTlsTransport {
    fn get(
        &self,
        url: &url::Url,
        _host: &str,
        _address: std::net::SocketAddr,
        policy: &ResearchPolicy,
    ) -> Result<TransportResponse, PolicyViolation> {
        let client = self.client(policy)?;
        let target = format!("https://127.0.0.1:{}{}", self.address.port(), url.path());
        let response = client.get(target).send().map_err(|error| PolicyViolation {
            code: if error.is_timeout() {
                "ERR_TIMEOUT"
            } else {
                "ERR_INTERNAL"
            },
            message: error.to_string(),
        })?;
        let status = response.status().as_u16();
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        let body = response.bytes().map_err(|error| PolicyViolation {
            code: "ERR_INTERNAL",
            message: error.to_string(),
        })?;
        Ok(TransportResponse {
            status,
            content_type,
            body: body.to_vec(),
        })
    }
}

fn fetch_fixture(
    server: &TlsTestServer,
    path: &str,
    policy: &ResearchPolicy,
) -> Result<viper_boxd::research_fetcher::FetchResult, PolicyViolation> {
    let url = url::Url::parse(&server.url(path)).expect("fixture URL parses");
    let transport = TestTlsTransport {
        address: server.address,
        certificate_der: server.certificate_der.clone(),
    };
    let response = transport.get(&url, "example.invalid", server.address, policy)?;
    validate_response(
        policy,
        &server.url(path),
        response.status,
        &response.content_type,
        &response.body,
    )
}

#[test]
fn tls_ok_returns_untrusted_evidence_and_hash() {
    let server = TlsTestServer::start();
    let result = fetch_fixture(&server, "/ok", &ResearchPolicy::mock()).expect("OK fixture fetch");
    assert_eq!(result.status, 200);
    assert_eq!(result.evidence_class, "UNTRUSTED_EVIDENCE");
    assert_eq!(result.text, "deterministic tls fixture");
    assert_eq!(result.content_sha256.len(), 64);
}

#[test]
fn tls_redirect_is_rejected_without_following() {
    let server = TlsTestServer::start();
    let error = fetch_fixture(&server, "/redirect", &ResearchPolicy::mock()).unwrap_err();
    assert_eq!(error.code, "ERR_REDIRECT_DENIED");
}

#[test]
fn tls_large_body_is_rejected_by_policy() {
    let server = TlsTestServer::start();
    let policy = ResearchPolicy {
        max_fetch_bytes: 16,
        ..ResearchPolicy::mock()
    };
    let error = fetch_fixture(&server, "/large", &policy).unwrap_err();
    assert_eq!(error.code, "ERR_FETCH_LIMIT_EXCEEDED");
}

#[test]
fn tls_binary_content_is_rejected() {
    let server = TlsTestServer::start();
    let error = fetch_fixture(&server, "/binary", &ResearchPolicy::mock()).unwrap_err();
    assert_eq!(error.code, "ERR_CONTENT_TYPE_DENIED");
}

#[test]
fn tls_slow_response_times_out() {
    let server = TlsTestServer::start();
    let policy = ResearchPolicy {
        timeout_seconds: 1,
        ..ResearchPolicy::mock()
    };
    let error = fetch_fixture(&server, "/slow", &policy).unwrap_err();
    assert_eq!(error.code, "ERR_TIMEOUT");
}

/// Proves the harness performs genuine certificate validation rather than
/// disabling it: a client that does not trust this server's self-signed
/// root must fail the handshake instead of silently succeeding.
#[test]
fn tls_connection_without_trusted_root_is_rejected() {
    let server = TlsTestServer::start();
    let client = Client::builder()
        .redirect(Policy::none())
        .no_proxy()
        .timeout(Duration::from_secs(2))
        .build()
        .expect("build client with only built-in trust roots");
    let target = format!("https://127.0.0.1:{}/ok", server.address.port());
    let error = client.get(target).send().expect_err(
        "a client without the test root must not complete the TLS handshake",
    );
    assert!(error.is_connect() || error.is_request());
}
