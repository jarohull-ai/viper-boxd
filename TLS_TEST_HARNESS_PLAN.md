# Local TLS test harness — implementation contract

## Scope

This harness is test-only. It must never be compiled into the production
gateway path and must not weaken production URL, DNS or private-address
validation.

## Components

1. `tests/tls_server.rs` starts a Rustls server on `127.0.0.1:0`.
2. The server uses a per-test self-signed certificate and fixed routes.
3. A test `HttpTransport` implementation connects through the existing seam.
4. The production `ReqwestTransport` remains unchanged and verifies normal
   certificates, public DNS results and policy restrictions.

## Fixed routes

- `/ok` → `200 text/html`, deterministic body;
- `/redirect` → `302` with a `Location` header;
- `/large` → body larger than the configured limit;
- `/binary` → `200 application/octet-stream`;
- `/slow` → response delayed beyond the configured timeout.

## Acceptance criteria

- successful fetch returns the expected body, SHA-256 and
  `UNTRUSTED_EVIDENCE`;
- redirects are rejected and never followed;
- oversized bodies are rejected while streaming;
- non-text content types are rejected;
- timeout returns a structured error;
- every test is deterministic and uses no external network;
- `cargo test --locked`, Clippy, `cargo audit` and CI all pass.

## Dependency policy

Use the smallest test-only set needed for Rustls certificate generation and a
minimal HTTP/TLS server. Any new crate must be reviewed with `cargo audit` and
must not be promoted to normal runtime dependencies unless required by the
production gateway.

## Security boundary

The test server is intentionally loopback-only. Its endpoint mapping is a
test seam, not a production allowlist exception. Production code continues to
reject loopback and private IP addresses before DNS or transport execution.
