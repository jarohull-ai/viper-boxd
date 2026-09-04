# Gateway Contract v0.1

The gateway is the only future network or model boundary exposed to a Box.
This stage defines an unprivileged, Unix-socket protocol and a deterministic
mock implementation. It does not perform network requests or hold secrets.

## Transport

- Unix socket, one JSON request and one JSON response per line.
- `version` must be `1.0`; unsupported versions fail closed.
- Requests contain `request_id`, `method`, and `params`.
- Supported methods are `SEARCH`, `FETCH`, and `MODEL_GENERATE`.

## Request rules

The caller sends only logical parameters. It may not supply provider URLs,
API keys, proxy settings, shell commands, or arbitrary socket paths.

## Response rules

Every response carries `version`, `request_id`, `audit_trace_id`, and `ok`,
plus either `result` or `error`. `audit_trace_id` is generated once per
response by `viper_boxd::ipc::generate_audit_trace_id` (a process id,
timestamp, and monotonic counter hashed with SHA-256) and is unique per
request/response pair; it never encodes caller-supplied data. Successful
`SEARCH` and `FETCH` responses are classified as `UNTRUSTED_EVIDENCE` and
include deterministic mock metadata. Model responses are marked
`MODEL_OUTPUT`. Errors contain a stable `code` and human-readable `message`.

The mock accepts no other methods and never opens an outbound connection. A
future trusted gateway may implement these methods, but must preserve the
versioned envelope, default-deny policy, rate limits, secret isolation, and
audit trace fields.

## Error codes

Codes are stable identifiers; messages are for humans and may change. A code
not listed here should be treated as an unrecognized-envelope failure by
callers, the same as `ERR_UNSUPPORTED_SCHEMA`.

| Code | Raised by | Meaning |
| --- | --- | --- |
| `ERR_UNSUPPORTED_SCHEMA` | any gateway | `version` did not match `IPC_VERSION`. |
| `ERR_INVALID_REQUEST` | any gateway | Request body was malformed or missing a required param (`url`, `query`, `prompt`). |
| `ERR_TOOL_NOT_ALLOWED` | any gateway | `method` is not one this gateway serves. |
| `ERR_NOT_IMPLEMENTED` | research gateway | Method is contractually valid but no provider is configured for it (`SEARCH` with no `[search]` table). |
| `ERR_SEARCH_QUERY_INVALID` | search provider | `params.query` was missing, empty, or unreasonably long. |
| `ERR_SEARCH_FAILED` | search provider | The search provider request failed at the transport level (DNS, TLS, connect, timeout, non-2xx status). |
| `ERR_SEARCH_RESPONSE_INVALID` | search provider | The search provider's response was not the expected JSON shape. |
| `ERR_MODEL_PROMPT_INVALID` | model gateway | `params.prompt` was missing, empty, or exceeded the configured length. |
| `ERR_MODEL_FAILED` | model gateway | The model provider request failed at the transport level. |
| `ERR_MODEL_RESPONSE_INVALID` | model gateway | The model provider's response was not the expected JSON shape. |
| `ERR_REQUEST_LIMIT_EXCEEDED` | research gateway | `max_requests` budget for the process is exhausted. |
| `ERR_INVALID_URL` | research policy | `params.url` failed to parse as a URL. |
| `ERR_URL_SCHEME_DENIED` | research policy | Scheme other than `https`. |
| `ERR_URL_CREDENTIALS_DENIED` | research policy | URL contained a userinfo component. |
| `ERR_URL_PORT_DENIED` | research policy | Port other than the default HTTPS port (443). |
| `ERR_URL_HOST_REQUIRED` | research policy / fetcher | URL had no host component. |
| `ERR_PRIVATE_ADDRESS_DENIED` | research policy / fetcher | Host literal or DNS resolution is a private, loopback, link-local, or metadata address. |
| `ERR_IP_LITERAL_DENIED` | research policy | Host is a public IP literal instead of an allowlisted domain name. |
| `ERR_DOMAIN_NOT_ALLOWED` | research policy | Host is not in `allowed_domains`. |
| `ERR_FETCH_LIMIT_EXCEEDED` | research policy | Response body exceeds `max_fetch_bytes`. |
| `ERR_FETCH_CLIENT` | research fetcher | The HTTP client could not be constructed. |
| `ERR_FETCH_FAILED` | research fetcher | The HTTPS request failed at the transport level (DNS, TLS, connect, timeout). |
| `ERR_FETCH_READ` | research fetcher | The response body could not be read from the socket. |
| `ERR_REDIRECT_DENIED` | research fetcher | Upstream returned a 3xx status; redirects are disabled in v0. |
| `ERR_HTTP_STATUS` | research fetcher | Upstream returned a non-2xx, non-3xx status. |
| `ERR_CONTENT_TYPE_DENIED` | research fetcher | Response `Content-Type` is not `text/*` or `application/json`. |

The initial research policy validator is implemented in
`src/research_policy.rs`. It is deliberately transport-free: URL and limit
checks can be tested without contacting the Internet. The live transport must
pass those checks before it is introduced.
