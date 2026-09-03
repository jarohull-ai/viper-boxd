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

Successful `SEARCH` and `FETCH` responses are classified as
`UNTRUSTED_EVIDENCE` and include deterministic mock metadata. Model responses
are marked `MODEL_OUTPUT`. Errors contain a stable `code` and human-readable
`message`.

The mock accepts no other methods and never opens an outbound connection. A
future trusted gateway may implement these methods, but must preserve the
versioned envelope, default-deny policy, rate limits, secret isolation, and
audit trace fields.

The initial research policy validator is implemented in
`src/research_policy.rs`. It is deliberately transport-free: URL and limit
checks can be tested without contacting the Internet. The live transport must
pass those checks before it is introduced.
