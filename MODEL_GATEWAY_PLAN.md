# Model gateway — implementation contract

## Purpose

A separate trusted gateway process that lets a Box request AI-model
inference without ever holding model credentials or a direct connection to
a model provider. It is a distinct gateway namespace from the research
gateway: manifests already reference it as `MODEL:VIPER_LOCAL_OLLAMA_V1`
(see `examples/research.jfp`), separate from `RESEARCH:*` gateway
references. It ships as its own binary, `viper-model-gateway`, and its own
socket, resolved through the same `viper-helper` gateway registry used for
the research gateway.

## Methods

- `MODEL_GENERATE` — the method name already established by
  `GATEWAY_CONTRACT.md` and the mock gateway's `MODEL_GENERATE` handler.
  Implemented by this plan.
- `EMBED` (vectors) — a real, useful second method, but not implemented
  here. Documented as a future method behind the same provider seam.
- Streaming (token-by-token output) is explicitly **not** a method name.
  The current IPC contract is one JSON request to exactly one JSON response
  per line (`ipc::send_request` reads one line and returns); token
  streaming needs a different transport shape (multiple response frames, or
  a persistent connection) and is a separate architectural decision, not an
  incremental addition. Out of scope until that decision is made
  deliberately.

## Response classification

Successful `MODEL_GENERATE` responses are classified `MODEL_OUTPUT`,
matching what `GATEWAY_CONTRACT.md` and the mock gateway already document —
not `UNTRUSTED_EVIDENCE` (reserved for SEARCH/FETCH) and not a new
"trusted" label. A model's own output is never pre-classified as trusted;
nothing here changes that.

## Provider

First and only implemented provider: a **local Ollama** instance
(`http://127.0.0.1:11434` by default), matching the existing
`VIPER_LOCAL_OLLAMA_V1` manifest reference. No API key, no external network
call — the gateway process talks to a fixed, administrator-configured
loopback endpoint. This is not the same trust boundary as a Box's FETCH: the
research gateway's SSRF protections (`is_private_or_local`, domain
allowlist) exist because a Box's FETCH target is attacker-influenceable; a
model gateway's provider endpoint is fixed operator configuration, never
caller-supplied, so a loopback target here is the intended, correct
behavior, not a bypassed control.

OpenAI and Anthropic remain possible future providers behind the same
`ModelTransport` seam, each requiring an operator-supplied API key read
from a named environment variable at startup — the same opt-in,
fail-closed-if-misconfigured pattern already used for the Brave Search
provider (see `SEARCH_PROVIDER_PLAN.md`). Neither is implemented here.

## Configuration

New binary, new config schema (`examples/model-gateway.toml`):

```toml
schema = "viper-boxd.model-gateway.v0"
gateway_id = "VIPER_LOCAL_OLLAMA_V1"
provider = "ollama"
endpoint = "http://127.0.0.1:11434"
model = "mistral:7b"
max_requests = 30
max_prompt_chars = 8000
max_output_tokens = 1024
timeout_seconds = 30
```

`max_output_tokens` is passed to Ollama as `options.num_predict`, bounding
generation server-side rather than trusting the client to stop. A per-call
cost budget (`MODEL_COST_BUDGET_USD` in the manifest) is not enforced by
this provider: local inference has no per-token billing. Cost enforcement
is provider-specific and becomes relevant only for a future paid provider.

## Request/response contract

No new caller-facing surface beyond what `GATEWAY_CONTRACT.md` already
specifies: `MODEL_GENERATE` takes `params.prompt`. The caller cannot supply
a model name, endpoint, provider, or token limit — those are fixed by the
gateway's config.

```json
{"gateway": "ollama-model-v0", "classification": "MODEL_OUTPUT", "model": "mistral:7b", "text": "..."}
```

## Transport seam

Mirrors `research_fetcher::HttpTransport` and `search_provider::SearchTransport`:
a `ModelTransport` trait isolates the real HTTP call to Ollama's
`/api/generate` endpoint from prompt validation and response parsing, so
those are unit-tested with a canned transport, no live Ollama instance
required for the test suite.

## New error codes

| Code | Meaning |
| --- | --- |
| `ERR_MODEL_PROMPT_INVALID` | `params.prompt` missing, empty, or exceeds `max_prompt_chars` |
| `ERR_MODEL_FAILED` | Transport-level failure (connect/timeout/non-2xx from the provider) |
| `ERR_MODEL_RESPONSE_INVALID` | Provider response was not the expected JSON shape |

`ERR_REQUEST_LIMIT_EXCEEDED` is reused for the shared `max_requests`
budget, checked before any call to the provider, matching the research
gateway's existing pattern for FETCH and SEARCH.

## Wiring into viper-helper

`examples/gateway-registry.toml` gains an entry for this gateway's socket
under the same reference name the manifests already use:

```toml
VIPER_LOCAL_OLLAMA_V1 = "/tmp/viper-model-gateway.sock"
```

A Box's profile can then request `network_mode = "GATEWAY_ONLY"` with
`gateway_refs` including `VIPER_LOCAL_OLLAMA_V1`, exactly like the research
gateway integration already wired into `viper-helper`.

## Acceptance tests before this is considered done

- prompt validation rejects empty/oversized prompts without any network
  call;
- a canned successful Ollama response maps to the documented shape with
  `MODEL_OUTPUT` and the configured model name;
- a canned error/malformed response maps to a stable error code;
- the request budget is consumed before the transport call;
- `cargo test --locked`, Clippy, and `cargo audit` all pass;
- verified against a real local Ollama instance on this host, not only
  canned responses.

## Explicitly out of scope here

- `EMBED` and any streaming transport;
- OpenAI, Anthropic, or any other keyed/paid provider;
- per-token or per-request cost budgeting (meaningful only for a paid
  provider);
- wiring `viper-model-gateway` into a live Box spawn end-to-end (the
  `viper-helper` registry entry makes it possible, but no automated test
  spawns a real Box against it here — mirrors how the research gateway's
  own `spawn`-level wiring was proven separately, in the `viper-helper`
  integration work).
