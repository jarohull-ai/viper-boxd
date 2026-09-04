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
- `EMBED` (vectors) — implemented, opt-in via an `[embed]` config table
  (same opt-in pattern as `[search]` for the research gateway), behind a
  separate `EmbedTransport` seam mirroring `ModelTransport`. Requires an
  embedding-capable model distinct from the generation model — Ollama gates
  this by the model's declared `embedding` capability, not by a server
  flag; `mistral:7b` fails with `ERR_EMBED_FAILED`, `nomic-embed-text`
  works (verified live, 768-dimension vectors). Not added to the mock
  gateway (`viper-gateway-mock`), which still only serves `SEARCH`,
  `FETCH`, and `MODEL_GENERATE`.
- Streaming (token-by-token output) is explicitly **not** a method name —
  it is `params.stream: true` on `MODEL_GENERATE`. It required a real
  transport-shape change (multiple `StreamChunk` frames per request instead
  of one `Response`), which was deliberately treated as a separate
  architectural decision rather than an incremental addition. That decision
  is made and implemented, for all four providers; see
  [STREAM_PLAN.md](STREAM_PLAN.md) for the design and verification detail
  rather than duplicating it here.

## Response classification

Successful `MODEL_GENERATE` responses are classified `MODEL_OUTPUT`,
matching what `GATEWAY_CONTRACT.md` and the mock gateway already document —
not `UNTRUSTED_EVIDENCE` (reserved for SEARCH/FETCH) and not a new
"trusted" label. A model's own output is never pre-classified as trusted;
nothing here changes that.

## Provider

Four `MODEL_GENERATE` providers are implemented, selected by the config's
`provider` field, one gateway process per provider (a Box picks which one
via `gateway_refs`, same as the research gateway):

- **`ollama`** — a local Ollama instance (`http://127.0.0.1:11434` by
  default), matching the existing `VIPER_LOCAL_OLLAMA_V1` manifest
  reference. No API key, no external network call — the gateway process
  talks to a fixed, administrator-configured loopback endpoint. This is not
  the same trust boundary as a Box's FETCH: the research gateway's SSRF
  protections (`is_private_or_local`, domain allowlist) exist because a
  Box's FETCH target is attacker-influenceable; a model gateway's provider
  endpoint is fixed operator configuration, never caller-supplied, so a
  loopback target here is the intended, correct behavior, not a bypassed
  control.
- **`openai`** — `POST {endpoint}/chat/completions`, `Authorization: Bearer
  <key>`, Chat Completions request/response shape.
- **`anthropic`** — `POST {endpoint}/v1/messages`, `x-api-key: <key>` plus
  `anthropic-version: 2023-06-01`, Messages API request/response shape. Text
  is joined from every `content[]` block with `type == "text"`; non-text
  blocks (e.g. tool use) are skipped rather than erroring, since a plain
  `MODEL_GENERATE` call has no tool-use surface to trigger them.
- **`openrouter`** — reuses the exact same `OpenAiCompatibleTransport` as
  `openai`, since OpenRouter's API is a drop-in-compatible proxy over the
  same Chat Completions shape; only `endpoint` (`https://openrouter.ai/api/v1`)
  and the model naming convention (e.g. `openai/gpt-4o-mini`) differ.

`openai`, `anthropic`, and `openrouter` each require `api_key_env`, read
from that named environment variable at startup — the same opt-in,
fail-closed-if-misconfigured pattern already used for the Brave Search
provider (see `SEARCH_PROVIDER_PLAN.md`). `ollama` needs no key;
`api_key_env` is optional and simply unused when `provider = "ollama"`. The
key is read once at gateway startup and held only in the gateway process's
own memory; it is never written to a config file, logged, or returned to a
caller. `GatewayConfig::load` also requires `endpoint` to start with
`https://` for these three providers — the key would otherwise cross the
network in plaintext on a misconfigured `http://` endpoint, a config typo
that would ship a real secret in the clear rather than merely fail loudly.
`ollama`'s `endpoint` is unrestricted (`http://127.0.0.1:11434` by default):
it is expected to run on an admin-chosen local or private address, not a
provider requiring a bearer token. There is deliberately no allowlist of
specific provider hosts beyond the `https://` requirement — see
[KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md).

`EMBED` is implemented for `ollama`, `openai`, and `openrouter`.
`OpenAiCompatibleEmbedTransport` (`POST {endpoint}/embeddings`, Bearer auth)
serves both `openai` and `openrouter`: OpenRouter's published OpenAPI spec
documents the same `data[].embedding` response shape as OpenAI's, not
merely an approximation, so one transport and one parser cover both,
mirroring `OpenAiCompatibleTransport` for `MODEL_GENERATE`. `anthropic` has
no public embeddings API at all — `[embed]` with `provider = "anthropic"`
is rejected at config load, not left to fail per-call or silently ignored.
Anthropic has no public embeddings API at all.

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

`EMBED` is opt-in via an additional table (`examples/model-gateway-with-embed.toml`),
absent by default so the base config's behavior is unchanged:

```toml
[embed]
model = "nomic-embed-text"
max_input_chars = 8000
```

## Request/response contract

No new caller-facing surface beyond what `GATEWAY_CONTRACT.md` already
specifies: `MODEL_GENERATE` takes `params.prompt`, `EMBED` takes
`params.input`. The caller cannot supply a model name, endpoint, provider,
or token limit — those are fixed by the gateway's config.

```json
{"gateway": "ollama-model-v0", "classification": "MODEL_OUTPUT", "model": "mistral:7b", "text": "..."}
{"gateway": "ollama-model-v0", "classification": "MODEL_OUTPUT", "model": "nomic-embed-text", "embedding": [...], "dimensions": 768}
```

## Transport seam

Mirrors `research_fetcher::HttpTransport` and `search_provider::SearchTransport`:
a `ModelTransport` trait isolates the real HTTP call from prompt validation
and response parsing, and a parallel `EmbedTransport` trait does the same
for `/api/embed`, so both are unit-tested with a canned transport, no live
provider instance required for the test suite. Every `ModelTransport`
implementation (`OllamaTransport`, `OpenAiCompatibleTransport`,
`AnthropicTransport`) returns raw response bytes; response parsing is a
separate, provider-specific free function (`parse_ollama_response`,
`parse_openai_response`, `parse_anthropic_response`), each independently
unit-tested against canned bytes.

## New error codes

| Code | Meaning |
| --- | --- |
| `ERR_MODEL_PROMPT_INVALID` | `params.prompt` missing, empty, or exceeds `max_prompt_chars` |
| `ERR_MODEL_FAILED` | Transport-level failure (connect/timeout/non-2xx from the provider) |
| `ERR_MODEL_RESPONSE_INVALID` | Provider response was not the expected JSON shape |
| `ERR_EMBED_INPUT_INVALID` | `params.input` missing, empty, or exceeds `max_input_chars` |
| `ERR_EMBED_FAILED` | Transport-level failure, including a model with no embedding capability |
| `ERR_EMBED_RESPONSE_INVALID` | Provider response was not the expected JSON shape, or returned no vector |

`ERR_REQUEST_LIMIT_EXCEEDED` is reused for the shared `max_requests`
budget, checked before any call to the provider, matching the research
gateway's existing pattern for FETCH and SEARCH.

## Wiring into viper-helper

`examples/gateway-registry.toml` gains one entry per provider's socket,
since each provider runs as its own `viper-model-gateway` process:

```toml
VIPER_LOCAL_OLLAMA_V1 = "/tmp/viper-model-gateway.sock"
OPENAI_GPT_V1 = "/tmp/viper-model-gateway-openai.sock"
ANTHROPIC_CLAUDE_V1 = "/tmp/viper-model-gateway-anthropic.sock"
OPENROUTER_V1 = "/tmp/viper-model-gateway-openrouter.sock"
```

A Box's profile can then request `network_mode = "GATEWAY_ONLY"` with
`gateway_refs` including one of these, exactly like the research gateway
integration already wired into `viper-helper`.

## Acceptance tests before this is considered done

- prompt/input validation rejects empty/oversized values without any
  network call, for both `MODEL_GENERATE` and `EMBED`;
- a canned successful Ollama response maps to the documented shape with
  `MODEL_OUTPUT` and the configured model name, for both methods;
- a canned error/malformed response maps to a stable error code, for both
  methods;
- the request budget is consumed before the transport call, for both
  methods;
- `EMBED` with no `[embed]` table returns `ERR_NOT_IMPLEMENTED`, matching
  the base `examples/model-gateway.toml`'s unchanged behavior;
- `cargo test --locked`, Clippy, and `cargo audit` all pass;
- verified against a real local Ollama instance on this host, not only
  canned responses — done for both methods: `MODEL_GENERATE` against
  `mistral:7b`, `EMBED` against `nomic-embed-text` (a model with no
  declared `embedding` capability, e.g. `mistral:7b`, fails per-call with
  `ERR_EMBED_FAILED` rather than at gateway startup);
- `openai`, `anthropic`, and `openrouter` verified live against their real
  APIs with operator-supplied keys: `openrouter` returned a real completion
  (`MODEL_OUTPUT`, correct `model` field); `openai` returned a real HTTP 429
  (rate/quota limited on that key) mapped to `ERR_MODEL_FAILED`; `anthropic`
  returned a real HTTP 400, root-caused via a direct `curl` against the same
  endpoint to an insufficient-credit account error, not a request-shape bug
  — confirming the request format, auth headers, and error mapping are all
  correct for a provider whose only live response available was a failure.
  Test keys were provided for this verification only, meant to be rotated
  by the operator immediately afterward.

## Explicitly out of scope here

- streaming for `openai`, `anthropic`, and `openrouter` (SSE parsing per
  provider — non-streaming `MODEL_GENERATE` and `EMBED` are implemented for
  all three; streaming is implemented for `ollama` only, see
  [STREAM_PLAN.md](STREAM_PLAN.md));
- Blackbox, or any other provider whose request/response contract has not
  been confirmed against real documentation (no API shape is guessed here);
- `EMBED` for `anthropic` (no public embeddings API exists to call — this
  is a real absence, not an unimplemented one, and `[embed]` with
  `provider = "anthropic"` is rejected at config load rather than left to
  fail per-call);
- per-token or per-request cost budgeting (meaningful only for a paid
  provider);
- adding `EMBED` to the mock gateway (`viper-gateway-mock`).

## End-to-end verification: a live Box calling a live gateway

Wiring `viper-model-gateway` into a live Box spawn end-to-end is done and
verified on this host, closing the loop the whole gateway architecture was
built for. `spawn`'s own payload deliberately stays the fixed
`/usr/bin/sleep` test executable — per `BACKEND_CONTRACT.md`, `viper-helper`
must not accept "arbitrary shell commands," and adding a way to run
caller-chosen code inside a spawned Box would be exactly that. Instead,
`viper-gateway-probe` (already a fixed, narrow, pre-approved test binary)
gained a `--call MODEL_GENERATE` mode: a real `MODEL_GENERATE` request with
a fixed, non-configurable prompt, run in a second transient unit under
byte-identical isolation properties (`PrivateNetwork=yes`, the same
`BindPaths=` gateway socket) to whatever `spawn` would apply. Verified
together: `spawn` a Box with `network_mode: GATEWAY_ONLY`,
`gateway_refs: [VIPER_LOCAL_OLLAMA_V1]` (confirmed `status: active`); while
it is alive, `gateway_probe` with `--call MODEL_GENERATE` against the same
gateway returns a real Ollama completion (`MODEL_OUTPUT`, non-empty text)
with `external_network_blocked: true` and `local_network_blocked: true`;
then `kill`/`cleanup` the Box.
