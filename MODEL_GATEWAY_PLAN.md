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
caller.

`EMBED` remains `ollama`-only for now: OpenAI and OpenRouter both offer a
real embeddings endpoint and are natural next candidates behind the same
`EmbedTransport` seam, but adding them was out of scope for this round.
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

- any streaming transport;
- Blackbox, or any other provider whose request/response contract has not
  been confirmed against real documentation (no API shape is guessed here);
- `EMBED` for `openai` or `openrouter` (both offer a real embeddings
  endpoint and are natural next candidates behind `EmbedTransport`, but
  adding them was out of scope for this round);
- per-token or per-request cost budgeting (meaningful only for a paid
  provider);
- wiring `viper-model-gateway` into a live Box spawn end-to-end (the
  `viper-helper` registry entry makes it possible, but no automated test
  spawns a real Box against it here — mirrors how the research gateway's
  own `spawn`-level wiring was proven separately, in the `viper-helper`
  integration work);
- adding `EMBED` to the mock gateway (`viper-gateway-mock`).
